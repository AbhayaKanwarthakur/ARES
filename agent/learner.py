"""LEARN + IMPROVE. Three DIFFERENT kinds of adaptation - kept separate on purpose:

 1. MEMORY adaptation   patterns table: fingerprints are stored/reinforced, so a repeat or
                        near-repeat attack is recognised even if the ML model has never seen it.
                        (The model's weights do NOT change.)
 2. RULE adaptation     action_stats table: the planner prefers responses that worked
                        (see planner.py). (The model's weights do NOT change.)
 3. MODEL retraining    retrain(): the Random Forest is genuinely re-fit on the original
                        dataset + labelled experiences from memory. Only this changes weights.
"""
import json

import numpy as np
import pandas as pd

from .detector import DATA_PATH, fit_and_save, get_detector
from .features import to_vector
from .memory import now


def next_novel_name(mem):
    fams = {p["base_type"] for p in mem.patterns() if p["base_type"].startswith("Novel-")}
    return f"Novel-{chr(65 + len(fams) % 26)}"


def learn(mem, feats, det, ana, plan, resp, truth, decision_ms):
    """Update memory + statistics after a response. Returns lines for the dashboard."""
    vec, ftype, ok = to_vector(feats), ana["final_type"], resp["success"]
    mem_lines, learn_lines, pattern = [], [], None
    base_type = ftype

    if ftype == "Normal Traffic":
        status = "BASELINE - nothing to learn"
        learn_lines.append("Normal traffic: no pattern stored.")
    elif ana["recognized"]:
        p, n = ana["pattern"], ana["pattern"]["count"]
        cent = ((np.array(p["centroid"]) * n + np.array(vec)) / (n + 1)).tolist()
        mem.update_pattern(p["id"], centroid=cent, count=n + 1, confidence=ana["final_conf"],
                           tries=p["tries"] + 1, successes=p["successes"] + int(ok),
                           action=resp["action"], last_seen=now())
        pattern, base_type = mem.pattern(p["id"]), p["base_type"]
        status = f"PATTERN REINFORCED (x{n + 1})"
        learn_lines += [f"Pattern '{p['name']}' reinforced: confidence {p['confidence']:.0%} -> {ana['final_conf']:.0%}.",
                        f"Earlier responses to this pattern: {p['successes']}/{p['tries']} worked."]
    else:
        base_type = ftype if ftype != "Unknown Suspicious" else next_novel_name(mem)
        k = sum(1 for q in mem.patterns() if q["base_type"] == base_type) + 1
        name = f"{base_type} #{k}"
        pid = mem.add_pattern({"name": name, "base_type": base_type, "centroid": vec, "count": 1,
                               "confidence": ana["final_conf"], "successes": int(ok), "tries": 1,
                               "action": resp["action"], "description": ana["traits"],
                               "first_seen": now(), "last_seen": now()})
        pattern = mem.pattern(pid)
        status = "NEW PATTERN LEARNED"
        learn_lines.append(f"New pattern '{name}' added to attack memory ({ana['traits']}).")
        if ftype == "Unknown Suspicious":
            learn_lines.append("Unknown behaviour profiled and stored: the next similar attack will be recognised from memory.")

    if ftype != "Normal Traffic":
        mem.record_outcome(base_type, resp["action"], ok)
        learn_lines.append(f"Response {resp['action']} {'worked' if ok else 'did NOT fully work'} -> action preference for "
                           f"'{base_type}' updated (RULE adaptation).")
        if plan["adapted"]:
            learn_lines.append(f"Rule adapted: default {plan['default']} replaced by {plan['action']}.")
        learn_lines.append("Adaptation type this step: MEMORY + RULE. ML model weights unchanged until retraining.")

    train_label = (truth if truth in ("Normal Traffic",) or not truth.startswith("Novel")
                   else (pattern["base_type"] if pattern else base_type))
    if ftype == "Normal Traffic":
        train_label = "Normal Traffic"
    iid = mem.add_incident({
        "source_ip": feats["source_ip"], "attack_type": ftype, "truth_label": truth, "train_label": train_label,
        "model_label": det["raw_label"], "model_conf": det["confidence"], "final_conf": ana["final_conf"],
        "risk": ana["risk"], "risk_score": ana["risk_score"], "action": resp["action"], "result": resp["result"],
        "success": int(ok), "path": ana["path"], "similarity": ana["similarity"],
        "pattern_id": pattern["id"] if pattern else None, "pattern_name": pattern["name"] if pattern else None,
        "analysis_steps": ana["analysis_steps"], "decision_ms": round(decision_ms, 1),
        "features": json.dumps(feats), "reasoning": plan["reason"], "learning_status": status})
    mem_lines.append(f"Incident #{iid} stored: {ftype} from {feats['source_ip']}, action {resp['action']}, "
                     f"success={ok}, path={ana['path']}.")
    if pattern:
        mem_lines.append(f"Linked to pattern '{pattern['name']}' (seen {pattern['count']}x).")
    return {"incident_id": iid, "status": status, "mem_lines": mem_lines, "learn_lines": learn_lines,
            "pattern": pattern}


# ---------------------------------------------------------------- model retraining
def eligible_experiences(mem):
    """Labelled experiences usable for retraining. Novel classes need >= 2 sightings (confirmed recurrence)."""
    df = mem.incidents_df()
    if df.empty:
        return df
    df = df[df["train_label"].notna()]
    is_nov = df["train_label"].str.startswith("Novel-")
    counts = df.loc[is_nov, "train_label"].value_counts()
    keep = (~is_nov) | df["train_label"].map(counts).fillna(0).ge(2)
    return df[keep]


def pending_count(mem):
    df = eligible_experiences(mem)
    return 0 if df.empty else int((df["used_in_training"] == 0).sum())


def retrain(mem, reason="manual"):
    """REAL model retraining: original dataset + (augmented) labelled experiences from memory."""
    exp = eligible_experiences(mem)
    if exp.empty:
        return None
    exp_df = pd.DataFrame([json.loads(f) for f in exp["features"]])
    exp_df["attack_type"] = exp["train_label"].values
    det = get_detector()
    before = float(np.mean(det.raw_labels(exp_df) == exp_df["attack_type"].values))
    res = fit_and_save(pd.read_csv(DATA_PATH), exp_df)
    det.reload()
    after = float(np.mean(det.raw_labels(exp_df) == exp_df["attack_type"].values))   # in-sample!
    mem._x("UPDATE incidents SET used_in_training=1 WHERE id IN (%s)" % ",".join(str(i) for i in exp["id"]))
    res.update(exp_acc_before=before, exp_acc_after=after, n_experiences=len(exp), reason=reason)
    mem.add_model_log(reason=reason, n_experiences=len(exp), classes=json.dumps(res["classes"]),
                      holdout_acc=res["holdout_acc"], exp_acc_before=before, exp_acc_after=after)
    return res


def maybe_retrain(mem, every):
    if every and pending_count(mem) >= every:
        return retrain(mem, reason=f"auto: {every} new labelled experiences")
    return None


# ---------------------------------------------------------------- statistics for the dashboard
def adaptation_stats(mem):
    df, pats, log = mem.incidents_df(), mem.patterns(), mem.model_log_df()
    atk = df[df["attack_type"] != "Normal Traffic"] if not df.empty else df
    out = {"attacks": len(atk), "normal": len(df) - len(atk), "patterns": len(pats),
           "reinforced": sum(p["count"] >= 2 for p in pats), "retrains": len(log),
           "pending": pending_count(mem), "fast_rate": 0.0, "success_rate": 0.0,
           "steps_first": None, "steps_last": None, "conf_first": None, "conf_last": None}
    if len(atk):
        out["fast_rate"] = float((atk["path"] == "FAST_MEMORY").mean())
        out["success_rate"] = float(atk["success"].mean())
        h = min(5, max(1, len(atk) // 2))
        out.update(steps_first=float(atk["analysis_steps"].head(h).mean()), steps_last=float(atk["analysis_steps"].tail(h).mean()),
                   conf_first=float(atk["final_conf"].head(h).mean()), conf_last=float(atk["final_conf"].tail(h).mean()))
    return out
