"""ANALYZE: compare the detection with attack memory and decide HOW to think about it.

Paths (this is where "faster after experience" comes from):
  BASELINE       normal traffic                               -> 2 analysis steps
  FAST_MEMORY    memory recognises the pattern (>= MATCH_T)   -> 2 steps (skips deep analysis)
  STANDARD       model is confident, memory has no match      -> 4 steps (new pattern stored)
  FULL_ANALYSIS  unknown to model AND to memory               -> 6 steps (profile, score, cautious plan)
"""
from .detector import risk_label, risk_score
from .features import to_vector

MATCH_T = 0.90   # similarity needed to say "I have seen this pattern before"

TRACES = {
    "BASELINE": ["Fingerprint event window", "Baseline check"],
    "FAST_MEMORY": ["Fingerprint + match learned patterns", "Reinforce pattern"],
    "STANDARD": ["Fingerprint event window", "Compare with attack memory",
                 "Validate model verdict", "Register new pattern"],
    "FULL_ANALYSIS": ["Fingerprint event window", "Compare with attack memory", "Profile behaviour",
                      "Score risk", "Choose cautious response", "Register new pattern"],
}


def describe(f):
    """Human-readable behaviour profile of an event window."""
    t = []
    if f["packets_per_second"] > 1500: t.append("very high packet rate")
    elif f["packets_per_second"] < 5: t.append("very low, stealthy packet rate")
    if f["request_count"] > 2000: t.append("huge request volume")
    if f["failed_login_count"] >= 5: t.append(f"{f['failed_login_count']} failed logins")
    if f["login_frequency"] > 1: t.append("rapid login attempts")
    if f["distinct_ports"] >= 8: t.append(f"touches {f['distinct_ports']} different ports")
    if f["payload_length"] > 2000: t.append("very large payloads")
    elif f["payload_length"] > 400 and f["special_char_ratio"] > 0.12: t.append("long, symbol-heavy payloads")
    if f["unusual_port"] >= 0.5: t.append(f"unusual port {f['destination_port']}")
    if f["connection_duration"] > 60: t.append("very long-lived connections")
    return ", ".join(t) or "no strong standard indicators"


def analyze(mem, feats, det, match_threshold=MATCH_T):
    vec = to_vector(feats)
    ranked = mem.rank_patterns(vec)
    best, sim = ranked[0] if ranked else (None, 0.0)
    label, conf, nov = det["attack_type"], det["confidence"], det["novelty"]
    traits = describe(feats)
    anomaly = min(1.0, max(0.0, (nov - 1.5) / 5))
    ev = [f"Behaviour profile: {traits}."]
    pattern, recognized = None, False
    closest = (f"Closest memory: '{best['name']}' at {sim:.0%} similarity (below the {match_threshold:.0%} match threshold)."
               if best else "Attack memory is empty - nothing to compare with.")

    if label == "Normal Traffic":
        path, final_type, final_conf = "BASELINE", label, conf
        ev.append("Matches the normal-traffic baseline.")
    elif det["is_unknown"]:
        if best and sim >= match_threshold:
            path, final_type, pattern, recognized = "FAST_MEMORY", best["base_type"], best, True
            pc = best["confidence"]
            final_conf = round(pc + 0.5 * (0.99 - pc), 3)
            ev.append(f"The ML model does not know this ({det['unknown_reason']}).")
            ev.append(f"But memory does: it matches '{best['name']}' at {sim:.0%} similarity (seen {best['count']}x before).")
            ev.append("Similar pattern recognised -> deep analysis skipped.")
        else:
            path, final_type = "FULL_ANALYSIS", "Unknown Suspicious"
            final_conf = round(0.5 + 0.15 * anomaly, 3)
            ev.append("Unknown suspicious behaviour detected - " + det["unknown_reason"] + ".")
            ev.append(closest)
            ev.append("Treating it as a potential new attack: profiling behaviour and scoring risk.")
    else:
        same = best is not None and sim >= match_threshold and best["base_type"] == label
        if same:
            path, final_type, pattern, recognized = "FAST_MEMORY", label, best, True
            final_conf = round(min(0.99, conf + 0.5 * (0.99 - conf) * sim), 3)
            ev.append(f"Model says {label} ({conf:.0%}). Memory agrees: '{best['name']}' at {sim:.0%} similarity (seen {best['count']}x).")
            ev.append("Memory-based confidence boost applied; deep analysis skipped.")
        else:
            path, final_type, final_conf = "STANDARD", label, conf
            ev.append(f"Model says {label} ({conf:.0%}).")
            ev.append(closest if best else "No earlier pattern to compare with - this is the first of its kind.")
            ev.append("New behaviour variant -> registering it as a new pattern.")

    score = risk_score(final_type, final_conf, nov)
    return {"final_type": final_type, "final_conf": final_conf, "risk": risk_label(score),
            "risk_score": score, "path": path, "trace": TRACES[path], "analysis_steps": len(TRACES[path]),
            "evidence": ev, "similarity": round(sim, 3), "best": best, "pattern": pattern,
            "recognized": recognized, "traits": traits, "model_label": det["raw_label"],
            "model_conf": conf, "novelty": nov}
