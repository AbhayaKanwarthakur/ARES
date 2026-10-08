"""The full agent loop:  LOG -> DETECT -> ANALYZE -> DECIDE -> RESPOND -> REMEMBER -> LEARN -> IMPROVE"""
import json
import time

from .analyzer import analyze
from .detector import get_detector
from .features import extract_features
from .learner import learn, maybe_retrain
from .planner import plan_response
from .responder import execute_response
from .simulator import LOG_PATH, read_batch

PACE = 0.22   # seconds of visible "thinking" per analysis step (cosmetic, can be switched off)


def run_agent(mem, batch_id, truth, deliberate=False, on_step=None, log_path=LOG_PATH, retrain_every=10):
    t0, steps, ui = time.perf_counter(), [], [0.0]   # ui = time spent inside the dashboard callback (excluded)

    def emit(key, title, lines):
        s = {"key": key, "title": title, "lines": lines}
        steps.append(s)
        if on_step:
            c = time.perf_counter()
            on_step(s)
            ui[0] += time.perf_counter() - c
        return s

    events = read_batch(batch_id, log_path)                       # 1. read the batch back from the log file
    delivered = [e for e in events if not e.get("blocked")]
    src = events[0]["src_ip"]
    failed = sum(e["outcome"] == "login_failed" for e in events)
    emit("app", "DEMO APP -> SECURITY LOG",
         [f"{len(events)} events from {src} handled by the local sandbox app and written to data/security.log.",
          f"{failed} failed logins - {len({e['dst_port'] for e in events})} distinct ports - "
          f"{sum(e['requests'] for e in events)} requests."])
    if not delivered:
        emit("defense", "SIMULATED DEFENSE ALREADY ACTIVE",
             [f"All {len(events)} events were rejected by the simulated blocklist from an earlier response.",
              "The agent's previous decision is still protecting the app - no new analysis needed."])
        return {"dropped": True, "steps": steps, "src_ip": src}

    feats = extract_features(delivered)
    det = get_detector().detect(feats)                              # 2. DETECT
    emit("detect", "DETECTION (ML model)",
         [f"Prediction: {det['attack_type']}  |  confidence {det['confidence']:.0%}  |  initial risk {det['risk']}",
          f"Raw model label: {det['raw_label']}  |  novelty distance {det['novelty']}"
          + (f"  |  UNKNOWN because {det['unknown_reason']}" if det["is_unknown"] else "")])

    ana = analyze(mem, feats, det)                                  # 3. ANALYZE
    if deliberate:
        time.sleep(PACE * ana["analysis_steps"])
    emit("analyze", f"ANALYSIS - path: {ana['path']} ({ana['analysis_steps']} steps)",
         ana["evidence"] + [f"Steps executed: {' -> '.join(ana['trace'])}",
                            f"Final classification: {ana['final_type']} | confidence {ana['final_conf']:.0%} | "
                            f"risk {ana['risk']} (score {ana['risk_score']:.0f}/100)"])

    plan = plan_response(mem, ana)                                  # 4. DECIDE
    emit("decide", f"AGENT DECISION: {plan['action']}", [plan["reason"]])

    resp = execute_response(mem, plan, ana, src)                    # 5. RESPOND (simulated)
    emit("defend", "SIMULATED DEFENSE", [resp["result"], resp.get("outcome", "")] if resp.get("outcome") else [resp["result"]])
    decision_ms = (time.perf_counter() - t0 - ui[0]) * 1000

    res = learn(mem, feats, det, ana, plan, resp, truth, decision_ms)   # 6-7. REMEMBER + LEARN
    emit("memory", "MEMORY", res["mem_lines"])
    emit("learn", f"LEARNING: {res['status']}", res["learn_lines"])

    retrain_res = maybe_retrain(mem, retrain_every)                  # 8. IMPROVE (real model retraining, periodic)
    if retrain_res:
        emit("retrain", "MODEL RETRAINED (weights actually updated)",
             [f"Random Forest re-fit on base dataset + {retrain_res['n_experiences']} labelled experiences.",
              f"Holdout accuracy (original data): {retrain_res['holdout_acc']:.1%}",
              f"Accuracy on stored experiences: {retrain_res['exp_acc_before']:.0%} before -> {retrain_res['exp_acc_after']:.0%} after (in-sample).",
              f"Classes now known to the model: {', '.join(retrain_res['classes'])}"])

    fast = f"fast path: {ana['analysis_steps']} steps" if ana["path"] == "FAST_MEMORY" else f"{ana['analysis_steps']} analysis steps"
    tl = {"BASELINE": ["Normal traffic", "-> Allowed"],
          "STANDARD": [f"Detected {ana['final_type']} ({ana['final_conf']:.0%})", f"-> {resp['action']}", "-> Pattern stored"],
          "FAST_MEMORY": [f"Similarity detected: {ana['similarity']:.0%}", f"-> Faster classification ({fast})",
                          f"-> {resp['action']}", "-> Pattern reinforced"],
          "FULL_ANALYSIS": ["Unknown suspicious behaviour", f"-> Analysed ({fast})", f"-> {resp['action']} (cautious)",
                            "-> New pattern learned"]}[ana["path"]]
    mem.update_incident(res["incident_id"], steps=json.dumps(steps), timeline=json.dumps(tl))
    return {"dropped": False, "steps": steps, "incident_id": res["incident_id"], "src_ip": src,
            "final_type": ana["final_type"], "final_conf": ana["final_conf"], "risk": ana["risk"],
            "action": resp["action"], "path": ana["path"], "status": res["status"],
            "decision_ms": decision_ms, "retrain": retrain_res}
