"""DECIDE: pick a response. Starts from a default playbook, then adapts using outcome history.

RULE ADAPTATION: each (attack type, action) pair keeps tries/successes in memory. The planner
scores every candidate action as a smoothed success rate that starts from a prior (default
action = 0.7, others = 0.5) and moves with evidence -> if the default stops working, it
switches. This is NOT ML retraining; it is learned preference.
"""
DEFAULTS = {"Brute Force": "BLOCK_IP", "Port Scan": "RATE_LIMIT", "SQL Injection": "BLOCK_REQUEST",
            "DDoS": "RATE_LIMIT_SOURCE", "Suspicious Login": "REQUIRE_MFA",
            "Unknown Suspicious": "MONITOR_AND_LEARN", "Normal Traffic": "ALLOW"}
CANDIDATES = {"Brute Force": ["BLOCK_IP", "RATE_LIMIT", "REQUIRE_MFA"],
              "Port Scan": ["RATE_LIMIT", "BLOCK_IP", "MONITOR_AND_LEARN"],
              "SQL Injection": ["BLOCK_REQUEST", "BLOCK_IP", "RATE_LIMIT"],
              "DDoS": ["RATE_LIMIT_SOURCE", "BLOCK_IP", "RATE_LIMIT"],
              "Suspicious Login": ["REQUIRE_MFA", "BLOCK_IP", "MONITOR_AND_LEARN"]}
NOVEL_CANDIDATES = ["RATE_LIMIT_SOURCE", "BLOCK_IP", "MONITOR_AND_LEARN"]


def plan_response(mem, ana):
    t = ana["final_type"]
    if t == "Normal Traffic":
        return {"action": "ALLOW", "default": "ALLOW", "adapted": False, "scores": {},
                "reason": "Traffic matches the normal baseline, so it is allowed through."}
    if t == "Unknown Suspicious":
        return {"action": "MONITOR_AND_LEARN", "default": "MONITOR_AND_LEARN", "adapted": False, "scores": {},
                "reason": (f"The behaviour is unfamiliar (risk {ana['risk']}, score {ana['risk_score']:.0f}). "
                           "Without evidence, blocking could hit legitimate users, so I choose a cautious "
                           "response: flag the source, log verbosely and learn the pattern.")}
    novel = t.startswith("Novel-")
    cands = NOVEL_CANDIDATES if novel else CANDIDATES.get(t, NOVEL_CANDIDATES)
    default = "RATE_LIMIT_SOURCE" if novel else DEFAULTS.get(t, "RATE_LIMIT_SOURCE")
    stats = mem.action_stats(t)
    scores, hist = {}, []
    for a in cands:
        tries, succ = stats.get(a, (0, 0))
        prior = 0.7 if a == default else (0.4 if (novel and a == "MONITOR_AND_LEARN") else 0.5)
        scores[a] = round((succ + 2 * prior) / (tries + 2), 3)
        if tries:
            hist.append(f"{a} worked {succ}/{tries}")
    best = max(scores, key=scores.get)
    adapted = best != default
    why = f"{t} (risk {ana['risk']}) -> default playbook says {default}."
    if novel:
        why = (f"{t} is a learned pattern. It is now understood well enough to act firmly: "
               f"{default} is the learned default for novel patterns.")
    if hist:
        why += " Past outcomes: " + ", ".join(hist) + "."
    if adapted:
        why += f" RULE ADAPTED: switching to {best} because its success estimate ({scores[best]:.0%}) beats the default's ({scores[default]:.0%})."
    return {"action": best, "default": default, "adapted": adapted, "scores": scores, "reason": why}
