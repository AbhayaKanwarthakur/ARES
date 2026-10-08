"""RESPOND: execute the chosen action - SIMULATED ONLY.

Nothing is blocked on a real firewall. 'BLOCK_IP' adds the IP to a table in memory.db that
the local demo app consults. Whether a response "worked" is drawn from a hidden effectiveness
table (a stand-in for real telemetry such as 'did the attack stop?').
"""
import random

RNG = random.Random(7)
EFFECT = {("Brute Force", "BLOCK_IP"): .95, ("Brute Force", "RATE_LIMIT"): .6, ("Brute Force", "REQUIRE_MFA"): .5,
          ("Port Scan", "RATE_LIMIT"): .85, ("Port Scan", "BLOCK_IP"): .8, ("Port Scan", "MONITOR_AND_LEARN"): .4,
          ("SQL Injection", "BLOCK_REQUEST"): .95, ("SQL Injection", "BLOCK_IP"): .85, ("SQL Injection", "RATE_LIMIT"): .4,
          ("DDoS", "RATE_LIMIT_SOURCE"): .88, ("DDoS", "BLOCK_IP"): .7, ("DDoS", "RATE_LIMIT"): .6,
          ("Suspicious Login", "REQUIRE_MFA"): .9, ("Suspicious Login", "BLOCK_IP"): .7,
          ("Suspicious Login", "MONITOR_AND_LEARN"): .4}
NOVEL_EFFECT = {"RATE_LIMIT_SOURCE": .85, "BLOCK_IP": .9, "MONITOR_AND_LEARN": .6}


def execute_response(mem, plan, ana, src_ip):
    a, t = plan["action"], ana["final_type"]
    p = EFFECT.get((t, a)) if t in DEFAULTS_KNOWN else NOVEL_EFFECT.get(a, .6)
    p = p if p is not None else .6
    if a == "ALLOW":
        return {"action": a, "success": True, "result": "Traffic allowed (simulated).", "p": 1.0}
    ok = RNG.random() < p
    if a == "BLOCK_IP":
        mem.add_defense(src_ip, a, t)
        msg = f"IP {src_ip} added to the SIMULATED blocklist."
    elif a in ("RATE_LIMIT", "RATE_LIMIT_SOURCE"):
        mem.add_defense(src_ip, a, t)
        msg = f"Simulated rate limit applied to {src_ip} (10 req/s)."
    elif a == "BLOCK_REQUEST":
        mem.add_defense(src_ip, a, t)
        msg = "Malicious request rejected with a simulated HTTP 403; WAF rule noted."
    elif a == "REQUIRE_MFA":
        mem.add_defense(src_ip, a, t)
        msg = f"Step-up authentication (MFA) enforced for sessions from {src_ip} (simulated)."
    else:
        mem.add_defense(src_ip, a, t)
        msg = f"{src_ip} flagged for monitoring; verbose logging enabled (simulated)."
    outcome = "Outcome: threat contained." if ok else "Outcome: NOT fully contained - the agent will remember this."
    return {"action": a, "success": ok, "result": msg, "outcome": outcome, "p": p}


DEFAULTS_KNOWN = {"Brute Force", "Port Scan", "SQL Injection", "DDoS", "Suspicious Login"}
