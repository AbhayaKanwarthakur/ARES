"""Headless end-to-end test of the agent loop (no Streamlit needed). Uses a temp DB + temp log."""
import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shutil
import agent.detector as D
from agent.memory import Memory
from agent.simulator import DemoApp, generate_events, new_batch_id
from agent.pipeline import run_agent

assert len({new_batch_id() for _ in range(100)}) == 100

tmp = tempfile.mkdtemp()
D.ensure_model()                      # never overwrite the real model during tests
shutil.copy(D.MODEL_PATH, os.path.join(tmp, 'detector.joblib')); D.MODEL_PATH = os.path.join(tmp, 'detector.joblib')
mem, log = Memory(os.path.join(tmp, "m.db")), os.path.join(tmp, "s.log")


def attack(kind, n=15, mutated=False, var=0.15, ip=None, seed=None, retrain_every=0):
    bid = new_batch_id() + str(seed)
    evs = generate_events(kind, n, 5, var, ip, mutated, seed)
    DemoApp(mem, log).run_batch(evs, bid)
    r = run_agent(mem, bid, kind, False, log_path=log, retrain_every=retrain_every)
    if r["dropped"]:
        print(f"{kind:17s} mut={mutated!s:5s} DROPPED by simulated blocklist"); return r
    print(f"{kind:17s} mut={mutated!s:5s} -> {r['final_type']:18s} conf={r['final_conf']:.0%} risk={r['risk']:6s} "
          f"{r['action']:18s} path={r['path']:13s} {r['status']}")
    return r


if __name__ == "__main__":
    print("== Attack 1/2/3: brute force, repeat, modified ==")
    attack("Brute Force", seed=1); attack("Brute Force", seed=2); attack("Brute Force", mutated=True, var=.3, seed=3)
    print("== Novel attack: first vs second encounter ==")
    attack("Novel Attack", seed=4); attack("Novel Attack", seed=5); attack("Novel Attack", seed=6)
    print("== other scenarios ==")
    for i, k in enumerate(["Port Scan", "SQL Injection", "DDoS", "Normal Traffic", "Suspicious Login",
                           "Unknown Suspicious"]):
        attack(k, seed=10 + i)
    print("== blocked IP re-attack ==")
    ip = mem.defenses_df().query("action=='BLOCK_IP'")["ip"].iloc[0]
    attack("Brute Force", ip=ip, seed=20)
    print("== retraining ==")
    from agent.learner import retrain, adaptation_stats
    attack("Brute Force", mutated=True, var=.3, seed=21)
    r = retrain(mem, "smoke test")
    print({k: (round(v, 3) if isinstance(v, float) else v) for k, v in r.items() if k != "classes"}, r["classes"])
    print("== after retraining: novel + modified brute force ==")
    attack("Novel Attack", seed=30); attack("Brute Force", mutated=True, var=.3, seed=31)
    print(adaptation_stats(mem))
    print(mem.patterns()[0]["name"], [(p["name"], p["count"], round(p["confidence"], 2)) for p in mem.patterns()])
