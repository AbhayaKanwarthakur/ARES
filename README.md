# 🛡️ Adaptive Security Agent

A defensive, **fully simulated** agentic-AI prototype. It detects attacks in a local sandbox, analyses them,
chooses a response, remembers the attack and gets better at recognising repeats and variants.

```
ATTACK LOG → DETECT → ANALYZE → DECIDE → RESPOND → REMEMBER → LEARN → IMPROVE
```

## Safety
- All traffic is **synthetic**. The "demo application" is an in-process Python object: **no sockets, no network**.
- Source IPs come only from RFC 5737 documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`).
- Credentials are fake strings (`guess-3`, `demo-pass-A`) and are never written to the log.
- "Blocking" = a row in a local SQLite table the sandbox app consults. Nothing real is blocked, scanned, exploited or stolen.
- There is no code that accepts a target address, so it cannot be pointed at anything else.

## Install & run
```bash
cd adaptive-security-agent
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python train.py            # optional: builds data/attacks.csv + models/detector.joblib (the app does it on first run)
python smoke_test.py       # optional: headless end-to-end test of the whole agent loop
streamlit run app.py
```

## Project layout
```
app.py                 Streamlit SOC dashboard + Demo Attack Lab + Attack Replay
train.py               builds the synthetic dataset and trains the baseline Random Forest
smoke_test.py          headless test (temp DB, never touches your real memory/model)
agent/features.py      event window → feature vector; normalisation; similarity
agent/simulator.py     local sandbox demo app + synthetic attack generators + dataset builder
agent/detector.py      Random Forest + "is this unfamiliar?" check (low confidence / outlier)
agent/analyzer.py      compares with memory, picks FAST / STANDARD / FULL analysis path, scores risk
agent/planner.py       default playbook + outcome-based action preference (rule adaptation)
agent/responder.py     SIMULATED defence execution + simulated outcome
agent/memory.py        SQLite: incidents, patterns, action stats, defences, retraining log
agent/learner.py       pattern learning, statistics, periodic REAL model retraining
agent/pipeline.py      orchestrates the full loop and emits step-by-step events for the UI
data/                  attacks.csv, security.log (sandbox log), memory.db (created at runtime)
models/                detector.joblib
```

## Architecture
1. **Sandbox app (`simulator.py`)** receives synthetic events one by one, decides an outcome (`login_failed`, `http_200`…)
   and appends a JSON line to `data/security.log`. If the source IP is on the simulated blocklist, events are rejected.
2. **Detection** reads the batch back *from the log file*, aggregates it into one feature vector (failed logins,
   packets/s, payload size, distinct ports, login frequency, …) and a Random Forest classifies it. A window is
   declared **Unknown** if confidence < 65 % *or* it is far from every known class (random forests are over-confident
   on unfamiliar inputs, so the outlier check matters).
3. **Analysis** fingerprints the window and compares it with every learned pattern (similarity 0–100 %).
   ≥ 90 % → *recognised*. It then chooses how much thinking is needed:
   `FAST_MEMORY` (2 steps) · `STANDARD` (4) · `FULL_ANALYSIS` (6) · `BASELINE` (2).
4. **Planner** picks an action from a playbook, adjusted by what has worked before.
5. **Responder** executes the action *in simulation* and returns whether it "contained" the threat.
6. **Memory + Learner** store the incident, create or reinforce a pattern, update action statistics and
   periodically retrain the model.

## How the system adapts - three distinct mechanisms
| Mechanism | What changes | Changes ML weights? |
|---|---|---|
| **Memory adaptation** | `patterns` table: fingerprints stored; each repeat raises the pattern's confidence and moves its centroid. A repeat or near-repeat is recognised **even if the model has never seen it**. | ❌ No |
| **Rule adaptation** | `action_stats` table: planner scores each response as a smoothed success rate (prior 0.7 for the default, 0.5 others). If the default stops working, it switches. | ❌ No |
| **Model retraining** | Random Forest is **really re-fit** on the original data + labelled experiences from memory (jittered ×15). Runs automatically every *N* experiences (sidebar) or via the "Retrain" button. | ✅ Yes |

The dashboard labels each step with the adaptation type, and shows retraining separately with before/after numbers.

**Labels for retraining** come from the simulator's ground truth (standing in for analyst feedback). For novel attacks
the label is the family name the agent assigned (`Novel-A`), and only after it has been seen ≥ 2 times.
The "before → after" experience accuracy is *in-sample* (the model was trained on those rows) - it shows the model
absorbed the experience, not that it generalises.

## 2-minute demo script
1. *(0:00)* "This is a SOC for an agent that learns. Everything is a local simulation." Point at the KPI row.
2. *(0:15)* **🔴 Simulate Brute Force.** Watch events stream into the log, then the chain: detection → analysis (4 steps) → BLOCK_IP → "NEW PATTERN LEARNED".
3. *(0:35)* Click it **again.** "Similarity 9x %, fast path, 2 steps, confidence up." Open **Learning Timeline**.
4. *(0:55)* **🟣 Simulate Unknown/Novel Attack.** "Unknown suspicious behaviour - the model has never seen this." It profiles it, picks the *cautious* MONITOR_AND_LEARN, stores a new pattern (~56 % confidence).
5. *(1:15)* Click novel **again.** "Recognised from memory at ~97 % similarity → Novel-A, 78 % confidence, firm response, 2 steps instead of 6." Show the **First vs latest encounter** panel. Click a third time: ~88 %.
6. *(1:35)* **💉 Inject New Attack** (a modified brute force: slower, different port). "Doesn't match memory → analysed → new variant learned."
7. *(1:45)* Tick **Reuse the previous attacker IP** and run Brute Force: "Dropped by the simulated blocklist from earlier."
8. *(1:50)* **Analytics tab:** memory / rule / retraining panels. Press **Retrain model now:** "Only this changes model weights - and we show before/after."

## Why this is an *agentic* AI prototype
- **Autonomy:** it perceives events, decides and acts with no human in the loop.
- **Goal-directed, multi-step reasoning:** a pipeline of detect → analyse → plan → act, with the depth of analysis chosen per situation.
- **Tool use / actions on an environment:** it acts on the sandbox (blocklist, rate limits) and observes the result.
- **Memory:** persistent episodic memory (incidents) and semantic memory (patterns) that survives restarts.
- **Feedback-driven adaptation:** outcomes change future behaviour (action preference, pattern confidence, model retraining).

*Honest caveat:* the "reasoning" is rule-and-statistics based, not an LLM. An LLM could be added to the analyzer for richer explanations.

## Known limitations
- Synthetic data is cleanly separable, so hold-out accuracy is ~100 %. Real traffic will not be.
- "Did the response work?" is simulated from a hidden effectiveness table; in production it would come from telemetry.
- Similarity uses 9 hand-picked features and a fixed threshold; SQLite is single-node.

## Production improvements
Real log ingestion (Zeek/Suricata/syslog) and streaming windows · analyst feedback loop for labels · drift monitoring and
model versioning with shadow/canary rollout · proper open-set / anomaly models (isolation forest, autoencoders) ·
real enforcement via firewall/WAF/IAM APIs with approval gates and automatic rollback · LLM-generated incident reports
with guardrails · per-tenant memory, vector search for pattern retrieval · RBAC, audit logging, tests/CI.
