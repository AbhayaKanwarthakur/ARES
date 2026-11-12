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

This repository now explicitly separates the two operating modes:

- `demo` mode: local dashboard, synthetic traffic, and simulator-only features
- `production` mode: the production API service path, guarded by runtime mode checks and policy controls

### Demo mode (local simulation)
#### Windows (PowerShell)
```bash
cd adaptive-security-agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train.py            # optional: the app builds the model on first run
python smoke_test.py       # optional: headless end-to-end test of the whole agent loop
ARES_RUNTIME_MODE=demo python -m streamlit run app.py
```

#### macOS / Linux
```bash
cd adaptive-security-agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python train.py            # optional: the app builds the model on first run
python smoke_test.py       # optional: headless end-to-end test of the whole agent loop
ARES_RUNTIME_MODE=demo python -m streamlit run app.py
```

### Production mode (security service path)
```bash
cd adaptive-security-agent
# Requires a trusted deployment environment and validated secrets.
set ARES_RUNTIME_MODE=production
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

The dashboard and synthetic simulator are intentionally unavailable in production mode. This prevents a demo system from being mistaken for an operational security system.

## Project layout
```
app.py                 Streamlit SOC dashboard + Demo Attack Lab + Attack Replay
agent/testing_mode.py  bounded automated scenario-vs-agent runs in the local sandbox
train.py               builds the synthetic dataset and trains the baseline Random Forest
smoke_test.py          headless test (temp DB, never touches your real memory/model)
agent/features.py      event window → feature vector; normalisation; similarity
agent/event_schema.py  validated synthetic events (RFC 5737 source addresses only)
agent/simulator.py     local sandbox demo app + synthetic attack generators + dataset builder
agent/detector.py      Random Forest + "is this unfamiliar?" check (low confidence / outlier)
agent/analyzer.py      compares with memory, picks FAST / STANDARD / FULL analysis path, scores risk
agent/planner.py       default playbook + outcome-based action preference (rule adaptation)
agent/responder.py     SIMULATED defence execution + simulated outcome
agent/memory.py        SQLite: incidents, patterns, action stats, defences, retraining log
agent/learner.py       pattern learning, statistics, periodic REAL model retraining
agent/pipeline.py      orchestrates the full loop and emits step-by-step events for the UI
agent/settings.py      validated settings loader for persistent, dynamic runtime options
config/settings.json   editable dashboard presets and detector / memory thresholds
api/                   authenticated passive scoring API for approved website backends
migrations/             versioned PostgreSQL schema migrations
data/                  attacks.csv, security.log (sandbox log), memory.db (created at runtime)
models/                detector.joblib
```

## Dynamic runtime settings
The dashboard's **Agent settings** panel persists operating options in `config/settings.json`.
Edit settings in the dashboard and select **Save settings**, or update that JSON file directly.
It controls the existing confidence and novelty gates, memory-match threshold, analysis and
dashboard animation delays, periodic retraining interval, replay defaults, and editable quick-launch presets.
Quick-launch presets can be added, removed, or reordered and must use one of the synthetic
scenario types already supported by the simulator.

These settings do not replace the detector, analysis paths, response playbook, or the three
documented adaptation mechanisms. They only tune the current thresholds and UI/runtime options.
Memory and rule learning still do not alter model weights; only the existing Random Forest
retraining operation does. Invalid settings are reported rather than silently replaced.

## Testing Mode
Open the dashboard's **Testing Mode** tab, choose built-in synthetic scenarios and rounds,
then run the sandbox test. Each generated event batch goes to the in-process demo application
and through the same detection, analysis, response, memory, and learning pipeline used by the
Demo Attack Lab. The results show the selected scenario, agent response, simulated containment,
and learning status. Runs are capped at 20 cases and use documentation-range source IPs.
This mode does not include exploit code, accept targets, open sockets, or contact real systems.

## Passive website integration service
The API is a separate, opt-in backend service. It accepts a bounded **aggregate feature window**,
not raw HTTP requests, logs, credentials, or target addresses. It returns a classification,
confidence, novelty/risk assessment, and an action recommendation from the existing playbook.
Recommendations are passive only: this service never executes a response. The endpoint requires
a tenant-scoped bearer key, requires a client-generated UUID `event_id` for retry-safe
idempotency, and persists score records in PostgreSQL. Reusing an event ID for the same tenant
returns the existing result.

The website's server-side backend is responsible for authenticating its users, aggregating
appropriate security telemetry into the documented feature fields, calling this API over TLS,
and handling its response. Do not call it with a browser-held API key. Do not forward secrets or
full request bodies. The scores are prototype results, not a blocking policy or a production
security guarantee.

### Start the local Docker Compose pilot (Windows PowerShell)
Install Docker Desktop, then from the project directory generate local-only secrets:

```powershell
python -c "import json,pathlib,secrets; p=pathlib.Path('secrets'); p.mkdir(exist_ok=True); (p/'postgres_password.txt').write_text(secrets.token_urlsafe(48), encoding='utf-8'); key=secrets.token_urlsafe(48); (p/'api_keys.json').write_text(json.dumps([{'key_id':'local-website','tenant_id':'website-local','secret':key}], indent=2), encoding='utf-8'); print('Website backend bearer key:', key)"
docker compose up --build -d
docker compose ps
Invoke-RestMethod http://localhost:8000/health/ready
```

`secrets/` is excluded from Git. The database password is mounted as a Docker secret rather
than passed in the API's environment. Store the generated bearer key only in the **website
backend's** secret manager; never put it in frontend code. The Compose API port
binds to localhost and its internal Docker network is private. Before remote deployment, place
the service behind a TLS-terminating reverse proxy or private service network with ingress
restrictions, request-rate limits, monitoring, and an operational secret-rotation process.
Configure production PostgreSQL TLS, backups, retention, and restore testing. Do not expose
PostgreSQL directly to the internet. The API container runs as non-root with a read-only
filesystem, and the API's direct Python dependencies are pinned in `requirements-api.txt`.
Review and update those pins through a tested dependency-update process; also pin base-image
digests and scan images/dependencies before a real release. The detector file is a trusted
joblib/pickle artifact: only load one produced and integrity-checked by your own trusted
training/release pipeline, because loading an untrusted artifact can execute code.
The detector now records its `scikit-learn` version and artifact format in the model payload,
and automatically retrains if the saved artifact was created with a different runtime. This
prevents stale model files from silently producing incompatible or warning-heavy predictions.

### Score a synthetic/aggregated event window
The endpoint is `POST /v1/windows/score`. Required features match the existing 11-feature
classifier input:

```json
{
  "event_id": "d5df90f9-e092-4f4b-9da4-5c4579d96dbe",
  "features": {
    "destination_port": 22,
    "protocol": "SSH",
    "packets_per_second": 35.0,
    "failed_login_count": 8,
    "request_count": 8,
    "payload_length": 80.0,
    "connection_duration": 0.6,
    "unusual_port": 0.0,
    "login_frequency": 2.0,
    "special_char_ratio": 0.04,
    "distinct_ports": 1
  }
}
```

The authenticated response includes `classification`, `confidence`, `risk`, `is_unknown`,
`recommendation`, `recommendation_reason`, and the detector model's SHA-256 version. A
recommendation describes what the playbook would suggest; no firewall, account, website, or
simulated-defense state is changed by this API.

For local API development only, install `requirements-api.txt`, provision the same environment
variables and a local PostgreSQL database, apply `python -m alembic upgrade head`, then run
`uvicorn api.main:app --host 127.0.0.1 --port 8000`. Interactive API docs are disabled by
default; set `ARES_ENABLE_API_DOCS=true` only in a trusted local development environment.

## Phase 3: reinforcement-learning pipeline
The optional Gymnasium environment and Stable-Baselines3 DQN train exclusively on
synthetic scenarios. Its seven-dimensional observation excludes scenario labels; reward
feedback uses labels only inside the simulator. Actions are monitor, alert, simulated
rate-limit, simulated temporary block, and human review. The environment documents its
reward costs and efficacy in `agent/rl_env.py`; disruption penalties for false blocking
are deliberately larger than verified-containment rewards, preventing a block-everything
policy from maximizing reward.

```powershell
python -m pip install -r requirements.txt
python train_rl.py --smoke
python train_rl.py --timesteps 10000 --eval-episodes 50 --seed 7
python -m unittest discover -s tests -v
```

Training saves `models/ares_dqn.zip`, episode reward/length rows to
`data/ares_rl_episodes.csv`, and held-out trained-vs-fixed-rule metrics to
`data/ares_rl_evaluation.json`. Both policies use the same held-out seeds; DQN
evaluation is deterministic and does not update model parameters.

## Simulation and detection baseline
The simulator generates seeded, reproducible traffic windows including normal activity,
port scans, brute-force login attempts, traffic spikes, and traffic floods. Legitimate
unusual activity is also generated deliberately; its burst can be flagged by the
rule-based baseline to demonstrate a false positive. `agent.event_schema` validates
simulated events, and `agent.features` extracts agent-visible features and evaluates
the rules. Simulator ground-truth labels are attached only to dataset rows as
`attack_type`; they are not included in event dictionaries or extracted features.
The existing Random Forest remains the main classifier, with the rule baseline shown
alongside its output.

Run the Phase 2 tests from the project directory:
```bash
python -m unittest discover -s tests -v
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
