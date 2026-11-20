# Adaptive Security Agent: 90-Second Demo

## Before you start

Open this folder in VS Code and run the **Run Adaptive Security Agent** configuration.
The dashboard is a safe local simulation: no real traffic is sent and no real system is blocked.

## Presenter script

### 0:00 — Introduce the project

> “This is an adaptive SOC prototype. It receives synthetic attack events, detects the pattern,
> chooses a response, stores what it learned, and becomes faster on repeated attacks.”

### 0:15 — Show a first attack

1. Open **Demo Attack Lab**.
2. Click **Simulate Brute Force**.
3. Point out the chain: **Detect → Analyze → Decide → Respond → Remember → Learn**.

Say:

> “The agent classified the brute-force pattern and selected `BLOCK_IP`. This is simulated containment
> recorded in the local sandbox, not a real firewall rule.”

### 0:35 — Show adaptation

1. Click **Simulate Brute Force** again.
2. Open **Learning Timeline** or **Analytics & Adaptation**.

Say:

> “Because the pattern is remembered, the second encounter uses the faster memory path and needs fewer
> analysis steps.”

### 0:55 — Show an unfamiliar attack

1. Click **Simulate Unknown/Novel Attack**.
2. Point out the cautious `MONITOR_AND_LEARN` response.

Say:

> “For unfamiliar behavior, the agent avoids overreacting, monitors it, and creates a new pattern.”

### 1:10 — Show the simulated blocklist

1. Enable **Reuse the previous attacker IP**.
2. Run **Simulate Brute Force** once more.

Say:

> “The sandbox now rejects the reused source because the simulated blocklist remembers it.”

### 1:20 — Close with the value

Open **Analytics & Adaptation** and say:

> “The project demonstrates detection, response selection, memory adaptation, and model retraining in one
> explainable workflow. In a production system, the simulated defenses would be replaced by approved,
> monitored firewall, WAF, or IAM integrations.”

## Important wording

Say **“simulated containment”** or **“sandbox response”**, not **“we stopped a real hacker.”**
