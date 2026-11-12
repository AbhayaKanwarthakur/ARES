"""Bounded adversary-versus-defender tests using the local synthetic sandbox only."""
from .pipeline import run_agent
from .simulator import KINDS, LOG_PATH, DemoApp, generate_events, new_batch_id, new_ip

MAX_TEST_CASES = 20


def validate_test_plan(scenarios, rounds, events_per_scenario):
    """Reject empty, unsupported, or oversized simulation plans."""
    if not scenarios:
        raise ValueError("Select at least one synthetic scenario.")
    unsupported = sorted(set(scenarios) - set(KINDS))
    if unsupported:
        raise ValueError(f"Unsupported synthetic scenario(s): {', '.join(unsupported)}.")
    if isinstance(rounds, bool) or not isinstance(rounds, int) or not 1 <= rounds <= 5:
        raise ValueError("Rounds must be an integer between 1 and 5.")
    if (isinstance(events_per_scenario, bool) or not isinstance(events_per_scenario, int)
            or not 5 <= events_per_scenario <= 40):
        raise ValueError("Events per scenario must be an integer between 5 and 40.")
    total = len(scenarios) * rounds
    if total > MAX_TEST_CASES:
        raise ValueError(f"A test run is limited to {MAX_TEST_CASES} scenarios.")
    return total


def run_test_campaign(mem, scenarios, rounds, events_per_scenario, *, log_path=LOG_PATH,
                      retrain_every=10, confidence_threshold=0.65,
                      outlier_threshold=3.0, match_threshold=0.90,
                      thinking_delay_seconds=0.22, on_trial=None):
    """Run generated scenarios through the demo app and defensive agent, never the network."""
    total = validate_test_plan(scenarios, rounds, events_per_scenario)
    demo_app = DemoApp(mem, log_path)
    results = []

    for round_number in range(1, rounds + 1):
        for scenario in scenarios:
            batch_id = new_batch_id()
            source_ip = new_ip()
            events = generate_events(
                scenario, n_events=events_per_scenario, src_ip=source_ip)
            demo_app.run_batch(events, batch_id)
            outcome = run_agent(
                mem, batch_id, scenario, log_path=log_path, retrain_every=retrain_every,
                confidence_threshold=confidence_threshold,
                outlier_threshold=outlier_threshold,
                match_threshold=match_threshold,
                thinking_delay_seconds=thinking_delay_seconds,
            )
            incident = mem.latest_incident() if outcome.get("incident_id") else None
            row = {
                "round": round_number,
                "scenario": scenario,
                "source_ip": source_ip,
                "classification": outcome.get("final_type", "Rejected by simulated blocklist"),
                "risk": outcome.get("risk", "-"),
                "response": outcome.get("action", "SIMULATED BLOCKLIST"),
                "response_success": bool(incident["success"]) if incident else False,
                "contained": bool(incident["success"]) if incident and scenario != "Normal Traffic" else False,
                "status": outcome.get("status", "No new analysis"),
                "incident_id": outcome.get("incident_id"),
            }
            results.append(row)
            if on_trial:
                on_trial(len(results), total, row)
    return results
