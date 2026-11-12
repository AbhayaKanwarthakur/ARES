import unittest

import joblib
import sklearn

from agent.detector import Detector, MODEL_PATH
from agent.event_schema import validate_event
from agent.features import detect_rules, extract_features
from agent.simulator import generate_events, process_event


def feature_window(kind, seed):
    events = [process_event(event) for event in generate_events(kind, n_events=20, seed=seed)]
    return events, extract_features(events)


class SimulationPipelineTests(unittest.TestCase):
    def test_schema_accepts_generated_event_and_rejects_public_ip(self):
        event = generate_events("Normal Traffic", n_events=1, seed=4)[0]
        self.assertIs(validate_event(event), event)
        invalid = dict(event, src_ip="8.8.8.8")
        with self.assertRaisesRegex(ValueError, "RFC 5737"):
            validate_event(invalid)

    def test_feature_extraction_rejects_empty_window(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            extract_features([])

    def test_generation_is_reproducible(self):
        self.assertEqual(
            generate_events("Port Scan", n_events=10, seed=21),
            generate_events("Port Scan", n_events=10, seed=21),
        )

    def test_rules_detect_expected_patterns_and_legitimate_false_positive(self):
        _, normal = feature_window("Normal Traffic", 1)
        _, scan = feature_window("Port Scan", 2)
        brute_events, brute = feature_window("Brute Force", 3)
        _, flood = feature_window("Traffic Flood", 4)
        benign_events, benign_burst = feature_window("Legitimate Unusual Activity", 5)

        self.assertEqual(detect_rules(normal)["label"], "Normal Traffic")
        self.assertEqual(detect_rules(scan)["label"], "Port Scan")
        self.assertEqual(detect_rules(brute)["label"], "Brute Force")
        self.assertEqual(detect_rules(flood)["label"], "Traffic Flood")
        self.assertEqual(detect_rules(benign_burst)["label"], "Traffic Spike")
        self.assertTrue(detect_rules(benign_burst)["is_anomaly"])
        self.assertNotIn("ground_truth", benign_events[0])
        self.assertNotIn("attack_type", benign_events[0])
        self.assertNotIn("ground_truth", benign_burst)
        self.assertNotIn("attack_type", benign_burst)

    def test_model_payload_tracks_runtime_version(self):
        detector = Detector()
        self.assertIsNotNone(detector)
        payload = joblib.load(MODEL_PATH)
        self.assertEqual(payload["artifact_format"], 1)
        self.assertEqual(payload["sklearn_version"], sklearn.__version__)
        self.assertIn("model", payload)


if __name__ == "__main__":
    unittest.main()
