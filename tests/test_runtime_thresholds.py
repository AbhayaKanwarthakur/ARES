import unittest

import numpy as np

from agent.analyzer import analyze
from agent.detector import Detector
from agent.features import extract_features, to_vector
from agent.simulator import generate_events, process_event


class FixedProbabilityModel:
    classes_ = np.array(["Normal Traffic", "Brute Force"])

    def predict_proba(self, features):
        return np.array([[0.60, 0.40]])


class RankedMemory:
    def __init__(self, similarity):
        self.similarity = similarity

    def rank_patterns(self, vector):
        return [({
            "name": "Brute Force #1",
            "base_type": "Brute Force",
            "count": 1,
            "confidence": 0.8,
        }, self.similarity)]


def normal_features():
    events = [process_event(event) for event in generate_events("Normal Traffic", n_events=10, seed=10)]
    return extract_features(events)


class RuntimeThresholdTests(unittest.TestCase):
    def test_detector_threshold_override_uses_same_unknown_gate(self):
        features = normal_features()
        vector = np.asarray(to_vector(features))
        detector = object.__new__(Detector)
        detector.fresh = lambda: None
        detector.b = {
            "model": FixedProbabilityModel(),
            "class_stats": {"Normal Traffic": (vector, np.ones_like(vector))},
        }

        default_result = detector.detect(features)
        adjusted_result = detector.detect(features, confidence_threshold=0.55)

        self.assertTrue(default_result["is_unknown"])
        self.assertEqual(default_result["unknown_reason"], "low model confidence (60%)")
        self.assertFalse(adjusted_result["is_unknown"])
        self.assertEqual(adjusted_result["attack_type"], "Normal Traffic")

    def test_memory_threshold_override_changes_only_analysis_path(self):
        features = normal_features()
        detection = {
            "attack_type": "Brute Force",
            "confidence": 0.9,
            "novelty": 0.0,
            "is_unknown": False,
            "raw_label": "Brute Force",
        }
        memory = RankedMemory(0.85)

        recognized = analyze(memory, features, detection, match_threshold=0.80)
        not_recognized = analyze(memory, features, detection, match_threshold=0.90)

        self.assertEqual(recognized["path"], "FAST_MEMORY")
        self.assertEqual(not_recognized["path"], "STANDARD")


if __name__ == "__main__":
    unittest.main()
