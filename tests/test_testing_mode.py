import os
import tempfile
import unittest

from agent.memory import Memory
from agent.testing_mode import MAX_TEST_CASES, run_test_campaign, validate_test_plan


class TestingModePlanTests(unittest.TestCase):
    def test_valid_plan_reports_number_of_cases(self):
        self.assertEqual(validate_test_plan(["Brute Force", "Normal Traffic"], 2, 20), 4)

    def test_empty_or_unsupported_scenarios_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one"):
            validate_test_plan([], 1, 10)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            validate_test_plan(["external target"], 1, 10)

    def test_bounds_and_total_case_limit_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "Rounds"):
            validate_test_plan(["Brute Force"], 6, 10)
        with self.assertRaisesRegex(ValueError, "Events"):
            validate_test_plan(["Brute Force"], 1, 41)
        with self.assertRaisesRegex(ValueError, str(MAX_TEST_CASES)):
            validate_test_plan(
                ["Brute Force", "Port Scan", "DDoS", "Normal Traffic", "SQL Injection"], 5, 10)

    def test_campaign_uses_only_the_local_sandbox_and_persists_agent_result(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = os.path.join(directory, "security.log")
            mem = Memory(os.path.join(directory, "memory.db"))
            results = run_test_campaign(
                mem, ["Normal Traffic"], 1, 5, log_path=log_path, retrain_every=0)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["scenario"], "Normal Traffic")
            self.assertEqual(results[0]["classification"], "Normal Traffic")
            self.assertTrue(results[0]["response_success"])
            self.assertFalse(results[0]["contained"])
            self.assertEqual(len(mem.incidents_df()), 1)
            with open(log_path, encoding="utf-8") as source:
                self.assertNotIn("secret", source.read())


if __name__ == "__main__":
    unittest.main()
