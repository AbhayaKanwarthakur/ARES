import copy
import json
import os
import tempfile
import unittest

from agent.runtime_mode import get_runtime_mode, require_demo_mode, require_production_mode
from agent.settings import DEFAULT_SETTINGS, load_settings, save_settings


class SettingsTests(unittest.TestCase):
    def test_missing_settings_file_is_created_with_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            self.assertEqual(load_settings(path), DEFAULT_SETTINGS)
            self.assertTrue(os.path.isfile(path))

    def test_settings_round_trip_and_default_merging(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            settings = copy.deepcopy(DEFAULT_SETTINGS)
            settings["analysis"]["memory_match_threshold"] = 0.93
            save_settings(settings, path)
            self.assertEqual(load_settings(path), settings)

            with open(path, "w", encoding="utf-8") as target:
                json.dump({"version": 1, "analysis": {"memory_match_threshold": 0.93},
                           "detector": {}, "dashboard": {}}, target)
            loaded = load_settings(path)
            self.assertEqual(loaded["analysis"]["memory_match_threshold"], 0.93)
            self.assertEqual(loaded["dashboard"], DEFAULT_SETTINGS["dashboard"])

    def test_invalid_settings_are_rejected_without_overwriting_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            original = copy.deepcopy(DEFAULT_SETTINGS)
            save_settings(original, path)
            invalid = copy.deepcopy(original)
            invalid["detector"]["confidence_threshold"] = 1.5

            with self.assertRaisesRegex(ValueError, "confidence_threshold"):
                save_settings(invalid, path)
            self.assertEqual(load_settings(path), original)

    def test_malformed_json_shape_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "settings.json")
            with open(path, "w", encoding="utf-8") as target:
                json.dump([], target)
            with self.assertRaisesRegex(ValueError, "JSON object"):
                load_settings(path)

    def test_runtime_mode_enforces_demo_and_production_safely(self):
        original = os.environ.get("ARES_RUNTIME_MODE")
        try:
            os.environ.pop("ARES_RUNTIME_MODE", None)
            self.assertEqual(get_runtime_mode(), "demo")
            os.environ["ARES_RUNTIME_MODE"] = "production"
            self.assertEqual(get_runtime_mode(), "production")
            with self.assertRaisesRegex(RuntimeError, "disabled in production mode"):
                require_demo_mode()
            require_production_mode()
            os.environ["ARES_RUNTIME_MODE"] = "staging"
            with self.assertRaisesRegex(ValueError, "ARES_RUNTIME_MODE"):
                get_runtime_mode()
        finally:
            if original is None:
                os.environ.pop("ARES_RUNTIME_MODE", None)
            else:
                os.environ["ARES_RUNTIME_MODE"] = original


if __name__ == "__main__":
    unittest.main()
