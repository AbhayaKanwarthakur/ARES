"""Validated, persistent configuration for the dashboard and agent thresholds."""
import copy
import json
import os
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")

DEFAULT_SETTINGS = {
    "version": 1,
    "detector": {
        "confidence_threshold": 0.65,
        "outlier_threshold": 3.0,
    },
    "analysis": {
        "memory_match_threshold": 0.90,
    },
    "dashboard": {
        "thinking_delay_enabled": True,
        "thinking_delay_seconds": 0.22,
        "step_animation_delay_seconds": 0.45,
        "auto_retrain_every": 10,
        "default_event_count": 20,
        "default_intensity": 5,
        "default_variation": 0.15,
        "quick_launch": [
            {"label": "Simulate Brute Force", "kind": "Brute Force", "events": 12,
             "intensity": 5, "variation": 0.15, "mutated": False},
            {"label": "Simulate Port Scan", "kind": "Port Scan", "events": 25,
             "intensity": 5, "variation": 0.15, "mutated": False},
            {"label": "Simulate SQL Injection Attempt", "kind": "SQL Injection", "events": 10,
             "intensity": 5, "variation": 0.15, "mutated": False},
            {"label": "Simulate DDoS-like Traffic Spike", "kind": "DDoS", "events": 15,
             "intensity": 5, "variation": 0.15, "mutated": False},
            {"label": "Simulate Unknown/Novel Attack", "kind": "Novel Attack", "events": 10,
             "intensity": 5, "variation": 0.15, "mutated": False},
            {"label": "Generate Normal Traffic", "kind": "Normal Traffic", "events": 12,
             "intensity": 5, "variation": 0.15, "mutated": False},
        ],
    },
}


def _validate(settings):
    if (not isinstance(settings, dict) or isinstance(settings.get("version"), bool)
            or settings.get("version") != 1):
        raise ValueError("Settings must be an object with supported version 1.")
    for section in ("detector", "analysis", "dashboard"):
        if not isinstance(settings.get(section), dict):
            raise ValueError(f"Settings section '{section}' must be an object.")

    detector = settings["detector"]
    _number(detector, "confidence_threshold", 0.30, 0.95)
    _number(detector, "outlier_threshold", 0.5, 10.0)
    _number(settings["analysis"], "memory_match_threshold", 0.50, 1.0)

    dashboard = settings["dashboard"]
    if not isinstance(dashboard.get("thinking_delay_enabled"), bool):
        raise ValueError("'thinking_delay_enabled' must be a boolean.")
    _number(dashboard, "thinking_delay_seconds", 0.0, 1.0)
    _number(dashboard, "step_animation_delay_seconds", 0.0, 2.0)
    _integer(dashboard, "auto_retrain_every", 0, 30)
    _integer(dashboard, "default_event_count", 5, 60)
    _integer(dashboard, "default_intensity", 1, 10)
    _number(dashboard, "default_variation", 0.0, 1.0)

    presets = dashboard.get("quick_launch")
    if not isinstance(presets, list):
        raise ValueError("'quick_launch' must be a list.")
    labels = set()
    for index, preset in enumerate(presets):
        if not isinstance(preset, dict):
            raise ValueError(f"Quick-launch preset {index + 1} must be an object.")
        for key in ("label", "kind"):
            if not isinstance(preset.get(key), str) or not preset[key].strip():
                raise ValueError(f"Quick-launch preset {index + 1} needs a non-empty '{key}'.")
        if preset["label"] in labels:
            raise ValueError(f"Quick-launch labels must be unique: '{preset['label']}'.")
        labels.add(preset["label"])
        _integer(preset, "events", 3, 60)
        _integer(preset, "intensity", 1, 10)
        _number(preset, "variation", 0.0, 1.0)
        if not isinstance(preset.get("mutated"), bool):
            raise ValueError(f"Quick-launch preset {index + 1} 'mutated' must be a boolean.")


def _number(section, key, minimum, maximum):
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"'{key}' must be a number.")
    if not minimum <= value <= maximum:
        raise ValueError(f"'{key}' must be between {minimum} and {maximum}.")


def _integer(section, key, minimum, maximum):
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"'{key}' must be an integer.")
    if not minimum <= value <= maximum:
        raise ValueError(f"'{key}' must be between {minimum} and {maximum}.")


def _with_defaults(settings):
    if not isinstance(settings, dict):
        raise ValueError("Settings file must contain a JSON object.")
    merged = copy.deepcopy(DEFAULT_SETTINGS)
    for section in ("detector", "analysis", "dashboard"):
        supplied = settings.get(section)
        if not isinstance(supplied, dict):
            raise ValueError(f"Settings section '{section}' must be an object.")
        merged[section].update(supplied)
    merged["version"] = settings.get("version")
    return merged


def load_settings(path=SETTINGS_PATH):
    """Load current settings, filling newly added options from safe defaults."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        settings = copy.deepcopy(DEFAULT_SETTINGS)
        save_settings(settings, path)
        return settings
    with open(path, encoding="utf-8") as source:
        stored = json.load(source)
    settings = _with_defaults(stored)
    _validate(settings)
    return settings


def save_settings(settings, path=SETTINGS_PATH):
    """Validate and atomically persist settings so edits cannot leave partial JSON."""
    candidate = _with_defaults(settings)
    _validate(candidate)
    path = os.path.abspath(path)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                         delete=False) as target:
            temporary_path = target.name
            json.dump(candidate, target, indent=2)
            target.write("\n")
        os.replace(temporary_path, path)
    finally:
        if temporary_path and os.path.exists(temporary_path):
            os.remove(temporary_path)
