"""Feature extraction + normalisation shared by the simulator, detector, analyzer and memory.

An *event window* (a batch of log events from one source) is turned into ONE feature
dictionary. That dictionary is what the ML model classifies and what memory fingerprints.
"""
import math
import os
from collections import Counter

import numpy as np

from .event_schema import validate_event

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
MODEL_DIR = os.path.join(ROOT, "models")

COMMON_PORTS = {22, 53, 80, 443, 8080}
PROTO_CODE = {"TCP": 0, "UDP": 1, "HTTP": 2, "SSH": 3}

# Columns the Random Forest sees
FEATURES = [
    "destination_port", "protocol", "packets_per_second", "failed_login_count",
    "request_count", "payload_length", "connection_duration", "unusual_port",
    "login_frequency", "special_char_ratio", "distinct_ports",
]

# Features used to FINGERPRINT an attack for similarity: (name, use_log_scale, cap)
SIM_SPEC = [
    ("packets_per_second", True, 10000), ("failed_login_count", True, 60),
    ("request_count", True, 20000), ("payload_length", True, 8000),
    ("connection_duration", True, 400), ("unusual_port", False, 1.0),
    ("login_frequency", True, 20), ("special_char_ratio", False, 0.5),
    ("distinct_ports", True, 100),
]
SIM_SCALE = 0.40  # RMS distance (in 0..1 space) at which similarity drops to 0


def extract_features(events):
    """Aggregate a list of processed log events into one feature dict."""
    if not events:
        raise ValueError("events must contain at least one event")
    for event in events:
        validate_event(event)
    n = len(events)
    ports = [e["dst_port"] for e in events]
    logins = [e for e in events if e["event_type"] == "login"]
    failed = sum(1 for e in logins if e["outcome"] == "login_failed")
    span = max(1.0, max(e["t"] for e in events) - min(e["t"] for e in events))
    mean = lambda k: float(np.mean([e[k] for e in events]))
    return {
        "source_ip": Counter(e["src_ip"] for e in events).most_common(1)[0][0],
        "destination_port": Counter(ports).most_common(1)[0][0],
        "protocol": Counter(e["protocol"] for e in events).most_common(1)[0][0],
        "packets_per_second": round(mean("pps"), 2),
        "failed_login_count": failed,
        "request_count": int(sum(e.get("requests", 1) for e in events)),
        "payload_length": round(mean("payload_len"), 1),
        "connection_duration": round(mean("duration"), 3),
        "unusual_port": round(sum(p not in COMMON_PORTS for p in ports) / n, 3),
        "login_frequency": round(len(logins) / span, 3),
        "special_char_ratio": round(mean("special_ratio"), 3),
        "distinct_ports": len(set(ports)),
    }


def detect_rules(features):
    """Return a rule-based detection without consulting simulator ground-truth labels."""
    if features["failed_login_count"] >= 4 and features["login_frequency"] >= 0.5:
        label, reason = "Brute Force", "repeated failed logins at a high rate"
    elif features["distinct_ports"] >= 8:
        label, reason = "Port Scan", "many distinct destination ports in one window"
    elif features["packets_per_second"] >= 1000 or features["request_count"] >= 500:
        label, reason = "Traffic Flood", "extreme packet or request volume"
    elif features["packets_per_second"] >= 500:
        label, reason = "Traffic Spike", "unusually high packet rate"
    else:
        label, reason = "Normal Traffic", "no baseline threshold was exceeded"
    return {"label": label, "is_anomaly": label != "Normal Traffic", "reason": reason}


def to_vector(f):
    """Normalise a feature dict to a 0..1 vector used for similarity / novelty."""
    out = []
    for k, use_log, cap in SIM_SPEC:
        v, c = (math.log1p(f[k]), math.log1p(cap)) if use_log else (f[k], cap)
        out.append(min(1.0, v / c))
    return out


def similarity(a, b):
    """1.0 = identical fingerprint, 0.0 = completely different."""
    d = float(np.sqrt(np.mean((np.asarray(a) - np.asarray(b)) ** 2)))
    return max(0.0, 1.0 - d / SIM_SCALE)
