"""LOCAL SANDBOX: a fake demo application + synthetic traffic generators.

SAFETY: nothing here opens a socket or touches the network. The "demo app" is a Python
object that receives synthetic event dicts, decides an outcome (login failed, 200 OK ...)
and appends a JSON line to data/security.log. Source IPs come only from the RFC 5737
documentation ranges (192.0.2.x / 198.51.100.x / 203.0.113.x) which are reserved for
examples and never route to real hosts. Credentials are fake strings like "guess-3".
"""
import json
import os
import time
import uuid
from datetime import datetime

import numpy as np
import pandas as pd

from .features import DATA_DIR, extract_features

LOG_PATH = os.path.join(DATA_DIR, "security.log")
FAKE_USERS = {"alice": "demo-pass-A", "bob": "demo-pass-B", "demo_user": "demo-pass-C"}
DOC_NETS = ["192.0.2", "198.51.100", "203.0.113"]

TRAINING_KINDS = ["Normal Traffic", "Brute Force", "Port Scan", "SQL Injection",
                  "DDoS", "Suspicious Login", "Unknown Suspicious"]
KINDS = TRAINING_KINDS + ["Novel Attack"]   # "Novel Attack" is NEVER in the training data


def new_ip(rng=None):
    rng = rng or np.random.default_rng()
    return f"{DOC_NETS[int(rng.integers(3))]}.{int(rng.integers(2, 250))}"


def new_batch_id():
    return f"b{uuid.uuid4().hex}"


# --------------------------------------------------------------------------- generators
def generate_events(kind, n_events=20, intensity=5, variation=0.15, src_ip=None,
                    mutated=False, seed=None):
    """Create a list of synthetic events for one scenario.

    intensity : 1..10  (scales rates / volumes)
    variation : 0..1   (random jitter of the whole pattern -> "slightly different" attacks)
    mutated   : apply a structural modification (slower, different port, obfuscated ...)
    """
    rng = np.random.default_rng(seed)
    ip = src_ip or new_ip(rng)
    s = max(0.2, intensity / 5.0)
    sig = 0.05 + 0.3 * variation
    J = lambda x: float(x * np.exp(rng.normal(0, sig)))     # window-level jitter
    U = lambda a, b: float(rng.uniform(a, b))                 # per-event noise
    m = mutated
    n = max(3, int(n_events))
    evs, t = [], 0.0

    def add(t, port, proto, etype, user="", secret="", plen=0, sp=0.0, pps=0.0, dur=0.0, req=1):
        evs.append(dict(t=round(t, 3), src_ip=ip, dst_port=int(port), protocol=proto,
                        event_type=etype, username=user, secret=secret,
                        payload_len=int(max(0, plen)), special_ratio=round(max(0.0, sp), 3),
                        pps=round(max(0.0, pps), 2), duration=round(max(0.0, dur), 3),
                        requests=int(max(1, req))))

    if kind == "Brute Force":                 # many fast failed SSH logins
        gap, pps, plen, dur, sp = J(0.35 / s) * (5 if m else 1), J(35 * s) * (0.4 if m else 1), J(80), J(0.6), J(0.04)
        port = 2222 if m else 22
        users = ["admin", "root", "alice", "bob", "test", "guest"]
        for i in range(n):
            t += gap * U(.7, 1.3)
            add(t, port, "SSH", "login", users[int(rng.integers(6))], f"guess-{i}",
                plen * U(.8, 1.2), sp * U(.7, 1.3), pps * U(.8, 1.2), dur * U(.7, 1.3))

    elif kind == "Port Scan":                 # one probe per port, very fast, tiny packets
        k = max(3, n // 3) if m else n
        ports = rng.choice(np.arange(1, 10000), size=k, replace=False)
        gap, pps = J(0.02 / s) * (12 if m else 1), J(150 * s) * (0.25 if m else 1)
        for p in ports:
            t += gap * U(.7, 1.3)
            add(t, p, "TCP", "probe", plen=J(40) * U(.8, 1.2), pps=pps * U(.8, 1.2), dur=J(0.05) * U(.7, 1.3))

    elif kind == "SQL Injection":             # few HTTP requests with long, symbol-heavy payloads
        port = int(rng.choice([80, 443, 8080]))
        gap, pps, plen, sp = J(1.2 / s) * (2 if m else 1), J(12 * s), J(650) * (1.8 if m else 1), J(0.25) * (0.5 if m else 1)
        for i in range(n):
            t += gap * U(.7, 1.3)
            add(t, port, "HTTP", "http", plen=plen * U(.6, 1.4), sp=sp * U(.7, 1.3),
                pps=pps * U(.8, 1.2), dur=J(1.5) * U(.7, 1.3))

    elif kind == "DDoS":                      # huge request volume, very high packet rate
        port = int(rng.choice([80, 443, 53]))
        proto = "UDP" if port == 53 else "TCP"
        gap, pps, req = J(0.05 / s) * (4 if m else 1), J(4500 * s) * (0.2 if m else 1), J(180 * s) * (0.3 if m else 1)
        for i in range(n):
            t += gap * U(.7, 1.3)
            add(t, port, proto, "traffic", plen=J(70) * U(.8, 1.2), sp=0.01,
                pps=pps * U(.7, 1.3), dur=J(0.1) * U(.7, 1.3), req=req * U(.5, 1.5))

    elif kind == "Suspicious Login":          # a few failures then success, slow, web login
        fails = int(np.clip(round(n * 0.35), 2, 8))
        gap = J(8.0) * (0.4 if m else 1)
        for i in range(n):
            t += gap * U(.5, 1.5)
            ok = i >= fails
            add(t, 443, "HTTP", "login", "demo_user", FAKE_USERS["demo_user"] if ok else f"guess-{i}",
                J(300) * U(.7, 1.3), J(0.05) * U(.7, 1.3), J(8) * U(.7, 1.3), J(3) * U(.7, 1.3))

    elif kind == "Unknown Suspicious":        # mildly odd, mixed behaviour (training class)
        base_port = int(rng.choice([8081, 8443, 9000, 2000, 6000]))
        for i in range(n):
            t += J(1.0) * U(.5, 1.5)
            port = int(rng.choice([base_port, base_port, 80, 443]))
            if rng.random() < 0.5:
                add(t, port, "TCP", "login", "alice", f"guess-{i}" if rng.random() < .3 else FAKE_USERS["alice"],
                    J(450) * U(.3, 2), J(0.1) * U(.5, 2), J(70) * U(.5, 1.8), J(8) * U(.3, 3))
            else:
                add(t, port, "TCP", "http", plen=J(450) * U(.3, 2), sp=J(0.1) * U(.5, 2),
                    pps=J(70) * U(.5, 1.8), dur=J(8) * U(.3, 3), req=int(rng.integers(1, 6)))

    elif kind == "Novel Attack":              # synthetic "low-and-slow beacon" - not in training data
        port = 8883 if m else 9443
        gap = J(6.0) * (0.4 if m else 1)
        plen, pps, dur = J(4500) * (0.55 if m else 1), J(2.5) * (2.5 if m else 1), J(180) * (0.45 if m else 1)
        for i in range(n):
            t += gap * U(.7, 1.3)
            add(t, port, "TCP", "traffic", plen=plen * U(.9, 1.1), sp=J(0.02) * U(.7, 1.3),
                pps=pps * U(.8, 1.2), dur=dur * U(.8, 1.2), req=3)

    else:                                     # Normal Traffic
        for i in range(n):
            t += J(2.0) * U(.5, 2)
            port = int(rng.choice([80, 443, 443, 53, 22]))
            proto = "UDP" if port == 53 else ("SSH" if port == 22 else "HTTP")
            if port in (80, 443) and rng.random() < 0.25:
                bad = rng.random() < 0.05
                add(t, port, proto, "login", "alice", "typo" if bad else FAKE_USERS["alice"],
                    J(700) * U(.3, 1.6), J(0.03) * U(.5, 1.5), J(25) * U(.5, 1.5), J(8) * U(.3, 2))
            else:
                add(t, port, proto, "http", plen=J(700) * U(.3, 1.6), sp=J(0.03) * U(.5, 1.5),
                    pps=J(25) * U(.5, 1.5), dur=J(8) * U(.3, 2), req=int(rng.integers(1, 5)))
    return evs


# --------------------------------------------------------------------------- demo app
def process_event(ev):
    """What the (fake) application does with one event. Pure function."""
    if ev["event_type"] == "login":
        ok = FAKE_USERS.get(ev.get("username")) == ev.get("secret")
        ev["outcome"] = "login_ok" if ok else "login_failed"
    elif ev["event_type"] == "http":
        ev["outcome"] = "http_200"
    else:
        ev["outcome"] = "accepted"
    return ev


class DemoApp:
    """In-process sandbox service. Writes every event to data/security.log (JSON lines)."""

    def __init__(self, memory=None, log_path=LOG_PATH):
        self.memory, self.log_path = memory, log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def stream(self, events, batch_id):
        """Yield events one by one as the app handles (and logs) them."""
        blocked = bool(events) and self.memory is not None and self.memory.is_blocked(events[0]["src_ip"])
        with open(self.log_path, "a") as fh:
            for i, ev in enumerate(events):
                ev = process_event(dict(ev))
                ev.update(id=f"{batch_id}-{i}", batch=batch_id, ts=datetime.now().isoformat(timespec="milliseconds"))
                ev["blocked"] = blocked
                if blocked:   # the SIMULATED blocklist from an earlier response
                    ev["outcome"] = "rejected_by_simulated_blocklist"
                ev.pop("secret", None)          # never log secrets, even fake ones
                fh.write(json.dumps(ev) + "\n")
                fh.flush()
                yield ev

    def run_batch(self, events, batch_id):
        return list(self.stream(events, batch_id))


def read_batch(batch_id, log_path=LOG_PATH):
    """The detection engine reads the batch back FROM THE LOG FILE."""
    out = []
    with open(log_path) as fh:
        for line in fh:
            if f'"batch": "{batch_id}"' in line:
                out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------- dataset
def build_dataset(n_per_class=300, seed=1):
    """Synthetic labelled dataset: one row per event window (same generator as the demo)."""
    rng = np.random.default_rng(seed)
    rows = []
    for kind in TRAINING_KINDS:
        for _ in range(n_per_class):
            evs = generate_events(kind, int(rng.integers(6, 51)), int(rng.integers(2, 10)),
                                  float(rng.uniform(0, 0.6)), None, False, int(rng.integers(1 << 31)))
            evs = [process_event(e) for e in evs]
            f = extract_features(evs)
            f["attack_type"] = kind
            rows.append(f)
    return pd.DataFrame(rows)
