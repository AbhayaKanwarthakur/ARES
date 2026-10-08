"""REMEMBER: persistent attack memory in SQLite (survives app restarts).

Tables
  incidents     every analysed event window (features, confidence, action, result, success ...)
  patterns      learned attack fingerprints (centroid, times seen, confidence, success rate)
  action_stats  how often each response worked for each attack type  (-> RULE adaptation)
  defenses      the SIMULATED blocklist / rate limits (nothing real is ever blocked)
  model_log     history of real ML model retraining runs
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

import pandas as pd

from .features import DATA_DIR, similarity

DB_PATH = os.path.join(DATA_DIR, "memory.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, source_ip TEXT, attack_type TEXT,
  truth_label TEXT, train_label TEXT, model_label TEXT, model_conf REAL, final_conf REAL,
  risk TEXT, risk_score REAL, action TEXT, result TEXT, success INTEGER, path TEXT,
  similarity REAL, pattern_id INTEGER, pattern_name TEXT, analysis_steps INTEGER,
  decision_ms REAL, features TEXT, reasoning TEXT, steps TEXT, timeline TEXT,
  learning_status TEXT, used_in_training INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS patterns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, base_type TEXT, centroid TEXT,
  count INTEGER, confidence REAL, successes INTEGER, tries INTEGER, action TEXT,
  description TEXT, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS action_stats(
  attack_type TEXT, action TEXT, tries INTEGER, successes INTEGER, PRIMARY KEY(attack_type, action));
CREATE TABLE IF NOT EXISTS defenses(
  ip TEXT, action TEXT, attack_type TEXT, ts TEXT, PRIMARY KEY(ip, action));
CREATE TABLE IF NOT EXISTS model_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, reason TEXT, n_experiences INTEGER,
  classes TEXT, holdout_acc REAL, exp_acc_before REAL, exp_acc_after REAL);
"""


def now():
    return datetime.now().isoformat(timespec="seconds")


class Memory:
    def __init__(self, path=DB_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self._c() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _c(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _q(self, sql, args=()):
        with self._c() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    def _x(self, sql, args=()):
        with self._c() as c:
            return c.execute(sql, args).lastrowid

    def _insert(self, table, d):
        cols = ",".join(d)
        return self._x(f"INSERT INTO {table}({cols}) VALUES({','.join('?' * len(d))})", list(d.values()))

    def _update(self, table, id_, **kw):
        sets = ",".join(f"{k}=?" for k in kw)
        self._x(f"UPDATE {table} SET {sets} WHERE id=?", list(kw.values()) + [id_])

    # ---- incidents
    def add_incident(self, d):
        return self._insert("incidents", {"ts": now(), **d})

    def update_incident(self, id_, **kw):
        self._update("incidents", id_, **kw)

    def incidents_df(self):
        with self._c() as c:
            return pd.read_sql_query("SELECT * FROM incidents ORDER BY id", c)

    def latest_incident(self):
        r = self._q("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
        return r[0] if r else None

    def incidents_for_pattern(self, pid):
        return self._q("SELECT * FROM incidents WHERE pattern_id=? ORDER BY id", (pid,))

    # ---- patterns
    def add_pattern(self, d):
        d = {**d, "centroid": json.dumps(d["centroid"])}
        return self._insert("patterns", d)

    def update_pattern(self, id_, **kw):
        if "centroid" in kw:
            kw["centroid"] = json.dumps(kw["centroid"])
        self._update("patterns", id_, **kw)

    def patterns(self):
        rows = self._q("SELECT * FROM patterns ORDER BY id")
        for r in rows:
            r["centroid"] = json.loads(r["centroid"])
        return rows

    def pattern(self, id_):
        return next((p for p in self.patterns() if p["id"] == id_), None)

    def rank_patterns(self, vec):
        """All learned patterns ordered by similarity to this fingerprint."""
        ranked = [(p, similarity(vec, p["centroid"])) for p in self.patterns()]
        return sorted(ranked, key=lambda x: -x[1])

    # ---- response statistics (rule adaptation)
    def record_outcome(self, attack_type, action, success):
        self._x("INSERT OR IGNORE INTO action_stats VALUES(?,?,0,0)", (attack_type, action))
        self._x("UPDATE action_stats SET tries=tries+1, successes=successes+? WHERE attack_type=? AND action=?",
                (int(success), attack_type, action))

    def action_stats(self, attack_type):
        rows = self._q("SELECT * FROM action_stats WHERE attack_type=?", (attack_type,))
        return {r["action"]: (r["tries"], r["successes"]) for r in rows}

    def action_stats_df(self):
        with self._c() as c:
            return pd.read_sql_query("SELECT * FROM action_stats ORDER BY attack_type, action", c)

    # ---- simulated defenses
    def add_defense(self, ip, action, attack_type):
        self._x("INSERT OR REPLACE INTO defenses VALUES(?,?,?,?)", (ip, action, attack_type, now()))

    def is_blocked(self, ip):
        return bool(self._q("SELECT 1 FROM defenses WHERE ip=? AND action='BLOCK_IP'", (ip,)))

    def defenses_df(self):
        with self._c() as c:
            return pd.read_sql_query("SELECT ip, action, attack_type, ts FROM defenses ORDER BY ts DESC", c)

    # ---- model retraining history
    def add_model_log(self, **d):
        return self._insert("model_log", {"ts": now(), **d})

    def model_log_df(self):
        with self._c() as c:
            return pd.read_sql_query("SELECT * FROM model_log ORDER BY id", c)

    def reset(self):
        with self._c() as c:
            for t in ["incidents", "patterns", "action_stats", "defenses", "model_log"]:
                c.execute(f"DELETE FROM {t}")
