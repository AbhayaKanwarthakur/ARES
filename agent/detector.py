"""DETECT: a lightweight Random Forest classifier + a simple 'is this unfamiliar?' check.

Two ways an event window is declared UNKNOWN even if the forest picks a label:
  1. low confidence      (top class probability < CONF_T)
  2. outlier             (far from EVERY known class in normalised feature space)
Random Forests are over-confident on data unlike anything they were trained on, so the
outlier check is what catches truly novel attacks.
"""
import os
import warnings

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

from .features import DATA_DIR, FEATURES, MODEL_DIR, PROTO_CODE, detect_rules, to_vector

MODEL_PATH = os.environ.get("ARES_MODEL_PATH", os.path.join(MODEL_DIR, "detector.joblib"))
DATA_PATH = os.environ.get("ARES_DATA_PATH", os.path.join(DATA_DIR, "attacks.csv"))
MODEL_FORMAT_VERSION = 1
CONF_T = 0.65       # below this the verdict is "unknown"
OUTLIER_T = 3.0     # novelty distance above this is "unlike anything known"

SEVERITY = {"Brute Force": 0.85, "SQL Injection": 0.90, "DDoS": 0.85, "Port Scan": 0.55,
            "Suspicious Login": 0.60, "Unknown Suspicious": 0.60, "Normal Traffic": 0.0}


def severity(attack_type):
    return SEVERITY.get(attack_type, 0.65 if attack_type.startswith("Novel") else 0.6)


def risk_score(attack_type, conf, novelty):
    anomaly = min(1.0, max(0.0, (novelty - 1.5) / 5))
    return round(100 * min(1.0, severity(attack_type) * (0.4 + 0.6 * conf) + 0.2 * anomaly), 1)


def risk_label(score):
    return "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"


# --------------------------------------------------------------------------- training
def model_matrix(df):
    X = df[FEATURES].copy()
    X["protocol"] = X["protocol"].map(PROTO_CODE).fillna(0).astype(int)
    return X


def vectors(df):
    return np.array([to_vector(r) for r in df.to_dict("records")])


def augment(exp_df, copies=15, noise=0.08, seed=0):
    """Turn a handful of real experiences into a small jittered training set."""
    rng = np.random.default_rng(seed)
    rows = []
    for _ in range(copies):
        d = exp_df.copy()
        for c in ["packets_per_second", "request_count", "payload_length", "connection_duration",
                  "login_frequency", "special_char_ratio", "failed_login_count", "distinct_ports"]:
            d[c] = d[c] * np.exp(rng.normal(0, noise, len(d)))
        for c in ["request_count", "failed_login_count", "distinct_ports"]:
            d[c] = d[c].round().astype(int)
        rows.append(d)
    return pd.concat(rows, ignore_index=True)


def fit_and_save(base_df, exp_df=None):
    """Train the forest. exp_df = labelled experiences gathered by the agent (optional)."""
    train, test = train_test_split(base_df, test_size=0.2, stratify=base_df["attack_type"], random_state=0)
    if exp_df is not None and len(exp_df):
        train = pd.concat([train, augment(exp_df)], ignore_index=True)
    clf = RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=0, n_jobs=-1)
    clf.fit(model_matrix(train), train["attack_type"])
    acc = float(accuracy_score(test["attack_type"], clf.predict(model_matrix(test))))
    V, y = vectors(train), train["attack_type"].values
    stats = {c: (V[y == c].mean(0), V[y == c].std(0)) for c in clf.classes_}
    os.makedirs(MODEL_DIR, exist_ok=True)
    payload = {
        "model": clf,
        "class_stats": stats,
        "holdout_acc": acc,
        "n_train": len(train),
        "artifact_format": MODEL_FORMAT_VERSION,
        "sklearn_version": sklearn.__version__,
    }
    joblib.dump(payload, MODEL_PATH)
    return {"holdout_acc": acc, "classes": list(clf.classes_), "n_train": len(train), "sklearn_version": sklearn.__version__}


def ensure_model():
    """Create dataset + model on first run."""
    if not os.path.exists(DATA_PATH):
        from .simulator import build_dataset
        build_dataset().to_csv(DATA_PATH, index=False)
    if not os.path.exists(MODEL_PATH):
        fit_and_save(pd.read_csv(DATA_PATH))


# --------------------------------------------------------------------------- inference
class Detector:
    def __init__(self):
        self._mtime = None
        self.reload()

    def reload(self):
        if not os.path.exists(MODEL_PATH):
            ensure_model()
        try:
            payload = joblib.load(MODEL_PATH)
        except Exception as exc:  # pragma: no cover - defensive around stale/partial artifacts
            raise RuntimeError(f"Unable to load detector model from {MODEL_PATH}: {exc}") from exc
        if not isinstance(payload, dict) or "model" not in payload or "class_stats" not in payload:
            raise ValueError(f"Model artifact at {MODEL_PATH} is missing expected detector metadata.")

        if payload.get("artifact_format") != MODEL_FORMAT_VERSION or payload.get("sklearn_version") != sklearn.__version__:
            warnings.warn(
                f"Detector artifact for scikit-learn {payload.get('sklearn_version', 'unknown')} is incompatible with runtime {sklearn.__version__}; retraining the model.",
                UserWarning,
                stacklevel=2,
            )
            if os.path.exists(DATA_PATH):
                base_df = pd.read_csv(DATA_PATH)
            else:
                from .simulator import build_dataset
                base_df = build_dataset()
                base_df.to_csv(DATA_PATH, index=False)
            fit_and_save(base_df)
            payload = joblib.load(MODEL_PATH)

        self.b = payload
        self._mtime = os.path.getmtime(MODEL_PATH)

    def fresh(self):
        if os.path.getmtime(MODEL_PATH) != self._mtime:
            self.reload()

    def raw_labels(self, df):
        self.fresh()
        return self.b["model"].predict(model_matrix(df))

    def novelty(self, vec):
        """Smallest normalised distance to any known class (low = familiar)."""
        v = np.asarray(vec)
        return float(min(np.sqrt(np.mean(((v - mu) / (sd + 0.05)) ** 2))
                         for mu, sd in self.b["class_stats"].values()))

    def detect(self, feats, confidence_threshold=CONF_T, outlier_threshold=OUTLIER_T):
        self.fresh()
        rule_based = detect_rules(feats)
        X = model_matrix(pd.DataFrame([feats]))
        proba = self.b["model"].predict_proba(X)[0]
        i = int(np.argmax(proba))
        raw, conf = str(self.b["model"].classes_[i]), min(0.99, float(proba[i]))
        nov = self.novelty(to_vector(feats))
        reason = None
        if raw == "Unknown Suspicious":
            reason = "model label is 'Unknown Suspicious'"
        elif conf < confidence_threshold:
            reason = f"low model confidence ({conf:.0%})"
        elif nov > outlier_threshold:
            reason = f"outlier: distance {nov:.1f} from every known class"
        attack_type = "Unknown Suspicious" if reason else raw
        return {"attack_type": attack_type, "confidence": round(conf, 3),
                "risk": risk_label(risk_score(attack_type, conf, nov)),
                "raw_label": raw, "novelty": round(nov, 2), "is_unknown": reason is not None,
                "unknown_reason": reason,
                "rule_based": rule_based,
                "probabilities": {str(c): round(float(p), 3) for c, p in zip(self.b["model"].classes_, proba) if p > 0.01}}


_DET = None


def get_detector():
    global _DET
    if _DET is None:
        ensure_model()
        _DET = Detector()
    return _DET
