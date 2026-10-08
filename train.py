"""Build the synthetic dataset (data/attacks.csv) and train the baseline Random Forest.

    python train.py
"""
import json

import pandas as pd
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from agent.detector import DATA_PATH, MODEL_PATH, Detector, fit_and_save, model_matrix
from agent.simulator import build_dataset

if __name__ == "__main__":
    df = build_dataset(n_per_class=300)
    df.to_csv(DATA_PATH, index=False)
    print(f"Dataset: {len(df)} synthetic event windows -> {DATA_PATH}")
    print(df["attack_type"].value_counts().to_string(), "\n")
    res = fit_and_save(df)
    print(f"Random Forest trained. Hold-out accuracy: {res['holdout_acc']:.1%}  (model saved to {MODEL_PATH})")
    _, test = train_test_split(df, test_size=0.2, stratify=df["attack_type"], random_state=0)
    det = Detector()
    print(classification_report(test["attack_type"], det.raw_labels(test)))
    print("Note: the data is synthetic and well separated, so accuracy is very high. That is expected for a prototype.\n")
    sample = test[test["attack_type"] == "Brute Force"].iloc[0].drop("attack_type").to_dict()
    d = det.detect(sample)
    print("Example detector output:\n", json.dumps({k: d[k] for k in ("attack_type", "confidence", "risk")}, indent=2))
