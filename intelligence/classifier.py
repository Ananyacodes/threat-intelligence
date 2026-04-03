"""
intelligence/classifier.py
Phase 3 — supervised classifier that labels each alert with an attack type.

Uses a Random Forest trained on the labelled synthetic data.
In a real deployment you would train on labelled historical incidents.

Unit 2 justification:
  Supervised learning / classification model.
"""

import numpy as np
import pandas as pd
import pickle
import os
import sys
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import MODELS_DIR

CLASSIFIER_PATH = os.path.join(MODELS_DIR, "attack_classifier.pkl")

FEATURE_COLS = [
    "anomaly_score", "severity", "confidence",
    "hour", "is_external_ip",
]

FEATURE_COLS_NET = [
    "anomaly_score", "severity", "confidence",
    "hour", "bytes_sent", "pps",
]


class AttackClassifier:
    def __init__(self):
        self.scaler  = StandardScaler()
        self.encoder = LabelEncoder()
        self.model   = RandomForestClassifier(
            n_estimators=100, random_state=42, n_jobs=-1
        )
        self.trained = False
        self.classes_: list = []

    def _feature_matrix(self, df: pd.DataFrame) -> np.ndarray:
        cols = [c for c in FEATURE_COLS if c in df.columns]
        if not cols:
            cols = [c for c in FEATURE_COLS_NET if c in df.columns]
        return df[cols].fillna(0).values.astype(float)

    def fit(self, alerts: pd.DataFrame) -> "AttackClassifier":
        if "attack_type" not in alerts.columns:
            raise ValueError("alerts must have an 'attack_type' column for training.")
        if len(alerts) < 10:
            print("[classifier] Too few samples to train classifier.")
            return self

        X = self._feature_matrix(alerts)
        y = self.encoder.fit_transform(alerts["attack_type"])
        self.classes_ = list(self.encoder.classes_)

        X_scaled = self.scaler.fit_transform(X)
        X_tr, X_te, y_tr, y_te = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
            if len(np.unique(y)) > 1 else None
        )
        self.model.fit(X_tr, y_tr)
        self.trained = True

        y_pred = self.model.predict(X_te)
        print("\n[classifier] Evaluation on held-out test set:")
        print(classification_report(
            y_te, y_pred,
            target_names=self.encoder.inverse_transform(np.unique(y_te)),
            zero_division=0,
        ))
        return self

    def predict(self, alerts: pd.DataFrame) -> pd.DataFrame:
        if not self.trained:
            raise RuntimeError("Classifier not trained.")
        alerts = alerts.copy()
        X = self.scaler.transform(self._feature_matrix(alerts))
        pred_idx       = self.model.predict(X)
        pred_proba     = self.model.predict_proba(X).max(axis=1)
        alerts["predicted_attack_type"]       = self.encoder.inverse_transform(pred_idx)
        alerts["classification_confidence"]   = (pred_proba * 100).round(1)
        return alerts

    def save(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(CLASSIFIER_PATH, "wb") as f:
            pickle.dump(self, f)
        print(f"[classifier] Saved → {CLASSIFIER_PATH}")

    @staticmethod
    def load() -> "AttackClassifier":
        with open(CLASSIFIER_PATH, "rb") as f:
            return pickle.load(f)


if __name__ == "__main__":
    from core.alert_engine import load_alerts

    alerts = load_alerts()
    if alerts.empty:
        print("[classifier] No alerts. Run main.py first.")
    else:
        clf = AttackClassifier()
        clf.fit(alerts)
        result = clf.predict(alerts)
        print(result[["attack_type", "predicted_attack_type",
                       "classification_confidence"]].head(20))
        clf.save()
