"""
core/anomaly_detector.py
Trains and runs an anomaly-detection ensemble:
  - Isolation Forest  (fast, tree-based, good for high-dim data)
  - One-Class SVM     (kernel-based, catches different anomaly shapes)

The final anomaly score is a weighted average of both models.
Models are persisted to disk so the dashboard can reload them without
re-training on every request.

Unit 2 justification:
  Unsupervised learning — models learn "normal" behaviour and flag deviations.
"""

import numpy as np
import pandas as pd
import pickle
import os
import sys
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    CONTAMINATION, IFOREST_N_ESTIMATORS, OCSVM_NU, OCSVM_KERNEL,
    ANOMALY_SCORE_THRESHOLD,
    IFOREST_MODEL_PATH, OCSVM_MODEL_PATH, MODELS_DIR,
)


# ══════════════════════════════════════════════════════════════════════════════
class AnomalyDetector:
    """
    Ensemble anomaly detector.
    fit()    → trains on normal-only data (or all data with contamination hint)
    predict() → returns anomaly scores [0..1] and binary flags
    """

    def __init__(self, name: str = "detector"):
        self.name    = name
        self.scaler  = StandardScaler()
        self.iforest = IsolationForest(
            n_estimators=IFOREST_N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self.ocsvm = OneClassSVM(
            nu=OCSVM_NU,
            kernel=OCSVM_KERNEL,
            gamma="scale",
        )
        self.trained = False

    # ── Training ───────────────────────────────────────────────────────────────
    def fit(self, X: np.ndarray) -> "AnomalyDetector":
        """Train on feature matrix X (numpy array)."""
        print(f"[{self.name}] Training on {X.shape[0]} samples, "
              f"{X.shape[1]} features …")
        X_scaled = self.scaler.fit_transform(X)
        self.iforest.fit(X_scaled)
        # OCSVM is expensive on large datasets — subsample to 2000 rows max
        n = min(len(X_scaled), 2000)
        idx = np.random.choice(len(X_scaled), n, replace=False)
        self.ocsvm.fit(X_scaled[idx])
        self.trained = True
        print(f"[{self.name}] Training complete.")
        return self

    # ── Prediction ─────────────────────────────────────────────────────────────
    def predict(self, X: np.ndarray) -> dict:
        """
        Returns dict with keys:
          anomaly_score   float [0..1]  higher = more anomalous
          is_anomaly      int   {0, 1}
          iforest_score   raw isolation forest score
          ocsvm_score     raw ocsvm decision score
        """
        if not self.trained:
            raise RuntimeError("Model not trained. Call fit() first.")

        X_scaled = self.scaler.transform(X)

        # IsolationForest: score_samples returns negative — flip and normalise
        raw_if   = -self.iforest.score_samples(X_scaled)
        if_norm  = (raw_if - raw_if.min()) / (raw_if.max() - raw_if.min() + 1e-9)

        # OneClassSVM: decision_function negative = more anomalous
        raw_oc   = -self.ocsvm.decision_function(X_scaled)
        oc_norm  = (raw_oc - raw_oc.min()) / (raw_oc.max() - raw_oc.min() + 1e-9)

        # Weighted ensemble (IForest gets more weight — it is more reliable)
        combined = 0.65 * if_norm + 0.35 * oc_norm

        return {
            "anomaly_score": combined,
            "is_anomaly":    (combined >= ANOMALY_SCORE_THRESHOLD).astype(int),
            "iforest_score": if_norm,
            "ocsvm_score":   oc_norm,
        }

    # ── Persistence ────────────────────────────────────────────────────────────
    def save(self, path: str = None):
        path = path or os.path.join(MODELS_DIR, f"{self.name}.pkl")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        print(f"[{self.name}] Model saved → {path}")

    @staticmethod
    def load(path: str) -> "AnomalyDetector":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        print(f"[AnomalyDetector] Loaded from {path}")
        return obj


# ══════════════════════════════════════════════════════════════════════════════
# Convenience wrappers used by main.py
# ══════════════════════════════════════════════════════════════════════════════

def train_system_detector(X_train: np.ndarray) -> AnomalyDetector:
    det = AnomalyDetector(name="system_detector")
    det.fit(X_train)
    det.save(IFOREST_MODEL_PATH)
    return det


def train_network_detector(X_train: np.ndarray) -> AnomalyDetector:
    det = AnomalyDetector(name="network_detector")
    det.fit(X_train)
    det.save(OCSVM_MODEL_PATH)
    return det


def load_system_detector() -> AnomalyDetector:
    return AnomalyDetector.load(IFOREST_MODEL_PATH)


def load_network_detector() -> AnomalyDetector:
    return AnomalyDetector.load(OCSVM_MODEL_PATH)


if __name__ == "__main__":
    from preprocessor     import preprocess_system_logs, preprocess_network_logs
    from feature_engineer import system_feature_matrix, network_feature_matrix

    sys_df  = preprocess_system_logs()
    net_df  = preprocess_network_logs()

    X_sys = system_feature_matrix(sys_df)
    X_net = network_feature_matrix(net_df)

    sys_det = train_system_detector(X_sys)
    net_det = train_network_detector(X_net)

    sys_pred = sys_det.predict(X_sys)
    net_pred = net_det.predict(X_net)

    print(f"\nSystem anomalies detected : {sys_pred['is_anomaly'].sum()} / {len(X_sys)}")
    print(f"Network anomalies detected: {net_pred['is_anomaly'].sum()} / {len(X_net)}")
