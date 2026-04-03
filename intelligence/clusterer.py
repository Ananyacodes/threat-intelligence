"""
intelligence/clusterer.py
Phase 3 — groups anomalous events into attack campaigns using:
  - K-Means    (fixed k, fast, good for well-separated clusters)
  - DBSCAN     (density-based, finds arbitrarily shaped clusters + noise)

Unit 2 justification:
  Unsupervised clustering to extract recurring attack patterns from alerts.
"""

import numpy as np
import pandas as pd
import pickle
import os
import sys
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    KMEANS_N_CLUSTERS, DBSCAN_EPS, DBSCAN_MIN_SAMPLES,
    KMEANS_MODEL_PATH, MODELS_DIR,
)

CLUSTER_FEATURES = [
    "anomaly_score", "severity", "confidence",
    "hour", "is_external_ip",
]

CLUSTER_FEATURES_NET = [
    "anomaly_score", "severity", "confidence",
    "hour", "bytes_sent", "pps",
]


def _build_cluster_matrix(alerts: pd.DataFrame) -> np.ndarray:
    cols = [c for c in CLUSTER_FEATURES if c in alerts.columns]
    if not cols:
        cols = [c for c in CLUSTER_FEATURES_NET if c in alerts.columns]
    X = alerts[cols].fillna(0).values.astype(float)
    return X, cols


class AttackClusterer:
    def __init__(self):
        self.scaler = StandardScaler()
        self.kmeans = KMeans(n_clusters=KMEANS_N_CLUSTERS, random_state=42, n_init=10)
        self.dbscan = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES)
        self.fitted = False

    def fit_predict(self, alerts: pd.DataFrame) -> pd.DataFrame:
        """
        Adds two columns to alerts:
          cluster_kmeans   int  (0 … k-1)
          cluster_dbscan   int  (-1 = noise, 0+ = cluster id)
        """
        if len(alerts) < 5:
            alerts["cluster_kmeans"] = 0
            alerts["cluster_dbscan"] = 0
            return alerts

        alerts = alerts.copy()
        X, used_cols = _build_cluster_matrix(alerts)
        X_scaled = self.scaler.fit_transform(X)

        k = min(KMEANS_N_CLUSTERS, len(alerts))
        self.kmeans.set_params(n_clusters=k)

        alerts["cluster_kmeans"] = self.kmeans.fit_predict(X_scaled)
        alerts["cluster_dbscan"] = self.dbscan.fit_predict(X_scaled)
        self.fitted = True
        return alerts

    def cluster_summary(self, alerts: pd.DataFrame) -> pd.DataFrame:
        """Per-cluster statistics for the threat report."""
        if "cluster_kmeans" not in alerts.columns:
            return pd.DataFrame()

        summary = (
            alerts.groupby("cluster_kmeans")
            .agg(
                count=("attack_type", "count"),
                dominant_attack=("attack_type", lambda x: x.mode().iloc[0]),
                avg_severity=("severity", "mean"),
                max_severity=("severity", "max"),
                avg_confidence=("confidence", "mean"),
                unique_ips=("source_ip", "nunique"),
                start_time=("timestamp", "min"),
                end_time=("timestamp", "max"),
            )
            .reset_index()
            .rename(columns={"cluster_kmeans": "cluster_id"})
            .sort_values("avg_severity", ascending=False)
        )
        return summary

    def save(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(KMEANS_MODEL_PATH, "wb") as f:
            pickle.dump(self, f)
        print(f"[clusterer] Model saved → {KMEANS_MODEL_PATH}")

    @staticmethod
    def load() -> "AttackClusterer":
        with open(KMEANS_MODEL_PATH, "rb") as f:
            return pickle.load(f)


if __name__ == "__main__":
    from core.alert_engine import load_alerts

    alerts = load_alerts()
    if alerts.empty:
        print("[clusterer] No alerts found. Run main.py first.")
    else:
        c = AttackClusterer()
        alerts = c.fit_predict(alerts)
        summary = c.cluster_summary(alerts)
        print("\nCluster summary:")
        print(summary.to_string(index=False))
        c.save()
