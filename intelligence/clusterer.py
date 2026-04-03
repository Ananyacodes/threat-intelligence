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

    # Alerts can come from different pipeline versions; coerce to numeric to
    # avoid crashes when old rows contain strings in feature columns.
    numeric_df = alerts[cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    X = numeric_df.values.astype(float)
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

        alerts = alerts.copy()
        for col in ["severity", "confidence"]:
            if col in alerts.columns:
                alerts[col] = pd.to_numeric(alerts[col], errors="coerce")
        if "timestamp" in alerts.columns:
            alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")

        agg_spec = {
            "count": ("attack_type", "count"),
            "dominant_attack": ("attack_type", lambda x: x.mode().iloc[0] if not x.mode().empty else "unknown"),
        }
        if "severity" in alerts.columns:
            agg_spec["avg_severity"] = ("severity", "mean")
            agg_spec["max_severity"] = ("severity", "max")
        if "confidence" in alerts.columns:
            agg_spec["avg_confidence"] = ("confidence", "mean")
        if "source_ip" in alerts.columns:
            agg_spec["unique_ips"] = ("source_ip", "nunique")
        if "timestamp" in alerts.columns:
            agg_spec["start_time"] = ("timestamp", "min")
            agg_spec["end_time"] = ("timestamp", "max")

        summary = (
            alerts.groupby("cluster_kmeans")
            .agg(**agg_spec)
            .reset_index()
            .rename(columns={"cluster_kmeans": "cluster_id"})
        )

        if "avg_severity" not in summary.columns:
            summary["avg_severity"] = 0
        if "max_severity" not in summary.columns:
            summary["max_severity"] = 0
        if "avg_confidence" not in summary.columns:
            summary["avg_confidence"] = 0
        if "unique_ips" not in summary.columns:
            summary["unique_ips"] = 0
        if "start_time" not in summary.columns:
            summary["start_time"] = pd.NaT
        if "end_time" not in summary.columns:
            summary["end_time"] = pd.NaT

        summary = summary.sort_values("avg_severity", ascending=False)

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
