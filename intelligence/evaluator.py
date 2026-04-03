from __future__ import annotations

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support


ORDERED_LABELS = ["DoS", "Brute Force", "Port Scan", "Data Exfiltration", "Unknown"]


def _reference_label(row: pd.Series) -> str:
    if row["request_frequency"] > 120 and row["packets_sum"] > 15_000:
        return "DoS"
    if row["failed_login_count"] > 10:
        return "Brute Force"
    if row["unique_ports"] > 12:
        return "Port Scan"
    if row["bytes_sum"] > 10_000_000 and row["request_frequency"] < 20:
        return "Data Exfiltration"
    return "Unknown"


def evaluate_predictions(scored_df: pd.DataFrame) -> dict:
    if scored_df.empty or "attack_type" not in scored_df.columns:
        return {
            "classification_metrics": {
                "accuracy": 0.0,
                "precision_weighted": 0.0,
                "recall_weighted": 0.0,
                "f1_weighted": 0.0,
                "support": 0,
            },
            "confusion_summary": {
                "labels": ORDERED_LABELS,
                "matrix": [[0 for _ in ORDERED_LABELS] for _ in ORDERED_LABELS],
                "top_confusions": [],
            },
        }

    df = scored_df.copy()
    df["reference_label"] = df.apply(_reference_label, axis=1)

    y_true = df["reference_label"]
    y_pred = df["attack_type"].where(df["attack_type"].isin(ORDERED_LABELS), "Unknown")

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=ORDERED_LABELS,
        average="weighted",
        zero_division=0,
    )
    acc = accuracy_score(y_true, y_pred)

    matrix = confusion_matrix(y_true, y_pred, labels=ORDERED_LABELS)
    confusion_entries = []
    for i, true_label in enumerate(ORDERED_LABELS):
        for j, pred_label in enumerate(ORDERED_LABELS):
            if i != j and int(matrix[i, j]) > 0:
                confusion_entries.append(
                    {
                        "true_label": true_label,
                        "predicted_label": pred_label,
                        "count": int(matrix[i, j]),
                    }
                )

    confusion_entries = sorted(confusion_entries, key=lambda item: item["count"], reverse=True)[:10]

    return {
        "classification_metrics": {
            "accuracy": round(float(acc), 4),
            "precision_weighted": round(float(precision), 4),
            "recall_weighted": round(float(recall), 4),
            "f1_weighted": round(float(f1), 4),
            "support": int(len(df)),
        },
        "confusion_summary": {
            "labels": ORDERED_LABELS,
            "matrix": matrix.tolist(),
            "top_confusions": confusion_entries,
        },
    }
