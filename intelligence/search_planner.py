"""
intelligence/search_planner.py
Unit 2 add-on: Best-First Search for alert triage ordering.

Given current alerts, this module returns an investigation queue where the
highest-priority next alert is always expanded first (greedy best-first).
"""

from __future__ import annotations

from typing import Any
import pandas as pd


def _row_priority(row: pd.Series) -> float:
    """Heuristic priority score used by best-first expansion."""
    severity = float(row.get("severity", 0) or 0)
    confidence = float(row.get("confidence", 0) or 0)
    risk_score = float(row.get("risk_score", 0) or 0)

    # Weighted threat heuristic for greedy expansion.
    return (2.0 * severity) + (0.06 * confidence) + (0.8 * risk_score)


def best_first_triage_plan(alerts: pd.DataFrame, limit: int = 10) -> dict[str, Any]:
    """Return a best-first investigation order over current alerts.

    The method computes a heuristic score per alert and expands the frontier by
    always selecting the highest-score unvisited node first.
    """
    if alerts.empty:
        return {
            "algorithm": "Best-First Search",
            "queue": [],
            "notes": "No alerts available.",
        }

    df = alerts.copy()
    df["heuristic_priority"] = df.apply(_row_priority, axis=1)
    df = df.sort_values("heuristic_priority", ascending=False).reset_index(drop=True)

    queue = []
    for _, row in df.head(limit).iterrows():
        queue.append(
            {
                "source_ip": str(row.get("source_ip", "")),
                "attack_type": str(row.get("attack_type", "unknown")),
                "severity": int(float(row.get("severity", 0) or 0)),
                "confidence": round(float(row.get("confidence", 0) or 0), 1),
                "risk_score": round(float(row.get("risk_score", 0) or 0), 2),
                "priority": round(float(row.get("heuristic_priority", 0) or 0), 2),
            }
        )

    return {
        "algorithm": "Best-First Search",
        "queue": queue,
        "notes": "Higher priority indicates earlier triage order.",
    }
