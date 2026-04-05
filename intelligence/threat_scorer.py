"""
intelligence/threat_scorer.py
Phase 3 — assigns a CVSS-inspired numeric risk score (0–10) to each alert.

Score components
  Attack vector     external IP → higher score
  Complexity        unknown anomaly → higher (less understood)
  Confidence        model confidence → amplifier
  Severity          base attack severity (from config)
  Time factor       night-time attacks score higher

Final score = weighted sum, clamped to [0, 10].
"""

import pandas as pd
import numpy as np
import ipaddress
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import ATTACK_SEVERITY

# ── Scoring weights ────────────────────────────────────────────────────────────
W_SEVERITY   = 0.35
W_CONFIDENCE = 0.25
W_EXTERNAL   = 0.15
W_COMPLEXITY = 0.15
W_TIME       = 0.10

COMPLEXITY_MAP = {
    "dos":                  0.5,   # well-understood
    "port_scan":            0.4,
    "brute_force":          0.6,
    "privilege_escalation": 0.8,
    "data_exfiltration":    0.9,
    "unknown_anomaly":      1.0,   # least understood → highest complexity
}


def score_alerts(alerts: pd.DataFrame) -> pd.DataFrame:
    """
    Adds a `risk_score` column (0–10, 2 d.p.) and `risk_level` (Low/Med/High/Critical).
    """
    alerts = alerts.copy()

    # Normalised severity [0,1]
    max_sev = max(ATTACK_SEVERITY.values()) or 5
    alerts["_sev_norm"]   = alerts["severity"].clip(0, max_sev) / max_sev

    # Normalised confidence [0,1]
    alerts["_conf_norm"]  = alerts["confidence"].clip(0, 100) / 100

    # External IP flag
    if "is_external_ip" in alerts.columns:
        alerts["_ext_flag"] = pd.to_numeric(alerts["is_external_ip"], errors="coerce").fillna(0)
    elif "source_ip" in alerts.columns:
        def _is_external(ip_value) -> int:
            try:
                ip_obj = ipaddress.ip_address(str(ip_value))
                return 0 if ip_obj.is_private else 1
            except ValueError:
                return 0
        alerts["_ext_flag"] = alerts["source_ip"].apply(_is_external)
    else:
        alerts["_ext_flag"] = 0

    # Complexity
    alerts["_complexity"] = alerts["attack_type"].map(COMPLEXITY_MAP).fillna(0.7)

    # Time factor (night = 1, day = 0.5)
    if "hour" in alerts.columns:
        alerts["_time_factor"] = alerts["hour"].apply(
            lambda h: 1.0 if (h < 6 or h >= 22) else 0.5
        )
    else:
        alerts["_time_factor"] = 0.7

    # Weighted sum → scale to [0, 10]
    raw = (
        W_SEVERITY   * alerts["_sev_norm"]   +
        W_CONFIDENCE * alerts["_conf_norm"]  +
        W_EXTERNAL   * alerts["_ext_flag"]   +
        W_COMPLEXITY * alerts["_complexity"] +
        W_TIME       * alerts["_time_factor"]
    )
    alerts["risk_score"] = (raw * 10).clip(0, 10).round(2)

    # Risk level thresholds
    def _level(s):
        if s >= 8.0:   return "Critical"
        if s >= 6.0:   return "High"
        if s >= 4.0:   return "Medium"
        return "Low"

    alerts["risk_level"] = alerts["risk_score"].apply(_level)

    # Drop helper cols
    alerts.drop(columns=[c for c in alerts.columns if c.startswith("_")],
                inplace=True)
    return alerts


if __name__ == "__main__":
    from core.alert_engine import load_alerts

    alerts = load_alerts()
    if alerts.empty:
        print("[scorer] No alerts found. Run main.py first.")
    else:
        scored = score_alerts(alerts)
        print(scored[["attack_type", "severity", "confidence",
                       "risk_score", "risk_level"]].sort_values(
            "risk_score", ascending=False).head(20).to_string(index=False))
