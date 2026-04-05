"""
core/alert_engine.py
Converts raw anomaly scores into structured, actionable alerts.

Each alert contains:
  - timestamp, source_ip
  - attack_type   (inferred from heuristics + model score)
  - severity      (1=low … 5=critical)
  - confidence    (0–100 %)
  - description
  - recommendation
"""

import pandas as pd
import numpy as np
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    ATTACK_SEVERITY, ANOMALY_SCORE_THRESHOLD, ALERTS_PATH, DATA_DIR
)


# ── Attack type inference ──────────────────────────────────────────────────────

def _infer_attack_type_system(row: pd.Series) -> str:
    if row.get("heuristic_priv_esc", 0):
        return "privilege_escalation"
    if row.get("heuristic_brute_force", 0):
        return "brute_force"
    return "unknown_anomaly"


def _infer_attack_type_network(row: pd.Series) -> str:
    if row.get("heuristic_firewall_activity", 0):
        return "firewall_activity"
    if row.get("heuristic_dos", 0):
        return "dos"
    if row.get("heuristic_exfil", 0):
        return "data_exfiltration"
    if row.get("heuristic_port_scan", 0):
        return "port_scan"
    return "unknown_anomaly"


# ── Recommendations ────────────────────────────────────────────────────────────

RECOMMENDATIONS = {
    "brute_force":          "Block source IP. Enforce MFA. Implement account lockout after 5 failures.",
    "privilege_escalation": "Audit sudo rules. Review PAM config. Alert SOC immediately.",
    "port_scan":            "Block source IP at firewall. Review exposed services. Enable IDS rules.",
    "dos":                  "Rate-limit source IP. Enable CDN/WAF. Scale or failover target service.",
    "data_exfiltration":    "Isolate source host. Revoke credentials. Capture network forensics.",
    "firewall_activity":    "Review recent firewall rule or profile changes. Confirm they match approved change control.",
    "unknown_anomaly":      "Investigate manually. Capture full logs for the source IP in this window.",
}

DESCRIPTIONS = {
    "brute_force":          "Repeated failed login attempts detected from a single source.",
    "privilege_escalation": "Attempt to gain elevated system privileges detected.",
    "port_scan":            "Rapid probe of multiple destination ports from a single source.",
    "dos":                  "Sustained high-rate connection observations targeting a host/service.",
    "data_exfiltration":    "Sustained outbound connection observations toward external destinations.",
    "firewall_activity":    "Firewall rule or profile change activity detected in the Windows event logs.",
    "unknown_anomaly":      "Anomalous behaviour detected by ML model without matching heuristic.",
}


# ══════════════════════════════════════════════════════════════════════════════
def build_alerts(df: pd.DataFrame,
                 prediction: dict,
                 log_type: str = "system") -> pd.DataFrame:
    """
    Parameters
    ----------
    df          : preprocessed + feature-engineered DataFrame
    prediction  : output dict from AnomalyDetector.predict()
    log_type    : "system" or "network"

    Returns
    -------
    DataFrame of alerts (only anomalous rows), sorted by severity desc.
    """
    df = df.copy()
    df["anomaly_score"] = prediction["anomaly_score"]
    df["is_anomaly"]    = prediction["is_anomaly"]
    df["iforest_score"] = prediction["iforest_score"]
    df["ocsvm_score"]   = prediction["ocsvm_score"]

    if log_type == "system":
        heuristic_mask = (df.get("heuristic_brute_force", 0) == 1) | (df.get("heuristic_priv_esc", 0) == 1)
    else:
        heuristic_mask = (
            (df.get("heuristic_port_scan", 0) == 1) |
            (df.get("heuristic_dos", 0) == 1) |
            (df.get("heuristic_exfil", 0) == 1) |
            (df.get("heuristic_firewall_activity", 0) == 1)
        )

    anomalies = df[(df["is_anomaly"] == 1) | heuristic_mask].copy()
    if anomalies.empty:
        print(f"[alert_engine] No anomalies found in {log_type} logs.")
        return pd.DataFrame()

    anomalies["rule_based_alert"] = (~(anomalies["is_anomaly"] == 1) & heuristic_mask.loc[anomalies.index]).astype(int)

    # Infer attack type per row
    if log_type == "system":
        anomalies["attack_type"] = anomalies.apply(_infer_attack_type_system, axis=1)
    else:
        anomalies["attack_type"] = anomalies.apply(_infer_attack_type_network, axis=1)

    # Severity: base from config + boost for high confidence
    anomalies["base_severity"] = anomalies["attack_type"].map(ATTACK_SEVERITY).fillna(3)
    anomalies["confidence"]    = (anomalies["anomaly_score"] * 100).round(1)
    anomalies.loc[anomalies["rule_based_alert"] == 1, "confidence"] = 75.0

    # Boost severity if confidence > 85
    anomalies["severity"] = anomalies.apply(
        lambda r: min(5, int(r["base_severity"]) + 1)
        if r["confidence"] > 85 else int(r["base_severity"]),
        axis=1
    )

    anomalies["description"]     = anomalies["attack_type"].map(DESCRIPTIONS)
    anomalies["recommendation"]  = anomalies["attack_type"].map(RECOMMENDATIONS)
    anomalies["log_type"]        = log_type
    anomalies["detected_at"]     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    anomalies["data_origin"]     = "real_collected"

    alert_cols = [
        "detected_at", "timestamp", "source_ip", "attack_type",
        "severity", "confidence", "anomaly_score",
        "description", "recommendation", "log_type", "data_origin",
        "rule_based_alert",
    ]
    # Add optional columns if they exist
    for opt in ["destination_ip", "destination_port", "connection_observation_count",
                "connection_observation_rate", "duration_sec",
            "hour", "is_external_ip", "is_external_src",
            "user", "service", "event", "event_type", "event_id",
            "event_message", "log_level", "query_name", "query_type", "action"]:
        if opt in anomalies.columns:
            alert_cols.append(opt)

    alerts = anomalies[alert_cols].sort_values(
        ["severity", "confidence"], ascending=False
    ).reset_index(drop=True)

    return alerts


# ══════════════════════════════════════════════════════════════════════════════
def save_alerts(alerts: pd.DataFrame):
    """Persist alerts to CSV with a stable merged schema."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if alerts.empty:
        return

    if os.path.exists(ALERTS_PATH):
        existing = pd.read_csv(ALERTS_PATH, engine="python", on_bad_lines="skip")
        combined = pd.concat([existing, alerts], ignore_index=True, sort=False)
    else:
        combined = alerts.copy()

    combined.to_csv(ALERTS_PATH, index=False)
    print(f"[alert_engine] {len(alerts)} alerts saved → {ALERTS_PATH}")


def load_alerts() -> pd.DataFrame:
    if not os.path.exists(ALERTS_PATH):
        return pd.DataFrame()
    alerts = pd.read_csv(ALERTS_PATH, engine="python", on_bad_lines="skip")
    if "data_origin" not in alerts.columns:
        print("[alert_engine] Ignoring alerts without data_origin=real_collected.")
        return pd.DataFrame()
    alerts = alerts[alerts["data_origin"] == "real_collected"].copy()
    if alerts.empty:
        print("[alert_engine] No real_collected alerts found in store.")
    return alerts


def print_alert_summary(alerts: pd.DataFrame, log_type: str = ""):
    if alerts.empty:
        print(f"[{log_type}] No alerts.")
        return
    label = f"{log_type} " if log_type else ""
    print(f"\n{'='*60}")
    print(f"  {label.upper()}ALERTS  ({len(alerts)} total)")
    print(f"{'='*60}")
    for _, row in alerts.head(15).iterrows():
        sev_bar = "█" * int(row["severity"]) + "░" * (5 - int(row["severity"]))
        print(f"  [{sev_bar}] SEV {int(row['severity'])}  {row['attack_type']:<25}"
              f"  {str(row.get('source_ip','')):<18}"
              f"  conf={row['confidence']:.0f}%")
        print(f"             ↳ {row['description']}")
        print(f"             ✓ {row['recommendation']}\n")
    if len(alerts) > 15:
        print(f"  … and {len(alerts)-15} more alerts (see alerts_store.csv)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    from preprocessor     import preprocess_system_logs, preprocess_network_logs
    from feature_engineer import system_feature_matrix, network_feature_matrix, \
                                   system_features, network_features
    from anomaly_detector import train_system_detector, train_network_detector

    sys_df  = preprocess_system_logs()
    net_df  = preprocess_network_logs()

    sys_feat_df = system_features(sys_df)
    net_feat_df = network_features(net_df)

    X_sys = sys_feat_df[
        ["failed_count","event_code","log_level_code","hour",
         "is_night","is_external_ip","is_privileged_user",
         "ip_event_count","ip_failed_count",
         "heuristic_brute_force","heuristic_priv_esc"]
    ].fillna(0).values

    X_net = net_feat_df[
                ["duration_sec","connection_observation_count","connection_observation_rate","log_type_code","event_id",
                "event_type_code","event_message_length","protocol_code",
                "source_port","destination_port","is_well_known_port",
                "is_external_src","is_external_dst","has_source_ip","has_destination_ip",
                "has_source_port","has_destination_port","has_protocol",
                "is_firewall_event","is_dns_event","is_security_event",
                "hour","is_night",
            "heuristic_port_scan","heuristic_dos","heuristic_exfil","heuristic_firewall_activity"]
    ].fillna(0).values

    sys_det  = train_system_detector(X_sys)
    net_det  = train_network_detector(X_net)

    sys_pred = sys_det.predict(X_sys)
    net_pred = net_det.predict(X_net)

    sys_alerts = build_alerts(sys_feat_df, sys_pred, "system")
    net_alerts = build_alerts(net_feat_df, net_pred, "network")

    print_alert_summary(sys_alerts, "SYSTEM")
    print_alert_summary(net_alerts, "NETWORK")

    save_alerts(sys_alerts)
    save_alerts(net_alerts)
