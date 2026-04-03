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
    "unknown_anomaly":      "Investigate manually. Capture full logs for the source IP in this window.",
}

DESCRIPTIONS = {
    "brute_force":          "Repeated failed login attempts detected from a single source.",
    "privilege_escalation": "Attempt to gain elevated system privileges detected.",
    "port_scan":            "Rapid probe of multiple destination ports from a single source.",
    "dos":                  "High packet-rate flood targeting a single host/service.",
    "data_exfiltration":    "Unusually large outbound data transfer to an external IP.",
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

    anomalies = df[df["is_anomaly"] == 1].copy()
    if anomalies.empty:
        print(f"[alert_engine] No anomalies found in {log_type} logs.")
        return pd.DataFrame()

    # Infer attack type per row
    if log_type == "system":
        anomalies["attack_type"] = anomalies.apply(_infer_attack_type_system, axis=1)
    else:
        anomalies["attack_type"] = anomalies.apply(_infer_attack_type_network, axis=1)

    # Severity: base from config + boost for high confidence
    anomalies["base_severity"] = anomalies["attack_type"].map(ATTACK_SEVERITY).fillna(3)
    anomalies["confidence"]    = (anomalies["anomaly_score"] * 100).round(1)

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

    alert_cols = [
        "detected_at", "timestamp", "source_ip", "attack_type",
        "severity", "confidence", "anomaly_score",
        "description", "recommendation", "log_type",
    ]
    # Add optional columns if they exist
    for opt in ["destination_ip", "destination_port", "bytes_sent",
                "user", "service", "event"]:
        if opt in anomalies.columns:
            alert_cols.append(opt)

    alerts = anomalies[alert_cols].sort_values(
        ["severity", "confidence"], ascending=False
    ).reset_index(drop=True)

    return alerts


# ══════════════════════════════════════════════════════════════════════════════
def save_alerts(alerts: pd.DataFrame):
    """Append alerts to the persistent CSV store."""
    os.makedirs(DATA_DIR, exist_ok=True)
    if alerts.empty:
        return
    write_header = not os.path.exists(ALERTS_PATH)
    alerts.to_csv(ALERTS_PATH, mode="a", header=write_header, index=False)
    print(f"[alert_engine] {len(alerts)} alerts saved → {ALERTS_PATH}")


def load_alerts() -> pd.DataFrame:
    if not os.path.exists(ALERTS_PATH):
        return pd.DataFrame()
    return pd.read_csv(ALERTS_PATH)


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
        ["bytes_sent","bytes_received","bytes_ratio","duration_sec",
         "packet_count","pps","protocol_code","destination_port",
         "is_well_known_port","is_external_src","hour","is_night",
         "heuristic_port_scan","heuristic_dos","heuristic_exfil"]
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
