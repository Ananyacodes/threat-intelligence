"""
core/feature_engineer.py
Transforms preprocessed log DataFrames into feature matrices for ML models.

Two feature sets:
  - system_features()   → for system/auth log anomaly detection
  - network_features()  → for network traffic anomaly detection
"""

import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    BRUTE_FORCE_FAILED_LOGINS,
    PORT_SCAN_UNIQUE_PORTS,
    DOS_PACKETS_PER_SECOND,
    EXFIL_BYTES_THRESHOLD,
)

# ── Rolling-window aggregations ────────────────────────────────────────────────
WINDOW_MINUTES = 10   # look-back window for per-IP aggregations


def _rolling_ip_stats(df: pd.DataFrame, window_min: int = WINDOW_MINUTES) -> pd.DataFrame:
    """
    For each row, count events from the same source_ip in the preceding
    `window_min` minutes.  Adds:
      - ip_event_count     total events from this IP in window
      - ip_failed_count    total failed logins from this IP in window
    """
    df = df.sort_values("timestamp").copy()
    df["_ts_num"] = df["timestamp"].astype(np.int64) // 1_000_000  # ms
    window_ms     = window_min * 60 * 1_000

    ip_event   = []
    ip_failed  = []

    for _, row in df.iterrows():
        mask = (
            (df["source_ip"] == row["source_ip"]) &
            (df["_ts_num"]   >= row["_ts_num"] - window_ms) &
            (df["_ts_num"]   <= row["_ts_num"])
        )
        subset = df[mask]
        ip_event.append(len(subset))
        if "failed_count" in df.columns:
            ip_failed.append(subset["failed_count"].sum())
        else:
            ip_failed.append(0)

    df["ip_event_count"]  = ip_event
    df["ip_failed_count"] = ip_failed
    df.drop(columns=["_ts_num"], inplace=True)
    return df


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM FEATURES
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_FEATURE_COLS = [
    "failed_count",
    "event_code",
    "log_level_code",
    "hour",
    "is_night",
    "is_external_ip",
    "is_privileged_user",
    "ip_event_count",
    "ip_failed_count",
    "heuristic_brute_force",
    "heuristic_priv_esc",
]


def system_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Returns df with SYSTEM_FEATURE_COLS filled in.
    Also adds heuristic flag columns for viva justification.
    """
    df = df.copy()

    # Rolling IP stats (slow but transparent — swap for groupby if needed)
    df = _rolling_ip_stats(df)

    # Heuristic flags (Unit 1: AI Agents / Knowledge Representation)
    df["heuristic_brute_force"] = (
        (df["failed_count"] >= BRUTE_FORCE_FAILED_LOGINS) |
        (df["ip_failed_count"] >= BRUTE_FORCE_FAILED_LOGINS)
    ).astype(int)

    df["heuristic_priv_esc"] = (
        df["event_code"] == 2      # PRIVILEGE_ESCALATION code
    ).astype(int)

    # Fill any missing feature columns with 0
    for col in SYSTEM_FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    return df


def system_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Return pure numpy matrix of system features."""
    df = system_features(df)
    return df[SYSTEM_FEATURE_COLS].fillna(0).values


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK FEATURES
# ══════════════════════════════════════════════════════════════════════════════

NETWORK_FEATURE_COLS = [
    "bytes_sent",
    "bytes_received",
    "bytes_ratio",
    "duration_sec",
    "packet_count",
    "pps",
    "protocol_code",
    "destination_port",
    "is_well_known_port",
    "is_external_src",
    "hour",
    "is_night",
    "heuristic_port_scan",
    "heuristic_dos",
    "heuristic_exfil",
]


def network_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Per-IP unique destination-port count in a 10-min window
    df = df.sort_values("timestamp")
    window_ms  = WINDOW_MINUTES * 60 * 1_000
    df["_ts_num"] = df["timestamp"].astype(np.int64) // 1_000_000

    unique_ports = []
    for _, row in df.iterrows():
        mask = (
            (df["source_ip"] == row["source_ip"]) &
            (df["_ts_num"]   >= row["_ts_num"] - window_ms) &
            (df["_ts_num"]   <= row["_ts_num"])
        )
        unique_ports.append(df[mask]["destination_port"].nunique())
    df["ip_unique_dst_ports"] = unique_ports
    df.drop(columns=["_ts_num"], inplace=True)

    # Heuristic flags
    df["heuristic_port_scan"] = (
        df["ip_unique_dst_ports"] >= PORT_SCAN_UNIQUE_PORTS
    ).astype(int)

    df["heuristic_dos"] = (
        df["pps"] >= DOS_PACKETS_PER_SECOND
    ).astype(int)

    df["heuristic_exfil"] = (
        (df["bytes_sent"]  >= EXFIL_BYTES_THRESHOLD) &
        (df["bytes_ratio"] >= 10)   # sending much more than receiving
    ).astype(int)

    for col in NETWORK_FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0

    return df


def network_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    df = network_features(df)
    return df[NETWORK_FEATURE_COLS].fillna(0).values


if __name__ == "__main__":
    from preprocessor import preprocess_system_logs, preprocess_network_logs

    sys_df = preprocess_system_logs()
    net_df = preprocess_network_logs()

    sys_feat = system_features(sys_df)
    net_feat = network_features(net_df)

    print("System feature matrix shape :", system_feature_matrix(sys_df).shape)
    print("Network feature matrix shape:", network_feature_matrix(net_df).shape)
    print("\nSystem heuristic flags:")
    print(sys_feat[["source_ip", "event", "heuristic_brute_force",
                     "heuristic_priv_esc"]].value_counts(
        ["heuristic_brute_force", "heuristic_priv_esc"]))
