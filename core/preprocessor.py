"""
core/preprocessor.py
Loads raw CSV logs, cleans them, and returns normalised DataFrames
ready for feature engineering.

Handles both system logs and network logs.
"""

import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import SYSTEM_LOG_PATH, NETWORK_LOG_PATH


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_timestamp(df: pd.DataFrame) -> pd.DataFrame:
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).copy()
    df["hour"]       = df["timestamp"].dt.hour
    df["minute"]     = df["timestamp"].dt.minute
    df["day_of_week"] = df["timestamp"].dt.dayofweek   # 0=Mon … 6=Sun
    df["is_night"]   = df["hour"].apply(lambda h: 1 if h < 6 or h >= 22 else 0)
    return df


def _encode_ip(ip_series: pd.Series) -> pd.Series:
    """Convert dotted-quad IP to a single int64 for ML models."""
    def to_int(ip):
        try:
            parts = str(ip).split(".")
            return int(parts[0]) * 16_777_216 + int(parts[1]) * 65_536 + \
                   int(parts[2]) * 256 + int(parts[3])
        except Exception:
            return 0
    return ip_series.apply(to_int)


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM LOG PREPROCESSING
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_REQUIRED_COLS = [
    "timestamp", "source_ip", "user", "service",
    "event", "failed_count", "log_level",
]

def preprocess_system_logs(path: str = None) -> pd.DataFrame:
    path = path or SYSTEM_LOG_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"System log not found: {path}\n"
                                "Run core/generate_logs.py first.")

    df = pd.read_csv(path)
    print(f"[preprocessor] Loaded {len(df)} system log rows.")

    # Drop rows missing critical fields
    df = df.dropna(subset=["timestamp", "source_ip", "event"]).copy()

    # Fill optional columns
    df["failed_count"] = pd.to_numeric(df.get("failed_count", 0), errors="coerce").fillna(0)
    df["log_level"]    = df.get("log_level", "INFO").fillna("INFO")
    df["user"]         = df.get("user", "unknown").fillna("unknown")
    df["service"]      = df.get("service", "unknown").fillna("unknown")

    # Timestamp features
    df = _parse_timestamp(df)

    # Encode categoricals
    df["event_code"] = df["event"].map({
        "LOGIN_SUCCESS":       0,
        "LOGIN_FAILED":        1,
        "PRIVILEGE_ESCALATION": 2,
    }).fillna(3).astype(int)

    df["log_level_code"] = df["log_level"].map({
        "INFO": 0, "WARNING": 1, "ERROR": 2
    }).fillna(0).astype(int)

    df["source_ip_int"] = _encode_ip(df["source_ip"])

    # Is the source IP external?  (not 192.168.x.x)
    df["is_external_ip"] = (~df["source_ip"].str.startswith("192.168.")).astype(int)

    # Is user a privileged account?
    privileged = {"root", "admin", "administrator"}
    df["is_privileged_user"] = df["user"].isin(privileged).astype(int)

    print(f"[preprocessor] System logs cleaned: {len(df)} rows.")
    return df


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK LOG PREPROCESSING
# ══════════════════════════════════════════════════════════════════════════════

def preprocess_network_logs(path: str = None) -> pd.DataFrame:
    path = path or NETWORK_LOG_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(f"Network log not found: {path}\n"
                                "Run core/generate_logs.py first.")

    df = pd.read_csv(path)
    print(f"[preprocessor] Loaded {len(df)} network log rows.")

    df = df.dropna(subset=["timestamp", "source_ip", "destination_ip"]).copy()

    # Numeric coercion
    for col in ["bytes_sent", "bytes_received", "duration_sec", "packet_count",
                "source_port", "destination_port"]:
        df[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0)

    df["protocol"] = df.get("protocol", "TCP").fillna("TCP")

    # Timestamp features
    df = _parse_timestamp(df)

    # Encode protocol
    df["protocol_code"] = df["protocol"].map({"TCP": 0, "UDP": 1, "ICMP": 2}).fillna(3).astype(int)

    # IP encodings
    df["source_ip_int"]      = _encode_ip(df["source_ip"])
    df["destination_ip_int"] = _encode_ip(df["destination_ip"])
    df["is_external_src"]    = (~df["source_ip"].str.startswith("192.168.")).astype(int)

    # Derived features
    df["bytes_ratio"] = df["bytes_sent"] / (df["bytes_received"] + 1)
    df["pps"]         = df["packet_count"] / (df["duration_sec"] + 0.001)  # packets/sec
    df["is_well_known_port"] = (df["destination_port"] < 1024).astype(int)

    print(f"[preprocessor] Network logs cleaned: {len(df)} rows.")
    return df


# ── Quick test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    sys_df = preprocess_system_logs()
    net_df = preprocess_network_logs()
    print("\nSystem log sample:")
    print(sys_df[["timestamp", "source_ip", "event", "failed_count",
                   "is_external_ip", "is_night"]].head())
    print("\nNetwork log sample:")
    print(net_df[["timestamp", "source_ip", "bytes_sent", "pps",
                   "bytes_ratio", "is_external_src"]].head())
