"""
core/preprocessor.py
Loads raw CSV logs, cleans them, and returns normalised DataFrames
ready for feature engineering.

Handles both system logs and network logs.
"""

import pandas as pd
import os
import sys
from pandas.errors import EmptyDataError

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


def _is_external_ip(ip: object) -> int:
    value = str(ip).strip()
    if not value or value.lower() in {"unknown", "none", "nan", "-"}:
        return 0
    if value.startswith(("10.", "127.", "192.168.", "169.254.")):
        return 0
    if value.startswith("172."):
        try:
            second = int(value.split('.')[1])
            if 16 <= second <= 31:
                return 0
        except Exception:
            pass
    if value in {"::1", "::", "0.0.0.0"}:
        return 0
    return 1


def _require_columns(df: pd.DataFrame, required: list[str], label: str):
    missing = [col for col in required if col not in df.columns]
    if missing:
        raise ValueError(f"{label} is missing required columns: {missing}")


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
                                "Run the real log collector first.")

    try:
        df = pd.read_csv(path)
    except EmptyDataError:
        print("[preprocessor] System log CSV is empty; skipping system branch.")
        return pd.DataFrame(columns=SYSTEM_REQUIRED_COLS)
    print(f"[preprocessor] Loaded {len(df)} system log rows.")

    if df.empty:
        print("[preprocessor] No system rows collected; skipping system branch.")
        return df

    _require_columns(df, SYSTEM_REQUIRED_COLS, "System log CSV")

    # Drop rows missing critical fields
    df = df.dropna(subset=["timestamp", "source_ip", "event", "failed_count", "log_level"]).copy()

    # Remove placeholders from legacy or non-real datasets.
    df["source_ip"] = df["source_ip"].astype(str).str.strip()
    df = df[~df["source_ip"].str.lower().isin(["", "unknown", "none", "nan", "-", "::1"])].copy()

    df["failed_count"] = pd.to_numeric(df["failed_count"], errors="coerce")
    df = df.dropna(subset=["failed_count"]).copy()
    df["failed_count"] = df["failed_count"].astype(int)

    df["event"] = df["event"].astype(str).str.strip().str.upper()
    df["log_level"] = df["log_level"].astype(str).str.strip().str.upper()
    df["user"] = df["user"].astype(str).str.strip()
    df["service"] = df["service"].astype(str).str.strip()

    if df.empty:
        print("[preprocessor] No usable system rows after strict real-data filtering.")
        return df

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

    # Is the source IP external?
    df["is_external_ip"] = df["source_ip"].apply(_is_external_ip).astype(int)

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
                                "Run the real log collector first.")

    try:
        df = pd.read_csv(path)
    except EmptyDataError:
        print("[preprocessor] Network log CSV is empty; skipping network branch.")
        return pd.DataFrame(columns=[
            "timestamp", "log_type", "event_type", "event_id", "event_message",
            "connection_observation_count", "duration_sec",
        ])

    print(f"[preprocessor] Loaded {len(df)} network log rows.")

    required = [
        "timestamp", "log_type", "event_type", "event_id", "event_message",
        "connection_observation_count", "duration_sec",
    ]
    _require_columns(df, required, "Network log CSV")

    df = df.dropna(subset=["timestamp", "log_type", "event_type", "event_id", "event_message"]).copy()

    for column in [
        "source_ip", "destination_ip", "protocol", "user", "service",
        "query_name", "query_type", "action",
    ]:
        if column not in df.columns:
            df[column] = ""
        df[column] = df[column].fillna("").astype(str).str.strip()

    for column in ["source_port", "destination_port", "event_id", "failed_count", "connection_observation_count", "duration_sec"]:
        if column not in df.columns:
            df[column] = 0
        df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

    df["source_port"] = df["source_port"].astype(int)
    df["destination_port"] = df["destination_port"].astype(int)
    df["event_id"] = df["event_id"].astype(int)
    df["failed_count"] = df["failed_count"].astype(int)
    df["connection_observation_count"] = df["connection_observation_count"].astype(int)
    df["duration_sec"] = df["duration_sec"].astype(float)
    df["log_type"] = df["log_type"].astype(str).str.strip().str.lower()
    df["event_type"] = df["event_type"].astype(str).str.strip().str.upper()
    df["event_message"] = df["event_message"].astype(str).str.strip()
    df["protocol"] = df["protocol"].astype(str).str.strip().str.upper()
    if "log_level" not in df.columns:
        df["log_level"] = "INFORMATION"
    df["log_level"] = df["log_level"].fillna("INFORMATION").astype(str).str.strip().str.upper()

    if df.empty:
        print("[preprocessor] No usable network rows after filtering; skipping network branch.")
        return df

    df = _parse_timestamp(df)

    df["protocol_code"] = df["protocol"].map({"TCP": 0, "UDP": 1, "ICMP": 2, "DNS": 3}).fillna(4).astype(int)
    df["log_type_code"] = df["log_type"].map({"security": 0, "firewall": 1, "dns": 2}).fillna(3).astype(int)
    df["event_type_code"] = pd.factorize(df["event_type"])[0].astype(int)

    df["source_ip_int"]      = _encode_ip(df["source_ip"])
    df["destination_ip_int"] = _encode_ip(df["destination_ip"])
    df["is_external_src"]    = df["source_ip"].apply(_is_external_ip).astype(int)
    df["is_external_dst"]    = df["destination_ip"].apply(_is_external_ip).astype(int)

    df["has_source_ip"]      = (df["source_ip"].str.len() > 0).astype(int)
    df["has_destination_ip"] = (df["destination_ip"].str.len() > 0).astype(int)
    df["has_source_port"]    = (df["source_port"] > 0).astype(int)
    df["has_destination_port"] = (df["destination_port"] > 0).astype(int)
    df["has_protocol"]       = (df["protocol"].str.len() > 0).astype(int)
    df["event_message_length"] = df["event_message"].str.len().astype(int)
    df["is_firewall_event"]  = (df["log_type"] == "firewall").astype(int)
    df["is_dns_event"]       = (df["log_type"] == "dns").astype(int)
    df["is_security_event"]  = (df["log_type"] == "security").astype(int)

    df["connection_observation_rate"] = df["connection_observation_count"] / (df["duration_sec"] + 0.001)
    df["is_well_known_port"] = (df["destination_port"] > 0) & (df["destination_port"] < 1024)
    df["is_well_known_port"] = df["is_well_known_port"].astype(int)

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
    print(net_df[["timestamp", "log_type", "event_type", "event_id", "connection_observation_count",
                   "duration_sec", "connection_observation_rate", "is_firewall_event", "is_dns_event"]].head())
