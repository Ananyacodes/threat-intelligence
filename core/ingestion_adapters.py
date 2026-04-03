from __future__ import annotations

from pathlib import Path

import pandas as pd


SYSTEM_COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "event_time", "datetime", "ts"],
    "user": ["user", "username", "account", "principal", "actor"],
    "ip": ["ip", "src_ip", "source_ip", "client_ip", "host_ip"],
    "event_type": ["event_type", "event", "action", "event_name", "status"],
    "process_name": ["process_name", "process", "proc", "service", "application"],
}

NETWORK_COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "event_time", "datetime", "ts"],
    "src_ip": ["src_ip", "source_ip", "ip", "client_ip", "src"],
    "dst_ip": ["dst_ip", "destination_ip", "dest_ip", "server_ip", "dst"],
    "dst_port": ["dst_port", "destination_port", "port", "server_port"],
    "protocol": ["protocol", "proto", "transport"],
    "packets": ["packets", "packet_count", "pkt_count", "pkts"],
    "bytes_sent": ["bytes_sent", "bytes", "bytes_out", "byte_count", "payload_bytes"],
}


def _normalize(df: pd.DataFrame) -> pd.DataFrame:
    cleaned = df.copy()
    cleaned.columns = [str(col).strip().lower() for col in cleaned.columns]
    return cleaned


def _resolve_aliases(df: pd.DataFrame, aliases: dict[str, list[str]], kind: str) -> pd.DataFrame:
    resolved = {}
    source_columns = set(df.columns)

    for target, candidates in aliases.items():
        match = next((candidate for candidate in candidates if candidate in source_columns), None)
        if match is not None:
            resolved[target] = match

    required = ["timestamp", "ip", "event_type"] if kind == "system" else ["timestamp", "src_ip", "dst_port", "packets", "bytes_sent"]
    missing_required = [column for column in required if column not in resolved]
    if missing_required:
        raise ValueError(
            f"Missing required {kind} columns after alias mapping: {missing_required}. "
            f"Available columns: {sorted(source_columns)}"
        )

    output = pd.DataFrame()
    for target in aliases:
        if target in resolved:
            output[target] = df[resolved[target]]

    # Keep unknown fields for troubleshooting and future feature additions.
    untouched = [col for col in df.columns if col not in resolved.values()]
    for col in untouched:
        output[col] = df[col]

    if kind == "system" and "user" not in output.columns:
        output["user"] = "unknown"
    if kind == "system" and "process_name" not in output.columns:
        output["process_name"] = "unknown"
    if kind == "network" and "dst_ip" not in output.columns:
        output["dst_ip"] = "unknown"
    if kind == "network" and "protocol" not in output.columns:
        output["protocol"] = "UNKNOWN"

    return output


def load_system_logs(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"System log file not found: {path}")

    raw = pd.read_csv(path)
    normalized = _normalize(raw)
    return _resolve_aliases(normalized, SYSTEM_COLUMN_ALIASES, kind="system")


def load_network_logs(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Network log file not found: {path}")

    raw = pd.read_csv(path)
    normalized = _normalize(raw)
    return _resolve_aliases(normalized, NETWORK_COLUMN_ALIASES, kind="network")
