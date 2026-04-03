from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from config import NETWORK_LOG_PATH, SYSTEM_LOG_PATH

SYSTEM_LOG_PATH = Path(SYSTEM_LOG_PATH)
NETWORK_LOG_PATH = Path(NETWORK_LOG_PATH)


def _run_powershell(command: str) -> str:
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed.")
    return result.stdout.strip()


def _json_from_powershell(command: str) -> list[dict]:
    output = _run_powershell(command)
    if not output:
        return []

    parsed = json.loads(output)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    return []


def collect_system_logs(minutes: int, max_events: int) -> pd.DataFrame:
    # Security log: 4624=login success, 4625=login failed, 4688=process start.
    security_query = f"""
    $start=(Get-Date).AddMinutes(-{minutes});
    $events=Get-WinEvent -FilterHashtable @{{LogName='Security'; StartTime=$start; Id=4624,4625,4688}} -MaxEvents {max_events} -ErrorAction SilentlyContinue;
    $events | ForEach-Object {{
            $etype='other';
            if ($_.Id -eq 4624) {{ $etype='login_success' }}
            elseif ($_.Id -eq 4625) {{ $etype='login_failed' }}
            elseif ($_.Id -eq 4688) {{ $etype='process_start' }}
      [PSCustomObject]@{{
        timestamp=$_.TimeCreated.ToString('o');
        user=(if($_.Properties.Count -gt 5 -and $_.Properties[5].Value){{ [string]$_.Properties[5].Value }} else {{ 'unknown' }});
        ip=(if($_.Properties.Count -gt 18 -and $_.Properties[18].Value){{ [string]$_.Properties[18].Value }} else {{ 'unknown' }});
                event_type=$etype;
        process_name=(if($_.Properties.Count -gt 0 -and $_.Properties[0].Value){{ [string]$_.Properties[0].Value }} else {{ 'unknown' }});
      }}
    }} | ConvertTo-Json -Depth 4
    """

    rows = _json_from_powershell(security_query)
    if rows:
        df = pd.DataFrame(rows)
        df["source_ip"] = df.get("ip", "unknown")
        df["service"] = df.get("process_name", "unknown")
        df["event"] = df.get("event_type", "other").astype(str).str.upper()
        df["failed_count"] = (df["event"] == "LOGIN_FAILED").astype(int)
        df["log_level"] = df["event"].map(
            {"LOGIN_FAILED": "WARNING", "PROCESS_START": "INFO", "LOGIN_SUCCESS": "INFO"}
        ).fillna("INFO")
        out_cols = [
            "timestamp", "source_ip", "user", "service",
            "event", "failed_count", "log_level",
        ]
        return df[out_cols]

    # Fallback if Security log access is restricted.
    fallback_query = f"""
    $start=(Get-Date).AddMinutes(-{minutes});
    $events=Get-WinEvent -FilterHashtable @{{LogName='System'; StartTime=$start}} -MaxEvents {max_events} -ErrorAction SilentlyContinue;
    $events | ForEach-Object {{
      [PSCustomObject]@{{
        timestamp=$_.TimeCreated.ToString('o');
        user='system';
        ip='unknown';
        event_type='process_start';
        process_name=[string]$_.ProviderName;
      }}
    }} | ConvertTo-Json -Depth 4
    """
    fallback_rows = _json_from_powershell(fallback_query)
    if not fallback_rows:
        return pd.DataFrame(
            columns=["timestamp", "source_ip", "user", "service", "event", "failed_count", "log_level"]
        )

    df = pd.DataFrame(fallback_rows)
    df["source_ip"] = df.get("ip", "unknown")
    df["service"] = df.get("process_name", "unknown")
    df["event"] = "PROCESS_START"
    df["failed_count"] = 0
    df["log_level"] = "INFO"
    out_cols = [
        "timestamp", "source_ip", "user", "service",
        "event", "failed_count", "log_level",
    ]
    return df[out_cols]


def collect_network_logs(duration_seconds: int, sample_interval: float) -> pd.DataFrame:
    samples = []
    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        query = """
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort |
        ConvertTo-Json -Depth 3
        """

        try:
            rows = _json_from_powershell(query)
        except RuntimeError:
            rows = []

        ts = datetime.now(tz=timezone.utc).isoformat()
        for row in rows:
            local_addr = str(row.get("LocalAddress", "unknown"))
            local_port = int(row.get("LocalPort", 0) or 0)
            remote_addr = str(row.get("RemoteAddress", "unknown"))
            remote_port = int(row.get("RemotePort", 0) or 0)

            if remote_port <= 0:
                continue

            samples.append(
                {
                    "timestamp": ts,
                    "source_ip": local_addr,
                    "destination_ip": remote_addr,
                    "source_port": local_port,
                    "destination_port": remote_port,
                    "protocol": "TCP",
                    "duration_sec": sample_interval,
                }
            )

        time.sleep(sample_interval)

    if not samples:
        return pd.DataFrame(
            columns=[
                "timestamp", "source_ip", "destination_ip", "source_port",
                "destination_port", "protocol", "bytes_sent", "bytes_received",
                "duration_sec", "packet_count",
            ]
        )

    df = pd.DataFrame(samples)

    # Convert repeated observed flows into packet/byte proxies usable by feature engineering.
    grouped = (
        df.groupby(
            ["timestamp", "source_ip", "destination_ip", "source_port", "destination_port", "protocol"],
            as_index=False,
        )
        .size()
        .rename(columns={"size": "packet_count"})
    )
    grouped["bytes_sent"] = grouped["packet_count"] * 1200
    grouped["bytes_received"] = grouped["packet_count"] * 300
    grouped["duration_sec"] = sample_interval

    return grouped


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect real Windows logs into CSV files for the threat-intel pipeline.")
    parser.add_argument("--minutes", type=int, default=180, help="How far back to read Windows event logs.")
    parser.add_argument("--max-events", type=int, default=8000, help="Max system events to pull.")
    parser.add_argument(
        "--network-seconds",
        type=int,
        default=90,
        help="How long to sample active network connections.",
    )
    parser.add_argument(
        "--network-interval",
        type=float,
        default=1.0,
        help="Sampling interval for network collection in seconds.",
    )
    args = parser.parse_args()

    SYSTEM_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    NETWORK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    system_df = collect_system_logs(minutes=args.minutes, max_events=args.max_events)
    network_df = collect_network_logs(
        duration_seconds=args.network_seconds,
        sample_interval=args.network_interval,
    )

    if system_df.empty:
        raise RuntimeError("No system events were collected. Try running PowerShell as Administrator.")
    if network_df.empty:
        raise RuntimeError("No active network connections were observed during sampling.")

    system_df.to_csv(SYSTEM_LOG_PATH, index=False)
    network_df.to_csv(NETWORK_LOG_PATH, index=False)

    print(f"System logs written: {SYSTEM_LOG_PATH} ({len(system_df)} rows)")
    print(f"Network logs written: {NETWORK_LOG_PATH} ({len(network_df)} rows)")


if __name__ == "__main__":
    main()
