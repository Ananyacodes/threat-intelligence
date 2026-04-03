"""
core/generate_logs.py
Generates realistic synthetic system and network logs.
Injects labelled attack patterns for training and demo purposes.

Attack types injected:
  System  → brute_force, privilege_escalation
  Network → port_scan, dos, data_exfiltration
"""

import pandas as pd
import numpy as np
import random
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (
    SYSTEM_LOG_PATH, NETWORK_LOG_PATH,
    N_NORMAL_SYSTEM_LOGS, N_NORMAL_NETWORK_LOGS, RANDOM_SEED,
    DATA_DIR
)

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ── Actors & constants ─────────────────────────────────────────────────────────
NORMAL_IPS  = [f"192.168.1.{i}" for i in range(10, 60)]
ATTACK_IPS  = ["10.0.0.99", "185.234.218.45", "203.0.113.77", "198.51.100.22"]
USERS       = ["alice", "bob", "charlie", "diana", "eve", "root", "admin"]
SERVICES    = ["sshd", "nginx", "apache2", "mysql", "vsftpd", "cron"]
PORTS       = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 3389, 5432, 8080, 8443]
START_TIME  = datetime(2024, 6, 1, 0, 0, 0)


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM LOGS
# ══════════════════════════════════════════════════════════════════════════════

def _sys_normal(t):
    user    = random.choice(USERS[:5])
    ip      = random.choice(NORMAL_IPS)
    service = random.choice(SERVICES)
    success = random.random() > 0.05
    return {
        "timestamp":    t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":    ip,
        "user":         user,
        "service":      service,
        "event":        "LOGIN_SUCCESS" if success else "LOGIN_FAILED",
        "failed_count": 0 if success else random.randint(1, 2),
        "log_level":    "INFO" if success else "WARNING",
        "label":        "normal",
    }


def _sys_brute_force(t):
    return {
        "timestamp":    t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":    random.choice(ATTACK_IPS),
        "user":         random.choice(["root", "admin", "administrator"]),
        "service":      "sshd",
        "event":        "LOGIN_FAILED",
        "failed_count": random.randint(10, 60),
        "log_level":    "ERROR",
        "label":        "brute_force",
    }


def _sys_priv_escalation(t):
    return {
        "timestamp":    t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":    random.choice(ATTACK_IPS),
        "user":         random.choice(USERS),
        "service":      "sudo",
        "event":        "PRIVILEGE_ESCALATION",
        "failed_count": random.randint(3, 10),
        "log_level":    "ERROR",
        "label":        "privilege_escalation",
    }


def generate_system_logs():
    logs = []

    # Normal traffic spread over 10 000 minutes
    for _ in range(N_NORMAL_SYSTEM_LOGS):
        t = START_TIME + timedelta(minutes=random.randint(0, 10_000))
        logs.append(_sys_normal(t))

    # Brute-force burst at hour 5 (one attempt every 2 s)
    burst_start = START_TIME + timedelta(hours=5)
    for i in range(150):
        logs.append(_sys_brute_force(burst_start + timedelta(seconds=i * 2)))

    # Second brute-force burst at hour 48
    burst2 = START_TIME + timedelta(hours=48)
    for i in range(100):
        logs.append(_sys_brute_force(burst2 + timedelta(seconds=i * 3)))

    # Privilege escalation attempts at hour 12
    priv_start = START_TIME + timedelta(hours=12)
    for i in range(80):
        logs.append(_sys_priv_escalation(priv_start + timedelta(minutes=i)))

    df = (pd.DataFrame(logs)
            .sort_values("timestamp")
            .reset_index(drop=True))
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(SYSTEM_LOG_PATH, index=False)
    print(f"[+] System logs  → {SYSTEM_LOG_PATH}  ({len(df)} rows)")
    return df


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK LOGS
# ══════════════════════════════════════════════════════════════════════════════

def _net_normal(t):
    return {
        "timestamp":        t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":        random.choice(NORMAL_IPS),
        "destination_ip":   f"10.0.0.{random.randint(1, 20)}",
        "source_port":      random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 3306]),
        "protocol":         random.choice(["TCP", "UDP"]),
        "bytes_sent":       random.randint(100, 5_000),
        "bytes_received":   random.randint(100, 10_000),
        "duration_sec":     round(random.uniform(0.1, 30.0), 2),
        "packet_count":     random.randint(5, 200),
        "label":            "normal",
    }


def _net_port_scan(t, attacker_ip):
    return {
        "timestamp":        t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":        attacker_ip,
        "destination_ip":   f"10.0.0.{random.randint(1, 20)}",
        "source_port":      random.randint(1024, 65535),
        "destination_port": random.choice(PORTS),
        "protocol":         "TCP",
        "bytes_sent":       random.randint(40, 80),
        "bytes_received":   0,
        "duration_sec":     round(random.uniform(0.001, 0.1), 4),
        "packet_count":     1,
        "label":            "port_scan",
    }


def _net_dos(t, attacker_ip):
    return {
        "timestamp":        t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":        attacker_ip,
        "destination_ip":   "10.0.0.1",
        "source_port":      random.randint(1024, 65535),
        "destination_port": 80,
        "protocol":         "TCP",
        "bytes_sent":       random.randint(1_000, 100_000),
        "bytes_received":   random.randint(0, 500),
        "duration_sec":     round(random.uniform(0.01, 2.0), 3),
        "packet_count":     random.randint(500, 5_000),
        "label":            "dos",
    }


def _net_exfil(t, attacker_ip):
    return {
        "timestamp":        t.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip":        random.choice(NORMAL_IPS),   # internal compromised host
        "destination_ip":   attacker_ip,
        "source_port":      random.randint(1024, 65535),
        "destination_port": random.choice([443, 8080, 4444, 53]),
        "protocol":         random.choice(["TCP", "UDP"]),
        "bytes_sent":       random.randint(50_000, 500_000),
        "bytes_received":   random.randint(100, 1_000),
        "duration_sec":     round(random.uniform(30, 300), 1),
        "packet_count":     random.randint(50, 500),
        "label":            "data_exfiltration",
    }


def generate_network_logs():
    logs = []

    # Normal traffic
    for _ in range(N_NORMAL_NETWORK_LOGS):
        t = START_TIME + timedelta(minutes=random.randint(0, 10_000))
        logs.append(_net_normal(t))

    # Port scan sweep at hour 3
    scan_start  = START_TIME + timedelta(hours=3)
    attacker    = "185.234.218.45"
    for i in range(200):
        logs.append(_net_port_scan(scan_start + timedelta(seconds=i * 0.5), attacker))

    # DoS flood at hour 8
    dos_start   = START_TIME + timedelta(hours=8)
    attacker2   = "203.0.113.77"
    for i in range(300):
        logs.append(_net_dos(dos_start + timedelta(seconds=i * 0.3), attacker2))

    # Data exfiltration at hour 20
    exfil_start = START_TIME + timedelta(hours=20)
    attacker3   = "198.51.100.22"
    for i in range(60):
        logs.append(_net_exfil(exfil_start + timedelta(minutes=i * 2), attacker3))

    df = (pd.DataFrame(logs)
            .sort_values("timestamp")
            .reset_index(drop=True))
    os.makedirs(DATA_DIR, exist_ok=True)
    df.to_csv(NETWORK_LOG_PATH, index=False)
    print(f"[+] Network logs → {NETWORK_LOG_PATH}  ({len(df)} rows)")
    return df


if __name__ == "__main__":
    generate_system_logs()
    generate_network_logs()
    print("[✓] Log generation complete.")
