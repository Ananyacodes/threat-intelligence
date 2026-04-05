"""
config.py
Central configuration for the AI Threat Intelligence System.
Edit thresholds and paths here — no need to touch other files.
"""

import os

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_DIR   = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")

SYSTEM_LOG_PATH  = os.path.join(DATA_DIR, "system_logs.csv")
NETWORK_LOG_PATH = os.path.join(DATA_DIR, "network_logs.csv")
ALERTS_PATH      = os.path.join(DATA_DIR, "alerts_store.csv")

IFOREST_MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")
OCSVM_MODEL_PATH   = os.path.join(MODELS_DIR, "ocsvm.pkl")
KMEANS_MODEL_PATH  = os.path.join(MODELS_DIR, "kmeans_clusters.pkl")

# ── Anomaly Detection ──────────────────────────────────────────────────────────
CONTAMINATION        = 0.08   # expected fraction of anomalies (8%)
IFOREST_N_ESTIMATORS = 100
OCSVM_NU             = 0.05
OCSVM_KERNEL         = "rbf"

# Combined anomaly score threshold (0–1). Above this = alert.
ANOMALY_SCORE_THRESHOLD = 0.55

# ── Heuristic Thresholds ───────────────────────────────────────────────────────
BRUTE_FORCE_FAILED_LOGINS   = 5    # failed logins in window → brute force flag
PORT_SCAN_UNIQUE_PORTS       = 10   # unique dst ports from one IP → scan flag
DOS_CONNECTION_OBSERVATIONS  = 25   # repeated observations of same flow → DoS flag
EXFIL_CONNECTION_OBSERVATIONS = 20  # sustained outbound flow observations → exfil flag

# ── Severity Scoring ───────────────────────────────────────────────────────────
# Each attack type maps to a base severity (1=low … 5=critical)
ATTACK_SEVERITY = {
    "normal":               0,
    "brute_force":          4,
    "port_scan":            2,
    "dos":                  5,
    "data_exfiltration":    5,
    "firewall_activity":    3,
    "privilege_escalation": 4,
    "unknown_anomaly":      3,
}

# ── Clustering (Phase 3) ───────────────────────────────────────────────────────
KMEANS_N_CLUSTERS = 5
DBSCAN_EPS        = 0.5
DBSCAN_MIN_SAMPLES = 5

# ── Flask Dashboard (Phase 2) ──────────────────────────────────────────────────
FLASK_HOST     = "0.0.0.0"
FLASK_PORT     = 5000
FLASK_DEBUG    = True
POLL_INTERVAL  = 5   # seconds between dashboard refreshes

# ── Reproducibility ───────────────────────────────────────────────────────────
RANDOM_SEED = 42
