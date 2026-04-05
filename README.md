# AI Threat Intelligence System

A full-stack AI-powered threat detection and intelligence platform using real Windows log collection.

---

## Quick Start

**Run these commands in PowerShell in order:**

```powershell
# 1) Navigate to project
Set-Location "C:\Users\Ananya\OneDrive\threat-intel\threat_intel_system"

# 2) Install dependencies (first time only)
python.exe -m pip install -r requirements.txt

# 3) Run full pipeline (collect Windows logs → detect anomalies → generate intelligence report)
python.exe main.py

# 4) Launch dashboard in a second PowerShell window
powershell -ExecutionPolicy Bypass -File scripts\run_dashboard.ps1
```

**Then open your browser:**
```
http://localhost:5000
```

**Stop the dashboard:** Press `Ctrl+C` in the terminal.

---

## Using Specific Parameters

Customize data collection and analysis with these command variations:

```powershell
# Phase 1 only: collect logs and detect anomalies (skip intelligence/clustering)
python.exe main.py --phase 1

# Phase 3 only: run intelligence/clustering on existing alerts (skip collection)
python.exe main.py --phase 3

# Collect Windows logs from last N minutes (default is 180)
python.exe main.py --real-minutes 90

# Limit maximum events collected (default is 8000)
python.exe main.py --real-minutes 180 --real-max-events 5000
```

---

## Project Structure

```
threat_intel_system/
├── core/
│   ├── preprocessor.py        # Parse & clean logs
│   ├── feature_engineer.py    # ML feature extraction
│   ├── anomaly_detector.py    # Isolation Forest + One-Class SVM
│   └── alert_engine.py        # Severity scoring + alert output
├── dashboard/
│   ├── app.py                 # Flask REST API
│   ├── visualiser.py          # Plotly chart generators
│   ├── templates/             # HTML pages
│   └── static/                # CSS + JS
├── intelligence/
│   ├── clusterer.py           # K-Means / DBSCAN
│   ├── classifier.py          # Random Forest attack labeller
│   ├── threat_scorer.py       # CVSS-style risk scoring
│   └── report_generator.py    # Threat intelligence report
├── data/                      # Generated logs + alert store
├── models/                    # Saved .pkl model files
├── config.py                  # All thresholds & paths
├── scripts/
│   └── collect_real_logs.ps1   # Real Windows log collection (PowerShell-backed)
├── main.py                    # CLI pipeline runner
└── scripts/run_dashboard.ps1  # Flask server launcher
```

---

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `python.exe main.py` | Full pipeline: collect Windows logs → detect anomalies → clustering → intelligence report |
| `python.exe main.py --phase 1` | Detection only: skip clustering and intelligence (Phase 1) |
| `python.exe main.py --phase 3` | Intelligence only: run clustering/report using existing alerts (Phase 3, requires prior Phase 1 data) |
| `python.exe main.py --real-minutes 90` | Collect logs from last 90 minutes (default 180) |
| `python.exe main.py --real-max-events 5000` | Limit collection to 5000 events (default 8000) |
| `powershell -ExecutionPolicy Bypass -File scripts\run_dashboard.ps1` | Start Flask dashboard on http://localhost:5000 |

---

## Phases

### Phase 1 — Core Detection
- Reads system logs (auth/syslog) and network logs (packet/flow)
- Cleans and normalises data (`preprocessor.py`)
- Extracts ML features (`feature_engineer.py`)
- Detects anomalies using **Isolation Forest** + **One-Class SVM** ensemble
- Outputs scored alerts with severity 1–5 and actionable recommendations

### Phase 2 — Dashboard
- Flask REST API (`/api/alerts`, `/api/stats`, `/api/charts`)
- Live-polling web dashboard (refreshes every 8 seconds)
- 5 Plotly charts: timeline, severity donut, attack types, top IPs, risk histogram
- "Re-run Pipeline" button to trigger detection from the browser

### Phase 3 — Threat Intelligence
- **K-Means + DBSCAN** clustering to find attack campaigns
- **Random Forest** classifier to label attack types
- **CVSS-style risk scoring** (0–10) per alert
- **Best-First Search triage queue** (Unit 2 concept)
- **CSP backtracking response assignment** (Unit 3 concept)
- Structured threat report with IOCs, campaign analysis, and prioritised recommendations

---

## What Makes This Unique

Most student security projects stop at anomaly detection. This system goes further by turning alerts into analyst-ready intelligence.

- **PowerShell-backed real ingestion**: Windows events and active TCP sessions are pulled from shell commands and normalized into ML-ready CSVs.
- **Detection-to-intelligence chain**: one run moves from anomaly detection to campaign clustering to risk-scored reporting.
- **Explainable output**: every alert includes reason, severity, confidence, and mitigation advice.
- **Operational view**: dashboard + API + JSON report make it usable for demos, viva, and portfolio review.
- **Analyst-first design**: focuses on actionable prioritisation, not just model accuracy.

### Signature Flow

Raw logs → Feature engineering → Ensemble anomaly detection → Alert scoring → Attack clustering → Risk classification → Threat report.

---

## Common Workflows

### Workflow 1: Full Analysis (Recommended for Demo/Viva)
```powershell
# Clean up old data
Remove-Item -Path data\alerts_store.csv -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\system_logs.csv -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\network_logs.csv -Force -ErrorAction SilentlyContinue

# Collect 3 hours of logs and run full analysis
python.exe main.py --real-minutes 180

# Check alert count
python.exe -c "import pandas as pd; df=pd.read_csv('data/alerts_store.csv'); print(f'Generated {len(df)} alerts'); print(f'Max severity: {df[\"severity\"].max()}')"

# Start dashboard
powershell -ExecutionPolicy Bypass -File scripts\run_dashboard.ps1
```

### Workflow 2: Quick Test (5-10 minutes)
```powershell
python.exe main.py --real-minutes 10
python.exe -c "import pandas as pd; df=pd.read_csv('data/alerts_store.csv'); print(f'{len(df)} alerts found')"
```

### Workflow 3: Cluster Existing Alerts (Intelligence Only)
```powershell
# Re-cluster and re-report without re-collecting logs
python.exe main.py --phase 3
```

Open `http://localhost:5000` to see live dashboard.

---

## How Real Logs Are Collected

This is shell-backed collection with Python orchestration.

- `scripts/collect_real_logs.ps1` collects Windows events and TCP samples directly in PowerShell.
- System logs source: `Get-WinEvent`
- Network logs source: `Get-NetTCPConnection`
- Results are normalized into:
	- `data/system_logs.csv`
	- `data/network_logs.csv`

There is no synthetic demo workflow in this repository.

---

## File Purpose And Unit Mapping (Viva Ready)

| File | Purpose | Unit Concept Used |
|---|---|---|
| `config.py` | Central thresholds, paths, runtime settings | Unit 1: problem formulation and environment parameters |
| `scripts/collect_real_logs.ps1` | Pulls real Windows/system-network data via PowerShell and writes CSVs | Unit 1: data acquisition + agent percepts |
| `main.py` | End-to-end orchestration of detect/intel pipeline | Unit 1: intelligent-agent control loop |
| `core/preprocessor.py` | Cleans logs, parses timestamps, encodes fields | Unit 1: state representation |
| `core/feature_engineer.py` | Builds model input features + heuristic flags | Unit 1: knowledge representation and heuristics |
| `core/anomaly_detector.py` | Isolation Forest + One-Class SVM ensemble | Unit 1/2: AI model selection for search in state space |
| `core/alert_engine.py` | Converts anomalies into explainable alerts and actions | Unit 1: perception-to-action mapping |
| `intelligence/clusterer.py` | K-Means/DBSCAN campaign grouping | Unit 3: intelligent behavior from unsupervised structure |
| `intelligence/classifier.py` | Labels attack families from learned patterns | Unit 3: rational decision support |
| `intelligence/threat_scorer.py` | Risk scoring and prioritization logic | Unit 1: performance measure and utility |
| `intelligence/search_planner.py` | Best-First Search investigation queue | Unit 2: search strategy (Best-First) |
| `intelligence/csp_response_planner.py` | Backtracking CSP for analyst-task assignment | Unit 3: constraint satisfaction problems |
| `intelligence/report_generator.py` | Generates actionable intelligence report JSON | Unit 3: rational agent output and explanation |
| `dashboard/app.py` | API + page routes for operational view | Unit 1: agent-environment interface |
| `dashboard/visualiser.py` | Generates dashboard chart payloads | Unit 1: monitoring/performance visualization |
| `dashboard/static/dashboard.js` | Polling/rendering of live data in UI | Unit 1: feedback loop |
| `dashboard/templates/index.html` | Dashboard layout for live SOC-style view | Unit 1: action/observation interface |
| `scripts/run_dashboard.ps1` | Starts Flask dashboard server | Unit 1: deployment of agent view |

### Unit Coverage Summary

- **Unit 1 (Intro to AI):** intelligent agent pipeline, heuristic detection, performance/risk measures, perception-action flow.
- **Unit 2 (Data Structures/Search):** explicit **Best-First Search** triage planner in `intelligence/search_planner.py`.
- **Unit 3 (Advanced Search/Intelligent Agent):** explicit **CSP backtracking** planner in `intelligence/csp_response_planner.py` plus campaign clustering/intel reporting.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/report` | Threat report UI |
| GET | `/api/alerts` | Latest alerts (JSON) |
| GET | `/api/stats` | Summary counts (JSON) |
| GET | `/api/charts` | All Plotly chart data |
| GET | `/api/report` | Full threat report (JSON) |
| POST | `/api/run_pipeline` | Trigger re-detection |

---

## Configuration

Edit `config.py` to tune:
- `CONTAMINATION` — expected anomaly fraction (default 8 %)
- `ANOMALY_SCORE_THRESHOLD` — alert trigger threshold (default 0.55)
- `BRUTE_FORCE_FAILED_LOGINS` — failed login heuristic (default 5)
- `DOS_CONNECTION_OBSERVATIONS` — DoS heuristic (default 25 repeated flow observations)
- `EXFIL_CONNECTION_OBSERVATIONS` — exfil heuristic (default 20 sustained outbound observations)
- `KMEANS_N_CLUSTERS` — number of attack clusters (default 5)
