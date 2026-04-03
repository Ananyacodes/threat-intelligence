# AI Threat Intelligence System

A full-stack AI-powered threat detection and intelligence platform.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic logs + run full pipeline
python main.py --gen

# 3. Launch the dashboard
python run_dashboard.py
# Open http://localhost:5000
```

---

## Project Structure

```
threat_intel_system/
├── core/
│   ├── generate_logs.py       # Synthetic log generator
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
├── main.py                    # CLI pipeline runner
└── run_dashboard.py           # Flask server launcher
```

---

## CLI Usage

| Command | What it does |
|---|---|
| `python main.py --gen` | Regenerate logs + full pipeline |
| `python main.py` | Full pipeline (Phase 1 + 3) |
| `python main.py --phase 1` | Detection + alerts only |
| `python main.py --phase 3` | Clustering + report only |
| `python run_dashboard.py` | Start Flask dashboard |

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
- 6 Plotly charts: timeline, severity donut, attack types, top IPs, heatmap, risk histogram
- "Re-run Pipeline" button to trigger detection from the browser

### Phase 3 — Threat Intelligence
- **K-Means + DBSCAN** clustering to find attack campaigns
- **Random Forest** classifier to label attack types
- **CVSS-style risk scoring** (0–10) per alert
- Structured threat report with IOCs, campaign analysis, and prioritised recommendations

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
- `DOS_PACKETS_PER_SECOND` — DoS heuristic (default 500 pps)
- `KMEANS_N_CLUSTERS` — number of attack clusters (default 5)
