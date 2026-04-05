"""
dashboard/app.py
Phase 2 — Flask web application.

Routes
  GET  /                  → dashboard HTML
  GET  /report            → threat intelligence report page
  GET  /api/alerts        → JSON list of latest alerts
  GET  /api/stats         → JSON summary stats
  GET  /api/charts        → JSON all Plotly chart data
  GET  /api/report        → JSON full threat report
  POST /api/run_pipeline  → re-run full detection pipeline
"""

import sys
import os

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, jsonify, render_template, request
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG, ALERTS_PATH

app = Flask(__name__)

# ── Lazy imports (avoid circular deps) ────────────────────────────────────────
def _get_alerts():
    from core.alert_engine import load_alerts
    import pandas as pd
    alerts = load_alerts()
    if alerts.empty:
        return pd.DataFrame()
    # Attach risk scores if available (Phase 3)
    try:
        from intelligence.threat_scorer import score_alerts
        alerts = score_alerts(alerts)
    except Exception:
        pass
    return alerts


# ══════════════════════════════════════════════════════════════════════════════
# HTML pages
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/report")
def report_page():
    return render_template("report.html")


# ══════════════════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/alerts")
def api_alerts():
    alerts = _get_alerts()
    if alerts.empty:
        return jsonify({"alerts": [], "total": 0})
    limit = int(request.args.get("limit", 100))
    cols  = [c for c in ["detected_at","source_ip","destination_ip","destination_port","attack_type","severity",
                          "confidence","risk_score","risk_level","description",
                          "recommendation","log_type","data_origin",
                          "event_type","event_id","event_message","log_level",
                          "connection_observation_count","connection_observation_rate","duration_sec"]
             if c in alerts.columns]
    records = (alerts.sort_values("severity", ascending=False)
                     .head(limit)[cols]
                     .fillna("")
                     .to_dict(orient="records"))
    return jsonify({"alerts": records, "total": len(alerts)})


@app.route("/api/stats")
def api_stats():
    alerts = _get_alerts()
    if alerts.empty:
        return jsonify({
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "attack_types": {}, "top_ips": {},
        })

    def _count(level):
        if "risk_level" in alerts.columns:
            return int((alerts["risk_level"] == level).sum())
        return 0

    top_sources = {}
    if not alerts.empty:
        src = alerts.copy()
        if "source_ip" not in src.columns:
            src["source_ip"] = ""
        if "service" not in src.columns:
            src["service"] = ""
        if "log_type" not in src.columns:
            src["log_type"] = ""

        src["source_label"] = src["source_ip"].fillna("").astype(str).str.strip()
        src["source_label"] = src["source_label"].replace({"nan": "", "None": "", "none": "", "unknown": "", "-": ""})
        empty_mask = src["source_label"] == ""
        src.loc[empty_mask, "source_label"] = src.loc[empty_mask, "service"].fillna("").astype(str).str.strip()
        empty_mask = src["source_label"] == ""
        src.loc[empty_mask, "source_label"] = src.loc[empty_mask, "log_type"].fillna("").astype(str).str.strip()
        src["source_label"] = src["source_label"].replace({"nan": "", "None": "", "none": "", "unknown": "", "-": ""})
        src = src[src["source_label"] != ""].copy()
        if not src.empty:
            top_sources = (src.groupby("source_label").size()
                             .sort_values(ascending=False)
                             .head(5).to_dict())

    return jsonify({
        "total":         len(alerts),
        "critical":      _count("Critical"),
        "high":          _count("High"),
        "medium":        _count("Medium"),
        "low":           _count("Low"),
        "attack_types":  alerts["attack_type"].value_counts().to_dict()
                         if "attack_type" in alerts.columns else {},
        "top_ips":       top_sources,
    })


@app.route("/api/charts")
def api_charts():
    from dashboard.visualiser import all_charts
    alerts = _get_alerts()
    return jsonify(all_charts(alerts))


@app.route("/api/report")
def api_report():
    import json
    from config import DATA_DIR
    report_path = os.path.join(DATA_DIR, "threat_report.json")
    if not os.path.exists(report_path):
        return jsonify({"error": "Report not generated yet. Run main.py first."})
    with open(report_path) as f:
        return jsonify(json.load(f))


@app.route("/api/run_pipeline", methods=["POST"])
def api_run_pipeline():
    """Re-run the full detection pipeline on demand."""
    api_token = os.getenv("THREATINTEL_API_TOKEN", "").strip()
    if api_token:
        provided = request.headers.get("X-API-Token", "").strip()
        if provided != api_token:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "..", "main.py")],
            capture_output=True, text=True, timeout=120
        )
        return jsonify({
            "status": "ok" if result.returncode == 0 else "error",
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-500:],
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
