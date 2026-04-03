"""
intelligence/report_generator.py
Phase 3 — compiles all analysis into a structured Threat Intelligence Report.

Output: plain-text summary + JSON report saved to data/threat_report.json
"""

import json
import os
import sys
import pandas as pd
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import DATA_DIR

REPORT_PATH = os.path.join(DATA_DIR, "threat_report.json")


def generate_report(alerts: pd.DataFrame,
                    cluster_summary: pd.DataFrame = None) -> dict:
    """
    Parameters
    ----------
    alerts          : scored + classified alerts DataFrame
    cluster_summary : output of AttackClusterer.cluster_summary()

    Returns
    -------
    dict — the full threat intelligence report
    """
    if alerts.empty:
        return {"error": "No alerts available for report generation."}

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Executive summary ──────────────────────────────────────────────────────
    total_alerts   = len(alerts)
    critical_count = len(alerts[alerts.get("risk_level", pd.Series()) == "Critical"]) \
                     if "risk_level" in alerts.columns else 0
    high_count     = len(alerts[alerts.get("risk_level", pd.Series()) == "High"]) \
                     if "risk_level" in alerts.columns else 0
    attack_counts  = alerts["attack_type"].value_counts().to_dict()
    top_attackers  = (alerts.groupby("source_ip")
                            .size()
                            .sort_values(ascending=False)
                            .head(10)
                            .to_dict())

    # ── Indicators of Compromise (IOCs) ────────────────────────────────────────
    iocs = []
    for ip, count in top_attackers.items():
        attacks = alerts[alerts["source_ip"] == ip]["attack_type"].unique().tolist()
        iocs.append({
            "type":        "ip_address",
            "value":       ip,
            "event_count": int(count),
            "attack_types": attacks,
        })

    # ── Attack timeline ────────────────────────────────────────────────────────
    if "timestamp" in alerts.columns:
        alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")
        timeline = (alerts.dropna(subset=["timestamp"])
                          .set_index("timestamp")
                          .resample("1h")["attack_type"]
                          .count()
                          .rename("alert_count")
                          .reset_index()
                          .assign(timestamp=lambda df: df["timestamp"].dt.strftime("%Y-%m-%d %H:%M"))
                          .to_dict(orient="records"))
    else:
        timeline = []

    # ── Cluster insights ───────────────────────────────────────────────────────
    cluster_insights = []
    if cluster_summary is not None and not cluster_summary.empty:
        for _, row in cluster_summary.iterrows():
            cluster_insights.append({
                "cluster_id":       int(row["cluster_id"]),
                "dominant_attack":  row["dominant_attack"],
                "event_count":      int(row["count"]),
                "unique_ips":       int(row["unique_ips"]),
                "avg_severity":     round(float(row["avg_severity"]), 2),
                "max_severity":     int(row["max_severity"]),
                "time_range":       f"{row['start_time']} → {row['end_time']}",
            })

    # ── Recommendations ────────────────────────────────────────────────────────
    recs = _build_recommendations(alerts)

    report = {
        "report_generated_at": now,
        "executive_summary": {
            "total_alerts":      total_alerts,
            "critical_alerts":   critical_count,
            "high_alerts":       high_count,
            "attack_type_breakdown": attack_counts,
            "unique_attacker_ips": alerts["source_ip"].nunique(),
            "observation_window": {
                "start": str(alerts["timestamp"].min()) if "timestamp" in alerts.columns else "N/A",
                "end":   str(alerts["timestamp"].max()) if "timestamp" in alerts.columns else "N/A",
            },
        },
        "indicators_of_compromise": iocs,
        "attack_timeline_hourly":   timeline,
        "attack_campaigns":         cluster_insights,
        "recommendations":          recs,
        "top_alerts": (
            alerts.sort_values("risk_score", ascending=False)
                  .head(20)
                  [["detected_at", "source_ip", "attack_type",
                    "severity", "risk_score", "risk_level",
                    "description", "recommendation"]]
                  .fillna("")
                  .to_dict(orient="records")
        ) if "risk_score" in alerts.columns else [],
    }

    # Save to disk
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[report] Threat intelligence report saved → {REPORT_PATH}")

    return report


def _build_recommendations(alerts: pd.DataFrame) -> list:
    recs = []
    attack_types = alerts["attack_type"].unique() if "attack_type" in alerts.columns else []

    if "brute_force" in attack_types:
        recs.append({
            "priority": "HIGH",
            "action":   "Enforce MFA across all remote access services (SSH, VPN, RDP).",
            "rationale": "Brute force attacks detected against login services.",
        })
        recs.append({
            "priority": "HIGH",
            "action":   "Implement IP-based account lockout after 5 consecutive failures.",
            "rationale": "Limit attacker retry rate.",
        })

    if "port_scan" in attack_types:
        recs.append({
            "priority": "MEDIUM",
            "action":   "Review firewall rules — block non-essential ports at perimeter.",
            "rationale": "Port scanning activity suggests attacker reconnaissance.",
        })

    if "dos" in attack_types:
        recs.append({
            "priority": "CRITICAL",
            "action":   "Enable rate limiting and DDoS protection on public-facing services.",
            "rationale": "DoS attacks detected targeting internal hosts.",
        })

    if "data_exfiltration" in attack_types:
        recs.append({
            "priority": "CRITICAL",
            "action":   "Isolate suspected hosts immediately and conduct forensic review.",
            "rationale": "Large outbound data transfers detected to external IPs.",
        })
        recs.append({
            "priority": "CRITICAL",
            "action":   "Deploy DLP (Data Loss Prevention) policies on egress traffic.",
            "rationale": "Prevent future exfiltration attempts.",
        })

    if "privilege_escalation" in attack_types:
        recs.append({
            "priority": "HIGH",
            "action":   "Audit and tighten sudo/PAM configuration on all servers.",
            "rationale": "Privilege escalation attempts detected.",
        })

    recs.append({
        "priority": "MEDIUM",
        "action":   "Deploy centralised SIEM for real-time log correlation.",
        "rationale": "Improve detection speed and reduce mean time to respond (MTTR).",
    })

    return recs


def print_report_summary(report: dict):
    es = report.get("executive_summary", {})
    print("\n" + "="*65)
    print("  THREAT INTELLIGENCE REPORT")
    print("="*65)
    print(f"  Generated at  : {report.get('report_generated_at')}")
    print(f"  Total alerts  : {es.get('total_alerts', 0)}")
    print(f"  Critical      : {es.get('critical_alerts', 0)}")
    print(f"  High          : {es.get('high_alerts', 0)}")
    print(f"  Unique IPs    : {es.get('unique_attacker_ips', 0)}")
    print("\n  Attack breakdown:")
    for atk, cnt in es.get("attack_type_breakdown", {}).items():
        print(f"    {atk:<28} {cnt}")
    print(f"\n  Top IOCs ({len(report.get('indicators_of_compromise', []))}):")
    for ioc in report.get("indicators_of_compromise", [])[:5]:
        print(f"    {ioc['value']:<20} → {', '.join(ioc['attack_types'])}")
    print(f"\n  {len(report.get('recommendations', []))} recommendations generated.")
    print("="*65 + "\n")


if __name__ == "__main__":
    from core.alert_engine        import load_alerts
    from intelligence.threat_scorer import score_alerts
    from intelligence.clusterer    import AttackClusterer

    alerts = load_alerts()
    if alerts.empty:
        print("[report] No alerts. Run main.py first.")
    else:
        alerts   = score_alerts(alerts)
        clusterer = AttackClusterer()
        alerts   = clusterer.fit_predict(alerts)
        summary  = clusterer.cluster_summary(alerts)
        report   = generate_report(alerts, summary)
        print_report_summary(report)
