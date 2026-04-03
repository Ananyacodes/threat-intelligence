"""
main.py
CLI entry point — runs the full AI Threat Intelligence pipeline.

Usage:
  python main.py              # full pipeline (phases 1, 2 prep, 3)
  python main.py --gen        # regenerate synthetic logs first
  python main.py --phase 1    # Phase 1 only (detection + alerts)
  python main.py --phase 3    # Phase 3 only (clustering + report)

The script automatically handles both system and network logs.
"""

import argparse
import sys
import os
import time

# ── Ensure root on path ────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          AI THREAT INTELLIGENCE SYSTEM  v1.0                 ║
║  Phase 1: Detection  │  Phase 2: Dashboard  │  Phase 3: Intel║
╚══════════════════════════════════════════════════════════════╝
""")


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Core detection pipeline
# ══════════════════════════════════════════════════════════════════════════════
def run_phase1():
    print("\n── PHASE 1: Data ingestion, feature engineering, anomaly detection ──")
    t0 = time.time()

    from core.preprocessor     import preprocess_system_logs, preprocess_network_logs
    from core.feature_engineer import system_features, network_features, \
                                       SYSTEM_FEATURE_COLS, NETWORK_FEATURE_COLS
    from core.anomaly_detector import train_system_detector, train_network_detector
    from core.alert_engine     import build_alerts, save_alerts, print_alert_summary

    # ── System logs ────────────────────────────────────────────────────────────
    print("\n[1/6] Preprocessing system logs …")
    sys_df = preprocess_system_logs()

    print("[2/6] Engineering system features …")
    sys_feat = system_features(sys_df)
    X_sys    = sys_feat[SYSTEM_FEATURE_COLS].fillna(0).values

    print("[3/6] Training system anomaly detector …")
    sys_det  = train_system_detector(X_sys)
    sys_pred = sys_det.predict(X_sys)

    sys_alerts = build_alerts(sys_feat, sys_pred, "system")
    print_alert_summary(sys_alerts, "SYSTEM")
    save_alerts(sys_alerts)

    # ── Network logs ───────────────────────────────────────────────────────────
    print("[4/6] Preprocessing network logs …")
    net_df = preprocess_network_logs()

    print("[5/6] Engineering network features …")
    net_feat = network_features(net_df)
    X_net    = net_feat[NETWORK_FEATURE_COLS].fillna(0).values

    print("[6/6] Training network anomaly detector …")
    net_det  = train_network_detector(X_net)
    net_pred = net_det.predict(X_net)

    net_alerts = build_alerts(net_feat, net_pred, "network")
    print_alert_summary(net_alerts, "NETWORK")
    save_alerts(net_alerts)

    print(f"\n[Phase 1 complete in {time.time()-t0:.1f}s]")
    return sys_alerts, net_alerts


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Clustering, classification, scoring, report
# ══════════════════════════════════════════════════════════════════════════════
def run_phase3():
    print("\n── PHASE 3: Clustering, classification, scoring, report ──")
    t0 = time.time()

    from core.alert_engine               import load_alerts
    from intelligence.clusterer          import AttackClusterer
    from intelligence.classifier         import AttackClassifier
    from intelligence.threat_scorer      import score_alerts
    from intelligence.report_generator   import generate_report, print_report_summary

    alerts = load_alerts()
    if alerts.empty:
        print("[!] No alerts found. Run Phase 1 first.")
        return

    print(f"[1/4] Loaded {len(alerts)} alerts from store.")

    print("[2/4] Clustering attack patterns …")
    clusterer = AttackClusterer()
    alerts    = clusterer.fit_predict(alerts)
    summary   = clusterer.cluster_summary(alerts)
    clusterer.save()
    print(f"      Found {alerts['cluster_kmeans'].nunique()} K-Means clusters.")

    print("[3/4] Scoring risk (CVSS-style) …")
    alerts = score_alerts(alerts)
    print(f"      Risk level breakdown:")
    if "risk_level" in alerts.columns:
        for lvl, cnt in alerts["risk_level"].value_counts().items():
            print(f"        {lvl:<10} {cnt}")

    print("[4/4] Generating threat intelligence report …")
    try:
        clf    = AttackClassifier()
        clf.fit(alerts)
        alerts = clf.predict(alerts)
        clf.save()
    except Exception as e:
        print(f"      [classifier skipped: {e}]")

    report = generate_report(alerts, summary)
    print_report_summary(report)

    print(f"\n[Phase 3 complete in {time.time()-t0:.1f}s]")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(description="AI Threat Intelligence System")
    parser.add_argument("--gen",   action="store_true", help="Regenerate synthetic logs")
    parser.add_argument("--phase", type=int, choices=[1, 3], help="Run specific phase only")
    args = parser.parse_args()

    # Generate logs if requested or if files don't exist
    from config import SYSTEM_LOG_PATH, NETWORK_LOG_PATH, ALERTS_PATH
    if args.gen and os.path.exists(ALERTS_PATH):
        os.remove(ALERTS_PATH)
        print(f"[*] Reset alert store → {ALERTS_PATH}")

    if args.gen or not os.path.exists(SYSTEM_LOG_PATH):
        print("[*] Generating synthetic logs …")
        from core.generate_logs import generate_system_logs, generate_network_logs
        generate_system_logs()
        generate_network_logs()

    if args.phase == 1:
        run_phase1()
    elif args.phase == 3:
        run_phase3()
    else:
        # Full pipeline
        run_phase1()
        run_phase3()

    print("\n[✓] Pipeline complete.")
    print("    → Alert store : data/alerts_store.csv")
    print("    → Report      : data/threat_report.json")
    print("    → Dashboard   : python run_dashboard.py  then open http://localhost:5000")


if __name__ == "__main__":
    main()
