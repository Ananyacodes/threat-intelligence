"""
main.py
CLI entry point — runs the full AI Threat Intelligence pipeline.

Usage:
    python main.py              # full pipeline (collect real logs, phases 1 and 3)
  python main.py --phase 1    # Phase 1 only (detection + alerts)
  python main.py --phase 3    # Phase 3 only (clustering + report)

The script automatically handles both system and network logs.
"""

import argparse
import sys
import os
import time
import subprocess

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

    if sys_df.empty:
        print("[2/6] Engineering system features … skipped (no real system rows)")
        print("[3/6] Training system anomaly detector … skipped")
        sys_alerts = None
    else:
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
    if net_df.empty:
        print("[5/6] Engineering network features … skipped (no real network rows)")
        print("[6/6] Training network anomaly detector … skipped")
        net_alerts = None
    else:
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
    from intelligence.search_planner     import best_first_triage_plan
    from intelligence.csp_response_planner import plan_response_csp

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

    print("      Building Unit 2 best-first triage queue …")
    triage_plan = best_first_triage_plan(alerts, limit=10)
    print(f"      Triage queue length: {len(triage_plan.get('queue', []))}")

    print("      Solving Unit 3 CSP response assignment …")
    csp_plan = plan_response_csp(alerts, max_assignments=8, max_per_analyst=3)
    print(f"      CSP assigned: {len(csp_plan.get('assignments', []))}")

    report = generate_report(
        alerts,
        summary,
        triage_plan=triage_plan,
        csp_plan=csp_plan,
    )
    print_report_summary(report)

    print(f"\n[Phase 3 complete in {time.time()-t0:.1f}s]")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(description="AI Threat Intelligence System")
    parser.add_argument("--phase", type=int, choices=[1, 3], help="Run specific phase only")
    parser.add_argument("--real-minutes", type=int, default=180,
                        help="How far back to read Windows event logs.")
    parser.add_argument("--real-max-events", type=int, default=8000,
                        help="Maximum system events to pull during real collection.")
    args = parser.parse_args()

    from config import SYSTEM_LOG_PATH, NETWORK_LOG_PATH, ALERTS_PATH

    if args.phase != 3 and os.path.exists(ALERTS_PATH):
        os.remove(ALERTS_PATH)
        print(f"[*] Reset alert store → {ALERTS_PATH}")

    if args.phase != 3:
        for path in (SYSTEM_LOG_PATH, NETWORK_LOG_PATH):
            if os.path.exists(path):
                os.remove(path)
                print(f"[*] Reset log file → {path}")

    if args.phase != 3:
        print("[*] Collecting real logs …")
        script_path = os.path.join(ROOT, "scripts", "collect_real_logs.ps1")
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-Minutes", str(args.real_minutes),
            "-MaxEvents", str(args.real_max_events),
            "-SystemOutPath", SYSTEM_LOG_PATH,
            "-NetworkOutPath", NETWORK_LOG_PATH,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.stdout.strip():
            print(proc.stdout.strip())
        if proc.returncode != 0:
            err = proc.stderr.strip() or "Real log collection failed."
            raise RuntimeError(err)

    if args.phase != 3 and (not os.path.exists(SYSTEM_LOG_PATH) or not os.path.exists(NETWORK_LOG_PATH)):
        raise FileNotFoundError("Real log CSV files are missing. Run the collector again.")

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
    print("    → Dashboard   : powershell -File scripts/run_dashboard.ps1  then open http://localhost:5000")


if __name__ == "__main__":
    main()
