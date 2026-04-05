"""
intelligence/csp_response_planner.py
Unit 3 add-on: Constraint Satisfaction Problem (CSP) for response assignment.

Assigns top alerts to analysts subject to:
  - per-analyst capacity constraints
  - attack-type skill constraints
"""

from __future__ import annotations

from typing import Any
import pandas as pd


DEFAULT_ANALYSTS: dict[str, set[str]] = {
    "analyst_alpha": {"brute_force", "privilege_escalation", "unknown_anomaly"},
    "analyst_bravo": {"dos", "port_scan", "unknown_anomaly"},
    "analyst_charlie": {"data_exfiltration", "privilege_escalation", "unknown_anomaly"},
}


def _top_alert_variables(alerts: pd.DataFrame, limit: int) -> list[dict[str, Any]]:
    df = alerts.copy()
    if "risk_score" in df.columns:
        df = df.sort_values("risk_score", ascending=False)
    elif "severity" in df.columns:
        df = df.sort_values("severity", ascending=False)

    vars_out: list[dict[str, Any]] = []
    for _, row in df.head(limit).iterrows():
        vars_out.append(
            {
                "source_ip": str(row.get("source_ip", "")),
                "attack_type": str(row.get("attack_type", "unknown_anomaly")),
                "severity": int(float(row.get("severity", 0) or 0)),
                "risk_score": round(float(row.get("risk_score", 0) or 0), 2),
            }
        )
    return vars_out


def _backtrack(
    variables: list[dict[str, Any]],
    domains: list[list[str]],
    capacity: dict[str, int],
    idx: int,
    assignment: list[str],
) -> bool:
    if idx == len(variables):
        return True

    for analyst in domains[idx]:
        if capacity[analyst] <= 0:
            continue

        assignment.append(analyst)
        capacity[analyst] -= 1

        if _backtrack(variables, domains, capacity, idx + 1, assignment):
            return True

        assignment.pop()
        capacity[analyst] += 1

    return False


def plan_response_csp(
    alerts: pd.DataFrame,
    max_assignments: int = 8,
    max_per_analyst: int = 3,
) -> dict[str, Any]:
    """Solve a small CSP that allocates high-priority alerts to analysts."""
    if alerts.empty:
        return {
            "algorithm": "CSP Backtracking",
            "assignments": [],
            "unassigned": 0,
            "notes": "No alerts available.",
        }

    variables = _top_alert_variables(alerts, limit=max_assignments)
    if not variables:
        return {
            "algorithm": "CSP Backtracking",
            "assignments": [],
            "unassigned": 0,
            "notes": "No candidate alerts.",
        }

    domains: list[list[str]] = []
    for var in variables:
        atk = var["attack_type"]
        eligible = [name for name, skills in DEFAULT_ANALYSTS.items() if atk in skills]
        if not eligible:
            eligible = [name for name in DEFAULT_ANALYSTS.keys() if "unknown_anomaly" in DEFAULT_ANALYSTS[name]]
        domains.append(eligible)

    capacity = {name: max_per_analyst for name in DEFAULT_ANALYSTS.keys()}
    assignment: list[str] = []

    solved = _backtrack(variables, domains, capacity, 0, assignment)

    output = []
    if solved:
        for var, analyst in zip(variables, assignment):
            row = dict(var)
            row["assigned_to"] = analyst
            output.append(row)

    return {
        "algorithm": "CSP Backtracking",
        "assignments": output,
        "unassigned": 0 if solved else len(variables),
        "notes": "Capacity + skill constraints applied.",
    }
