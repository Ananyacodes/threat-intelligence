"""
dashboard/visualiser.py
Phase 2 — generates all Plotly charts returned as JSON for the dashboard.

Charts:
  1. alerts_timeline     — alert count per hour
  2. severity_donut      — distribution of severity levels
  3. attack_type_bar     — top attack types by frequency
  4. top_ips_bar         — top attacker IPs
  5. heatmap             — alerts by hour-of-day × day-of-week
  6. risk_score_hist     — distribution of risk scores (Phase 3)
"""

import json
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder


COLORS = {
    "Critical": "#E24B4A",
    "High":     "#EF9F27",
    "Medium":   "#378ADD",
    "Low":      "#1D9E75",
    "unknown":  "#888780",
}

ATTACK_COLORS = [
    "#534AB7", "#D85A30", "#185FA5",
    "#0F6E56", "#993556", "#3B6D11",
]


def _fig_to_json(fig) -> str:
    return json.dumps(fig, cls=PlotlyJSONEncoder)


# ── 1. Alerts timeline ─────────────────────────────────────────────────────────
def alerts_timeline(alerts: pd.DataFrame) -> str:
    if alerts.empty or "detected_at" not in alerts.columns:
        return _empty_chart("No alert timeline data")

    df = alerts.copy()
    df["detected_at"] = pd.to_datetime(df["detected_at"], errors="coerce")
    df = df.dropna(subset=["detected_at"])
    df = df.set_index("detected_at").resample("1h").size().reset_index()
    df.columns = ["time", "count"]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["time"], y=df["count"],
        mode="lines+markers",
        line=dict(color="#534AB7", width=2),
        marker=dict(size=5),
        fill="tozeroy",
        fillcolor="rgba(83,74,183,0.12)",
        name="Alerts/hour",
    ))
    fig.update_layout(**_base_layout("Alerts Over Time"))
    fig.update_xaxes(title="Time")
    fig.update_yaxes(title="Alert Count")
    return _fig_to_json(fig)


# ── 2. Severity donut ──────────────────────────────────────────────────────────
def severity_donut(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return _empty_chart("No severity data")

    col = "risk_level" if "risk_level" in alerts.columns else "severity"
    counts = alerts[col].value_counts().reset_index()
    counts.columns = ["level", "count"]

    colors = [COLORS.get(str(l), COLORS["unknown"]) for l in counts["level"]]

    fig = go.Figure(go.Pie(
        labels=counts["level"],
        values=counts["count"],
        hole=0.55,
        marker=dict(colors=colors),
        textinfo="label+percent",
        hovertemplate="%{label}: %{value} alerts<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Alert Severity Distribution"))
    return _fig_to_json(fig)


# ── 3. Attack type bar ─────────────────────────────────────────────────────────
def attack_type_bar(alerts: pd.DataFrame) -> str:
    if alerts.empty or "attack_type" not in alerts.columns:
        return _empty_chart("No attack type data")

    counts = (alerts["attack_type"]
              .value_counts()
              .reset_index()
              .rename(columns={"attack_type": "type", "count": "count"}))

    fig = go.Figure(go.Bar(
        x=counts["count"],
        y=counts["type"],
        orientation="h",
        marker=dict(
            color=ATTACK_COLORS[:len(counts)],
            line=dict(width=0),
        ),
        hovertemplate="%{y}: %{x} alerts<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Attacks by Type"))
    fig.update_xaxes(title="Count")
    fig.update_yaxes(autorange="reversed")
    return _fig_to_json(fig)


# ── 4. Top attacker IPs ────────────────────────────────────────────────────────
def top_ips_bar(alerts: pd.DataFrame) -> str:
    if alerts.empty or "source_ip" not in alerts.columns:
        return _empty_chart("No IP data")

    top = (alerts.groupby("source_ip")
                 .size()
                 .sort_values(ascending=False)
                 .head(10)
                 .reset_index(name="count"))

    fig = go.Figure(go.Bar(
        x=top["count"],
        y=top["source_ip"],
        orientation="h",
        marker=dict(color="#D85A30"),
        hovertemplate="%{y}: %{x} events<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Top Attacker IPs"))
    fig.update_xaxes(title="Alert Count")
    fig.update_yaxes(autorange="reversed")
    return _fig_to_json(fig)


# ── 5. Hour × day-of-week heatmap ─────────────────────────────────────────────
def attack_heatmap(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return _empty_chart("No heatmap data")

    df = alerts.copy()
    ts_col = "detected_at" if "detected_at" in df.columns else "timestamp"
    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce")
    df = df.dropna(subset=[ts_col])
    df["hour"] = df[ts_col].dt.hour
    df["dow"]  = df[ts_col].dt.day_name()

    days  = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
    pivot = (df.groupby(["dow","hour"])
               .size()
               .unstack(fill_value=0)
               .reindex(days, fill_value=0))

    fig = go.Figure(go.Heatmap(
        z=pivot.values,
        x=list(pivot.columns),
        y=list(pivot.index),
        colorscale="Reds",
        hovertemplate="Day: %{y}<br>Hour: %{x}:00<br>Alerts: %{z}<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Alert Heatmap (Day × Hour)"))
    fig.update_xaxes(title="Hour of day (0–23)")
    return _fig_to_json(fig)


# ── 6. Risk score histogram ────────────────────────────────────────────────────
def risk_score_histogram(alerts: pd.DataFrame) -> str:
    if alerts.empty or "risk_score" not in alerts.columns:
        return _empty_chart("No risk score data — run Phase 3")

    fig = go.Figure(go.Histogram(
        x=alerts["risk_score"],
        nbinsx=20,
        marker=dict(color="#534AB7"),
        hovertemplate="Score: %{x}<br>Count: %{y}<extra></extra>",
    ))
    fig.add_vline(x=8.0, line_dash="dash", line_color=COLORS["Critical"],
                  annotation_text="Critical threshold")
    fig.add_vline(x=6.0, line_dash="dash", line_color=COLORS["High"],
                  annotation_text="High threshold")
    fig.update_layout(**_base_layout("Risk Score Distribution"))
    fig.update_xaxes(title="Risk Score (0–10)")
    fig.update_yaxes(title="Count")
    return _fig_to_json(fig)


# ── Helpers ────────────────────────────────────────────────────────────────────
def _base_layout(title: str) -> dict:
    return dict(
        title=dict(text=title, font=dict(size=14)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="sans-serif", size=12),
        margin=dict(l=10, r=10, t=40, b=10),
        legend=dict(orientation="h", y=-0.15),
        height=300,
    )


def _empty_chart(msg: str) -> str:
    fig = go.Figure()
    fig.add_annotation(text=msg, xref="paper", yref="paper",
                       x=0.5, y=0.5, showarrow=False,
                       font=dict(size=14, color="#888"))
    fig.update_layout(**_base_layout(""))
    return _fig_to_json(fig)


def all_charts(alerts: pd.DataFrame) -> dict:
    """Return all chart JSON in one dict — called by the Flask API."""
    return {
        "timeline":    alerts_timeline(alerts),
        "severity":    severity_donut(alerts),
        "attack_type": attack_type_bar(alerts),
        "top_ips":     top_ips_bar(alerts),
        "heatmap":     attack_heatmap(alerts),
        "risk_hist":   risk_score_histogram(alerts),
    }
