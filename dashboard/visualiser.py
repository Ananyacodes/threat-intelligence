"""
dashboard/visualiser.py
Phase 2 — generates all Plotly charts returned as JSON for the dashboard.

Charts:
  1. alerts_timeline     — alert count per hour
  2. severity_donut      — distribution of severity levels
  3. attack_type_bar     — top attack types by frequency
  4. top_ips_bar         — top attacker IPs
    5. risk_score_hist     — distribution of risk scores (Phase 3)
"""

import json
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.utils import PlotlyJSONEncoder
import plotly.io as pio


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
    return pio.to_json(fig, validate=False, pretty=False, remove_uids=True, engine="json")


def _dashboard_time_col(df: pd.DataFrame) -> str | None:
    """Prefer event timestamp; fall back to detection timestamp."""
    if "timestamp" in df.columns:
        return "timestamp"
    if "detected_at" in df.columns:
        return "detected_at"
    return None


# ── 1. Alerts timeline ─────────────────────────────────────────────────────────
def alerts_timeline(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return _empty_chart("No alert timeline data")

    df = alerts.copy()
    ts_col = _dashboard_time_col(df)
    if ts_col is None:
        return _empty_chart("No alert timeline data")

    df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce", utc=True)
    df = df.dropna(subset=[ts_col])
    df = df.set_index(ts_col).resample("1h").size().reset_index()
    df.columns = ["time", "count"]
    df["count"] = pd.to_numeric(df["count"], errors="coerce").fillna(0)

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
    fig.update_xaxes(title="Time", type="date", tickformat="%b %d %H:%M")
    fig.update_yaxes(title="Alert Count")

    # When only one bucket exists, pad ranges so the chart does not collapse.
    if len(df) == 1:
        center = pd.to_datetime(df.loc[0, "time"], utc=True)
        fig.update_xaxes(range=[center - pd.Timedelta(minutes=30), center + pd.Timedelta(minutes=30)])
        ymax = max(1.0, float(df.loc[0, "count"]) + 1.0)
        fig.update_yaxes(range=[0, ymax])

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
    counts["count"] = pd.to_numeric(counts["count"], errors="coerce").fillna(0)

    fig = go.Figure(go.Bar(
        x=counts["count"].tolist(),
        y=counts["type"].tolist(),
        orientation="h",
        marker=dict(
            color=ATTACK_COLORS[:len(counts)],
            line=dict(width=0),
        ),
        hovertemplate="%{y}: %{x} alerts<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Attacks by Type"))
    fig.update_xaxes(title="Count", type="linear")
    fig.update_yaxes(autorange="reversed")
    return _fig_to_json(fig)


# ── 4. Top attacker IPs ────────────────────────────────────────────────────────
def top_ips_bar(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return _empty_chart("No IP data")

    df = alerts.copy()
    if "source_ip" not in df.columns:
        df["source_ip"] = ""
    if "service" not in df.columns:
        df["service"] = ""
    if "log_type" not in df.columns:
        df["log_type"] = ""

    # Real fallback: if source_ip is unavailable for firewall/admin events,
    # group by event provider so the panel still communicates source context.
    df["source_label"] = df["source_ip"].fillna("").astype(str).str.strip()
    df["source_label"] = df["source_label"].replace({"nan": "", "None": "", "none": "", "unknown": "", "-": ""})
    empty_mask = df["source_label"] == ""
    df.loc[empty_mask, "source_label"] = df.loc[empty_mask, "service"].fillna("").astype(str).str.strip()
    empty_mask = df["source_label"] == ""
    df.loc[empty_mask, "source_label"] = df.loc[empty_mask, "log_type"].fillna("").astype(str).str.strip()
    df["source_label"] = df["source_label"].replace({"nan": "", "None": "", "none": "", "unknown": "", "-": ""})
    df = df[df["source_label"] != ""].copy()

    if df.empty:
        return _empty_chart("No IP data")

    top = (df.groupby("source_label")
                 .size()
                 .sort_values(ascending=False)
                 .head(10)
                 .reset_index(name="count"))
    top["count"] = pd.to_numeric(top["count"], errors="coerce").fillna(0)

    fig = go.Figure(go.Bar(
        x=top["count"].tolist(),
        y=top["source_label"].tolist(),
        orientation="h",
        marker=dict(color="#D85A30"),
        hovertemplate="%{y}: %{x} events<extra></extra>",
    ))
    fig.update_layout(**_base_layout("Top Attacker IPs"))
    fig.update_xaxes(title="Alert Count", type="linear")
    fig.update_yaxes(autorange="reversed")
    return _fig_to_json(fig)


# ── 5. Hour × day-of-week heatmap ─────────────────────────────────────────────
def attack_heatmap(alerts: pd.DataFrame) -> str:
    if alerts.empty:
        return _empty_chart("No heatmap data")

    try:
        df = alerts.copy()
        ts_col = _dashboard_time_col(df)
        if ts_col is None:
            return _empty_chart("No heatmap data")

        # Use UTC parsing to avoid mixed-timezone dtype issues.
        df[ts_col] = pd.to_datetime(df[ts_col], errors="coerce", utc=True)
        df = df.dropna(subset=[ts_col])
        if df.empty:
            return _empty_chart("No heatmap data")

        df["hour"] = df[ts_col].dt.hour
        df["dow"] = df[ts_col].dt.day_name()

        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        pivot = (
            df.groupby(["dow", "hour"]).size().unstack(fill_value=0)
            .reindex(index=days, fill_value=0)
            .reindex(columns=list(range(24)), fill_value=0)
        )

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
    except Exception:
        return _empty_chart("Heatmap unavailable")


# ── 6. Risk score histogram ────────────────────────────────────────────────────
def risk_score_histogram(alerts: pd.DataFrame) -> str:
    if alerts.empty or "risk_score" not in alerts.columns:
        return _empty_chart("No risk score data — run Phase 3")

    df = alerts.copy()
    df["risk_score"] = pd.to_numeric(df["risk_score"], errors="coerce")
    df = df.dropna(subset=["risk_score"])
    if df.empty:
        return _empty_chart("No risk score data — run Phase 3")

    fig = go.Figure(go.Histogram(
        x=df["risk_score"],
        nbinsx=20,
        marker=dict(color="#534AB7"),
        hovertemplate="Score: %{x}<br>Count: %{y}<extra></extra>",
    ))
    fig.add_vline(x=8.0, line_dash="dash", line_color=COLORS["Critical"],
                  annotation_text="Critical threshold")
    fig.add_vline(x=6.0, line_dash="dash", line_color=COLORS["High"],
                  annotation_text="High threshold")
    fig.update_layout(**_base_layout("Risk Score Distribution"))
    fig.update_xaxes(title="Risk Score (0–10)", type="linear", range=[0, 10])
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
        "risk_hist":   risk_score_histogram(alerts),
    }
