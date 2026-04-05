/**
 * dashboard/static/dashboard.js
 * Polls the Flask API every POLL_MS milliseconds.
 * Renders Plotly charts and fills the alert table.
 */

const POLL_MS = 8000;

const SEV_CLASS = {
  "Critical": "sev-critical",
  "High":     "sev-high",
  "Medium":   "sev-medium",
  "Low":      "sev-low",
  5: "sev-5", 4: "sev-4", 3: "sev-3", 2: "sev-2", 1: "sev-1",
};

// ── Stats ──────────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    document.getElementById("stat-total").textContent    = data.total    ?? "—";
    document.getElementById("stat-critical").textContent = data.critical ?? "—";
    document.getElementById("stat-high").textContent     = data.high     ?? "—";
    document.getElementById("stat-medium").textContent   = data.medium   ?? "—";
    document.getElementById("stat-low").textContent      = data.low      ?? "—";
  } catch (e) {
    console.warn("Stats fetch failed:", e);
  }
}

// ── Charts ─────────────────────────────────────────────────────────────────────
const CHART_LAYOUT_PATCH = {
  paper_bgcolor: "rgba(0,0,0,0)",
  plot_bgcolor:  "rgba(0,0,0,0)",
  font:          { color: "#e6edf3", size: 11 },
  margin:        { l: 8, r: 8, t: 36, b: 8 },
  xaxis:         { gridcolor: "#30363d", zerolinecolor: "#30363d" },
  yaxis:         { gridcolor: "#30363d", zerolinecolor: "#30363d" },
};

function decodePlotlyBinary(node) {
  if (Array.isArray(node)) {
    return node.map(decodePlotlyBinary);
  }

  if (!node || typeof node !== "object") {
    return node;
  }

  const keys = Object.keys(node);
  if (keys.includes("dtype") && keys.includes("bdata") && typeof node.bdata === "string") {
    try {
      const binary = atob(node.bdata);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
      }

      const view = new DataView(bytes.buffer);
      const out = [];
      const dtype = String(node.dtype).toLowerCase();

      let stride = 1;
      let reader = (offset) => view.getInt8(offset);

      if (dtype === "u1") {
        reader = (offset) => view.getUint8(offset);
      } else if (dtype === "i2") {
        stride = 2;
        reader = (offset) => view.getInt16(offset, true);
      } else if (dtype === "u2") {
        stride = 2;
        reader = (offset) => view.getUint16(offset, true);
      } else if (dtype === "i4") {
        stride = 4;
        reader = (offset) => view.getInt32(offset, true);
      } else if (dtype === "u4") {
        stride = 4;
        reader = (offset) => view.getUint32(offset, true);
      } else if (dtype === "f4") {
        stride = 4;
        reader = (offset) => view.getFloat32(offset, true);
      } else if (dtype === "f8") {
        stride = 8;
        reader = (offset) => view.getFloat64(offset, true);
      }

      for (let offset = 0; offset + stride <= bytes.length; offset += stride) {
        out.push(reader(offset));
      }
      return out;
    } catch {
      return node;
    }
  }

  const result = {};
  for (const [k, v] of Object.entries(node)) {
    result[k] = decodePlotlyBinary(v);
  }
  return result;
}

async function loadCharts() {
  try {
    const res    = await fetch("/api/charts");
    const charts = await res.json();

    const render = (id, json) => {
      if (!json) return;
      try {
        const fig = decodePlotlyBinary(JSON.parse(json));
        const baseLayout = fig.layout || {};
        fig.layout = {
          ...baseLayout,
          ...CHART_LAYOUT_PATCH,
          xaxis: { ...(baseLayout.xaxis || {}), ...(CHART_LAYOUT_PATCH.xaxis || {}) },
          yaxis: { ...(baseLayout.yaxis || {}), ...(CHART_LAYOUT_PATCH.yaxis || {}) },
        };

        // Preserve semantic axis types per chart to avoid epoch-style rendering.
        if (id === "chart-timeline") {
          fig.layout.xaxis = { ...(fig.layout.xaxis || {}), type: "date" };
        }
        if (id === "chart-attacks" || id === "chart-ips" || id === "chart-risk") {
          fig.layout.xaxis = { ...(fig.layout.xaxis || {}), type: "linear" };
        }

        Plotly.react(id, fig.data, fig.layout, { responsive: true, displayModeBar: false });
      } catch (e) {
        console.warn(`Chart render failed for ${id}:`, e);
      }
    };

    render("chart-timeline",  charts.timeline);
    render("chart-severity",  charts.severity);
    render("chart-attacks",   charts.attack_type);
    render("chart-ips",       charts.top_ips);
    render("chart-risk",      charts.risk_hist);
  } catch (e) {
    console.warn("Charts fetch failed:", e);
  }
}

// ── Alert table ────────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const res  = await fetch("/api/alerts?limit=50");
    const data = await res.json();
    const tbody = document.getElementById("alert-tbody");
    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:#7d8590;padding:24px">
        No alerts yet — run the detection pipeline.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.alerts.map(a => {
      const riskClass = SEV_CLASS[a.risk_level] || "";
      const sevClass  = SEV_CLASS[a.severity]   || "";
      return `
        <tr>
          <td>${(a.detected_at || "").slice(0, 16)}</td>
          <td><code>${a.source_ip || ""}</code></td>
          <td><span class="badge">${a.attack_type || ""}</span></td>
          <td class="${sevClass}">${a.severity ?? ""}</td>
          <td>${a.confidence !== undefined ? a.confidence.toFixed(0) + "%" : ""}</td>
          <td class="${riskClass}">${a.risk_level || ""} ${a.risk_score !== undefined ? "(" + a.risk_score + ")" : ""}</td>
          <td class="small">${a.recommendation || ""}</td>
        </tr>`;
    }).join("");
  } catch (e) {
    console.warn("Alerts fetch failed:", e);
  }
}

// ── Pipeline trigger ───────────────────────────────────────────────────────────
async function runPipeline() {
  const btn = document.querySelector(".btn-run");
  btn.disabled    = true;
  btn.textContent = "Running…";
  try {
    const res  = await fetch("/api/run_pipeline", { method: "POST" });
    const data = await res.json();
    btn.textContent = data.status === "ok" ? "✓ Done" : "✗ Error";
    await refreshAll();
  } catch (e) {
    btn.textContent = "✗ Failed";
  }
  setTimeout(() => {
    btn.disabled    = false;
    btn.textContent = "↺ Re-run Pipeline";
  }, 3000);
}

// ── Timestamp ──────────────────────────────────────────────────────────────────
function updateTimestamp() {
  const el = document.getElementById("last-updated");
  if (el) el.textContent = "Updated " + new Date().toLocaleTimeString();
}

// ── Orchestrate ────────────────────────────────────────────────────────────────
async function refreshAll() {
  await Promise.all([loadStats(), loadCharts(), loadAlerts()]);
  updateTimestamp();
}

// Initial load + polling
refreshAll();
setInterval(refreshAll, POLL_MS);
