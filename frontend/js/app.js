const API_BASE = "/api";
let activeScan = null;
const state = { events: 0, subdomains: 0, ports: 0, urls: 0, parameters: 0, findings: 0 };

function el(id) { return document.getElementById(id); }
function esc(str) { if (str == null) return ""; return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function fmtStatus(status) {
  const map = { queued: "neutral", created: "neutral", running: "running", paused: "stopped", partial_failure: "stopped", completed: "success", stopped: "stopped", cancelled: "stopped" };
  return map[status] || "neutral";
}
function clearEmpty(containerId) { const c = el(containerId); const f = c.querySelector(".empty"); if (f) f.remove(); }
function setEmpty(containerId, text) { const c = el(containerId); c.innerHTML = `<div class="empty">${esc(text)}</div>`; }
function setText(id, value) { const e = el(id); if (e) e.textContent = value; }

function addEvent(ev) {
  const container = el("eventStream");
  clearEmpty("eventStream");
  const item = document.createElement("div");
  item.className = "event-item";
  const sev = ev.severity ? `sev-${ev.severity}` : "sev-info";
  const cat = ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO");
  const ts = ev.created_at ? ev.created_at.slice(11, 19) : new Date().toLocaleTimeString();
  item.innerHTML = `<span class="ts">${esc(ts)}</span><span class="icon">${ev.icon || "📋"}</span><span class="cat ${sev}">${esc(cat)}</span><span>${esc(ev.message)}</span>`;
  container.appendChild(item);
  container.scrollTop = container.scrollHeight;
  state.events += 1;
  setText("eventCounter", state.events);
}

function addAssetNode(node) {
  const container = el("assetTree");
  clearEmpty("assetTree");
  const div = document.createElement("div");
  div.className = "tree-node";
  const meta = [node.type, `depth ${node.depth}`, node.ip, node.status].filter(Boolean).join(" · ");
  div.innerHTML = `<div class="title">🐢 ${esc(node.hostname || node.id)}</div><div class="meta">${esc(meta)}</div>`;
  if (node.children && node.children.length) {
    const wrap = document.createElement("div");
    wrap.className = "tree-children";
    node.children.forEach((c) => wrap.appendChild(makeAssetNode(c)));
    div.appendChild(wrap);
  }
  container.appendChild(div);
}

function makeAssetNode(node) {
  const div = document.createElement("div");
  div.className = "tree-node";
  const meta = [node.type, `depth ${node.depth}`, node.ip, node.status].filter(Boolean).join(" · ");
  div.innerHTML = `<div class="title">🐢 ${esc(node.hostname || node.id)}</div><div class="meta">${esc(meta)}</div>`;
  if (node.children && node.children.length) {
    const wrap = document.createElement("div");
    wrap.className = "tree-children";
    node.children.forEach((c) => wrap.appendChild(makeAssetNode(c)));
    div.appendChild(wrap);
  }
  return div;
}

function addFinding(f) {
  const container = el("findingsPanel");
  clearEmpty("findingsPanel");
  const div = document.createElement("div");
  div.className = "finding";
  div.innerHTML = `<span class="severity-badge severity-${f.severity}">${esc(f.severity)}</span><div><div style="font-weight:700">${esc(f.title)}</div><div style="color:var(--muted);font-size:12px">confidence ${Number(f.confidence || 0).toFixed(2)} · ${esc(f.status)}</div></div>`;
  container.appendChild(div);
  state.findings += 1;
  setText("findingsSummary", state.findings);
}

function addHistoryItem(scan) {
  const container = el("historyPanel");
  clearEmpty("historyPanel");
  const div = document.createElement("div");
  div.className = "history-item";
  div.innerHTML = `<div class="title">${esc(scan.root_domain)}</div><div class="meta">${esc(scan.status)} · ${esc(scan.profile)} · ${scan.created_at ? new Date(scan.created_at).toLocaleString("id-ID") : "-"}</div>`;
  div.addEventListener("click", () => openHistoryScan(scan.id));
  container.appendChild(div);
}

async function startScan() {
  const target = el("target").value.trim();
  if (!target) return alert("Masukkan target domain");
  try {
    const res = await fetch(`${API_BASE}/scans?target=${encodeURIComponent(target)}&profile=standard&include_subdomains=true`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    activeScan = data.scan_id;
    setText("scanStatus", "RUNNING");
    el("startBtn").disabled = true;
    el("pauseBtn").disabled = false;
    el("stopBtn").disabled = false;
    connectEvents(activeScan);
  } catch (e) {
    alert("Gagal start scan: " + e.message);
  }
}

function connectEvents(scanId) {
  const es = new EventSource(`${API_BASE}/scans/${encodeURIComponent(scanId)}/events`);
  es.onmessage = (ev) => {
    const data = JSON.parse(ev.data);
    if (data.event_type === "asset.discovered") {
      state.subdomains += 1;
    } else if (data.event_type === "port.open") {
      state.ports += 1;
    } else if (data.event_type === "url.discovered") {
      state.urls += 1;
    } else if (data.event_type === "parameter.discovered") {
      state.parameters += 1;
    } else if (data.event_type === "finding.created") {
      state.findings += 1;
      addFinding({ title: data.message, severity: data.severity || "INFO", confidence: 0.7, status: "open" });
    }
    addEvent(data);
  };
  es.onerror = () => {
    setText("scanStatus", "ERROR");
    es.close();
  };
  window._currentEs = es;
}

async function loadHistory() {
  const res = await fetch(`${API_BASE}/scans`);
  const scans = await res.json();
  const container = el("historyPanel");
  container.innerHTML = "";
  if (!scans.length) {
    setEmpty("historyPanel", "Belum ada history.");
    return;
  }
  scans.forEach((s) => addHistoryItem(s));
}

function openHistoryScan(scanId) {
  // Placeholder: bisa kamu kembangkan jadi detail view
  alert("History scan: " + scanId + "\nFitur detail history segera hadir.");
}

document.addEventListener("DOMContentLoaded", () => {
  el("startBtn").addEventListener("click", startScan);
  el("pauseBtn").addEventListener("click", async () => {
    if (!activeScan) return;
    await fetch(`${API_BASE}/scans/${encodeURIComponent(activeScan)}/pause`, { method: "POST" });
    setText("scanStatus", "PAUSED");
  });
  el("stopBtn").addEventListener("click", async () => {
    if (!activeScan) return;
    await fetch(`${API_BASE}/scans/${encodeURIComponent(activeScan)}/stop`, { method: "POST" });
    setText("scanStatus", "STOPPED");
    if (window._currentEs) window._currentEs.close();
  });
  el("refreshTreeBtn").addEventListener("click", async () => {
    if (!activeScan) return;
    const res = await fetch(`${API_BASE}/assets/tree?scan_id=${encodeURIComponent(activeScan)}`);
    const tree = await res.json();
    el("assetTree").innerHTML = "";
    if (!tree.length) {
      setEmpty("assetTree", "Belum ada asset.");
      return;
    }
    tree.forEach((node) => addAssetNode(node));
  });
  el("refreshHistoryBtn").addEventListener("click", loadHistory);
});
