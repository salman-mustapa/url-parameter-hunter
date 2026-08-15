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
  const cat = ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO";
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

async function api(path, opts = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers: { "Content-Type": "application/json", ...(opts.headers || {}) } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/event-stream")) return res;
  return res.json();
}

async function startScan() {
  const target = el("target").value.trim();
  if (!target) return alert("Masukkan target domain (contoh: example.com)");
  try {
    const data = await api(`/scans?target=${encodeURIComponent(target)}&profile=standard&include_subdomains=true`, { method: "POST" });
    activeScan = data.scan_id;
    setStatus(data.status, data.target);
    el("pauseBtn").disabled = false;
    el("stopBtn").disabled = false;
    el("pauseBtn").textContent = "PAUSE";
    subscribeStream(data.scan_id);
    await loadHistory();
  } catch (e) {
    alert("Gagal memulai scan: " + e.message);
  }
}

async function pauseScan() {
  if (!activeScan) return;
  await api(`/scans/${activeScan}/pause`, { method: "POST" });
  el("pauseBtn").textContent = "RESUME";
  setStatus("paused", activeScan);
}

async function resumeScan() {
  if (!activeScan) return;
  await api(`/scans/${activeScan}/resume`, { method: "POST" });
  el("pauseBtn").textContent = "PAUSE";
  setStatus("running", activeScan);
}

async function togglePause() {
  if (!activeScan) return;
  const current = el("pauseBtn").textContent;
  if (current === "PAUSE") await pauseScan();
  else await resumeScan();
}

async function stopScan() {
  if (!activeScan) return;
  await api(`/scans/${activeScan}/stop`, { method: "POST" });
  setStatus("stopped", activeScan);
  el("pauseBtn").disabled = true;
  el("stopBtn").disabled = true;
}

function setStatus(status, target) {
  const pill = el("scanStatus");
  pill.textContent = (status || "IDLE").toUpperCase();
  pill.className = "pill pill-" + fmtStatus(status);
  if (target) setText("scanProfile", target);
}

async function subscribeStream(scanId) {
  try {
    const res = await api(`/scans/${scanId}/events`);
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop();
      for (const chunk of parts) {
        const line = chunk.replace(/^data:\s*/, "").trim();
        if (!line) continue;
        try { handleEvent(JSON.parse(line)); } catch (e) { console.warn("skip event", e); }
      }
    }
  } catch (e) {
    console.warn("Stream ended:", e);
  }
}

function handleEvent(ev) {
  addEvent(ev);
  const type = ev.event_type || "";
  if (type === "asset.discovered") {
    const asset = { id: ev.hostname || ev.asset_id, hostname: ev.hostname, type: ev.asset_type || "subdomain", depth: ev.depth || 0, ip: ev.ip || "", status: ev.status || "discovered", children: [] };
    addAssetNode(asset);
    state.subdomains += 1;
  } else if (type === "dns.resolved") {
    state.ips = (state.ips || 0) + 1;
  } else if (type === "port.open") {
    state.ports += 1;
  } else if (type === "url.discovered") {
    state.urls += 1;
  } else if (type === "parameter.discovered") {
    state.parameters += 1;
  } else if (type === "finding.created" || type === "finding.updated") {
    addFinding(ev);
  } else if (type === "scan.completed") {
    setStatus("completed", activeScan);
    el("pauseBtn").disabled = true;
    el("stopBtn").disabled = true;
  } else if (type === "scan.stopped" || type === "scan.failed") {
    setStatus(type.replace("scan.", ""), activeScan);
    el("pauseBtn").disabled = true;
    el("stopBtn").disabled = true;
  }
}

async function loadTree() {
  if (!activeScan) return alert("Pilih scan aktif terlebih dahulu");
  try {
    const data = await api(`/assets/tree?scan_id=${activeScan}`);
    const container = el("assetTree");
    container.innerHTML = "";
    if (!data.length) { setEmpty("assetTree", "Belum ada asset."); return; }
    data.forEach((node) => container.appendChild(buildTreeDOM(node)));
  } catch (e) { console.warn(e); }
}

function buildTreeDOM(node) {
  const div = document.createElement("div");
  div.className = "tree-node";
  const meta = [node.type, `depth ${node.depth}`, node.ip, node.status].filter(Boolean).join(" · ");
  div.innerHTML = `<div class="title">🐢 ${esc(node.hostname || node.id)}</div><div class="meta">${esc(meta)}</div>`;
  if (node.children && node.children.length) {
    const wrap = document.createElement("div");
    wrap.className = "tree-children";
    node.children.forEach((c) => wrap.appendChild(buildTreeDOM(c)));
    div.appendChild(wrap);
  }
  return div;
}

async function loadFindings() {
  if (!activeScan) return alert("Pilih scan aktif terlebih dahulu");
  try {
    const data = await api(`/findings?scan_id=${activeScan}`);
    const container = el("findingsPanel");
    container.innerHTML = "";
    if (!data.length) { setEmpty("findingsPanel", "Belum ada finding."); return; }
    data.forEach((f) => addFinding(f));
  } catch (e) { console.warn(e); }
}

async function loadHistory() {
  try {
    const scans = await api(`/scans`);
    const container = el("historyPanel");
    container.innerHTML = "";
    if (!scans.length) { setEmpty("historyPanel", "Belum ada history."); return; }
    scans.forEach((s) => addHistoryItem(s));
  } catch (e) { console.warn(e); }
}

async function openHistoryScan(scanId) {
  activeScan = scanId;
  const data = await api(`/scans/${scanId}`);
  setStatus(data.status, data.root_domain);
  el("pauseBtn").disabled = data.status === "completed" || data.status === "stopped";
  el("stopBtn").disabled = data.status === "completed" || data.status === "stopped";
  await loadTree();
  await loadFindings();
  subscribeStream(scanId);
}

function init() {
  el("startBtn").addEventListener("click", startScan);
  el("pauseBtn").addEventListener("click", togglePause);
  el("stopBtn").addEventListener("click", stopScan);
  el("refreshTreeBtn").addEventListener("click", loadTree);
  el("refreshHistoryBtn").addEventListener("click", loadHistory);
  loadHistory();
}

init();
