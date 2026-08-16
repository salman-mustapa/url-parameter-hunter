const API_BASE = "/api";
let activeScan = null;
let es = null;
let treePollTimer = null;
const state = { events: 0, subdomains: 0, ports: 0, urls: 0, parameters: 0, findings: 0 };

function el(id) { return document.getElementById(id); }
function esc(str) { if (str == null) return ""; return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function fmtStatus(status) {
  const map = { queued: "neutral", created: "neutral", running: "running", paused: "stopped", partial_failure: "stopped", completed: "success", stopped: "stopped", cancelled: "stopped" };
  return map[status] || "neutral";
}
function clearEmpty(id) { const c = el(id); if (!c) return; const f = c.querySelector(".empty"); if (f) f.remove(); }
function setEmpty(id, text) { const c = el(id); if (c) c.innerHTML = `<div class="empty">${esc(text)}</div>`; }

function addEvent(ev) {
  const container = el("eventStream");
  clearEmpty("eventStream");
  const item = document.createElement("div");
  item.className = "event-item";
  const sev = ev.severity ? `sev-${ev.severity}` : "sev-info";
  const cat = ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO");
  const ts = ev.created_at ? String(ev.created_at).slice(11, 19) : new Date().toLocaleTimeString();
  item.innerHTML = `<span class="ts">${esc(ts)}</span><span class="icon">${ev.icon || "📋"}</span><span class="cat ${sev}">${esc(cat)}</span><span>${esc(ev.message)}</span>`;
  container.appendChild(item);
  while (container.children.length > 500) container.removeChild(container.firstChild);
  container.scrollTop = container.scrollHeight;
  state.events += 1;
  setText("eventCounter", state.events);
}

function renderTreeNode(node, depth = 0) {
  const div = document.createElement("div");
  div.className = "tree-node";
  const meta = [node.type, node.depth != null ? `depth ${node.depth}` : "", node.ip, node.status].filter(Boolean).join(" · ");
  let label = node.hostname || node.fqdn || node.id;
  div.innerHTML = `<div class="title" style="padding-left:${depth * 14}px">${depth ? "└ " : ""}${node.type === "ip" ? "🌐" : "🐢"} ${esc(label)} <span class="meta">${esc(meta)}</span></div>`;
  div.querySelector(".title").addEventListener("click", (e) => {
    e.stopPropagation();
    loadAssetDetail(node.id);
  });
  (node.children || []).forEach((c) => div.appendChild(renderTreeNode(c, depth + 1)));
  return div;
}

function renderTree(tree) {
  const container = el("assetTree");
  container.innerHTML = "";
  if (!tree || !tree.length) { setEmpty("assetTree", "Belum ada asset."); return; }
  tree.forEach((n) => container.appendChild(renderTreeNode(n)));
}

async function refreshTree() {
  if (!activeScan) return;
  try {
    const res = await fetch(`${API_BASE}/assets/tree?scan_id=${encodeURIComponent(activeScan)}`);
    renderTree(await res.json());
  } catch (e) { /* silent */ }
}

async function loadAssetDetail(assetId) {
  try {
    const res = await fetch(`${API_BASE}/assets/${encodeURIComponent(assetId)}`);
    const a = await res.json();
    if (!a || !a.id) return;
    const panel = el("assetDetail");
    panel.classList.remove("hidden");
    let html = `<div class="section-header"><h3>🔍 ${esc(a.hostname || a.id)}</h3><button class="btn btn-ghost" onclick="document.getElementById('assetDetail').classList.add('hidden')">✕</button></div>`;
    html += `<div class="meta">${esc(a.type || "")} · depth ${a.depth} · ${esc(a.status || "")} · IP: ${esc(a.ip || "-")}${a.metadata_ && a.metadata_.cname ? ` · CNAME: ${esc(a.metadata_.cname)}` : ""}</div>`;
    if (a.ports && a.ports.length) {
      html += `<h4>Ports</h4><div class="chips">${a.ports.map(p => `<span class="chip">${p.port}/${p.protocol} ${esc(p.service || "")}</span>`).join("")}</div>`;
    }
    if (a.urls && a.urls.length) {
      html += `<h4>URLs (${a.urls.length})</h4><ul class="url-list">${a.urls.slice(0, 30).map(u => `<li><a href="${esc(u.url)}" target="_blank" rel="noopener">${esc(u.url)}</a> <span class="code">${u.status_code || "-"}</span></li>`).join("")}</ul>`;
    }
    if (a.parameters && a.parameters.length) {
      html += `<h4>Parameters (${a.parameters.length})</h4><div class="chips">${a.parameters.map(p => `<span class="chip">${esc(p.name)} <small>${esc(p.location)}</small></span>`).join("")}</div>`;
    }
    if (a.technologies && a.technologies.length) {
      html += `<h4>Technologies</h4><div class="chips">${a.technologies.map(t => `<span class="chip">⚙️ ${esc(t.name)}${t.version ? " " + esc(t.version) : ""}</span>`).join("")}</div>`;
    }
    if (a.certificates && a.certificates.length) {
      html += `<h4>Certificates</h4><ul class="url-list">${a.certificates.map(c => `<li>🔐 ${esc(c.subject_cn)}<br><small>issuer: ${esc(c.issuer_cn)} · exp: ${c.not_after ? new Date(c.not_after).toLocaleDateString("id-ID") : "-"}</small></li>`).join("")}</ul>`;
    }
    if (a.findings && a.findings.length) {
      html += `<h4>Findings (${a.findings.length})</h4>` + a.findings.map(f => `<div class="finding"><span class="severity-badge severity-${esc(f.severity)}">${esc(f.severity)}</span><div style="font-weight:700">${esc(f.title)}</div><div style="color:var(--muted);font-size:12px">${esc(f.status)}</div></div>`).join("");
    }
    if (a.observations && a.observations.length) {
      html += `<h4>Observations (${a.observations.length})</h4><div class="chips">${a.observations.map(o => `<span class="chip">👁 ${esc(o.title)}</span>`).join("")}</div>`;
    }
    panel.innerHTML = html;
  } catch (e) { /* silent */ }
}

function addFinding(f) {
  const container = el("findingsPanel");
  clearEmpty("findingsPanel");
  const div = document.createElement("div");
  div.className = "finding";
  div.innerHTML = `<span class="severity-badge severity-${esc(f.severity)}">${esc(f.severity)}</span><div><div style="font-weight:700">${esc(f.title)}</div><div style="color:var(--muted);font-size:12px">confidence ${Number(f.confidence || 0).toFixed(2)} · ${esc(f.status)}</div></div>`;
  container.appendChild(div);
  setText("findingsSummary", container.children.length);
}

async function loadFindings() {
  if (!activeScan) return;
  try {
    const res = await fetch(`${API_BASE}/findings?scan_id=${encodeURIComponent(activeScan)}`);
    const findings = await res.json();
    const container = el("findingsPanel");
    container.innerHTML = "";
    if (!findings.length) { setEmpty("findingsPanel", "Belum ada finding."); return; }
    findings.forEach((f) => addFinding(f));
    setText("findingsSummary", findings.length);
  } catch (e) { /* silent */ }
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
    el("eventStream").innerHTML = ""; setEmpty("eventStream", "Scan dimulai...");
    el("assetTree").innerHTML = ""; setEmpty("assetTree", "Menunggu asset...");
    el("findingsPanel").innerHTML = ""; setEmpty("findingsPanel", "Belum ada finding.");
    connectEvents(activeScan);
    treePollTimer = setInterval(refreshTree, 5000);
    refreshTree();
  } catch (e) {
    alert("Gagal start scan: " + e.message);
  }
}

function connectEvents(scanId) {
  if (es) es.close();
  es = new EventSource(`${API_BASE}/scans/${encodeURIComponent(scanId)}/events`);
  es.onmessage = (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch (e) { return; }
    if (data.event_type === "asset.discovered") { state.subdomains += 1; refreshTree(); }
    else if (data.event_type === "port.open") state.ports += 1;
    else if (data.event_type === "url.discovered") state.urls += 1;
    else if (data.event_type === "parameter.discovered") state.parameters += 1;
    else if (data.event_type === "finding.created") { state.findings += 1; loadFindings(); }
    else if (data.event_type === "scan.completed") {
      clearInterval(treePollTimer);
      refreshTree(); loadFindings();
      setText("scanStatus", "COMPLETED");
      el("startBtn").disabled = false;
      el("pauseBtn").disabled = true;
      el("stopBtn").disabled = true;
      es.close();
    } else if (data.event_type === "scan.stopped" || data.event_type === "scan.failed") {
      clearInterval(treePollTimer);
      setText("scanStatus", data.event_type === "scan.stopped" ? "STOPPED" : "FAILED");
      el("startBtn").disabled = false;
      el("pauseBtn").disabled = true;
      el("stopBtn").disabled = true;
    }
    addEvent(data);
  };
  es.onerror = () => { /* SSE reconnect auto; keep state */ };
}

async function loadHistory() {
  const [res, domainsRes] = await Promise.all([
    fetch(`${API_BASE}/scans`),
    fetch(`${API_BASE}/domains`),
  ]);
  const scans = await res.json();
  const domains = await domainsRes.json();
  const container = el("historyPanel");
  container.innerHTML = "";
  if (!scans.length) { setEmpty("historyPanel", "Belum ada history."); return; }

  // group scans by root domain (architecture §27)
  domains.forEach((d) => {
    const dScans = scans.filter((s) => s.root_domain === d.root_domain);
    const dom = document.createElement("div");
    dom.className = "history-domain";
    let html = `<div class="history-domain-title">🌐 ${esc(d.root_domain)} <span class="pill pill-neutral">${d.scan_count} scan</span> <span class="pill pill-neutral">last ${d.last_scan ? new Date(d.last_scan).toLocaleDateString("id-ID") : "-"}</span></div>`;
    html += dScans.map((scan) => `
      <div class="history-item">
        <div class="title">#${scan.id.replace(/^scan_\d+_/, "").slice(0, 8)} — ${esc(scan.status)}</div>
        <div class="meta"><span class="pill pill-${fmtStatus(scan.status)}">${esc(scan.status)}</span> · ${esc(scan.profile)} · ${scan.created_at ? new Date(scan.created_at).toLocaleString("id-ID") : "-"} · assets ${(scan.progress && scan.progress.assets) || 0} · urls ${(scan.progress && scan.progress.urls) || 0} · ports ${(scan.progress && scan.progress.ports) || 0} · findings ${(scan.progress && scan.progress.findings) || 0}</div>
      </div>`).join("");
    dom.innerHTML = html;
    dom.querySelectorAll(".history-item").forEach((item, i) => {
      item.addEventListener("click", () => openHistoryScan(dScans[i].id, d.root_domain));
    });
    container.appendChild(dom);
  });
}

async function openHistoryScan(scanId, domain) {
  activeScan = scanId;
  setText("scanStatus", "LOADED");
  el("startBtn").disabled = false;
  el("pauseBtn").disabled = true;
  el("stopBtn").disabled = true;
  el("target").value = domain || "";
  document.querySelector('[data-route="/"]').click();
  el("eventStream").innerHTML = ""; setEmpty("eventStream", "Stream history tidak diputar ulang. Lihat tree & findings.");
  await refreshTree();
  await loadFindings();
  connectEvents(scanId);
  treePollTimer = setInterval(refreshTree, 10000);
}

function setText(id, value) { const e = el(id); if (e) e.textContent = value; }

document.addEventListener("DOMContentLoaded", () => {
  // simple hash router
  function route() {
    const hash = location.hash || "#/";
    const isHistory = hash.startsWith("#/history");
    document.querySelector(".dashboard").classList.toggle("hidden", isHistory);
    document.getElementById("historySection").classList.toggle("hidden", !isHistory);
    document.querySelectorAll(".nav-link").forEach((a) => a.classList.toggle("active", a.dataset.route === (isHistory ? "/history" : "/")));
  }
  window.addEventListener("hashchange", route);

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
    if (es) es.close();
    clearInterval(treePollTimer);
    el("startBtn").disabled = false;
    el("pauseBtn").disabled = true;
    el("stopBtn").disabled = true;
  });
  el("refreshTreeBtn").addEventListener("click", refreshTree);
  el("refreshHistoryBtn").addEventListener("click", loadHistory);

  route();
  loadHistory();
});