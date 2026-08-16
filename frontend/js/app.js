/**
 * HUNTER AJA — Attack Surface & Parameter Intelligence Platform
 * Frontend SPA Application Logic
 */

const API_BASE = "/api";

const state = {
  activeScanId: null,
  activeTarget: "",
  scanStatus: "IDLE",
  timerInterval: null,
  timerSeconds: 0,
  es: null,
  treePollInterval: null,
  currentCategoryFilter: "ALL",
  events: [],
  assetsTreeData: [],
  selectedAssetId: null,
  activeDetailTab: "overview",
  collapsedNodeIds: new Set(),
  currentAssetData: null,
  counters: {

    assets: 0,
    ports: 0,
    urls: 0,
    params: 0,
    techs: 0,
    findings: 0,
  },
  severityCounts: {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  },
};

// Utilities
function el(id) { return document.getElementById(id); }
function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(seconds) {
  const m = Math.floor(seconds / 60).toString().padStart(2, "0");
  const s = (seconds % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

// --------------------------------------------------------------------------
// Navigation & Views
// --------------------------------------------------------------------------
function setupNavigation() {
  document.querySelectorAll(".nav-link[data-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll(".nav-link[data-tab]").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      document.querySelectorAll(".tab-view").forEach((v) => v.classList.add("hidden"));
      if (tab === "dashboard") {
        el("viewDashboard").classList.remove("hidden");
      } else if (tab === "history") {
        el("viewHistory").classList.remove("hidden");
        loadHistory();
      } else if (tab === "diff") {
        el("viewDiff").classList.remove("hidden");
        populateDiffSelects();
      }
    });
  });
}

// --------------------------------------------------------------------------
// Event Stream & Terminal
// --------------------------------------------------------------------------
function getCategoryTagClass(cat) {
  const map = {
    DISCOVERY: "tag-discovery",
    DNS: "tag-dns",
    PORT: "tag-port",
    HTTP: "tag-http",
    URL: "tag-url",
    PARAM: "tag-param",
    PARAMETER: "tag-param",
    TECH: "tag-tech",
    TECHNOLOGY: "tag-tech",
    FINDING: "tag-finding",
    SCAN: "tag-scan",
    CERT: "tag-cert",
    OBSERVATION: "tag-observation",
  };
  return map[cat] || "tag-scan";
}

function addEventToStream(ev) {
  state.events.push(ev);
  if (state.events.length > 800) state.events.shift();

  el("streamCount").textContent = `${state.events.length} events`;

  const container = el("eventStreamContainer");
  const empty = container.querySelector(".event-empty-msg");
  if (empty) empty.remove();

  const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
  const normalizedCat = cat.startsWith("PARAM") ? "PARAM" : (cat.startsWith("TECH") ? "TECH" : cat);

  // Check filter
  if (state.currentCategoryFilter !== "ALL" && !normalizedCat.includes(state.currentCategoryFilter)) {
    return;
  }

  const item = document.createElement("div");
  item.className = "event-item";
  item.dataset.category = normalizedCat;

  const ts = ev.created_at ? String(ev.created_at).slice(11, 19) : new Date().toLocaleTimeString();
  const tagClass = getCategoryTagClass(normalizedCat);

  item.innerHTML = `
    <span class="event-time">[${esc(ts)}]</span>
    <span class="event-tag ${tagClass}">${esc(normalizedCat)}</span>
    <span class="event-msg">${esc(ev.message)}</span>
  `;

  container.appendChild(item);

  if (el("autoScrollCheck").checked) {
    container.scrollTop = container.scrollHeight;
  }
}

function filterStreamEvents(filterCat) {
  state.currentCategoryFilter = filterCat;
  const container = el("eventStreamContainer");
  container.innerHTML = "";

  const filtered = state.events.filter((ev) => {
    if (filterCat === "ALL") return true;
    const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
    return cat.includes(filterCat);
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="event-empty-msg"><p>Tidak ada event untuk filter <strong>${esc(filterCat)}</strong>.</p></div>`;
    return;
  }

  filtered.forEach((ev) => {
    const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
    const normalizedCat = cat.startsWith("PARAM") ? "PARAM" : (cat.startsWith("TECH") ? "TECH" : cat);
    const ts = ev.created_at ? String(ev.created_at).slice(11, 19) : new Date().toLocaleTimeString();
    const tagClass = getCategoryTagClass(normalizedCat);

    const item = document.createElement("div");
    item.className = "event-item";
    item.innerHTML = `
      <span class="event-time">[${esc(ts)}]</span>
      <span class="event-tag ${tagClass}">${esc(normalizedCat)}</span>
      <span class="event-msg">${esc(ev.message)}</span>
    `;
    container.appendChild(item);
  });

  if (el("autoScrollCheck").checked) {
    container.scrollTop = container.scrollHeight;
  }
}

// --------------------------------------------------------------------------
// Scan Controls
// --------------------------------------------------------------------------
function updateScanStatusUI(status) {
  state.scanStatus = status;
  const statusEl = el("scanStatus");
  statusEl.textContent = status;
  statusEl.className = "pill";

  const map = {
    IDLE: "pill-neutral",
    QUEUED: "pill-neutral",
    RUNNING: "pill-running",
    PAUSED: "pill-paused",
    STOPPED: "pill-stopped",
    COMPLETED: "pill-completed",
    FAILED: "pill-stopped",
  };
  statusEl.classList.add(map[status] || "pill-neutral");

  const isRunning = status === "RUNNING";
  const isPaused = status === "PAUSED";

  el("startBtn").disabled = isRunning || isPaused;
  el("pauseBtn").disabled = !isRunning;
  el("pauseBtn").classList.toggle("hidden", isPaused);
  el("resumeBtn").classList.toggle("hidden", !isPaused);
  el("stopBtn").disabled = !(isRunning || isPaused);
  el("exportBtn").disabled = !state.activeScanId;
  el("quickExportBtn").disabled = !state.activeScanId;
}

function startTimer() {
  clearInterval(state.timerInterval);
  state.timerSeconds = 0;
  el("scanTime").classList.remove("hidden");
  el("scanTime").textContent = `⏱ 00:00`;
  state.timerInterval = setInterval(() => {
    state.timerSeconds += 1;
    el("scanTime").textContent = `⏱ ${formatTime(state.timerSeconds)}`;
  }, 1000);
}

function stopTimer() {
  clearInterval(state.timerInterval);
}

async function startScan() {
  const target = el("targetInput").value.trim();
  if (!target) {
    alert("Masukkan root domain atau URL target (contoh: example.com)");
    return;
  }

  const profile = el("profileSelect").value;
  const includeSubdomains = el("subdomainsToggle").checked;

  try {
    const res = await fetch(`${API_BASE}/scans?target=${encodeURIComponent(target)}&profile=${encodeURIComponent(profile)}&include_subdomains=${includeSubdomains}`, {
      method: "POST",
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    state.activeScanId = data.scan_id;
    state.activeTarget = data.target;

    el("scanIdDisplay").textContent = `ID: ${data.scan_id}`;
    el("scanIdDisplay").classList.remove("hidden");

    // Reset counters & stream
    state.events = [];
    state.counters = { assets: 0, ports: 0, urls: 0, params: 0, techs: 0, findings: 0 };
    state.severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    updateCounterDisplays();

    el("eventStreamContainer").innerHTML = "";
    el("assetTreeContainer").innerHTML = `<div class="tree-empty-msg"><p>Menjalankan pipeline aktif...</p></div>`;
    el("findingsListContainer").innerHTML = `<div class="findings-empty-msg"><p>Menganalisis temuan keamanan...</p></div>`;

    updateScanStatusUI("RUNNING");
    startTimer();
    connectEventSource(data.scan_id);

    clearInterval(state.treePollInterval);
    state.treePollInterval = setInterval(refreshAssetTree, 4000);
    refreshAssetTree();
  } catch (err) {
    alert(`Gagal memulai scan: ${err.message}`);
  }
}

async function pauseScan() {
  if (!state.activeScanId) return;
  try {
    await fetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/pause`, { method: "POST" });
    updateScanStatusUI("PAUSED");
  } catch (err) {
    console.error("Pause error:", err);
  }
}

async function resumeScan() {
  if (!state.activeScanId) return;
  try {
    await fetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/resume`, { method: "POST" });
    updateScanStatusUI("RUNNING");
  } catch (err) {
    console.error("Resume error:", err);
  }
}

async function stopScan() {
  if (!state.activeScanId) return;
  try {
    await fetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/stop`, { method: "POST" });
    updateScanStatusUI("STOPPED");
    stopTimer();
    if (state.es) state.es.close();
    clearInterval(state.treePollInterval);
    refreshAssetTree();
    loadFindings();
  } catch (err) {
    console.error("Stop error:", err);
  }
}

async function exportScanJSON() {
  if (!state.activeScanId) return;
  try {
    const res = await fetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/export`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunter_aja_${state.activeScanId}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Gagal mengunduh laporan scan: " + err.message);
  }
}

// --------------------------------------------------------------------------
// Realtime SSE Event Handler
// --------------------------------------------------------------------------
function connectEventSource(scanId) {
  if (state.es) state.es.close();

  state.es = new EventSource(`${API_BASE}/scans/${encodeURIComponent(scanId)}/events`);

  state.es.onmessage = (event) => {
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (e) {
      return;
    }

    addEventToStream(data);

    // Event counter dispatchers
    if (data.event_type === "asset.discovered") {
      state.counters.assets += 1;
      updateCounterDisplays();
      refreshAssetTree();
    } else if (data.event_type === "port.open") {
      state.counters.ports += 1;
      updateCounterDisplays();
    } else if (data.event_type === "url.discovered") {
      state.counters.urls += 1;
      updateCounterDisplays();
    } else if (data.event_type === "parameter.discovered") {
      state.counters.params += 1;
      updateCounterDisplays();
    } else if (data.event_type === "technology.detected") {
      state.counters.techs += 1;
      updateCounterDisplays();
    } else if (data.event_type === "finding.created") {
      state.counters.findings += 1;
      const sev = (data.severity || "INFO").toUpperCase();
      if (state.severityCounts[sev] != null) state.severityCounts[sev] += 1;
      updateCounterDisplays();
      loadFindings();
    } else if (data.event_type === "scan.completed") {
      updateScanStatusUI("COMPLETED");
      stopTimer();
      refreshAssetTree();
      loadFindings();
      if (state.es) state.es.close();
      clearInterval(state.treePollInterval);
    } else if (data.event_type === "scan.stopped" || data.event_type === "scan.failed") {
      updateScanStatusUI(data.event_type === "scan.stopped" ? "STOPPED" : "FAILED");
      stopTimer();
      refreshAssetTree();
      loadFindings();
    }
  };

  state.es.onerror = () => {
    // EventSource auto reconnects
  };
}

function updateCounterDisplays() {
  el("counterAssets").textContent = state.counters.assets;
  el("counterPorts").textContent = state.counters.ports;
  el("counterUrls").textContent = state.counters.urls;
  el("counterParams").textContent = state.counters.params;
  el("counterTechs").textContent = state.counters.techs;
  el("counterFindings").textContent = state.counters.findings;

  el("findingsBadgeTotal").textContent = `${state.counters.findings} Total`;
  el("sevCritCount").textContent = state.severityCounts.CRITICAL;
  el("sevHighCount").textContent = state.severityCounts.HIGH;
  el("sevMedCount").textContent = state.severityCounts.MEDIUM;
  el("sevLowCount").textContent = state.severityCounts.LOW;
  el("sevInfoCount").textContent = state.severityCounts.INFO;
}

// --------------------------------------------------------------------------
// Hierarchical Asset Tree
// --------------------------------------------------------------------------
async function refreshAssetTree() {
  if (!state.activeScanId) return;
  try {
    const res = await fetch(`${API_BASE}/assets/tree?scan_id=${encodeURIComponent(state.activeScanId)}`);
    const tree = await res.json();
    state.assetsTreeData = tree;
    renderAssetTree(tree);
  } catch (e) {
    // silent
  }
}

function collectParentIds(nodes, set) {
  if (!nodes || !nodes.length) return;
  nodes.forEach((n) => {
    if (n.children && n.children.length > 0) {
      set.add(n.id);
      collectParentIds(n.children, set);
    }
  });
}

function collapseAllNodes() {
  if (!state.assetsTreeData || !state.assetsTreeData.length) return;
  collectParentIds(state.assetsTreeData, state.collapsedNodeIds);
  renderAssetTree(state.assetsTreeData);
}

function expandAllNodes() {
  state.collapsedNodeIds.clear();
  renderAssetTree(state.assetsTreeData);
}

function renderAssetTree(treeNodes) {
  const container = el("assetTreeContainer");
  const searchQuery = (el("treeSearchInput").value || "").trim().toLowerCase();

  container.innerHTML = "";
  if (!treeNodes || !treeNodes.length) {
    container.innerHTML = `<div class="tree-empty-msg"><p>Belum ada asset aktif yang terdeteksi.</p></div>`;
    return;
  }

  function filterNode(node) {
    const matches = (node.hostname || "").toLowerCase().includes(searchQuery) ||
                    (node.ip || "").toLowerCase().includes(searchQuery);
    const matchingChildren = (node.children || []).filter(filterNode);
    return matches || matchingChildren.length > 0;
  }

  const nodesToRender = searchQuery ? treeNodes.filter(filterNode) : treeNodes;

  if (!nodesToRender.length) {
    container.innerHTML = `<div class="tree-empty-msg"><p>Tidak ada asset yang cocok dengan "${esc(searchQuery)}".</p></div>`;
    return;
  }

  nodesToRender.forEach((node) => {
    container.appendChild(createTreeNodeElement(node, 0));
  });
}

function createTreeNodeElement(node, depth = 0) {
  const wrap = document.createElement("div");
  wrap.className = "tree-node-item";

  const isIp = node.type === "ip";
  const icon = isIp ? "🌐" : (node.depth === 0 ? "🎯" : "🌿");
  const label = isIp ? (node.ip || node.hostname) : (node.hostname || node.fqdn || node.ip || node.id);
  const isSelected = state.selectedAssetId === node.id;
  const hasChildren = node.children && node.children.length > 0;
  const isCollapsed = state.collapsedNodeIds.has(node.id);

  const content = document.createElement("div");
  content.className = `tree-node-content ${isSelected ? "selected" : ""}`;
  content.style.paddingLeft = `${Math.min(depth * 14 + 6, 80)}px`;

  let badgesHtml = "";
  if (isIp) {
    badgesHtml += `<span class="node-badge" style="background:#E0F2FE; color:#0369A1; font-weight:800;">Host IP</span>`;
  } else {
    if (node.status === "resolved" || node.status === "active") {
      badgesHtml += `<span class="node-badge badge-live">🟢 Active</span>`;
    }
    if (node.ip) {
      badgesHtml += `<span class="node-badge">IP: ${esc(node.ip)}</span>`;
    }
  }

  const toggleHtml = hasChildren
    ? `<button class="tree-toggle-btn" title="${isCollapsed ? 'Buka cabang' : 'Tutup cabang'}">${isCollapsed ? '▶' : '▼'}</button>`
    : `<span class="tree-toggle-spacer"></span>`;

  content.innerHTML = `
    <div class="node-title-group">
      ${toggleHtml}
      <span class="node-icon">${icon}</span>
      <span>${esc(label)}</span>
    </div>
    <div class="node-badges">
      ${badgesHtml}
    </div>
  `;

  // Toggle button event
  if (hasChildren) {
    const toggleBtn = content.querySelector(".tree-toggle-btn");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (state.collapsedNodeIds.has(node.id)) {
          state.collapsedNodeIds.delete(node.id);
        } else {
          state.collapsedNodeIds.add(node.id);
        }
        renderAssetTree(state.assetsTreeData);
      });
    }
  }

  // Node selection event
  content.addEventListener("click", (e) => {
    e.stopPropagation();
    state.selectedAssetId = node.id;
    document.querySelectorAll(".tree-node-content").forEach((c) => c.classList.remove("selected"));
    content.classList.add("selected");
    loadAssetDetail(node.id);
  });

  wrap.appendChild(content);

  if (hasChildren) {
    const childrenContainer = document.createElement("div");
    childrenContainer.className = "tree-children" + (isCollapsed ? " collapsed" : "");
    node.children.forEach((c) => {
      childrenContainer.appendChild(createTreeNodeElement(c, depth + 1));
    });
    wrap.appendChild(childrenContainer);
  }

  return wrap;
}

// --------------------------------------------------------------------------
// Asset Detail Inspector
// --------------------------------------------------------------------------
async function loadAssetDetail(assetId) {
  try {
    const res = await fetch(`${API_BASE}/assets/${encodeURIComponent(assetId)}`);
    const a = await res.json();
    if (!a || !a.id) return;

    state.currentAssetData = a;

    const card = el("assetDetailCard");
    card.classList.remove("hidden");

    el("detailHostname").textContent = a.hostname || a.ip || a.id;
    el("detailTypeIcon").textContent = a.type === "ip" ? "🌐" : (a.depth === 0 ? "🎯" : "🌿");
    el("detailSubMeta").textContent = `Depth: ${a.depth} · Status: ${a.status || "active"} · IP: ${a.ip || "N/A"}`;

    el("tabCountPorts").textContent = (a.ports || []).length;
    el("tabCountUrls").textContent = (a.urls || []).length;
    el("tabCountParams").textContent = (a.parameters || []).length;
    el("tabCountTechs").textContent = (a.technologies || []).length;
    el("tabCountFindings").textContent = (a.findings || []).length;

    // Tab buttons listener and active state synchronization
    document.querySelectorAll(".detail-tab").forEach((btn) => {
      if (btn.dataset.detailTab === state.activeDetailTab) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
      btn.onclick = () => {
        document.querySelectorAll(".detail-tab").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        state.activeDetailTab = btn.dataset.detailTab;
        renderDetailTabContent(state.currentAssetData, state.activeDetailTab);
      };
    });

    renderDetailTabContent(a, state.activeDetailTab);

    el("closeDetailBtn").onclick = () => {
      card.classList.add("hidden");
      state.selectedAssetId = null;
      document.querySelectorAll(".tree-node-content").forEach((c) => c.classList.remove("selected"));
    };
  } catch (err) {
    console.error("Load detail error:", err);
  }
}

function renderDetailTabContent(asset, tabName) {
  const container = el("detailTabContent");
  container.innerHTML = "";
  if (!asset) return;

  if (tabName === "overview") {
    const portsSummary = (asset.ports || []).map((p) => `<span class="chip">🔌 ${p.port}/${p.protocol} (${esc(p.service || "unknown")})</span>`).join(" ");
    const techsSummary = (asset.technologies || []).map((t) => `<span class="chip">⚙️ ${esc(t.name)} ${t.version ? `v${esc(t.version)}` : ""}</span>`).join(" ");

    container.innerHTML = `
      <table class="mini-table">
        <tr><th>ID Aset</th><td><code>${esc(asset.id)}</code></td></tr>
        <tr><th>Tipe Aset</th><td><strong>${esc(asset.type.toUpperCase())}</strong></td></tr>
        <tr><th>Hostname / FQDN</th><td><strong>${esc(asset.hostname || asset.fqdn || "-")}</strong></td></tr>
        <tr><th>Alamat IP</th><td><code>${esc(asset.ip || "-")}</code></td></tr>
        <tr><th>Kedalaman Hierarki</th><td>Depth ${asset.depth} (${asset.depth === 0 ? "Root Target" : "Subdomain Level " + asset.depth})</td></tr>
        <tr><th>Status Keaktifan</th><td><span class="pill pill-running">🟢 Active & Resolvable</span></td></tr>
        <tr><th>Sumber Ditemukan</th><td><small>${esc((asset.discovered_from || ["Passive Discovery"]).join(", "))}</small></td></tr>
        <tr><th>Port Terbuka (${(asset.ports || []).length})</th><td>${portsSummary || "<small>Belum ada port terdeteksi</small>"}</td></tr>
        <tr><th>Teknologi (${(asset.technologies || []).length})</th><td>${techsSummary || "<small>Belum ada teknologi terfingerprint</small>"}</td></tr>
      </table>
    `;
  } else if (tabName === "ports") {
    if (!asset.ports || !asset.ports.length) {
      container.innerHTML = `<div class="empty-msg">Tidak ada port terbuka yang terdeteksi pada host ini.</div>`;
      return;
    }
    let html = `<div class="url-table-wrap"><table class="mini-table"><thead><tr><th>Port</th><th>Protokol</th><th>Service</th><th>Banner / Service Info</th><th>Aksi</th></tr></thead><tbody>`;
    asset.ports.forEach((p) => {
      const isWeb = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000].includes(p.port);
      const scheme = [443, 8443].includes(p.port) ? "https" : "http";
      const targetHost = asset.hostname || asset.ip;
      const testUrl = `${scheme}://${targetHost}:${p.port}/`;

      html += `<tr>
        <td><span class="node-badge badge-live"><strong>${p.port}</strong></span></td>
        <td><code>${esc(p.protocol.toUpperCase())}</code></td>
        <td><strong>${esc(p.service || "unknown")}</strong></td>
        <td><small>${p.banner ? `“${esc(p.banner)}”` : "<em>(Tidak ada banner)</em>"}</small></td>
        <td>${isWeb ? `<a href="${esc(testUrl)}" target="_blank" rel="noopener" class="btn btn-ghost btn-xs">🌐 Buka</a>` : "-"}</td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    container.innerHTML = html;
  } else if (tabName === "urls") {
    if (!asset.urls || !asset.urls.length) {
      container.innerHTML = `<div class="empty-msg">Belum ada URL/endpoint yang dicrawl pada host ini.</div>`;
      return;
    }
    let html = `<div class="url-table-wrap"><table class="mini-table"><thead><tr><th>Status</th><th>URL Endpoint</th><th>Content-Type</th><th>Title</th></tr></thead><tbody>`;
    asset.urls.forEach((u) => {
      const codeClass = u.status_code < 400 ? "badge-live" : "pill-stopped";
      html += `<tr>
        <td><span class="node-badge ${codeClass}">${u.status_code || "-"}</span></td>
        <td><a href="${esc(u.url)}" target="_blank" rel="noopener"><code>${esc(u.url)}</code></a></td>
        <td><small>${esc(u.content_type || "-")}</small></td>
        <td><small>${esc(u.title || "-")}</small></td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    container.innerHTML = html;
  } else if (tabName === "params") {
    if (!asset.parameters || !asset.parameters.length) {
      container.innerHTML = `<div class="empty-msg">Tidak ada parameter yang diekstrak pada host ini.</div>`;
      return;
    }
    let html = `<div class="url-table-wrap"><table class="mini-table"><thead><tr><th>Nama Parameter</th><th>Lokasi</th><th>Tipe</th><th>Confidence</th></tr></thead><tbody>`;
    asset.parameters.forEach((p) => {
      html += `<tr>
        <td><code><strong>${esc(p.name)}</strong></code></td>
        <td><span class="node-badge" style="background:#FEF3C7; color:#92400E;">${esc((p.location || "query").toUpperCase())}</span></td>
        <td><small>${esc(p.type || "string")}</small></td>
        <td><small>${Math.round((p.confidence || 0.9) * 100)}%</small></td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    container.innerHTML = html;
  } else if (tabName === "tech") {
    if (!asset.technologies || !asset.technologies.length) {
      container.innerHTML = `<div class="empty-msg">Belum ada teknologi yang terfingerprint pada host ini.</div>`;
      return;
    }
    let html = `<div class="url-table-wrap"><table class="mini-table"><thead><tr><th>Teknologi</th><th>Versi</th><th>Kategori</th><th>Bukti (Evidence)</th></tr></thead><tbody>`;
    asset.technologies.forEach((t) => {
      html += `<tr>
        <td>⚙️ <strong>${esc(t.name)}</strong></td>
        <td>${t.version ? `<code>v${esc(t.version)}</code>` : "<small>N/A</small>"}</td>
        <td><span class="node-badge" style="background:#E0E7FF; color:#3730A3;">${esc(t.category || "General")}</span></td>
        <td><small>${esc(t.evidence || "-")}</small></td>
      </tr>`;
    });
    html += `</tbody></table></div>`;
    container.innerHTML = html;
  } else if (tabName === "certs") {
    if (!asset.certificates || !asset.certificates.length) {
      container.innerHTML = `<div class="empty-msg">Tidak ada sertifikat TLS yang tercatat pada host ini.</div>`;
      return;
    }
    let html = `<table class="mini-table">`;
    asset.certificates.forEach((c) => {
      const sans = (c.san_dns || []).map((s) => `<span class="chip"><small>${esc(s)}</small></span>`).join(" ");
      html += `
        <tr><th>Subject CN</th><td><strong>${esc(c.subject_cn || "-")}</strong></td></tr>
        <tr><th>Issuer CN</th><td>${esc(c.issuer_cn || "-")}</td></tr>
        <tr><th>Masa Berlaku</th><td>${c.not_before ? new Date(c.not_before).toLocaleDateString("id-ID") : "-"} s/d <strong>${c.not_after ? new Date(c.not_after).toLocaleDateString("id-ID") : "-"}</strong></td></tr>
        <tr><th>Subject Alternative Names (SANs)</th><td><div class="chips-wrap">${sans || "<small>-</small>"}</div></td></tr>
        <tr><th>Fingerprint SHA-256</th><td><small><code>${esc(c.fingerprint_sha256 || "-")}</code></small></td></tr>
      `;
    });
    html += `</table>`;
    container.innerHTML = html;
  } else if (tabName === "findings") {
    if (!asset.findings || !asset.findings.length) {
      container.innerHTML = `<div class="empty-msg">🛡️ Aman — tidak ada temuan kerentanan pada aset ini.</div>`;
      return;
    }
    let html = `<div class="findings-list">`;
    asset.findings.forEach((f) => {
      const sevClass = (f.severity || "INFO").toLowerCase();
      html += `
        <div class="finding-item-card">
          <div class="finding-top-row">
            <div style="display:flex; align-items:center; gap:8px;">
              <span class="finding-badge sev-${sevClass}">${esc(f.severity)}</span>
              <strong>${esc(f.title)}</strong>
            </div>
            <select class="custom-select" style="width:auto; padding:3px 8px; font-size:11px;" onchange="updateFindingStatus('${f.id}', this.value)">
              <option value="OPEN" ${f.status === "OPEN" ? "selected" : ""}>OPEN</option>
              <option value="CONFIRMED" ${f.status === "CONFIRMED" ? "selected" : ""}>CONFIRMED</option>
              <option value="FALSE_POSITIVE" ${f.status === "FALSE_POSITIVE" ? "selected" : ""}>FALSE POSITIVE</option>
              <option value="FIXED" ${f.status === "FIXED" ? "selected" : ""}>FIXED</option>
            </select>
          </div>
          <p class="finding-desc">${esc(f.description || "")}</p>
          ${f.evidence && Object.keys(f.evidence).length ? `<div style="margin-top:6px;"><pre style="background:#191410; color:#FEEBC8; padding:6px; border-radius:6px; font-size:11px; overflow-x:auto;">${esc(JSON.stringify(f.evidence, null, 2))}</pre></div>` : ""}
        </div>
      `;
    });
    html += `</div>`;
    container.innerHTML = html;
  }
}

async function updateFindingStatus(findingId, newStatus) {
  try {
    await fetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}?status=${encodeURIComponent(newStatus)}`, {
      method: "PATCH",
    });
    if (state.selectedAssetId) {
      loadAssetDetail(state.selectedAssetId);
    }
    loadFindings();
  } catch (e) {
    alert("Gagal memperbarui status temuan: " + e.message);
  }
}

}

// --------------------------------------------------------------------------
// Findings & Triaging
// --------------------------------------------------------------------------
async function loadFindings() {
  if (!state.activeScanId) return;
  try {
    const res = await fetch(`${API_BASE}/findings?scan_id=${encodeURIComponent(state.activeScanId)}`);
    const findings = await res.json();
    renderFindings(findings);
  } catch (err) {
    console.error("Load findings error:", err);
  }
}

function renderFindings(findings) {
  const container = el("findingsListContainer");
  container.innerHTML = "";

  if (!findings || !findings.length) {
    container.innerHTML = `<div class="findings-empty-msg"><p>Belum ada temuan kerentanan / miskonfigurasi keamanan.</p></div>`;
    return;
  }

  findings.forEach((f) => {
    const sev = (f.severity || "INFO").toUpperCase();
    const item = document.createElement("div");
    item.className = "finding-item-card";

    const evJson = f.evidence && Object.keys(f.evidence).length ? JSON.stringify(f.evidence) : "";

    item.innerHTML = `
      <div class="finding-top-row">
        <div class="finding-title-group">
          <span class="finding-badge sev-${sev.toLowerCase()}">${esc(sev)}</span>
          <span>${esc(f.title)}</span>
        </div>
        <select class="triage-select" data-id="${f.id}">
          <option value="OPEN" ${f.status === "OPEN" ? "selected" : ""}>OPEN</option>
          <option value="CONFIRMED" ${f.status === "CONFIRMED" ? "selected" : ""}>CONFIRMED</option>
          <option value="FALSE_POSITIVE" ${f.status === "FALSE_POSITIVE" ? "selected" : ""}>FALSE POSITIVE</option>
          <option value="FIXED" ${f.status === "FIXED" ? "selected" : ""}>FIXED</option>
        </select>
      </div>
      <p class="finding-desc">${esc(f.description || "Tidak ada deskripsi rinci.")}</p>
      ${evJson ? `<div class="finding-evidence-box">Evidence: ${esc(evJson)}</div>` : ""}
      <div class="finding-footer">
        <span class="pill-muted">Confidence: ${(Number(f.confidence || 0) * 100).toFixed(0)}%</span>
        <span class="pill-muted">First Seen: ${f.first_seen ? new Date(f.first_seen).toLocaleTimeString("id-ID") : "-"}</span>
      </div>
    `;

    // Triage change listener
    item.querySelector(".triage-select").addEventListener("change", async (e) => {
      const newStatus = e.target.value;
      try {
        await fetch(`${API_BASE}/findings/${encodeURIComponent(f.id)}?status=${encodeURIComponent(newStatus)}`, {
          method: "PATCH",
        });
      } catch (err) {
        alert("Gagal update status finding: " + err.message);
      }
    });

    container.appendChild(item);
  });
}

// --------------------------------------------------------------------------
// Scan History
// --------------------------------------------------------------------------
async function loadHistory() {
  const container = el("historyListContainer");
  container.innerHTML = `<div class="empty-msg">Memuat riwayat scan...</div>`;

  try {
    const [scansRes, domainsRes] = await Promise.all([
      fetch(`${API_BASE}/scans`),
      fetch(`${API_BASE}/domains`),
    ]);

    const scans = await scansRes.json();
    const domains = await domainsRes.json();

    container.innerHTML = "";
    if (!scans || !scans.length) {
      container.innerHTML = `<div class="empty-msg">Belum ada riwayat scan yang tersimpan.</div>`;
      return;
    }

    domains.forEach((d) => {
      const domainScans = scans.filter((s) => s.root_domain === d.root_domain);
      const block = document.createElement("div");
      block.className = "history-domain-block";

      let rowsHtml = "";
      domainScans.forEach((s) => {
        const p = s.progress || {};
        rowsHtml += `
          <div class="history-scan-row" data-id="${s.id}" data-domain="${s.root_domain}">
            <div>
              <strong>#${esc(s.id.slice(0, 18))}</strong>
              <span class="pill pill-${s.status === 'completed' ? 'completed' : 'neutral'}">${esc(s.status)}</span>
              <span class="pill-muted">Profile: ${esc(s.profile)}</span>
            </div>
            <div class="pill-muted">
              Assets: ${p.assets || 0} · Ports: ${p.ports || 0} · URLs: ${p.urls || 0} · Findings: ${p.findings || 0} · ${s.created_at ? new Date(s.created_at).toLocaleString("id-ID") : "-"}
            </div>
          </div>
        `;
      });

      block.innerHTML = `
        <div class="history-domain-header">
          <span>🌐 <strong>${esc(d.root_domain)}</strong></span>
          <span class="badge-pill">${d.scan_count} Scan(s)</span>
        </div>
        ${rowsHtml}
      `;

      block.querySelectorAll(".history-scan-row").forEach((row) => {
        row.addEventListener("click", () => {
          openHistoricalScan(row.dataset.id, row.dataset.domain);
        });
      });

      container.appendChild(block);
    });
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat riwayat: ${err.message}</div>`;
  }
}

async function openHistoricalScan(scanId, domain) {
  state.activeScanId = scanId;
  state.activeTarget = domain;

  el("targetInput").value = domain;
  el("scanIdDisplay").textContent = `ID: ${scanId}`;
  el("scanIdDisplay").classList.remove("hidden");

  updateScanStatusUI("COMPLETED");

  // Switch to Dashboard
  document.querySelector('.nav-link[data-tab="dashboard"]').click();

  el("eventStreamContainer").innerHTML = `
    <div class="event-empty-msg">
      <span class="empty-icon">📁</span>
      <p>Scan riwayat dibuka: <strong>${esc(scanId)}</strong>. Lihat Asset Tree & Findings.</p>
    </div>
  `;

  await refreshAssetTree();
  await loadFindings();
}

// --------------------------------------------------------------------------
// Differential Scan (Diff)
// --------------------------------------------------------------------------
async function populateDiffSelects() {
  try {
    const res = await fetch(`${API_BASE}/scans`);
    const scans = await res.json();

    const curSelect = el("diffCurrentScanSelect");
    const prevSelect = el("diffPreviousScanSelect");

    curSelect.innerHTML = "";
    prevSelect.innerHTML = "";

    scans.forEach((s, idx) => {
      const opt1 = document.createElement("option");
      opt1.value = s.id;
      opt1.textContent = `${s.root_domain} (${s.id.slice(0, 16)}) - ${s.created_at ? new Date(s.created_at).toLocaleDateString("id-ID") : ""}`;
      curSelect.appendChild(opt1);

      const opt2 = document.createElement("option");
      opt2.value = s.id;
      opt2.textContent = `${s.root_domain} (${s.id.slice(0, 16)}) - ${s.created_at ? new Date(s.created_at).toLocaleDateString("id-ID") : ""}`;
      if (idx === 1) opt2.selected = true;
      prevSelect.appendChild(opt2);
    });
  } catch (e) {
    // silent
  }
}

async function runDiffAnalysis() {
  const current = el("diffCurrentScanSelect").value;
  const previous = el("diffPreviousScanSelect").value;

  if (!current || !previous) {
    alert("Pilih 2 scan untuk dibandingkan.");
    return;
  }
  if (current === previous) {
    alert("Pilih 2 scan yang berbeda untuk analisis diferensial.");
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/diff?current=${encodeURIComponent(current)}&previous=${encodeURIComponent(previous)}`);
    const diff = await res.json();

    const container = el("diffResultsContainer");
    container.classList.remove("hidden");

    container.innerHTML = `
      <div class="diff-grid">
        <div class="diff-column">
          <h4 style="color: var(--primary);">➕ Subdomain Baru Ditemukan (${diff.new_subdomains.length})</h4>
          <ul class="url-list">
            ${diff.new_subdomains.length ? diff.new_subdomains.map((s) => `<li><code>${esc(s)}</code></li>`).join("") : "<li><small>Tidak ada subdomain baru.</small></li>"}
          </ul>
        </div>
        <div class="diff-column">
          <h4 style="color: #EF4444;">➖ Subdomain Hilang / Tidak Aktif (${diff.removed_subdomains.length})</h4>
          <ul class="url-list">
            ${diff.removed_subdomains.length ? diff.removed_subdomains.map((s) => `<li><code>${esc(s)}</code></li>`).join("") : "<li><small>Tidak ada subdomain yang hilang.</small></li>"}
          </ul>
        </div>
        <div class="diff-column">
          <h4 style="color: var(--accent-marigold);">🔌 Port Terbuka Baru (${diff.new_ports.length})</h4>
          <ul class="url-list">
            ${diff.new_ports.length ? diff.new_ports.map((p) => `<li><code>${esc(p)}</code></li>`).join("") : "<li><small>Tidak ada port baru.</small></li>"}
          </ul>
        </div>
        <div class="diff-column">
          <h4 style="color: #DC2626;">🛡️ Temuan Keamanan Baru (${diff.new_findings.length})</h4>
          <ul class="url-list">
            ${diff.new_findings.length ? diff.new_findings.map((f) => `<li><strong>${esc(f)}</strong></li>`).join("") : "<li><small>Tidak ada temuan baru.</small></li>"}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    alert("Gagal menjalankan Diff: " + err.message);
  }
}

// --------------------------------------------------------------------------
// Initialization
// --------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();

  el("startBtn").addEventListener("click", startScan);
  el("targetInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      startScan();
    }
  });
  el("pauseBtn").addEventListener("click", pauseScan);

  el("resumeBtn").addEventListener("click", resumeScan);
  el("stopBtn").addEventListener("click", stopScan);
  el("exportBtn").addEventListener("click", exportScanJSON);
  el("quickExportBtn").addEventListener("click", exportScanJSON);

  el("refreshTreeBtn").addEventListener("click", refreshAssetTree);
  if (el("collapseAllBtn")) el("collapseAllBtn").addEventListener("click", collapseAllNodes);
  if (el("expandAllBtn")) el("expandAllBtn").addEventListener("click", expandAllNodes);
  el("treeSearchInput").addEventListener("input", () => renderAssetTree(state.assetsTreeData));

  el("refreshHistoryBtn").addEventListener("click", loadHistory);
  el("runDiffBtn").addEventListener("click", runDiffAnalysis);

  el("clearStreamBtn").addEventListener("click", () => {
    state.events = [];
    el("eventStreamContainer").innerHTML = `<div class="event-empty-msg"><p>Stream dibersihkan.</p></div>`;
    el("streamCount").textContent = "0 events";
  });

  document.querySelectorAll(".filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filterStreamEvents(pill.dataset.filter);
    });
  });
});