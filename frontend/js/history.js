/**
 * history.js — Target Workspace, Historical Intelligence & Differential Scanning (§35, §36)
 * Attack Surface & Parameter Intelligence Platform
 */

let allHistoricalScans = [];
let allHistoricalDomains = [];
let currentHistoryFilter = "ALL";
let currentHistorySort = "LATEST";

function formatPortItem(p) {
  if (!p) return "-";
  if (typeof p === "object") {
    const host = p.hostname ? `${p.hostname}:` : "";
    const svc = p.service ? ` (${p.service})` : "";
    return `${host}${p.port || p.port_number || '-'}/${p.protocol || 'tcp'}${svc}`;
  }
  return String(p);
}

function formatFindingItem(f) {
  if (!f) return "-";
  if (typeof f === "object") {
    const sev = (f.severity || "INFO").toUpperCase();
    const cwe = f.cwe_id ? ` [${f.cwe_id}]` : "";
    return `[${sev}] ${f.title || f.id || 'Vulnerability'}${cwe}`;
  }
  return String(f);
}

let isHistoryFetching = false;
let historyPollInterval = null;

async function loadHistory(showLoading = true) {
  const container = el("historyListContainer");
  if (!container || isHistoryFetching) return;

  if (showLoading && (!allHistoricalScans || allHistoricalScans.length === 0)) {
    container.innerHTML = `<div class="empty-msg">Memuat workspace dan intelligence target...</div>`;
  }

  isHistoryFetching = true;
  try {
    const [scansRes, domainsRes] = await Promise.all([
      authFetch(`${API_BASE}/scans`),
      authFetch(`${API_BASE}/domains`),
    ]);

    const scansData = await scansRes.json();
    const domainsData = await domainsRes.json();
    allHistoricalScans = Array.isArray(scansData) ? scansData : (Array.isArray(scansData?.scans) ? scansData.scans : []);
    allHistoricalDomains = Array.isArray(domainsData) ? domainsData : (Array.isArray(domainsData?.domains) ? domainsData.domains : []);

    updateHistoryTelemetry(allHistoricalScans, allHistoricalDomains);
    renderFilteredHistory();
  } catch (err) {
    if (showLoading && (!allHistoricalScans || allHistoricalScans.length === 0)) {
      container.innerHTML = `<div class="empty-msg">Gagal memuat riwayat: ${err.message}</div>`;
    }
  } finally {
    isHistoryFetching = false;
  }
}

// Background real-time sync for Scan History when active
function startHistoryLiveSync() {
  if (historyPollInterval) clearInterval(historyPollInterval);
  historyPollInterval = setInterval(() => {
    if (typeof document !== "undefined" && document.hidden) return;
    const viewHistory = el("viewHistory");
    const isHistoryActive = viewHistory && !viewHistory.classList.contains("hidden");
    if (!isHistoryActive) return;

    const hasRunning = (allHistoricalScans || []).some(s => {
      const st = (s.status || "").toUpperCase();
      return st === "RUNNING" || st === "QUEUED" || st === "STARTING";
    }) || state.scanStatus === "RUNNING";

    if (hasRunning) {
      loadHistory(false);
    }
  }, 4000);
}
startHistoryLiveSync();

function updateHistoryTelemetry(scans, domains) {
  const domainSet = new Set();
  let totalSubdomains = 0;
  let totalFindings = 0;

  scans.forEach(s => {
    if (s.root_domain) domainSet.add(s.root_domain);
    const p = s.progress || {};
    totalSubdomains += (p.assets || 0);
    totalFindings += (s.severity_counts?.CRITICAL || 0) + (s.severity_counts?.HIGH || 0);
  });

  domains.forEach(d => {
    if (d.root_domain) domainSet.add(d.root_domain);
  });

  if (el("histTotalDomains")) el("histTotalDomains").textContent = domainSet.size;
  if (el("histTotalScans")) el("histTotalScans").textContent = scans.length;
  if (el("histTotalSubdomains")) el("histTotalSubdomains").textContent = totalSubdomains;
  if (el("histTotalFindings")) el("histTotalFindings").textContent = totalFindings;
}

function renderFilteredHistory() {
  const container = el("historyListContainer");
  if (!container) return;

  const query = (el("historySearchInput")?.value || "").trim().toLowerCase();
  const filter = currentHistoryFilter || "ALL";
  const sort = currentHistorySort || "LATEST";

  if (!allHistoricalScans.length) {
    container.innerHTML = `
      <div class="event-empty-msg">
        <span class="empty-icon">📜</span>
        <p>Belum ada riwayat target yang dipindai. Silakan jalankan reconnaissance pertama Anda di menu Dashboard.</p>
      </div>
    `;
    return;
  }

  // 1. Group scans by root_domain first to build domain intelligence
  const domainMap = new Map();
  (allHistoricalDomains || []).forEach(d => {
    if (d.root_domain) domainMap.set(d.root_domain, []);
  });
  allHistoricalScans.forEach(s => {
    const rd = s.root_domain || "unknown";
    if (!domainMap.has(rd)) domainMap.set(rd, []);
    domainMap.get(rd).push(s);
  });

  // 2. Build structured domain objects
  let targetDomains = [];
  domainMap.forEach((scans, rootDomain) => {
    if (!scans || !scans.length) return;

    // Sort scans inside domain by created_at desc
    scans.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));

    const totalFindings = scans.reduce((acc, s) => acc + (s.progress?.findings || 0), 0);
    const maxAssets = scans.reduce((max, s) => Math.max(max, s.progress?.assets || 0), 0);
    const maxPorts = scans.reduce((max, s) => Math.max(max, s.progress?.ports || 0), 0);
    const maxUrls = scans.reduce((max, s) => Math.max(max, s.progress?.urls || 0), 0);
    const hasRunning = scans.some(s => (s.status || "").toUpperCase() === "RUNNING");
    const latestScan = scans[0];

    // Severity derives from stored findings, never from asset or finding counts.
    const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    const riskLevel = severityOrder.find(level => scans.some(s => (s.severity_counts?.[level] || 0) > 0)) || "NOT_RECORDED";
    const riskScore = riskLevel === "NOT_RECORDED" ? 0 : severityOrder.length - severityOrder.indexOf(riskLevel);

    targetDomains.push({
      rootDomain,
      scans,
      totalFindings,
      maxAssets,
      maxPorts,
      maxUrls,
      hasRunning,
      riskLevel,
      riskScore,
      latestScanDate: latestScan.created_at ? new Date(latestScan.created_at) : new Date(0),
    });
  });

  // 3. Apply Filter
  targetDomains = targetDomains.filter(td => {
    // Search query
    const matchQuery = !query ||
      td.rootDomain.toLowerCase().includes(query) ||
      td.scans.some(s => s.id.toLowerCase().includes(query) || (s.profile && s.profile.toLowerCase().includes(query)));

    if (!matchQuery) return false;

    if (filter === "ALL") return true;
    if (filter === "HIGH_RISK") return td.riskScore >= 3 || td.totalFindings > 0;
    if (filter === "COMPLETED") return td.scans.some(s => (s.status || "").toUpperCase() === "COMPLETED");
    if (filter === "RUNNING") return td.hasRunning;
    if (filter === "HAS_FINDINGS") return td.totalFindings > 0;
    return true;
  });

  // 4. Apply Sort
  targetDomains.sort((a, b) => {
    if (sort === "LATEST") return b.latestScanDate - a.latestScanDate;
    if (sort === "HIGHEST_RISK") return b.riskScore - a.riskScore || b.totalFindings - a.totalFindings;
    if (sort === "MOST_ASSETS") return b.maxAssets - a.maxAssets;
    if (sort === "MOST_FINDINGS") return b.totalFindings - a.totalFindings;
    if (sort === "ALPHABETICAL") return a.rootDomain.localeCompare(b.rootDomain);
    return 0;
  });

  if (!targetDomains.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada target domain yang cocok dengan filter atau kata kunci pencarian Anda.</div>`;
    return;
  }

  // 5. Render Target Workspaces with Clean TUI Session Tables
  container.innerHTML = "";
  targetDomains.forEach(td => {
    const block = document.createElement("div");
    block.className = "target-workspace-card";
    const safeDomain = td.rootDomain.replace(/[^a-zA-Z0-9_-]/g, "_");

    // Risk badge class
    const riskBadgeClass = td.riskLevel === 'CRITICAL' ? 'risk-badge-critical' : (td.riskLevel === 'HIGH' ? 'risk-badge-high' : (td.riskLevel === 'MEDIUM' ? 'risk-badge-medium' : 'risk-badge-clean'));
    const latestDateStr = td.latestScanDate.getTime() > 0 ? td.latestScanDate.toLocaleString("id-ID", { dateStyle: "medium", timeStyle: "short" }) : "-";

    // Build Clean TUI Table Rows
    let tableRowsHtml = "";
    td.scans.forEach((s, idx) => {
      const p = s.progress || {};
      const st = (s.status || "completed").toUpperCase();
      const isLatest = idx === 0;
      const hasPriorScan = idx < td.scans.length - 1;
      const priorScanId = hasPriorScan ? td.scans[idx + 1].id : null;

      let statusBadgeHtml = "";
      if (st === "COMPLETED") {
        statusBadgeHtml = `<span class="pill pill-completed font-mono">🟢 COMPLETED</span>`;
      } else if (st === "RUNNING") {
        statusBadgeHtml = `<span class="pill pill-running pulse font-mono">⚡ RUNNING</span>`;
      } else if (st === "PAUSED") {
        statusBadgeHtml = `<span class="pill pill-paused font-mono">⏸ PAUSED</span>`;
      } else {
        statusBadgeHtml = `<span class="pill pill-danger font-mono">⚠️ ${esc(st)}</span>`;
      }

      const scanDate = s.created_at ? new Date(s.created_at).toLocaleString("id-ID", { dateStyle: "short", timeStyle: "short" }) : "-";
      const shortScanId = s.id && s.id.length > 20 ? (s.id.slice(0, 18) + '…') : s.id;
      const scanTarget = (s.options && (s.options.target_url || s.options.target_host)) || s.target_url || s.target_host || s.root_domain || td.rootDomain;

      tableRowsHtml += `
        <tr class="tui-session-row ${isLatest ? 'is-latest-session' : ''}" data-id="${esc(s.id)}" data-domain="${esc(scanTarget)}">
          <td>
            <div class="session-cell-id">
              <span class="session-id-link font-mono" title="${esc(s.id)}" onclick="openScanFromHistory(${jsArg(s.id)})">#${esc(shortScanId)}</span>
              ${isLatest ? '<span class="pill-latest-badge font-mono">LATEST</span>' : ''}
            </div>
          </td>
          <td>${statusBadgeHtml}</td>
          <td>
            <span class="session-cell-url font-mono" title="${esc(scanTarget)}">${esc(scanTarget)}</span>
          </td>
          <td><span class="font-mono text-bright"><strong>${p.assets || 0}</strong></span></td>
          <td><span class="font-mono text-bright"><strong>${p.ports || 0}</strong></span></td>
          <td>
            <span class="font-mono ${p.findings > 0 ? 'text-danger font-bold' : 'text-muted'}">
              ${p.findings > 0 ? `🛡️ ${p.findings}` : '0'}
            </span>
          </td>
          <td><span class="font-mono text-muted text-xs">${scanDate}</span></td>
          <td style="text-align: right;">
            <div class="session-action-group">
              <button class="btn btn-primary btn-xs btn-open-dash font-mono" title="Buka di Dashboard">🎯 Dashboard</button>
              <button class="btn btn-secondary btn-xs btn-open-report font-mono" title="Buka Laporan">📑 Laporan</button>
              ${priorScanId ? `<button class="btn btn-secondary btn-xs btn-quick-diff font-mono" data-scan-a="${esc(s.id)}" data-scan-b="${esc(priorScanId)}" title="Bandingkan dengan scan sebelumnya">⚖️ Diff</button>` : ''}
              <button class="btn btn-secondary btn-xs btn-export-json font-mono" title="Unduh JSON">💾</button>
              <button class="btn btn-ghost btn-xs btn-delete-scan text-danger font-mono" title="Hapus Scan">🗑️</button>
            </div>
          </td>
        </tr>
      `;
    });

    block.innerHTML = `
      <!-- 1. Domain Header Block -->
      <div class="target-card-header">
        <div class="target-identity-wrap" onclick="openDomainDetail(${jsArg(td.rootDomain)})">
          <div class="target-avatar">🌐</div>
          <div class="target-title-block">
            <div class="target-title-row">
              <h3 class="target-domain-name font-mono">${esc(td.rootDomain)}</h3>
              <span class="target-health-pill status-active">ACTIVE</span>
              <span class="target-risk-badge ${riskBadgeClass}">${esc(td.riskLevel)}</span>
              <span class="target-scope-pill font-mono">IN-SCOPE</span>
            </div>
            <div class="target-sub-meta">
              <span>🎯 <strong>${td.scans.length}</strong> Sesi Scan</span> · 
              <span>Terakhir Dipindai: <strong>${latestDateStr}</strong></span>
            </div>
          </div>
        </div>

        <div class="target-header-actions">
          <button class="btn btn-primary btn-sm btn-rescan-target font-mono" title="Mulai Scan Baru pada Domain ini">🚀 Scan Baru</button>
          <button class="btn btn-secondary btn-sm font-mono" onclick="openDomainDetail(${jsArg(td.rootDomain)})">🌐 360° Intel ↗</button>
          ${td.scans.length > 1 ? `<button class="btn btn-secondary btn-sm btn-toggle-diff font-mono" data-domain="${esc(td.rootDomain)}">⚖️ Diff Compare</button>` : ''}
          <button class="btn btn-secondary btn-sm btn-open-domain-report font-mono" data-domain="${esc(td.rootDomain)}">📑 Laporan</button>
        </div>
      </div>

      <!-- 2. Surface Summary Strip -->
      <div class="target-surface-strip">
        <div class="surface-stat-item">
          <span class="dot-chip dot-green"></span>
          <span class="surface-lbl font-mono">Subdomains</span>
          <strong class="surface-val font-mono">${td.maxAssets}</strong>
        </div>
        <div class="surface-stat-item">
          <span class="dot-chip dot-cyan"></span>
          <span class="surface-lbl font-mono">Open Ports</span>
          <strong class="surface-val font-mono">${td.maxPorts}</strong>
        </div>
        <div class="surface-stat-item">
          <span class="dot-chip dot-purple"></span>
          <span class="surface-lbl font-mono">Endpoints</span>
          <strong class="surface-val font-mono">${td.maxUrls}</strong>
        </div>
        <div class="surface-stat-item ${td.totalFindings > 0 ? 'surface-danger' : ''}">
          <span class="dot-chip dot-red"></span>
          <span class="surface-lbl font-mono">Findings</span>
          <strong class="surface-val font-mono ${td.totalFindings > 0 ? 'text-danger' : ''}">${td.totalFindings}</strong>
        </div>
      </div>

      <!-- 3. Inline Diff Drawer -->
      <div class="target-inline-diff-drawer hidden" id="diffDrawer_${safeDomain}">
        <div class="inline-diff-header">
          <h4>⚖️ Perbandingan Diferensial (Diff) Sesi Scan — ${esc(td.rootDomain)}</h4>
          <button class="btn btn-ghost btn-xs btn-close-inline-diff" data-target="diffDrawer_${safeDomain}">✕ Tutup Diff</button>
        </div>
        <div class="inline-diff-content" id="diffContent_${safeDomain}">
          <div class="table-loading">Memuat perbandingan scan...</div>
        </div>
      </div>

      <!-- 4. Clean TUI Session History Table (Matching Image 2 Reference) -->
      <div class="target-scan-tree-wrapper">
        <div class="tui-table-wrap">
          <table class="tui-sessions-table">
            <thead>
              <tr>
                <th>SESI / SCAN ID</th>
                <th>STATUS</th>
                <th>TARGET URL</th>
                <th>SUBS</th>
                <th>PORTS</th>
                <th>FINDINGS</th>
                <th>WAKTU</th>
                <th style="text-align: right;">AKSI CEPAT</th>
              </tr>
            </thead>
            <tbody>
              ${tableRowsHtml}
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Bind Domain-level event handlers
    block.querySelector(".btn-rescan-target")?.addEventListener("click", (e) => {
      e.stopPropagation();
      triggerRescan(td.rootDomain, "deep");
    });

    block.querySelector(".btn-open-domain-report")?.addEventListener("click", (e) => {
      e.stopPropagation();
      const latestScanId = td.scans[0]?.id;
      state.activeScanId = latestScanId;
      state.activeTarget = td.rootDomain;
      switchViewTab("reports");
      if (typeof loadReportHubData === "function") {
        const sel = el("reportScanSelect");
        if (sel) sel.value = latestScanId;
        loadReportHubData(latestScanId);
      }
    });

    block.querySelector(".btn-toggle-diff")?.addEventListener("click", async (e) => {
      e.stopPropagation();
      const drawer = el(`diffDrawer_${safeDomain}`);
      if (!drawer) return;
      if (!drawer.classList.contains("hidden")) {
        drawer.classList.add("hidden");
        return;
      }
      drawer.classList.remove("hidden");
      if (td.scans.length >= 2) {
        await renderInlineDiff(td.rootDomain, td.scans[0].id, td.scans[1].id, `diffContent_${safeDomain}`);
      }
    });

    block.querySelector(".btn-close-inline-diff")?.addEventListener("click", (e) => {
      const targetId = e.target.dataset.target;
      if (el(targetId)) el(targetId).classList.add("hidden");
    });

    // Bind Session-level event handlers
    block.querySelectorAll(".scan-session-row, .tui-session-row").forEach(row => {
      const sid = row.dataset.id;
      const dom = row.dataset.domain;

      row.querySelector(".btn-rescan-session")?.addEventListener("click", (e) => {
        e.stopPropagation();
        const target = e.currentTarget.dataset.target || dom;
        const profile = e.currentTarget.dataset.profile || "deep";
        triggerRescan(target, profile);
      });

      row.querySelector(".btn-open-dash")?.addEventListener("click", (e) => {
        e.stopPropagation();
        openHistoricalScan(sid, dom);
      });

      row.querySelector(".btn-open-report")?.addEventListener("click", (e) => {
        e.stopPropagation();
        state.activeScanId = sid;
        state.activeTarget = dom;
        switchViewTab("reports", { scan_id: sid });
      });

      row.querySelector(".btn-quick-diff")?.addEventListener("click", async (e) => {
        e.stopPropagation();
        const scanA = e.currentTarget.dataset.scanA;
        const scanB = e.currentTarget.dataset.scanB;
        const drawer = el(`diffDrawer_${safeDomain}`);
        if (drawer) {
          drawer.classList.remove("hidden");
          drawer.scrollIntoView({ behavior: "smooth", block: "nearest" });
          await renderInlineDiff(td.rootDomain, scanA, scanB, `diffContent_${safeDomain}`);
        }
      });

      row.querySelector(".btn-export-json")?.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(sid)}/export`);
          const data = await res.json();
          const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `evidence_package_${sid}.json`;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          if (typeof showToast === "function") showToast("Evidence Package JSON berhasil diunduh.", "success");
        } catch (err) {
          if (typeof showToast === "function") showToast("Gagal mengunduh evidence: " + err.message, "danger");
        }
      });

      row.querySelector(".btn-delete-scan")?.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteHistoricalScan(sid, dom);
      });

      row.addEventListener("click", () => {
        openHistoricalScan(sid, dom);
      });
    });

    container.appendChild(block);
  });
}

async function renderInlineDiff(domain, scanCurrent, scanPrevious, containerId) {
  const container = el(containerId);
  if (!container) return;
  container.innerHTML = `<div class="table-loading">Membandingkan scan #${scanCurrent.slice(0, 16)} vs #${scanPrevious.slice(0, 16)}...</div>`;

  try {
    const res = await authFetch(`${API_BASE}/scans/diff?current_scan_id=${encodeURIComponent(scanCurrent)}&previous_scan_id=${encodeURIComponent(scanPrevious)}`);
    const diff = await res.json();

    const newSubs = diff.new_subdomains || [];
    const remSubs = diff.removed_subdomains || [];
    const newPorts = diff.new_ports || [];
    const newFindings = diff.new_findings || [];
    const resolvedFindings = diff.resolved_findings || diff.fixed_findings || [];

    container.innerHTML = `
      <div class="diff-summary-banner">
        <span>Bandingkan: <strong>#${esc(scanCurrent.slice(0, 16))}</strong> (Baru) vs <strong>#${esc(scanPrevious.slice(0, 16))}</strong> (Pembanding)</span>
        <button class="btn btn-secondary btn-xs" onclick="switchViewTab('diff'); if (el('diffCurrentScanSelect')) el('diffCurrentScanSelect').value = ${jsArg(scanCurrent)}; if (el('diffPreviousScanSelect')) el('diffPreviousScanSelect').value = ${jsArg(scanPrevious)};">Buka di Diff Analyzer Penuh ↗</button>
      </div>

      <div class="diff-columns-grid">
        <div class="diff-col-card">
          <div class="diff-col-header text-success">
            <span>➕ Subdomain Baru Ditemukan (${newSubs.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newSubs.map(s => `<li><span class="diff-pill-add">+ ${esc(s)}</span></li>`).join("") || '<li class="diff-empty">Tidak ada perubahan</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-danger">
            <span>➖ Subdomain Tidak Ditemukan (${remSubs.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${remSubs.map(s => `<li><span class="diff-pill-rem">- ${esc(s)}</span></li>`).join("") || '<li class="diff-empty">Tidak ada perubahan</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-warning">
            <span>📡 Port Baru Terbuka (${newPorts.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newPorts.map(p => `<li><code class="diff-code-port">+ ${esc(formatPortItem(p))}</code></li>`).join("") || '<li class="diff-empty">Tidak ada port baru</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-danger">
            <span>🛡️ Temuan Baru / Resolved (${newFindings.length} / ${resolvedFindings.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newFindings.map(f => `<li><span class="finding-badge sev-high">NEW: ${esc(formatFindingItem(f))}</span></li>`).join("")}
            ${resolvedFindings.map(f => `<li><span class="finding-badge sev-low">RESOLVED: ${esc(formatFindingItem(f))}</span></li>`).join("")}
            ${(!newFindings.length && !resolvedFindings.length) ? '<li class="diff-empty">Tidak ada temuan baru</li>' : ''}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="diff-empty">Gagal memuat diff: ${err.message}</div>`;
  }
}

function setupHistoryEvents() {
  const searchInput = el("historySearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderFilteredHistory();
    });
  }

  document.querySelectorAll(".hist-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".hist-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      currentHistoryFilter = pill.dataset.histFilter;
      renderFilteredHistory();
    });
  });

  const sortSelect = el("historySortSelect");
  if (sortSelect) {
    sortSelect.addEventListener("change", (e) => {
      currentHistorySort = e.target.value;
      renderFilteredHistory();
    });
  }
}

async function deleteHistoricalScan(scanId, domain) {
  const proceed = async () => {
    try {
      const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
      if (res.ok) {
        if (state.activeScanId === scanId) {
          if (state.es) { state.es.close(); state.es = null; }
          state.activeScanId = null;
          if (typeof stopTimer === "function") stopTimer();
          if (typeof resetCleanDashboard === "function") {
            resetCleanDashboard();
          }
        }
        if (typeof showToast === "function") showToast(`Sesi scan #${scanId.slice(0, 16)} berhasil dihapus.`, "success");
        if (typeof syncActiveScansBar === "function") syncActiveScansBar();
        await loadHistory();
        if (!allHistoricalScans || allHistoricalScans.length === 0) {
          if (typeof resetCleanDashboard === "function") {
            resetCleanDashboard();
          }
        }
      } else {
        const err = await res.json();
        if (typeof showToast === "function") showToast("Gagal menghapus scan: " + (err.detail || res.statusText), "danger");
      }
    } catch (err) {
      if (typeof showToast === "function") showToast("Gagal menghapus scan: " + err.message, "danger");
    }
  };

  if (typeof showSystemConfirm === "function") {
    showSystemConfirm(
      "Hapus Sesi Pemindaian",
      `Apakah Anda yakin ingin menghapus riwayat scan #${scanId} (${domain || 'Target'})? Seluruh graf aset, port, parameter, dan temuan yang terhubung akan dibersihkan secara permanen.`,
      proceed,
      "🗑️"
    );
  } else {
    if (confirm(`Hapus scan #${scanId}?`)) proceed();
  }
}

function triggerRescan(target, profile) {
  if (!target) return;
  state.activeScanId = null;
  state.events = [];
  state.activeTarget = target;
  state.currentTarget = target;
  
  if (el("targetInput")) el("targetInput").value = target;
  if (profile && el("profileSelect")) el("profileSelect").value = profile;
  
  switchViewTab("dashboard", { newScanTarget: target, profile: profile || "deep", skipAutoLoad: true });
  
  if (typeof startScan === "function") {
    startScan();
  }
}

async function openHistoricalScan(scanId, domain) {
  const isSameScan = state.activeScanId === scanId;
  state.activeScanId = scanId;
  if (domain) {
    state.activeTarget = domain;
    state.currentTarget = domain;
    if (el("targetInput")) el("targetInput").value = domain;
    if (el("dashReportTarget")) el("dashReportTarget").textContent = domain;
  }

  if (el("scanIdDisplay")) {
    el("scanIdDisplay").textContent = `ID: ${scanId}`;
    el("scanIdDisplay").classList.remove("hidden");
  }

  // Switch tab view to Dashboard
  switchViewTab("dashboard", { scan_id: scanId, target: domain, noReload: true, skipAutoLoad: true });

  if (typeof updateBreadcrumbUI === "function") {
    updateBreadcrumbUI("dashboard", { scan_id: scanId, target: domain });
  }

  // If different scan or no cached events, display smooth loader
  if (!isSameScan || !state.events || state.events.length === 0) {
    if (el("eventStreamContainer")) {
      el("eventStreamContainer").innerHTML = `
        <div class="event-empty-msg">
          <span class="empty-icon">⏳</span>
          <p>Memuat data dan timeline scan <strong>${esc(scanId)}</strong>...</p>
        </div>
      `;
    }
  }

  try {
    // 1. Fetch scan status and event history concurrently for maximum speed
    const [scanRes, eventsRes] = await Promise.all([
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`),
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/events/history?limit=300`)
    ]);

    const scanData = await scanRes.json();
    const eventsData = await eventsRes.json();

    const scanObj = scanData.scan || scanData;
    const exactTarget = (scanObj.options && (scanObj.options.target_url || scanObj.options.target_host)) 
      || scanObj.target_url || scanObj.target_host || scanObj.root_domain || domain || "";
    if (exactTarget) {
      state.activeTarget = exactTarget;
      state.currentTarget = exactTarget;
      if (el("targetInput")) el("targetInput").value = exactTarget;
      if (el("dashReportTarget")) el("dashReportTarget").textContent = exactTarget;
    }
    if (typeof updateBreadcrumbUI === "function") {
      updateBreadcrumbUI("dashboard", { scan_id: scanId, target: exactTarget });
    }

    const scanStatus = (scanObj.status || "completed").toUpperCase();

    if (scanObj.profile && el("profileSelect")) {
      el("profileSelect").value = scanObj.profile;
    }

    // 2. Render events
    state.events = Array.isArray(eventsData) ? eventsData : (eventsData?.events || []);
    if (typeof renderStreamEvents === "function") renderStreamEvents();

    // 3. Update telemetry counters from progress
    const prog = scanObj.progress || scanData.progress || scanData.statistics || {};
    state.counters.assets = prog.assets ?? prog.total_assets ?? 0;
    state.counters.ports = prog.ports ?? prog.total_ports ?? 0;
    state.counters.urls = prog.urls ?? prog.total_urls ?? 0;
    state.counters.params = prog.parameters ?? prog.total_parameters ?? 0;
    state.counters.techs = prog.technologies ?? prog.total_technologies ?? 0;
    state.counters.findings = prog.findings ?? prog.total_findings ?? 0;
    if (typeof updateScanStatusUI === "function") updateScanStatusUI(scanStatus);
    if (typeof updateCounterDisplays === "function") updateCounterDisplays();

    // 4. If RUNNING or QUEUED, connect to live SSE stream & start timer with accurate elapsed time
    if (scanStatus === "RUNNING" || scanStatus === "QUEUED") {
      let initialSecs = 0;
      const timeStr = scanObj.started_at || scanObj.created_at;
      if (timeStr) {
        const normalizedTimeStr = (timeStr.endsWith("Z") || timeStr.includes("+")) ? timeStr : timeStr + "Z";
        const start = new Date(normalizedTimeStr).getTime();
        if (!isNaN(start)) {
          initialSecs = Math.max(0, Math.round((Date.now() - start) / 1000));
        }
      }

      // If timer is already running accurately for this same scan, keep it running smoothly
      if (!isSameScan || !state.timerInterval || Math.abs(state.timerSeconds - initialSecs) > 3) {
        if (typeof startTimer === "function") startTimer(initialSecs);
      }

      if (!state.es || !isSameScan) {
        if (typeof connectEventSource === "function") connectEventSource(scanId);
      }

      clearInterval(state.treePollInterval);
      if (typeof refreshAssetTree === "function") {
        state.treePollInterval = setInterval(refreshAssetTree, 4000);
      }
      clearInterval(state.statusPollInterval);
      if (typeof syncScanStatus === "function") {
        state.statusPollInterval = setInterval(syncScanStatus, 3000);
      }
    } else {
      if (typeof stopTimer === "function") stopTimer();
      if (state.es) { state.es.close(); state.es = null; }
      clearInterval(state.treePollInterval);
      clearInterval(state.statusPollInterval);
      const timeStr = scanObj.started_at || scanObj.created_at;
      if (timeStr && el("scanTime")) {
        const normalizedStart = (timeStr.endsWith("Z") || timeStr.includes("+")) ? timeStr : timeStr + "Z";
        const start = new Date(normalizedStart).getTime();
        const endStr = scanObj.completed_at;
        const end = endStr ? new Date((endStr.endsWith("Z") || endStr.includes("+")) ? endStr : endStr + "Z").getTime() : NaN;
        const elapsed = Math.max(0, Math.round((end - start) / 1000));
        el("scanTime").classList.remove("hidden");
        el("scanTime").textContent = Number.isFinite(elapsed) ? `⏱ ${formatTime(elapsed)}` : "⏱ Durasi tidak tercatat";
      }
    }

    // 5. Refresh essential dashboard components immediately
    if (typeof refreshAssetTree === "function") refreshAssetTree();
    if (typeof loadFindings === "function") loadFindings();

    // 6. Stagger secondary modules (Report, AI Hypotheses, State Machine) for smooth 60fps UI
    setTimeout(() => {
      if (state.activeScanId === scanId) {
        if (typeof loadReportHubData === "function") loadReportHubData(scanId, false);
        if (typeof loadV4HypothesesAndPlans === "function" && v4State.activeViewMode === "hypotheses") loadV4HypothesesAndPlans();
        if (typeof loadV4StateMachineData === "function" && v4State.activeViewMode === "statemachine") loadV4StateMachineData();
      }
    }, 120);
  } catch (err) {
    console.debug("Failed to load historical scan:", err);
  }
}

// --------------------------------------------------------------------------
// Differential Scanning Analyzer View (§35)
// --------------------------------------------------------------------------
async function populateDiffSelects() {
  const curSelect = el("diffCurrentScanSelect");
  const prevSelect = el("diffPreviousScanSelect");
  if (!curSelect || !prevSelect) return;

  try {
    const res = await authFetch(`${API_BASE}/scans`);
    const scans = await res.json();

    curSelect.innerHTML = "";
    prevSelect.innerHTML = "";

    if (!scans || !scans.length) {
      curSelect.innerHTML = `<option value="">Belum ada scan</option>`;
      prevSelect.innerHTML = `<option value="">Belum ada scan</option>`;
      return;
    }

    scans.forEach((s, idx) => {
      const opt1 = document.createElement("option");
      opt1.value = s.id;
      opt1.textContent = `${s.root_domain} — #${s.id.slice(0, 16)} (${s.status.toUpperCase()}) [${new Date(s.created_at).toLocaleDateString()}]`;
      curSelect.appendChild(opt1);

      const opt2 = document.createElement("option");
      opt2.value = s.id;
      opt2.textContent = `${s.root_domain} — #${s.id.slice(0, 16)} (${s.status.toUpperCase()}) [${new Date(s.created_at).toLocaleDateString()}]`;
      prevSelect.appendChild(opt2);
    });

    if (scans.length >= 2) {
      prevSelect.selectedIndex = 1;
    }
  } catch (err) {
    console.error("Failed to populate diff selects:", err);
  }
}

async function runDiffAnalysis() {
  const currentId = el("diffCurrentScanSelect")?.value;
  const previousId = el("diffPreviousScanSelect")?.value;
  const container = el("diffResultsContainer");

  if (!currentId || !previousId) {
    if (typeof showToast === "function") showToast("Silakan pilih 2 scan yang akan dibandingkan.", "warning");
    return;
  }

  if (currentId === previousId) {
    if (typeof showToast === "function") showToast("Pilih 2 scan yang berbeda untuk analisis diferensial.", "warning");
    return;
  }

  if (container) {
    container.classList.remove("hidden");
    container.innerHTML = `<div class="tab-loading">Menganalisis perbedaan antara #${currentId} dan #${previousId}...</div>`;
  }

  try {
    const res = await authFetch(`${API_BASE}/scans/diff?current_scan_id=${encodeURIComponent(currentId)}&previous_scan_id=${encodeURIComponent(previousId)}`);
    const diff = await res.json();

    if (!container) return;

    const newSubs = diff.new_subdomains || [];
    const remSubs = diff.removed_subdomains || [];
    const newPorts = diff.new_ports || [];
    const newFindings = diff.new_findings || [];
    const resolvedFindings = diff.resolved_findings || diff.fixed_findings || [];

    container.innerHTML = `
      <div class="diff-summary-card">
        <div class="diff-stat-badge">
          <span class="diff-num text-success">+${newSubs.length}</span>
          <span class="diff-lbl">Subdomain Baru</span>
        </div>
        <div class="diff-stat-badge">
          <span class="diff-num text-danger">-${remSubs.length}</span>
          <span class="diff-lbl">Subdomain Hilang</span>
        </div>
        <div class="diff-stat-badge">
          <span class="diff-num text-warning">+${newPorts.length}</span>
          <span class="diff-lbl">Port Baru</span>
        </div>
        <div class="diff-stat-badge">
          <span class="diff-num text-danger">+${newFindings.length}</span>
          <span class="diff-lbl">Temuan Baru</span>
        </div>
      </div>

      <div class="diff-columns-grid">
        <div class="diff-col-card">
          <div class="diff-col-header text-success">
            <span>🌳 Subdomain Baru Ditemukan (${newSubs.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newSubs.map(s => `<li><span class="diff-pill-add">+ ${esc(s)}</span></li>`).join("") || '<li class="diff-empty">Tidak ada perubahan</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-danger">
            <span>🗑️ Subdomain Tidak Ditemukan Lagi (${remSubs.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${remSubs.map(s => `<li><span class="diff-pill-rem">- ${esc(s)}</span></li>`).join("") || '<li class="diff-empty">Tidak ada perubahan</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-warning">
            <span>📡 Port Baru Terbuka (${newPorts.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newPorts.map(p => `<li><code class="diff-code-port">+ ${esc(formatPortItem(p))}</code></li>`).join("") || '<li class="diff-empty">Tidak ada port baru</li>'}
          </ul>
        </div>

        <div class="diff-col-card">
          <div class="diff-col-header text-danger">
            <span>🛡️ Temuan Keamanan Baru / Resolved (${newFindings.length} / ${resolvedFindings.length})</span>
          </div>
          <ul class="diff-tag-list">
            ${newFindings.map(f => `<li><span class="finding-badge sev-high">NEW: ${esc(formatFindingItem(f))}</span></li>`).join("")}
            ${resolvedFindings.map(f => `<li><span class="finding-badge sev-low">RESOLVED: ${esc(formatFindingItem(f))}</span></li>`).join("")}
            ${(!newFindings.length && !resolvedFindings.length) ? '<li class="diff-empty">Tidak ada temuan baru</li>' : ''}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="tab-empty">Gagal membandingkan scan: ${err.message}</div>`;
  }
}

// --------------------------------------------------------------------------
// Domain & Finding Detail Page Deep Dives (§36, §37, §38)
// --------------------------------------------------------------------------
async function openDomainDetail(domainName, updateUrl = true) {
  if (updateUrl) {
    switchViewTab('domainDetail', { name: domainName });
  }
  if (el('domainBreadcrumbName')) el('domainBreadcrumbName').textContent = domainName;
  if (el('domainDetailTitle')) el('domainDetailTitle').textContent = `🌐 ${domainName}`;

  try {
    const res = await authFetch(`${API_BASE}/domains/${encodeURIComponent(domainName)}/detail`);
    const d = await res.json();

    const subCount = d.total_subdomains != null ? d.total_subdomains : (d.subdomains || []).length;
    const ipCount = d.total_ips != null ? d.total_ips : (d.ips || []).length;
    const portCount = d.total_ports != null ? d.total_ports : (d.open_ports != null ? d.open_ports : 0);
    const urlCount = d.total_urls != null ? d.total_urls : (d.url_count != null ? d.url_count : 0);
    const findCount = d.total_findings != null ? d.total_findings : (d.findings || []).length;
    const scanCount = d.total_scans != null ? d.total_scans : (d.scan_count != null ? d.scan_count : 0);

    if (el('domainSubdomainCount')) el('domainSubdomainCount').textContent = subCount;
    if (el('domainIPCount')) el('domainIPCount').textContent = ipCount;
    if (el('domainPortCount')) {
      el('domainPortCount').textContent = portCount;
      if (d.unique_ports) {
        el('domainPortCount').title = `${portCount} total open service endpoints across ${d.unique_ports} unique port numbers`;
      }
    }
    if (el('domainURLCount')) el('domainURLCount').textContent = urlCount;
    if (el('domainFindingCount')) el('domainFindingCount').textContent = findCount;
    if (el('domainScanCount')) el('domainScanCount').textContent = scanCount;

    // Subdomains with Realtime Search & Copy All
    const subdomainsList = d.subdomains || [];
    if (el('domainSubdomainCountHeader')) el('domainSubdomainCountHeader').textContent = subdomainsList.length;

    const renderSubdomains = (filterQuery = "") => {
      const subList = el('domainSubdomainList');
      if (!subList) return;
      const q = filterQuery.toLowerCase().trim();
      const filtered = q ? subdomainsList.filter(s => s.toLowerCase().includes(q)) : subdomainsList;
      if (!filtered.length) {
        subList.innerHTML = '<span class="empty-msg font-mono" style="padding:10px;">Tidak ada subdomain yang cocok</span>';
        return;
      }
      subList.innerHTML = filtered.map(s =>
        `<span class="tag-item font-mono" onclick="openDomainDetail(${jsArg(s)})" title="Buka detail ${esc(s)}">${esc(s)}</span>`
      ).join('');
    };

    renderSubdomains();

    const searchInput = el('domainSubSearchInput');
    if (searchInput) {
      searchInput.value = "";
      searchInput.oninput = (e) => renderSubdomains(e.target.value);
    }

    const copyBtn = el('copyAllSubdomainsBtn');
    if (copyBtn) {
      copyBtn.onclick = () => {
        if (!subdomainsList.length) return;
        navigator.clipboard?.writeText(subdomainsList.join('\n'));
        copyBtn.textContent = "✅ Tersalin!";
        setTimeout(() => { copyBtn.textContent = "📋 Salin Semua"; }, 1800);
      };
    }

    // IPs
    const ipList = el('domainIPList');
    if (ipList) {
      ipList.innerHTML = (d.ips || []).map(ip =>
        `<span class="tag-item">${esc(ip)}</span>`
      ).join('') || '<span class="empty-msg">No IPs resolved</span>';
    }

    // Technologies
    const techList = el('domainTechList');
    if (techList) {
      techList.innerHTML = (d.technologies || []).map(t => {
        const name = typeof t === 'object' && t ? (t.name || t.product || 'Unknown') : String(t);
        const ver = typeof t === 'object' && t && t.version ? ` v${t.version}` : '';
        return `<span class="tag-item"><strong>${esc(name)}</strong>${esc(ver)}</span>`;
      }).join('') || '<span class="empty-msg">No technologies detected</span>';
    }

    // Findings
    const findList = el('domainFindingsList');
    if (findList) {
      findList.innerHTML = (d.findings || []).map(f => `
        <div class="finding-card" onclick="openFindingDetail(${jsArg(f.id)})">
          <span class="severity-badge severity-${(f.severity||'info').toLowerCase()}">${esc(f.severity||'INFO')}</span>
          <span class="finding-card-title">${esc(f.title || f.id)}</span>
          <span class="status-badge status-${(f.status||'open').toLowerCase()}">${esc(f.status||'OPEN')}</span>
        </div>
      `).join('') || '<span class="empty-msg">No findings for this domain</span>';
    }

    // Risk badge
    const severity = (d.findings || []).some(f => (f.severity||'').toLowerCase() === 'critical') ? 'critical'
      : (d.findings || []).some(f => (f.severity||'').toLowerCase() === 'high') ? 'high'
      : (d.findings || []).length > 0 ? 'medium' : 'low';
    if (el('domainRiskBadge')) {
      el('domainRiskBadge').className = `risk-badge risk-${severity}`;
      el('domainRiskBadge').textContent = severity.toUpperCase();
    }
  } catch(e) {
    console.warn('Failed to load domain detail:', e);
  }
}

async function openAssetDetail(assetId, updateUrl = true) {
  if (updateUrl) {
    switchViewTab('assetDetail', { id: assetId });
  }
  if (el('assetBreadcrumbName')) el('assetBreadcrumbName').textContent = assetId;

  try {
    const res = await authFetch(`${API_BASE}/assets/${encodeURIComponent(assetId)}`);
    const a = await res.json();

    if (el('assetDetailTitle')) el('assetDetailTitle').textContent = `🖥️ ${a.hostname || assetId}`;
    if (el('assetBreadcrumbName')) el('assetBreadcrumbName').textContent = a.hostname || assetId;
    if (el('assetBreadcrumbDomain')) {
      el('assetBreadcrumbDomain').textContent = a.root_domain || '';
      el('assetBreadcrumbDomain').onclick = () => openDomainDetail(a.root_domain);
    }

    if (el('assetTypeBadge')) el('assetTypeBadge').textContent = a.asset_type || 'SUBDOMAIN';

    if (el('assetPortCount')) el('assetPortCount').textContent = (a.ports || []).length;
    if (el('assetURLCount')) el('assetURLCount').textContent = (a.urls || []).length;
    if (el('assetParamCount')) el('assetParamCount').textContent = a.param_count || 0;
    if (el('assetTechCount')) el('assetTechCount').textContent = (a.technologies || []).length;
    if (el('assetFindingCount')) el('assetFindingCount').textContent = (a.findings || []).length;

    // Ports
    const pList = el('assetPortsList');
    if (pList) {
      if ((a.ports || []).length === 0) {
        pList.innerHTML = '<span class="empty-msg">No open ports recorded</span>';
      } else {
        pList.innerHTML = `<table class="tui-ports-table"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Banner</th></tr></thead><tbody>${
          a.ports.map(p => `<tr><td><strong>${p.port_number || p.port}</strong></td><td>${esc(p.protocol||'tcp')}</td><td>${esc(p.service_name||p.service||'-')}</td><td class="mono">${esc(p.banner||'-')}</td></tr>`).join('')
        }</tbody></table>`;
      }
    }

    // Technologies
    const tList = el('assetTechList');
    if (tList) {
      tList.innerHTML = (a.technologies || []).map(t => `<span class="tag-item"><strong>${esc(t.name || t)}</strong> (${esc(t.category||'General')})</span>`).join('') || '<span class="empty-msg">No technologies</span>';
    }

    // URLs
    const uList = el('assetURLList');
    if (uList) {
      uList.innerHTML = (a.urls || []).slice(0, 50).map(u => `<div class="url-item mono"><span class="badge status-${u.status_code || 200}">${u.status_code || 200}</span> <a href="${esc(safeLink(u.url))}" target="_blank">${esc(u.url)}</a></div>`).join('') || '<span class="empty-msg">No URLs</span>';
    }

    // Findings
    const fList = el('assetFindingsList');
    if (fList) {
      fList.innerHTML = (a.findings || []).map(f => `
        <div class="finding-card" onclick="openFindingDetail(${jsArg(f.id)})">
          <span class="severity-badge severity-${(f.severity||'info').toLowerCase()}">${esc(f.severity||'INFO')}</span>
          <span class="finding-card-title">${esc(f.title || f.id)}</span>
          <span class="status-badge status-${(f.status||'open').toLowerCase()}">${esc(f.status||'OPEN')}</span>
        </div>
      `).join('') || '<span class="empty-msg">No findings</span>';
    }
  } catch(e) {
    console.warn('Failed to load asset detail:', e);
  }
}

let findingDetailRequest = 0;
async function openFindingDetail(findingId, updateUrl = true) {
  const requestId = ++findingDetailRequest;
  if (updateUrl) {
    switchViewTab('findingDetail', { id: findingId });
  }
  if (el('findingBreadcrumbName')) el('findingBreadcrumbName').textContent = findingId;

  try {
    const res = await authFetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/detail`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const f = await res.json();
    if (requestId !== findingDetailRequest) return;

    if (el('findingDetailTitle')) el('findingDetailTitle').textContent = `🔒 ${esc(f.title || findingId)}`;
    if (el('findingBreadcrumbName')) el('findingBreadcrumbName').textContent = f.title || findingId;

    if (el('findingSeverityBadge')) {
      el('findingSeverityBadge').className = `severity-badge severity-${(f.severity||'info').toLowerCase()}`;
      el('findingSeverityBadge').textContent = f.severity || 'INFO';
    }
    if (el('findingStatusBadge')) {
      el('findingStatusBadge').className = `status-badge status-${(f.status||'open').toLowerCase()}`;
      el('findingStatusBadge').textContent = f.status || 'OPEN';
    }

    // Evidence Level & Score (V5 §2, §26)
    const eLevel = f.evidence_level || "E0";
    if (el('findingEvidenceLevelBadge')) {
      el('findingEvidenceLevelBadge').className = `badge-${eLevel.toLowerCase()}`;
      el('findingEvidenceLevelBadge').textContent = `${eLevel} — ${eLevel === 'E3' ? 'IMPACT PROOF' : (eLevel === 'E2' ? 'REPRODUCIBLE' : 'INDICATOR')}`;
    }
    if (el('findingConfidenceBadge')) {
      el('findingConfidenceBadge').textContent = `CONFIDENCE: ${formatConfidence(f.confidence)}`;
    }
    if (el('findingScoreBadge')) {
      el('findingScoreBadge').textContent = `EVIDENCE SCORE: ${f.evidence_score ?? 0}/100`;
    }

    // Meta items
    if (el('findingCode')) el('findingCode').textContent = f.finding_code || f.code || f.id || '-';
    if (el('findingCWE')) el('findingCWE').textContent = f.cwe_id || f.cwe || '-';
    if (el('findingCVE')) el('findingCVE').textContent = f.cve_id || f.cve || '-';
    if (el('findingCVSS')) el('findingCVSS').textContent = f.cvss_score ? String(f.cvss_score) : '-';
    if (el('findingAsset')) el('findingAsset').textContent = (f.asset && f.asset.hostname) || f.asset_hostname || '-';
    if (el('findingLocation')) el('findingLocation').textContent = (f.evidence && f.evidence.url) || f.location || '/';

    // Impact Matrix (V5 §29)
    const mat = f.impact_matrix || {};
    if (el('imConfidentiality')) {
      const c = (mat.confidentiality || 'NOT_RECORDED').toUpperCase();
      el('imConfidentiality').textContent = c;
      el('imConfidentiality').className = `im-val ${c.toLowerCase()}`;
    }
    if (el('imIntegrity')) {
      const i = (mat.integrity || 'NOT_RECORDED').toUpperCase();
      el('imIntegrity').textContent = i;
      el('imIntegrity').className = `im-val ${i.toLowerCase()}`;
    }
    if (el('imAvailability')) {
      const a = (mat.availability || 'NOT_RECORDED').toUpperCase();
      el('imAvailability').textContent = a;
      el('imAvailability').className = `im-val ${a.toLowerCase()}`;
    }
    if (el('imAuthBypass')) {
      el('imAuthBypass').textContent = mat.auth_bypass || 'NOT_RECORDED';
    }
    if (el('imDataExposure')) {
      const de = (mat.data_exposure || 'NOT_RECORDED').toUpperCase();
      el('imDataExposure').textContent = de;
      el('imDataExposure').className = `im-val ${de.toLowerCase()}`;
    }

    // Local AI Intelligence & MITRE ATT&CK Integration (V4 & V5)
    const evData = f.evidence || {};
    const aiConf = evData.ai_confidence_score ?? null;
    const aiDec = evData.ai_triage_decision || 'NOT_RECORDED';
    const fpRisk = evData.false_positive_probability ?? null;

    if (el('aiConfidenceChip')) {
      el('aiConfidenceChip').textContent = `🤖 AI CONFIDENCE: ${aiConf == null ? "Belum dinilai" : aiConf + "%"}`;
      el('aiConfidenceChip').className = aiConf >= 80 ? 'pill pill-success' : 'pill pill-warn';
    }
    if (el('aiTriageDecision')) {
      el('aiTriageDecision').textContent = aiDec;
      el('aiTriageDecision').style.color = aiDec === 'CONFIRMED' ? '#10b981' : (aiDec === 'FALSE_POSITIVE' ? '#ef4444' : '#38bdf8');
    }
    if (el('aiFpRisk')) {
      el('aiFpRisk').textContent = fpRisk == null ? "Belum diukur" : `${(fpRisk * 100).toFixed(1)}% (estimasi model)`;
    }
    if (el('aiProofMode')) {
      el('aiProofMode').textContent = f.report_quality?.status || 'NEEDS_REVIEW';
    }

    // MITRE ATT&CK Matrix Chips
    if (el('aiMitreContainer')) {
      const mitreList = evData.mitre_attack || [];
      el('aiMitreContainer').innerHTML = mitreList.map(m => `
        <a href="${esc(safeLink(m.mitre_url || 'https://attack.mitre.org/'))}" target="_blank" class="tag-item" style="text-decoration:none; display:inline-flex; align-items:center; gap:6px; background:#0f172a; border:1px solid #334155; padding:4px 10px; border-radius:6px; font-size:11px; color:#38bdf8;">
          <span style="font-weight:700; color:#34d399;">${esc(m.technique_id)}</span>
          <span style="color:#f8fafc;">${esc(m.technique_name || m.name || 'Technique')}</span>
          <span style="font-size:10px; color:#94a3b8; background:#1e293b; padding:1px 5px; border-radius:3px;">${esc(m.tactic || 'ATT&CK')}</span>
          <span>↗</span>
        </a>
      `).join('') || '<span class="empty-msg">No MITRE ATT&CK mappings</span>';
    }

    // Plain English & Root Cause
    if (el('findingExecutiveDesc')) {
      el('findingExecutiveDesc').textContent = f.executive_explanation || f.description || "Deskripsi belum dicatat.";
    }
    if (el('findingRootCause')) {
      el('findingRootCause').textContent = f.root_cause || f.technical_details || "Akar masalah belum dibuktikan.";
    }

    if (el('findingTechDetails')) el('findingTechDetails').textContent = f.technical_details || f.description || 'Tidak ada analisis teknis tambahan.';
    if (el('findingRemediation')) el('findingRemediation').textContent = f.remediation || 'Terapkan validasi input terikat, escaping kontekstual, dan pembaruan berkala.';

    window._currentFindingId = findingId;

    // The detail page uses the same evidence contract as the report hub.
    if (el('findingEvidence')) {
      const d = f.poc_dossier || {};
      const quality = f.report_quality || {status:"NEEDS_REVIEW", missing:[]};
      el('findingEvidence').innerHTML = `<p><strong>${esc(quality.status)}</strong> - Belum lengkap: ${esc(quality.missing.join(', ') || 'Tetap perlu tinjauan manusia')}</p>
        <p>Template replay bukan bukti keberhasilan. Skor HTTP saja tidak membuktikan celah.</p>
        <h4>Request tersimpan</h4><pre class="code-box-mini">${esc(d.raw_http_request || 'Belum direkam')}</pre>
        <h4>Response tersimpan</h4><pre class="code-box-mini">${esc(d.raw_http_response || 'Belum direkam')}</pre>
        <h4>Langkah reproduksi / daftar pemeriksaan</h4><ol>${(d.reproduction_steps || []).map(step=>`<li>${esc(step)}</li>`).join('')}</ol>
        <h4>cURL replay</h4><pre class="code-box-mini">${esc(d.curl_command || 'Belum direkam')}</pre>
        <button class="btn btn-secondary" onclick="openFindingPocDossier(${jsArg(f.id)})">Buka dossier lengkap</button>`;
    }
    const lifecycleSelect = el('findingLifecycleSelect');
    const lifecycleButton = el('findingTransitionBtn');
    if (lifecycleSelect && lifecycleButton) {
      lifecycleSelect.innerHTML = (f.allowed_transitions || []).map(status=>`<option value="${esc(status)}">${esc(status)}</option>`).join('');
      lifecycleButton.disabled = !(f.allowed_transitions || []).length;
      lifecycleButton.onclick = async () => {
        lifecycleButton.disabled = true;
        try {
          const response = await authFetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/transition?next_state=${encodeURIComponent(lifecycleSelect.value)}`, {method:'POST'});
          if (!response.ok) throw new Error(apiError(await response.json(), `HTTP ${response.status}`));
          workspaceCache.clear();
          await openFindingDetail(findingId, false);
          showToast('Status temuan diperbarui.', 'success');
        } catch(error) { showToast(error.message, 'danger'); lifecycleButton.disabled = false; }
      };
    }

    // Discovered Artifacts & Schema Intelligence (V9.1)
    const artSection = el('findingArtifactsSection');
    const artList = el('findingArtifactsList');
    const artBadge = el('findingArtifactsCountBadge');
    if (artSection && artList) {
      artSection.classList.add('hidden');
      artList.innerHTML = '';
      try {
        const scanIdToQuery = f.scan_id || state.activeScanId;
        if (scanIdToQuery) {
          const artRes = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanIdToQuery)}/artifacts/all`);
          const allArts = await artRes.json();
          if (requestId !== findingDetailRequest) return;
          if (Array.isArray(allArts) && allArts.length > 0) {
            const targetHost = (f.asset && f.asset.hostname) || f.asset_hostname || '';
            const targetUrl = (f.evidence && f.evidence.url) || f.location || '';
            const matchedArts = allArts.filter(a => {
              if (f.finding_type && (f.finding_type.includes('sql') || f.finding_type.includes('dump')) && a.file_type === 'sql_dump') return true;
              if (f.finding_type && f.finding_type.includes('csv') && a.file_type === 'csv_export') return true;
              if (f.finding_type && f.finding_type.includes('env') && a.file_type === 'env_file') return true;
              if (targetHost && a.hostname && a.hostname.toLowerCase() === targetHost.toLowerCase()) return true;
              if (targetUrl && a.filename && targetUrl.includes(a.filename)) return true;
              return false;
            });

            const artsToDisplay = matchedArts.length ? matchedArts : allArts;
            if (artsToDisplay.length) {
              artSection.classList.remove('hidden');
              if (artBadge) artBadge.textContent = `${artsToDisplay.length} Discovered Artifacts`;

              artList.innerHTML = artsToDisplay.map(art => {
                const icon = art.file_type === 'sql_dump' ? '🗄️' : (art.file_type === 'csv_export' ? '📊' : (art.file_type === 'env_file' ? '⚙️' : '📄'));
                const sizeKB = (art.size_bytes / 1024).toFixed(1) + ' KB';
                const shortSha = art.sha256_hash ? art.sha256_hash.substring(0, 16) + '...' : '-';

                let schemaPreviewHtml = '';
                if (art.file_type === 'sql_dump' && art.total_tables > 0) {
                  schemaPreviewHtml = `
                    <div style="background:#020617; border:1px solid #1e293b; border-radius:6px; padding:12px; margin-top:10px; font-size:12px;">
                      <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;">
                        <span style="color:#e2e8f0;">📦 Database: <strong style="color:#38bdf8;">${esc(art.database_name || 'Extracted Database')}</strong></span>
                        <span style="color:#e2e8f0;">📋 Total Tabel: <strong style="color:#10b981; font-weight:700;">${art.total_tables}</strong></span>
                        <span style="color:#e2e8f0;">🔑 Kredensial / Hashes: <strong style="color:#f87171; font-weight:700;">${art.total_hashes || 0}</strong></span>
                      </div>
                    </div>
                  `;
                }

                return `
                  <div class="artifact-card-item" style="background:#090f1f; border:1px solid #1e293b; border-radius:8px; padding:14px; margin-bottom:12px;">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
                      <div>
                        <strong style="font-size:13px; color:#f8fafc;">${icon} ${esc(art.filename)}</strong>
                        <div style="font-size:11px; color:#94a3b8; margin-top:3px;">
                          <span class="pill pill-neutral" style="font-size:10px;">${esc(art.file_type.toUpperCase())}</span>
                          <span> · Host: <code>${esc(art.hostname || '-')}</code></span>
                          <span> · Ukuran: ${sizeKB}</span>
                          <span> · SHA-256: <code>${esc(shortSha)}</code></span>
                        </div>
                      </div>
                      <div style="display:flex; gap:6px; flex-wrap:wrap;">
                        <button class="btn btn-secondary btn-xs" onclick="openArtifactDetailModal(${jsArg(art.id)})">🔍 Inspect Intelligence</button>
                        <a href="${API_BASE}/artifacts/${encodeURIComponent(art.id)}/export-sanitized" target="_blank" class="btn btn-primary btn-xs">🛡️ Download Sanitized Export</a>
                        <a href="${API_BASE}/artifacts/${encodeURIComponent(art.id)}/download" target="_blank" class="btn btn-secondary btn-xs">📥 Download Raw Quarantined File</a>
                      </div>
                    </div>
                    ${schemaPreviewHtml}
                  </div>
                `;
              }).join('');
            }
          }
        }
      } catch (artErr) {
        console.warn('Failed to load artifacts for finding:', artErr);
      }
    }

    // Bind V5 Action Buttons
    const btnPkg = el('btnDownloadEvidencePackage');
    if (btnPkg) {
      btnPkg.onclick = async () => {
        try {
          const r = await authFetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/evidence-package`);
          const pkgData = await r.json();
          const blob = new Blob([JSON.stringify(pkgData, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `evidence_package_${f.finding_code || findingId}.json`;
          a.click();
          URL.revokeObjectURL(url);
          if (typeof showToast === "function") showToast("Evidence Package berhasil diunduh.", "success");
        } catch(err) {
          if (typeof showToast === "function") showToast("Gagal mengunduh evidence package: " + err.message, "danger");
        }
      };
    }

    const btnBB = el('btnDownloadBugBountyReport');
    if (btnBB) {
      btnBB.onclick = () => {
        window.open(`${API_BASE}/findings/${encodeURIComponent(findingId)}/bugbounty`, '_blank');
      };
    }

    const btnCVE = el('btnDownloadCveReport');
    if (btnCVE) {
      btnCVE.onclick = () => {
        window.open(`${API_BASE}/findings/${encodeURIComponent(findingId)}/cve-ready`, '_blank');
      };
    }

    const btnRepro = el('btnDownloadReproduction');
    if (btnRepro) {
      btnRepro.onclick = () => {
        window.open(`${API_BASE}/findings/${encodeURIComponent(findingId)}/reproduction`, '_blank');
      };
    }

    const btnRetest = el('btnExecuteLiveRetest');
    if (btnRetest) {
      btnRetest.onclick = () => {
        const doRetest = async () => {
          btnRetest.disabled = true;
          btnRetest.textContent = "⏳ Retesting...";
          try {
            const r = await authFetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/retest`, { method: "POST" });
            const resRetest = await r.json();
            if (!r.ok) throw new Error(apiError(resRetest, `HTTP ${r.status}`));
            if (resRetest.retest_result === "INCONCLUSIVE") {
              if (el('retestStatusBanner')) el('retestStatusBanner').classList.remove('hidden');
              if (el('retestStatusText')) el('retestStatusText').textContent = "INCONCLUSIVE: " + resRetest.verdict;
              showToast("Retest belum dapat menyimpulkan hasil. Status temuan tetap.", "warning");
              return;
            }
            if (el('retestStatusBanner')) {
              el('retestStatusBanner').classList.remove('hidden');
              const comp = resRetest.comparison_result || resRetest.comparison || resRetest;
              const verdict = comp.verdict || (comp.retest_result === "PASSED" ? "Vulnerability remediated." : "Still vulnerable.");
              const isPassed = comp.retest_result === "PASSED" || comp.after_status === "FIXED";
              
              const beforeSt = comp.before_status || "CONFIRMED";
              const afterSt = comp.after_status || (isPassed ? "FIXED" : "NOT_FIXED");
              const targetUrl = comp.target_url || "-";
              const vulnFamily = comp.vulnerability_family || "Targeted Vulnerability";

              el('retestStatusBanner').className = `retest-banner ${isPassed ? 'retest-passed' : 'retest-failed'}`;
              el('retestStatusText').innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                  <strong style="font-size:14px; color:${isPassed ? '#10B981' : '#EF4444'};">
                    ${isPassed ? '✅ REMEDIATION VERIFIED (PASSED)' : '❌ VULNERABILITY PERSISTS (FAILED)'}
                  </strong>
                  <span class="pill pill-neutral" style="font-size:11px;">Tested at: ${esc(new Date().toLocaleTimeString())}</span>
                </div>
                <div style="font-size:12px; margin-bottom:6px; color:#E2E8F0;">${esc(verdict)}</div>
                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:8px; margin-top:8px; font-size:11px; background:rgba(0,0,0,0.3); padding:8px; border-radius:6px;">
                  <div><span class="text-muted">Target Endpoint:</span> <code>${esc(targetUrl)}</code></div>
                  <div><span class="text-muted">Vulnerability:</span> <strong>${esc(vulnFamily)}</strong></div>
                  <div><span class="text-muted">Before Status:</span> <span class="pill pill-warn">${esc(beforeSt)}</span></div>
                  <div><span class="text-muted">After Status:</span> <span class="pill ${isPassed ? 'pill-success' : 'pill-danger'}">${esc(afterSt)}</span></div>
                </div>
              `;
            }
            if (el('findingStatusBadge')) {
              const finalSt = resRetest.after_status || (resRetest.retest_result === "PASSED" ? "FIXED" : "NOT_FIXED");
              el('findingStatusBadge').textContent = finalSt;
              el('findingStatusBadge').className = `status-badge status-${finalSt.toLowerCase()}`;
            }
            if (typeof showToast === "function") {
              const isPassed = resRetest.retest_result === "PASSED" || resRetest.after_status === "FIXED";
              showToast(isPassed ? "Retest selesai: Celah keamanan terverifikasi telah DIPERBAIKI (FIXED)!" : "Retest selesai: Celah keamanan MASIH TERBUKA (NOT FIXED)!", isPassed ? "success" : "warn");
            }
          } catch(err) {
            if (typeof showToast === "function") showToast("Retest gagal: " + err.message, "danger");
          } finally {
            btnRetest.disabled = false;
            btnRetest.textContent = "🔄 Live Retest";
          }
        };

        if (typeof showSystemConfirm === "function") {
          showSystemConfirm(
            "Jalankan Live Retest",
            "Eksekusi verifikasi ulang secara non-destruktif untuk membuktikan apakah celah keamanan telah diperbaiki?",
            doRetest,
            "🔄"
          );
        } else {
          doRetest();
        }
      };
    }

  } catch(e) {
    console.warn('Failed to load finding detail:', e);
  }
}

async function reTriageFindingWithAi(findingId) {
  const targetId = findingId || window._currentFindingId;
  if (!targetId) {
    if (typeof showToast === 'function') showToast('ID Finding tidak ditemukan.', 'warn');
    return;
  }

  const btn = el('reTriageAiBtn');
  const oldText = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '⏳ Menjalankan Live LLM Triage...';
  }

  try {
    const res = await authFetch(`${API_BASE}/findings/${encodeURIComponent(targetId)}/ai-triage`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();
    if (typeof showToast === 'function') {
      showToast('AI Deep Reasoning Triage berhasil diperbarui secara live!', 'success');
    }
    await openFindingDetail(targetId, false);
  } catch (err) {
    console.error('AI Triage error:', err);
    if (typeof showToast === 'function') {
      showToast('Gagal memproses AI Triage: ' + err.message, 'danger');
    }
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = oldText || '🤖 Re-Triage Live LLM';
    }
  }
}

window.reTriageFindingWithAi = reTriageFindingWithAi;

