/**
 * reports.js — Autonomous Investigation Workspace & Security Intelligence Hub
 * Comprehensive Workspace (§11-§27)
 */

let currentWorkspaceScanId = null;
let currentWorkspaceData = null;
let activeWorkspaceTab = "overview";
let exportPollInterval = null;

async function initReportHub(preferredScanId = null) {
  const selectEl = el("reportScanSelect");
  if (!selectEl) return;

  try {
    let scans = null;
    try {
      const res = await authFetch(`${API_BASE}/investigations`);
      if (res.ok) {
        scans = await res.json();
      }
    } catch (e) {
      console.warn("Failed /investigations, falling back to /scans:", e);
    }

    if (!scans || !Array.isArray(scans) || !scans.length) {
      try {
        const res2 = await authFetch(`${API_BASE}/scans`);
        if (res2.ok) {
          const raw = await res2.json();
          scans = Array.isArray(raw) ? raw : (raw && Array.isArray(raw.scans) ? raw.scans : []);
        }
      } catch (e2) {
        console.warn("Failed fallback /scans:", e2);
      }
    }

    selectEl.innerHTML = "";
    if (!scans || !scans.length) {
      selectEl.innerHTML = `<option value="">Belum ada investigasi tersimpan</option>`;
      renderWorkspaceEmpty();
      return;
    }

    scans.forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.id;
      const targetDomain = s.root_domain || s.target_host || s.target_url || s.target || "Target";
      const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString("id-ID") : "";
      const statusStr = (s.status || "COMPLETED").toUpperCase();
      opt.textContent = `${targetDomain} — #${s.id.slice(0, 16)} (${statusStr}) [${dateStr}]`;
      selectEl.appendChild(opt);
    });

    const targetScan = preferredScanId && scans.some(s => s.id === preferredScanId)
      ? preferredScanId
      : (state.activeScanId && scans.some(s => s.id === state.activeScanId)
        ? state.activeScanId
        : scans[0].id);

    selectEl.value = targetScan;
    currentWorkspaceScanId = targetScan;
    state.activeScanId = targetScan;
    await loadWorkspaceData(currentWorkspaceScanId);
  } catch (err) {
    console.error("Failed to load investigations for Workspace:", err);
    renderWorkspaceEmpty();
  }
}

const workspaceCache = new Map();
let workspaceRequest = 0;
let workspaceAbort = null;
const pendingExports = new Set();

async function loadReportHubData(scanId, updateUrl = false) {
  return loadWorkspaceData(scanId, updateUrl);
}

async function loadWorkspaceData(scanId, updateUrl = false) {
  if (!scanId) {
    renderWorkspaceEmpty();
    return;
  }
  const requestId = ++workspaceRequest;
  workspaceAbort?.abort();
  workspaceAbort = new AbortController();
  const requestSignal = workspaceAbort.signal;
  currentWorkspaceScanId = scanId;
  if (el("reportScanSelect")) el("reportScanSelect").value = scanId;
  const isReportsViewActive = el("viewReports") && !el("viewReports").classList.contains("hidden");
  if (updateUrl || isReportsViewActive) {
    updateRouteURL("reports", { scan_id: scanId });
    updateBreadcrumbUI("reports", { scan_id: scanId });
  }

  // Instant render from cache (0ms delay)
  if (workspaceCache.has(scanId)) {
    const cachedWs = workspaceCache.get(scanId);
    currentWorkspaceData = cachedWs;
    renderWorkspace(cachedWs);
  } else {
    renderWorkspaceEmpty();
    if (el("wsExecSummaryText")) {
      el("wsExecSummaryText").innerHTML = `<em>🔄 Memuat telemetri investigasi #${scanId.slice(0, 16)}...</em>`;
    }
  }

  if (typeof showTopLoader === "function") showTopLoader();

  try {
    let res = await authFetch(`${API_BASE}/investigations/${encodeURIComponent(scanId)}/workspace`, {signal: requestSignal});
    if (!res.ok) {
      res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/workspace`, {signal: requestSignal});
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: Failed to fetch workspace data`);
    }
    const ws = await res.json();
    if (requestId !== workspaceRequest || scanId !== currentWorkspaceScanId) return;
    currentWorkspaceData = ws;
    workspaceCache.delete(scanId);
    workspaceCache.set(scanId, ws);
    while (workspaceCache.size > 3) workspaceCache.delete(workspaceCache.keys().next().value);
    renderWorkspace(ws);
  } catch (err) {
    if (err.name === "AbortError" || requestId !== workspaceRequest) return;
    console.error("Failed to fetch investigation workspace data:", err);
    if (!workspaceCache.has(scanId)) {
      showToast("Gagal memuat Investigation Workspace: " + err.message, "danger");
      if (el("wsExecSummaryText")) {
        el("wsExecSummaryText").textContent = "Gagal memuat data investigasi. Silakan periksa koneksi atau pilih scan lain.";
      }
    }
  } finally {
    if (requestId === workspaceRequest && typeof hideTopLoader === "function") hideTopLoader();
  }
}

function renderWorkspaceEmpty() {
  if (typeof renderReportProfile === "function") renderReportProfile({}, null);
  currentWorkspaceData = null;
  [renderWorkspaceAssets, renderWorkspaceServices, renderWorkspaceEndpoints, renderWorkspaceFindings,
    renderWorkspaceEvidence, renderWorkspaceArtifacts, renderWorkspaceTimeline, renderWorkspaceExports].forEach(render => render([]));
  renderWorkspaceAttackChains([], {});
  if (el("wsTargetName")) el("wsTargetName").textContent = "Target: -";
  if (el("wsInvestigationId")) el("wsInvestigationId").textContent = "ID: -";
  if (el("wsStatusBadge")) {
    el("wsStatusBadge").textContent = "NO DATA";
    el("wsStatusBadge").className = "status-badge status-neutral";
  }
  if (el("wsDuration")) el("wsDuration").textContent = "00m 00s";
  if (el("wsCoverage")) el("wsCoverage").textContent = "Belum terukur";
  if (el("wsStartTime")) el("wsStartTime").textContent = "-";
  if (el("wsExecSummaryText")) el("wsExecSummaryText").textContent = "Pilih atau mulai investigasi untuk membuka Investigation Workspace.";
  
  if (el("wsStatAssets")) el("wsStatAssets").textContent = "0";
  if (el("wsStatServices")) el("wsStatServices").textContent = "0";
  if (el("wsStatEndpoints")) el("wsStatEndpoints").textContent = "0";
  if (el("wsStatTechs")) el("wsStatTechs").textContent = "0";
  if (el("wsStatFindings")) el("wsStatFindings").textContent = "0";
  if (el("wsStatArtifacts")) el("wsStatArtifacts").textContent = "0";

  if (el("wsSevCrit")) el("wsSevCrit").textContent = "0";
  if (el("wsSevHigh")) el("wsSevHigh").textContent = "0";
  if (el("wsSevMed")) el("wsSevMed").textContent = "0";
  if (el("wsSevLow")) el("wsSevLow").textContent = "0";
  if (el("wsSevInfo")) el("wsSevInfo").textContent = "0";

  if (el("wsConfConfirmed")) el("wsConfConfirmed").textContent = "0";
  if (el("wsConfLikely")) el("wsConfLikely").textContent = "0";
  if (el("wsConfPotential")) el("wsConfPotential").textContent = "0";
  if (el("wsConfInconclusive")) el("wsConfInconclusive").textContent = "0";
}

function renderWorkspace(ws) {
  if (typeof renderReportProfile === "function") renderReportProfile(ws.report_context, currentWorkspaceScanId);
  const scan = ws.overview || {};
  const metrics = ws.metrics || {};
  if (el("dashReportRisk")) {
    const scores = (ws.findings || []).map(f => f.cvss_score).filter(x => typeof x === "number" && Number.isFinite(x));
    el("dashReportRisk").textContent = scores.length ? `${Math.max(...scores)} / 10 (tercatat)` : "Belum tercatat";
  }
  const exactTarget = scan.target_url || scan.target_host || scan.root_domain || scan.target || "Target";
  const status = (scan.status || "COMPLETED").toUpperCase();

  // 1. Header Information
  if (el("wsTargetName")) el("wsTargetName").textContent = `Target: ${exactTarget}`;
  if (el("wsInvestigationId")) el("wsInvestigationId").textContent = `ID: #${scan.id || scan.investigation_id || '-'}`;
  if (el("wsEngineBadge")) el("wsEngineBadge").textContent = scan.profile || "Assessment";
  if (el("wsLevelBadge")) el("wsLevelBadge").textContent = (scan.validation_level || "Belum diketahui").replaceAll("_", " ");
  if (el("wsStatusBadge")) {
    el("wsStatusBadge").textContent = status;
    el("wsStatusBadge").className = `status-badge status-${status.toLowerCase()}`;
  }
  const durSec = scan.duration_seconds || 0;
  const durStr = scan.duration || (durSec > 0 ? `${Math.floor(durSec / 60)}m ${durSec % 60}s` : "00m 00s");
  if (el("wsDuration")) el("wsDuration").textContent = scan.duration_seconds == null ? "Tidak tercatat" : durStr;
  if (el("wsCoverage")) el("wsCoverage").textContent = Number.isFinite(scan.coverage_percentage ?? metrics.coverage_percent) ? `${scan.coverage_percentage ?? metrics.coverage_percent}%` : "Belum terukur";
  if (el("wsStartTime")) {
    const sTime = scan.started_at;
    el("wsStartTime").textContent = sTime ? new Date(sTime).toLocaleString("id-ID") : "Tidak tercatat";
  }

  // Update tab counts badges
  if (el("wsTabCountAssets")) el("wsTabCountAssets").textContent = (ws.assets || []).length;
  if (el("wsTabCountServices")) el("wsTabCountServices").textContent = (ws.services || []).length;
  if (el("wsTabCountEndpoints")) el("wsTabCountEndpoints").textContent = (ws.endpoints || []).length;
  if (el("wsTabCountFindings")) el("wsTabCountFindings").textContent = (ws.findings || []).length;
  if (el("wsTabCountArtifacts")) el("wsTabCountArtifacts").textContent = (ws.artifacts || []).length;

  // 2. Overview Panel
  renderWorkspaceOverview(ws);

  // 3. Tab Contents
  renderWorkspaceAssets(ws.assets || []);
  renderWorkspaceServices(ws.services || []);
  renderWorkspaceEndpoints(ws.endpoints || []);
  renderWorkspaceFindings(ws.findings || []);
  renderWorkspaceAttackChains(ws.attack_chains || [], ws);
  renderWorkspaceEvidence(ws.evidence || []);
  renderWorkspaceArtifacts(ws.artifacts || []);
  renderWorkspaceTimeline(ws.timeline || []);
  renderWorkspaceExports(ws.exports || ws.export_jobs || []);
}

function renderWorkspaceOverview(ws) {
  const m = ws.metrics || {};
  const o = ws.overview || {};
  const sev = m.severity_breakdown || o.severity_breakdown || o.severity_summary || {};
  const conf = m.confidence_breakdown || o.confidence_breakdown || o.confidence_summary || {};

  const assetsCount = m.assets_count ?? (ws.assets || []).length ?? 0;
  const servicesCount = m.services_count ?? (ws.services || []).length ?? 0;
  const endpointsCount = m.endpoints_count ?? (ws.endpoints || []).length ?? 0;
  const techsCount = m.technologies_count ?? o.counters?.technologies ?? (ws.technologies || []).length ?? 0;
  const findingsCount = m.findings_count ?? (ws.findings || []).length ?? 0;
  const artifactsCount = m.artifacts_count ?? (ws.artifacts || []).length ?? 0;

  if (el("wsStatAssets")) el("wsStatAssets").textContent = assetsCount;
  if (el("wsStatServices")) el("wsStatServices").textContent = servicesCount;
  if (el("wsStatEndpoints")) el("wsStatEndpoints").textContent = endpointsCount;
  if (el("wsStatTechs")) el("wsStatTechs").textContent = techsCount;
  if (el("wsStatFindings")) el("wsStatFindings").textContent = findingsCount;
  if (el("wsStatArtifacts")) el("wsStatArtifacts").textContent = artifactsCount;

  // Severities (handle case-insensitively)
  const crit = sev.critical ?? sev.CRITICAL ?? 0;
  const high = sev.high ?? sev.HIGH ?? 0;
  const med = sev.medium ?? sev.MEDIUM ?? 0;
  const low = sev.low ?? sev.LOW ?? 0;
  const info = sev.info ?? sev.INFO ?? 0;

  if (el("wsSevCrit")) el("wsSevCrit").textContent = crit;
  if (el("wsSevHigh")) el("wsSevHigh").textContent = high;
  if (el("wsSevMed")) el("wsSevMed").textContent = med;
  if (el("wsSevLow")) el("wsSevLow").textContent = low;
  if (el("wsSevInfo")) el("wsSevInfo").textContent = info;

  // Confidences (handle case-insensitively)
  if (el("wsConfConfirmed")) el("wsConfConfirmed").textContent = conf.confirmed ?? conf.CONFIRMED ?? 0;
  if (el("wsConfLikely")) el("wsConfLikely").textContent = conf.likely ?? conf.LIKELY ?? 0;
  if (el("wsConfPotential")) el("wsConfPotential").textContent = conf.potential ?? conf.POTENTIAL ?? 0;
  if (el("wsConfInconclusive")) el("wsConfInconclusive").textContent = conf.inconclusive ?? conf.INCONCLUSIVE ?? 0;

  // Executive text
  const target = o.target || o.root_domain || o.target_url || "Target";

  if (el("wsExecSummaryText")) {
    el("wsExecSummaryText").textContent = findingsCount
      ? `Pemeriksaan pada ${target} mencatat ${findingsCount} temuan (${crit} Critical, ${high} High), ${assetsCount} aset dan ${servicesCount} layanan. Periksa level bukti dan hasil validasi setiap temuan sebelum menyimpulkan dampaknya.`
      : `Belum ada temuan tercatat untuk ${target}. Data yang tersedia: ${assetsCount} aset dan ${servicesCount} layanan. Ketiadaan temuan bukan jaminan bahwa target aman atau cakupan pengujian lengkap.`;
  }
}


// Universal Paginated Table Controller for Reports Workspace with Filter Pills
const wsPaginationState = {
  assets: { page: 1, pageSize: 25, query: "", filter: "ALL", data: [] },
  services: { page: 1, pageSize: 25, query: "", filter: "ALL", data: [] },
  endpoints: { page: 1, pageSize: 25, query: "", filter: "ALL", data: [] },
  artifacts: { page: 1, pageSize: 25, query: "", filter: "ALL", data: [] },
  timeline: { page: 1, pageSize: 25, query: "", filter: "ALL", data: [] },
};

function setupFilterPills(containerId, stateKey, updateFn, attrName) {
  const container = el(containerId);
  if (!container || container.dataset.bound) return;
  container.dataset.bound = "true";

  container.querySelectorAll(".filter-pill").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      container.querySelectorAll(".filter-pill").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      wsPaginationState[stateKey].filter = btn.getAttribute(attrName) || "ALL";
      wsPaginationState[stateKey].page = 1;
      updateFn();
    });
  });
}

function renderWsPaginationControls(key, totalItems, onPageChange) {
  const pEl = el(`ws${key.charAt(0).toUpperCase() + key.slice(1)}Pagination`);
  if (!pEl) return;
  const state = wsPaginationState[key];
  const totalPages = Math.max(1, Math.ceil(totalItems / state.pageSize));
  if (state.page > totalPages) state.page = totalPages;

  const startIdx = totalItems === 0 ? 0 : (state.page - 1) * state.pageSize + 1;
  const endIdx = Math.min(state.page * state.pageSize, totalItems);

  pEl.innerHTML = `
    <div class="ws-pagination-info font-mono">
      Menampilkan <strong>${startIdx}-${endIdx}</strong> dari <strong>${totalItems}</strong> data
    </div>
    <div class="ws-pagination-controls">
      <button class="btn btn-secondary btn-xs font-mono btn-page-first" ${state.page <= 1 ? 'disabled' : ''}>⏮ Pertama</button>
      <button class="btn btn-secondary btn-xs font-mono btn-page-prev" ${state.page <= 1 ? 'disabled' : ''}>◀ Sebelumnya</button>
      <span class="ws-page-current font-mono">Halaman <strong>${state.page}</strong> / ${totalPages}</span>
      <button class="btn btn-secondary btn-xs font-mono btn-page-next" ${state.page >= totalPages ? 'disabled' : ''}>Berikutnya ▶</button>
      <button class="btn btn-secondary btn-xs font-mono btn-page-last" ${state.page >= totalPages ? 'disabled' : ''}>Terakhir ⏭</button>
    </div>
  `;

  pEl.querySelector(".btn-page-first")?.addEventListener("click", () => {
    if (state.page > 1) { state.page = 1; onPageChange(); }
  });
  pEl.querySelector(".btn-page-prev")?.addEventListener("click", () => {
    if (state.page > 1) { state.page--; onPageChange(); }
  });
  pEl.querySelector(".btn-page-next")?.addEventListener("click", () => {
    if (state.page < totalPages) { state.page++; onPageChange(); }
  });
  pEl.querySelector(".btn-page-last")?.addEventListener("click", () => {
    if (state.page < totalPages) { state.page = totalPages; onPageChange(); }
  });
}

function renderWorkspaceAssets(assets) {
  wsPaginationState.assets.data = assets || [];
  wsPaginationState.assets.page = 1;
  
  const searchInput = el("wsAssetSearchInput");
  if (searchInput && !searchInput.dataset.bound) {
    searchInput.dataset.bound = "true";
    searchInput.addEventListener("input", (e) => {
      wsPaginationState.assets.query = e.target.value.toLowerCase().trim();
      wsPaginationState.assets.page = 1;
      updateAssetsView();
    });
  }

  setupFilterPills("wsAssetFilterPills", "assets", updateAssetsView, "data-asset-filter");
  updateAssetsView();
}

function updateAssetsView() {
  const tbody = el("wsAssetsTbody");
  if (!tbody) return;
  const { data, page, pageSize, query, filter } = wsPaginationState.assets;

  let filtered = data;
  if (filter === "ACTIVE") {
    filtered = filtered.filter(a => (a.status || "ACTIVE").toUpperCase() === "ACTIVE");
  } else if (filter === "DOMAIN") {
    filtered = filtered.filter(a => (a.asset_type || "domain").toLowerCase().includes("domain"));
  } else if (filter === "IP") {
    filtered = filtered.filter(a => (a.asset_type || "").toLowerCase() === "ip" || (a.ip && a.ip === a.hostname));
  }

  if (query) {
    filtered = filtered.filter(a => (a.hostname || a.fqdn || "").toLowerCase().includes(query) || (a.ip || "").toLowerCase().includes(query) || (a.status || "").toLowerCase().includes(query));
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center p-3 text-muted font-mono">${(query || filter !== 'ALL') ? 'Tidak ada asset yang cocok dengan filter atau pencarian.' : 'Tidak ada data aset subdomain yang ditemukan.'}</td></tr>`;
    renderWsPaginationControls("assets", 0, updateAssetsView);
    return;
  }

  const start = (page - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  tbody.innerHTML = paged.map((a) => {
    const statusPill = `<span class="pill pill-${a.status === 'ACTIVE' ? 'success' : 'neutral'} font-mono">${esc(a.status || 'ACTIVE')}</span>`;
    return `
      <tr>
        <td><strong class="font-mono text-bright">${esc(a.hostname || a.fqdn || '-')}</strong></td>
        <td><code class="font-mono text-cyan">${esc(a.ip || '-')}</code></td>
        <td><span class="pill pill-neutral font-mono">${esc(a.asset_type || 'domain')}</span></td>
        <td>${statusPill}</td>
        <td class="text-xs font-mono">${(a.first_seen || a.created_at) ? new Date(a.first_seen || a.created_at).toLocaleDateString('id-ID') : '-'}</td>
        <td>
          <button class="btn btn-secondary btn-xs font-mono" onclick="openAssetDetail(${jsArg(a.id)})">🔍 Detail Asset</button>
        </td>
      </tr>
    `;
  }).join("");

  renderWsPaginationControls("assets", filtered.length, updateAssetsView);
}

function renderWorkspaceServices(services) {
  wsPaginationState.services.data = services || [];
  wsPaginationState.services.page = 1;

  const searchInput = el("wsServiceSearchInput");
  if (searchInput && !searchInput.dataset.bound) {
    searchInput.dataset.bound = "true";
    searchInput.addEventListener("input", (e) => {
      wsPaginationState.services.query = e.target.value.toLowerCase().trim();
      wsPaginationState.services.page = 1;
      updateServicesView();
    });
  }

  setupFilterPills("wsServiceFilterPills", "services", updateServicesView, "data-service-filter");
  updateServicesView();
}

function updateServicesView() {
  const tbody = el("wsServicesTbody");
  if (!tbody) return;
  const { data, page, pageSize, query, filter } = wsPaginationState.services;

  let filtered = data;
  if (filter === "WEB") {
    const webPorts = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000];
    filtered = filtered.filter(s => webPorts.includes(Number(s.port)) || (s.service || "").toLowerCase().includes("http"));
  } else if (filter === "TLS") {
    filtered = filtered.filter(s => s.is_tls || s.tls_enabled || Number(s.port) === 443 || Number(s.port) === 8443);
  } else if (filter === "PLAIN") {
    filtered = filtered.filter(s => !s.is_tls && !s.tls_enabled && Number(s.port) !== 443 && Number(s.port) !== 8443);
  } else if (filter === "AUTH") {
    filtered = filtered.filter(s => s.is_auth_surface);
  } else if (filter === "NON_STD") {
    filtered = filtered.filter(s => s.is_nonstandard_http || s.is_non_standard_http || ![80, 443].includes(Number(s.port)));
  }

  if (query) {
    filtered = filtered.filter(s => (s.host || "").toLowerCase().includes(query) || String(s.port || "").includes(query) || (s.service || s.service_name || "").toLowerCase().includes(query) || (s.banner || "").toLowerCase().includes(query));
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center p-3 text-muted font-mono">${(query || filter !== 'ALL') ? 'Tidak ada service yang cocok dengan filter atau pencarian.' : 'Tidak ada port atau service terbuka yang terdeteksi.'}</td></tr>`;
    renderWsPaginationControls("services", 0, updateServicesView);
    return;
  }

  const start = (page - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  tbody.innerHTML = paged.map((s) => {
    const isNonStdHttp = (s.is_nonstandard_http ?? s.is_non_standard_http) ? `<span class="pill pill-warning font-mono">Non-Std HTTP</span>` : '';
    const isTls = (s.is_tls ?? s.tls_enabled) ? `<span class="pill pill-success font-mono">TLS/HTTPS</span>` : `<span class="pill pill-muted font-mono">Plain</span>`;
    const authSurface = s.is_auth_surface ? `<span class="pill pill-danger font-mono">Auth Surface</span>` : `<span class="text-xs text-muted font-mono">Standard</span>`;

    return `
      <tr>
        <td><strong class="font-mono text-bright">${esc(s.host || '-')}</strong></td>
        <td><span class="font-mono font-bold text-primary">${esc(String(s.port))}</span></td>
        <td><code class="font-mono">${esc(s.protocol || 'tcp')}</code></td>
        <td><span class="pill pill-neutral font-mono">${esc(s.service || s.service_name || '-')}</span> ${isNonStdHttp}</td>
        <td class="font-mono">${esc(s.product || '')} ${esc(s.version || '')}</td>
        <td class="text-xs font-mono text-muted truncate-cell" title="${esc(s.banner || '')}">${esc(s.banner || '-')}</td>
        <td>${isTls}</td>
        <td>${authSurface}</td>
      </tr>
    `;
  }).join("");

  renderWsPaginationControls("services", filtered.length, updateServicesView);
}

function renderWorkspaceEndpoints(endpoints) {
  wsPaginationState.endpoints.data = endpoints || [];
  wsPaginationState.endpoints.page = 1;

  const searchInput = el("wsEndpointSearchInput");
  if (searchInput && !searchInput.dataset.bound) {
    searchInput.dataset.bound = "true";
    searchInput.addEventListener("input", (e) => {
      wsPaginationState.endpoints.query = e.target.value.toLowerCase().trim();
      wsPaginationState.endpoints.page = 1;
      updateEndpointsView();
    });
  }

  setupFilterPills("wsEndpointFilterPills", "endpoints", updateEndpointsView, "data-endpoint-filter");
  updateEndpointsView();
}

function updateEndpointsView() {
  const tbody = el("wsEndpointsTbody");
  if (!tbody) return;
  const { data, page, pageSize, query, filter } = wsPaginationState.endpoints;

  let filtered = data;
  if (filter === "GET") {
    filtered = filtered.filter(u => (u.method || "GET").toUpperCase() === "GET");
  } else if (filter === "POST") {
    filtered = filtered.filter(u => (u.method || "").toUpperCase() === "POST");
  } else if (filter === "2XX") {
    filtered = filtered.filter(u => u.status_code >= 200 && u.status_code < 300);
  } else if (filter === "3XX") {
    filtered = filtered.filter(u => u.status_code >= 300 && u.status_code < 400);
  } else if (filter === "4XX") {
    filtered = filtered.filter(u => u.status_code >= 400 && u.status_code < 500);
  } else if (filter === "SENSITIVE") {
    const sensitivePatterns = [".env", ".sql", ".git", "dump", "backup", "config", "admin", "secret", "login"];
    filtered = filtered.filter(u => sensitivePatterns.some(p => (u.url || "").toLowerCase().includes(p)));
  }

  if (query) {
    filtered = filtered.filter(u => (u.url || "").toLowerCase().includes(query) || (u.method || "").toLowerCase().includes(query) || (u.title || u.page_title || "").toLowerCase().includes(query) || String(u.status_code || "").includes(query));
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center p-3 text-muted font-mono">${(query || filter !== 'ALL') ? 'Tidak ada endpoint yang cocok dengan filter atau pencarian.' : 'Tidak ada endpoint URL yang terpetakan.'}</td></tr>`;
    renderWsPaginationControls("endpoints", 0, updateEndpointsView);
    return;
  }

  const start = (page - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  tbody.innerHTML = paged.map((u) => {
    const m = (u.method || 'GET').toUpperCase();
    const methodClass = m === 'POST' ? 'pill-warning' : (m === 'PUT' ? 'pill-info' : (m === 'DELETE' ? 'pill-danger' : 'pill-primary'));
    const statusClass = (u.status_code >= 200 && u.status_code < 300) ? 'text-success' : (u.status_code >= 400 ? 'text-danger' : 'text-muted');

    return `
      <tr>
        <td><span class="pill ${methodClass} font-mono">${esc(m)}</span></td>
        <td class="font-mono text-xs"><a href="${esc(safeLink(u.url))}" target="_blank" rel="noopener" class="text-cyan">${esc(u.url)}</a></td>
        <td><span class="font-bold font-mono ${statusClass}">${esc(String(u.status_code || '-'))}</span></td>
        <td class="text-xs text-muted font-mono">${esc(u.content_type || '-')}</td>
        <td class="text-xs font-mono">${esc(u.title || u.page_title || '-')}</td>
      </tr>
    `;
  }).join("");

  renderWsPaginationControls("endpoints", filtered.length, updateEndpointsView);
}

function renderWorkspaceArtifacts(artifacts) {
  wsPaginationState.artifacts.data = artifacts || [];
  wsPaginationState.artifacts.page = 1;

  const searchInput = el("wsArtifactSearchInput");
  if (searchInput && !searchInput.dataset.bound) {
    searchInput.dataset.bound = "true";
    searchInput.addEventListener("input", (e) => {
      wsPaginationState.artifacts.query = e.target.value.toLowerCase().trim();
      wsPaginationState.artifacts.page = 1;
      updateArtifactsView();
    });
  }

  setupFilterPills("wsArtifactFilterPills", "artifacts", updateArtifactsView, "data-artifact-filter");
  updateArtifactsView();
}

function updateArtifactsView() {
  const tbody = el("wsArtifactsTbody");
  if (!tbody) return;
  const { data, page, pageSize, query, filter } = wsPaginationState.artifacts;

  let filtered = data;
  if (filter === "SENSITIVE") {
    filtered = filtered.filter(a => ["CONFIDENTIAL", "SENSITIVE", "HIGHLY_SENSITIVE"].includes((a.classification || "").toUpperCase()));
  } else if (filter === "DATABASE") {
    filtered = filtered.filter(a => (a.category || "").toLowerCase().includes("database") || (a.filename || a.name || "").endsWith(".sql") || (a.filename || a.name || "").includes("dump"));
  } else if (filter === "CONFIG") {
    filtered = filtered.filter(a => (a.category || "").toLowerCase().includes("config") || (a.filename || a.name || "").includes(".env") || (a.filename || a.name || "").includes("config"));
  }

  if (query) {
    filtered = filtered.filter(a => (a.filename || a.name || "").toLowerCase().includes(query) || (a.category || "").toLowerCase().includes(query) || (a.classification || "").toLowerCase().includes(query) || (a.sha256 || "").toLowerCase().includes(query));
  }

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-3 text-muted font-mono">${(query || filter !== 'ALL') ? 'Tidak ada artefak yang cocok dengan filter atau pencarian.' : 'Tidak ada artefak yang diekstrak.'}</td></tr>`;
    renderWsPaginationControls("artifacts", 0, updateArtifactsView);
    return;
  }

  const start = (page - 1) * pageSize;
  const paged = filtered.slice(start, start + pageSize);

  tbody.innerHTML = paged.map((a, idx) => {
    const cls = (a.classification || "INTERNAL").toUpperCase();
    const clsBadge = cls === "HIGHLY_SENSITIVE" ? "pill-danger" : (cls === "CONFIDENTIAL" ? "pill-warning" : "pill-neutral");
    const shortHash = a.sha256 ? `${a.sha256.slice(0, 16)}…` : "-";

    return `
      <tr>
        <td><strong class="font-mono text-bright">${esc(a.filename || a.name || `artifact_${idx+1}`)}</strong></td>
        <td><span class="pill ${clsBadge} font-mono">${esc(cls)}</span></td>
        <td><span class="text-xs font-mono text-muted">${esc(a.category || 'EXTRACTED_DATA')}</span></td>
        <td class="font-mono">${esc(String(a.record_count || a.rows || '-'))}</td>
        <td class="font-mono text-xs">${esc(formatBytes(a.size || a.file_size || 0))}</td>
        <td><code class="font-mono text-xs" title="${esc(a.sha256 || '')}">${esc(shortHash)}</code></td>
        <td>
          <button class="btn btn-secondary btn-xs font-mono" onclick="openArtifactPreview(${jsArg(a.id || idx)})">👁️ Preview</button>
        </td>
      </tr>
    `;
  }).join("");

  renderWsPaginationControls("artifacts", filtered.length, updateArtifactsView);
}

function renderWorkspaceFindings(findings) {
  const container = el("wsFindingsContainer");
  if (!container) return;

  if (!findings.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada temuan kerentanan keamanan yang terdeteksi pada investigasi ini.</div>`;
    return;
  }

  container.innerHTML = findings.slice(0, 20).map((f, idx) => {
    const sev = (f.severity || "INFO").toUpperCase();
    const conf = (f.confidence || "INCONCLUSIVE").toUpperCase();
    const cveBadges = (f.cve_ids || (f.cve_id ? [f.cve_id] : [])).map(cve => `<span class="pill pill-danger font-mono">${esc(cve)}</span>`).join(" ");
    const quality = f.report_quality || {status: "NEEDS_REVIEW", missing: []};
    const code = f.finding_code || `INV-F-${String(idx + 1).padStart(3, '0')}`;
    const dossier = f.poc_dossier || {};
    const reproSteps = dossier.reproduction_steps || f.reproduction_steps || [];
    const pythonCode = dossier.python_poc || f.python_poc || "";
    const curlCode = dossier.curl_command || f.proof_curl || f.poc || "";
    const rawReq = dossier.raw_http_request || f.raw_http_request || "";
    const rawResp = dossier.raw_http_response || f.raw_http_response || "";
    const expected = dossier.expected_behavior || f.expected_behavior || "Perilaku yang diharapkan belum dicatat.";
    const actual = dossier.actual_behavior || f.actual_behavior || f.technical_details || "Perilaku aktual belum dicatat.";
    const ss = dossier.screenshot || f.screenshot || {};

    let screenshotHtml = `<div class="text-xs text-muted mt-2">Kesiapan laporan: <strong>${esc(quality.status)}</strong>. Belum lengkap: ${esc(quality.missing.join(", ") || "Tetap perlu tinjauan manusia")}. Script otomatis adalah template replay, bukan bukti keberhasilan.</div>`;
    if (ss.has_screenshot && ss.image_url) {
      screenshotHtml += `
        <div class="ws-screenshot-preview mt-3">
          <div class="ws-screenshot-header">📸 Bukti Visual (Real Browser Screenshot)</div>
          <div class="ws-screenshot-thumb-box" onclick="openScreenshotZoom(${jsArg(ss.image_url)}, ${jsArg(ss.caption || f.title)})">
            <img src="${esc(ss.image_url)}" alt="Visual Evidence Proof" class="ws-screenshot-img" loading="lazy" />
            <div class="ws-screenshot-overlay">🔍 Klik untuk Perbesar Tangkapan Layar Asli</div>
          </div>
          <div class="text-xs text-muted mt-1">${esc(ss.caption || 'Captured during live browser validation')}</div>
        </div>
      `;
    } else {
      screenshotHtml += `
        <div class="ws-screenshot-note mt-3">
          <span class="text-xs text-muted">📸 <strong>Status Visual Proof:</strong> ${esc(ss.explanation_if_none || 'Bukti visual browser tidak berlaku untuk endpoint API/protokol ini. Bukti HTTP wire request & response lengkap disertakan di bawah.')}</span>
        </div>
      `;
    }

    const stepsListHtml = reproSteps.length ? `
      <div class="ws-repro-steps-box mt-3">
        <strong class="text-xs text-primary">📋 Langkah-Langkah Reproduksi Rinci (Manual PoC):</strong>
        <ol class="ws-repro-list mt-1">
          ${reproSteps.map(st => `<li>${esc(st)}</li>`).join("")}
        </ol>
      </div>
    ` : '';

    return `
      <div class="card sketch-card ws-finding-card border-sev-${sev.toLowerCase()} mb-3" id="finding-card-${esc(f.id)}">
        <div class="flex-between flex-wrap gap-2">
          <div class="title-with-icon">
            <span class="severity-badge severity-${sev.toLowerCase()}">${sev}</span>
            <div>
              <span class="font-mono text-xs text-muted font-bold">${esc(code)}</span>
              <h3 class="ws-finding-title">${esc(f.title)}</h3>
            </div>
          </div>
          <div class="flex-row-gap flex-wrap">
            <span class="pill pill-info">${esc(conf)}</span>
            <span class="pill pill-neutral font-mono">${esc(f.cwe_id || 'Belum dipetakan')}</span>
            ${f.cve_id ? `<span class="pill pill-danger font-mono font-bold">${esc(f.cve_id)}</span>` : ''}
            ${f.cvss_score ? `<span class="pill pill-danger font-bold">CVSS ${f.cvss_score}</span>` : ''}
          </div>
        </div>

        <div class="ws-finding-meta mt-2">
          <span>Target Host: <strong>${esc(f.asset_hostname || '-')}</strong></span>
          ${f.location || f.url ? `<span class="ml-2">Endpoint: <code class="font-mono text-xs">${esc(f.location || f.url)}</code></span>` : ''}
          ${f.parameter ? `<span class="ml-2">Param: <code class="font-mono text-xs">${esc(f.parameter)}</code></span>` : ''}
        </div>

        ${cveBadges ? `<div class="mt-2">${cveBadges}</div>` : ''}

        <p class="ws-finding-desc mt-2">${esc(f.description || f.executive_explanation || '')}</p>

        ${stepsListHtml}

        <!-- Interactive PoC Multi-Tab Box -->
        <div class="ws-poc-container mt-3">
          <div class="ws-poc-tab-nav">
            <button class="ws-poc-tab-btn active" onclick="switchCardPocTab(${jsArg(f.id)}, 'python', this)">🐍 Python PoC Script</button>
            <button class="ws-poc-tab-btn" onclick="switchCardPocTab(${jsArg(f.id)}, 'curl', this)">⚡ cURL CLI Command</button>
            <button class="ws-poc-tab-btn" onclick="switchCardPocTab(${jsArg(f.id)}, 'raw_req', this)">📡 Raw HTTP Request</button>
            <button class="ws-poc-tab-btn" onclick="switchCardPocTab(${jsArg(f.id)}, 'raw_resp', this)">📥 Raw Response Proof</button>
            <button class="btn btn-secondary btn-xs ml-auto" onclick="copyCardActivePoc(${jsArg(f.id)}, this)">📋 Copy Script / Code</button>
          </div>

          <div class="ws-poc-tab-content-wrap">
            <pre class="ws-poc-code-pane active font-mono text-xs" id="poc-pane-${esc(f.id)}-python"><code>${esc(pythonCode)}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="poc-pane-${esc(f.id)}-curl"><code>${esc(curlCode)}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="poc-pane-${esc(f.id)}-raw_req"><code>${esc(rawReq)}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="poc-pane-${esc(f.id)}-raw_resp"><code>${esc(rawResp)}</code></pre>
          </div>
        </div>

        <!-- Expected vs Actual Behavior Box -->
        <div class="ws-behavior-box mt-3">
          <div class="behavior-row">
            <span class="behavior-tag tag-expected">✅ Perilaku Aman Seharusnya:</span>
            <span class="behavior-text">${esc(expected)}</span>
          </div>
          <div class="behavior-row mt-1">
            <span class="behavior-tag tag-actual">Perilaku aktual yang tercatat:</span>
            <span class="behavior-text">${esc(actual)}</span>
          </div>
        </div>

        ${screenshotHtml}

        ${f.remediation ? `
          <div class="ws-remediation-box mt-3">
            <strong>🛡️ Recommended Engineering Remediation:</strong>
            <p class="text-sm mt-1">${esc(f.remediation)}</p>
          </div>
        ` : ''}

        <div class="ws-finding-footer mt-3 flex-between flex-wrap gap-2">
          <span class="text-xs text-muted">Quality Gate: <strong>Periksa kelengkapan bukti</strong></span>
          <div class="flex-row-gap">
            <button class="btn btn-secondary btn-xs" onclick="downloadSingleFindingPoC(${jsArg(f.id)})">💾 Export PoC (.py)</button>
            <button class="btn btn-primary btn-xs" onclick="openFindingPocDossier(${jsArg(f.id)})">🔒 View In-Depth Analysis & PoC</button>
          </div>
        </div>
      </div>
    `;
  }).join("");
  if (findings.length > 20) container.insertAdjacentHTML("beforeend", `<p class="empty-msg">Menampilkan 20 dari ${findings.length} temuan. Gunakan pencarian/filter untuk mempersempit hasil, atau export untuk seluruh temuan.</p>`);
}


function renderWorkspaceAttackChains(chains, ws) {
  const canvas = el("wsAttackGraphCanvas");
  if (!canvas) return;
  canvas.innerHTML = `<div class="empty-msg">Belum ada rantai eksploitasi tervalidasi yang tersimpan. Temuan upload atau autentikasi saja tidak membuktikan RCE. Tinjau temuan dan bukti masing-masing sebelum menghubungkannya.</div>`;
}

function renderWorkspaceEvidence(evidence) {
  const container = el("wsEvidenceList");
  if (!container) return;

  if (!evidence.length) {
    container.innerHTML = `<div class="empty-msg">Belum ada paket bukti HTTP request/response terekam.</div>`;
    return;
  }

  container.innerHTML = evidence.map((e) => {
    return `
      <div class="card sketch-card ws-evidence-card mb-3">
        <div class="flex-between">
          <div class="title-with-icon">
            <span class="section-icon">🔒</span>
            <h4 class="font-bold">${esc(e.title || 'HTTP Proof Package')}</h4>
          </div>
          <span class="pill pill-neutral font-mono text-xs">SHA-256: ${esc((e.sha256_hash || '').slice(0, 16))}...</span>
        </div>

        <div class="ws-evidence-grid mt-2">
          ${e.request_headers || e.request_body ? `
            <div class="ws-evidence-box">
              <div class="ws-ev-label">HTTP Request</div>
              <pre class="ws-ev-pre font-mono text-xs"><code>${esc(e.request_headers || '')}\n\n${esc(e.request_body || '')}</code></pre>
            </div>
          ` : ''}

          ${e.response_headers || e.response_body ? `
            <div class="ws-evidence-box">
              <div class="ws-ev-label">HTTP Response (Status: ${esc(String(e.response_status || '-'))})</div>
              <pre class="ws-ev-pre font-mono text-xs"><code>${esc(e.response_headers || '')}\n\n${esc(e.response_body || '')}</code></pre>
            </div>
          ` : ''}
        </div>
      </div>
    `;
  }).join("");
}

function renderWorkspaceArtifacts(artifacts) {
  const tbody = el("wsArtifactsTbody");
  if (!tbody) return;

  if (!artifacts.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-3 text-muted">Tidak ada file atau dump data tersimpan pada sesi ini.</td></tr>`;
    return;
  }

  tbody.innerHTML = artifacts.map((art) => {
    const cls = (art.classification || 'INTERNAL').toUpperCase();
    const classBadge = `
      <span class="pill pill-class-${cls.toLowerCase()}">${esc(cls)}</span>
    `;
    const recCount = art.record_count ?? (art.preview_data?.rows?.length) ?? 0;
    const szBytes = art.size_bytes ?? art.file_size ?? 0;

    return `
      <tr>
        <td><strong>${esc(art.filename)}</strong></td>
        <td>${classBadge}</td>
        <td><span class="pill pill-neutral">${esc(art.category || 'generic')}</span></td>
        <td><strong class="font-mono">${esc(String(recCount))}</strong> rows</td>
        <td class="text-xs font-mono">${formatBytes(szBytes)}</td>
        <td class="text-xs font-mono text-muted">${esc((art.sha256_hash || '-').slice(0, 16))}...</td>
        <td>
          <button class="btn btn-primary btn-xs" onclick="openArtifactPreview(${jsArg(art.id)})">👁️ Pratinjau</button>
        </td>
      </tr>
    `;
  }).join("");
}

async function openArtifactPreview(artifactId) {
  if (!currentWorkspaceScanId || !artifactId) return;
  const modal = el("wsArtifactModal");
  if (!modal) return;

  modal.classList.remove("hidden");
  if (el("wsArtModalContent")) {
    el("wsArtModalContent").innerHTML = `
      <div class="p-5 text-center text-muted">
        <div class="spinner-inline mb-2">⚡</div>
        <div>Memuat pratinjau & intelijen data terekstrak...</div>
      </div>
    `;
  }

  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(currentWorkspaceScanId)}/artifacts/${encodeURIComponent(artifactId)}/preview`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    if (el("wsArtModalTitle")) el("wsArtModalTitle").textContent = `👁️ Pratinjau: ${data.filename}`;
    if (el("wsArtModalClassBadge")) {
      el("wsArtModalClassBadge").textContent = data.classification;
      el("wsArtModalClassBadge").className = `pill pill-class-${(data.classification || 'internal').toLowerCase()}`;
    }
    if (el("wsArtModalCategory")) el("wsArtModalCategory").textContent = data.category;
    if (el("wsArtModalRecordCount")) el("wsArtModalRecordCount").textContent = `Total Records: ${data.record_count || 0}`;

    const preview = data.preview_data || {};
    const schema = data.schema_data || {};
    const entities = data.extracted_entities || {};

    const dbName = schema.database_name || preview.database_name || "";
    const vendor = schema.vendor || preview.vendor || "";
    const tables = (preview.tables && preview.tables.length) ? preview.tables : (schema.tables || []);
    const hashes = (preview.extracted_hashes && preview.extracted_hashes.length) ? preview.extracted_hashes : (entities.hashes || schema.extracted_hashes || []);
    const users = (preview.extracted_users && preview.extracted_users.length) ? preview.extracted_users : (entities.users || schema.extracted_users || schema.real_users || []);

    // Resilient Raw Sample Synthesis: Never allow Raw Sample to be empty if file has data
    let rawSample = preview.raw_sample || schema.raw_sample || "";
    if (!rawSample || !rawSample.trim()) {
      if (preview.rows && preview.rows.length) {
        if (preview.columns && preview.columns.includes("Content")) {
          rawSample = preview.rows.map(r => r["Content"]).join("\n");
        } else if (preview.columns && preview.columns.includes("SQL Statement Sample")) {
          rawSample = preview.rows.map(r => r["SQL Statement Sample"]).join("\n");
        } else if (preview.columns) {
          rawSample = preview.columns.join(",") + "\n" + preview.rows.map(r => preview.columns.map(c => r[c] != null ? r[c] : '').join(",")).join("\n");
        }
      } else if (tables && tables.length) {
        rawSample = tables.map(t => {
          const tName = t.name || t.table_name || 'table';
          const cols = (t.columns || []).map(c => typeof c === 'object' ? `${c.name || c} ${c.type || ''}` : String(c)).join(",\n  ");
          const rows = (t.sample_rows || []).slice(0, 5).map(r => {
            if (typeof r === 'object') return `INSERT INTO \`${tName}\` VALUES (${Object.values(r).map(v => JSON.stringify(v)).join(", ")});`;
            return String(r);
          }).join("\n");
          return `-- Struktur tabel \`${tName}\`\nCREATE TABLE \`${tName}\` (\n  ${cols || 'id INT'}\n);\n${rows ? rows + '\n' : ''}`;
        }).join("\n");
      }
    }

    const crackedCount = hashes.filter(h => h.is_cracked || h.plaintext).length;
    const crackedUsers = hashes.filter(h => h.is_cracked || h.plaintext).map(h => `${h.associated_user || h.user || 'user'}: ${h.plaintext}`);

    // Build Intelligence Summary Pills
    let summaryHtml = `
      <div class="art-intel-summary-bar mb-3">
        ${dbName ? `<span class="pill pill-primary">🗄️ Database: <strong>${esc(dbName)}</strong>${vendor ? ` (${esc(vendor)})` : ''}</span>` : ''}
        ${tables.length ? `<span class="pill pill-neutral">📑 <strong>${tables.length}</strong> Tabel Terdeteksi</span>` : ''}
        ${hashes.length ? `<span class="pill pill-danger">🔑 <strong>${hashes.length}</strong> Hash Password ${crackedCount > 0 ? `(🔓 ${crackedCount} Terpecahkan!)` : ''}</span>` : ''}
        ${users.length ? `<span class="pill pill-warning">👤 <strong>${users.length}</strong> Akun User</span>` : ''}
      </div>
    `;

    // Determine available tabs
    const hasTables = tables.length > 0 || (preview.columns && preview.rows);
    const hasHashes = hashes.length > 0;
    const hasUsers = users.length > 0;
    const hasRaw = Boolean(rawSample && rawSample.trim());

    let tabsNavHtml = `
      <div class="art-modal-tabs mb-3">
        ${hasTables ? `<button class="art-tab-btn active" onclick="switchArtModalSubTab('tables', this)">📊 Tabel & Data (${tables.length || 1})</button>` : ''}
        ${hasHashes ? `<button class="art-tab-btn ${!hasTables ? 'active' : ''}" onclick="switchArtModalSubTab('hashes', this)">🔑 Hash Sandi (${hashes.length}) ${crackedCount > 0 ? '🔓' : ''}</button>` : ''}
        ${hasUsers ? `<button class="art-tab-btn ${(!hasTables && !hasHashes) ? 'active' : ''}" onclick="switchArtModalSubTab('users', this)">👤 Akun Pengguna (${users.length})</button>` : ''}
        <button class="art-tab-btn ${(!hasTables && !hasHashes && !hasUsers) ? 'active' : ''}" onclick="switchArtModalSubTab('raw', this)">📄 Raw Sample</button>
      </div>
    `;

    // Section 1: Tables View
    let tablesContentHtml = "";
    if (hasTables) {
      if (tables.length > 0) {
        // Multi-table SQL view with table switcher
        tablesContentHtml = `
          <div id="artSubTabTables" class="art-subtab-pane active">
            <div class="art-table-switcher mb-2">
              <label class="text-xs text-muted font-bold mr-2">Pilih Tabel:</label>
              <div class="art-table-pills">
                ${tables.map((t, idx) => `
                  <button class="btn btn-xs ${idx === 0 ? 'btn-primary active' : 'btn-secondary'} art-tbl-pill"
                    data-tbl-idx="${idx}"
                    onclick="selectArtTable(${idx}, this)">
                    ${esc(t.name || t.table_name || `Table ${idx+1}`)} ${t.sample_rows ? `(${t.sample_rows.length})` : ''}
                  </button>
                `).join("")}
              </div>
            </div>
            <div id="artTableDisplayContainer">
              ${renderSingleArtTable(tables[0])}
            </div>
          </div>
        `;
      } else if (preview.columns && preview.rows) {
        // Single flat table (e.g. CSV or Generic rows)
        tablesContentHtml = `
          <div id="artSubTabTables" class="art-subtab-pane active">
            <div class="table-responsive-box">
              <table class="ws-table">
                <thead>
                  <tr>${preview.columns.map(c => `<th>${esc(c)}</th>`).join("")}</tr>
                </thead>
                <tbody>
                  ${preview.rows.map(r => `
                    <tr>${preview.columns.map(c => `<td>${esc(String(r[c] != null ? r[c] : ''))}</td>`).join("")}</tr>
                  `).join("")}
                </tbody>
              </table>
            </div>
          </div>
        `;
      }
    } else {
      tablesContentHtml = `<div id="artSubTabTables" class="art-subtab-pane ${!hasHashes && !hasUsers ? 'active' : ''}"><div class="p-3 text-muted">Tidak ada tabel terstruktur yang dapat diekstrak.</div></div>`;
    }

    // Section 2: Hashes View with AI Decryption Intelligence
    let hashesContentHtml = `
      <div id="artSubTabHashes" class="art-subtab-pane ${!hasTables ? 'active' : ''}">
        ${hashes.length ? `
          <div class="ws-remediation-box mb-3" style="background: ${crackedCount > 0 ? '#FFFBEB' : '#F8FAFC'}; border-color: ${crackedCount > 0 ? '#FCD34D' : '#CBD5E1'}; color: ${crackedCount > 0 ? '#92400E' : '#334155'};">
            <strong>🤖 AI Threat & Credential Compromise Analysis:</strong>
            <p class="text-xs mt-1 mb-0">
              ${crackedCount > 0 
                ? `Ditemukan <strong>${crackedCount} kata sandi berhasil dipecahkan</strong> secara deterministik! Kredensial akun <code>${esc(crackedUsers.join(', '))}</code> menggunakan password yang rentan. Penyerang dapat memanfaatkan kredensial ini untuk login dan mengambil alih hak akses administratif.` 
                : `Ditemukan <strong>${hashes.length} password hash kriptografis</strong>. Seluruh hash siap diekspor untuk audit password offline menggunakan John The Ripper atau Hashcat.`}
            </p>
          </div>

          <div class="table-responsive-box">
            <table class="ws-table">
              <thead>
                <tr>
                  <th>Tabel Sumber</th>
                  <th>Akun / User Terkait</th>
                  <th>Tipe Algoritma</th>
                  <th>Sampel Hash Kredensial</th>
                  <th>🔓 Status & Password Terpecahkan (AI Engine)</th>
                  <th>Aksi</th>
                </tr>
              </thead>
              <tbody>
                ${hashes.map(h => {
                  const hType = (h.hash_type || 'hash').toUpperCase();
                  const hSample = h.hash_sample || h.sample || h.full_hash || '-';
                  const hFull = h.full_hash || hSample;
                  const isCracked = Boolean(h.is_cracked || h.plaintext);
                  const plaintext = h.plaintext || '';
                  const assocUser = h.associated_user || h.user || '-';

                  return `
                    <tr>
                      <td><strong>${esc(h.table || '-')}</strong></td>
                      <td><code class="font-mono font-bold">${esc(assocUser)}</code></td>
                      <td><span class="pill pill-danger">${esc(hType)}</span></td>
                      <td class="font-mono text-xs text-break">${esc(hSample)}</td>
                      <td>
                        ${isCracked ? `
                          <div class="flex-row-gap flex-wrap">
                            <span class="pill pill-success font-bold font-mono">🔓 ${esc(plaintext)}</span>
                            <span class="pill pill-neutral text-xs" style="background:#D1FAE5; color:#065F46;">CRACKED</span>
                          </div>
                        ` : `
                          <span class="pill pill-neutral font-mono text-xs">🔒 Uncracked (Belum Terpecahkan)</span>
                        `}
                      </td>
                      <td>
                        <div class="flex-row-gap flex-wrap">
                          <button class="btn btn-ghost btn-xs" onclick="navigator.clipboard.writeText(${jsArg(hFull)}); showToast('Hash disalin!', 'success');">📋 Salin Hash</button>
                          ${isCracked ? `
                            <button class="btn btn-success btn-xs" onclick="navigator.clipboard.writeText(${jsArg(plaintext)}); showToast('Password plaintext disalin!', 'success');">🔑 Salin Pass</button>
                          ` : ''}
                        </div>
                      </td>
                    </tr>
                  `;
                }).join("")}
              </tbody>
            </table>
          </div>
        ` : `<div class="p-3 text-muted">Tidak ada cryptographic hash yang terdeteksi.</div>`}
      </div>
    `;

    // Section 3: Users View
    let usersContentHtml = `
      <div id="artSubTabUsers" class="art-subtab-pane ${(!hasTables && !hasHashes) ? 'active' : ''}">
        ${users.length ? `
          <div class="table-responsive-box">
            <table class="ws-table">
              <thead>
                <tr>
                  <th>Username / Pengguna</th>
                  <th>Tabel / Sumber</th>
                  <th>Email / Metadata</th>
                  <th>Peran Terdeteksi</th>
                </tr>
              </thead>
              <tbody>
                ${users.map(u => {
                  const uName = u.username || u.identifier || '-';
                  const uTable = u.table || (u.home ? 'passwd' : '-');
                  const uMeta = u.email || (u.shell ? `Shell: ${u.shell}, UID: ${u.uid}` : '-');
                  const uRole = u.role || (uName === 'root' || u.uid === 0 ? 'admin' : 'user');
                  return `
                    <tr>
                      <td><strong>${esc(uName)}</strong></td>
                      <td><code>${esc(uTable)}</code></td>
                      <td class="text-xs text-muted">${esc(uMeta)}</td>
                      <td><span class="pill ${uRole === 'admin' ? 'pill-danger' : 'pill-neutral'}">${esc(uRole.toUpperCase())}</span></td>
                    </tr>
                  `;
                }).join("")}
              </tbody>
            </table>
          </div>
        ` : `<div class="p-3 text-muted">Tidak ada akun pengguna yang terdeteksi.</div>`}
      </div>
    `;

    // Section 4: Raw Sample View
    let rawContentHtml = `
      <div id="artSubTabRaw" class="art-subtab-pane ${(!hasTables && !hasHashes && !hasUsers) ? 'active' : ''}">
        <div class="mb-2 flex-between align-center">
          <span class="text-xs text-muted">Cuplikan teks mentah bersanitasi (${(rawSample || '').split('\n').length} baris)</span>
          <button class="btn btn-ghost btn-xs" onclick="navigator.clipboard.writeText(document.getElementById('wsArtRawCodeBlock')?.innerText || ''); showToast('Raw sample disalin!', 'success');">📋 Salin Raw</button>
        </div>
        ${rawSample ? `
          <pre class="font-mono text-xs p-3 bg-dark-box text-break" id="wsArtRawCodeBlock" style="max-height: 380px; overflow-y: auto; color: #E2E8F0; background: #0B0F19; border-radius: 6px;"><code>${esc(rawSample)}</code></pre>
        ` : `<div class="p-3 text-muted">Tidak ada raw sample yang tersedia.</div>`}
      </div>
    `;

    // Store tables in window for fast tab switching
    window.__currentArtTables = tables;

    if (el("wsArtModalContent")) {
      el("wsArtModalContent").innerHTML = `
        ${summaryHtml}
        ${tabsNavHtml}
        <div class="art-subtab-contents">
          ${tablesContentHtml}
          ${hashesContentHtml}
          ${usersContentHtml}
          ${rawContentHtml}
        </div>
      `;
    }
  } catch (err) {
    if (el("wsArtModalContent")) el("wsArtModalContent").innerHTML = `<div class="p-4 text-danger">Gagal memuat pratinjau: ${esc(err.message)}</div>`;
  }
}

function renderSingleArtTable(table) {
  if (!table) return "<div class='p-3 text-muted'>Tabel kosong atau belum terurai.</div>";
  let cols = (table.columns || []).map(c => typeof c === 'object' ? (c.name || JSON.stringify(c)) : String(c));
  const rows = table.sample_rows || table.rows || [];
  if ((!cols || !cols.length) && rows && rows.length && typeof rows[0] === 'object') {
    cols = Object.keys(rows[0]);
  }
  const tName = table.name || table.table_name || "Tabel";
  const displayRows = rows.slice(0, 50);

  return `
    <div class="mb-2 flex-between align-center flex-wrap gap-2">
      <span class="text-xs text-muted">
        Tabel: <strong class="text-primary font-mono">${esc(tName)}</strong> |
        Kolom: <strong>${cols.length}</strong> |
        Sampel Baris: <strong>${rows.length}</strong> ${rows.length > 50 ? `<small class="text-info">(menampilkan 50)</small>` : ''}
      </span>
      ${table.primary_key ? `<span class="pill pill-neutral text-xs font-mono">🔑 PK: ${esc(table.primary_key)}</span>` : ''}
    </div>
    <div class="table-responsive-box">
      <table class="ws-table">
        <thead>
          <tr>${cols.length ? cols.map(c => `<th>${esc(c)}</th>`).join("") : '<th>Kolom</th>'}</tr>
        </thead>
        <tbody>
          ${displayRows.length ? displayRows.map(r => `
            <tr>
              ${cols.map((c, i) => {
                const val = (r && typeof r === 'object' && !Array.isArray(r)) ? r[c] : (Array.isArray(r) ? r[i] : r);
                return `<td>${esc(String(val != null ? val : ''))}</td>`;
              }).join("")}
            </tr>
          `).join("") : `<tr><td colspan="${cols.length || 1}" class="text-center p-3 text-muted">Tidak ada baris data sampel pada tabel ini.</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

window.selectArtTable = function(tableIndex, btn) {
  const tables = window.__currentArtTables || [];
  const t = tables[tableIndex];
  if (!t) return;
  document.querySelectorAll(".art-tbl-pill").forEach((b, idx) => {
    if (idx === tableIndex || b === btn) {
      b.classList.add("btn-primary", "active");
      b.classList.remove("btn-secondary");
    } else {
      b.classList.remove("btn-primary", "active");
      b.classList.add("btn-secondary");
    }
  });
  if (el("artTableDisplayContainer")) {
    el("artTableDisplayContainer").innerHTML = renderSingleArtTable(t);
  }
};

window.switchArtModalSubTab = function(tabKey, btn) {
  document.querySelectorAll(".art-tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".art-subtab-pane").forEach(pane => pane.classList.remove("active"));
  
  if (tabKey === 'tables') {
    if (el("artSubTabTables")) el("artSubTabTables").classList.add("active");
  } else if (tabKey === 'hashes') {
    if (el("artSubTabHashes")) el("artSubTabHashes").classList.add("active");
  } else if (tabKey === 'users') {
    if (el("artSubTabUsers")) el("artSubTabUsers").classList.add("active");
  } else if (tabKey === 'raw') {
    if (el("artSubTabRaw")) el("artSubTabRaw").classList.add("active");
  }

  const targetBtn = btn || (typeof event !== 'undefined' ? (event?.currentTarget || event?.target) : null);
  if (targetBtn && targetBtn.classList && targetBtn.classList.contains("art-tab-btn")) {
    targetBtn.classList.add("active");
  }
};

function renderWorkspaceTimeline(timeline) {
  const stream = el("wsTimelineStream");
  if (!stream) return;

  if (!timeline.length) {
    stream.innerHTML = `<div class="empty-msg">Tidak ada catatan aktivitas telemetri investigasi.</div>`;
    return;
  }

  stream.innerHTML = timeline.map((ev) => {
    const timeStr = ev.created_at ? new Date(ev.created_at).toLocaleTimeString('id-ID') : '';
    const sevClass = (ev.severity || 'info').toLowerCase();
    return `
      <div class="ws-timeline-item border-sev-${sevClass}">
        <span class="ws-time font-mono text-xs">${esc(timeStr)}</span>
        <span class="pill pill-neutral text-xs">${esc(ev.event_type || 'event')}</span>
        <span class="ws-msg">${esc(ev.message || '')}</span>
      </div>
    `;
  }).join("");
}

function renderWorkspaceExports(exportJobs) {
  const tbody = el("wsExportJobsTbody");
  if (!tbody) return;

  if (!exportJobs.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-3 text-muted">Belum ada file export yang dibuat. Klik tombol di atas untuk membuat export baru.</td></tr>`;
    return;
  }

  tbody.innerHTML = exportJobs.map((job) => {
    const st = (job.status || 'QUEUED').toUpperCase();
    const stBadge = st === 'COMPLETED'
      ? `<span class="pill pill-success">READY</span>`
      : (st === 'PROCESSING' || st === 'QUEUED'
        ? `<span class="pill pill-warning">${st}</span>`
        : `<span class="pill pill-danger">${st}</span>`);

    const downloadBtn = (st === 'COMPLETED' && job.download_url)
      ? `<a href="${esc(safeLink(job.download_url))}" class="btn btn-success btn-xs" target="_blank" download>📥 Download</a>`
      : `<button class="btn btn-secondary btn-xs" disabled>⏳ Pending</button>`;

    return `
      <tr>
        <td><strong>${esc((job.export_type || job.format || "export").toUpperCase())}</strong></td>
        <td class="font-mono text-xs">${esc(job.filename || job.file_name || '-')}</td>
        <td>${stBadge}${st === 'FAILED' ? `<div class="text-xs text-danger">${esc(job.error_message || 'Export gagal. Silakan coba lagi.')}</div>` : ''}</td>
        <td class="font-mono text-xs">${formatBytes(job.file_size || 0)}</td>
        <td class="font-mono text-xs text-muted">${esc((job.sha256_hash || '-').slice(0, 16))}...</td>
        <td class="text-xs">${job.completed_at ? new Date(job.completed_at).toLocaleTimeString('id-ID') : '-'}</td>
        <td>${downloadBtn}</td>
      </tr>
    `;
  }).join("");
}

async function triggerAsyncExport(format) {
  if (!currentWorkspaceScanId) {
    showToast("Pilih investigasi terlebih dahulu untuk mengekspor.", "warning");
    return;
  }

  const scanId = currentWorkspaceScanId;
  const key = `${scanId}:${format}`;
  if (pendingExports.has(key)) return;
  pendingExports.add(key);
  try {
    showToast(`Memulai pembuatan export ${format.toUpperCase()} di latar belakang...`, "info");
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/export/${encodeURIComponent(format)}`, {
      method: "POST"
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const job = await res.json();
    showToast(`Tugas export ${format.toUpperCase()} berhasil dimasukkan antrian!`, "success");

    // Refresh workspace to get updated export job
    if (currentWorkspaceScanId !== scanId) return;
    await loadWorkspaceData(scanId);

    // Poll for export completion
    startExportPolling();
  } catch (err) {
    showToast("Gagal memulai export: " + err.message, "danger");
  } finally {
    pendingExports.delete(key);
  }
}

function startExportPolling() {
  if (exportPollInterval) clearInterval(exportPollInterval);
  let attempts = 0;
  let inFlight = false;
  const scanId = currentWorkspaceScanId;

  exportPollInterval = setInterval(async () => {
    if (inFlight || document.hidden) return;
    attempts++;
    if (attempts > 30 || !currentWorkspaceScanId || currentWorkspaceScanId !== scanId) {
      clearInterval(exportPollInterval);
      return;
    }

    try {
      inFlight = true;
      const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/exports`);
      if (res.ok) {
        const jobs = await res.json();
        if (currentWorkspaceScanId !== scanId) return;
        renderWorkspaceExports(jobs);
        const hasPending = jobs.some(j => j.status === "QUEUED" || j.status === "PROCESSING");
        if (!hasPending) {
          clearInterval(exportPollInterval);
        }
      }
    } catch (e) {
      console.debug("Export poll skip:", e);
    } finally {
      inFlight = false;
    }
  }, 2000);
}

function setupReportHubEvents() {
  // Investigation selector dropdown
  const selectEl = el("reportScanSelect");
  if (selectEl) {
    selectEl.addEventListener("change", (e) => {
      const newScanId = e.target.value;
      if (newScanId) {
        state.activeScanId = newScanId;
        loadWorkspaceData(newScanId, true);
      }
    });
  }

  const refreshBtn = el("refreshReportHubBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", async () => {
      if (typeof setButtonLoading === "function") setButtonLoading(refreshBtn, true, "Menyinkronkan...");
      try {
        if (currentWorkspaceScanId) {
          workspaceCache.delete(currentWorkspaceScanId);
          await loadWorkspaceData(currentWorkspaceScanId);
        } else {
          await initReportHub();
        }
      } finally {
        if (typeof setButtonLoading === "function") setButtonLoading(refreshBtn, false);
      }
    });
  }

  // Unified Workspace Tab Switching (Buttons & Mobile Select)
  const switchWorkspaceSubTab = (tabName) => {
    if (!tabName) return;
    document.querySelectorAll(".ws-tab-btn").forEach(b => {
      if (b.getAttribute("data-ws-tab") === tabName) b.classList.add("active");
      else b.classList.remove("active");
    });
    const mobileSelect = el("wsMobileNavSelect");
    if (mobileSelect && mobileSelect.value !== tabName) mobileSelect.value = tabName;

    document.querySelectorAll(".ws-tab-content").forEach(c => c.classList.add("hidden"));
    const targetPane = el(`wsTab${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
    if (targetPane) targetPane.classList.remove("hidden");
    activeWorkspaceTab = tabName;
  };

  document.querySelectorAll(".ws-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-ws-tab");
      switchWorkspaceSubTab(tabName);
    });
  });

  const mobileNavSelect = el("wsMobileNavSelect");
  if (mobileNavSelect) {
    mobileNavSelect.addEventListener("change", (e) => {
      switchWorkspaceSubTab(e.target.value);
    });
  }

  el("wsReloadAttackGraphBtn")?.addEventListener("click", async () => {
    if (!currentWorkspaceScanId) return;
    const scanId = currentWorkspaceScanId;
    const button = el("wsReloadAttackGraphBtn");
    button.disabled = true;
    try {
      const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/attack-chains`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const graph = await res.json();
      if (currentWorkspaceScanId !== scanId) return;
      const canvas = el("wsAttackGraphCanvas");
      canvas.innerHTML = `<p class="text-muted">Relasi aset yang tercatat. Relasi ini bukan bukti rantai eksploitasi berhasil.</p><div class="ws-chain-stepper-grid">${(graph.nodes || []).map(node => `<div class="ws-chain-step-card"><strong>${esc(node.label)}</strong><div>${esc(node.type)}</div></div>`).join("")}</div>`;
    } catch (error) { showToast("Gagal memuat relasi aset: " + error.message, "danger"); }
    finally { button.disabled = false; }
  });

  // Async Export triggers
  document.querySelectorAll(".ws-btn-export").forEach((btn) => {
    btn.addEventListener("click", () => {
      const format = btn.getAttribute("data-format");
      if (format) triggerAsyncExport(format);
    });
  });

  // Table searches
  const assetInput = el("wsAssetSearchInput");
  if (assetInput) {
    assetInput.addEventListener("input", (e) => {
      const q = e.target.value.toLowerCase();
      const assets = (currentWorkspaceData?.assets || []).filter(a =>
        (a.hostname || "").toLowerCase().includes(q) || (a.ip || "").toLowerCase().includes(q)
      );
      renderWorkspaceAssets(assets);
    });
  }

  const serviceInput = el("wsServiceSearchInput");
  if (serviceInput) {
    serviceInput.addEventListener("input", (e) => {
      const q = e.target.value.toLowerCase();
      const svcs = (currentWorkspaceData?.services || []).filter(s =>
        (s.service || s.service_name || "").toLowerCase().includes(q) ||
        String(s.port).includes(q) ||
        (s.host || "").toLowerCase().includes(q) ||
        (s.banner || "").toLowerCase().includes(q)
      );
      renderWorkspaceServices(svcs);
    });
  }

  const endpointInput = el("wsEndpointSearchInput");
  if (endpointInput) {
    endpointInput.addEventListener("input", (e) => {
      const q = e.target.value.toLowerCase();
      const eps = (currentWorkspaceData?.endpoints || []).filter(u =>
        (u.url || "").toLowerCase().includes(q) || (u.method || "").toLowerCase().includes(q)
      );
      renderWorkspaceEndpoints(eps);
    });
  }

  const findingInput = el("wsFindingSearchInput");
  const findingFilter = el("wsFindingSevFilter");
  const filterFindings = () => {
    const q = (findingInput?.value || "").toLowerCase();
    const sev = findingFilter?.value || "ALL";
    let list = currentWorkspaceData?.findings || [];
    if (sev !== "ALL") {
      list = list.filter(f => (f.severity || "").toUpperCase() === sev);
    }
    if (q) {
      list = list.filter(f =>
        (f.title || "").toLowerCase().includes(q) ||
        (f.cwe_id || "").toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        (f.location || f.url || "").toLowerCase().includes(q)
      );
    }
    renderWorkspaceFindings(list);
  };

  if (findingInput) findingInput.addEventListener("input", filterFindings);
  if (findingFilter) findingFilter.addEventListener("change", filterFindings);
}

function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

// Interactive PoC Tab Switcher for Finding Cards
window.switchCardPocTab = function(findingId, tabKey, btn) {
  const card = el(`finding-card-${findingId}`);
  if (!card) return;

  card.querySelectorAll(".ws-poc-tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  card.querySelectorAll(".ws-poc-code-pane").forEach(p => p.classList.add("hidden"));
  const targetPane = el(`poc-pane-${findingId}-${tabKey}`);
  if (targetPane) targetPane.classList.remove("hidden");
};

// Copy active card code snippet
window.copyCardActivePoc = function(findingId, btn) {
  const card = el(`finding-card-${findingId}`);
  if (!card) return;

  const activePane = card.querySelector(".ws-poc-code-pane:not(.hidden)");
  if (!activePane) return;

  const textToCopy = activePane.innerText || activePane.textContent;
  writeClipboard(textToCopy).then(() => {
    const originalText = btn.textContent;
    btn.textContent = "✅ Copied!";
    btn.classList.add("btn-success");
    setTimeout(() => {
      btn.textContent = originalText;
      btn.classList.remove("btn-success");
    }, 2000);
  }).catch(err => {
    console.error("Failed to copy:", err);
  });
};

// Download standalone Python PoC file
window.downloadSingleFindingPoC = function(findingId) {
  const finding = (currentWorkspaceData?.findings || []).find(x => x.id === findingId);
  const dossier = finding?.poc_dossier || {};
  const code = dossier.python_poc || finding?.python_poc || `#!/usr/bin/env python3\n# PoC for ${finding?.title || findingId}\nprint("No PoC script generated.")\n`;
  const blob = new Blob([code], { type: "text/x-python" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `poc_${(finding?.finding_code || findingId).toLowerCase().replace(/[^a-z0-9_-]/g, '_')}.py`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// Open Comprehensive Finding PoC Dossier Modal
window.openFindingPocDossier = async function(findingId) {
  let modal = el("wsFindingPocModal");
  if (!modal) {
    console.warn("wsFindingPocModal not found in DOM");
    return;
  }

  const finding = (currentWorkspaceData?.findings || []).find(x => x.id === findingId);
  const modalBody = el("wsPocModalBody");
  if (!modalBody) return;

  modalBody.innerHTML = `
    <div class="p-5 text-center text-muted">
      <div class="spinner-inline mb-2">⚡</div>
      <div>Memuat berkas PoC lengkap & verifikasi bukti kriptografis...</div>
    </div>
  `;
  modal.classList.remove("hidden");

  try {
    let dossier = finding?.poc_dossier;
    if (!dossier) {
      const res = await authFetch(`${API_BASE}/findings/${encodeURIComponent(findingId)}/poc`);
      if (res.ok) {
        const data = await res.json();
        dossier = data.dossier;
      }
    }

    const sev = (finding?.severity || dossier?.severity || "INFO").toUpperCase();
    const title = finding?.title || dossier?.title || "Security Finding";
    const code = finding?.finding_code || `INV-F-${findingId.slice(0, 6)}`;
    const cwe = dossier?.cwe_id || finding?.cwe_id || "Belum dipetakan";
    const cve = dossier?.cve_id || finding?.cve_id || "";
    const cvss = dossier?.cvss_score || finding?.cvss_score || "-";
    const reproSteps = dossier?.reproduction_steps || [];
    const ss = dossier?.screenshot || {};
    const expected = dossier?.expected_behavior || "Perilaku yang diharapkan belum dicatat.";
    const actual = dossier?.actual_behavior || finding?.technical_details || "Perilaku aktual belum dicatat.";

    const sevBadge = el("wsPocModalSevBadge");
    if (sevBadge) {
      sevBadge.className = `severity-badge severity-${sev.toLowerCase()}`;
      sevBadge.textContent = sev;
    }
    const modalTitle = el("wsPocModalTitle");
    if (modalTitle) {
      modalTitle.textContent = `${code}: ${title}`;
    }

    let screenshotSection = "";
    if (ss.has_screenshot && ss.image_url) {
      screenshotSection = `
        <div class="poc-section mt-4">
          <h4 class="poc-section-heading">📸 Visual Evidence (Real Browser Screenshot)</h4>
          <div class="ws-screenshot-modal-wrap mt-2" onclick="openScreenshotZoom(${jsArg(ss.image_url)}, ${jsArg(ss.caption || title)})">
            <img src="${esc(ss.image_url)}" alt="Visual Proof Capture" class="ws-screenshot-full-img" />
          </div>
          <div class="text-xs text-muted mt-1">${esc(ss.caption || '')} (Klik gambar untuk zoom layar penuh)</div>
        </div>
      `;
    } else {
      screenshotSection = `
        <div class="poc-section mt-4">
          <div class="ws-screenshot-note">
            <strong>📸 Status Bukti Visual:</strong> ${esc(ss.explanation_if_none || 'Bukti visual browser tidak berlaku untuk endpoint ini. Bukti HTTP wire request & response lengkap tervalidasi.')}
          </div>
        </div>
      `;
    }

    modalBody.innerHTML = `
      <div class="poc-dossier-layout">
        <!-- Metadata Strip -->
        <div class="poc-meta-strip">
          <div class="poc-meta-item"><strong>Target URL:</strong> <code>${esc(dossier?.target_url || finding?.location || '-')}</code></div>
          <div class="poc-meta-item"><strong>CWE:</strong> <span class="pill pill-neutral font-mono">${esc(cwe)}</span></div>
          ${cve ? `<div class="poc-meta-item"><strong>CVE:</strong> <span class="pill pill-danger font-mono font-bold">${esc(cve)}</span></div>` : ''}
          <div class="poc-meta-item"><strong>CVSS (versi belum dicatat):</strong> <span class="pill pill-danger font-bold">${esc(String(cvss))}</span></div>
          <div class="poc-meta-item"><strong>Method:</strong> <span class="pill pill-primary">${esc(dossier?.method || 'GET')}</span></div>
          <div class="poc-meta-item"><strong>Parameter:</strong> <code>${esc(dossier?.parameter || 'N/A')}</code></div>
        </div>

        <!-- Summary & Impact -->
        <div class="poc-section mt-3">
          <h4 class="poc-section-heading">📑 Ringkasan & Dampak Risiko</h4>
          <p class="text-sm text-secondary">${esc(finding?.description || finding?.executive_explanation || dossier?.description || 'Kerentanan terkonfirmasi pada target.')}</p>
        </div>

        <!-- Step-by-Step Reproduction Guide -->
        <div class="poc-section mt-3">
          <h4 class="poc-section-heading">📋 Panduan Langkah-demi-Langkah Reproduksi (Manual PoC)</h4>
          <ol class="poc-numbered-steps">
            ${reproSteps.map(st => `<li>${esc(st)}</li>`).join("")}
          </ol>
        </div>

        <!-- Exploit Demonstrator Multi-Tab -->
        <div class="poc-section mt-3">
          <h4 class="poc-section-heading">💻 Demonstrasi Kode Eksploitasi & Verifikasi</h4>
          <div class="ws-poc-tab-nav">
            <button class="ws-poc-tab-btn active" onclick="switchModalPocTab('python', this)">🐍 Python PoC Script</button>
            <button class="ws-poc-tab-btn" onclick="switchModalPocTab('curl', this)">⚡ cURL CLI Command</button>
            <button class="ws-poc-tab-btn" onclick="switchModalPocTab('raw_req', this)">📡 Raw HTTP Request</button>
            <button class="ws-poc-tab-btn" onclick="switchModalPocTab('raw_resp', this)">📥 Raw Response Proof</button>
            <button class="btn btn-secondary btn-xs ml-auto" onclick="copyActiveModalPoc(this)">📋 Copy Selected Code</button>
          </div>
          <div class="ws-poc-tab-content-wrap mt-2">
            <pre class="ws-poc-code-pane active font-mono text-xs" id="modal-poc-pane-python"><code>${esc(dossier?.python_poc || '')}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="modal-poc-pane-curl"><code>${esc(dossier?.curl_command || '')}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="modal-poc-pane-raw_req"><code>${esc(dossier?.raw_http_request || '')}</code></pre>
            <pre class="ws-poc-code-pane hidden font-mono text-xs" id="modal-poc-pane-raw_resp"><code>${esc(dossier?.raw_http_response || '')}</code></pre>
          </div>
        </div>

        <!-- Behavioral Comparison -->
        <div class="poc-section mt-3">
          <h4 class="poc-section-heading">⚖️ Analisis Kontras Perilaku Server</h4>
          <div class="ws-behavior-box">
            <div class="behavior-row">
              <span class="behavior-tag tag-expected">✅ Perilaku Aman:</span>
              <span class="behavior-text">${esc(expected)}</span>
            </div>
            <div class="behavior-row mt-2">
              <span class="behavior-tag tag-actual">❌ Perilaku Rentan:</span>
              <span class="behavior-text">${esc(actual)}</span>
            </div>
          </div>
        </div>

        ${screenshotSection}

        <!-- Remediation Playbook -->
        <div class="poc-section mt-3">
          <h4 class="poc-section-heading">🛡️ Panduan Perbaikan / Remediasi Developer</h4>
          <ul class="poc-bullet-list">
            ${(dossier?.remediation_playbook || [finding?.remediation || 'Gunakan parameterized queries dan validasi ketat.']).map(r => `<li>${esc(r)}</li>`).join("")}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    modalBody.innerHTML = `<div class="p-4 text-danger">Gagal memuat detail PoC: ${esc(err.message)}</div>`;
  }
};

window.closeFindingPocModal = function() {
  el("wsFindingPocModal")?.classList.add("hidden");
};

window.switchModalPocTab = function(tabKey, btn) {
  const modal = el("wsFindingPocModal");
  if (!modal) return;

  modal.querySelectorAll(".ws-poc-tab-btn").forEach(b => b.classList.remove("active"));
  if (btn) btn.classList.add("active");

  modal.querySelectorAll(".ws-poc-code-pane").forEach(p => p.classList.add("hidden"));
  const target = el(`modal-poc-pane-${tabKey}`);
  if (target) target.classList.remove("hidden");
};

window.copyActiveModalPoc = function(btn) {
  const modal = el("wsFindingPocModal");
  if (!modal) return;

  const activePane = modal.querySelector(".ws-poc-code-pane:not(.hidden)");
  if (!activePane) return;

  const textToCopy = activePane.innerText || activePane.textContent;
  writeClipboard(textToCopy).then(() => {
    const orig = btn.textContent;
    btn.textContent = "✅ Copied!";
    btn.classList.add("btn-success");
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove("btn-success");
    }, 2000);
  });
};

// Screenshot Zoom Lightbox Modal
window.openScreenshotZoom = function(imgUrl, caption) {
  let lightbox = el("wsScreenshotLightbox");
  if (!lightbox) {
    lightbox = document.createElement("div");
    lightbox.id = "wsScreenshotLightbox";
    lightbox.className = "modal-backdrop ws-lightbox-backdrop";
    lightbox.innerHTML = `
      <div class="ws-lightbox-container">
        <button class="ws-lightbox-close" onclick="closeScreenshotZoom()">✕</button>
        <img id="wsLightboxImg" class="ws-lightbox-img" src="" alt="Screenshot" />
        <div id="wsLightboxCaption" class="ws-lightbox-caption"></div>
      </div>
    `;
    document.body.appendChild(lightbox);
  }

  el("wsLightboxImg").src = imgUrl;
  el("wsLightboxCaption").textContent = caption || "Visual Browser Evidence Proof";
  lightbox.classList.remove("hidden");
};

window.closeScreenshotZoom = function() {
  el("wsScreenshotLightbox")?.classList.add("hidden");
};
