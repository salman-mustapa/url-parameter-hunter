/**
 * modals.js — Contextual Explorer Modals & Multi-Format Security Report Hub
 * Attack Surface & Parameter Intelligence Platform
 */

async function ensureActiveScanId() {
  if (state.activeScanId) return state.activeScanId;
  try {
    const res = await authFetch(`${API_BASE}/scans`);
    const scans = await res.json();
    if (scans && scans.length > 0) {
      state.activeScanId = scans[0].id;
      if (scans[0].root_domain) state.activeTarget = scans[0].root_domain;
      return state.activeScanId;
    }
  } catch (e) { }
  return null;
}

// --------------------------------------------------------------------------
// Port Matrix Explorer Modal
// --------------------------------------------------------------------------
function openPortsModal() {
  const modal = el("portsModal");
  if (modal) {
    modal.classList.remove("hidden");
    state.currentPortFilter = "ALL";
    if (el("portSearchInput")) el("portSearchInput").value = "";
    document.querySelectorAll(".port-filter-pill").forEach(p => {
      p.classList.toggle("active", p.dataset.portFilter === "ALL");
    });
    currentPortsPage = 1;
    loadAllPorts();
  }
}

async function loadAllPorts() {
  const container = el("portsMatrixContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat matriks port.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar port seluruh aset...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/ports/all`);
    const ports = await res.json();
    state.allPortsData = ports || [];
    if (state.allPortsData.length) { state.counters.ports = state.allPortsData.length; if (typeof updateCounterDisplays === "function") updateCounterDisplays(); }
    renderPortsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat ports: ${err.message}</div>`;
  }
}

let currentPortsPage = 1;
let currentParamsPage = 1;
let currentUrlsPage = 1;
const MODAL_CHUNK_SIZE = 25;

function renderModalPagination(currentPage, totalPages, totalItems, onPageChangeFn) {
  if (totalPages <= 1) {
    return `<div class="modal-pagination-simple">Total: <strong>${totalItems}</strong> item</div>`;
  }
  const startIdx = (currentPage - 1) * MODAL_CHUNK_SIZE + 1;
  const endIdx = Math.min(currentPage * MODAL_CHUNK_SIZE, totalItems);
  return `
    <div class="modal-pagination-bar">
      <span class="modal-pagination-info">Menampilkan <strong>${startIdx}–${endIdx}</strong> dari <strong>${totalItems}</strong> item</span>
      <div class="modal-pagination-controls">
        <button class="btn btn-secondary btn-xs" ${currentPage <= 1 ? 'disabled' : ''} onclick="${onPageChangeFn}(${currentPage - 1})">◀ Sebelumnya</button>
        <span class="modal-page-chip">Hal ${currentPage} / ${totalPages}</span>
        <button class="btn btn-secondary btn-xs" ${currentPage >= totalPages ? 'disabled' : ''} onclick="${onPageChangeFn}(${currentPage + 1})">Berikutnya ▶</button>
      </div>
    </div>
  `;
}

function setPortsPage(p) {
  currentPortsPage = p;
  renderPortsMatrix();
}
window.setPortsPage = setPortsPage;

function setParamsPage(p) {
  currentParamsPage = p;
  renderParamsMatrix();
}
window.setParamsPage = setParamsPage;

function setUrlsPage(p) {
  currentUrlsPage = p;
  renderUrlsMatrix();
}
window.setUrlsPage = setUrlsPage;

function renderPortsMatrix() {
  const container = el("portsMatrixContainer");
  if (!container) return;

  const query = (el("portSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentPortFilter;

  const filtered = state.allPortsData.filter((p) => {
    const matchQuery = !query ||
      p.hostname.toLowerCase().includes(query) ||
      (p.ip && p.ip.includes(query)) ||
      String(p.port).includes(query) ||
      (p.service && p.service.toLowerCase().includes(query)) ||
      (p.banner && p.banner.toLowerCase().includes(query));

    if (!matchQuery) return false;

    if (filter === "ALL") return true;
    if (filter === "80") return p.port === 80;
    if (filter === "443") return p.port === 443;
    if (filter === "WEB_ALT") return [8080, 8443, 8000, 8888, 3000, 5000, 9000, 9001].includes(p.port);
    if (filter === "DB") return [3306, 5432, 6379, 27017, 1433, 1521].includes(p.port);
    if (filter === "SSH") return p.port === 22;
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada port yang cocok dengan filter atau kata kunci.</div>`;
    return;
  }

  const totalPages = Math.ceil(filtered.length / MODAL_CHUNK_SIZE) || 1;
  if (currentPortsPage > totalPages) currentPortsPage = 1;
  if (currentPortsPage < 1) currentPortsPage = 1;

  const paged = filtered.slice((currentPortsPage - 1) * MODAL_CHUNK_SIZE, currentPortsPage * MODAL_CHUNK_SIZE);

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Host / Subdomain</th>
          <th>IP Address</th>
          <th>Port</th>
          <th>Proto</th>
          <th>Service</th>
          <th>Banner / Signature</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody>
  `;

  paged.forEach((p) => {
    html += `
      <tr>
        <td><strong>${esc(p.hostname)}</strong></td>
        <td><code>${esc(p.ip || '-')}</code></td>
        <td><span class="port-badge">${p.port}</span></td>
        <td>${esc(p.protocol.toUpperCase())}</td>
        <td>${esc(p.service || '-')}</td>
        <td class="banner-cell"><code>${esc(p.banner || '-')}</code></td>
        <td>
          ${p.direct_url ? `<a href="${esc(safeLink(p.direct_url))}" target="_blank" rel="noopener" class="link-btn">🌐 Buka Web</a>` : '-'}
        </td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  html += renderModalPagination(currentPortsPage, totalPages, filtered.length, "setPortsPage");
  container.innerHTML = html;
}

// --------------------------------------------------------------------------
// Parameter Discovery Explorer Modal
// --------------------------------------------------------------------------
function openParamsModal() {
  const modal = el("paramsModal");
  if (modal) {
    modal.classList.remove("hidden");
    currentParamsPage = 1;
    loadAllParameters();
  }
}

async function loadAllParameters() {
  const container = el("paramsMatrixContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat daftar parameter.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar parameter seluruh endpoint...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/parameters/all`);
    const params = await res.json();
    state.allParamsData = params || [];
    currentParamsPage = 1;
    renderParamsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat parameters: ${err.message}</div>`;
  }
}

function renderParamsMatrix() {
  const container = el("paramsMatrixContainer");
  if (!container) return;

  const query = (el("paramSearchInput")?.value || "").trim().toLowerCase();

  const filtered = state.allParamsData.filter((p) => {
    return !query ||
      p.name.toLowerCase().includes(query) ||
      p.location.toLowerCase().includes(query) ||
      p.url.toLowerCase().includes(query) ||
      p.host.toLowerCase().includes(query);
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada parameter yang cocok dengan kata kunci pencarian.</div>`;
    return;
  }

  const totalPages = Math.ceil(filtered.length / MODAL_CHUNK_SIZE) || 1;
  if (currentParamsPage > totalPages) currentParamsPage = 1;
  if (currentParamsPage < 1) currentParamsPage = 1;

  const paged = filtered.slice((currentParamsPage - 1) * MODAL_CHUNK_SIZE, currentParamsPage * MODAL_CHUNK_SIZE);

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Nama Parameter</th>
          <th>Lokasi</th>
          <th>Host Target</th>
          <th>Endpoint URL</th>
          <th>Tipe</th>
          <th>Confidence</th>
        </tr>
      </thead>
      <tbody>
  `;

  paged.forEach((p) => {
    html += `
      <tr>
        <td><strong class="param-name-pill">${esc(p.name)}</strong></td>
        <td><span class="loc-badge">${esc(p.location)}</span></td>
        <td><strong>${esc(p.host)}</strong></td>
        <td><a href="${esc(safeLink(p.url))}" target="_blank" rel="noopener" class="endpoint-link">${esc(p.url)}</a></td>
        <td>${esc(p.type || 'string')}</td>
        <td>${(Number(p.confidence || 0) * 100).toFixed(0)}%</td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  html += renderModalPagination(currentParamsPage, totalPages, filtered.length, "setParamsPage");
  container.innerHTML = html;
}

// --------------------------------------------------------------------------
// Discovered URLs & Endpoints Explorer Modal
// --------------------------------------------------------------------------
function openUrlsModal() {
  const modal = el("urlsModal");
  if (modal) {
    modal.classList.remove("hidden");
    state.currentUrlFilter = "ALL";
    if (el("urlSearchInput")) el("urlSearchInput").value = "";
    document.querySelectorAll(".url-filter-pill").forEach(p => {
      p.classList.toggle("active", p.dataset.urlFilter === "ALL");
    });
    currentUrlsPage = 1;
    loadAllUrls();
  }
}

async function loadAllUrls() {
  const container = el("urlsMatrixContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat daftar URL.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar seluruh endpoint URL...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/urls/all`);
    const urls = await res.json();
    state.allUrlsData = urls || [];
    currentUrlsPage = 1;
    renderUrlsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat URLs: ${err.message}</div>`;
  }
}

function renderUrlsMatrix() {
  const container = el("urlsMatrixContainer");
  if (!container) return;

  const query = (el("urlSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentUrlFilter || "ALL";

  const filtered = state.allUrlsData.filter((u) => {
    const matchQuery = !query ||
      u.url.toLowerCase().includes(query) ||
      u.path.toLowerCase().includes(query) ||
      u.hostname.toLowerCase().includes(query) ||
      String(u.status_code || "").includes(query);

    if (!matchQuery) return false;

    const st = Number(u.status_code || 0);
    if (filter === "ALL") return true;
    if (filter === "200") return st === 200;
    if (filter === "REDIRECT") return st >= 300 && st < 400;
    if (filter === "CLIENT_ERR") return st >= 400 && st < 500;
    if (filter === "SERVER_ERR") return st >= 500;
    if (filter === "HAS_PARAMS") return (u.parameters_count || 0) > 0;
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada URL yang cocok dengan filter atau kata kunci pencarian.</div>`;
    return;
  }

  const totalPages = Math.ceil(filtered.length / MODAL_CHUNK_SIZE) || 1;
  if (currentUrlsPage > totalPages) currentUrlsPage = 1;
  if (currentUrlsPage < 1) currentUrlsPage = 1;

  const paged = filtered.slice((currentUrlsPage - 1) * MODAL_CHUNK_SIZE, currentUrlsPage * MODAL_CHUNK_SIZE);

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Status</th>
          <th>Endpoint URL</th>
          <th>Host Target</th>
          <th>Params</th>
          <th>Title / Context</th>
        </tr>
      </thead>
      <tbody>
  `;

  paged.forEach((u) => {
    const st = Number(u.status_code || 200);
    let stClass = "status-200";
    if (st >= 300 && st < 400) stClass = "status-300";
    else if (st >= 400 && st < 500) stClass = "status-400";
    else if (st >= 500) stClass = "status-500";

    html += `
      <tr>
        <td><span class="badge ${stClass}">${st}</span></td>
        <td><a href="${esc(safeLink(u.url))}" target="_blank" rel="noopener" class="endpoint-link mono">${esc(u.url)}</a></td>
        <td><strong>${esc(u.hostname)}</strong></td>
        <td><span class="badge badge-info">${u.parameters_count || 0} params</span></td>
        <td><small>${esc(u.title || '-')}</small></td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  html += renderModalPagination(currentUrlsPage, totalPages, filtered.length, "setUrlsPage");
  container.innerHTML = html;
}

// --------------------------------------------------------------------------
// Technology Stack & Fingerprints Matrix Modal
// --------------------------------------------------------------------------
function openTechsModal() {
  const modal = el("techsModal");
  if (modal) {
    modal.classList.remove("hidden");
    state.currentTechFilter = "ALL";
    if (el("techSearchInput")) el("techSearchInput").value = "";
    document.querySelectorAll(".tech-filter-pill").forEach(p => {
      p.classList.toggle("active", p.dataset.techFilter === "ALL");
    });
    loadAllTechnologies();
  }
}

async function loadAllTechnologies() {
  const container = el("techsMatrixContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat matriks teknologi.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar teknologi seluruh aset...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/technologies/all`);
    const techs = await res.json();
    state.allTechsData = techs || [];
    renderTechsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat teknologi: ${err.message}</div>`;
  }
}

function renderTechsMatrix() {
  const container = el("techsMatrixContainer");
  if (!container) return;

  const query = (el("techSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentTechFilter || "ALL";

  const filtered = state.allTechsData.filter((t) => {
    const matchQuery = !query ||
      t.name.toLowerCase().includes(query) ||
      (t.version && t.version.toLowerCase().includes(query)) ||
      (t.category && t.category.toLowerCase().includes(query)) ||
      t.hostname.toLowerCase().includes(query);

    if (!matchQuery) return false;

    const cat = (t.category || "").toUpperCase();
    if (filter === "ALL") return true;
    if (filter === "SERVER") return cat.includes("SERVER") || ["NGINX", "APACHE", "IIS", "CADDY", "LITESPEED", "CLOUDFLARE"].some(k => t.name.toUpperCase().includes(k));
    if (filter === "CMS") return cat.includes("CMS") || ["WORDPRESS", "DRUPAL", "JOOMLA"].some(k => t.name.toUpperCase().includes(k));
    if (filter === "FRAMEWORK") return cat.includes("FRAMEWORK") || ["LARAVEL", "DJANGO", "SPRING", "EXPRESS", "RAILS", "REACT", "VUE", "ANGULAR", "NEXT", "NUXT"].some(k => t.name.toUpperCase().includes(k));
    if (filter === "CDN_WAF") return cat.includes("CDN") || cat.includes("WAF") || ["CLOUDFLARE", "AWS", "AKAMAI", "FASTLY", "INCAPSULA"].some(k => t.name.toUpperCase().includes(k));
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada teknologi yang cocok dengan filter atau kata kunci pencarian.</div>`;
    return;
  }

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Teknologi</th>
          <th>Versi</th>
          <th>Kategori</th>
          <th>Host / Subdomain Terdeteksi</th>
          <th>IP Address</th>
          <th>CPE / Identifikasi</th>
        </tr>
      </thead>
      <tbody>
  `;

  filtered.forEach((t) => {
    html += `
      <tr>
        <td><strong>⚙️ ${esc(t.name)}</strong></td>
        <td><span class="pill pill-neutral">${esc(t.version || 'Detected')}</span></td>
        <td><span class="pill-muted">${esc(t.category || 'General')}</span></td>
        <td><strong>${esc(t.hostname)}</strong></td>
        <td><code>${esc(t.ip || '-')}</code></td>
        <td><span class="text-xs font-mono text-muted">${esc(t.cpe || '-')}</span></td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

// --------------------------------------------------------------------------
// Active Assets & Subdomains Matrix Modal
// --------------------------------------------------------------------------
function openAssetsModal() {
  const modal = el("assetsModal");
  if (modal) {
    modal.classList.remove("hidden");
    loadAllAssets();
  }
}

async function loadAllAssets() {
  const container = el("assetsMatrixContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat matriks aset.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar aset dan subdomain...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/assets/all`);
    const assets = await res.json();
    state.allAssetsData = assets || [];
    renderAssetsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat aset: ${err.message}</div>`;
  }
}

function renderAssetsMatrix() {
  const container = el("assetsMatrixContainer");
  if (!container) return;

  const query = (el("assetSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentAssetFilter || "ALL";

  const filtered = state.allAssetsData.filter((a) => {
    const matchQuery = !query ||
      a.hostname.toLowerCase().includes(query) ||
      (a.ip && a.ip.includes(query)) ||
      (a.technologies && a.technologies.some(t => {
        const tStr = typeof t === 'object' && t ? (t.name || t.product || '') : String(t || '');
        return tStr.toLowerCase().includes(query);
      }));

    if (!matchQuery) return false;

    if (filter === "ALL") return true;
    if (filter === "ROOT") return a.depth === 0;
    if (filter === "SUBDOMAINS") return a.depth > 0;
    if (filter === "HAS_PORTS") return (a.ports_count || 0) > 0;
    if (filter === "HAS_FINDINGS") return (a.findings_count || 0) > 0;
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada aset yang cocok dengan filter atau kata kunci pencarian.</div>`;
    return;
  }

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Hostname</th>
          <th>IP Address</th>
          <th>Level</th>
          <th>Ports</th>
          <th>URLs</th>
          <th>Findings</th>
          <th>Technologies</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
  `;

  filtered.forEach((a) => {
    const techDisplay = (a.technologies || []).slice(0, 3).map(t => typeof t === 'object' && t ? (t.name || t.product || '') : String(t || '')).filter(Boolean).join(', ') || '-';
    html += `
      <tr>
        <td><strong>🌐 ${esc(a.hostname)}</strong></td>
        <td><code>${esc(a.ip || '-')}</code></td>
        <td><span class="pill pill-neutral">Level ${a.depth}</span></td>
        <td><span class="port-badge">${a.ports_count || 0}</span></td>
        <td><span class="pill-muted">${a.urls_count || 0}</span></td>
        <td>
          ${a.findings_count > 0 ? `<span class="severity-badge severity-high">${a.findings_count}</span>` : '<span class="pill-muted">0</span>'}
        </td>
        <td><span class="text-xs text-muted">${esc(techDisplay)}</span></td>
        <td>
          <button class="btn btn-secondary btn-xs" onclick="openAssetDetailFromModal(${jsArg(a.id)})">🔍 Inspect</button>
        </td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function openAssetDetailFromModal(assetId) {
  if (el("assetsModal")) el("assetsModal").classList.add("hidden");
  if (typeof openAssetDetailById === "function") {
    openAssetDetailById(assetId);
  }
}

// --------------------------------------------------------------------------
// Security Findings & Vulnerabilities Matrix Modal
// --------------------------------------------------------------------------
function openFindingsModal() {
  const modal = el("findingsModal");
  if (modal) {
    modal.classList.remove("hidden");
    loadAllFindingsModal();
  }
}

async function loadAllFindingsModal() {
  const container = el("findingsModalContainer");
  if (!container) return;

  await ensureActiveScanId();

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat matriks temuan.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar seluruh temuan keamanan...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/findings?scan_id=${encodeURIComponent(state.activeScanId)}`);
    const findings = await res.json();
    state.allFindingsModalData = findings || [];
    renderFindingsModal();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat temuan: ${err.message}</div>`;
  }
}

function renderFindingsModal() {
  const container = el("findingsModalContainer");
  if (!container) return;

  const query = (el("findingModalSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentFindingModalFilter || "ALL";

  const filtered = state.allFindingsModalData.filter((f) => {
    const matchQuery = !query ||
      f.title.toLowerCase().includes(query) ||
      (f.finding_code && f.finding_code.toLowerCase().includes(query)) ||
      (f.cwe_id && f.cwe_id.toLowerCase().includes(query)) ||
      (f.cve_id && f.cve_id.toLowerCase().includes(query)) ||
      (f.asset_hostname && f.asset_hostname.toLowerCase().includes(query));

    if (!matchQuery) return false;

    const sev = (f.severity || "").toUpperCase();
    if (filter === "ALL") return true;
    if (filter === "CRITICAL") return sev === "CRITICAL";
    if (filter === "HIGH") return sev === "HIGH";
    if (filter === "MEDIUM") return sev === "MEDIUM";
    if (filter === "LOW") return sev === "LOW";
    if (filter === "CONFIRMED") return (f.status || "").toUpperCase() === "CONFIRMED" || (f.evidence_level || "").toUpperCase() === "E3";
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada temuan yang cocok dengan filter atau kata kunci pencarian.</div>`;
    return;
  }

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Kode & Judul Temuan</th>
          <th>Host Target</th>
          <th>CWE / CVSS</th>
          <th>Evidence</th>
          <th>Status</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody>
  `;

  filtered.forEach((f) => {
    const sev = (f.severity || "INFO").toUpperCase();
    html += `
      <tr>
        <td><span class="severity-badge severity-${sev.toLowerCase()}">${sev}</span></td>
        <td>
          <strong>${esc(f.finding_code || f.id)}</strong>: ${esc(f.title)}
        </td>
        <td><strong>${esc(f.asset_hostname || '-')}</strong></td>
        <td><code>${esc(f.cwe_id || '-')}</code> ${f.cvss_score ? `(${f.cvss_score})` : ''}</td>
        <td><span class="badge-e0">${esc(f.evidence_level || "E0")}</span></td>
        <td><span class="status-badge status-${(f.status || 'open').toLowerCase()}">${esc(f.status || 'OPEN')}</span></td>
        <td>
          <button class="btn btn-primary btn-xs" onclick="openFindingDetailFromModal(${jsArg(f.id)})">🔒 Detail (V5)</button>
        </td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function openFindingDetailFromModal(findingId) {
  if (el("findingsModal")) el("findingsModal").classList.add("hidden");
  if (typeof openFindingDetail === "function") {
    openFindingDetail(findingId);
  }
}
// --------------------------------------------------------------------------
// Security Assessment Report Hub Modal (§52, §53, §100)
// --------------------------------------------------------------------------
function openReportModal() {
  const sid = state.activeScanId;
  if (!sid) {
    showToast("Silakan pilih target dari Riwayat Scan terlebih dahulu untuk membuka laporan eksekutif.", "warning");
    switchViewTab("history");
    return;
  }
  const modal = el("reportModal");
  if (!modal) return;

  if (el("reportModalTarget")) el("reportModalTarget").textContent = state.activeTarget || "Target Aktif";
  if (el("reportModalScanId")) el("reportModalScanId").textContent = `ID: ${sid}`;
  if (el("reportMetricAssets")) el("reportMetricAssets").textContent = state.counters.assets || 0;
  if (el("reportMetricPorts")) el("reportMetricPorts").textContent = state.counters.ports || 0;
  if (el("reportMetricUrls")) el("reportMetricUrls").textContent = state.counters.urls || 0;
  if (el("reportMetricParams")) el("reportMetricParams").textContent = state.counters.params || 0;
  if (el("reportMetricFindings")) el("reportMetricFindings").textContent = state.counters.findings || 0;

  modal.classList.remove("hidden");
}

function setupReportModal() {
  el("dashReportBBBtn")?.addEventListener("click", () => {
    if (!state.activeScanId) return showToast("Pilih scan terlebih dahulu.", "warning");
    window.open(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/report/markdown`, "_blank");
  });
  el("dashReportCVEBtn")?.addEventListener("click", () => {
    switchViewTab("reports");
    showToast("Pilih temuan dan buka detailnya untuk membuat draft riset CVE. CVE memerlukan pemeriksaan produk/versi dan koordinasi vendor.", "info");
  });
  el("dashReportJSONBtn")?.addEventListener("click", exportScanJSON);
  const modal = el("reportModal");
  if (!modal) return;

  const closeBtn = el("closeReportModalBtn");
  if (closeBtn) closeBtn.addEventListener("click", () => modal.classList.add("hidden"));

  modal.addEventListener("click", (e) => {
    if (e.target === modal) modal.classList.add("hidden");
  });

  // 1. PDF Executive Report
  const pdfBtn = el("downloadPdfReportBtn");
  if (pdfBtn) {
    pdfBtn.addEventListener("click", () => {
      const sid = state.activeScanId;
      if (!sid) return;
      window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/report/pdf`, "_blank");
    });
  }

  // 2. HTML Interactive Report
  const htmlBtn = el("viewHtmlReportBtn");
  if (htmlBtn) {
    htmlBtn.addEventListener("click", () => {
      const sid = state.activeScanId;
      if (!sid) return;
      window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/report/html`, "_blank");
    });
  }

  // 3. Markdown Technical Report
  const mdBtn = el("downloadMdReportBtn");
  if (mdBtn) {
    mdBtn.addEventListener("click", () => {
      const sid = state.activeScanId;
      if (!sid) return;
      window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/report/markdown`, "_blank");
    });
  }

  // 4. Raw JSON Export
  const jsonBtn = el("downloadJsonReportBtn");
  if (jsonBtn) {
    jsonBtn.addEventListener("click", () => {
      exportScanJSON();
    });
  }

  // 5. OpenAPI 3.0 Spec Export
  const openApiBtn = el("downloadOpenApiReportBtn");
  if (openApiBtn) {
    openApiBtn.addEventListener("click", () => {
      downloadOpenApiSpec();
    });
  }

  // Scan Completed Banner Actions
  const bannerReportBtn = el("bannerDownloadReportBtn");
  if (bannerReportBtn) bannerReportBtn.addEventListener("click", openReportModal);

  const bannerDismissBtn = el("bannerDismissBtn");
  if (bannerDismissBtn) {
    bannerDismissBtn.addEventListener("click", () => {
      if (el("scanCompletedBanner")) el("scanCompletedBanner").classList.add("hidden");
    });
  }
}

async function exportScanJSON() {
  if (!state.activeScanId) {
    showToast("Tidak ada sesi scan yang aktif untuk diekspor.", "warning");
    return;
  }
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/report/json`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `hunter_aja_${state.activeScanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("Evidence Package JSON berhasil diunduh.", "success");
  } catch (err) {
    showToast("Gagal ekspor JSON: " + err.message, "danger");
  }
}

// --------------------------------------------------------------------------
// Custom System Toast & Sketch Modal Dialogs
// --------------------------------------------------------------------------
function showToast(message, type = "info", duration = 4000) {
  const container = el("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `system-toast toast-${type}`;
  const icon = type === "success" ? "✅" : (type === "warning" ? "⚠️" : (type === "danger" ? "❌" : "ℹ️"));

  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-text">${esc(message)}</span>
    <button class="toast-close">✕</button>
  `;

  toast.querySelector(".toast-close").addEventListener("click", () => {
    toast.classList.add("toast-fade-out");
    setTimeout(() => toast.remove(), 250);
  });

  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.classList.add("toast-fade-out");
      setTimeout(() => toast.remove(), 250);
    }
  }, duration);
}

let pendingSysConfirmCallback = null;

function showSystemAlert(title, message, icon = "ℹ️") {
  const modal = el("systemConfirmModal");
  if (!modal) return;

  if (el("sysModalTitle")) el("sysModalTitle").textContent = title;
  if (el("sysModalMessage")) el("sysModalMessage").textContent = message;
  if (el("sysModalIcon")) el("sysModalIcon").textContent = icon;

  const cancelBtn = el("sysModalCancelBtn");
  if (cancelBtn) cancelBtn.classList.add("hidden");

  const confirmBtn = el("sysModalConfirmBtn");
  if (confirmBtn) {
    confirmBtn.textContent = "Mengerti";
    confirmBtn.onclick = () => modal.classList.add("hidden");
  }

  const closeBtn = el("sysModalCloseBtn");
  if (closeBtn) closeBtn.onclick = () => modal.classList.add("hidden");

  modal.classList.remove("hidden");
}

function showSystemConfirm(title, message, onConfirm, icon = "⚠️") {
  const modal = el("systemConfirmModal");
  if (!modal) return;

  if (el("sysModalTitle")) el("sysModalTitle").textContent = title;
  if (el("sysModalMessage")) el("sysModalMessage").textContent = message;
  if (el("sysModalIcon")) el("sysModalIcon").textContent = icon;

  const cancelBtn = el("sysModalCancelBtn");
  if (cancelBtn) {
    cancelBtn.classList.remove("hidden");
    cancelBtn.onclick = () => modal.classList.add("hidden");
  }

  const confirmBtn = el("sysModalConfirmBtn");
  if (confirmBtn) {
    confirmBtn.textContent = "Ya, Lanjutkan";
    confirmBtn.onclick = async () => {
      modal.classList.add("hidden");
      if (typeof onConfirm === "function") await onConfirm();
    };
  }

  const closeBtn = el("sysModalCloseBtn");
  if (closeBtn) closeBtn.onclick = () => modal.classList.add("hidden");

  modal.classList.remove("hidden");
}

function showScreenshotLightbox(imgSrc, title = "Screenshot Bukti Validasi", meta = "") {
  const modal = el("screenshotLightboxModal");
  if (!modal) return;

  if (el("lightboxTitle")) el("lightboxTitle").textContent = title;
  const img = el("lightboxImg");
  if (img) {
    img.style.display = "block";
    img.src = imgSrc;
    img.onerror = () => {
      img.style.display = "none";
      if (el("lightboxMeta")) {
        el("lightboxMeta").textContent = `${meta} | [Informasi: Bukti visual proof tersimpan dalam format log cryptographic hash]`;
      }
    };
    img.onload = () => {
      img.style.display = "block";
    };
  }
  if (el("lightboxMeta")) el("lightboxMeta").textContent = meta;

  const closeBtn = el("closeLightboxBtn");
  if (closeBtn) closeBtn.onclick = () => modal.classList.add("hidden");

  modal.classList.remove("hidden");
}

// Expose modal functions to the window object globally
window.openPortsModal = openPortsModal;
window.openParamsModal = openParamsModal;
window.openUrlsModal = openUrlsModal;
window.openTechsModal = openTechsModal;
window.openAssetsModal = openAssetsModal;
window.openFindingsModal = openFindingsModal;
window.showScreenshotLightbox = showScreenshotLightbox;
window.showSystemConfirm = showSystemConfirm;
window.showSystemAlert = showSystemAlert;

function downloadOpenApiSpec() {
  const sid = state.activeScanId;
  if (!sid) {
    if (typeof showToast === "function") showToast("Pilih scan aktif terlebih dahulu.", "warning");
    return;
  }
  window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/export/openapi.json`, "_blank");
}

function openAccountSettingsModal(tab = "notifications") {
  const modal = el("accountSettingsModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  if (typeof loadUserNotificationsConfig === "function") {
    loadUserNotificationsConfig();
  }
}

window.downloadOpenApiSpec = downloadOpenApiSpec;
window.openAccountSettingsModal = openAccountSettingsModal;
window.openReportModal = openReportModal;


