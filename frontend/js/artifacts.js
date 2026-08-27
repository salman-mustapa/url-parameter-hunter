/**
 * artifacts.js — Deep Artifact Intelligence & Security Schema Explorer (V9)
 * Manages captured SQL dumps, CSV exports, logs, credentials, and sanitized exports.
 */

let currentArtifactData = null;
let currentArtifactActiveTab = "schema";

function openArtifactsModal() {
  const modal = document.getElementById("artifactsModal");
  if (modal) {
    modal.classList.remove("hidden");
    loadAllArtifacts();
  }
}

async function loadAllArtifacts() {
  const container = document.getElementById("artifactsMatrixContainer");
  if (!container) return;

  if (typeof ensureActiveScanId === "function") {
    await ensureActiveScanId();
  }

  if (!state.activeScanId) {
    container.innerHTML = `<div class="empty-msg">Pilih atau jalankan scan aktif terlebih dahulu untuk melihat daftar artefak keamanan.</div>`;
    return;
  }

  container.innerHTML = `<div class="empty-msg">Memuat daftar artefak dan database dump...</div>`;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(state.activeScanId)}/artifacts/all`);
    const artifacts = await res.json();
    state.allArtifactsData = artifacts || [];
    renderArtifactsMatrix();
  } catch (err) {
    container.innerHTML = `<div class="empty-msg">Gagal memuat artifacts: ${err.message}</div>`;
  }
}

function renderArtifactsMatrix() {
  const container = document.getElementById("artifactsMatrixContainer");
  if (!container) return;

  const query = (document.getElementById("artifactSearchInput")?.value || "").trim().toLowerCase();
  const filter = state.currentArtifactFilter || "ALL";

  const filtered = (state.allArtifactsData || []).filter((art) => {
    const matchQuery = !query ||
      art.filename.toLowerCase().includes(query) ||
      (art.hostname && art.hostname.toLowerCase().includes(query)) ||
      (art.file_type && art.file_type.toLowerCase().includes(query)) ||
      (art.database_name && art.database_name.toLowerCase().includes(query)) ||
      (art.sha256_hash && art.sha256_hash.toLowerCase().includes(query));

    if (!matchQuery) return false;
    if (filter === "ALL") return true;
    if (filter === "SQL") return art.file_type === "sql_dump" || art.filename.endsWith(".sql");
    if (filter === "CSV") return art.file_type === "csv_export" || art.filename.endsWith(".csv");
    if (filter === "HASHES") return (art.total_hashes || 0) > 0;
    if (filter === "PII") return art.has_pii;
    return true;
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada artefak yang cocok dengan filter atau kata kunci.</div>`;
    return;
  }

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Nama File</th>
          <th>Tipe Artefak</th>
          <th>Host Terkait</th>
          <th>Ukuran</th>
          <th>Tabel DB</th>
          <th>Kredensial / Hashes</th>
          <th>SHA-256 Hash</th>
          <th>Aksi</th>
        </tr>
      </thead>
      <tbody>
  `;

  filtered.forEach((art) => {
    const icon = art.file_type === "sql_dump" ? "🗄️" : (art.file_type === "csv_export" ? "📊" : "📄");
    const sizeKB = (art.size_bytes / 1024).toFixed(1) + " KB";
    const shortSha = art.sha256_hash ? art.sha256_hash.substring(0, 10) + "..." : "-";

    html += `
      <tr>
        <td><strong>${icon} ${esc(art.filename)}</strong></td>
        <td><span class="pill pill-neutral">${esc(art.file_type.toUpperCase())}</span></td>
        <td><code>${esc(art.hostname || '-')}</code></td>
        <td><span class="pill-muted">${sizeKB}</span></td>
        <td><strong>${art.total_tables || 0}</strong></td>
        <td>
          ${art.total_hashes > 0 ? `<span class="severity-badge severity-critical">${art.total_hashes} Hashes</span>` : (art.total_users > 0 ? `<span class="severity-badge severity-high">${art.total_users} Users</span>` : '<span class="pill-muted">0</span>')}
        </td>
        <td><code class="text-xs">${esc(shortSha)}</code></td>
        <td>
          <button class="btn btn-secondary btn-xs" onclick="openArtifactDetailModal('${esc(art.id)}')">🔍 Inspect Intelligence</button>
        </td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

async function openArtifactDetailModal(artifactId) {
  const modal = document.getElementById("artifactDetailModal");
  if (!modal) return;
  modal.classList.remove("hidden");

  const titleEl = document.getElementById("artifactDetailTitle");
  const metaEl = document.getElementById("artifactDetailMeta");
  const contentEl = document.getElementById("artifactDetailContent");

  if (titleEl) titleEl.textContent = "Memuat Artefak...";
  if (contentEl) contentEl.innerHTML = `<div class="empty-msg">Mengambil struktur skema dan entitas artefak...</div>`;

  try {
    const res = await authFetch(`${API_BASE}/artifacts/${encodeURIComponent(artifactId)}`);
    const data = await res.json();
    currentArtifactData = data;

    if (titleEl) titleEl.textContent = `📦 ${data.filename}`;
    if (metaEl) {
      const sizeKB = (data.size_bytes / 1024).toFixed(1) + " KB";
      metaEl.textContent = `Tipe: ${data.file_type.toUpperCase()} · Host: ${data.hostname || '-'} · Ukuran: ${sizeKB} · SHA-256: ${data.sha256_hash}`;
    }

    renderArtifactActiveTab(currentArtifactActiveTab);
  } catch (err) {
    if (contentEl) contentEl.innerHTML = `<div class="empty-msg">Gagal memuat detail artefak: ${err.message}</div>`;
  }
}

function setArtifactTab(tabName) {
  currentArtifactActiveTab = tabName;
  document.querySelectorAll(".art-tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });
  renderArtifactActiveTab(tabName);
}

function renderArtifactActiveTab(tabName) {
  const container = document.getElementById("artifactDetailContent");
  if (!container || !currentArtifactData) return;

  const data = currentArtifactData;
  const schema = data.schema_data || {};
  const entities = data.extracted_entities || {};

  if (tabName === "schema") {
    // 1. Environment File Schema View
    if (data.file_type === "env_file" || schema.parsed_variables) {
      const vars = schema.parsed_variables || {};
      const sensKeys = schema.sensitive_keys || [];
      let html = `
        <div class="db-summary-card">
          <div><strong>Config Type:</strong> <code>ENVIRONMENT / .ENV</code></div>
          <div><strong>Total Variables:</strong> <span>${schema.total_keys || Object.keys(vars).length}</span></div>
          <div><strong>Sensitive Keys:</strong> <span class="severity-badge severity-critical">${sensKeys.length} Secret(s)</span></div>
        </div>
        <table class="detail-table" style="margin-top: 12px;">
          <thead>
            <tr>
              <th>Variable Key</th>
              <th>Sample Value (Masked)</th>
              <th>Sensitivity</th>
            </tr>
          </thead>
          <tbody>
      `;
      Object.entries(vars).forEach(([k, v]) => {
        const isSens = sensKeys.includes(k) || ["PASS", "SECRET", "KEY", "TOKEN", "AUTH", "DATABASE"].some(sk => k.toUpperCase().includes(sk));
        html += `
          <tr>
            <td><code>${esc(k)}</code></td>
            <td><code>${esc(v)}</code></td>
            <td>${isSens ? '<span class="severity-badge severity-critical">⚠️ Secret / Token</span>' : '<span class="pill-muted">Standard</span>'}</td>
          </tr>
        `;
      });
      html += `</tbody></table>`;
      container.innerHTML = html;
      return;
    }

    // 2. CSV Data Export View
    if (data.file_type === "csv_export" || schema.headers) {
      const headers = schema.headers || [];
      const sampleRows = schema.sample_rows || [];
      const piiHeaders = schema.pii_headers || [];

      let html = `
        <div class="db-summary-card">
          <div><strong>Total Rows:</strong> <span>${schema.row_count || 0}</span></div>
          <div><strong>Total Columns:</strong> <span>${schema.column_count || headers.length}</span></div>
          <div><strong>PII Columns:</strong> <span class="severity-badge severity-high">${piiHeaders.length} Column(s)</span></div>
        </div>
        <table class="detail-table" style="margin-top: 12px; font-size: 11px;">
          <thead>
            <tr>
              ${headers.map(h => `<th>${esc(h)} ${piiHeaders.includes(h) ? '<span style="color:#ef4444;">⚠️</span>' : ''}</th>`).join('')}
            </tr>
          </thead>
          <tbody>
      `;
      sampleRows.forEach(row => {
        html += `<tr>${headers.map(h => `<td>${esc(row[h] || '')}</td>`).join('')}</tr>`;
      });
      html += `</tbody></table>`;
      container.innerHTML = html;
      return;
    }

    // 2b. Unix passwd File Schema View
    if (data.file_type === "passwd_file" || schema.real_users) {
      const users = schema.real_users || [];
      let html = `
        <div class="db-summary-card">
          <div><strong>Config Type:</strong> <code>UNIX PASSWD</code></div>
          <div><strong>Total System Accounts:</strong> <span>${schema.total_entries || users.length}</span></div>
          <div><strong>Real Users (UID &ge; 1000):</strong> <span class="severity-badge severity-high">${users.filter(u => u.uid >= 1000).length} User(s)</span></div>
        </div>
        <table class="detail-table" style="margin-top: 12px;">
          <thead>
            <tr>
              <th>Username</th>
              <th>UID</th>
              <th>GID</th>
              <th>Home Directory</th>
              <th>Login Shell</th>
            </tr>
          </thead>
          <tbody>
      `;
      users.forEach(u => {
        const isRoot = u.username === "root";
        const isReal = u.uid >= 1000;
        const badge = isRoot ? '<span class="severity-badge severity-critical">root</span>' : (isReal ? '<span class="severity-badge severity-high">user</span>' : '<span class="pill-muted">system</span>');
        html += `
          <tr>
            <td><code><strong>${esc(u.username)}</strong></code> ${badge}</td>
            <td><code>${u.uid}</code></td>
            <td><code>${u.gid}</code></td>
            <td><code>${esc(u.home)}</code></td>
            <td><code>${esc(u.shell)}</code></td>
          </tr>
        `;
      });
      html += `</tbody></table>`;
      container.innerHTML = html;
      return;
    }

    // 3. SQL Database Schema View
    const tables = schema.tables || [];
    if (!tables.length) {
      container.innerHTML = `<div class="tab-empty">Tidak ada struktur tabel SQL yang teridentifikasi dalam artefak ini.</div>`;
      return;
    }

    let html = `
      <div class="db-summary-card">
        <div><strong>Database Name:</strong> <code>${esc(schema.database_name || 'N/A')}</code></div>
        <div><strong>Vendor / Dialect:</strong> <span>${esc(schema.vendor || 'Generic SQL')}</span></div>
        <div><strong>Total Tables:</strong> <span>${tables.length}</span></div>
      </div>
      <div class="tables-accordion">
    `;

    tables.forEach((t) => {
      html += `
        <div class="table-card">
          <div class="table-header">
            <h4>📋 Tabel: <strong>${esc(t.table_name)}</strong></h4>
            <span class="pill-muted">${t.columns ? t.columns.length : 0} kolom</span>
          </div>
          <table class="detail-table">
            <thead>
              <tr>
                <th>Nama Kolom</th>
                <th>Tipe Data</th>
                <th>Primary Key</th>
                <th>Sensitivitas / PII</th>
              </tr>
            </thead>
            <tbody>
      `;
      (t.columns || []).forEach((c) => {
        html += `
          <tr>
            <td><code>${esc(c.name)}</code></td>
            <td><span class="pill-muted">${esc(c.type)}</span></td>
            <td>${c.is_primary_key ? '<span class="pill pill-primary">PRIMARY KEY</span>' : '-'}</td>
            <td>${c.is_sensitive ? '<span class="severity-badge severity-critical">⚠️ PII / Secret Field</span>' : '<span class="pill-muted">Standard</span>'}</td>
          </tr>
        `;
      });
      html += `</tbody></table></div>`;
    });

    html += `</div>`;
    container.innerHTML = html;

  } else if (tabName === "credentials") {
    const hashes = entities.hashes || [];
    const users = entities.users || [];

    if (!hashes.length && !users.length) {
      container.innerHTML = `<div class="tab-empty">Tidak ada hash password atau user account yang teridentifikasi dalam dump ini.</div>`;
      return;
    }

    let html = `<h4>🔑 Discovered Credential & Password Hashes (${hashes.length})</h4>`;
    if (hashes.length > 0) {
      html += `
        <table class="detail-table">
          <thead>
            <tr>
              <th>Tabel</th>
              <th>Kolom</th>
              <th>Tipe Algoritma Hash</th>
              <th>Sample Hash (Masked)</th>
            </tr>
          </thead>
          <tbody>
      `;
      hashes.forEach((h) => {
        html += `
          <tr>
            <td><strong>${esc(h.table)}</strong></td>
            <td><code>${esc(h.column)}</code></td>
            <td><span class="severity-badge severity-high">${esc(h.hash_type.toUpperCase())}</span></td>
            <td><code>${esc(h.hash_sample)}</code></td>
          </tr>
        `;
      });
      html += `</tbody></table>`;
    }

    if (users.length > 0) {
      html += `<h4 style="margin-top: 1.5rem;">👤 Discovered User Accounts & Emails (${users.length})</h4>
        <div class="user-pill-grid">
      `;
      users.slice(0, 50).forEach((u) => {
        html += `<span class="pill pill-neutral">${esc(u.identifier)} <small class="text-muted">(${esc(u.table)})</small></span>`;
      });
      html += `</div>`;
    }

    container.innerHTML = html;

  } else if (tabName === "preview") {
    container.innerHTML = `<div class="empty-msg">Mengambil preview artefak...</div>`;
    authFetch(`${API_BASE}/artifacts/${encodeURIComponent(data.id)}/preview`)
      .then((res) => res.json())
      .then((p) => {
        container.innerHTML = `
          <div class="preview-toolbar">
            <button class="btn btn-secondary btn-xs" onclick="navigator.clipboard.writeText(currentArtifactData.rawPreviewText || ''); showToast('Teks preview berhasil disalin!');">📋 Copy Preview</button>
            <a href="${API_BASE}/artifacts/${encodeURIComponent(data.id)}/export-sanitized" target="_blank" class="btn btn-primary btn-xs">🛡️ Download Sanitized Export</a>
            <a href="${API_BASE}/artifacts/${encodeURIComponent(data.id)}/download" target="_blank" class="btn btn-secondary btn-xs">📥 Download Raw Quarantined File</a>
          </div>
          <div class="preview-box">
            <pre><code>${esc(p.sanitized_preview || p.raw_preview || '')}</code></pre>
          </div>
        `;
        currentArtifactData.rawPreviewText = p.raw_preview;
      })
      .catch((err) => {
        container.innerHTML = `<div class="empty-msg">Gagal memuat preview: ${err.message}</div>`;
      });
  }
}
