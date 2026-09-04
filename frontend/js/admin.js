/**
 * admin.js — Administrator Oversight Dashboard, Operational Controls & Health
 * Attack Surface & Parameter Intelligence Platform
 */

async function runSyntheticLab() {
  const button = el("runSyntheticLabBtn");
  const status = el("syntheticLabStatus");
  if (!state.currentUser || state.currentUser.role !== "admin" || button?.disabled) return;
  if (button) button.disabled = true;
  if (status) status.textContent = "Lab berjalan: discovery, validasi, penyimpanan bukti…";
  try {
    const response = await authFetch(`${API_BASE}/labs/synthetic/run`, { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Lab gagal dijalankan");
    if (status) {
      status.textContent = `Lab selesai: ${result.status}. Temuan tersimpan: ${result.finding_ids.length}. `;
      const link = document.createElement("a");
      link.textContent = "Lihat hasil dan laporan";
      link.href = `#/reports?scan_id=${encodeURIComponent(result.scan_id)}`;
      status.appendChild(link);
    }
    await loadAdminData();
  } catch (error) {
    if (status) status.textContent = `Lab gagal: ${error.message}`;
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadAdminData() {
  if (!state.currentUser || state.currentUser.role !== "admin") {
    if (typeof showToast === "function") showToast("Akses hanya untuk Administrator.", "warning");
    return;
  }

  // 1. Load Overview Metrics
  try {
    const res = await authFetch(`${API_BASE}/admin/overview`);
    const data = await res.json();
    if (el("admTotalUsers")) el("admTotalUsers").textContent = data.total_users || 0;
    if (el("admTotalScans")) el("admTotalScans").textContent = data.total_scans || 0;
    if (el("admTotalDomains")) el("admTotalDomains").textContent = data.total_domains || 0;
    if (el("admTotalSubdomains")) el("admTotalSubdomains").textContent = data.total_subdomains || 0;
    if (el("admTotalIps")) el("admTotalIps").textContent = data.total_ips || 0;
    if (el("admTotalFindings")) el("admTotalFindings").textContent = data.total_findings || 0;
  } catch (err) {
    console.error("Admin overview fetch error:", err);
  }

  // 2. Load Active Scans / Operational Panel
  await loadAdminActiveScans();

  // 3. Load System Health & Resources
  await loadAdminHealth();

  // 4. Load User Scrapping Analytics
  try {
    const res = await authFetch(`${API_BASE}/admin/users`);
    const usersData = await res.json();
    const users = Array.isArray(usersData) ? usersData : (Array.isArray(usersData?.users) ? usersData.users : []);
    const tbody = el("adminUsersTbody");
    if (tbody) {
      tbody.innerHTML = "";

      if (!users.length) {
        tbody.innerHTML = `<tr><td colspan="9" class="table-loading">Belum ada data aktivitas pengguna.</td></tr>`;
      } else {
        users.forEach((u) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td><strong>${esc(u.username)}</strong></td>
            <td>${esc(u.email)}</td>
            <td><span class="role-badge ${u.role === 'admin' ? 'role-admin' : 'role-user'}">${esc(u.role.toUpperCase())}</span></td>
            <td><strong>${u.total_scans}</strong></td>
            <td>${u.total_domains} Domain</td>
            <td><span class="tree-node-badge badge-active">${u.total_subdomains}</span></td>
            <td><span class="tree-node-badge badge-ip">${u.total_ips}</span></td>
            <td><span class="tree-node-badge badge-crit">${u.total_findings}</span></td>
            <td>${u.last_scan_date ? new Date(u.last_scan_date).toLocaleString("id-ID") : (u.created_at ? new Date(u.created_at).toLocaleDateString("id-ID") : '-')}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    }
  } catch (err) {
    if (el("adminUsersTbody")) {
      el("adminUsersTbody").innerHTML = `<tr><td colspan="9" class="table-loading">Gagal memuat data pengguna: ${err.message}</td></tr>`;
    }
  }

  // 5. Load Domain Scrapping Audit
  try {
    const res = await authFetch(`${API_BASE}/admin/domains`);
    const domainsData = await res.json();
    const domains = Array.isArray(domainsData) ? domainsData : (Array.isArray(domainsData?.domains) ? domainsData.domains : []);
    const tbody = el("adminDomainsTbody");
    if (tbody) {
      tbody.innerHTML = "";

      if (!domains.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="table-loading">Belum ada domain yang di-scrap.</td></tr>`;
      } else {
        domains.forEach((d) => {
          const tr = document.createElement("tr");
          const usersHtml = (d.scrapped_by || []).map(u => `<span class="user-chip">👤 ${esc(u.username)} (${u.scan_count})</span>`).join(" ");
          tr.innerHTML = `
            <td><strong>🌐 ${esc(d.root_domain)}</strong></td>
            <td><strong>${d.total_scans}</strong></td>
            <td>${usersHtml || '-'}</td>
            <td><span class="tree-node-badge badge-active">${d.total_subdomains} Subdomain</span></td>
            <td><span class="tree-node-badge badge-ip">${d.total_ips} IP</span></td>
            <td><span class="tree-node-badge badge-crit">${d.total_findings} Finding</span></td>
            <td>${d.first_seen ? new Date(d.first_seen).toLocaleDateString("id-ID") : '-'}</td>
            <td>${d.last_scanned ? new Date(d.last_scanned).toLocaleString("id-ID") : '-'}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    }
  } catch (err) {
    if (el("adminDomainsTbody")) {
      el("adminDomainsTbody").innerHTML = `<tr><td colspan="8" class="table-loading">Gagal memuat audit domain: ${err.message}</td></tr>`;
    }
  }

  // 6. Load AI Config
  if (typeof loadAiConfig === "function") {
    loadAiConfig();
  }
}

async function loadAdminActiveScans() {
  const tbody = el("adminActiveScansTbody");
  if (!tbody) return;

  try {
    const res = await authFetch(`${API_BASE}/admin/scans/active`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const scans = await res.json();

    if (el("admActiveCountBadge")) {
      const runningCount = scans.filter(s => (s.status || '').toUpperCase() === 'RUNNING').length;
      el("admActiveCountBadge").textContent = `${runningCount} Running / ${scans.length} Total`;
    }

    if (!scans.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center p-3 text-muted">Tidak ada tugas investigasi aktif atau berjalan saat ini.</td></tr>`;
      return;
    }

    tbody.innerHTML = scans.map((s) => {
      const st = (s.status || 'PENDING').toUpperCase();
      const stClass = st === 'RUNNING' ? 'pill-primary' : (st === 'COMPLETED' ? 'pill-success' : (st === 'PAUSED' ? 'pill-warning' : 'pill-danger'));
      const isRunning = st === 'RUNNING';
      const isPaused = st === 'PAUSED';

      return `
        <tr>
          <td><strong>🌐 ${esc(s.target_url || s.root_domain || '-')}</strong></td>
          <td class="font-mono text-xs">#${esc(s.id.slice(0, 16))}</td>
          <td><span class="pill ${stClass}">${esc(st)}</span></td>
          <td><code>${esc(s.user || s.user_id || 'System')}</code></td>
          <td class="text-xs">${s.started_at ? new Date(s.started_at).toLocaleTimeString('id-ID') : '-'}</td>
          <td class="text-xs">Assets: <strong>${s.progress?.assets || 0}</strong> | Ports: <strong>${s.progress?.ports || 0}</strong></td>
          <td>
            <div class="flex-row-gap">
              <button class="btn btn-primary btn-xs" onclick="inspectAdminScan(${jsArg(s.id)})">🔍 Workspace</button>
              ${isRunning ? `<button class="btn btn-warning btn-xs" onclick="adminPauseScan(${jsArg(s.id)})">⏸ Pause</button>` : ''}
              ${isPaused ? `<button class="btn btn-success btn-xs" onclick="adminResumeScan(${jsArg(s.id)})">▶ Resume</button>` : ''}
              ${(isRunning || isPaused) ? `<button class="btn btn-danger btn-xs" onclick="adminCancelScan(${jsArg(s.id)})">⏹ Cancel</button>` : ''}
              <button class="btn btn-secondary btn-xs" onclick="adminRetryScan(${jsArg(s.id)})">🔄 Retry</button>
            </div>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.debug("Admin active scans skip:", err);
  }
}

async function loadAdminHealth() {
  try {
    const res = await authFetch(`${API_BASE}/admin/system/health`);
    if (!res.ok) return;
    const h = await res.json();

    const cpu = h.cpu_percent || 0;
    const mem = h.memory_percent || 0;
    const disk = h.disk_percent || 0;

    if (el("admHealthCpu")) el("admHealthCpu").textContent = `${cpu.toFixed(1)}%`;
    if (el("admHealthCpuBar")) el("admHealthCpuBar").style.width = `${Math.min(100, cpu)}%`;

    if (el("admHealthMem")) el("admHealthMem").textContent = `${mem.toFixed(1)}%`;
    if (el("admHealthMemBar")) el("admHealthMemBar").style.width = `${Math.min(100, mem)}%`;

    if (el("admHealthDisk")) el("admHealthDisk").textContent = `${disk.toFixed(1)}%`;
    if (el("admHealthDiskBar")) el("admHealthDiskBar").style.width = `${Math.min(100, disk)}%`;

    if (el("admGovState")) {
      const stateVal = (h.status || 'ACCEPTING').toUpperCase();
      el("admGovState").textContent = stateVal;
      el("admGovState").className = `pill pill-${stateVal === 'ACCEPTING' ? 'success' : (stateVal === 'THROTTLED' ? 'warning' : 'danger')}`;
    }
  } catch (err) {
    console.debug("Admin health skip:", err);
  }
}

function inspectAdminScan(scanId) {
  if (typeof loadWorkspaceData === "function") {
    loadWorkspaceData(scanId, true);
  }
  if (typeof navigateToView === "function") {
    navigateToView("reports");
  }
}

async function adminCancelScan(scanId) {
  if (!confirm(`Hentikan dan batalkan investigasi #${scanId.slice(0, 16)}?`)) return;
  try {
    const res = await authFetch(`${API_BASE}/admin/scans/${encodeURIComponent(scanId)}/cancel`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast("Investigasi berhasil dibatalkan.", "warning");
    await loadAdminActiveScans();
  } catch (err) {
    showToast("Gagal membatalkan investigasi: " + err.message, "danger");
  }
}

async function adminRetryScan(scanId) {
  try {
    const res = await authFetch(`${API_BASE}/admin/scans/${encodeURIComponent(scanId)}/retry`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    showToast(`Investigasi berhasil di-retry dengan ID #${(data.new_scan_id || '').slice(0, 16)}!`, "success");
    await loadAdminActiveScans();
  } catch (err) {
    showToast("Gagal me-retry investigasi: " + err.message, "danger");
  }
}

async function adminPauseScan(scanId) {
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/pause`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast("Investigasi dijeda.", "info");
    await loadAdminActiveScans();
  } catch (err) {
    showToast("Gagal pause: " + err.message, "danger");
  }
}

async function adminResumeScan(scanId) {
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/resume`, { method: "POST" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast("Investigasi dilanjutkan.", "success");
    await loadAdminActiveScans();
  } catch (err) {
    showToast("Gagal resume: " + err.message, "danger");
  }
}

// ==========================================================================
// AI Agent Chat & Configuration Controllers
// ==========================================================================

let aiChatMessages = [
  { role: "system", content: "You are a helpful security assistant in a vulnerability scanner portal." }
];

let aiSavedConfig = null;
let aiFormRevision = 0;
let aiConfigDirty = false;
let aiConfigLoadId = 0;
let aiModelRequestId = 0;
let aiTestRequestId = 0;
let aiSavePending = false;
let aiCatalog = [];
let aiCatalogEndpoint = "";
let aiConfigPoll = null;

function readAiCandidate() {
  return {
    provider: el("aiProvider")?.value || "openai_compatible",
    base_url: el("aiBaseUrl")?.value.trim() || "",
    api_key: el("aiApiKey")?.value.trim() || "",
    model: el("aiModelManual")?.value.trim() || el("aiModel")?.value || "",
    routing_mode: el("aiRoutingMode")?.value || "single",
    llm_enabled: el("aiLlmEnabled")?.value === "true",
    expected_revision: aiSavedConfig?.revision,
  };
}

function aiEndpointFingerprint(cfg = readAiCandidate()) {
  return JSON.stringify([cfg.provider, cfg.base_url, cfg.api_key]);
}

function aiSyncMessage(message) {
  if (el("aiConfigSyncStatus")) el("aiConfigSyncStatus").textContent = message;
}

function markAiConfigDirty() {
  aiFormRevision++;
  aiConfigDirty = true;
  aiSyncMessage("Draft belum diterapkan. Chat dan scan tetap memakai konfigurasi backend.");
  if (el("aiConnStatus")) el("aiConnStatus").textContent = "Draft — belum diuji";
}

function renderAiModelChoices(preferred = readAiCandidate().model) {
  const select = el("aiModel");
  if (!select) return;
  const mode = el("aiRoutingMode")?.value || "single";
  const entries = aiCatalogEndpoint === aiEndpointFingerprint() ? aiCatalog : [];
  const choices = entries.filter(row => mode === "router_combo" ? row.kind === "combo" : row.kind !== "combo");
  select.innerHTML = "";
  const add = (value, label) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    select.appendChild(option);
  };
  add("", "Pilih ID dari katalog provider...");
  choices.forEach(row => add(row.id, row.id + (row.kind === "combo" ? " [combo]" : " [model]")));
  // Never silently select a different model after fetching or changing modes.
  const known = entries.find(row => row.id === preferred);
  const mismatch = known && ((mode === "single" && known.kind === "combo") || (mode === "router_combo" && known.kind !== "combo"));
  if (preferred && !mismatch && !choices.some(row => row.id === preferred)) add(preferred, preferred + " [belum diverifikasi di katalog]");
  select.value = mismatch ? "" : preferred;
  select.disabled = mode === "task_router";
  if (el("aiModelManual")) el("aiModelManual").disabled = mode === "task_router";
  const descriptions = {
    single: "Kirim satu ID persis; aplikasi tidak beralih ke model lain. Perilaku internal provider tetap mengikuti konfigurasi provider.",
    router_combo: "Kirim nama combo persis; urutan fallback dan kuota dikelola NineRouter.",
    task_router: "Routing aplikasi: reasoning → security/developer/free; laporan → business/content/developer/free. Hanya mode ini memakai fallback lintas ID.",
  };
  if (el("aiRoutingHelp")) el("aiRoutingHelp").textContent = descriptions[mode];
}

async function fetchAndPopulateModels(candidateConfig = null) {
  const payload = candidateConfig || readAiCandidate();
  const endpoint = aiEndpointFingerprint(payload);
  const requestId = ++aiModelRequestId;
  const revision = aiFormRevision;
  if (el("aiModelCatalogStatus")) el("aiModelCatalogStatus").textContent = "Memuat katalog provider...";
  try {
    const res = await authFetch(`${API_BASE}/ai/models`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload), timeoutMs: 12000,
    });
    const data = await res.json();
    if (requestId !== aiModelRequestId || revision !== aiFormRevision || endpoint !== aiEndpointFingerprint()) return;
    if (!res.ok || data.status !== "success") throw new Error(data.message || data.detail || "Katalog tidak tersedia");
    aiCatalog = Array.isArray(data.entries) ? data.entries : [];
    aiCatalogEndpoint = endpoint;
    renderAiModelChoices();
    const combos = aiCatalog.filter(row => row.kind === "combo").length;
    if (el("aiModelCatalogStatus")) el("aiModelCatalogStatus").textContent = `${combos} combo · ${aiCatalog.length - combos} model. Katalog bukan bukti inference/kuota.`;
  } catch (err) {
    if (requestId !== aiModelRequestId || revision !== aiFormRevision || endpoint !== aiEndpointFingerprint()) return;
    aiCatalog = [];
    aiCatalogEndpoint = endpoint;
    renderAiModelChoices();
    if (el("aiModelCatalogStatus")) el("aiModelCatalogStatus").textContent = err.message + ". ID pilihan tetap dipertahankan; tidak ada daftar cadangan.";
  }
}

function applyAiConfigToForm(cfg) {
  aiSavedConfig = cfg;
  aiConfigDirty = false;
  aiFormRevision++;
  if (el("aiLlmEnabled")) el("aiLlmEnabled").value = cfg.llm_enabled ? "true" : "false";
  const provider = el("aiProvider");
  if (provider) {
    if (![...provider.options].some(row => row.value === cfg.provider)) {
      const option = document.createElement("option");
      option.value = option.textContent = cfg.provider;
      provider.appendChild(option);
    }
    provider.value = cfg.provider;
  }
  if (el("aiBaseUrl")) el("aiBaseUrl").value = cfg.base_url || "";
  if (el("aiApiKey")) {
    el("aiApiKey").value = "";
    el("aiApiKey").placeholder = cfg.api_key_configured ? "Tersimpan; kosong = tetap untuk endpoint yang sama" : "API key belum disetel";
  }
  if (el("aiRoutingMode")) el("aiRoutingMode").value = cfg.routing_mode;
  if (el("aiModelManual")) el("aiModelManual").value = "";
  renderAiModelChoices(cfg.model);
  if (el("aiConnStatus")) el("aiConnStatus").textContent = cfg.llm_enabled ? "Aktif — inference belum diuji" : "AI nonaktif";
  aiSyncMessage(`Sinkron dengan backend (revisi ${cfg.revision}). Berlaku selama proses server ini; .env tidak diubah.`);
}

async function loadAiConfig(force = false) {
  const id = ++aiConfigLoadId;
  const revision = aiFormRevision;
  try {
    const res = await authFetch(`${API_BASE}/ai/config`, {timeoutMs: 8000});
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const cfg = await res.json();
    if (id !== aiConfigLoadId || revision !== aiFormRevision) return;
    if (aiConfigDirty && !force) {
      if (cfg.revision !== aiSavedConfig?.revision) aiSyncMessage("Backend berubah di sesi lain. Draft Anda dipertahankan; muat ulang sebelum menyimpan.");
      return;
    }
    if (force || !aiSavedConfig || cfg.revision !== aiSavedConfig.revision ||
        JSON.stringify(cfg) !== JSON.stringify(aiSavedConfig)) {
      applyAiConfigToForm(cfg);
      await fetchAndPopulateModels();
    }
  } catch (err) {
    if (id === aiConfigLoadId) aiSyncMessage("Sinkronisasi konfigurasi gagal: " + err.message);
  }
}

async function saveAiSettings() {
  if (aiSavePending) return;
  const payload = readAiCandidate();
  if (!payload.model && payload.routing_mode !== "task_router") {
    showToast("Pilih ID model/combo terlebih dahulu.", "warning");
    return;
  }
  const revision = aiFormRevision;
  aiSavePending = true;
  try {
    const res = await authFetch(`${API_BASE}/ai/config`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload), timeoutMs: 12000,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Gagal menerapkan konfigurasi");
    if (revision === aiFormRevision) {
      applyAiConfigToForm(data.config);
      await fetchAndPopulateModels();
    } else {
      aiSavedConfig = data.config;
      aiSyncMessage("Konfigurasi permintaan sebelumnya diterapkan; edit terbaru masih berupa draft.");
    }
    showToast("Konfigurasi runtime diterapkan. Belum berarti inference berhasil.", "success");
  } catch (err) {
    showToast("Gagal menyimpan: " + err.message, "danger");
  } finally {
    aiSavePending = false;
  }
}

async function testAiConnection() {
  const payload = readAiCandidate();
  if (!payload.model && payload.routing_mode !== "task_router") {
    showToast("Pilih model/combo atau masukkan ID terlebih dahulu.", "warning");
    return;
  }
  const id = ++aiTestRequestId;
  const revision = aiFormRevision;
  const pill = el("aiConnStatus");
  if (pill) pill.textContent = "Menguji inference draft...";
  try {
    const res = await authFetch(`${API_BASE}/ai/test`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload), timeoutMs: 30000,
    });
    const data = await res.json();
    if (id !== aiTestRequestId || revision !== aiFormRevision) return;
    if (!res.ok || data.status !== "success") throw new Error(data.message || data.detail || "Inference gagal");
    const route = data.routing || {};
    if (pill) pill.textContent = `Inference OK · ${data.latency_ms} ms`;
    if (el("aiTestDetails")) el("aiTestDetails").textContent = `Mode: ${data.routing_mode}. Diminta: ${route.requested_model || "tidak dilaporkan"}. Respons provider: ${route.response_model || "tidak dilaporkan"}. Uji ini tidak menyimpan konfigurasi atau menjamin kuota.`;
  } catch (err) {
    if (id !== aiTestRequestId || revision !== aiFormRevision) return;
    if (pill) pill.textContent = "Inference gagal";
    if (el("aiTestDetails")) el("aiTestDetails").textContent = err.message;
  }
}

async function sendAiChatMessage() {
  if (aiConfigDirty || aiSavePending) {
    showToast("Terapkan konfigurasi atau muat ulang backend sebelum chat.", "warning");
    return;
  }
  const txtArea = el("aiChatTextarea");
  if (!txtArea) return;
  const userMsg = txtArea.value.trim();
  if (!userMsg) return;
  txtArea.value = "";

  appendChatBubble("user", userMsg);
  aiChatMessages.push({ role: "user", content: userMsg });
  const loadingId = appendChatBubble("assistant", "⏳ Berpikir...");

  try {
    const res = await authFetch(`${API_BASE}/ai/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: aiChatMessages.slice(-8)
      }),
      timeoutMs: 30000
    });

    const loadingElem = el(loadingId);
    if (loadingElem) loadingElem.remove();

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Server error.");
    }
    
    const data = await res.json();
    appendChatBubble("assistant", data.reply);
    aiChatMessages.push({ role: "assistant", content: data.reply });
  } catch (err) {
    const loadingElem = el(loadingId);
    if (loadingElem) loadingElem.remove();
    
    appendChatBubble("assistant", `⚠️ Error: ${err.message}`);
    if (typeof showToast === "function") showToast("Gagal chat: " + err.message, "danger");
  }
}

function appendChatBubble(sender, text) {
  const chatLogs = el("aiChatLogs");
  if (!chatLogs) return null;

  const bubbleId = "chat_bubble_" + Math.random().toString(36).substr(2, 9);
  const div = document.createElement("div");
  div.id = bubbleId;
  div.className = `chat-msg-bubble ${sender}`;

  let formattedText = esc(text);
  formattedText = formattedText.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  formattedText = formattedText.replace(/`([^`]+)`/g, '<code>$1</code>');
  formattedText = formattedText.replace(/\n/g, '<br>');

  div.innerHTML = `<div class="chat-msg-text">${formattedText}</div>`;
  chatLogs.appendChild(div);
  chatLogs.scrollTop = chatLogs.scrollHeight;
  return bubbleId;
}

function setupAdminTabs() {
  document.querySelectorAll(".admin-subtab").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const viewName = btn.getAttribute("data-admin-view");
      if (!viewName) return;

      document.querySelectorAll(".admin-subtab").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      document.querySelectorAll(".admin-view-content").forEach(c => c.classList.add("hidden"));
      const targetView = el(`admin${viewName.charAt(0).toUpperCase() + viewName.slice(1)}View`);
      if (targetView) targetView.classList.remove("hidden");

      if (viewName === "operations") loadAdminActiveScans();
      if (viewName === "health") loadAdminHealth();
      if (viewName === "ai") loadAiConfig();
    });
  });

  const refreshBtn = el("refreshAdminBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadAdminData();
    });
  }
}

function initializeAiSettingsWiring() {
  setupAdminTabs();
  const panel = el("adminAiView");
  if (panel?.dataset.aiWired) return;
  if (panel) panel.dataset.aiWired = "true";
  ["aiLlmEnabled", "aiProvider", "aiBaseUrl", "aiApiKey", "aiRoutingMode", "aiModel", "aiModelManual"].forEach(id => {
    el(id)?.addEventListener("input", () => {
      if (id === "aiModel" && el("aiModelManual")) el("aiModelManual").value = "";
      markAiConfigDirty();
      if (id === "aiRoutingMode") renderAiModelChoices();
    });
  });
  el("loadAiModelsBtn")?.addEventListener("click", () => fetchAndPopulateModels());
  el("reloadAiConfigBtn")?.addEventListener("click", () => loadAiConfig(true));
  clearInterval(aiConfigPoll);
  aiConfigPoll = setInterval(() => {
    if (!document.hidden && state.currentUser && panel && !panel.classList.contains("hidden")) loadAiConfig();
  }, 15000);

  if (el("saveAiSettingsBtn")) {
    el("saveAiSettingsBtn").addEventListener("click", (e) => {
      e.preventDefault();
      saveAiSettings();
    });
  }
  if (el("testAiConnectionBtn")) {
    el("testAiConnectionBtn").addEventListener("click", (e) => {
      e.preventDefault();
      testAiConnection();
    });
  }
  if (el("aiChatSendBtn")) {
    el("aiChatSendBtn").addEventListener("click", (e) => {
      e.preventDefault();
      sendAiChatMessage();
    });
  }
  if (el("aiChatTextarea")) {
    el("aiChatTextarea").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendAiChatMessage();
      }
    });
  }
  if (el("clearAiChatBtn")) {
    el("clearAiChatBtn").addEventListener("click", (e) => {
      e.preventDefault();
      const chatLogs = el("aiChatLogs");
      if (chatLogs) {
        chatLogs.innerHTML = `
          <div class="chat-msg-bubble system">
            <div class="chat-msg-text">
              System: Logs cleared. Copilot ready.
            </div>
          </div>
        `;
      }
      aiChatMessages = [
        { role: "system", content: "You are a helpful security assistant in a vulnerability scanner portal." }
      ];
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(initializeAiSettingsWiring, 800);
});
