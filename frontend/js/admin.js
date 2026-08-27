/**
 * admin.js — Administrator Oversight Dashboard, Operational Controls & Health
 * Attack Surface & Parameter Intelligence Platform
 */

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
          <td><code>${esc(s.user_id || 'System')}</code></td>
          <td class="text-xs">${s.started_at ? new Date(s.started_at).toLocaleTimeString('id-ID') : '-'}</td>
          <td class="text-xs">Assets: <strong>${s.progress?.assets || 0}</strong> | Ports: <strong>${s.progress?.ports || 0}</strong></td>
          <td>
            <div class="flex-row-gap">
              <button class="btn btn-primary btn-xs" onclick="inspectAdminScan('${esc(s.id)}')">🔍 Workspace</button>
              ${isRunning ? `<button class="btn btn-warning btn-xs" onclick="adminPauseScan('${esc(s.id)}')">⏸ Pause</button>` : ''}
              ${isPaused ? `<button class="btn btn-success btn-xs" onclick="adminResumeScan('${esc(s.id)}')">▶ Resume</button>` : ''}
              ${(isRunning || isPaused) ? `<button class="btn btn-danger btn-xs" onclick="adminCancelScan('${esc(s.id)}')">⏹ Cancel</button>` : ''}
              <button class="btn btn-secondary btn-xs" onclick="adminRetryScan('${esc(s.id)}')">🔄 Retry</button>
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

async function fetchAndPopulateModels(candidateConfig = null) {
  const provider = el("aiProvider") ? el("aiProvider").value : "openai_compatible";
  const baseUrl = el("aiBaseUrl") ? el("aiBaseUrl").value : "";
  const apiKey = el("aiApiKey") ? el("aiApiKey").value : "";
  
  const payload = candidateConfig || {
    provider: provider,
    base_url: baseUrl,
    api_key: apiKey
  };

  const defaultModels = [
    "combo",
    "developer",
    "ag/gemini-3.7-flash-medium",
    "gemini/gemini-3.5-flash-lite",
    "fast",
    "ag/claude-sonnet-4-6",
    "free"
  ];

  try {
    const res = await authFetch(`${API_BASE}/ai/models`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    
    let modelsList = defaultModels;
    if (res.ok) {
      const data = await res.json();
      if (data.models && data.models.length > 0) {
        modelsList = data.models;
      }
    } else {
      console.warn("API/models returned non-ok status, falling back to default models.");
    }
    
    const modelSelect = el("aiModel");
    if (modelSelect) {
      const currentSelected = modelSelect.value;
      modelSelect.innerHTML = "";
      modelsList.forEach((m) => {
        const opt = document.createElement("option");
        opt.value = m;
        opt.textContent = m;
        modelSelect.appendChild(opt);
      });
      modelSelect.disabled = false;
      if (currentSelected && modelsList.includes(currentSelected)) {
        modelSelect.value = currentSelected;
      }
    }
  } catch (err) {
    console.error("fetchAndPopulateModels error:", err);
  }
}

async function loadAiConfig() {
  try {
    const res = await authFetch(`${API_BASE}/ai/config`);
    if (!res.ok) return;
    const cfg = await res.json();
    
    if (el("aiLlmEnabled")) el("aiLlmEnabled").value = cfg.llm_enabled ? "true" : "false";
    if (el("aiProvider")) el("aiProvider").value = cfg.provider || "openai_compatible";
    if (el("aiBaseUrl")) el("aiBaseUrl").value = cfg.base_url || "";
    if (el("aiApiKey") && cfg.api_key_configured) el("aiApiKey").placeholder = "(Tersimpan di sistem server)";
    
    const statusPill = el("aiConnStatus");
    if (statusPill) {
      if (cfg.llm_enabled) {
        statusPill.textContent = "🟢 Connected & Ready";
        statusPill.className = "ai-status-pill active";
      } else {
        statusPill.textContent = "⚪ Disabled";
        statusPill.className = "ai-status-pill inactive";
      }
    }
    
    await fetchAndPopulateModels(cfg);
    if (cfg.model && el("aiModel")) {
      el("aiModel").value = cfg.model;
    }
  } catch (err) {
    console.error("loadAiConfig error:", err);
  }
}

async function saveAiSettings() {
  const llmEnabled = el("aiLlmEnabled") ? el("aiLlmEnabled").value === "true" : true;
  const provider = el("aiProvider") ? el("aiProvider").value : "openai_compatible";
  const baseUrl = el("aiBaseUrl") ? el("aiBaseUrl").value : "";
  const apiKey = el("aiApiKey") ? el("aiApiKey").value : "";
  const model = el("aiModel") ? el("aiModel").value : "";

  const payload = {
    llm_enabled: llmEnabled,
    provider: provider,
    base_url: baseUrl,
    api_key: apiKey,
    model: model
  };

  try {
    const res = await authFetch(`${API_BASE}/ai/config`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.detail || "Failed to save AI config.");
    }
    if (typeof showToast === "function") showToast("Konfigurasi AI berhasil disimpan.", "success");
    await loadAiConfig();
  } catch (err) {
    if (typeof showToast === "function") showToast("Gagal menyimpan konfigurasi: " + err.message, "danger");
  }
}

async function testAiConnection() {
  const provider = el("aiProvider") ? el("aiProvider").value : "openai_compatible";
  const baseUrl = el("aiBaseUrl") ? el("aiBaseUrl").value : "";
  const apiKey = el("aiApiKey") ? el("aiApiKey").value : "";

  const payload = {
    provider: provider,
    base_url: baseUrl,
    api_key: apiKey
  };

  const statusPill = el("aiConnStatus");
  if (statusPill) {
    statusPill.textContent = "🟡 Connecting & Testing...";
    statusPill.className = "ai-status-pill inactive";
  }

  try {
    const res = await authFetch(`${API_BASE}/ai/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok && data.status === "success") {
      if (statusPill) {
        statusPill.textContent = "🟢 Connected & Validated";
        statusPill.className = "ai-status-pill active";
      }
      if (typeof showToast === "function") showToast("Koneksi AI berhasil diverifikasi!", "success");
      await fetchAndPopulateModels(payload);
    } else {
      throw new Error(data.message || data.error || "Connection failed.");
    }
  } catch (err) {
    if (statusPill) {
      statusPill.textContent = "🔴 Connection Failed";
      statusPill.className = "ai-status-pill inactive";
    }
    if (typeof showToast === "function") showToast("Gagal terhubung ke AI API: " + err.message, "danger");
  }
}

async function sendAiChatMessage() {
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
      })
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
    
    appendChatBubble("assistant", `⚠️ Error: ${err.message}.`);
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
    });
  });

  const refreshBtn = el("refreshAdminBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      loadAdminData();
    });
  }
}

// Wire events when script is parsed
function initializeAiSettingsWiring() {
  setupAdminTabs();

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
