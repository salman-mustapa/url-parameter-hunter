/**
 * admin.js — Administrator Oversight Dashboard, User Activity & Domain Auditing
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

  // 2. Load User Scrapping Analytics
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

  // 3. Load Domain Scrapping Audit
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

  // 4. Load AI Config
  if (typeof loadAiConfig === "function") {
    loadAiConfig();
  }
}

// ==========================================================================
// AI Agent Chat & Configuration Controllers
// ==========================================================================

let aiChatMessages = [
  { role: "system", content: "You are a helpful security assistant in a vulnerability scanner portal." }
];

async function loadAiConfig() {
  try {
    const res = await authFetch(`${API_BASE}/ai/status`);
    if (!res.ok) throw new Error("Gagal mengambil status AI.");
    const data = await res.json();

    if (el("aiLlmEnabled")) el("aiLlmEnabled").value = data.enabled ? "true" : "false";
    if (el("aiProvider")) el("aiProvider").value = data.provider || "openai_compatible";
    if (el("aiBaseUrl")) el("aiBaseUrl").value = data.base_url || "";
    if (el("aiModel")) el("aiModel").value = data.model || "gemini/gemini-3.5-flash-lite";

    updateAiStatusUI(data.is_configured);
  } catch (err) {
    console.error("loadAiConfig error:", err);
  }
}

function updateAiStatusUI(isConfigured) {
  const statusPill = el("aiConnStatus");
  if (statusPill) {
    if (isConfigured) {
      statusPill.className = "ai-status-pill active";
      statusPill.innerHTML = "🟢 Connected";
    } else {
      statusPill.className = "ai-status-pill inactive";
      statusPill.innerHTML = "🔴 Disconnected";
    }
  }
}

async function saveAiSettings() {
  const enabled = el("aiLlmEnabled") ? el("aiLlmEnabled").value === "true" : false;
  const provider = el("aiProvider") ? el("aiProvider").value : "openai_compatible";
  const baseUrl = el("aiBaseUrl") ? el("aiBaseUrl").value : "";
  const apiKey = el("aiApiKey") ? el("aiApiKey").value : "";
  const model = el("aiModel") ? el("aiModel").value : "";

  const payload = { enabled, provider, base_url: baseUrl, model };
  if (apiKey.trim()) {
    payload.api_key = apiKey;
  }

  try {
    const btn = el("saveAiSettingsBtn");
    if (btn) btn.disabled = true;

    const res = await authFetch(`${API_BASE}/ai/settings`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    
    if (!res.ok) throw new Error("Gagal menyimpan konfigurasi.");
    const data = await res.json();
    
    if (typeof showToast === "function") showToast("Konfigurasi AI diperbarui!", "success");
    if (el("aiApiKey")) el("aiApiKey").value = ""; // clear key input for safety
    
    updateAiStatusUI(data.is_configured);
    appendSystemMessage(`System: Configuration applied successfully. Active model is now "${data.model}".`);
  } catch (err) {
    if (typeof showToast === "function") showToast("Gagal: " + err.message, "danger");
  } finally {
    const btn = el("saveAiSettingsBtn");
    if (btn) btn.disabled = false;
  }
}

async function testAiConnection() {
  const statusPill = el("aiConnStatus");
  if (statusPill) statusPill.innerHTML = "🟡 Testing...";

  try {
    const btn = el("testAiConnectionBtn");
    if (btn) btn.disabled = true;

    const res = await authFetch(`${API_BASE}/ai/test`, { method: "POST" });
    if (!res.ok) throw new Error("Koneksi gagal.");
    const data = await res.json();

    if (data.status === "success" || data.status === "ready" || data.status === "PENTEST_AI_READY" || data.reply === "PENTEST_AI_READY") {
      if (typeof showToast === "function") showToast("Koneksi AI Berhasil!", "success");
      updateAiStatusUI(true);
      appendSystemMessage(`System: AI connection successful. Connected to model "${data.model || 'active model'}".`);
    } else {
      throw new Error(data.message || "Model failed to respond.");
    }
  } catch (err) {
    if (typeof showToast === "function") showToast("Koneksi Gagal: " + err.message, "danger");
    updateAiStatusUI(false);
    appendSystemMessage(`⚠️ System Failover Warning: AI connection failed or model is degraded. Details: ${err.message}. Cascading/failover model is ready to route requests.`);
  } finally {
    const btn = el("testAiConnectionBtn");
    if (btn) btn.disabled = false;
  }
}

async function sendAiChatMessage() {
  const textarea = el("aiChatTextarea");
  if (!textarea || !textarea.value.trim()) return;

  const userMsg = textarea.value.trim();
  textarea.value = "";

  // Append user message to log
  appendChatBubble("user", userMsg);
  
  aiChatMessages.push({ role: "user", content: userMsg });

  // Add a placeholder message for loading
  const loadingId = appendChatBubble("assistant", "⏳ Berpikir...");

  try {
    const res = await authFetch(`${API_BASE}/ai/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        messages: aiChatMessages.slice(-8) // keep context size small
      })
    });

    // Remove loading placeholder
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

  // Format pre/code formatting for markdown-style responses
  let formattedText = esc(text);
  formattedText = formattedText.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  formattedText = formattedText.replace(/`([^`]+)`/g, '<code>$1</code>');
  formattedText = formattedText.replace(/\n/g, '<br>');

  div.innerHTML = `<div class="chat-msg-text">${formattedText}</div>`;
  chatLogs.appendChild(div);
  chatLogs.scrollTop = chatLogs.scrollHeight;
  return bubbleId;
}

function appendSystemMessage(text) {
  const chatLogs = el("aiChatLogs");
  if (!chatLogs) return;

  const div = document.createElement("div");
  div.className = "chat-msg-bubble system";
  div.innerHTML = `<div class="chat-msg-text">${esc(text)}</div>`;
  chatLogs.appendChild(div);
  chatLogs.scrollTop = chatLogs.scrollHeight;
}

// Wire events when script is parsed
function initializeAiSettingsWiring() {
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

// Automatically bind events when loaded
document.addEventListener("DOMContentLoaded", () => {
  setTimeout(initializeAiSettingsWiring, 1000);
});

