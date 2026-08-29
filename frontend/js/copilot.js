/**
 * copilot.js — Interactive Pentest AI Copilot Drawer & Context-Aware Assistant
 * Hunter Aja Intelligence Platform
 */

let copilotHistory = [];
let isCopilotSending = false;

function _safeEsc(text) {
  if (typeof window.esc === "function") return window.esc(text);
  if (typeof esc === "function") return esc(text);
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function initCopilot() {
  const toggleBtn = el("openCopilotBtn");
  const closeBtn = el("closeCopilotBtn");
  const drawer = el("aiCopilotDrawer");
  const sendBtn = el("copilotSendBtn");
  const inputEl = el("copilotInput");

  if (toggleBtn && drawer) {
    toggleBtn.onclick = () => {
      drawer.classList.toggle("hidden");
      if (!drawer.classList.contains("hidden")) {
        inputEl?.focus();
        scrollCopilotBottom();
      }
    };
  }

  if (closeBtn && drawer) {
    closeBtn.onclick = () => {
      drawer.classList.add("hidden");
    };
  }

  if (sendBtn && inputEl) {
    sendBtn.onclick = () => {
      sendCopilotMessage();
    };

    inputEl.onkeydown = (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendCopilotMessage();
      }
    };
  }

  // Quick Action Chips in Copilot Drawer
  document.querySelectorAll(".copilot-prompt-chip").forEach((chip) => {
    chip.onclick = () => {
      const prompt = chip.dataset.prompt || chip.textContent.trim();
      const inEl = el("copilotInput");
      if (inEl) {
        inEl.value = prompt;
        sendCopilotMessage();
      }
    };
  });
}

async function sendCopilotMessage() {
  const inputEl = el("copilotInput");
  if (!inputEl || isCopilotSending) return;

  const msg = inputEl.value.trim();
  if (!msg) return;

  inputEl.value = "";
  isCopilotSending = true;

  // Append user bubble
  appendCopilotBubble("user", msg);
  scrollCopilotBottom();

  // Show typing indicator
  const typingId = "copilotTypingIndicator_" + Date.now();
  appendCopilotTyping(typingId);
  scrollCopilotBottom();

  try {
    const activeScanId = state?.activeScanId || null;
    const fetchFn = typeof authFetch === "function" ? authFetch : fetch;
    const res = await fetchFn(`${API_BASE}/ai/copilot/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: msg,
        scan_id: activeScanId,
        history: copilotHistory.slice(-6),
      }),
    });

    removeCopilotEl(typingId);

    if (!res.ok) {
      const errData = await res.json().catch(() => ({ detail: "Gagal memproses pesan." }));
      appendCopilotBubble("assistant", `⚠️ ${errData.detail || "Terjadi kendala saat memproses permintaan AI Copilot. Silakan coba lagi."}`);
      return;
    }

    const data = await res.json();
    const replyText = data.reply || "Analisis selesai.";
    appendCopilotBubble("assistant", replyText, data.source, data.model);

    copilotHistory.push({ role: "user", content: msg });
    copilotHistory.push({ role: "assistant", content: replyText });

  } catch (err) {
    removeCopilotEl(typingId);
    appendCopilotBubble("assistant", `⚠️ Error komunikasi Copilot: ${err.message}`);
  } finally {
    isCopilotSending = false;
    scrollCopilotBottom();
  }
}

function appendCopilotBubble(role, text, source, model) {
  const container = el("copilotMessagesList");
  if (!container) return;

  const isUser = role === "user";
  const bubble = document.createElement("div");
  bubble.className = `copilot-bubble ${isUser ? "copilot-bubble-user" : "copilot-bubble-ai"}`;

  const header = document.createElement("div");
  header.className = "copilot-bubble-header";
  header.innerHTML = isUser
    ? `<span class="bubble-sender">👤 Anda</span>`
    : `<span class="bubble-sender">🤖 Hunter Aja Copilot</span> ${model ? `<span class="bubble-model-tag">[${_safeEsc(model)}]</span>` : ''}`;

  const content = document.createElement("div");
  content.className = "copilot-bubble-content markdown-rendered";
  content.innerHTML = renderMarkdownSimple(text);

  bubble.appendChild(header);
  bubble.appendChild(content);

  container.appendChild(bubble);
}

function appendCopilotTyping(id) {
  const container = el("copilotMessagesList");
  if (!container) return;

  const typing = document.createElement("div");
  typing.id = id;
  typing.className = "copilot-bubble copilot-bubble-ai copilot-typing";
  typing.innerHTML = `
    <div class="typing-dots">
      <span></span><span></span><span></span>
    </div>
    <span class="typing-text">AI sedang menganalisis attack surface & merumuskan respons...</span>
  `;
  container.appendChild(typing);
}

function removeCopilotEl(id) {
  const elNode = el(id);
  if (elNode) elNode.remove();
}

function scrollCopilotBottom() {
  const container = el("copilotMessagesList");
  if (container) {
    container.scrollTop = container.scrollHeight;
  }
}

function renderMarkdownSimple(md) {
  if (!md) return "";
  let html = _safeEsc(md);

  // Code blocks ```lang ... ```
  html = html.replace(/```([a-zA-Z0-9_+-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
    const codeId = "code_" + Math.random().toString(36).substr(2, 7);
    return `
      <div class="copilot-code-block">
        <div class="code-block-header">
          <span class="code-lang">${lang || "code"}</span>
          <button type="button" class="copy-code-btn" onclick="copyCopilotCode('${codeId}')">📋 Salin</button>
        </div>
        <pre id="${codeId}"><code>${code}</code></pre>
      </div>
    `;
  });

  // Inline code `...`
  html = html.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');

  // Headings
  html = html.replace(/^### (.*$)/gim, '<h4 class="md-h4">$1</h4>');
  html = html.replace(/^## (.*$)/gim, '<h3 class="md-h3">$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h2 class="md-h2">$1</h2>');

  // Bold & Italic
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

  // Bullet points
  html = html.replace(/^\s*[-•]\s+(.*$)/gim, '<li class="md-li">$1</li>');

  // Blockquotes
  html = html.replace(/^>\s*(.*$)/gim, '<blockquote class="md-quote">$1</blockquote>');

  // Line breaks
  html = html.replace(/\n/g, '<br/>');

  return html;
}

function copyCopilotCode(codeId) {
  const block = el(codeId);
  if (!block) return;
  const text = block.textContent;
  navigator.clipboard.writeText(text).then(() => {
    if (typeof showToast === "function") showToast("Kode berhasil disalin ke clipboard!", "success");
  }).catch(() => {
    if (typeof showToast === "function") showToast("Gagal menyalin kode.", "warning");
  });
}

window.initCopilot = initCopilot;
window.sendCopilotMessage = sendCopilotMessage;
window.copyCopilotCode = copyCopilotCode;

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initCopilot);
  } else {
    initCopilot();
  }
}
