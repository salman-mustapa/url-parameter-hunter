/**
 * stream.js — Real-time Event Stream Terminal & Message Categorization
 * Attack Surface & Parameter Intelligence Platform
 */

let _v4SyncDebounceTimer = null;
function triggerV4DebouncedSync() {
  if (_v4SyncDebounceTimer) return;
  _v4SyncDebounceTimer = setTimeout(() => {
    _v4SyncDebounceTimer = null;
    if (typeof v4State !== "undefined" && v4State.activeViewMode) {
      if (v4State.activeViewMode === "statemachine" && typeof loadV4StateMachineData === "function") {
        loadV4StateMachineData();
      } else if (v4State.activeViewMode === "hypotheses" && typeof loadV4HypothesesAndPlans === "function") {
        loadV4HypothesesAndPlans();
      }
    }
  }, 1200);
}

function getCategoryTagClass(cat) {
  const map = {
    DISCOVERY: "tag-discovery",
    DNS: "tag-dns",
    PORT: "tag-port",
    SERVICE: "tag-http",
    HTTP: "tag-http",
    URL: "tag-url",
    CRAWL: "tag-url",
    DIRSEARCH: "tag-url",
    SUBFINDER: "tag-discovery",
    TOOL: "tag-tech",
    PARAM: "tag-param",
    PARAMETER: "tag-param",
    TECH: "tag-tech",
    TECHNOLOGY: "tag-tech",
    CVE: "tag-cert",
    TRIAGE: "tag-observation",
    VALIDATE: "tag-finding",
    EVIDENCE: "tag-cert",
    FINDING: "tag-finding",
    REPORT: "tag-scan",
    SCAN: "tag-scan",
    CERT: "tag-cert",
    OBSERVATION: "tag-observation",
    ARTIFACT: "tag-cert",
  };
  return map[cat] || "tag-scan";
}

function renderStreamEvents() {
  const container = el("eventStreamContainer");
  if (!container) return;
  container.innerHTML = "";
  if (el("streamCount")) el("streamCount").textContent = `${state.events.length} events`;

  const filtered = state.events.filter((ev) => {
    if (state.currentCategoryFilter === "ALL") return true;
    const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
    const normalizedCat = cat.startsWith("PARAM") ? "PARAM" : (cat.startsWith("TECH") ? "TECH" : cat);
    return normalizedCat.includes(state.currentCategoryFilter);
  });

  if (!filtered.length) {
    container.innerHTML = `<div class="event-empty-msg"><p>Tidak ada event untuk filter <strong>${esc(state.currentCategoryFilter)}</strong>.</p></div>`;
    return;
  }

  // Render max 120 items into a DocumentFragment for 60fps performance
  const itemsToRender = filtered.slice(-120);
  const fragment = document.createDocumentFragment();

  itemsToRender.forEach((ev) => {
    const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
    const normalizedCat = cat.startsWith("PARAM") ? "PARAM" : (cat.startsWith("TECH") ? "TECH" : cat);
    const ts = ev.created_at ? String(ev.created_at).slice(11, 19) : new Date().toLocaleTimeString();
    const tagClass = getCategoryTagClass(normalizedCat);

    const item = document.createElement("div");
    item.className = "event-item";
    item.dataset.category = normalizedCat;
    item.innerHTML = `
      <span class="event-time">[${esc(ts)}]</span>
      <span class="event-tag ${tagClass}">${esc(normalizedCat)}</span>
      <span class="event-msg">${esc(ev.message)}</span>
    `;
    fragment.appendChild(item);
  });

  container.appendChild(fragment);

  if (el("autoScrollCheck")?.checked) {
    container.scrollTop = container.scrollHeight;
  }
}

function updatePipelineHud(stage, tool, progress, desc) {
  const toolBadge = el("activeToolBadge");
  const stageText = el("pipelineStageText");
  const progressPct = el("pipelineProgressPct");
  const progressBar = el("pipelineProgressBar");

  if (tool && toolBadge) {
    toolBadge.textContent = `⚡ Running: ${tool}`;
    toolBadge.style.color = "#38bdf8";
    toolBadge.style.borderColor = "#38bdf8";
  }

  if (stageText && (desc || stage)) {
    stageText.textContent = desc || `Tahap: ${stage}`;
  }

  if (progress !== undefined && progress !== null) {
    if (progressPct) progressPct.textContent = `${progress}%`;
    if (progressBar) progressBar.style.width = `${progress}%`;
  }

  const stages = ["stageRecon", "stageNetwork", "stageEnum", "stageExploit", "stageVerify"];
  const stageMap = {
    RECON: "stageRecon",
    DISCOVERY: "stageRecon",
    DNS: "stageRecon",
    NETWORK: "stageNetwork",
    PORT: "stageNetwork",
    HTTP: "stageNetwork",
    ENUM: "stageEnum",
    CRAWL: "stageEnum",
    DIRSEARCH: "stageEnum",
    KATANA: "stageEnum",
    EXPLOIT: "stageExploit",
    SQLI: "stageExploit",
    XSS: "stageExploit",
    AUTH: "stageExploit",
    VERIFY: "stageVerify",
    REPORT: "stageVerify",
  };

  const activeId = stageMap[String(stage).toUpperCase()];
  if (activeId) {
    stages.forEach((id) => {
      const p = el(id);
      if (!p) return;
      if (id === activeId) {
        p.style.borderColor = "#38bdf8";
        p.style.background = "rgba(56, 189, 248, 0.2)";
        p.style.color = "#38bdf8";
      } else {
        p.style.borderColor = "rgba(255, 255, 255, 0.1)";
        p.style.background = "rgba(255, 255, 255, 0.05)";
        p.style.color = "#94a3b8";
      }
    });
  }
}
window.updatePipelineHud = updatePipelineHud;

function addEventToStream(ev) {
  state.events.push(ev);
  if (state.events.length > 500) state.events.shift();

  if (el("streamCount")) el("streamCount").textContent = `${state.events.length} events`;

  // Update live HUD (throttled)
  if (ev.event_type === "pipeline.stage" || ev.event_type === "tool.active" || ev.stage || ev.tool || ev.progress) {
    updatePipelineHud(ev.stage || ev.event_type, ev.tool, ev.progress, ev.message);
  } else if (ev.category === "CRAWL" || ev.category === "URL") {
    updatePipelineHud("ENUM", "katana / dirsearch", 60, "Crawling & discovering endpoints...");
  } else if (ev.category === "FINDING" || ev.category === "EXPLOIT") {
    updatePipelineHud("EXPLOIT", "ai_pentest_engine", 85, "Testing injection vectors & verifying findings...");
  }

  // Throttled live sync of active V4 view (State Machine / AI Hypotheses) — prevents network/DOM flooding
  triggerV4DebouncedSync();

  const container = el("eventStreamContainer");
  if (!container) return;

  const empty = container.querySelector(".event-empty-msg");
  if (empty) empty.remove();

  const cat = (ev.category || (ev.event_type ? ev.event_type.split(".")[0].toUpperCase() : "INFO")).toUpperCase();
  const normalizedCat = cat.startsWith("PARAM") ? "PARAM" : (cat.startsWith("TECH") ? "TECH" : cat);

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

  // Keep DOM lean & lightning fast (max 120 elements in terminal view)
  while (container.children.length > 120) {
    container.removeChild(container.firstChild);
  }

  if (el("autoScrollCheck")?.checked) {
    container.scrollTop = container.scrollHeight;
  }
}

function filterStreamEvents(filterCat) {
  state.currentCategoryFilter = filterCat;
  renderStreamEvents();
}

function clearStreamLog() {
  state.events = [];
  const container = el("eventStreamContainer");
  if (container) {
    container.innerHTML = `
      <div class="event-empty-msg">
        <span class="empty-icon">⏳</span>
        <p>Log stream telah dibersihkan. Event baru akan muncul secara real-time saat pemindaian berjalan.</p>
      </div>
    `;
  }
  const countBadge = el("streamCount");
  if (countBadge) countBadge.textContent = "0 events";
  if (typeof showToast === "function") showToast("Log stream berhasil dibersihkan.", "info");
}
window.clearStreamLog = clearStreamLog;

let isAutonomousFetching = false;

async function pollAutonomousLoopTelemetry() {
  // Only poll if a scan is actively running to conserve CPU & network
  if (state.scanStatus !== "RUNNING" || !state.activeScanId || isAutonomousFetching) return;
  if (typeof document !== "undefined" && document.hidden) return;

  const banner = el("autonomousActionBanner");
  const actionText = el("autonomousActiveActionText");
  const queueBadge = el("autonomousQueueBadge");

  if (!banner || !actionText || !queueBadge) return;

  isAutonomousFetching = true;
  try {
    const res = await authFetch(`${API_BASE}/autonomous/queue`);
    if (!res.ok) return;
    const data = await res.json();
    const queue = data.queue || [];

    if (queue.length > 0 || (state.scanStatus === "RUNNING")) {
      banner.classList.remove("hidden");
      queueBadge.textContent = `${queue.length} Aksi Terjadwal`;
      if (queue.length > 0) {
        const topAction = queue[0];
        actionText.textContent = `[P${topAction.priority}] ${topAction.action_type} pada ${topAction.target}`;
      } else {
        actionText.textContent = "Menganalisis sinyal & teknologi target...";
      }
    } else {
      banner.classList.add("hidden");
    }
  } catch (err) {
    // Fail silently
  } finally {
    isAutonomousFetching = false;
  }
}

// Start periodic telemetry poll only when scan is active
setInterval(pollAutonomousLoopTelemetry, 5000);
window.pollAutonomousLoopTelemetry = pollAutonomousLoopTelemetry;
