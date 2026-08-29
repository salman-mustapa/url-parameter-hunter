/**
 * scan.js — Scan Lifecycle Controls, SSE Streaming & Telemetry Processor
 * Attack Surface & Parameter Intelligence Platform
 */

function updateScanStatusUI(statusText) {
  state.scanStatus = (statusText || "IDLE").toUpperCase();
  const badge = el("scanStatus");
  if (badge) {
    badge.textContent = state.scanStatus;
    badge.className = "pill";
  }

  const isRunning = state.scanStatus === "RUNNING";
  const isPaused = state.scanStatus === "PAUSED";
  const isQueued = state.scanStatus === "QUEUED";
  const isFailed = ["FAILED", "PARTIAL_FAILURE", "DEGRADED", "TIMEOUT"].includes(state.scanStatus);
  const isStopped = ["STOPPED", "CANCELLED"].includes(state.scanStatus);
  const isCompleted = state.scanStatus === "COMPLETED";

  if (badge) {
    if (isRunning) badge.classList.add("pill-running");
    else if (isPaused) badge.classList.add("pill-paused");
    else if (isQueued) badge.classList.add("pill-neutral");
    else if (isFailed) badge.classList.add("pill-failed");
    else if (isStopped) badge.classList.add("pill-stopped");
    else if (isCompleted) badge.classList.add("pill-completed");
    else badge.classList.add("pill-neutral");
  }

  // Always keep "Scan Intelligence & Professional Report Center" card 100% synchronized
  if (el("dashReportStatus")) {
    el("dashReportStatus").textContent = state.scanStatus;
    if (isRunning) el("dashReportStatus").style.color = "#0284c7";
    else if (isCompleted) el("dashReportStatus").style.color = "#16a34a";
    else if (isStopped) el("dashReportStatus").style.color = "#ea580c";
    else if (isFailed) el("dashReportStatus").style.color = "#dc2626";
    else if (isPaused) el("dashReportStatus").style.color = "#ca8a04";
    else el("dashReportStatus").style.color = "#64748b";
  }
  if (el("dashReportTarget") && (state.currentTarget || el("targetInput")?.value)) {
    el("dashReportTarget").textContent = state.currentTarget || el("targetInput")?.value;
  }

  if (isRunning) {
    // Multi-scan capability: Always allow starting a new target scan in parallel
    if (el("startBtn")) {
      el("startBtn").disabled = false;
      const inputVal = el("targetInput") ? el("targetInput").value.trim() : "";
      if (inputVal && inputVal !== state.activeTarget && inputVal !== state.currentTarget) {
        el("startBtn").innerHTML = `<span class="btn-icon">🚀</span> START SCAN (PARALEL)`;
      } else {
        el("startBtn").innerHTML = `<span class="btn-icon">🚀</span> START SCAN`;
      }
    }
    if (el("pauseBtn")) {
      el("pauseBtn").disabled = false;
      el("pauseBtn").classList.remove("hidden");
    }
    if (el("resumeBtn")) el("resumeBtn").classList.add("hidden");
    if (el("stopBtn")) el("stopBtn").disabled = false;
    if (el("exportBtn")) el("exportBtn").disabled = false;
    if (el("scanCompletedBanner")) el("scanCompletedBanner").classList.add("hidden");
  } else if (isPaused) {
    if (el("startBtn")) {
      el("startBtn").disabled = false;
      el("startBtn").innerHTML = `<span class="btn-icon">🚀</span> START SCAN`;
    }
    if (el("pauseBtn")) el("pauseBtn").classList.add("hidden");
    if (el("resumeBtn")) {
      el("resumeBtn").disabled = false;
      el("resumeBtn").classList.remove("hidden");
    }
    if (el("stopBtn")) el("stopBtn").disabled = false;
    if (el("exportBtn")) el("exportBtn").disabled = false;
  } else if (isQueued) {
    if (el("startBtn")) {
      el("startBtn").disabled = false;
      el("startBtn").innerHTML = `<span class="btn-icon">🚀</span> START SCAN`;
    }
    if (el("pauseBtn")) el("pauseBtn").disabled = true;
    if (el("stopBtn")) el("stopBtn").disabled = false;
    if (el("exportBtn")) el("exportBtn").disabled = true;
  } else {
    if (el("startBtn")) {
      el("startBtn").disabled = false;
      el("startBtn").innerHTML = `<span class="btn-icon">🚀</span> START SCAN`;
    }
    if (el("pauseBtn")) {
      el("pauseBtn").disabled = true;
      el("pauseBtn").classList.remove("hidden");
    }
    if (el("resumeBtn")) el("resumeBtn").classList.add("hidden");
    if (el("stopBtn")) el("stopBtn").disabled = true;
    if (el("exportBtn")) el("exportBtn").disabled = !state.activeScanId;

    if (isCompleted && el("scanCompletedBanner")) {
      const fCount = state.counters.findings || 0;
      const aCount = state.counters.assets || 0;
      const pCount = state.counters.ports || 0;
      if (el("scanCompletedTitle")) el("scanCompletedTitle").textContent = "Pemindaian Selesai!";
      if (el("scanCompletedSummary")) {
        el("scanCompletedSummary").textContent = `Attack surface berhasil dipetakan: ${aCount} aset aktif, ${pCount} open ports, dan ${fCount} temuan kerentanan terdeteksi.`;
      }
      el("scanCompletedBanner").classList.remove("hidden");
    }
  }

  // Update active scans bar
  syncActiveScansBar();
}

// Dynamic input listener to update start button text for parallel scan
if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const targetInput = el("targetInput");
    if (targetInput) {
      targetInput.addEventListener("input", () => {
        const val = targetInput.value.trim();
        const btn = el("startBtn");
        if (btn) {
          if (state.scanStatus === "RUNNING" && val && val !== state.activeTarget && val !== state.currentTarget) {
            btn.innerHTML = `<span class="btn-icon">🚀</span> START SCAN (PARALEL)`;
          } else {
            btn.innerHTML = `<span class="btn-icon">🚀</span> START SCAN`;
          }
        }
      });
    }
  });
}

let activeScansFetching = false;
let lastActiveScansSync = 0;
async function syncActiveScansBar() {
  const bar = el("activeScansBar");
  const list = el("activeScansChipsList");
  if (!bar || !list || !state.currentUser || activeScansFetching || Date.now() - lastActiveScansSync < 2000) return;

  activeScansFetching = true;
  try {
    const res = await authFetch(`${API_BASE}/scans?limit=25`);
    if (!res.ok) return;
    const scans = await res.json();
    lastActiveScansSync = Date.now();
    const allScans = Array.isArray(scans) ? scans : (scans.items || []);
    const activeScans = allScans.filter(
      s => (s.status || "").toUpperCase() === "RUNNING" || (s.status || "").toUpperCase() === "PAUSED"
    );

    if (activeScans.length === 0) {
      bar.classList.add("hidden");
      return;
    }

    bar.classList.remove("hidden");
    list.innerHTML = activeScans.map(s => {
      const isCurrent = s.id === state.activeScanId;
      const targetLabel = s.target_domain || s.target_url || s.root_domain || s.target || ("Scan " + s.id.slice(-6));
      const st = (s.status || "RUNNING").toUpperCase();
      const dotColor = st === "RUNNING" ? "#22c55e" : "#f59e0b";
      return `
        <button type="button" class="active-scan-chip ${isCurrent ? 'active' : ''}" 
                onclick="switchActiveScan('${s.id}')"
                title="Beralih ke pemantauan scan: ${escapeHtml(targetLabel)} (${st})">
          <span class="chip-status-dot" style="background:${dotColor}"></span>
          <span>📍 ${escapeHtml(targetLabel)}</span>
          <span style="font-size: 0.72rem; opacity: 0.85;">[${st}]</span>
        </button>
      `;
    }).join("");
  } catch (err) {
    console.debug("Sync active scans bar error:", err);
  } finally {
    activeScansFetching = false;
  }
}

async function switchActiveScan(scanId) {
  if (!scanId) return;
  if (typeof openHistoricalScan === "function") {
    await openHistoricalScan(scanId);
  }
  syncActiveScansBar();
}

function startTimer(initialSeconds = 0) {
  clearInterval(state.timerInterval);
  state.timerSeconds = initialSeconds;
  if (el("scanTime")) {
    el("scanTime").classList.remove("hidden");
    el("scanTime").textContent = `⏱ ${formatTime(state.timerSeconds)}`;
  }
  state.timerInterval = setInterval(() => {
    state.timerSeconds++;
    if (el("scanTime")) el("scanTime").textContent = `⏱ ${formatTime(state.timerSeconds)}`;
  }, 1000);
}

function stopTimer() {
  clearInterval(state.timerInterval);
}

let scanCreationPending = false;
async function startScan() {
  if (scanCreationPending) return;
  if (!state.currentUser) { openAuthModal("login"); return; }
  const target = el("targetInput") ? el("targetInput").value.trim() : "";
  if (!target) {
    showToast("Masukkan root domain atau URL target (contoh: example.com atau https://target.com)", "warning");
    return;
  }

  const previousRunningTarget = (state.scanStatus === "RUNNING" && state.activeTarget) ? state.activeTarget : null;
  const scopeMode = el("scopeModeSelect") ? el("scopeModeSelect").value : "recursive";
  const includeSubdomains = scopeMode === "recursive";
  const device_fingerprint = getDeviceFingerprint();
  let engagement;
  try { engagement = readEngagementForm(); }
  catch (error) { showToast(error.message, "warning"); return; }

  scanCreationPending = true;
  setButtonLoading(el("startBtn"), true, "Memulai...");
  try {
    const res = await authFetch(`${API_BASE}/investigations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: target,
        profile: "adversary_simulation",
        validation_level: "L4_HIGH_RISK",
        include_subdomains: includeSubdomains,
        device_fingerprint: device_fingerprint,
        engagement,
        authorization_reference: engagement.authorization_reference || `AUTHORIZED-L4-${target.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30)}-AUDIT`,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
      const detail = apiError(err, `HTTP ${res.status}`);

      // Check if trial limit reached
      if (res.status === 403 && (detail.includes("TRIAL_EXHAUSTED") || detail.includes("trial"))) {
        const trialModal = el("trialLimitModal");
        if (trialModal) {
          trialModal.classList.remove("hidden");
        } else {
          showAuthAlert("⚠️ Percobaan gratis untuk perangkat ini telah digunakan. Silakan Masuk atau Daftar Akun Baru untuk melanjutkan pemindaian!", false);
          el("authModal")?.classList.remove("hidden");
        }
        return;
      }

      throw new Error(detail);
    }

    const data = await res.json();
    state.activeScanId = data.scan_id;
    state.activeTarget = data.target;
    state.currentTarget = data.target;

    if (typeof updateRouteURL === "function") updateRouteURL("dashboard", { scan_id: data.scan_id });
    if (typeof updateBreadcrumbUI === "function") updateBreadcrumbUI("dashboard", { scan_id: data.scan_id });

    if (el("scanIdDisplay")) {
      el("scanIdDisplay").textContent = `ID: ${data.scan_id}`;
      el("scanIdDisplay").classList.remove("hidden");
    }

    // Reset counters & stream for the newly started scan
    state.events = [];
    state.counters = { assets: 0, ports: 0, urls: 0, params: 0, techs: 0, findings: 0 };
    state.severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    updateCounterDisplays();

    if (el("eventStreamContainer")) el("eventStreamContainer").innerHTML = "";
    if (el("assetTreeContainer")) el("assetTreeContainer").innerHTML = `<div class="tree-empty-msg"><p>Menjalankan pipeline aktif...</p></div>`;
    if (el("findingsListContainer")) el("findingsListContainer").innerHTML = `<div class="findings-empty-msg"><p>Menganalisis temuan keamanan...</p></div>`;

    updateScanStatusUI((data.status || "QUEUED").toUpperCase());
    if ((data.status || "").toUpperCase() === "RUNNING") startTimer();
    connectEventSource(data.scan_id);

    clearInterval(state.treePollInterval);
    if (typeof refreshAssetTree === "function") {
      state.treePollInterval = setInterval(refreshAssetTree, 4000);
      refreshAssetTree();
    }

    clearInterval(state.statusPollInterval);
    state.statusPollInterval = setInterval(syncScanStatus, 3000);
    syncScanStatus();

    if (previousRunningTarget && previousRunningTarget !== target) {
      showToast(`🚀 Scan baru dimulai untuk ${target}! Scan sebelumnya (${previousRunningTarget}) tetap berjalan di latar belakang.`, "success");
    } else {
      showToast(`🚀 Scan reconnaissance dimulai untuk ${target}!`, "success");
    }

    syncActiveScansBar();
  } catch (err) {
    showToast(`Gagal memulai scan: ${err.message}`, "danger");
  } finally {
    scanCreationPending = false;
    setButtonLoading(el("startBtn"), false);
  }
}

let isStatusFetching = false;

async function syncScanStatus() {
  if (!state.activeScanId || isStatusFetching) return;
  if (typeof document !== "undefined" && document.hidden) return;

  isStatusFetching = true;
  const currentScanId = state.activeScanId;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(currentScanId)}`);
    if (!res.ok || state.activeScanId !== currentScanId) return;
    const scan = await res.json();
    if (state.activeScanId !== currentScanId) return;
    if (scan.progress) {
      if (scan.progress.assets != null && scan.progress.assets > state.counters.assets) state.counters.assets = scan.progress.assets;
      if (scan.progress.ports != null && scan.progress.ports > state.counters.ports) state.counters.ports = scan.progress.ports;
      if (scan.progress.urls != null && scan.progress.urls > state.counters.urls) state.counters.urls = scan.progress.urls;
      if (scan.progress.parameters != null && scan.progress.parameters > state.counters.params) state.counters.params = scan.progress.parameters;
      if (scan.progress.technologies != null && scan.progress.technologies > state.counters.techs) state.counters.techs = scan.progress.technologies;
      if (scan.progress.findings != null && scan.progress.findings > state.counters.findings) {
        state.counters.findings = scan.progress.findings;
        if (typeof loadFindings === "function") loadFindings();
      }
      updateCounterDisplays();
    }
    const st = (scan.status || "").toUpperCase();
    if (["RUNNING", "QUEUED", "PAUSED"].includes(st) && st !== state.scanStatus) updateScanStatusUI(st);
    if (["COMPLETED", "STOPPED", "FAILED", "PARTIAL_FAILURE", "DEGRADED", "TIMEOUT", "CANCELLED"].includes(st)) {
      updateScanStatusUI(st);
      stopTimer();
      clearInterval(state.treePollInterval);
      clearInterval(state.statusPollInterval);
      if (typeof refreshAssetTree === "function") refreshAssetTree();
      if (typeof loadFindings === "function") loadFindings();
      if (typeof loadReportHubData === "function" && state.activeScanId) loadReportHubData(state.activeScanId);
      if (state.es) state.es.close();
    }
    syncActiveScansBar();
  } catch (err) {
    console.debug("Sync scan status skip:", err);
  } finally {
    isStatusFetching = false;
  }
}

async function pauseScan() {
  const scanId = state.activeScanId || state.currentScanId || (el("scanIdBadge")?.textContent?.replace(/ID:\s*/i, "")?.trim()) || null;
  if (!scanId) return;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/pause`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast("Gagal pause scan: " + (err.detail || res.statusText), "danger");
      return;
    }
    updateScanStatusUI("PAUSED");
    showToast("Scan dijeda (PAUSED).", "info");
    syncActiveScansBar();
  } catch (err) {
    showToast("Gagal pause scan: " + err.message, "danger");
  }
}

async function resumeScan() {
  const scanId = state.activeScanId || state.currentScanId || (el("scanIdBadge")?.textContent?.replace(/ID:\s*/i, "")?.trim()) || null;
  if (!scanId) return;
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/resume`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast("Gagal resume scan: " + (err.detail || res.statusText), "danger");
      return;
    }
    updateScanStatusUI("RUNNING");
    showToast("Scan dilanjutkan (RUNNING).", "info");
    syncActiveScansBar();
  } catch (err) {
    showToast("Gagal resume scan: " + err.message, "danger");
  }
}

async function stopScan() {
  const scanId = state.activeScanId || state.currentScanId || (el("scanIdBadge")?.textContent?.replace(/ID:\s*/i, "")?.trim()) || null;
  if (!scanId) {
    showToast("Tidak ada sesi scan aktif yang dapat dihentikan.", "warning");
    return;
  }
  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/stop`, { method: "POST" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      showToast("Gagal menghentikan scan: " + (err.detail || res.statusText), "danger");
      return;
    }
    updateScanStatusUI("STOPPED");
    stopTimer();
    if (state.es) {
      state.es.close();
      state.es = null;
    }
    clearInterval(state.treePollInterval);
    clearInterval(state.statusPollInterval);
    if (typeof refreshAssetTree === "function") refreshAssetTree();
    if (typeof loadFindings === "function") loadFindings();
    if (typeof loadReportHubData === "function" && scanId) loadReportHubData(scanId);
    showToast("Pemindaian berhasil dihentikan (STOPPED).", "warning");
    syncActiveScansBar();
  } catch (err) {
    showToast("Gagal stop scan: " + err.message, "danger");
  }
}

function connectEventSource(scanId) {
  if (state.es) {
    state.es.close();
  }

  const es = new EventSource(`${API_BASE}/scans/${encodeURIComponent(scanId)}/events`);
  state.es = es;

  es.onmessage = (e) => {
    try {
      const raw = JSON.parse(e.data);
      const ev = {
        ...(raw.data && typeof raw.data === "object" ? raw.data : {}),
        ...raw,
        event_type: raw.event_type || raw.type || "",
      };
      if (typeof addEventToStream === "function") addEventToStream(ev);
      processEventTelemetry(ev);
    } catch (err) {
      console.debug("SSE json parse skip:", err);
    }
  };

  es.onerror = () => {
    console.debug("SSE connection closed or re-negotiating.");
    const terminal = ["COMPLETED", "FAILED", "STOPPED", "PARTIAL_FAILURE", "DEGRADED", "TIMEOUT", "CANCELLED"].includes((state.scanStatus || "").toUpperCase());
    if (terminal && state.es) {
      state.es.close();
      state.es = null;
    }
  };
}

let _treeRefreshDebounceTimer = null;
function debouncedRefreshAssetTree() {
  if (_treeRefreshDebounceTimer) return;
  _treeRefreshDebounceTimer = setTimeout(() => {
    _treeRefreshDebounceTimer = null;
    if (typeof refreshAssetTree === "function") {
      refreshAssetTree();
    }
  }, 1200);
}

let _findingsRefreshDebounceTimer = null;
function debouncedLoadFindings() {
  if (_findingsRefreshDebounceTimer) return;
  _findingsRefreshDebounceTimer = setTimeout(() => {
    _findingsRefreshDebounceTimer = null;
    if (typeof loadFindings === "function") {
      loadFindings();
    }
  }, 1000);
}

function processEventTelemetry(ev) {
  const type = ev.event_type || "";

  if (type.startsWith("asset.") || type === "discovery.validated" || type.startsWith("discovery.")) {
    state.counters.assets++;
    debouncedRefreshAssetTree();
  } else if (type.startsWith("port.")) {
    state.counters.ports++;
  } else if (type.startsWith("url.") || type.startsWith("crawl.") || type.startsWith("http.")) {
    state.counters.urls++;
  } else if (type.startsWith("parameter.") || type.startsWith("param.")) {
    state.counters.params++;
  } else if (type.startsWith("technology.") || type.startsWith("tech.")) {
    state.counters.techs++;
  } else if (type.startsWith("finding.") || type.startsWith("scan.finding")) {
    state.counters.findings++;
    const sev = (ev.data && ev.data.severity) ? ev.data.severity.toUpperCase() : (ev.severity || "INFO").toUpperCase();
    if (state.severityCounts[sev] != null) {
      state.severityCounts[sev]++;
    }
    debouncedLoadFindings();
  } else if (type.startsWith("state_machine.") || type.startsWith("engine.") || type.startsWith("hypothesis.") || type.startsWith("plan.") || type.startsWith("discovery.")) {
    if (typeof triggerV4DebouncedSync === "function") {
      triggerV4DebouncedSync();
    }
  } else if (type === "scan.completed") {
    updateScanStatusUI("COMPLETED");
    stopTimer();
    clearInterval(state.treePollInterval);
    clearInterval(state.statusPollInterval);
    if (typeof refreshAssetTree === "function") refreshAssetTree();
    if (typeof loadFindings === "function") loadFindings();
    if (typeof loadReportHubData === "function" && state.activeScanId) loadReportHubData(state.activeScanId);
    if (state.es) {
      state.es.close();
      state.es = null;
    }
  } else if (["scan.failed", "scan.stopped", "scan.degraded", "scan.timeout", "scan.cancelled"].includes(type) || (ev.message && typeof ev.message === "string" && ev.message.includes("Scan stopped"))) {
    const terminalStatus = type === "scan.timeout" ? "TIMEOUT" : (type === "scan.degraded" ? "DEGRADED" : (type === "scan.failed" ? "FAILED" : "STOPPED"));
    updateScanStatusUI(terminalStatus);
    stopTimer();
    clearInterval(state.treePollInterval);
    clearInterval(state.statusPollInterval);
    if (typeof refreshAssetTree === "function") refreshAssetTree();
    if (typeof loadFindings === "function") loadFindings();
    if (typeof loadReportHubData === "function" && state.activeScanId) loadReportHubData(state.activeScanId);
    if (state.es) {
      state.es.close();
      state.es = null;
    }
  }

  updateCounterDisplays();
}

function updateCounterDisplays() {
  if (state.scanStatus === "COMPLETED" && el("scanCompletedSummary")) {
    el("scanCompletedSummary").textContent = `${state.counters.assets} aset, ${state.counters.ports} port, dan ${state.counters.findings} temuan tercatat. Tinjau bukti dan cakupan sebelum menyimpulkan hasil.`;
  }
  if (el("counterAssets")) el("counterAssets").textContent = state.counters.assets;
  if (el("counterPorts")) el("counterPorts").textContent = state.counters.ports;
  if (el("counterUrls")) el("counterUrls").textContent = state.counters.urls;
  if (el("counterParams")) el("counterParams").textContent = state.counters.params;
  if (el("counterTechs")) el("counterTechs").textContent = state.counters.techs;
  if (el("counterFindings")) el("counterFindings").textContent = state.counters.findings;

  if (el("sevCritCount")) el("sevCritCount").textContent = state.severityCounts.CRITICAL || 0;
  if (el("sevHighCount")) el("sevHighCount").textContent = state.severityCounts.HIGH || 0;
  if (el("sevMedCount")) el("sevMedCount").textContent = state.severityCounts.MEDIUM || 0;
  if (el("sevLowCount")) el("sevLowCount").textContent = state.severityCounts.LOW || 0;
  if (el("sevInfoCount")) el("sevInfoCount").textContent = state.severityCounts.INFO || 0;
  if (el("findingsBadgeTotal")) el("findingsBadgeTotal").textContent = `${state.counters.findings} Total`;
}
