/**
 * findings.js — Security Findings Triaging, Evidence Quality & V5 Deep Triaging (V5 §2, §26, §32, §37)
 * Attack Surface & Parameter Intelligence Platform
 */

let findingsRequest = null;
async function loadFindings() {
  if (!state.activeScanId) {
    state.allFindings = [];
    state.counters.findings = 0;
    state.severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    if (el("sevCritCount")) el("sevCritCount").textContent = "0";
    if (el("sevHighCount")) el("sevHighCount").textContent = "0";
    if (el("sevMedCount")) el("sevMedCount").textContent = "0";
    if (el("sevLowCount")) el("sevLowCount").textContent = "0";
    if (el("sevInfoCount")) el("sevInfoCount").textContent = "0";
    if (el("findingsBadgeTotal")) el("findingsBadgeTotal").textContent = "0 Total";
    if (typeof updateCounterDisplays === "function") updateCounterDisplays();
    renderFindings([]);
    return;
  }
  const scanId = state.activeScanId;
  if (findingsRequest?.scanId === scanId) { findingsRequest.again = true; return; }
  findingsRequest?.controller.abort();
  const request = {scanId, controller: new AbortController()};
  findingsRequest = request;
  try {
    const res = await authFetch(`${API_BASE}/findings?scan_id=${encodeURIComponent(scanId)}`, {signal: request.controller.signal});
    if (!res.ok) return;
    const findings = await res.json();
    if (state.activeScanId !== scanId || request.controller.signal.aborted) return;
    state.allFindings = Array.isArray(findings) ? findings : [];
    state.counters.findings = state.allFindings.length;

    let crit = 0, high = 0, med = 0, low = 0, info = 0;
    state.allFindings.forEach(f => {
      const s = (f.severity || "INFO").toUpperCase();
      if (s === "CRITICAL") crit++;
      else if (s === "HIGH") high++;
      else if (s === "MEDIUM") med++;
      else if (s === "LOW") low++;
      else info++;
    });
    state.severityCounts = { CRITICAL: crit, HIGH: high, MEDIUM: med, LOW: low, INFO: info };
    if (el("sevCritCount")) el("sevCritCount").textContent = crit;
    if (el("sevHighCount")) el("sevHighCount").textContent = high;
    if (el("sevMedCount")) el("sevMedCount").textContent = med;
    if (el("sevLowCount")) el("sevLowCount").textContent = low;
    if (el("sevInfoCount")) el("sevInfoCount").textContent = info;
    if (el("findingsBadgeTotal")) el("findingsBadgeTotal").textContent = `${state.allFindings.length} Total`;

    if (typeof updateCounterDisplays === "function") updateCounterDisplays();
    renderFindings();
  } catch (err) {
    if (err.name !== "AbortError") console.error("Load findings error:", err);
  } finally {
    if (findingsRequest === request) {
      findingsRequest = null;
      if (request.again && state.activeScanId === scanId) loadFindings();
    }
  }
}

function renderFindings(customFindings) {
  const container = el("findingsListContainer");
  if (!container) return;
  container.innerHTML = "";

  const findings = customFindings || state.allFindings || [];
  const sevFilter = state.currentFindingsSevFilter || "ALL";

  const filtered = (sevFilter === "ALL")
    ? findings
    : findings.filter((f) => (f.severity || "INFO").toUpperCase() === sevFilter);

  if (!filtered.length) {
    const filterMsg = sevFilter !== "ALL"
      ? `Tidak ada temuan dengan tingkat keparahan "${esc(sevFilter)}".`
      : "Belum ada temuan kerentanan / miskonfigurasi keamanan.";
    container.innerHTML = `<div class="findings-empty-msg"><p>${filterMsg}</p></div>`;
    return;
  }

  filtered.forEach((f) => {
    const sev = (f.severity || "INFO").toUpperCase();
    const eLevel = f.evidence_level || "E0";
    const eScore = f.evidence_score ?? 0;

    const item = document.createElement("div");
    item.className = "finding-item-card";

    // Cards show a bounded preview; full evidence remains in the detail view.
    const evJson = f.evidence && Object.keys(f.evidence).length ? JSON.stringify(f.evidence).slice(0, 1200) : "";
    const pocCode = (f.evidence && (f.evidence.poc || f.evidence.poc_curl || f.evidence.curl_command)) || "";
    const techDetails = f.technical_details || "";

    const hostBadge = f.asset_hostname ? `<span class="finding-host-badge" title="Target Host">🌐 ${esc(f.asset_hostname)}</span>` : "";
    const locBadge = f.location ? `<span class="finding-loc-badge" title="Location">📍 ${esc(f.location)}</span>` : (f.evidence && f.evidence.url ? `<span class="finding-loc-badge" title="URL">📍 ${esc(f.evidence.url)}</span>` : "");
    const cveBadge = f.cve_id ? `<span class="finding-cwe-badge">🏷 ${esc(f.cve_id)}</span>` : "";
    const cweBadge = f.cwe_id ? `<span class="finding-cwe-badge">🏷 ${esc(f.cwe_id)}</span>` : "";
    const cvssBadge = f.cvss_score ? `<span class="finding-cvss-badge">🔥 CVSS ${f.cvss_score}</span>` : "";

    item.innerHTML = `
      <div class="finding-top-row">
        <div class="finding-title-group">
          <span class="finding-badge sev-${sev.toLowerCase()}">${esc(sev)}</span>
          <span class="badge-${eLevel.toLowerCase()}" title="Tingkat Pembuktian Evidence">${esc(eLevel)}</span>
          <strong>${esc(f.title)}</strong>
        </div>
        <select class="triage-select" data-id="${esc(f.id)}" aria-label="Status temuan">
          <option value="${esc(f.status || 'OPEN')}" selected>${esc(f.status || 'OPEN')}</option>
          ${(f.allowed_transitions || []).map(status => `<option value="${esc(status)}">${esc(status)}</option>`).join('')}
        </select>
      </div>

      <div class="finding-asset-banner">
        ${hostBadge}
        ${locBadge}
        ${cveBadge || cweBadge}
        ${cvssBadge}
        <span class="pill-muted" title="Skor Kualitas Bukti">Score: ${eScore}/100</span>
      </div>

      <p class="finding-desc">${esc(f.description || "Tidak ada deskripsi rinci.")}</p>

      ${techDetails ? `<div class="finding-tech-details"><strong>Analisis Teknis:</strong> ${esc(techDetails)}</div>` : ""}
      ${pocCode ? `<div class="finding-poc-box"><code>${esc(pocCode)}</code></div>` : (evJson ? `<div class="finding-evidence-box">Evidence: ${esc(evJson)}</div>` : "")}

      <div class="finding-footer">
        <span class="pill-muted">Confidence: ${formatConfidence(f.confidence)}</span>
        <button class="btn btn-primary btn-xs view-detail-btn" data-finding-id="${esc(f.id)}">🔎 Buka Detail Lengkap (V5)</button>
        ${f.asset_id ? `<button class="btn btn-ghost btn-xs focus-asset-btn" data-asset-id="${esc(f.asset_id)}">🔍 Fokus di Pohon Aset</button>` : ""}
      </div>
    `;

    item.querySelector(".triage-select").addEventListener("change", async (e) => {
      const newStatus = e.target.value;
      e.target.disabled = true;
      try {
        const response = await authFetch(`${API_BASE}/findings/${encodeURIComponent(f.id)}/transition?next_state=${encodeURIComponent(newStatus)}`, {
          method: "POST",
        });
        if (!response.ok) throw new Error(apiError(await response.json(), `HTTP ${response.status}`));
        if (typeof workspaceCache !== "undefined") workspaceCache.delete(f.scan_id);
        await loadFindings();
      } catch (err) {
        e.target.value = f.status;
        if (typeof showToast === "function") showToast("Gagal update status finding: " + err.message, "danger");
      } finally { e.target.disabled = false; }
    });

    const viewDetailBtn = item.querySelector(".view-detail-btn");
    if (viewDetailBtn) {
      viewDetailBtn.addEventListener("click", () => {
        if (typeof openFindingDetail === "function") {
          openFindingDetail(f.id);
        }
      });
    }

    const focusBtn = item.querySelector(".focus-asset-btn");
    if (focusBtn) {
      focusBtn.addEventListener("click", () => {
        const aid = focusBtn.dataset.assetId;
        if (aid) {
          if (typeof loadAssetDetail === "function") loadAssetDetail(aid);
          const treeRow = document.querySelector(`.tree-node-row[data-id="${aid}"]`);
          if (treeRow) {
            treeRow.scrollIntoView({ behavior: "smooth", block: "center" });
            document.querySelectorAll(".tree-node-row").forEach((r) => r.classList.remove("selected"));
            treeRow.classList.add("selected");
          }
        }
      });
    }

    container.appendChild(item);
  });
}
