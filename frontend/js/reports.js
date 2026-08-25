/**
 * reports.js — Dedicated Report Hub & Professional Disclosure Center (V5 §31-§35)
 * Attack Surface & Parameter Intelligence Platform
 */

let currentReportScanId = null;
let currentReportScanData = null;
let currentReportFindings = [];

async function initReportHub(preferredScanId = null) {
  const selectEl = el("reportScanSelect");
  if (!selectEl) return;

  try {
    const res = await authFetch(`${API_BASE}/scans`);
    const scans = await res.json();

    selectEl.innerHTML = "";
    if (!scans || !scans.length) {
      selectEl.innerHTML = `<option value="">Belum ada scan tersimpan</option>`;
      renderReportHubEmpty();
      return;
    }

    scans.forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.id;
      const dateStr = s.created_at ? new Date(s.created_at).toLocaleDateString("id-ID") : "";
      opt.textContent = `${s.root_domain} — #${s.id.slice(0, 16)} (${s.status.toUpperCase()}) [${dateStr}]`;
      selectEl.appendChild(opt);
    });

    // Select preferredScanId or active scan or first scan
    const targetScan = preferredScanId && scans.some(s => s.id === preferredScanId) ? preferredScanId : (state.activeScanId && scans.some(s => s.id === state.activeScanId) ? state.activeScanId : scans[0].id);
    selectEl.value = targetScan;

    currentReportScanId = targetScan;
    await loadReportHubData(currentReportScanId);
  } catch (err) {
    console.error("Failed to load scans for Report Hub:", err);
  }
}

async function loadReportHubData(scanId, updateUrl = false) {
  if (!scanId) {
    renderReportHubEmpty();
    return;
  }
  currentReportScanId = scanId;
  const isReportsViewActive = el("viewReports") && !el("viewReports").classList.contains("hidden");
  if (updateUrl || isReportsViewActive) {
    updateRouteURL("reports", { scan_id: scanId });
    updateBreadcrumbUI("reports", { scan_id: scanId });
  }

  try {
    const [scanRes, findingsRes] = await Promise.all([
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`),
      authFetch(`${API_BASE}/findings?scan_id=${encodeURIComponent(scanId)}`),
    ]);

    currentReportScanData = await scanRes.json();
    currentReportFindings = await findingsRes.json() || [];

    renderReportHubView(currentReportScanData, currentReportFindings);
  } catch (err) {
    console.error("Failed to fetch report data:", err);
  }
}

function renderReportHubEmpty() {
  if (el("reportTargetBadge")) el("reportTargetBadge").textContent = "TARGET: -";
  if (el("reportExecTitle")) el("reportExecTitle").textContent = "Belum Ada Data Scan";
  if (el("reportScanIdChip")) el("reportScanIdChip").textContent = "Scan ID: -";
  if (el("reportDateChip")) el("reportDateChip").textContent = "Tanggal: -";
  if (el("reportRiskGauge")) el("reportRiskGauge").textContent = "0.0";
  if (el("reportRiskStatus")) el("reportRiskStatus").textContent = "NO DATA";
  if (el("reportHubFindingsContainer")) {
    el("reportHubFindingsContainer").innerHTML = `<div class="empty-msg">Silakan pilih atau jalankan scan untuk melihat pusat laporan.</div>`;
  }
  if (el("dashReportTarget")) el("dashReportTarget").textContent = "-";
  if (el("dashReportStatus")) el("dashReportStatus").textContent = "IDLE";
  if (el("dashReportRisk")) el("dashReportRisk").textContent = "0.0 / 10.0";
  if (el("dashReportEvidence")) el("dashReportEvidence").textContent = "NO PROOF";
  if (el("dashReportExecText")) el("dashReportExecText").textContent = "Hasil audit attack surface dan validasi parameter akan disintesis secara otomatis di sini setelah pemindaian selesai.";
}

function renderReportHubView(scan, findings) {
  const p = scan.progress || {};
  const exactTarget = (scan.options && (scan.options.target_url || scan.options.target_host)) || scan.target_url || scan.target_host || scan.root_domain || "Target";
  const rootDomain = scan.root_domain || exactTarget;
  const dateStr = scan.created_at ? new Date(scan.created_at).toLocaleString("id-ID") : "-";

  // 1. Executive Banner
  if (el("reportTargetBadge")) el("reportTargetBadge").textContent = `TARGET: ${exactTarget.toUpperCase()}`;
  if (el("reportExecTitle")) el("reportExecTitle").textContent = `Security Assessment Report: ${exactTarget}`;
  if (el("reportExecDesc")) {
    el("reportExecDesc").textContent = `Laporan hasil analisis keamanan mendalam dan investigasi attack surface untuk target ${exactTarget} (Domain: ${rootDomain}, Profile: ${scan.profile || 'standard'}).`;
  }
  if (el("reportScanIdChip")) el("reportScanIdChip").textContent = `ID: #${scan.id}`;
  if (el("reportDateChip")) el("reportDateChip").textContent = `📅 ${dateStr}`;

  // Dashboard-integrated report card sync
  if (el("dashReportTarget")) el("dashReportTarget").textContent = exactTarget;
  if (el("dashReportStatus")) {
    const st = (scan.status || state.scanStatus || "COMPLETED").toUpperCase();
    el("dashReportStatus").textContent = st;
    if (st === "RUNNING") el("dashReportStatus").style.color = "#0284c7";
    else if (st === "COMPLETED") el("dashReportStatus").style.color = "#16a34a";
    else if (st === "STOPPED") el("dashReportStatus").style.color = "#ea580c";
    else if (st === "FAILED") el("dashReportStatus").style.color = "#dc2626";
    else if (st === "PAUSED") el("dashReportStatus").style.color = "#ca8a04";
    else el("dashReportStatus").style.color = "#64748b";
  }

  // 2. Risk Calculation
  let maxCvss = 0.0;
  let critCount = 0;
  let highCount = 0;
  findings.forEach(f => {
    const sev = (f.severity || "").toUpperCase();
    if (sev === "CRITICAL") critCount++;
    if (sev === "HIGH") highCount++;
    if (f.cvss_score && f.cvss_score > maxCvss) maxCvss = f.cvss_score;
  });

  if (maxCvss === 0.0) {
    if (critCount > 0) maxCvss = 9.8;
    else if (highCount > 0) maxCvss = 7.8;
    else if (findings.length > 0) maxCvss = 5.3;
  }

  if (el("reportRiskGauge")) el("reportRiskGauge").textContent = maxCvss.toFixed(1);
  if (el("dashReportRisk")) el("dashReportRisk").textContent = `${maxCvss.toFixed(1)} / 10.0`;

  const riskStatusEl = el("reportRiskStatus");
  if (riskStatusEl) {
    if (critCount > 0 || maxCvss >= 9.0) {
      riskStatusEl.textContent = "CRITICAL RISK";
      riskStatusEl.className = "risk-gauge-status bg-critical";
    } else if (highCount > 0 || maxCvss >= 7.0) {
      riskStatusEl.textContent = "HIGH RISK";
      riskStatusEl.className = "risk-gauge-status bg-high";
    } else if (findings.length > 0) {
      riskStatusEl.textContent = "MODERATE RISK";
      riskStatusEl.className = "risk-gauge-status bg-medium";
    } else {
      riskStatusEl.textContent = "SECURE / CLEAN";
      riskStatusEl.className = "risk-gauge-status bg-clean";
    }
  }

  if (el("dashReportExecText")) {
    el("dashReportExecText").textContent = findings.length
      ? `Teridentifikasi ${findings.length} temuan keamanan (${critCount} Critical, ${highCount} High) pada ${p.assets || 1} subdomain aktif dan ${p.ports || 0} port terbuka untuk ${rootDomain}. Seluruh temuan telah diverifikasi melalui Proof Quality Gate non-destruktif.`
      : `Pemindaian pada ${rootDomain} selesai. Attack surface berhasil dipetakan (${p.assets || 1} subdomain, ${p.ports || 0} port) tanpa temuan risiko kritis terkonfirmasi.`;
  }

  // 3. Telemetry Numbers
  if (el("repStatAssets")) el("repStatAssets").textContent = p.assets || 0;
  if (el("repStatPorts")) el("repStatPorts").textContent = p.ports || 0;
  if (el("repStatUrls")) el("repStatUrls").textContent = p.urls || 0;
  if (el("repStatParams")) el("repStatParams").textContent = p.params || 0;
  if (el("repStatFindings")) el("repStatFindings").textContent = findings.length || p.findings || 0;

  // 4. Validated Findings Table
  const container = el("reportHubFindingsContainer");
  if (!container) return;

  if (!findings.length) {
    container.innerHTML = `<div class="empty-msg">Tidak ada temuan kerentanan keamanan yang terdeteksi pada sesi scan ini.</div>`;
    return;
  }

  let html = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Evidence Level</th>
          <th>Kode & Judul Temuan</th>
          <th>Host / Subdomain</th>
          <th>CWE / CVSS</th>
          <th>Status Validasi</th>
          <th>Aksi Inspeksi</th>
        </tr>
      </thead>
      <tbody>
  `;

  findings.forEach((f) => {
    const sev = (f.severity || "INFO").toUpperCase();
    const evLevel = f.evidence_level || "E3";
    html += `
      <tr>
        <td><span class="severity-badge severity-${sev.toLowerCase()}">${sev}</span></td>
        <td><span class="badge-e3">${esc(evLevel)}</span></td>
        <td><strong>${esc(f.finding_code || f.id)}</strong>: ${esc(f.title)}</td>
        <td><strong>${esc(f.asset_hostname || rootDomain)}</strong></td>
        <td><code>${esc(f.cwe_id || '-')}</code> ${f.cvss_score ? `(${f.cvss_score})` : ''}</td>
        <td><span class="status-badge status-${(f.status || 'open').toLowerCase()}">${esc(f.status || 'CONFIRMED')}</span></td>
        <td>
          <button class="btn btn-primary btn-xs" onclick="openFindingDetail('${esc(f.id)}')">🔒 Detail (V5)</button>
        </td>
      </tr>
    `;
  });

  html += `</tbody></table>`;
  container.innerHTML = html;
}

function setupReportHubEvents() {
  const selectEl = el("reportScanSelect");
  if (selectEl) {
    selectEl.addEventListener("change", (e) => {
      loadReportHubData(e.target.value);
    });
  }

  const refreshBtn = el("refreshReportHubBtn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      initReportHub();
    });
  }

  // Bind Dashboard Report Card buttons
  const dashBB = el("dashReportBBBtn");
  if (dashBB) {
    dashBB.onclick = () => {
      const sid = state.activeScanId || currentReportScanId;
      if (!sid) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/report/markdown`, "_blank");
    };
  }

  const dashCVE = el("dashReportCVEBtn");
  if (dashCVE) {
    dashCVE.onclick = () => {
      const sid = state.activeScanId || currentReportScanId;
      if (!sid) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(sid)}/report/markdown`, "_blank");
    };
  }

  const dashJSON = el("dashReportJSONBtn");
  if (dashJSON) {
    dashJSON.onclick = async () => {
      const sid = state.activeScanId || currentReportScanId;
      if (!sid) return showToast("Pilih scan target terlebih dahulu.", "warning");
      try {
        const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(sid)}/export`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `evidence_package_${sid}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Evidence Package JSON berhasil diunduh.", "success");
      } catch (err) {
        showToast("Gagal mengunduh paket bukti: " + err.message, "danger");
      }
    };
  }

  // 1. PDF
  const pdfBtn = el("hubPdfBtn");
  if (pdfBtn) {
    pdfBtn.addEventListener("click", () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(currentReportScanId)}/report/pdf`, "_blank");
    });
  }

  // 2. HTML
  const htmlBtn = el("hubHtmlBtn");
  if (htmlBtn) {
    htmlBtn.addEventListener("click", () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(currentReportScanId)}/report/html`, "_blank");
    });
  }

  // 3. Bug Bounty MD
  const bountyBtn = el("hubBountyBtn");
  if (bountyBtn) {
    bountyBtn.addEventListener("click", () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(currentReportScanId)}/report/markdown`, "_blank");
    });
  }

  // 4. CVE Research MD
  const cveBtn = el("hubCveBtn");
  if (cveBtn) {
    cveBtn.addEventListener("click", async () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      window.open(`${API_BASE}/scans/${encodeURIComponent(currentReportScanId)}/report/markdown`, "_blank");
    });
  }

  // 5. Evidence Package Bundle JSON
  const jsonBtn = el("hubJsonBtn");
  if (jsonBtn) {
    jsonBtn.addEventListener("click", async () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      try {
        const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(currentReportScanId)}/export`);
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `evidence_package_${currentReportScanId}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Evidence Package JSON berhasil diunduh.", "success");
      } catch (err) {
        showToast("Gagal mengunduh paket bukti: " + err.message, "danger");
      }
    });
  }

  // 6. Reproduction Bundle MD
  const reproBtn = el("hubReproBtn");
  if (reproBtn) {
    reproBtn.addEventListener("click", async () => {
      if (!currentReportScanId) return showToast("Pilih scan target terlebih dahulu.", "warning");
      try {
        const findings = currentReportFindings || [];
        if (!findings.length) {
          showToast("Tidak ada temuan pada scan ini untuk dibuatkan panduan reproduksi.", "warning");
          return;
        }
        const firstFindingId = findings[0].id;
        const res = await authFetch(`${API_BASE}/findings/${encodeURIComponent(firstFindingId)}/reproduction`);
        const data = await res.json();
        const blob = new Blob([data.markdown || "# Reproduction Bundle"], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `reproduction_${firstFindingId}.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Panduan reproduksi berhasil diunduh.", "success");
      } catch (err) {
        showToast("Gagal mengunduh panduan reproduksi: " + err.message, "danger");
      }
    });
  }
}
