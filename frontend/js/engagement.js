function readEngagementForm() {
  const read = id => (el(id)?.value || "").trim();
  const ackEl = el("engAuthorizationAck");
  if (ackEl && !ackEl.checked) {
    throw new Error("Konfirmasi izin pemilik target dan isi referensi izin sebelum scan.");
  }
  const authRef = read("engAuthorization");
  if (!authRef) throw new Error("Isi referensi izin program, izin tertulis pemilik, atau aset milik sendiri sebelum scan.");
  const splitHosts = value => value.split(/[\n,]+/).map(x => x.trim()).filter(Boolean);
  const scopeHosts = splitHosts(read("engScopeHosts"));
  if (!scopeHosts.length) throw new Error("Isi minimal satu host/pola pada In-scope hosts sesuai izin pemilik/program.");
  const time = id => read(id) ? new Date(read(id)).toISOString() : null;
  const portTokens = (read("engAllowedPorts") || "80,443").split(',').map(value => value.trim()).filter(Boolean);
  const ports = portTokens.map(value => Number(value));
  if (ports.length > 100 || ports.some(port => isNaN(port) || !Number.isInteger(port) || port < 1 || port > 65535)) {
    throw new Error("Isi port 1–65535, dipisahkan koma (maksimal 100 port).");
  }
  return {
    authorization_reference: authRef,
    authorization_acknowledged: Boolean(ackEl?.checked),
    starts_at: time("engStartsAt"),
    ends_at: time("engEndsAt"),
    scope_hosts: scopeHosts,
    excluded_hosts: splitHosts(read("engExcludedHosts")),
    allowed_ports: [...new Set(ports.length ? ports : [80, 443])],
    max_rps: Number(read("engMaxRps")) || 5,
    platform: read("engPlatform") || "HackerOne",
    program_url: read("engProgramUrl"),
    allowed_techniques: splitHosts(read("engAllowedTechniques")),
    prohibited_techniques: splitHosts(read("engProhibitedTechniques")),
    out_of_scope_findings: splitHosts(read("engOutOfScopeFindings")),
    safe_harbor_acknowledged: Boolean(el("engSafeHarborAck")?.checked),
    notes: read("engNotes"),
    report: {
      organization: read("engOrganization"),
      program: read("engProgram"),
      assessor: read("engAssessor")
    }
  };
}

async function reviewProgramPolicy() {
  const button = el("reviewProgramPolicyBtn");
  const output = el("programPolicyReview");
  if (!button || !output || button.disabled) return;
  const policyText = (el("engNotes")?.value || "").trim();
  if (policyText.length < 20) {
    output.textContent = "Tempel teks policy terlebih dahulu (minimal 20 karakter).";
    return;
  }
  button.disabled = true;
  output.textContent = "AI sedang membaca policy. Belum ada scan yang dijalankan...";
  try {
    const response = await authFetch(`${API_BASE}/ai/policy-review`, {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({policy_text: policyText}), timeoutMs: 25000,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(apiError(data, `HTTP ${response.status}`));
    if ((el("engNotes")?.value || "").trim() !== policyText) {
      output.textContent = "Policy berubah selama analisis. Klik analisis kembali untuk teks terbaru.";
      return;
    }
    const lines = [data.summary_id, "", "DRAFT — cocokkan dengan policy asli. Isi scope/teknik di formulir secara manual; AI tidak memberikan izin."];
    for (const [field, label] of Object.entries({in_scope:"In-scope", out_of_scope:"Out-of-scope", allowed_techniques:"Teknik diizinkan", prohibited_techniques:"Teknik dilarang", limits:"Batas pengujian", uncertainties:"Perlu diklarifikasi"})) {
      if (data[field]?.length) lines.push(`${label}:\n- ${data[field].join("\n- ")}`);
    }
    output.textContent = lines.join("\n\n");
  } catch (error) {
    output.textContent = `Analisis gagal: ${error.message}. Tidak ada aturan yang diterapkan otomatis.`;
  } finally { button.disabled = false; }
}

const reportProfileFields = {organization: "reportOrganization", program: "reportProgram",
  assessor: "reportAssessor", asset_name: "reportAssetName", asset_type: "reportAssetType",
  application_version: "reportApplicationVersion", contact: "reportContact",
  classification: "reportClassification", executive_context: "reportExecutiveContext"};
let reportLogoData = "";
let reportProfileScanId = null;
let reportProfileDirty = false;
let reportProfileSaving = false;

function renderReportProfile(context, scanId, force = false) {
  if (reportProfileDirty && reportProfileScanId === scanId && !force) return;
  const profile = context?.report || {};
  reportProfileScanId = scanId;
  reportProfileDirty = false;
  Object.entries(reportProfileFields).forEach(([key, id]) => {
    if (el(id)) el(id).value = profile[key] || (key === "asset_type" ? "Web / API" : key === "classification" ? "CONFIDENTIAL" : "");
  });
  reportLogoData = profile.logo_data_url || "";
  if (el("reportLogoFile")) el("reportLogoFile").value = "";
  if (el("reportLogoStatus")) el("reportLogoStatus").textContent = reportLogoData ? "Logo tersimpan (untuk PDF/HTML)." : "Logo belum dilampirkan.";
  if (el("reportProfileStatus")) el("reportProfileStatus").textContent = context?.authorization_reference
    ? `Referensi izin: ${context.authorization_reference}. Scope pengujian tidak diubah dari formulir ini.`
    : "Referensi izin belum tercatat. Periksa otorisasi sebelum pengujian lanjutan.";
  if (el("saveReportProfileBtn")) el("saveReportProfileBtn").disabled = !scanId;
}

async function saveReportProfile() {
  if (reportProfileSaving || !reportProfileScanId) return;
  const scanId = reportProfileScanId;
  const profile = Object.fromEntries(Object.entries(reportProfileFields).map(([key, id]) => [key, (el(id)?.value || "").trim()]));
  profile.logo_data_url = reportLogoData;
  reportProfileSaving = true;
  setButtonLoading(el("saveReportProfileBtn"), true, "Menyimpan...");
  try {
    const response = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/report-profile`, {
      method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify(profile)});
    const result = await response.json();
    if (!response.ok) throw new Error(apiError(result, `HTTP ${response.status}`));
    workspaceCache.delete(scanId);
    if (scanId !== reportProfileScanId) return;
    renderReportProfile(result, scanId, true);
    if (currentWorkspaceData) currentWorkspaceData.report_context = result;
    showToast("Identitas laporan disimpan. Buat export baru untuk menggunakan perubahan.", "success");
  } catch (error) { showToast(`Gagal menyimpan: ${error.message}`, "danger"); }
  finally { reportProfileSaving = false; setButtonLoading(el("saveReportProfileBtn"), false); }
}

document.addEventListener("DOMContentLoaded", () => {
  el("reviewProgramPolicyBtn")?.addEventListener("click", reviewProgramPolicy);
  el("saveReportProfileBtn")?.addEventListener("click", saveReportProfile);
  el("reportProfilePanel")?.addEventListener("input", () => { reportProfileDirty = true; });
  el("clearReportLogoBtn")?.addEventListener("click", () => {
    reportLogoData = ""; reportProfileDirty = true;
    if (el("reportLogoFile")) el("reportLogoFile").value = "";
    if (el("reportLogoStatus")) el("reportLogoStatus").textContent = "Logo dihapus dari draft; klik Simpan.";
  });
  el("reportLogoFile")?.addEventListener("change", async event => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (!["image/png", "image/jpeg"].includes(file.type) || file.size > 256 * 1024) {
      event.target.value = "";
      showToast("Gunakan PNG/JPEG maksimal 256 KiB.", "warning"); return;
    }
    const scanId = reportProfileScanId;
    const data = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result); reader.onerror = reject; reader.readAsDataURL(file);
    }).catch(() => null);
    if (scanId !== reportProfileScanId || !data) return;
    reportLogoData = data; reportProfileDirty = true;
    el("reportLogoStatus").textContent = "Logo siap disimpan. Gambar divalidasi ulang oleh server.";
  });
});
