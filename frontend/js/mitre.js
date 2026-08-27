/**
 * MITRE ATT&CK Matrix Navigator & Visual Proof Screenshot Gallery (V4 §10, §26).
 */

(function () {
  'use strict';

  function el(id) { return document.getElementById(id); }
  function esc(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // =========================================================================
  // 1. MITRE ATT&CK Matrix Explorer (§26)
  // =========================================================================
  async function loadMitreMatrix(scanId) {
    const container = el('mitreMatrixGrid');
    if (!container) return;

    if (!scanId) {
      container.innerHTML = '<div class="empty-state">Pilih pemindaian aktif atau riwayat untuk memuat Matriks MITRE ATT&CK.</div>';
      return;
    }

    container.innerHTML = '<div class="loading-spinner">Memetakan taktik & teknik MITRE ATT&CK...</div>';

    try {
      const res = await fetchWithTimeout(`/api/scans/${encodeURIComponent(scanId)}/mitre-matrix`);
      if (!res.ok) throw new Error('Gagal memuat matriks MITRE ATT&CK');
      const data = await res.json();

      const tactics = data.tactics || [];
      if (!tactics.length || data.total_tactics_active === 0) {
        container.innerHTML = `
          <div class="empty-state" style="padding: 30px; text-align: center;">
            <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
            <h4>Belum Ada Teknik ATT&CK Terobservasi</h4>
            <p style="color: var(--text-muted); font-size: 13px;">Semua endpoint yang diuji belum memperlihatkan perilaku deviasi TTP.</p>
          </div>
        `;
        return;
      }

      container.innerHTML = tactics.map(tac => {
        const isActive = tac.total_findings > 0;
        const techHtml = (tac.techniques || []).map(tech => {
          const maxSev = (tech.severities || [])[0] || 'MEDIUM';
          const sevClass = maxSev.toLowerCase();
          return `
            <div class="mitre-tech-card ${sevClass}" style="background: rgba(15, 23, 42, 0.8); border: 1px solid var(--border-color); border-left: 3px solid ${sevClass === 'critical' ? '#ef4444' : (sevClass === 'high' ? '#f97316' : '#38bdf8')}; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <span class="mono" style="font-weight:700; color:#38bdf8; font-size:11px;">${esc(tech.technique_id)}</span>
                <span class="badge badge-${sevClass}" style="font-size:9.5px; padding:2px 6px;">${tech.findings_count} FINDING</span>
              </div>
              <div style="font-weight:600; font-size:12px; color:#f8fafc; margin-bottom:4px;">${esc(tech.technique_name)}</div>
              <p style="font-size:11px; color:#94a3b8; margin:0 0 6px 0; line-height:1.3;">${esc(tech.rationale || '')}</p>
              <div style="display:flex; justify-content:space-between; align-items:center;">
                <a href="${esc(tech.mitre_url)}" target="_blank" style="font-size:10.5px; color:#34d399; text-decoration:none;">Lihat di MITRE ATT&CK ↗</a>
                ${tech.finding_ids && tech.finding_ids[0] ? `<button class="btn btn-ghost btn-xs" onclick="window.viewFindingDetailById('${esc(tech.finding_ids[0])}')" style="font-size:10px; padding:1px 6px;">Detail PoC ↗</button>` : ''}
              </div>
            </div>
          `;
        }).join('') || '<div style="font-size:11.5px; color:var(--text-muted); font-style:italic; padding:10px 0;">Tidak ada teknik aktif pada taktik ini.</div>';

        return `
          <div class="mitre-column" style="background:#090f1f; border:1px solid ${isActive ? '#334155' : '#1e293b'}; border-radius:8px; padding:12px; min-width:260px; flex:1;">
            <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:8px; margin-bottom:10px;">
              <strong style="font-size:13px; color:${isActive ? '#f8fafc' : '#64748b'};">${esc(tac.tactic)}</strong>
              <span class="pill ${isActive ? 'pill-running' : 'pill-muted'}" style="font-size:10px; padding:2px 8px;">${tac.total_findings} Terdeteksi</span>
            </div>
            <div class="mitre-column-body">
              ${techHtml}
            </div>
          </div>
        `;
      }).join('');
    } catch (err) {
      container.innerHTML = `<div class="error-msg">Gagal memuat data MITRE ATT&CK: ${esc(err.message)}</div>`;
    }
  }

  // =========================================================================
  // 2. Visual Proof Screenshot Gallery (§10)
  // =========================================================================
  async function loadScreenshotGallery(scanId) {
    const container = el('screenshotGalleryGrid');
    if (!container) return;

    if (!scanId) {
      container.innerHTML = '<div class="empty-state">Pilih scan aktif untuk memuat galeri tangkapan layar.</div>';
      return;
    }

    container.innerHTML = '<div class="loading-spinner">Memuat galeri visual proof...</div>';

    try {
      const res = await fetchWithTimeout(`/api/scans/${encodeURIComponent(scanId)}/screenshots`);
      if (!res.ok) throw new Error('Gagal memuat galeri screenshot');
      const list = await res.json();

      if (!list.length) {
        container.innerHTML = `
          <div class="empty-state" style="grid-column: 1 / -1; padding: 40px; text-align: center;">
            <div style="font-size: 36px; margin-bottom: 8px;">📸</div>
            <h4>Belum Ada Bukti Visual Ditangkap</h4>
            <p style="color: var(--text-muted); font-size: 13px;">Screenshot worker akan menangkap bukti visual secara otomatis pada setiap temuan dan host aktif.</p>
          </div>
        `;
        return;
      }

      container.innerHTML = list.map(s => `
        <div class="screenshot-card sketch-card" style="background:#090f1f; border:1px solid #1e293b; border-radius:8px; overflow:hidden; display:flex; flex-direction:column;">
          <div style="position:relative; cursor:pointer;" onclick="showScreenshotLightbox('${esc(s.image_url)}', '${esc(s.page_title || 'Visual Evidence')}', 'SHA-256: ${esc(s.content_hash || '')}')">
            <img src="${esc(s.thumb_url || s.image_url)}" alt="${esc(s.page_title || 'Screenshot')}" style="width:100%; height:160px; object-fit:cover; display:block; background:#020617;" loading="lazy" />
            <div style="position:absolute; top:8px; left:8px; background:rgba(0,0,0,0.75); padding:2px 8px; border-radius:4px; font-size:10px; font-weight:700; color:#38bdf8; backdrop-filter:blur(4px);">
              HTTP ${s.status_code || 200}
            </div>
            <div style="position:absolute; top:8px; right:8px; background:rgba(15,23,42,0.85); padding:2px 8px; border-radius:4px; font-size:10px; color:#cbd5e1;">
              ${esc(s.trigger || 'homepage').toUpperCase()}
            </div>
          </div>
          <div style="padding:12px; flex:1; display:flex; flex-direction:column; justify-content:space-between;">
            <div>
              <div style="font-weight:700; font-size:12.5px; color:#f8fafc; margin-bottom:4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="${esc(s.page_title)}">${esc(s.page_title || 'Visual Evidence')}</div>
              <div class="mono" style="font-size:10px; color:#64748b; margin-bottom:8px;">Hash: ${esc((s.content_hash || '').substring(0, 16))}...</div>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:8px;">
              <button class="btn btn-secondary btn-xs" onclick="showScreenshotLightbox('${esc(s.image_url)}', '${esc(s.page_title || 'Visual Evidence')}', 'SHA-256: ${esc(s.content_hash || '')}')">🔍 Full Lightbox</button>
              <a href="${esc(s.image_url)}" download="proof_${esc(s.id)}.png" class="btn btn-ghost btn-xs">💾 Download</a>
            </div>
          </div>
        </div>
      `).join('');
    } catch (err) {
      container.innerHTML = `<div class="error-msg">Gagal memuat galeri: ${esc(err.message)}</div>`;
    }
  }

  // Expose globally
  window.loadMitreMatrix = loadMitreMatrix;
  window.loadScreenshotGallery = loadScreenshotGallery;
})();
