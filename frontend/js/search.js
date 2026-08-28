/**
 * search.js — Global Command Palette (Ctrl+K / Cmd+K) & Universal Entity Search
 * Attack Surface & Parameter Intelligence Platform V11
 */

let searchTimer = null;

const QUICK_COMMANDS = [
  { icon: "🚀", title: "Mulai Scan Target Baru", subtitle: "Buka form konfigurasi scan dan fokuskan input target", action: () => { switchViewTab("dashboard"); el("targetInput")?.focus(); } },
  { icon: "🌳", title: "Buka Hierarchical Asset Tree", subtitle: "Lihat struktur node subdomain, IP, dan port", action: () => { switchViewTab("dashboard"); el("assetTreeContainer")?.scrollIntoView({ behavior: "smooth" }); } },
  { icon: "📡", title: "Buka Port Matrix Explorer", subtitle: "Eksplorasi seluruh port terbuka, service, dan banner", action: () => { if (typeof openPortsModal === "function") openPortsModal(); } },
  { icon: "🔗", title: "Buka Discovered URLs & Endpoints", subtitle: "Filter endpoint aktif berdasarkan kode status HTTP", action: () => { if (typeof openUrlsModal === "function") openUrlsModal(); } },
  { icon: "🧩", title: "Buka Parameter Discovery Matrix", subtitle: "Triage parameter rentan (IDOR, SSRF, SQLi, Auth)", action: () => { if (typeof openParamsModal === "function") openParamsModal(); } },
  { icon: "⚙️", title: "Buka Matriks Teknologi & Fingerprint", subtitle: "Lihat tumpukan teknologi, server, dan framework", action: () => { if (typeof openTechsModal === "function") openTechsModal(); } },
  { icon: "🛡️", title: "Buka Matriks Temuan Keamanan & Kerentanan", subtitle: "Tinjau temuan kerentanan tervalidasi dan PoC", action: () => { if (typeof openFindingsModal === "function") openFindingsModal(); } },
  { icon: "🎯", title: "Buka MITRE ATT&CK Navigator", subtitle: "Matriks pemetaan taktik dan teknik serangan siber", action: () => { if (typeof openMitreModal === "function") openMitreModal(); } },
  { icon: "📦", title: "Buka Pusat Laporan Keamanan", subtitle: "Unduh laporan PDF, HTML, JSON, Markdown, dan PoC package", action: () => { switchViewTab("reports"); } },
  { icon: "⚖️", title: "Buka Diff & Drift Analyzer", subtitle: "Bandingkan perubahan attack surface antar sesi scan", action: () => { switchViewTab("diff"); } },
  { icon: "📜", title: "Buka Histori Scan", subtitle: "Tinjau arsip seluruh scan dan riwayat penemuan aset", action: () => { switchViewTab("history"); } },
];

function renderDefaultCommandPalette() {
  const searchResults = el('globalSearchResults');
  if (!searchResults) return;

  let html = `<div class="command-group-title">⚡ Perintah Cepat & Navigasi</div>`;
  QUICK_COMMANDS.forEach((cmd, idx) => {
    html += `
      <div class="command-item" data-cmd-index="${idx}">
        <span class="command-icon">${cmd.icon}</span>
        <div class="command-info">
          <strong class="command-title">${esc(cmd.title)}</strong>
          <span class="command-sub">${esc(cmd.subtitle)}</span>
        </div>
        <span class="command-enter-badge">PILIH ↵</span>
      </div>
    `;
  });
  searchResults.innerHTML = html;

  // Add click listeners
  searchResults.querySelectorAll(".command-item").forEach((item) => {
    item.addEventListener("click", () => {
      const idx = parseInt(item.dataset.cmdIndex, 10);
      if (QUICK_COMMANDS[idx] && typeof QUICK_COMMANDS[idx].action === "function") {
        closeCommandPalette();
        QUICK_COMMANDS[idx].action();
      }
    });
  });
}

function openCommandPalette() {
  const searchOverlay = el('globalSearchOverlay');
  const searchInput = el('globalSearchInput');
  if (!searchOverlay) return;

  searchOverlay.classList.remove('hidden');
  if (searchInput) {
    searchInput.value = '';
    searchInput.focus();
  }
  renderDefaultCommandPalette();
}

function closeCommandPalette() {
  const searchOverlay = el('globalSearchOverlay');
  if (searchOverlay) searchOverlay.classList.add('hidden');
}

function setupGlobalSearch() {
  const searchOverlay = el('globalSearchOverlay');
  const searchInput = el('globalSearchInput');

  // Keyboard shortcut: Ctrl+K or Cmd+K
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) {
      e.preventDefault();
      if (!searchOverlay) return;
      if (searchOverlay.classList.contains('hidden')) {
        openCommandPalette();
      } else {
        closeCommandPalette();
      }
    }
    if (e.key === 'Escape' && searchOverlay && !searchOverlay.classList.contains('hidden')) {
      closeCommandPalette();
    }
  });

  el('closeSearchOverlay')?.addEventListener('click', closeCommandPalette);

  searchOverlay?.addEventListener('click', (e) => {
    if (e.target === searchOverlay) closeCommandPalette();
  });

  searchInput?.addEventListener('input', () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (!q) {
      renderDefaultCommandPalette();
      return;
    }
    if (q.length < 2) {
      const searchResults = el('globalSearchResults');
      if (searchResults) searchResults.innerHTML = '<div class="search-hint">Ketik minimal 2 karakter untuk memulai pencarian cerdas...</div>';
      return;
    }
    searchTimer = setTimeout(() => performGlobalSearch(q), 250);
  });
}

async function performGlobalSearch(query) {
  const searchResults = el('globalSearchResults');
  if (!searchResults) return;

  searchResults.innerHTML = '<div class="search-hint">Mencari entitas dan attack surface...</div>';
  try {
    const res = await authFetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);
    const r = await res.json();
    let html = '';
    let totalMatches = 0;

    // Filter quick commands matching query
    const matchedCmds = QUICK_COMMANDS.map((c, i) => ({ ...c, index: i })).filter(c => c.title.toLowerCase().includes(query.toLowerCase()) || c.subtitle.toLowerCase().includes(query.toLowerCase()));
    if (matchedCmds.length) {
      html += '<div class="command-group-title">⚡ Perintah Cepat</div>';
      matchedCmds.forEach((cmd) => {
        html += `
          <div class="command-item" data-cmd-index="${cmd.index}">
            <span class="command-icon">${cmd.icon}</span>
            <div class="command-info">
              <strong class="command-title">${esc(cmd.title)}</strong>
              <span class="command-sub">${esc(cmd.subtitle)}</span>
            </div>
            <span class="command-enter-badge">JALANKAN ↵</span>
          </div>
        `;
      });
      totalMatches += matchedCmds.length;
    }

    if (r.domains && r.domains.length) {
      html += '<div class="command-group-title">🌐 Domains</div>';
      r.domains.forEach(d => {
        html += `<div class="search-result-item" onclick="if (typeof openDomainDetail === 'function') openDomainDetail(${jsArg(d.name || d)}); closeCommandPalette();">
          <span class="search-result-type type-domain">DOMAIN</span>
          <span class="search-result-value font-mono"><strong>${esc(d.name || d)}</strong></span>
          <span class="search-result-meta">${esc(d.health_status || 'ACTIVE')}</span>
        </div>`;
      });
      totalMatches += r.domains.length;
    }

    if (r.assets && r.assets.length) {
      html += '<div class="command-group-title">🌳 Assets & Subdomains</div>';
      r.assets.forEach(a => {
        html += `<div class="search-result-item" onclick="if (typeof openAssetDetail === 'function') openAssetDetail(${jsArg(a.id || a.hostname)}); closeCommandPalette();">
          <span class="search-result-type type-asset">ASSET</span>
          <span class="search-result-value font-mono">${esc(a.hostname || a.ip)}</span>
          <span class="search-result-meta">${esc(a.ip || '-')}</span>
        </div>`;
      });
      totalMatches += r.assets.length;
    }

    if (r.urls && r.urls.length) {
      html += '<div class="command-group-title">🔗 Discovered Endpoints</div>';
      r.urls.forEach(u => {
        html += `<div class="search-result-item" onclick="window.open(${jsArg(u.url)}, '_blank'); closeCommandPalette();">
          <span class="search-result-type type-url">${esc(u.method || 'GET')}</span>
          <span class="search-result-value font-mono truncate">${esc(u.url)}</span>
          <span class="search-result-meta">${esc(u.status_code || 200)}</span>
        </div>`;
      });
      totalMatches += r.urls.length;
    }

    if (r.parameters && r.parameters.length) {
      html += '<div class="command-group-title">🧩 Parameters</div>';
      r.parameters.forEach(p => {
        html += `<div class="search-result-item" onclick="if (typeof openParamsModal === 'function') openParamsModal(); closeCommandPalette();">
          <span class="search-result-type type-param">PARAM</span>
          <span class="search-result-value font-mono"><strong>${esc(p.name)}</strong> (${esc(p.location || 'query')})</span>
          <span class="search-result-meta">${esc(p.type || 'string')}</span>
        </div>`;
      });
      totalMatches += r.parameters.length;
    }

    if (r.findings && r.findings.length) {
      html += '<div class="command-group-title">🛡️ Security Findings</div>';
      r.findings.forEach(f => {
        html += `<div class="search-result-item" onclick="if (typeof openFindingDetail === 'function') openFindingDetail(${jsArg(f.id)}); closeCommandPalette();">
          <span class="search-result-type type-finding ${f.severity ? f.severity.toLowerCase() : 'info'}">${esc(f.severity || 'FINDING')}</span>
          <span class="search-result-value"><strong>${esc(f.title || f.id)}</strong></span>
        </div>`;
      });
      totalMatches += r.findings.length;
    }

    if (r.ports && r.ports.length) {
      html += '<div class="command-group-title">📡 Open Ports & Services</div>';
      r.ports.forEach(pt => {
        html += `<div class="search-result-item" onclick="if (typeof openPortsModal === 'function') openPortsModal(); closeCommandPalette();">
          <span class="search-result-type type-port">PORT ${pt.port}</span>
          <span class="search-result-value font-mono">${esc(pt.service || '-')}</span>
          <span class="search-result-meta">${esc(pt.protocol || 'tcp').toUpperCase()}</span>
        </div>`;
      });
      totalMatches += r.ports.length;
    }

    if (r.technologies && r.technologies.length) {
      html += '<div class="command-group-title">⚙️ Technologies</div>';
      r.technologies.forEach(t => {
        html += `<div class="search-result-item" onclick="if (typeof openTechsModal === 'function') openTechsModal(); closeCommandPalette();">
          <span class="search-result-type type-tech">TECH</span>
          <span class="search-result-value"><strong>${esc(t.name)}</strong> ${esc(t.version || '')}</span>
          <span class="search-result-meta">${esc(t.category || '-')}</span>
        </div>`;
      });
      totalMatches += r.technologies.length;
    }

    if (!totalMatches) {
      html = '<div class="search-hint">Tidak ada entitas yang cocok dengan kata kunci "' + esc(query) + '".</div>';
    }

    searchResults.innerHTML = html;

    // Add click listeners to dynamic matched commands
    searchResults.querySelectorAll(".command-item").forEach((item) => {
      item.addEventListener("click", () => {
        const idx = parseInt(item.dataset.cmdIndex, 10);
        if (QUICK_COMMANDS[idx] && typeof QUICK_COMMANDS[idx].action === "function") {
          closeCommandPalette();
          QUICK_COMMANDS[idx].action();
        }
      });
    });

  } catch(e) {
    searchResults.innerHTML = '<div class="search-hint">Gagal mencari. Silakan coba kembali.</div>';
  }
}
