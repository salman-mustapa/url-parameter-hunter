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
}
