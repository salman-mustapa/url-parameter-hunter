/**
 * tree.js — Hierarchical Asset Tree Explorer (jsTree + Node Graph Support)
 * Attack Surface & Parameter Intelligence Platform
 */

let lastRenderedTreeHash = "";
let isTreeFetching = false;

async function refreshAssetTree() {
  if (!state.activeScanId || isTreeFetching) return;
  if (typeof document !== "undefined" && document.hidden) return;

  isTreeFetching = true;
  const currentScanId = state.activeScanId;
  try {
    const res = await authFetch(`${API_BASE}/assets/tree?scan_id=${encodeURIComponent(currentScanId)}`);
    if (!res.ok || state.activeScanId !== currentScanId) return;
    const data = await res.json();
    const searchVal = el("treeSearchInput")?.value || "";
    const dataHash = JSON.stringify(data) + "_" + (state.currentTreeSevFilter || "ALL") + "_" + searchVal;
    if (dataHash === lastRenderedTreeHash && state.assetsTreeData) {
      return; // Skip DOM update if data is unchanged
    }
    lastRenderedTreeHash = dataHash;
    state.assetsTreeData = data;
    renderAssetTree(data);
  } catch (err) {
    console.debug("Fetch asset tree skip:", err);
  } finally {
    isTreeFetching = false;
  }
}

function filterTreeNodes(nodes, searchKeyword, sevFilter) {
  if (!Array.isArray(nodes)) return [];
  const result = [];

  for (const node of nodes) {
    if (!node) continue;
    const hostStr = (node.hostname || node.fqdn || node.fingerprint || "").toLowerCase();
    const ipStr = String(node.ip || "");
    const matchesSearch = !searchKeyword || hostStr.includes(searchKeyword) || ipStr.includes(searchKeyword);

    const childrenFiltered = (node.children && Array.isArray(node.children) && node.children.length)
      ? filterTreeNodes(node.children, searchKeyword, sevFilter)
      : [];

    let matchesSev = true;
    if (sevFilter && sevFilter !== "ALL") {
      if (sevFilter === "ACTIVE") {
        matchesSev = (node.metadata && (node.metadata.active || node.metadata.root_domain)) || !!node.ip || (node.status === "ACTIVE");
      } else {
        const nodeSev = (node.findings_summary && node.findings_summary[sevFilter]) || 0;
        matchesSev = nodeSev > 0;
      }
    }

    if ((matchesSearch && matchesSev) || childrenFiltered.length > 0) {
      result.push({
        ...node,
        children: childrenFiltered,
      });
    }
  }

  return result;
}

function renderAssetTree(nodes) {
  const container = el("assetTreeContainer");
  if (!container) return;

  if (!nodes || !nodes.length) {
    container.innerHTML = `<div class="tree-empty-msg"><p>Aset akan muncul secara hierarkis saat scanning berjalan.</p></div>`;
    return;
  }

  const searchKeyword = (el("treeSearchInput")?.value || "").trim().toLowerCase();
  const filteredNodes = filterTreeNodes(nodes, searchKeyword, state.currentTreeSevFilter);

  if (!filteredNodes.length) {
    container.innerHTML = `<div class="tree-empty-msg"><p>Tidak ada aset yang cocok dengan filter "${esc(state.currentTreeSevFilter)}" atau pencarian "${esc(searchKeyword)}".</p></div>`;
    return;
  }

  renderWithNativeTree(container, filteredNodes);
}

function convertToJsTreeFormat(node) {
  const isDomain = node.type === "domain" || node.asset_type === "domain";
  const isSubdomain = node.type === "subdomain" || node.asset_type === "subdomain";
  
  let icon = "🌐";
  if (isDomain) icon = "🎯";
  else if (isSubdomain) icon = "🌱";
  else if (node.ip) icon = "💻";

  const displayName = node.hostname || node.fqdn || node.ip || "Target Node";
  let badgeHtml = "";
  if (node.ip) badgeHtml += ` [IP: ${esc(node.ip)}]`;
  if (node.ports_count) badgeHtml += ` [📡 ${node.ports_count}]`;
  if (node.urls_count) badgeHtml += ` [🔗 ${node.urls_count}]`;
  if (node.findings_summary && (node.findings_summary.CRITICAL || node.findings_summary.HIGH)) {
    badgeHtml += ` [🔴 Vulns]`;
  }

  const children = (node.children || []).map(convertToJsTreeFormat);

  return {
    id: node.id,
    text: `${icon} <strong>${esc(displayName)}</strong> <span style="font-size:10px; color:#64748B;">${badgeHtml}</span>`,
    state: {
      opened: !state.collapsedNodeIds.has(node.id),
      selected: state.selectedAssetId === node.id
    },
    children: children,
    rawNode: node
  };
}

function renderWithJsTree(container, nodes) {
  const treeDiv = document.createElement("div");
  treeDiv.id = "jsTreeInstance";
  container.appendChild(treeDiv);

  const jsTreeData = nodes.map(convertToJsTreeFormat);

  try {
    const $ = window.jQuery;
    $(treeDiv).jstree("destroy");
    $(treeDiv).jstree({
      core: {
        data: jsTreeData,
        themes: {
          name: "default",
          dots: true,
          icons: false
        }
      }
    }).on("select_node.jstree", function (e, data) {
      const original = data.node.original.rawNode;
      if (original) {
        state.selectedAssetId = original.id;
        openAssetInspectorDrawer(original);
      }
    });
  } catch (e) {
    console.warn("jsTree init failed, fallback to native tree:", e);
    container.innerHTML = "";
    renderWithNativeTree(container, nodes);
  }
}

function renderWithNativeTree(container, nodes) {
  const ul = document.createElement("ul");
  ul.className = "tree-root";
  nodes.forEach((node) => {
    ul.appendChild(buildTreeNode(node));
  });
  container.replaceChildren(ul);
}

function buildTreeNode(node) {
  const li = document.createElement("li");
  li.className = "tree-item";

  const hasChildren = node.children && node.children.length > 0;
  const isCollapsed = state.collapsedNodeIds.has(node.id);

  const row = document.createElement("div");
  row.className = `tree-node-row ${state.selectedAssetId === node.id ? 'selected' : ''}`;
  row.dataset.id = node.id;

  let icon = "🌐";
  if (node.type === "domain" || node.asset_type === "domain") icon = "🎯";
  else if (node.type === "subdomain" || node.asset_type === "subdomain") icon = "🌱";
  else if (node.type === "ip" || node.asset_type === "ip") icon = "💻";

  // Toggle button for subtrees
  let toggleHtml = "";
  if (hasChildren) {
    toggleHtml = `<button class="tree-toggle-btn" data-toggle-id="${node.id}" title="${isCollapsed ? 'Buka Subtree' : 'Tutup Subtree'}">${isCollapsed ? '▶' : '▼'}</button>`;
  } else {
    toggleHtml = `<span class="tree-toggle-spacer"></span>`;
  }

  // Active status & IP badge
  let metaBadges = "";
  if (node.ip) {
    metaBadges += `<span class="tree-node-badge badge-ip">IP: ${esc(node.ip)}</span>`;
  }
  if ((node.metadata && (node.metadata.active || node.metadata.root_domain)) || node.status === "ACTIVE") {
    metaBadges += `<span class="tree-node-badge badge-active">Active</span>`;
  }

  // Ports count badge
  if (node.ports_count) {
    metaBadges += `<span class="tree-node-badge badge-ports">📡 ${node.ports_count}</span>`;
  }

  // URLs count badge
  if (node.urls_count) {
    metaBadges += `<span class="tree-node-badge badge-urls">🔗 ${node.urls_count}</span>`;
  }

  // Tech count badge
  if (node.techs_count) {
    metaBadges += `<span class="tree-node-badge badge-techs">⚙️ ${node.techs_count}</span>`;
  }

  // Findings badge if any
  if (node.findings_summary) {
    if (node.findings_summary.CRITICAL) metaBadges += `<span class="tree-node-badge badge-crit">🔴 ${node.findings_summary.CRITICAL}</span>`;
    if (node.findings_summary.HIGH) metaBadges += `<span class="tree-node-badge badge-high">🟠 ${node.findings_summary.HIGH}</span>`;
    if (node.findings_summary.MEDIUM) metaBadges += `<span class="tree-node-badge badge-med">🟡 ${node.findings_summary.MEDIUM}</span>`;
  }

  const displayName = node.hostname || node.fqdn || node.fingerprint || node.ip || "Target Node";

  row.innerHTML = `
    ${toggleHtml}
    <span class="tree-node-icon">${icon}</span>
    <span class="tree-node-name">${esc(displayName)}</span>
    <div class="tree-node-meta">
      ${metaBadges}
    </div>
  `;

  // Toggle subtree click
  const toggleBtn = row.querySelector(".tree-toggle-btn");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      if (state.collapsedNodeIds.has(node.id)) {
        state.collapsedNodeIds.delete(node.id);
      } else {
        state.collapsedNodeIds.add(node.id);
      }
      renderAssetTree(state.assetsTreeData);
    });
  }

  // Row click to inspect asset
  row.addEventListener("click", () => {
    state.selectedAssetId = node.id;
    document.querySelectorAll(".tree-node-row").forEach(r => r.classList.remove("selected"));
    row.classList.add("selected");
    openAssetInspectorDrawer(node);
  });

  li.appendChild(row);

  if (hasChildren && !isCollapsed) {
    const subUl = document.createElement("ul");
    node.children.forEach((child) => {
      subUl.appendChild(buildTreeNode(child));
    });
    li.appendChild(subUl);
  }

  return li;
}

async function openAssetInspectorDrawer(node) {
  if (!node) return;
  const drawer = el("assetDetailDrawer");
  if (!drawer) return;

  drawer.classList.remove("hidden");

  const titleEl = el("drawerAssetTitle");
  const hostName = node.hostname || node.fqdn || node.ip || "Asset";
  if (titleEl) titleEl.textContent = hostName;

  const typeEl = el("drawerAssetType");
  if (typeEl) typeEl.textContent = (node.asset_type || node.type || (node.ip ? "IP" : "SUBDOMAIN")).toUpperCase();

  const ipEl = el("drawerAssetIP");
  if (ipEl) ipEl.textContent = node.ip || (node.asset_type === "ip" ? node.hostname : "-");

  const portsBox = el("drawerPortsList");
  const urlsBox = el("drawerUrlsList");
  if (portsBox) portsBox.innerHTML = `<span class="empty-msg">Memuat port...</span>`;
  if (urlsBox) urlsBox.innerHTML = `<span class="empty-msg">Memuat URL...</span>`;

  // Deep dive link
  const deepLink = el("drawerDeepDiveBtn");
  if (deepLink) {
    deepLink.onclick = () => {
      if (typeof openAssetDetail === "function") openAssetDetail(node.id || node.hostname || node.ip);
    };
  }

  // Load live asset metadata using ID, IP, or Hostname
  const targetKey = node.id || node.ip || node.hostname || node.fqdn;
  try {
    const res = await authFetch(`${API_BASE}/assets/${encodeURIComponent(targetKey)}`);
    if (res.ok) {
      const assetData = await res.json();
      renderDrawerAssetData(assetData || {});
    } else {
      renderDrawerAssetData({});
    }
  } catch (err) {
    console.debug("Drawer asset detail fetch failed:", err);
    renderDrawerAssetData({});
  }
}

function renderDrawerAssetData(a) {
  const portsBox = el("drawerPortsList");
  if (portsBox) {
    if (!a.ports || !a.ports.length) {
      portsBox.innerHTML = `<span class="empty-msg">Tidak ada port terbuka terdeteksi</span>`;
    } else {
      portsBox.innerHTML = `<table class="admin-table">
        <thead><tr><th>Port</th><th>Proto</th><th>Service</th></tr></thead>
        <tbody>
          ${a.ports.map(p => `<tr><td><strong>${p.port_number || p.port}</strong></td><td>${esc(p.protocol || 'tcp')}</td><td>${esc(p.service_name || '-')}</td></tr>`).join('')}
        </tbody>
      </table>`;
    }
  }

  const urlsBox = el("drawerUrlsList");
  if (urlsBox) {
    if (!a.urls || !a.urls.length) {
      urlsBox.innerHTML = `<span class="empty-msg">Tidak ada URL terdeteksi</span>`;
    } else {
      urlsBox.innerHTML = a.urls.slice(0, 30).map(u => `
        <div class="url-item mono">
          <span class="badge status-${u.status_code || 200}">${u.status_code || 200}</span>
          <a href="${esc(u.url)}" target="_blank" rel="noopener">${esc(u.url)}</a>
        </div>
      `).join('');
    }
  }
}

function expandAllNodes() {
  state.collapsedNodeIds.clear();
  renderAssetTree(state.assetsTreeData);
}

function collapseAllNodes() {
  function collectIds(nodes) {
    if (!Array.isArray(nodes)) return;
    nodes.forEach(n => {
      if (n.children && n.children.length) {
        state.collapsedNodeIds.add(n.id);
        collectIds(n.children);
      }
    });
  }
  collectIds(state.assetsTreeData);
  renderAssetTree(state.assetsTreeData);
}

window.expandAllNodes = expandAllNodes;
window.collapseAllNodes = collapseAllNodes;

function setupTreeControls() {
  const searchInput = el("treeSearchInput");
  if (searchInput) {
    searchInput.addEventListener("input", () => {
      renderAssetTree(state.assetsTreeData);
    });
  }

  const collapseAllBtn = el("collapseAllBtn");
  if (collapseAllBtn) {
    collapseAllBtn.addEventListener("click", collapseAllNodes);
  }

  const expandAllBtn = el("expandAllBtn");
  if (expandAllBtn) {
    expandAllBtn.addEventListener("click", expandAllNodes);
  }

  const refreshTreeBtn = el("refreshTreeBtn");
  if (refreshTreeBtn) {
    refreshTreeBtn.addEventListener("click", () => {
      lastRenderedTreeHash = "";
      refreshAssetTree();
    });
  }

  const closeDrawerBtn = el("closeDrawerBtn");
  const drawerEl = el("assetDetailDrawer");
  if (closeDrawerBtn) {
    closeDrawerBtn.addEventListener("click", () => {
      if (drawerEl) drawerEl.classList.add("hidden");
    });
  }
  if (drawerEl) {
    drawerEl.addEventListener("click", (e) => {
      if (e.target === drawerEl) {
        drawerEl.classList.add("hidden");
      }
    });
  }
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (drawerEl && !drawerEl.classList.contains("hidden")) {
        drawerEl.classList.add("hidden");
      }
    }
  });
}


// ==========================================================================
// Interactive Attack Surface Graph Canvas Visualizer (§35, §66)
// ==========================================================================

const graphState = {
  currentMode: "tree",
  layout: "radial", // "radial", "tree", "force", "grid"
  zoom: 1.0,
  panX: 0,
  panY: 0,
  isPanning: false,
  draggedNode: null,
  dragOffsetX: 0,
  dragOffsetY: 0,
  dragStartX: 0,
  dragStartY: 0,
  hoveredNode: null,
  nodes: [],
  edges: [],
  customPositions: new Map(),
};

window.zoomAttackGraph = function(factor) {
  graphState.zoom = Math.max(0.2, Math.min(3.5, graphState.zoom * factor));
  drawAttackGraph();
};

window.resetAttackGraph = function() {
  graphState.zoom = 1.0;
  const container = el("assetGraphContainer");
  if (container) {
    const rect = container.getBoundingClientRect();
    graphState.panX = rect.width / 2;
    graphState.panY = rect.height / 2;
  } else {
    graphState.panX = 0;
    graphState.panY = 0;
  }
  drawAttackGraph();
};

window.changeGraphLayout = function(layoutName) {
  graphState.layout = layoutName || "radial";
  graphState.customPositions.clear(); // Reset manual overrides on explicit layout change

  // Update button active states
  const btnMap = {
    radial: "layoutRadialBtn",
    tree: "layoutTreeBtn",
    force: "layoutForceBtn",
    grid: "layoutGridBtn",
  };

  Object.entries(btnMap).forEach(([k, btnId]) => {
    const btn = el(btnId);
    if (btn) {
      if (k === graphState.layout) {
        btn.className = "btn btn-xs btn-primary active";
      } else {
        btn.className = "btn btn-xs btn-secondary";
      }
    }
  });

  initAttackGraph();
};

function buildGraphModelFromTree(treeNodes, layout = "radial") {
  const nodes = [];
  const edges = [];
  const seenIds = new Set();
  const flatNodes = [];

  function collectFlat(node, parentId = null, depth = 0) {
    if (!node || seenIds.has(node.id)) return;
    seenIds.add(node.id);

    const isRoot = depth === 0;
    const label = node.hostname || node.fqdn || node.ip || "Target";
    const type = isRoot ? "DOMAIN" : (node.ip && !node.hostname ? "IP" : "SUBDOMAIN");

    const item = {
      id: node.id,
      parentId: parentId,
      depth: depth,
      label: label,
      type: type,
      isRoot: isRoot,
      radius: isRoot ? 26 : (type === "SUBDOMAIN" ? 19 : 15),
      portsCount: node.ports_count || 0,
      urlsCount: node.urls_count || 0,
      findingsCount: (node.findings_summary?.CRITICAL || 0) + (node.findings_summary?.HIGH || 0),
      rawNode: node
    };
    flatNodes.push(item);

    if (parentId) {
      edges.push({ source: parentId, target: node.id });
    }

    (node.children || []).forEach(child => collectFlat(child, node.id, depth + 1));
  }

  (treeNodes || []).forEach(root => collectFlat(root, null, 0));

  // Position calculation based on layout
  if (layout === "radial") {
    // Radial Orbit Layout
    flatNodes.forEach((node, idx) => {
      if (graphState.customPositions.has(node.id)) {
        const pos = graphState.customPositions.get(node.id);
        node.x = pos.x;
        node.y = pos.y;
      } else if (node.isRoot) {
        node.x = 0;
        node.y = 0;
      } else {
        const angle = (idx / Math.max(1, flatNodes.length - 1)) * Math.PI * 2;
        const radius = 130 + (node.depth * 95);
        node.x = Math.cos(angle) * radius;
        node.y = Math.sin(angle) * radius;
      }
      nodes.push(node);
    });
  } else if (layout === "tree") {
    // Hierarchical Top-Down Layout
    const byDepth = {};
    flatNodes.forEach(n => {
      byDepth[n.depth] = byDepth[n.depth] || [];
      byDepth[n.depth].push(n);
    });

    Object.keys(byDepth).forEach(d => {
      const row = byDepth[d];
      const spacingX = 140;
      const startX = -((row.length - 1) * spacingX) / 2;
      const y = (parseInt(d) * 110) - 120;

      row.forEach((node, colIdx) => {
        if (graphState.customPositions.has(node.id)) {
          const pos = graphState.customPositions.get(node.id);
          node.x = pos.x;
          node.y = pos.y;
        } else {
          node.x = startX + colIdx * spacingX;
          node.y = y;
        }
        nodes.push(node);
      });
    });
  } else if (layout === "grid") {
    // Compact Matrix Layout
    const cols = Math.ceil(Math.sqrt(flatNodes.length || 1));
    const spacing = 130;
    const startOffset = -((cols - 1) * spacing) / 2;

    flatNodes.forEach((node, idx) => {
      if (graphState.customPositions.has(node.id)) {
        const pos = graphState.customPositions.get(node.id);
        node.x = pos.x;
        node.y = pos.y;
      } else {
        const r = Math.floor(idx / cols);
        const c = idx % cols;
        node.x = startOffset + c * spacing;
        node.y = startOffset + r * spacing;
      }
      nodes.push(node);
    });
  } else {
    // Force / Organic Layout
    flatNodes.forEach((node, idx) => {
      if (graphState.customPositions.has(node.id)) {
        const pos = graphState.customPositions.get(node.id);
        node.x = pos.x;
        node.y = pos.y;
      } else if (node.isRoot) {
        node.x = 0;
        node.y = 0;
      } else {
        const phi = idx * 137.5 * (Math.PI / 180);
        const r = 40 * Math.sqrt(idx) + 80;
        node.x = Math.cos(phi) * r;
        node.y = Math.sin(phi) * r;
      }
      nodes.push(node);
    });
  }

  return { nodes, edges };
}

async function initAttackGraph() {
  const canvas = el("attackGraphCanvas");
  if (!canvas) return;

  const container = el("assetGraphContainer");
  if (!container) return;

  const rect = container.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;

  if (rect.width > 0 && rect.height > 0) {
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
  }

  // If assets tree data is not loaded yet, fetch it immediately
  if (!state.assetsTreeData && state.activeScanId) {
    try {
      const res = await authFetch(`${API_BASE}/assets/tree?scan_id=${encodeURIComponent(state.activeScanId)}`);
      if (res.ok) {
        state.assetsTreeData = await res.json();
      }
    } catch (_) {}
  }

  const { nodes, edges } = buildGraphModelFromTree(state.assetsTreeData || [], graphState.layout);
  graphState.nodes = nodes;
  graphState.edges = edges;

  // Center the view if not set
  if (graphState.panX === 0 && graphState.panY === 0 && rect.width > 0) {
    graphState.panX = rect.width / 2;
    graphState.panY = rect.height / 2;
  }

  setupGraphCanvasEvents(canvas);
  drawAttackGraph();
}

function setupGraphCanvasEvents(canvas) {
  if (canvas._hasGraphEvents) return;
  canvas._hasGraphEvents = true;

  let mouseDownPos = { x: 0, y: 0 };
  let clickedTargetNode = null;

  canvas.addEventListener("mousedown", (e) => {
    mouseDownPos = { x: e.clientX, y: e.clientY };
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - graphState.panX) / graphState.zoom;
    const mouseY = (e.clientY - rect.top - graphState.panY) / graphState.zoom;

    // Check if clicked directly on a node for drag-repositioning or inspection
    let targetNode = null;
    for (const node of graphState.nodes) {
      const dx = node.x - mouseX;
      const dy = node.y - mouseY;
      if (Math.sqrt(dx * dx + dy * dy) <= node.radius + 8) {
        targetNode = node;
        break;
      }
    }

    clickedTargetNode = targetNode;
    if (targetNode) {
      graphState.draggedNode = targetNode;
      graphState.dragOffsetX = mouseX - targetNode.x;
      graphState.dragOffsetY = mouseY - targetNode.y;
      canvas.style.cursor = "grabbing";
    } else {
      graphState.isPanning = true;
      graphState.dragStartX = e.clientX - graphState.panX;
      graphState.dragStartY = e.clientY - graphState.panY;
      canvas.style.cursor = "grabbing";
    }
  });

  window.addEventListener("mousemove", (e) => {
    // 1. Dragging individual node
    if (graphState.draggedNode) {
      const rect = canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - graphState.panX) / graphState.zoom;
      const mouseY = (e.clientY - rect.top - graphState.panY) / graphState.zoom;

      graphState.draggedNode.x = mouseX - (graphState.dragOffsetX || 0);
      graphState.draggedNode.y = mouseY - (graphState.dragOffsetY || 0);
      graphState.customPositions.set(graphState.draggedNode.id, {
        x: graphState.draggedNode.x,
        y: graphState.draggedNode.y,
      });

      drawAttackGraph();
      return;
    }

    // 2. Panning canvas
    if (graphState.isPanning) {
      graphState.panX = e.clientX - graphState.dragStartX;
      graphState.panY = e.clientY - graphState.dragStartY;
      drawAttackGraph();
      return;
    }

    // 3. Hover detection
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - graphState.panX) / graphState.zoom;
    const mouseY = (e.clientY - rect.top - graphState.panY) / graphState.zoom;

    let found = null;
    for (const node of graphState.nodes) {
      const dx = node.x - mouseX;
      const dy = node.y - mouseY;
      if (Math.sqrt(dx * dx + dy * dy) <= node.radius + 8) {
        found = node;
        break;
      }
    }

    if (found !== graphState.hoveredNode) {
      graphState.hoveredNode = found;
      canvas.style.cursor = found ? "pointer" : "grab";
      drawAttackGraph();
    }
  });

  window.addEventListener("mouseup", (e) => {
    const moveDist = Math.hypot(e.clientX - mouseDownPos.x, e.clientY - mouseDownPos.y);
    if (moveDist < 6 && clickedTargetNode) {
      state.selectedAssetId = clickedTargetNode.id;
      if (typeof openAssetInspectorDrawer === "function") {
        openAssetInspectorDrawer(clickedTargetNode.raw || clickedTargetNode);
      }
    }

    clickedTargetNode = null;
    graphState.draggedNode = null;
    graphState.isPanning = false;
    canvas.style.cursor = graphState.hoveredNode ? "pointer" : "grab";
  });

  canvas.addEventListener("wheel", (e) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.12 : 0.88;
    zoomAttackGraph(zoomFactor);
  }, { passive: false });

  canvas.addEventListener("dblclick", () => {
    if (graphState.hoveredNode && typeof openAssetInspectorDrawer === "function") {
      openAssetInspectorDrawer(graphState.hoveredNode.raw || graphState.hoveredNode);
    }
  });
}

function drawAttackGraph() {
  const canvas = el("attackGraphCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();

  ctx.save();
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.scale(dpr, dpr);

  // Background Grid Canvas
  ctx.fillStyle = "#FAF7F2";
  ctx.fillRect(0, 0, rect.width, rect.height);

  // Draw subtle grid dots
  ctx.fillStyle = "rgba(15, 23, 42, 0.08)";
  const dotSpacing = 24 * graphState.zoom;
  const offsetX = (graphState.panX % dotSpacing);
  const offsetY = (graphState.panY % dotSpacing);
  for (let x = offsetX; x < rect.width; x += dotSpacing) {
    for (let y = offsetY; y < rect.height; y += dotSpacing) {
      ctx.fillRect(x, y, 1.5, 1.5);
    }
  }

  ctx.translate(graphState.panX, graphState.panY);
  ctx.scale(graphState.zoom, graphState.zoom);

  const nodeMap = new Map(graphState.nodes.map(n => [n.id, n]));

  // Empty state message on canvas if no nodes
  if (!graphState.nodes || graphState.nodes.length === 0) {
    ctx.font = "bold 13px 'Plus Jakarta Sans', sans-serif";
    ctx.fillStyle = "#64748B";
    ctx.textAlign = "center";
    ctx.fillText("Belum ada target atau aset yang ditemukan untuk graf serangan.", 0, -10);
    ctx.font = "11px 'Plus Jakarta Sans', sans-serif";
    ctx.fillText("Jalankan pemindaian untuk melihat struktur topologi aset real-time.", 0, 14);
    ctx.restore();
    return;
  }

  // 1. Draw Edges
  for (const edge of graphState.edges) {
    const s = nodeMap.get(edge.source);
    const t = nodeMap.get(edge.target);
    if (!s || !t) continue;

    const isConnectedToHovered = graphState.hoveredNode &&
      (graphState.hoveredNode.id === s.id || graphState.hoveredNode.id === t.id);

    ctx.beginPath();
    ctx.strokeStyle = isConnectedToHovered ? "#2563EB" : "#94A3B8";
    ctx.lineWidth = isConnectedToHovered ? 2.5 : 1.5;
    ctx.setLineDash(isConnectedToHovered ? [] : [4, 4]);
    ctx.moveTo(s.x, s.y);
    ctx.lineTo(t.x, t.y);
    ctx.stroke();
    ctx.setLineDash([]);
  }

  // 2. Draw Nodes
  for (const node of graphState.nodes) {
    const isHovered = graphState.hoveredNode?.id === node.id;
    const isRoot = node.type === "DOMAIN";

    let fillColor = "#FFFFFF";
    let borderColor = "#0F172A";
    let icon = "🌐";

    if (isRoot) {
      fillColor = "#FEF08A";
      icon = "🎯";
    } else if (node.type === "SUBDOMAIN") {
      fillColor = "#D1FAE5";
      icon = "🌱";
    } else if (node.type === "IP") {
      fillColor = "#E0E7FF";
      icon = "💻";
    }

    if (node.findingsCount > 0) {
      fillColor = "#FEE2E2";
      borderColor = "#DC2626";
    }

    // Outer Shadow & Hover Ring
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius + (isHovered ? 5 : 1.5), 0, Math.PI * 2);
    ctx.fillStyle = isHovered ? "rgba(37, 99, 235, 0.3)" : "rgba(15, 23, 42, 0.12)";
    ctx.fill();

    // Node Circle Body
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
    ctx.fillStyle = fillColor;
    ctx.fill();
    ctx.strokeStyle = borderColor;
    ctx.lineWidth = isHovered ? 2.8 : 1.8;
    ctx.stroke();

    // Node Icon
    ctx.font = `${isRoot ? 14 : 11}px sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillStyle = "#0F172A";
    ctx.fillText(icon, node.x, node.y);

    // Node Label Pill
    ctx.font = `${isHovered ? 'bold ' : ''}11px 'Plus Jakarta Sans', sans-serif`;
    ctx.fillStyle = isHovered ? "#1D4ED8" : "#0F172A";
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    const labelText = node.label.length > 24 ? node.label.slice(0, 22) + "..." : node.label;
    ctx.fillText(labelText, node.x, node.y + node.radius + 5);

    // Ports & Findings Mini Badge
    if (node.portsCount > 0 || node.findingsCount > 0) {
      let badgeText = "";
      if (node.portsCount > 0) badgeText += `📡 ${node.portsCount}`;
      if (node.findingsCount > 0) badgeText += ` 🔴 ${node.findingsCount}`;
      
      ctx.font = "9px 'Plus Jakarta Sans', sans-serif";
      ctx.fillStyle = "#64748B";
      ctx.fillText(badgeText.trim(), node.x, node.y + node.radius + 18);
    }
  }

  ctx.restore();
}

// Export global helper functions
window.renderAttackGraphCanvas = initAttackGraph;
window.initAttackGraph = initAttackGraph;
window.drawAttackGraph = drawAttackGraph;
window.buildGraphModelFromTree = buildGraphModelFromTree;
