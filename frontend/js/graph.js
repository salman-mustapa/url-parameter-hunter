/**
 * graph.js — Interactive Force-Directed Attack Surface Graph Visualizer
 * High-performance 2D Canvas physics simulation for Hunter Aja
 */

class AttackSurfaceGraph {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");

    this.nodes = [];
    this.edges = [];
    this.animFrameId = null;

    // Viewport transform
    this.zoom = 1.0;
    this.panX = 0;
    this.panY = 0;

    // Interaction state
    this.isDragging = false;
    this.dragNode = null;
    this.dragStart = { x: 0, y: 0 };
    this.hoverNode = null;

    // Filter toggles
    this.filters = {
      assets: true,
      ports: true,
      findings: true,
      artifacts: true,
    };

    this.setupEvents();
    this.resize();
  }

  resize() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement?.getBoundingClientRect();
    const width = rect?.width || 800;
    const height = 480;

    const dpr = window.devicePixelRatio || 1;
    this.canvas.width = width * dpr;
    this.canvas.height = height * dpr;
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;
    this.ctx.scale(dpr, dpr);
    this.width = width;
    this.height = height;
    if (this.panX === 0 && this.panY === 0) {
      this.panX = width / 2;
      this.panY = height / 2;
    }
  }

  setData(graphData) {
    if (!graphData || !Array.isArray(graphData.nodes)) {
      this.nodes = [];
      this.edges = [];
      return;
    }

    const nodeMap = new Map();
    this.nodes = graphData.nodes.map((n, i) => {
      const angle = (i / graphData.nodes.length) * Math.PI * 2;
      const radius = 120 + Math.random() * 100;
      const node = {
        id: n.id,
        label: n.label || n.id,
        type: n.type || "asset",
        severity: n.severity || "info",
        x: n.type === "target" ? 0 : Math.cos(angle) * radius,
        y: n.type === "target" ? 0 : Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        radius: n.type === "target" ? 18 : n.type === "vulnerability" ? 14 : 10,
      };
      nodeMap.set(n.id, node);
      return node;
    });

    this.edges = (graphData.edges || []).map((e) => ({
      source: typeof e.source === "object" ? e.source.id : e.source,
      target: typeof e.target === "object" ? e.target.id : e.target,
      label: e.label || "",
    })).filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target));

    this.startSimulation();
  }

  setupEvents() {
    if (!this.canvas) return;

    this.canvas.addEventListener("mousedown", (e) => {
      const pos = this.getMousePos(e);
      const clickedNode = this.findNodeAt(pos.x, pos.y);
      if (clickedNode) {
        this.dragNode = clickedNode;
      } else {
        this.isDragging = true;
        this.dragStart = { x: e.clientX - this.panX, y: e.clientY - this.panY };
      }
    });

    window.addEventListener("mousemove", (e) => {
      if (this.dragNode) {
        const pos = this.getMousePos(e);
        this.dragNode.x = pos.x;
        this.dragNode.y = pos.y;
        this.dragNode.vx = 0;
        this.dragNode.vy = 0;
      } else if (this.isDragging) {
        this.panX = e.clientX - this.dragStart.x;
        this.panY = e.clientY - this.dragStart.y;
      } else {
        const pos = this.getMousePos(e);
        this.hoverNode = this.findNodeAt(pos.x, pos.y);
        this.canvas.style.cursor = this.hoverNode ? "pointer" : "grab";
      }
    });

    window.addEventListener("mouseup", () => {
      this.dragNode = null;
      this.isDragging = false;
      if (this.canvas) this.canvas.style.cursor = "grab";
    });

    this.canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.zoom = Math.max(0.3, Math.min(3.0, this.zoom * zoomFactor));
    });

    window.addEventListener("resize", () => {
      this.resize();
    });
  }

  getMousePos(e) {
    const rect = this.canvas.getBoundingClientRect();
    const rawX = e.clientX - rect.left;
    const rawY = e.clientY - rect.top;
    return {
      x: (rawX - this.panX) / this.zoom,
      y: (rawY - this.panY) / this.zoom,
    };
  }

  findNodeAt(x, y) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      if (!this.isNodeVisible(n)) continue;
      const dx = n.x - x;
      const dy = n.y - y;
      if (Math.sqrt(dx * dx + dy * dy) <= n.radius + 4) {
        return n;
      }
    }
    return null;
  }

  isNodeVisible(node) {
    if (node.type === "target") return true;
    if (node.type === "asset" && !this.filters.assets) return false;
    if (node.type === "service" && !this.filters.ports) return false;
    if (node.type === "vulnerability" && !this.filters.findings) return false;
    if (node.type === "artifact" && !this.filters.artifacts) return false;
    return true;
  }

  startSimulation() {
    if (this.animFrameId) cancelAnimationFrame(this.animFrameId);

    const step = () => {
      this.updatePhysics();
      this.render();
      this.animFrameId = requestAnimationFrame(step);
    };
    step();
  }

  updatePhysics() {
    const visibleNodes = this.nodes.filter((n) => this.isNodeVisible(n));
    const k = 80; // Ideal spring length
    const repulse = 1500; // Repulsion constant
    const damping = 0.82;

    // Node-Node Repulsion
    for (let i = 0; i < visibleNodes.length; i++) {
      const n1 = visibleNodes[i];
      for (let j = i + 1; j < visibleNodes.length; j++) {
        const n2 = visibleNodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 350) {
          const force = repulse / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          if (n1 !== this.dragNode && n1.type !== "target") {
            n1.vx -= fx;
            n1.vy -= fy;
          }
          if (n2 !== this.dragNode && n2.type !== "target") {
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }
    }

    // Node map for fast edge lookup
    const nodeMap = new Map();
    visibleNodes.forEach((n) => nodeMap.set(n.id, n));

    // Spring Attraction along Edges
    for (const edge of this.edges) {
      const source = nodeMap.get(edge.source);
      const target = nodeMap.get(edge.target);
      if (!source || !target) continue;

      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - k) * 0.04;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (source !== this.dragNode && source.type !== "target") {
        source.vx += fx;
        source.vy += fy;
      }
      if (target !== this.dragNode && target.type !== "target") {
        target.vx -= fx;
        target.vy -= fy;
      }
    }

    // Center Gravitational Pull
    for (const n of visibleNodes) {
      if (n === this.dragNode || n.type === "target") continue;
      n.vx -= n.x * 0.005;
      n.vy -= n.y * 0.005;

      n.vx *= damping;
      n.vy *= damping;

      n.x += n.vx;
      n.y += n.vy;
    }
  }

  render() {
    if (!this.ctx || !this.width) return;
    const ctx = this.ctx;

    ctx.save();
    ctx.clearRect(0, 0, this.width, this.height);

    // Background Grid
    this.drawBackgroundGrid();

    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    const nodeMap = new Map();
    this.nodes.filter((n) => this.isNodeVisible(n)).forEach((n) => nodeMap.set(n.id, n));

    // 1. Draw Edges
    for (const edge of this.edges) {
      const s = nodeMap.get(edge.source);
      const t = nodeMap.get(edge.target);
      if (!s || !t) continue;

      ctx.beginPath();
      ctx.moveTo(s.x, s.y);
      ctx.lineTo(t.x, t.y);
      ctx.strokeStyle = "rgba(71, 85, 105, 0.4)";
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }

    // 2. Draw Nodes
    for (const n of nodeMap.values()) {
      const isHovered = n === this.hoverNode;
      const color = this.getNodeColor(n);

      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius + (isHovered ? 4 : 0), 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      ctx.lineWidth = isHovered ? 3 : 2;
      ctx.strokeStyle = isHovered ? "#38bdf8" : "rgba(15, 23, 42, 0.8)";
      ctx.stroke();

      // Node Label
      ctx.font = `${isHovered ? "bold 11px" : "10px"} JetBrains Mono, monospace`;
      ctx.fillStyle = isHovered ? "#38bdf8" : "#cbd5e1";
      ctx.textAlign = "center";
      ctx.fillText(n.label.slice(0, 20), n.x, n.y + n.radius + 12);
    }

    ctx.restore();
  }

  getNodeColor(node) {
    if (node.type === "target") return "#06b6d4"; // Cyan
    if (node.type === "asset") return "#10b981"; // Emerald
    if (node.type === "service") return "#f59e0b"; // Amber
    if (node.type === "vulnerability") {
      const sev = (node.severity || "info").toLowerCase();
      if (sev === "critical") return "#ef4444"; // Red
      if (sev === "high") return "#ea580c"; // Orange
      if (sev === "medium") return "#f59e0b"; // Amber
      return "#38bdf8"; // Sky
    }
    if (node.type === "artifact") return "#a855f7"; // Purple
    return "#64748b";
  }

  drawBackgroundGrid() {
    const ctx = this.ctx;
    const gridSize = 30 * this.zoom;
    const startX = (this.panX % gridSize);
    const startY = (this.panY % gridSize);

    ctx.beginPath();
    ctx.strokeStyle = "rgba(30, 41, 59, 0.35)";
    ctx.lineWidth = 0.5;

    for (let x = startX; x < this.width; x += gridSize) {
      ctx.moveTo(x, 0);
      ctx.lineTo(x, this.height);
    }
    for (let y = startY; y < this.height; y += gridSize) {
      ctx.moveTo(0, y);
      ctx.lineTo(this.width, y);
    }
    ctx.stroke();
  }

  resetView() {
    this.zoom = 1.0;
    this.panX = this.width / 2;
    this.panY = this.height / 2;
  }
}

let attackGraphInstance = null;

async function loadAttackGraph(scanId) {
  if (!scanId) scanId = state?.activeScanId;
  if (!scanId) return;

  const canvasEl = el("attackGraphCanvas");
  if (!canvasEl) return;

  if (!attackGraphInstance) {
    attackGraphInstance = new AttackSurfaceGraph("attackGraphCanvas");
  }

  try {
    const res = await authFetch(`${API_BASE}/scans/${scanId}/attack-chains`);
    if (!res.ok) return;
    const data = await res.json();
    attackGraphInstance.setData(data);
  } catch (err) {
    console.debug("Failed to load attack graph data:", err);
  }
}

window.loadAttackGraph = loadAttackGraph;
window.AttackSurfaceGraph = AttackSurfaceGraph;
