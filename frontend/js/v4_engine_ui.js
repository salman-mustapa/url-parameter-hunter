/**
 * v4_engine_ui.js — V4 Autonomous Security Engine Dashboard & Reasoning Visualizer
 * Attack Surface & Parameter Intelligence Platform V4
 *
 * Provides realtime interactive visualization for:
 * 1. AI Hypotheses Hub & Next-Best-Action Scoring
 * 2. Attack Planner Progress & Multi-Step Execution Tracker
 * 3. Deterministic State Machine Lifecycle Pipeline
 * 4. Tool Registry Explorer & Risk Ratings
 * 5. Application Model & Entity Relationship Graph
 */

const v4State = {
  activeViewMode: "tree", // "tree", "graph", "hypotheses", "statemachine"
  hypotheses: [],
  plans: [],
  tools: [],
  engineStatus: null,
  modelSummary: null,
  pollInterval: null,
  isFetching: false,
};

// =========================================================================
// 1. View Mode Dispatcher (Tree vs Graph vs Hypotheses vs StateMachine)
// =========================================================================

function switchAssetViewMode(mode) {
  v4State.activeViewMode = mode;

  const btnTree = el("showTreeModeBtn");
  const btnGraph = el("showGraphModeBtn");
  const btnHyp = el("showHypothesesModeBtn");
  const btnSM = el("showStateMachineModeBtn");

  const boxTree = el("assetTreeContainer");
  const boxGraph = el("assetGraphContainer");
  const boxHyp = el("aiHypothesesContainer");
  const boxSM = el("stateMachineContainer");

  // Reset button active classes
  [btnTree, btnGraph, btnHyp, btnSM].forEach((b) => {
    if (b) {
      b.classList.remove("active", "btn-primary");
      b.classList.add("btn-secondary");
    }
  });

  // Hide all panels
  [boxTree, boxGraph, boxHyp, boxSM].forEach((c) => {
    if (c) c.classList.add("hidden");
  });

  if (mode === "tree") {
    if (btnTree) { btnTree.classList.add("active", "btn-primary"); btnTree.classList.remove("btn-secondary"); }
    if (boxTree) boxTree.classList.remove("hidden");
    if (typeof refreshAssetTree === "function") refreshAssetTree();
  } else if (mode === "graph") {
    if (btnGraph) { btnGraph.classList.add("active", "btn-primary"); btnGraph.classList.remove("btn-secondary"); }
    if (boxGraph) boxGraph.classList.remove("hidden");
    if (typeof initAttackGraph === "function") {
      initAttackGraph();
    } else if (typeof renderAttackGraphCanvas === "function") {
      renderAttackGraphCanvas();
    }
  } else if (mode === "hypotheses") {
    if (btnHyp) { btnHyp.classList.add("active", "btn-primary"); btnHyp.classList.remove("btn-secondary"); }
    if (boxHyp) boxHyp.classList.remove("hidden");
    loadV4HypothesesAndPlans();
  } else if (mode === "statemachine") {
    if (btnSM) { btnSM.classList.add("active", "btn-primary"); btnSM.classList.remove("btn-secondary"); }
    if (boxSM) boxSM.classList.remove("hidden");
    loadV4StateMachineData();
  }
}

// Real-time live polling for active scans with in-flight & visibility guards
function startV4LivePolling() {
  if (v4State.pollInterval) clearInterval(v4State.pollInterval);
  v4State.pollInterval = setInterval(() => {
    if (typeof document !== "undefined" && document.hidden) return;
    if (!state.activeScanId || v4State.isFetching) return;
    if (state.scanStatus !== "RUNNING" && state.scanStatus !== "QUEUED") return;

    if (v4State.activeViewMode === "statemachine") {
      loadV4StateMachineData();
    } else if (v4State.activeViewMode === "hypotheses") {
      loadV4HypothesesAndPlans();
    }
  }, 4000);
}

// Start polling immediately
if (typeof document !== "undefined") {
  startV4LivePolling();
}

// =========================================================================
// 2. AI Hypotheses & Attack Planner Live Loader
// =========================================================================

async function loadV4HypothesesAndPlans() {
  const scanId = state.activeScanId;
  const container = el("hypothesesListContainer");
  const plansContainer = el("attackPlansListContainer");
  const summaryBox = el("aiReasoningSummaryBox");

  if (!scanId) {
    if (container) {
      container.innerHTML = `
        <div class="v4-empty-box">
          <span class="v4-empty-icon">🧠</span>
          <p>Belum ada scan aktif. Masukkan target domain dan mulai scan untuk melihat perumusan hipotesis AI.</p>
        </div>
      `;
    }
    if (plansContainer) plansContainer.innerHTML = `<div class="v4-empty-box"><p>Belum ada attack plan aktif.</p></div>`;
    return;
  }

  if (v4State.isFetching) return;
  v4State.isFetching = true;

  try {
    const [hypRes, plansRes, engRes] = await Promise.all([
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/hypotheses`),
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/attack-plans`),
      authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/engine`),
    ]);

    if (state.activeScanId !== scanId) return; // Prevent race conditions on scan switch

    const hypData = await hypRes.json();
    const plansData = await plansRes.json();
    const engData = await engRes.json();

    v4State.hypotheses = hypData.hypotheses || [];
    v4State.plans = plansData.plans || [];
    v4State.engineStatus = engData;

    renderV4ReasoningSummary(engData, hypData, plansData);
    renderV4Hypotheses(v4State.hypotheses);
    renderV4AttackPlans(v4State.plans);
  } catch (err) {
    console.debug("Failed to load V4 hypotheses & plans:", err);
  } finally {
    v4State.isFetching = false;
  }
}

function renderV4ReasoningSummary(engData, hypData, plansData) {
  const box = el("aiReasoningSummaryBox");
  if (!box) return;

  const metrics = engData.metrics || {};
  const cycles = metrics.reasoning_cycles || 0;
  const gaps = metrics.coverage_gaps_identified || 0;
  const hypCount = hypData.total_hypotheses || v4State.hypotheses.length || 0;
  const planCount = plansData.total_plans || v4State.plans.length || 0;
  const phase = metrics.phase || "IDLE";

  box.innerHTML = `
    <div class="v4-metrics-grid">
      <div class="v4-metric-card">
        <span class="v4-metric-icon">🔄</span>
        <div class="v4-metric-content">
          <span class="v4-metric-val">${cycles}</span>
          <span class="v4-metric-lbl">Reasoning Cycles</span>
        </div>
      </div>
      <div class="v4-metric-card">
        <span class="v4-metric-icon">🔍</span>
        <div class="v4-metric-content">
          <span class="v4-metric-val">${gaps}</span>
          <span class="v4-metric-lbl">Coverage Gaps</span>
        </div>
      </div>
      <div class="v4-metric-card">
        <span class="v4-metric-icon">💡</span>
        <div class="v4-metric-content">
          <span class="v4-metric-val">${hypCount}</span>
          <span class="v4-metric-lbl">Formulated Hypotheses</span>
        </div>
      </div>
      <div class="v4-metric-card">
        <span class="v4-metric-icon">🎯</span>
        <div class="v4-metric-content">
          <span class="v4-metric-val">${planCount}</span>
          <span class="v4-metric-lbl">Attack Plans</span>
        </div>
      </div>
      <div class="v4-metric-card phase-badge-card">
        <span class="v4-metric-icon">⚙️</span>
        <div class="v4-metric-content">
          <span class="v4-phase-pill ${phase.toLowerCase()}">${esc(phase)}</span>
          <span class="v4-metric-lbl">Engine Stage</span>
        </div>
      </div>
    </div>
  `;
}

function renderV4Hypotheses(hypotheses) {
  const container = el("hypothesesListContainer");
  if (!container) return;

  if (!hypotheses || hypotheses.length === 0) {
    container.innerHTML = `
      <div class="v4-empty-box">
        <span class="v4-empty-icon">💡</span>
        <p>AI sedang menganalisis model aplikasi untuk merumuskan hipotesis serangan terbaik...</p>
      </div>
    `;
    return;
  }

  container.innerHTML = hypotheses.map((h, i) => {
    const pScore = h.priority_score || 0;
    const conf = Math.round((h.confidence || 0) * 100);
    const stateVal = (h.state || "OPEN").toUpperCase();
    const supCount = (h.supporting_evidence || []).length;
    const conCount = (h.contradicting_evidence || []).length;

    let stateClass = "state-open";
    if (stateVal === "CONFIRMED") stateClass = "state-confirmed";
    else if (stateVal === "REJECTED") stateClass = "state-rejected";
    else if (stateVal === "VALIDATING") stateClass = "state-validating";

    return `
      <div class="v4-hyp-card">
        <div class="v4-hyp-header">
          <div class="v4-hyp-title-wrap">
            <span class="v4-hyp-rank">#${i + 1}</span>
            <strong class="v4-hyp-statement">${esc(h.hypothesis || h.statement || "Attack Hypothesis")}</strong>
          </div>
          <div class="v4-hyp-status-wrap">
            <span class="v4-state-badge ${stateClass}">${esc(stateVal)}</span>
            <span class="v4-priority-badge" title="Dynamic Priority Score">P: ${pScore}</span>
          </div>
        </div>
        <div class="v4-hyp-meta">
          <span>🎯 Target: <code>${esc(h.target_endpoint || "-")}</code></span>
          ${h.parameter ? `<span>🧩 Param: <code>${esc(h.parameter)}</code></span>` : ""}
          <span>📊 Confidence: <strong>${conf}%</strong></span>
          ${h.next_test ? `<span>🛠️ Tool: <strong class="v4-tool-tag">${esc(h.next_test)}</strong></span>` : ""}
        </div>
        ${h.expected_result ? `<div class="v4-hyp-expected"><strong>Ekspektasi:</strong> ${esc(h.expected_result)}</div>` : ""}
        <div class="v4-hyp-evidence-row">
          <span class="v4-ev-tag sup" title="Bukti Pendukung">✅ ${supCount} Mendukung</span>
          <span class="v4-ev-tag con" title="Bukti Kontradiksi">❌ ${conCount} Kontradiksi</span>
        </div>
      </div>
    `;
  }).join("");
}

function renderV4AttackPlans(plans) {
  const container = el("attackPlansListContainer");
  if (!container) return;

  if (!plans || plans.length === 0) {
    container.innerHTML = `
      <div class="v4-empty-box">
        <span class="v4-empty-icon">📋</span>
        <p>Belum ada attack plan yang di-generate untuk target ini.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = plans.map((p) => {
    const status = (p.status || "DRAFT").toUpperCase();
    const progress = Math.round((p.progress || 0) * 100);
    const steps = p.steps || [];
    const risk = p.total_risk || 0;
    const budget = p.risk_budget || 10;

    let statusClass = "status-draft";
    if (status === "APPROVED" || status === "EXECUTING") statusClass = "status-executing";
    else if (status === "COMPLETED") statusClass = "status-completed";
    else if (status === "ABORTED" || status === "FAILED") statusClass = "status-aborted";

    return `
      <div class="v4-plan-card">
        <div class="v4-plan-header">
          <div>
            <h4 class="v4-plan-title">${esc(p.title)}</h4>
            <div class="v4-plan-submeta">
              <span>Target: <code>${esc(p.target)}</code></span> ·
              <span>Risk: <strong>${risk}/${budget}</strong></span>
            </div>
          </div>
          <span class="v4-plan-badge ${statusClass}">${esc(status)}</span>
        </div>

        <div class="v4-progress-wrap">
          <div class="v4-progress-bar" style="width:${progress}%;"></div>
        </div>
        <div class="v4-progress-text">${progress}% selesai (${steps.filter(s => s.status === "SUCCEEDED").length}/${steps.length} langkah)</div>

        <div class="v4-steps-timeline">
          ${steps.map((s) => {
            const sStatus = (s.status || "PENDING").toUpperCase();
            let sClass = "step-pending";
            let sIcon = "⏳";
            if (sStatus === "RUNNING") { sClass = "step-running"; sIcon = "⚡"; }
            else if (sStatus === "SUCCEEDED") { sClass = "step-succeeded"; sIcon = "✅"; }
            else if (sStatus === "FAILED") { sClass = "step-failed"; sIcon = "❌"; }
            else if (sStatus === "SKIPPED") { sClass = "step-skipped"; sIcon = "⏭️"; }
            else if (sStatus === "ABORTED") { sClass = "step-aborted"; sIcon = "🛑"; }

            return `
              <div class="v4-step-node ${sClass}">
                <span class="v4-step-icon">${sIcon}</span>
                <div class="v4-step-info">
                  <div class="v4-step-tool"><strong>Step ${s.step_number}:</strong> <code>${esc(s.tool_name)}</code></div>
                  <div class="v4-step-desc">${esc(s.description)}</div>
                </div>
                <span class="v4-step-status-chip ${sClass}">${esc(sStatus)}</span>
              </div>
            `;
          }).join("")}
        </div>
      </div>
    `;
  }).join("");
}

// =========================================================================
// 3. State Machine Lifecycle Pipeline Visualizer
// =========================================================================

async function loadV4StateMachineData() {
  const scanId = state.activeScanId;
  const container = el("stateMachineTimelineContainer");
  const historyContainer = el("stateMachineHistoryContainer");

  if (!scanId) {
    if (container) {
      container.innerHTML = `
        <div class="v4-empty-box">
          <span class="v4-empty-icon">⚙️</span>
          <p>Belum ada scan aktif. Jalankan pemindaian untuk memantau state machine real-time.</p>
        </div>
      `;
    }
    return;
  }

  if (v4State.isFetching) return;
  v4State.isFetching = true;

  try {
    const res = await authFetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/state-machine`);
    if (state.activeScanId !== scanId) return; // Prevent race conditions
    const data = await res.json();
    const sm = data.state_machine || {};
    const history = data.history || [];
    const currentState = (sm.current_state || "CREATED").toUpperCase();

    renderV4StateMachinePipeline(currentState);
    renderV4StateMachineHistory(history);
  } catch (err) {
    console.debug("Failed to load state machine data:", err);
  } finally {
    v4State.isFetching = false;
  }
}

function renderV4StateMachinePipeline(currentState) {
  const container = el("stateMachineTimelineContainer");
  if (!container) return;

  const stages = [
    { key: "CREATED", label: "Created", icon: "🌱" },
    { key: "DISCOVERING", label: "Discovery", icon: "🌐" },
    { key: "MODELING", label: "Modeling", icon: "🧠" },
    { key: "TESTING", label: "Testing", icon: "⚡" },
    { key: "VALIDATING", label: "Validating", icon: "🛡️" },
    { key: "REPORTING", label: "Reporting", icon: "📑" },
    { key: "COMPLETED", label: "Completed", icon: "🎉" },
  ];

  const currentIdx = stages.findIndex(s => s.key === currentState);

  container.innerHTML = `
    <div class="v4-sm-pipeline">
      ${stages.map((st, idx) => {
        let nodeClass = "stage-pending";
        if (st.key === currentState) nodeClass = "stage-active";
        else if (currentIdx > idx || currentState === "COMPLETED") nodeClass = "stage-done";

        return `
          <div class="v4-sm-stage ${nodeClass}">
            <div class="v4-sm-circle">${st.icon}</div>
            <div class="v4-sm-label">${esc(st.label)}</div>
            ${nodeClass === "stage-active" ? `<span class="v4-sm-active-dot pulse"></span>` : ""}
          </div>
          ${idx < stages.length - 1 ? `<div class="v4-sm-connector ${currentIdx > idx ? 'done' : ''}"></div>` : ""}
        `;
      }).join("")}
    </div>
  `;
}

function renderV4StateMachineHistory(history) {
  const container = el("stateMachineHistoryContainer");
  if (!container) return;

  if (!history || history.length === 0) {
    container.innerHTML = `<div class="v4-empty-box"><p>Belum ada rekaman transisi state.</p></div>`;
    return;
  }

  container.innerHTML = `
    <div class="v4-sm-history-table">
      <div class="v4-sm-th-row">
        <span>Waktu</span>
        <span>Dari State</span>
        <span>Transisi (Trigger)</span>
        <span>Ke State</span>
      </div>
      ${history.map(e => {
        const ts = (typeof e.timestamp === 'number') ? (e.timestamp > 1e11 ? new Date(e.timestamp) : new Date(e.timestamp * 1000)) : new Date(e.timestamp);
        const timeStr = isNaN(ts.getTime()) ? '-' : ts.toLocaleTimeString();
        return `
          <div class="v4-sm-tr-row">
            <span class="mono">${timeStr}</span>
            <span class="v4-state-chip">${esc(e.from_state)}</span>
            <span class="v4-trigger-chip">➔ ${esc(e.trigger)}</span>
            <span class="v4-state-chip active">${esc(e.to_state)}</span>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

// =========================================================================
// 4. Tool Registry Explorer Modal
// =========================================================================

async function openToolRegistryModal() {
  const modal = el("toolRegistryModal");
  if (!modal) return;
  modal.classList.remove("hidden");

  const container = el("toolRegistryModalContent");
  if (container) {
    container.innerHTML = `<div class="v4-empty-box"><span class="empty-icon">⏳</span><p>Memuat katalog tool keamanan...</p></div>`;
  }

  try {
    const res = await authFetch(`${API_BASE}/engine/tools`);
    const data = await res.json();
    v4State.tools = data.tools || [];
    renderToolRegistryModal(v4State.tools, data.by_category || {});
  } catch (err) {
    console.error("Failed to load tool registry:", err);
  }
}

function closeToolRegistryModal() {
  const modal = el("toolRegistryModal");
  if (modal) modal.classList.add("hidden");
}

function renderToolRegistryModal(tools, byCategory) {
  const container = el("toolRegistryModalContent");
  if (!container) return;

  const categories = Object.keys(byCategory);

  container.innerHTML = `
    <div class="v4-tool-modal-body">
      <div class="v4-tool-cats-bar">
        <button class="filter-pill active" onclick="filterToolRegistryCategory('ALL')">Semua (${tools.length})</button>
        ${categories.map(c => `
          <button class="filter-pill" onclick="filterToolRegistryCategory('${esc(c)}')">${esc(c)} (${byCategory[c]})</button>
        `).join("")}
      </div>

      <div id="toolRegistryCardsGrid" class="v4-tool-cards-grid">
        ${tools.map(t => renderToolCard(t)).join("")}
      </div>
    </div>
  `;
}

function renderToolCard(t) {
  const riskClass = `risk-${(t.risk_level || "SAFE").toLowerCase()}`;
  return `
    <div class="v4-tool-card" data-category="${esc(t.category)}">
      <div class="v4-tool-card-header">
        <strong class="v4-tool-name">${esc(t.name)}</strong>
        <span class="v4-risk-badge ${riskClass}">${esc(t.risk_level)}</span>
      </div>
      <div class="v4-tool-cat-badge">${esc(t.category)} · Cost: ${t.cost}</div>
      <p class="v4-tool-desc">${esc(t.description)}</p>
      <div class="v4-tool-caps">
        ${(t.capabilities || []).map(c => `<span class="v4-cap-chip">${esc(c)}</span>`).join("")}
      </div>
    </div>
  `;
}

function filterToolRegistryCategory(category) {
  const cards = document.querySelectorAll(".v4-tool-card");
  cards.forEach(c => {
    if (category === "ALL" || c.dataset.category === category) {
      c.classList.remove("hidden");
    } else {
      c.classList.add("hidden");
    }
  });

  // Update active pill button
  document.querySelectorAll(".v4-tool-cats-bar .filter-pill").forEach(p => {
    if (p.textContent.startsWith(category) || (category === "ALL" && p.textContent.startsWith("Semua"))) {
      p.classList.add("active");
    } else {
      p.classList.remove("active");
    }
  });
}
