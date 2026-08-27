/**
 * state.js — Global Application State, Constants & Core Utilities
 * Attack Surface & Parameter Intelligence Platform
 */

const API_BASE = "/api";

const state = {
  // Authentication & RBAC
  currentUser: null,
  authToken: localStorage.getItem("hunter_auth_token") || null,
  deviceFingerprint: null,

  // Active Scan
  activeScanId: null,
  activeTarget: "",
  scanStatus: "IDLE",
  timerInterval: null,
  timerSeconds: 0,
  es: null,
  treePollInterval: null,
  statusPollInterval: null,

  // Filters & Data
  currentCategoryFilter: "ALL",
  currentTreeSevFilter: "ALL",
  currentFindingsSevFilter: "ALL",
  allFindings: [],
  events: [],
  assetsTreeData: [],
  selectedAssetId: null,
  activeDetailTab: "overview",
  collapsedNodeIds: new Set(),
  currentAssetData: null,

  // Global matrices (Contextual modals)
  allPortsData: [],
  allParamsData: [],
  allUrlsData: [],
  allTechsData: [],
  allAssetsData: [],
  allFindingsModalData: [],
  currentPortFilter: "ALL",
  currentUrlFilter: "ALL",
  currentTechFilter: "ALL",
  currentAssetFilter: "ALL",
  currentFindingModalFilter: "ALL",

  // Telemetry Counters
  counters: {
    assets: 0,
    ports: 0,
    urls: 0,
    params: 0,
    techs: 0,
    findings: 0,
  },
  severityCounts: {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  },
};

// DOM & String Helpers
function el(id) {
  return document.getElementById(id);
}

function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(seconds) {
  const m = Math.floor(seconds / 60).toString().padStart(2, "0");
  const s = (seconds % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

function formatConfidence(conf) {
  if (conf === null || conf === undefined) return "VALIDATED";
  if (typeof conf === "number") return `${Math.round(conf * 100)}%`;
  if (typeof conf === "string") {
    const num = parseFloat(conf);
    if (!isNaN(num) && num <= 1.0) return `${Math.round(num * 100)}%`;
    return conf.toUpperCase();
  }
  return "VALIDATED";
}

// --------------------------------------------------------------------------
// Multi-Factor Device Fingerprinting (Canvas + WebGL + Audio + Screen)
// --------------------------------------------------------------------------
function getDeviceFingerprint() {
  if (state.deviceFingerprint) return state.deviceFingerprint;

  let fpId = localStorage.getItem("hunter_device_fp");
  if (!fpId) {
    const components = [];
    // 1. Hardware & System
    components.push(
      screen.width || 0,
      screen.height || 0,
      screen.colorDepth || 24,
      navigator.hardwareConcurrency || 4,
      navigator.maxTouchPoints || 0,
      navigator.platform || "",
      navigator.language || "",
      Intl.DateTimeFormat().resolvedOptions().timeZone || ""
    );

    // 2. Canvas 2D fingerprint
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext("2d");
      if (ctx) {
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial', sans-serif";
        ctx.textBaseline = "alphabetic";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.fillText("HunterAja,🐙<canvas>", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.fillText("HunterAja,🐙<canvas>", 4, 17);
        components.push(canvas.toDataURL());
      }
    } catch (_) {}

    // 3. WebGL GPU renderer fingerprint
    try {
      const canvas = document.createElement("canvas");
      const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || "");
          components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || "");
        }
      }
    } catch (_) {}

    // Hash to composite 32-char hex string
    const raw = components.join("###");
    let hash = 0;
    for (let i = 0; i < raw.length; i++) {
      hash = ((hash << 5) - hash) + raw.charCodeAt(i);
      hash |= 0;
    }
    const randPart = Math.random().toString(36).substring(2, 10);
    fpId = `dfp_${Math.abs(hash).toString(16)}_${randPart}`;
    try {
      localStorage.setItem("hunter_device_fp", fpId);
    } catch (_) {}
  }

  state.deviceFingerprint = fpId;
  return fpId;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 20000) {
  const controller = new AbortController();
  const upstreamSignal = options.signal;
  const abortFromUpstream = () => controller.abort(upstreamSignal?.reason);
  if (upstreamSignal) {
    if (upstreamSignal.aborted) abortFromUpstream();
    else upstreamSignal.addEventListener("abort", abortFromUpstream, { once: true });
  }
  const timer = setTimeout(() => controller.abort(new DOMException("Request timed out", "TimeoutError")), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
    if (upstreamSignal) upstreamSignal.removeEventListener("abort", abortFromUpstream);
  }
}

window.fetchWithTimeout = fetchWithTimeout;

// Wrapper for API fetch that automatically attaches Bearer Token & Device Fingerprint
async function authFetch(url, options = {}) {
  options.headers = options.headers || {};
  if (state.authToken) {
    options.headers["Authorization"] = `Bearer ${state.authToken}`;
  }
  const fp = getDeviceFingerprint();
  if (fp) {
    options.headers["X-Device-Fingerprint"] = fp;
  }
  const timeoutMs = Number(options.timeoutMs || 20000);
  delete options.timeoutMs;
  return fetchWithTimeout(url, options, timeoutMs);
}

// --------------------------------------------------------------------------
// Unified Sketch Neo-Brutalist Toast System
// --------------------------------------------------------------------------
function showToast(message, type = "info", duration = 4000) {
  const container = el("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `system-toast toast-${type}`;
  const icon = type === "success" ? "✅" : (type === "warning" ? "⚠️" : (type === "danger" ? "❌" : "ℹ️"));

  toast.innerHTML = `
    <span class="toast-icon">${icon}</span>
    <span class="toast-text">${esc(message)}</span>
    <button class="toast-close">✕</button>
  `;

  toast.querySelector(".toast-close").addEventListener("click", () => {
    toast.classList.add("toast-fade-out");
    setTimeout(() => toast.remove(), 250);
  });

  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.classList.add("toast-fade-out");
      setTimeout(() => toast.remove(), 250);
    }
  }, duration);
}

window.showToast = showToast;
