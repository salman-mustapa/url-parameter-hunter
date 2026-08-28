/**
 * state.js — Global Application State, Constants & Core Utilities
 * Attack Surface & Parameter Intelligence Platform
 */

const API_BASE = "/api";

// Storage may be unavailable in private or restricted browser contexts.
const appStorage = {
  getItem(key) { try { return localStorage.getItem(key); } catch (_) { return null; } },
  setItem(key, value) { try { localStorage.setItem(key, value); } catch (_) {} },
  removeItem(key) { try { localStorage.removeItem(key); } catch (_) {} },
};
// The HttpOnly cookie restores web sessions; do not persist bearer credentials in JS storage.
appStorage.removeItem("hunter_auth_token");

const state = {
  // Authentication & RBAC
  currentUser: null,
  authToken: null,
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
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
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
  let id = appStorage.getItem("hunter_device_fp");
  if (!id) {
    const randomId = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
    id = `device_${randomId}`;
    appStorage.setItem("hunter_device_fp", id);
  }
  state.deviceFingerprint = id;
  return id;
}

function apiError(data, fallback = "Request gagal") {
  const detail = data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg || fallback).join("; ");
  return fallback;
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

function jsArg(value) { return esc(JSON.stringify(String(value ?? ""))); }

async function writeClipboard(text) {
  if (!navigator.clipboard?.writeText) throw new Error("Clipboard memerlukan HTTPS/localhost. Salin teks secara manual.");
  await navigator.clipboard.writeText(String(text));
}
async function copyText(text) {
  try { await writeClipboard(text); showToast("Teks disalin.", "success"); }
  catch (error) { showToast(error.message || "Gagal menyalin teks.", "warning"); }
}

function safeLink(value) {
  try {
    const url = new URL(String(value || ""), window.location.origin);
    return ["http:", "https:"].includes(url.protocol) ? url.href : "#";
  } catch { return "#"; }
}
