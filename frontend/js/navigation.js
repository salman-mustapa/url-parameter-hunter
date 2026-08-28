/**
 * navigation.js — Single-Page Navigation, Stateful URL Routing & Breadcrumb Engine
 * Attack Surface & Parameter Intelligence Platform V11
 */

function parseRoute() {
  const hash = window.location.hash.replace(/^#\/?/, "");
  if (!hash) {
    const defaultTab = state.currentUser ? (state.currentUser.role === "admin" ? "admin" : "dashboard") : "home";
    return { tab: defaultTab, params: {} };
  }

  const [path, queryString] = hash.split("?");
  const params = {};
  if (queryString) {
    const searchParams = new URLSearchParams(queryString);
    for (const [k, v] of searchParams.entries()) {
      params[k] = v;
    }
  }

  let tab = path || "home";
  const protectedTabs = ["dashboard", "history", "reports", "diff", "admin", "domainDetail", "assetDetail", "findingDetail"];
  if (!state.currentUser && protectedTabs.includes(tab)) {
    tab = "home";
  }

  return { tab, params };
}

function updateRouteURL(tabName, params = {}) {
  const query = new URLSearchParams(params).toString();
  const newHash = `#/${tabName}${query ? '?' + query : ''}`;
  if (window.location.hash !== newHash) {
    window.history.pushState({ tab: tabName, params }, "", newHash);
  }
}

window.showTopLoader = function() {
  const elLoader = el("globalTopLoader");
  if (elLoader) {
    elLoader.classList.remove("done");
    elLoader.classList.add("loading");
  }
};

window.hideTopLoader = function() {
  const elLoader = el("globalTopLoader");
  if (elLoader) {
    elLoader.classList.add("done");
    setTimeout(() => {
      elLoader.classList.remove("loading", "done");
    }, 350);
  }
};

window.setButtonLoading = function(btn, isLoading, loadingText = "Memuat...") {
  if (!btn) return;
  if (isLoading) {
    if (!btn.dataset.origHtml) btn.dataset.origHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-inline">⏳</span> ${loadingText}`;
    btn.classList.add("btn-loading");
  } else {
    if (btn.dataset.origHtml) btn.innerHTML = btn.dataset.origHtml;
    btn.disabled = false;
    btn.classList.remove("btn-loading");
  }
};

function updateBreadcrumbUI(tabName, params = {}) {
  const dashBc = el("dashboardBreadcrumbName");
  if (dashBc) {
    if (state.activeTarget) {
      dashBc.textContent = `${state.activeTarget} (${state.activeScanId || 'Baru'})`;
    } else {
      dashBc.textContent = "Live Workspace";
    }
  }

  const repBc = el("reportsBreadcrumbScan");
  if (repBc) {
    const selScan = params.scan_id || state.activeScanId;
    repBc.textContent = selScan ? `#${selScan}` : "Semua Laporan";
  }
}

function switchViewTab(tabName, params = {}, pushState = true) {
  // 1. Strict Authentication Guard for Protected Views
  const protectedTabs = [
    "dashboard", "history", "reports", "diff", "admin",
    "domainDetail", "assetDetail", "findingDetail"
  ];

  if (!state.currentUser && protectedTabs.includes(tabName)) {
    console.warn(`[RouteGuard] Access to '${tabName}' blocked: User is not authenticated.`);
    tabName = "home";
    updateRouteURL("home");
    if (typeof openAuthModal === "function") {
      openAuthModal("login");
    }
    if (typeof showToast === "function") {
      showToast("Silakan Masuk atau Daftar terlebih dahulu untuk mengakses fitur ini.", "warning");
    }
  }

  // 2. Strict Role-Based Access Control for Admin View
  if (state.currentUser && tabName === "admin" && state.currentUser.role !== "admin") {
    console.warn("[RouteGuard] Access to 'admin' blocked: User does not have administrator privileges.");
    tabName = "dashboard";
    updateRouteURL("dashboard");
    if (typeof showToast === "function") {
      showToast("Halaman Admin hanya dapat diakses oleh Administrator.", "warning");
    }
  }

  // Update Topbar and Bottom Nav Active States
  document.querySelectorAll(".nav-link[data-tab], .bottom-nav-link[data-tab], .mobile-menu-link[data-tab]").forEach((b) => {
    if (b.dataset.tab === tabName) {
      b.classList.add("active");
      b.setAttribute("aria-current", "page");
    } else {
      b.classList.remove("active");
      b.removeAttribute("aria-current");
    }
  });
  const moreActive = ["admin", "diff"].includes(tabName);
  el("mobileMoreBtn")?.classList.toggle("active", moreActive);
  if (moreActive) el("mobileMoreBtn")?.setAttribute("aria-current", "page");
  else el("mobileMoreBtn")?.removeAttribute("aria-current");

  // Hide all tab views
  document.querySelectorAll(".tab-view").forEach((v) => v.classList.add("hidden"));

  // Dispatch Tab Views
  if (tabName === "home") {
    if (el("viewHome")) el("viewHome").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
  } else if (tabName === "trial") {
    if (el("viewHome")) el("viewHome").classList.remove("hidden");
    const trialSec = el("homeTrialSection");
    if (trialSec) trialSec.scrollIntoView({ behavior: "smooth" });
    if (el("trialTargetInput")) el("trialTargetInput").focus();
  } else if (tabName === "features") {
    if (el("viewHome")) el("viewHome").classList.remove("hidden");
    const featSec = el("homeFeaturesSection");
    if (featSec) featSec.scrollIntoView({ behavior: "smooth" });
  } else if (tabName === "dashboard") {
    if (el("viewDashboard")) el("viewDashboard").classList.remove("hidden");
    if (typeof renderStreamEvents === "function") renderStreamEvents();
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (typeof syncActiveScansBar === "function") syncActiveScansBar();

    if (params.newScanTarget) {
      state.activeScanId = null;
      state.activeTarget = params.newScanTarget;
      state.currentTarget = params.newScanTarget;
      if (el("targetInput")) el("targetInput").value = params.newScanTarget;
      if (params.profile && el("profileSelect")) el("profileSelect").value = params.profile;
      if (typeof updateBreadcrumbUI === "function") {
        updateBreadcrumbUI("dashboard", { target: params.newScanTarget });
      }
      return;
    }

    if (params.skipAutoLoad) {
      return;
    }

    const targetScanId = params.scan_id || state.activeScanId;

    if (targetScanId) {
      const isDifferentScan = params.scan_id && params.scan_id !== state.activeScanId;
      const isNotYetRendered = !state.events || state.events.length === 0 || !el("targetInput")?.value;

      if (isDifferentScan || isNotYetRendered) {
        if (typeof openHistoricalScan === "function") {
          openHistoricalScan(targetScanId, params.target || state.activeTarget);
        }
      }
    } else {
      authFetch(`${API_BASE}/scans`)
        .then(res => res.json())
        .then(scans => {
          const scanList = Array.isArray(scans) ? scans : (Array.isArray(scans?.scans) ? scans.scans : []);
          const runningScan = scanList.find(s => s.status === "running" || s.status === "queued");

          if (runningScan) {
            const exactTarget = (runningScan.options && (runningScan.options.target_url || runningScan.options.target_host)) || runningScan.target_url || runningScan.target_host || runningScan.root_domain || "";
            state.activeScanId = runningScan.id;
            state.activeTarget = exactTarget;
            state.currentTarget = exactTarget;
            if (typeof openHistoricalScan === "function") {
              openHistoricalScan(runningScan.id, exactTarget);
            }
          } else if (scanList.length > 0) {
            const latestScan = scanList[0];
            const exactTarget = (latestScan.options && (latestScan.options.target_url || latestScan.options.target_host)) || latestScan.target_url || latestScan.target_host || latestScan.root_domain || "";
            state.activeScanId = latestScan.id;
            state.activeTarget = exactTarget;
            state.currentTarget = exactTarget;
            if (typeof openHistoricalScan === "function") {
              openHistoricalScan(latestScan.id, exactTarget);
            }
          } else {
            if (typeof resetCleanDashboard === "function") {
              resetCleanDashboard();
            }
          }
        })
        .catch(err => console.warn("Failed to check scans:", err));
    }
  } else if (tabName === "history") {
    if (el("viewHistory")) el("viewHistory").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (typeof loadHistory === "function") loadHistory();
  } else if (tabName === "reports") {
    if (el("viewReports")) el("viewReports").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    const targetScanId = params.scan_id || state.activeScanId;
    if (typeof initReportHub === "function") initReportHub(targetScanId);
  } else if (tabName === "diff") {
    if (el("viewDiff")) el("viewDiff").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (typeof populateDiffSelects === "function") populateDiffSelects();
    if (params.scan_a && params.scan_b && typeof executeDiffComparison === "function") {
      executeDiffComparison(params.scan_a, params.scan_b);
    }
  } else if (tabName === "admin") {
    if (el("viewAdmin")) el("viewAdmin").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (typeof loadAdminData === "function") loadAdminData();
  } else if (tabName === "domainDetail") {
    if (el("viewDomainDetail")) el("viewDomainDetail").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (params.name && typeof openDomainDetail === "function") {
      openDomainDetail(params.name, false);
    }
  } else if (tabName === "assetDetail") {
    if (el("viewAssetDetail")) el("viewAssetDetail").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (params.id && typeof openAssetDetail === "function") {
      openAssetDetail(params.id, false);
    }
  } else if (tabName === "findingDetail") {
    if (el("viewFindingDetail")) el("viewFindingDetail").classList.remove("hidden");
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (params.id && typeof openFindingDetail === "function") {
      openFindingDetail(params.id, false);
    }
  }

  updateBreadcrumbUI(tabName, params);

  if (pushState) {
    updateRouteURL(tabName, params);
  }
}

function handleRouteFromURL() {
  const route = parseRoute();
  switchViewTab(route.tab, route.params, false);
}

function setupNavigation() {
  // Navigation Links (Top and Bottom)
  document.querySelectorAll(".nav-link[data-tab], .bottom-nav-link[data-tab]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const tabName = btn.dataset.tab;
      if (tabName) switchViewTab(tabName);
    });
  });

  // Breadcrumb global event delegation
  document.addEventListener("click", (e) => {
    const target = e.target.closest("[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    if (action === "goHome") {
      e.preventDefault();
      switchViewTab("home");
    } else if (action === "goDashboard") {
      e.preventDefault();
      switchViewTab("dashboard");
    } else if (action === "goHistory") {
      e.preventDefault();
      switchViewTab("history");
    } else if (action === "goReports") {
      e.preventDefault();
      switchViewTab("reports");
    } else if (action === "goDiff") {
      e.preventDefault();
      switchViewTab("diff");
    } else if (action === "openAuth") {
      e.preventDefault();
      if (typeof window.openAuthModal === "function") window.openAuthModal("login");
    } else if (action === "openRegister") {
      e.preventDefault();
      if (typeof window.openAuthModal === "function") window.openAuthModal("register");
    }
  });

  // Handle Browser Back / Forward and Direct URL load
  window.addEventListener("hashchange", handleRouteFromURL);
  window.addEventListener("popstate", (e) => {
    if (e.state && e.state.tab) {
      switchViewTab(e.state.tab, e.state.params || {}, false);
    } else {
      handleRouteFromURL();
    }
  });

  const logoBtn = el("brandLogoBtn");
  if (logoBtn) {
    logoBtn.addEventListener("click", () => {
      if (state.currentUser) {
        if (state.currentUser.role === "admin") {
          switchViewTab("admin");
        } else {
          switchViewTab("dashboard");
        }
      } else {
        switchViewTab("home");
      }
    });
  }

  const startTrialBtn = el("startTrialBtn");
  if (startTrialBtn) {
    startTrialBtn.addEventListener("click", () => {
      if (!state.currentUser) {
        openAuthModal("login");
        showToast("Masuk untuk menjalankan scan pada target yang Anda izinkan.", "info");
        return;
      }
      const trialVal = (el("trialTargetInput")?.value || "").trim();
      const trialScope = el("trialScopeModeSelect")?.value || "recursive";

      if (!trialVal) {
        if (typeof showToast === "function") showToast("Silakan masukkan URL / domain target untuk uji coba.", "warning");
        el("trialTargetInput")?.focus();
        return;
      }

      if (el("targetInput")) el("targetInput").value = trialVal;
      if (el("scopeModeSelect")) el("scopeModeSelect").value = trialScope;

      switchViewTab("dashboard");
      if (typeof startScan === "function") startScan();
    });
  }

  // Quick suggestion chips on home
  document.querySelectorAll(".sample-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const sample = chip.dataset.sample || chip.textContent.replace(/^[^\w]+/, "").trim();
      if (el("trialTargetInput")) el("trialTargetInput").value = sample;
      if (el("targetInput")) el("targetInput").value = sample;
    });
  });

  // FAQ Accordion interactive fold/expand
  document.querySelectorAll(".faq-question").forEach((faqQ) => {
    faqQ.addEventListener("click", () => {
      const faqItem = faqQ.closest(".faq-item");
      const icon = faqQ.querySelector(".faq-toggle-icon");
      if (faqItem) {
        const isCollapsed = faqItem.classList.contains("collapsed") || !faqItem.classList.contains("expanded");
        if (isCollapsed) {
          faqItem.classList.remove("collapsed");
          faqItem.classList.add("expanded");
          if (icon) icon.textContent = "➖";
        } else {
          faqItem.classList.remove("expanded");
          faqItem.classList.add("collapsed");
          if (icon) icon.textContent = "➕";
        }
      }
    });
  });

  // Initial Route Resolution on Page Load
  setTimeout(handleRouteFromURL, 50);
}

function resetCleanDashboard() {
  state.activeScanId = null;
  state.activeTarget = "";
  state.scanStatus = "IDLE";
  state.events = [];
  state.allFindings = [];
  state.counters = { assets: 0, ports: 0, urls: 0, params: 0, techs: 0, findings: 0 };
  state.severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  state.assetsTreeData = [];

  if (el("scanIdDisplay")) el("scanIdDisplay").classList.add("hidden");
  if (el("targetInput")) el("targetInput").value = "";
  if (typeof updateScanStatusUI === "function") updateScanStatusUI("IDLE");
  if (typeof updateCounterDisplays === "function") updateCounterDisplays();
  if (typeof renderStreamEvents === "function") renderStreamEvents();
  if (typeof renderAssetTree === "function") renderAssetTree([]);
  if (typeof renderFindings === "function") renderFindings([]);
  if (el("findingsBadgeTotal")) el("findingsBadgeTotal").textContent = "0 Total";
  if (el("sevCritCount")) el("sevCritCount").textContent = "0";
  if (el("sevHighCount")) el("sevHighCount").textContent = "0";
  if (el("sevMedCount")) el("sevMedCount").textContent = "0";
  if (el("sevLowCount")) el("sevLowCount").textContent = "0";
  if (el("sevInfoCount")) el("sevInfoCount").textContent = "0";
  if (el("scanTime")) el("scanTime").classList.add("hidden");
  if (el("scanCompletedBanner")) el("scanCompletedBanner").classList.add("hidden");
  if (typeof stopTimer === "function") stopTimer();
  if (typeof renderReportHubEmpty === "function") renderReportHubEmpty();
  if (typeof loadV4HypothesesAndPlans === "function") loadV4HypothesesAndPlans();
  if (typeof loadV4StateMachineData === "function") loadV4StateMachineData();
}

window.setupNavigation = setupNavigation;
window.resetCleanDashboard = resetCleanDashboard;
