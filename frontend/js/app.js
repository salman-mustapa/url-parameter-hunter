/**
 * app.js — Main Application Entrypoint & Event Listener Wiring
 * Attack Surface & Parameter Intelligence Platform
 */

document.addEventListener("DOMContentLoaded", async () => {
  // 1. Initialize Device Fingerprint & Verify Auth State FIRST
  getDeviceFingerprint();
  await checkAuth();

  // 2. Initialize Navigation & Subsystems with verified Auth Guard
  setupNavigation();
  setupAuthModal();
  setupReportModal();
  setupGlobalSearch();
  if (typeof setupTreeControls === "function") setupTreeControls();
  if (typeof setupHistoryEvents === "function") setupHistoryEvents();
  if (typeof setupReportHubEvents === "function") setupReportHubEvents();
  if (typeof syncActiveScansBar === "function") syncActiveScansBar();

  // 2. Scan Execution Controls
  if (el("startBtn")) el("startBtn").addEventListener("click", startScan);
  if (el("targetInput")) {
    el("targetInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        startScan();
      }
    });
  }

  if (el("pauseBtn")) el("pauseBtn").addEventListener("click", pauseScan);
  if (el("resumeBtn")) el("resumeBtn").addEventListener("click", resumeScan);
  if (el("stopBtn")) el("stopBtn").addEventListener("click", stopScan);
  if (el("exportBtn")) el("exportBtn").addEventListener("click", openReportModal);
  if (el("quickExportBtn")) el("quickExportBtn").addEventListener("click", openReportModal);

  // 3. Asset Tree Explorer Controls
  if (el("refreshTreeBtn")) el("refreshTreeBtn").addEventListener("click", refreshAssetTree);
  if (el("collapseAllBtn")) el("collapseAllBtn").addEventListener("click", collapseAllNodes);
  if (el("expandAllBtn")) el("expandAllBtn").addEventListener("click", expandAllNodes);
  if (el("treeSearchInput")) {
    el("treeSearchInput").addEventListener("input", () => renderAssetTree(state.assetsTreeData));
  }

  // 4. Synchronized Severity Filtering for BOTH Tree and Findings Triaging
  document.querySelectorAll(".clickable-sev-tag").forEach((tag) => {
    tag.addEventListener("click", () => {
      const sev = tag.dataset.sevFilter;
      const isAlreadyActive = tag.classList.contains("active");

      document.querySelectorAll(".clickable-sev-tag").forEach((t) => t.classList.remove("active"));

      if (isAlreadyActive) {
        // Toggle OFF -> show all
        state.currentTreeSevFilter = "ALL";
        state.currentFindingsSevFilter = "ALL";
      } else {
        // Toggle ON -> filter by specific severity
        tag.classList.add("active");
        state.currentTreeSevFilter = sev;
        state.currentFindingsSevFilter = sev;
      }
      renderAssetTree(state.assetsTreeData);
      renderFindings();
    });
  });

  // 5. Contextual Telemetry Cards (All Explorers & Matrices Modals)
  const telAssets = el("telemetryAssetsCard");
  if (telAssets) telAssets.addEventListener("click", openAssetsModal);

  const telPorts = el("telemetryPortsCard");
  if (telPorts) telPorts.addEventListener("click", openPortsModal);

  const telUrls = el("telemetryUrlsCard");
  if (telUrls) telUrls.addEventListener("click", openUrlsModal);

  const telParams = el("telemetryParamsCard");
  if (telParams) telParams.addEventListener("click", openParamsModal);

  const telTechs = el("telemetryTechsCard");
  if (telTechs) telTechs.addEventListener("click", openTechsModal);

  const telFindings = el("telemetryFindingsCard");
  if (telFindings) telFindings.addEventListener("click", openFindingsModal);

  const telMitre = el("telemetryMitreCard");
  if (telMitre) {
    telMitre.addEventListener("click", () => {
      const scanId = state.activeScanId || (state.historyItems && state.historyItems[0] ? state.historyItems[0].id : null);
      el("mitreModal")?.classList.remove("hidden");
      if (typeof window.loadMitreMatrix === "function") window.loadMitreMatrix(scanId);
    });
  }

  const telGallery = el("telemetryGalleryCard");
  if (telGallery) {
    telGallery.addEventListener("click", () => {
      const scanId = state.activeScanId || (state.historyItems && state.historyItems[0] ? state.historyItems[0].id : null);
      el("galleryModal")?.classList.remove("hidden");
      if (typeof window.loadScreenshotGallery === "function") window.loadScreenshotGallery(scanId);
    });
  }

  // Modal Closers Helper
  const setupModalCloser = (modalId, closeBtnId) => {
    const modalEl = el(modalId);
    const closeBtn = el(closeBtnId);
    if (closeBtn) closeBtn.addEventListener("click", () => modalEl?.classList.add("hidden"));
    if (modalEl) modalEl.addEventListener("click", (e) => { if (e.target === modalEl) modalEl.classList.add("hidden"); });
  };

  setupModalCloser("portsModal", "closePortsModalBtn");
  setupModalCloser("paramsModal", "closeParamsModalBtn");
  setupModalCloser("urlsModal", "closeUrlsModalBtn");
  setupModalCloser("techsModal", "closeTechsModalBtn");
  setupModalCloser("assetsModal", "closeAssetsModalBtn");
  setupModalCloser("findingsModal", "closeFindingsModalBtn");
  setupModalCloser("mitreModal", "closeMitreModalBtn");
  setupModalCloser("galleryModal", "closeGalleryModalBtn");

  if (el("refreshMitreModalBtn")) {
    el("refreshMitreModalBtn").addEventListener("click", () => {
      const scanId = state.activeScanId || (state.historyItems && state.historyItems[0] ? state.historyItems[0].id : null);
      if (typeof window.loadMitreMatrix === "function") window.loadMitreMatrix(scanId);
    });
  }

  if (el("refreshGalleryModalBtn")) {
    el("refreshGalleryModalBtn").addEventListener("click", () => {
      const scanId = state.activeScanId || (state.historyItems && state.historyItems[0] ? state.historyItems[0].id : null);
      if (typeof window.loadScreenshotGallery === "function") window.loadScreenshotGallery(scanId);
    });
  }

  // Global Port Matrix Search & Tags in Modal
  if (el("refreshPortsBtn")) el("refreshPortsBtn").addEventListener("click", loadAllPorts);
  if (el("portSearchInput")) el("portSearchInput").addEventListener("input", renderPortsMatrix);
  document.querySelectorAll(".port-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".port-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.currentPortFilter = pill.dataset.portFilter;
      renderPortsMatrix();
    });
  });

  // Global Parameters Search in Modal
  if (el("refreshParamsBtn")) el("refreshParamsBtn").addEventListener("click", loadAllParameters);
  if (el("paramSearchInput")) el("paramSearchInput").addEventListener("input", renderParamsMatrix);

  // Global URLs Search & Tags in Modal
  if (el("refreshUrlsBtn")) el("refreshUrlsBtn").addEventListener("click", loadAllUrls);
  if (el("urlSearchInput")) el("urlSearchInput").addEventListener("input", renderUrlsMatrix);
  document.querySelectorAll(".url-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".url-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.currentUrlFilter = pill.dataset.urlFilter;
      renderUrlsMatrix();
    });
  });

  // Global Technologies Search & Tags in Modal
  if (el("refreshTechsBtn")) el("refreshTechsBtn").addEventListener("click", loadAllTechnologies);
  if (el("techSearchInput")) el("techSearchInput").addEventListener("input", renderTechsMatrix);
  document.querySelectorAll(".tech-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".tech-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.currentTechFilter = pill.dataset.techFilter;
      renderTechsMatrix();
    });
  });

  // Global Assets Search & Tags in Modal
  if (el("refreshAssetsBtn")) el("refreshAssetsBtn").addEventListener("click", loadAllAssets);
  if (el("assetSearchInput")) el("assetSearchInput").addEventListener("input", renderAssetsMatrix);
  document.querySelectorAll(".asset-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".asset-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.currentAssetFilter = pill.dataset.assetFilter;
      renderAssetsMatrix();
    });
  });

  // Global Findings Modal Search & Tags
  if (el("refreshFindingsModalBtn")) el("refreshFindingsModalBtn").addEventListener("click", loadAllFindingsModal);
  if (el("findingModalSearchInput")) el("findingModalSearchInput").addEventListener("input", renderFindingsModal);
  document.querySelectorAll(".finding-modal-filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".finding-modal-filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      state.currentFindingModalFilter = pill.dataset.fsevFilter;
      renderFindingsModal();
    });
  });

  // 6. Asset Detail Inspector Tabs
  document.querySelectorAll(".detail-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      renderDetailTabContent(btn.dataset.detailTab);
    });
  });
  if (el("closeDetailBtn")) {
    el("closeDetailBtn").addEventListener("click", () => {
      if (el("assetDetailCard")) el("assetDetailCard").classList.add("hidden");
      state.selectedAssetId = null;
      document.querySelectorAll(".tree-node-row").forEach((r) => r.classList.remove("selected"));
    });
  }

  // 7. History & Diff Analyzer
  if (el("refreshHistoryBtn")) el("refreshHistoryBtn").addEventListener("click", loadHistory);
  if (el("runDiffBtn")) el("runDiffBtn").addEventListener("click", runDiffAnalysis);

  // 8. Stream Category Filter Pills & Clear Controls
  if (el("clearStreamBtn")) {
    el("clearStreamBtn").addEventListener("click", (e) => {
      e.preventDefault();
      if (typeof clearStreamLog === "function") clearStreamLog();
    });
  }

  document.querySelectorAll(".filter-pill").forEach((pill) => {
    pill.addEventListener("click", () => {
      document.querySelectorAll(".filter-pill").forEach((p) => p.classList.remove("active"));
      pill.classList.add("active");
      filterStreamEvents(pill.dataset.filter);
    });
  });

  // 9. Admin Oversight Dashboard
  if (el("refreshAdminBtn")) el("refreshAdminBtn").addEventListener("click", loadAdminData);
  document.querySelectorAll(".admin-subtab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".admin-subtab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const view = btn.dataset.adminView;
      if (view === "users") {
        if (el("adminUsersView")) el("adminUsersView").classList.remove("hidden");
        if (el("adminDomainsView")) el("adminDomainsView").classList.add("hidden");
      } else {
        if (el("adminUsersView")) el("adminUsersView").classList.add("hidden");
        if (el("adminDomainsView")) el("adminDomainsView").classList.remove("hidden");
      }
    });
  });

  // 10. Global Escape Key to close all modals, drawers, and lightboxes
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const selectors = [
        "portsModal", "paramsModal", "urlsModal", "techsModal", "assetsModal",
        "findingsModal", "mitreModal", "galleryModal", "reportModal", "authModal",
        "trialLimitModal", "screenshotLightboxModal", "systemConfirmModal",
        "globalSearchOverlay", "assetDetailDrawer", "assetDetailCard", "artifactsModal", "artifactDetailModal"
      ];
      selectors.forEach(id => {
        const modal = el(id);
        if (modal && !modal.classList.contains("hidden")) {
          modal.classList.add("hidden");
        }
      });
    }
  });

  // 11. Universal Click Delegation for Modal Closers and Backdrop Clicks
  document.addEventListener("click", (e) => {
    const closeBtn = e.target.closest(".modal-close-btn, [data-modal-close], #closeAuthModalBtn, #closePortsModalBtn, #closeParamsModalBtn, #closeUrlsModalBtn, #closeTechsModalBtn, #closeAssetsModalBtn, #closeFindingsModalBtn, #closeMitreModalBtn, #closeGalleryModalBtn, #closeReportModalBtn, #closeDrawerBtn, #closeDetailBtn");
    if (closeBtn) {
      e.preventDefault();
      const parentModal = closeBtn.closest(".modal-backdrop, .entity-drawer-backdrop, .asset-detail-card");
      if (parentModal) {
        parentModal.classList.add("hidden");
      } else {
        const allModals = [
          "portsModal", "paramsModal", "urlsModal", "techsModal", "assetsModal",
          "findingsModal", "mitreModal", "galleryModal", "reportModal", "authModal",
          "trialLimitModal", "screenshotLightboxModal", "systemConfirmModal",
          "globalSearchOverlay", "assetDetailDrawer", "assetDetailCard", "artifactsModal", "artifactDetailModal"
        ];
        allModals.forEach(id => {
          const m = el(id);
          if (m && !m.classList.contains("hidden")) m.classList.add("hidden");
        });
      }
      return;
    }

    // 2. Auth Tab button click (Masuk vs Daftar Akun Baru)
    const authTabBtn = e.target.closest(".auth-tab-btn, [data-auth-tab]");
    if (authTabBtn) {
      e.preventDefault();
      const tab = authTabBtn.dataset.authTab || "login";
      if (typeof window.openAuthModal === "function") {
        window.openAuthModal(tab);
      }
      return;
    }

    // 3. Backdrop click
    if (e.target.classList.contains("modal-backdrop") || e.target.classList.contains("entity-drawer-backdrop")) {
      e.target.classList.add("hidden");
    }
  });
});