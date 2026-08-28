/* Native mobile navigation and modal lifecycle. No continuous layout polling. */
document.addEventListener("DOMContentLoaded", () => {
  const menu = el("mobileMoreMenu");
  const trigger = el("mobileMoreBtn");
  const close = () => { if (menu?.open) menu.close(); };
  trigger?.addEventListener("click", () => {
    if (!menu.open) menu.showModal();
    trigger.setAttribute("aria-expanded", "true");
    syncModalState();
  });
  el("closeMobileMoreBtn")?.addEventListener("click", close);
  menu?.addEventListener("click", event => {
    const link = event.target.closest(".mobile-menu-link");
    if (link) {
      close();
      if (link.dataset.tab) switchViewTab(link.dataset.tab);
    } else if (event.target === menu) close();
  });
  menu?.addEventListener("close", () => {
    trigger.setAttribute("aria-expanded", "false");
    syncModalState();
  });
  matchMedia("(max-width: 960px)").addEventListener("change", event => { if (!event.matches) close(); });

  const backdrops = [...document.querySelectorAll(".modal-backdrop")];
  let previousFocus = null;
  let activeModal = null;
  function syncModalState() {
    const visible = backdrops.filter(node => !node.classList.contains("hidden"));
    const next = visible[visible.length - 1] || (menu?.open ? menu : null);
    document.body.classList.toggle("modal-open", !!next);
    if (next && !activeModal) previousFocus = document.activeElement;
    if (!next && activeModal && previousFocus?.isConnected) previousFocus.focus({preventScroll: true});
    if (next && next !== activeModal && next !== menu) {
      const dialog = next.querySelector(".modal-dialog, .modal-card") || next;
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-modal", "true");
      const heading = dialog.querySelector("h2, h3, h4");
      if (heading) {
        if (!heading.id) heading.id = `${next.id}-title`;
        dialog.setAttribute("aria-labelledby", heading.id);
      }
      const focusable = dialog.querySelector("button:not([disabled]), input:not([type=hidden]), select, [tabindex='0']");
      focusable?.focus({preventScroll: true});
    }
    activeModal = next;
  }
  const observer = new MutationObserver(syncModalState);
  backdrops.forEach(node => observer.observe(node, {attributes: true, attributeFilter: ["class"]}));
  document.addEventListener("keydown", event => {
    if (!activeModal || activeModal === menu) return;
    if (event.key === "Escape") { activeModal.classList.add("hidden"); return; }
    if (event.key !== "Tab") return;
    const focusable = [...activeModal.querySelectorAll("button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea, [tabindex='0']")].filter(node => node.getClientRects().length);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || !activeModal.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (document.activeElement === last || !activeModal.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
  });
  if (window.visualViewport) {
    const syncKeyboard = () => {
      const editing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
      document.body.classList.toggle("keyboard-open", editing && window.innerHeight - window.visualViewport.height > 150);
    };
    window.visualViewport.addEventListener("resize", syncKeyboard, {passive:true});
    document.addEventListener("focusout", syncKeyboard);
  }
});
