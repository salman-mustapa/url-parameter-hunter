/**
 * auth.js — Authentication, Registration & RBAC Access Control
 * Attack Surface & Parameter Intelligence Platform
 */

window.openAuthModal = function(defaultTab = "login") {
  const modal = document.getElementById("authModal");
  if (!modal) {
    console.warn("authModal element not found");
    return;
  }
  hideAuthAlert();
  
  document.querySelectorAll(".auth-tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.authTab === defaultTab);
  });

  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");

  if (defaultTab === "login") {
    if (loginForm) {
      loginForm.classList.remove("hidden");
      loginForm.style.display = "flex";
    }
    if (registerForm) {
      registerForm.classList.add("hidden");
      registerForm.style.display = "none";
    }
    setTimeout(() => document.getElementById("loginUsername")?.focus(), 50);
  } else {
    if (loginForm) {
      loginForm.classList.add("hidden");
      loginForm.style.display = "none";
    }
    if (registerForm) {
      registerForm.classList.remove("hidden");
      registerForm.style.display = "flex";
    }
    setTimeout(() => document.getElementById("regUsername")?.focus(), 50);
  }

  modal.classList.remove("hidden");
};

window.closeAuthModal = function() {
  const modal = document.getElementById("authModal");
  if (modal) {
    modal.classList.add("hidden");
  }
  hideAuthAlert();
};

async function checkAuth() {
  try {
    const res = await authFetch(`${API_BASE}/auth/me`);
    const data = await res.json();

    if (data.authenticated && data.user) {
      state.currentUser = data.user;
      renderUserAuthUI();
    } else {
      state.currentUser = null;
      renderUserAuthUI();
    }
  } catch (err) {
    console.debug("Auth check failed:", err);
    state.currentUser = null;
    renderUserAuthUI();
  }
}

function renderUserAuthUI() {
  const openAuthBtn = el("openAuthBtn");
  const userProfileWrap = el("userProfileWrap");
  const adminTabBtn = el("adminTabBtn");
  const adminNoticeBanner = el("adminNoticeBanner");

  const guestTabs = document.querySelectorAll(".guest-tab");
  const userTabs = document.querySelectorAll(".user-tab");

  if (state.currentUser) {
    // Authenticated state
    if (openAuthBtn) openAuthBtn.classList.add("hidden");
    if (userProfileWrap) userProfileWrap.classList.remove("hidden");

    const username = state.currentUser.username || "User";
    const role = (state.currentUser.role || "user").toUpperCase();
    const isAdm = role === "ADMIN";
    const initial = username.charAt(0).toUpperCase();

    if (el("navUsername")) el("navUsername").textContent = username;
    if (el("navUserRole")) {
      el("navUserRole").textContent = role;
      el("navUserRole").className = `role-badge ${isAdm ? 'role-admin' : 'role-user'}`;
    }

    // Populate profile dropdown header
    if (el("dropdownUsername")) el("dropdownUsername").textContent = username;
    if (el("dropdownUserEmail")) el("dropdownUserEmail").textContent = state.currentUser.email || `${username.toLowerCase()}@hunteraja.internal`;
    if (el("dropdownAvatarInitial")) el("dropdownAvatarInitial").textContent = initial;
    if (el("dropdownRoleBadge")) {
      el("dropdownRoleBadge").textContent = role;
      el("dropdownRoleBadge").className = `role-badge ${isAdm ? 'role-admin' : 'role-user'}`;
    }

    guestTabs.forEach((t) => t.classList.add("hidden"));
    userTabs.forEach((t) => t.classList.remove("hidden"));

    if (isAdm) {
      if (adminTabBtn) adminTabBtn.classList.remove("hidden");
      if (el("adminBottomTabBtn")) el("adminBottomTabBtn").classList.remove("hidden");
      if (adminNoticeBanner) adminNoticeBanner.classList.remove("hidden");
    } else {
      if (adminTabBtn) adminTabBtn.classList.add("hidden");
      if (el("adminBottomTabBtn")) el("adminBottomTabBtn").classList.add("hidden");
      if (adminNoticeBanner) adminNoticeBanner.classList.add("hidden");
    }

    const currentRoute = (typeof parseRoute === "function") ? parseRoute() : { tab: "home", params: {} };
    const isGuestOnlyRoute = !window.location.hash || window.location.hash === "#" || window.location.hash === "#/" || window.location.hash === "#/home" || currentRoute.tab === "home" || currentRoute.tab === "trial" || currentRoute.tab === "features";

    if (isGuestOnlyRoute) {
      if (state.currentUser.role === "admin") {
        switchViewTab("admin", {}, true);
        if (typeof loadAdminData === "function") loadAdminData();
      } else {
        switchViewTab("dashboard", {}, true);
      }
    } else {
      switchViewTab(currentRoute.tab, currentRoute.params, false);
    }
  } else {
    // Guest state
    if (openAuthBtn) openAuthBtn.classList.remove("hidden");
    if (userProfileWrap) userProfileWrap.classList.add("hidden");
    if (adminTabBtn) adminTabBtn.classList.add("hidden");
    if (el("adminBottomTabBtn")) el("adminBottomTabBtn").classList.add("hidden");
    if (adminNoticeBanner) adminNoticeBanner.classList.add("hidden");

    // Close dropdown if open
    closeProfileDropdown();

    guestTabs.forEach((t) => t.classList.remove("hidden"));
    userTabs.forEach((t) => t.classList.add("hidden"));

    const currentRoute = (typeof parseRoute === "function") ? parseRoute() : { tab: "home", params: {} };
    if (currentRoute.tab === "features" || currentRoute.tab === "trial") {
      switchViewTab(currentRoute.tab, currentRoute.params, false);
    } else {
      switchViewTab("home", {}, false);
    }
  }
}

function toggleProfileDropdown() {
  const dd = el("userProfileDropdown");
  const btn = el("userProfileDropdownBtn");
  if (!dd) return;
  const isHidden = dd.classList.contains("hidden");
  if (isHidden) {
    dd.classList.remove("hidden");
    if (btn) btn.classList.add("active");
  } else {
    dd.classList.add("hidden");
    if (btn) btn.classList.remove("active");
  }
}

function closeProfileDropdown() {
  const dd = el("userProfileDropdown");
  const btn = el("userProfileDropdownBtn");
  if (dd) dd.classList.add("hidden");
  if (btn) btn.classList.remove("active");
}

function openAccountSettingsModal(tabName = "password") {
  closeProfileDropdown();
  const modal = el("accountSettingsModal");
  if (!modal) return;
  modal.classList.remove("hidden");
  hideAccountAlert();
  switchAccountTab(tabName);

  // Populate API Token
  const tokenInput = el("userBearerTokenDisplay");
  if (tokenInput) {
    const token = state.authToken || localStorage.getItem("hunter_auth_token") || "hunter_session_verified_jwt";
    tokenInput.value = token;
  }
}

function closeAccountSettingsModal() {
  const modal = el("accountSettingsModal");
  if (modal) modal.classList.add("hidden");
  hideAccountAlert();
}

function switchAccountTab(tabName) {
  document.querySelectorAll(".acc-tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.accTab === tabName);
  });

  const paneMap = {
    password: "accTabPassword",
    linked: "accTabLinked",
    tokens: "accTabTokens",
    preferences: "accTabPreferences",
  };

  document.querySelectorAll(".acc-pane").forEach((pane) => pane.classList.add("hidden"));
  const targetPane = el(paneMap[tabName]);
  if (targetPane) targetPane.classList.remove("hidden");
}

function showAccountAlert(msg, isSuccess = false) {
  const alertEl = el("accountAlert");
  if (alertEl) {
    const icon = isSuccess ? "✅" : "⚠️";
    alertEl.innerHTML = `<span>${icon}</span> <span>${esc(msg)}</span>`;
    alertEl.className = `auth-alert ${isSuccess ? 'success' : 'error'}`;
    alertEl.classList.remove("hidden");
  }
  if (typeof showToast === "function") {
    showToast(msg, isSuccess ? "success" : "error");
  }
}

function hideAccountAlert() {
  const alertEl = el("accountAlert");
  if (alertEl) alertEl.classList.add("hidden");
}

function toggleTokenMask() {
  const input = el("userBearerTokenDisplay");
  if (!input) return;
  input.type = input.type === "password" ? "text" : "password";
}

function copyApiToken() {
  const input = el("userBearerTokenDisplay");
  if (!input || !input.value) return;
  navigator.clipboard.writeText(input.value)
    .then(() => {
      if (typeof showToast === "function") showToast("✅ API Bearer Token berhasil disalin ke clipboard!", "success");
    })
    .catch(() => {
      if (typeof showToast === "function") showToast("Gagal menyalin token.", "error");
    });
}

function toggleSSOLink(provider) {
  if (typeof showToast === "function") {
    showToast(`🔗 Autentikasi Single Sign-On (${provider.toUpperCase()}) siap dihubungkan.`, "info");
  }
}

function savePreference(key, value) {
  localStorage.setItem(`hunter_pref_${key}`, value ? "1" : "0");
  if (typeof showToast === "function") {
    showToast(`Preferensi ${key} berhasil disimpan.`, "success");
  }
}

function showAuthAlert(msg, isSuccess = false) {
  const alertEl = el("authAlert");
  if (alertEl) {
    const icon = isSuccess ? "✅" : "⚠️";
    alertEl.innerHTML = `<span>${icon}</span> <span>${esc(msg)}</span>`;
    alertEl.className = `auth-alert ${isSuccess ? 'success' : 'error'}`;
    alertEl.classList.remove("hidden");
  }
  if (!isSuccess && typeof showToast === "function") {
    showToast(msg, "error");
  }
}

function hideAuthAlert() {
  const alertEl = el("authAlert");
  if (alertEl) alertEl.classList.add("hidden");
}

function setupAuthModal() {
  const modal = el("authModal");
  const openBtn = el("openAuthBtn");
  const closeBtn = el("closeAuthModalBtn");
  const logoutBtn = el("logoutBtn");

  if (openBtn) {
    openBtn.addEventListener("click", () => window.openAuthModal("login"));
  }

  // Hook all buttons that should open the auth modal
  document.querySelectorAll('#openAuthFromHeroBtn, #ctaLoginBtn, #heroLoginBtn, [data-action="openAuth"]').forEach((btn) => {
    btn.addEventListener("click", () => window.openAuthModal("login"));
  });

  document.querySelectorAll('#ctaRegisterBtn, [data-action="openRegister"]').forEach((btn) => {
    btn.addEventListener("click", () => window.openAuthModal("register"));
  });

  if (closeBtn) {
    closeBtn.addEventListener("click", window.closeAuthModal);
  }

  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) window.closeAuthModal();
    });
  }

  // Global Escape key modal closer
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-backdrop").forEach((m) => m.classList.add("hidden"));
    }
  });

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      closeProfileDropdown();
      try {
        await authFetch(`${API_BASE}/auth/logout`, { method: "POST" });
      } catch (_) {}
      localStorage.removeItem("hunter_auth_token");
      state.authToken = null;
      state.currentUser = null;
      renderUserAuthUI();
      if (typeof showToast === "function") showToast("Anda telah keluar dari akun.", "info");
    });
  }

  // Profile Dropdown Toggle & Outside Click Handler
  const profileDropdownBtn = el("userProfileDropdownBtn");
  if (profileDropdownBtn) {
    profileDropdownBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleProfileDropdown();
    });
  }

  document.addEventListener("click", (e) => {
    const wrap = el("userProfileWrap");
    if (wrap && !wrap.contains(e.target)) {
      closeProfileDropdown();
    }
  });

  // Account Settings Modal Close Handler
  const closeAccBtn = el("closeAccountModalBtn");
  if (closeAccBtn) {
    closeAccBtn.addEventListener("click", closeAccountSettingsModal);
  }
  const accModal = el("accountSettingsModal");
  if (accModal) {
    accModal.addEventListener("click", (e) => {
      if (e.target === accModal) closeAccountSettingsModal();
    });
  }

  // Change Password Form Submission
  const changePwdForm = el("changePasswordForm");
  const newPwdInput = el("newPasswordInput");
  const pwdStrengthFill = el("pwdStrengthFill");
  const pwdStrengthLabel = el("pwdStrengthLabel");

  if (newPwdInput && pwdStrengthFill) {
    newPwdInput.addEventListener("input", () => {
      const val = newPwdInput.value;
      if (!val) {
        pwdStrengthFill.style.width = "0%";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Belum diisi";
          pwdStrengthLabel.style.color = "#64748B";
        }
        return;
      }

      let score = 0;
      if (val.length >= 6) score += 25;
      if (val.length >= 10) score += 25;
      if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score += 25;
      if (/[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) score += 25;

      pwdStrengthFill.style.width = `${score}%`;
      if (score <= 25) {
        pwdStrengthFill.style.background = "#ef4444";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Sangat Lemah (tambahkan huruf besar & simbol)";
          pwdStrengthLabel.style.color = "#ef4444";
        }
      } else if (score <= 50) {
        pwdStrengthFill.style.background = "#f59e0b";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Cukup (panjangkan lagi)";
          pwdStrengthLabel.style.color = "#d97706";
        }
      } else if (score <= 75) {
        pwdStrengthFill.style.background = "#3b82f6";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Bagus";
          pwdStrengthLabel.style.color = "#2563eb";
        }
      } else {
        pwdStrengthFill.style.background = "#10b981";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Sangat Kuat & Aman ✅";
          pwdStrengthLabel.style.color = "#059669";
        }
      }
    });
  }

  if (changePwdForm) {
    changePwdForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAccountAlert();

      const old_password = (el("oldPasswordInput")?.value || "").trim();
      const new_password = (el("newPasswordInput")?.value || "").trim();
      const confirm_pwd = (el("confirmPasswordInput")?.value || "").trim();

      if (new_password !== confirm_pwd) {
        showAccountAlert("Konfirmasi password baru tidak cocok. Silakan periksa kembali.", false);
        return;
      }

      if (new_password.length < 6) {
        showAccountAlert("Password baru minimal 6 karakter.", false);
        return;
      }

      const saveBtn = el("savePasswordBtn");
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = "⏳ Memproses...";
      }

      try {
        const res = await authFetch(`${API_BASE}/auth/change-password`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ old_password, new_password }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Gagal memperbarui password");

        showAccountAlert("✅ Password berhasil diubah! Kredensial baru telah aktif.", true);
        changePwdForm.reset();
        if (pwdStrengthFill) pwdStrengthFill.style.width = "0%";
        if (pwdStrengthLabel) {
          pwdStrengthLabel.textContent = "Kekuatan: Belum diisi";
          pwdStrengthLabel.style.color = "#64748B";
        }
      } catch (err) {
        showAccountAlert(err.message, false);
      } finally {
        if (saveBtn) {
          saveBtn.disabled = false;
          saveBtn.textContent = "💾 Simpan Perubahan Password";
        }
      }
    });
  }

  // Trial Limit Modal Handlers
  const trialLimitModal = el("trialLimitModal");
  const closeTrialLimitBtn = el("closeTrialLimitModalBtn");
  const trialLimitCloseBtn = el("trialLimitCloseBtn");
  const trialLimitAuthBtn = el("trialLimitAuthBtn");

  if (closeTrialLimitBtn && trialLimitModal) {
    closeTrialLimitBtn.addEventListener("click", () => trialLimitModal.classList.add("hidden"));
  }
  if (trialLimitCloseBtn && trialLimitModal) {
    trialLimitCloseBtn.addEventListener("click", () => trialLimitModal.classList.add("hidden"));
  }
  if (trialLimitModal) {
    trialLimitModal.addEventListener("click", (e) => {
      if (e.target === trialLimitModal) trialLimitModal.classList.add("hidden");
    });
  }
  if (trialLimitAuthBtn && trialLimitModal) {
    trialLimitAuthBtn.addEventListener("click", () => {
      trialLimitModal.classList.add("hidden");
      window.openAuthModal("login");
    });
  }

  // Auth Tab Switcher
  document.querySelectorAll(".auth-tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.authTab || "login";
      window.openAuthModal(tab);
    });
  });

  // Handle Login Submit
  const loginForm = el("loginForm");
  if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAuthAlert();
      const username = (el("loginUsername")?.value || "").trim();
      const password = (el("loginPassword")?.value || "").trim();
      const device_fingerprint = getDeviceFingerprint();

      try {
        const res = await fetch(`${API_BASE}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Device-Fingerprint": device_fingerprint },
          body: JSON.stringify({ username, password, device_fingerprint }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Gagal masuk");

        state.authToken = data.access_token;
        localStorage.setItem("hunter_auth_token", data.access_token);
        state.currentUser = data.user;
        renderUserAuthUI();
        window.closeAuthModal();

        if (state.currentUser.role === "admin") {
          switchViewTab("admin", {}, true);
          if (typeof loadAdminData === "function") loadAdminData();
        } else {
          switchViewTab("dashboard", {}, true);
        }

        const roleLabel = state.currentUser.role === "admin" ? "Administrator" : "User";
        if (typeof showToast === "function") {
          showToast(`✅ Selamat datang kembali, ${data.user?.username}! (Masuk sebagai ${roleLabel})`, "success");
        }
        if (typeof loadHistory === "function") loadHistory();
      } catch (err) {
        showAuthAlert(err.message, false);
      }
    });
  }

  // Handle Register Submit
  const registerForm = el("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      hideAuthAlert();
      const username = (el("regUsername")?.value || "").trim();
      const email = (el("regEmail")?.value || "").trim();
      const password = (el("regPassword")?.value || "").trim();
      const device_fingerprint = getDeviceFingerprint();

      try {
        const res = await fetch(`${API_BASE}/auth/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Device-Fingerprint": device_fingerprint },
          body: JSON.stringify({ username, email, password, device_fingerprint }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Gagal mendaftar");

        state.authToken = data.access_token;
        localStorage.setItem("hunter_auth_token", data.access_token);
        state.currentUser = data.user;
        renderUserAuthUI();
        window.closeAuthModal();

        if (state.currentUser.role === "admin") {
          switchViewTab("admin", {}, true);
          if (typeof loadAdminData === "function") loadAdminData();
        } else {
          switchViewTab("dashboard", {}, true);
        }

        if (typeof showToast === "function") {
          showToast(`✅ Akun berhasil dibuat. Selamat datang, ${data.user?.username}!`, "success");
        }
        if (typeof loadHistory === "function") loadHistory();
      } catch (err) {
        showAuthAlert(err.message, false);
      }
    });
  }
}

function toggleInputVisibility(inputId, btnEl) {
  const input = el(inputId);
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    if (btnEl) btnEl.textContent = "🙈";
  } else {
    input.type = "password";
    if (btnEl) btnEl.textContent = "👁️";
  }
}

// Export global helper functions
window.toggleProfileDropdown = toggleProfileDropdown;
window.closeProfileDropdown = closeProfileDropdown;
window.openAccountSettingsModal = openAccountSettingsModal;
window.closeAccountSettingsModal = closeAccountSettingsModal;
window.switchAccountTab = switchAccountTab;
window.toggleTokenMask = toggleTokenMask;
window.copyApiToken = copyApiToken;
window.toggleSSOLink = toggleSSOLink;
window.savePreference = savePreference;
window.toggleInputVisibility = toggleInputVisibility;
