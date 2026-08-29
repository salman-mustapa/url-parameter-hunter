/**
 * notifications_settings.js — User-Isolated Alert Integrations (Telegram, Discord, Slack)
 * Guarantees 100% tenant & account isolation for alerts.
 */

async function loadUserNotificationsConfig() {
  if (!state?.currentUser) return;
  try {
    const res = await authFetch(`${API_BASE}/user/notifications`);
    if (!res.ok) return;
    const data = await res.json();

    if (el("notifTelegramToken")) el("notifTelegramToken").value = data.telegram_bot_token || "";
    if (el("notifTelegramChatId")) el("notifTelegramChatId").value = data.telegram_chat_id || "";
    if (el("notifTelegramEnabled")) el("notifTelegramEnabled").checked = !!data.telegram_enabled;

    if (el("notifDiscordWebhook")) el("notifDiscordWebhook").value = data.discord_webhook_url || "";
    if (el("notifDiscordEnabled")) el("notifDiscordEnabled").checked = !!data.discord_enabled;

    if (el("notifSlackWebhook")) el("notifSlackWebhook").value = data.slack_webhook_url || "";
    if (el("notifSlackEnabled")) el("notifSlackEnabled").checked = !!data.slack_enabled;

    if (el("notifCritToggle")) el("notifCritToggle").checked = data.notify_on_critical !== false;
    if (el("notifHighToggle")) el("notifHighToggle").checked = data.notify_on_high !== false;
    if (el("notifScanCompleteToggle")) el("notifScanCompleteToggle").checked = data.notify_on_scan_complete !== false;
    if (el("notifNewAssetsToggle")) el("notifNewAssetsToggle").checked = data.notify_on_new_assets !== false;
  } catch (err) {
    console.debug("Failed to load user notification configs:", err);
  }
}

async function saveUserNotificationsConfig() {
  if (!state?.currentUser) {
    if (typeof openAuthModal === "function") openAuthModal("login");
    return;
  }

  const payload = {
    telegram_bot_token: el("notifTelegramToken")?.value.trim() || null,
    telegram_chat_id: el("notifTelegramChatId")?.value.trim() || null,
    telegram_enabled: !!el("notifTelegramEnabled")?.checked,

    discord_webhook_url: el("notifDiscordWebhook")?.value.trim() || null,
    discord_enabled: !!el("notifDiscordEnabled")?.checked,

    slack_webhook_url: el("notifSlackWebhook")?.value.trim() || null,
    slack_enabled: !!el("notifSlackEnabled")?.checked,

    notify_on_critical: !!el("notifCritToggle")?.checked,
    notify_on_high: !!el("notifHighToggle")?.checked,
    notify_on_scan_complete: !!el("notifScanCompleteToggle")?.checked,
    notify_on_new_assets: !!el("notifNewAssetsToggle")?.checked,
  };

  const saveBtn = el("saveNotifConfigBtn");
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = "Menyimpan...";
  }

  try {
    const res = await authFetch(`${API_BASE}/user/notifications`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Gagal menyimpan konfigurasi" }));
      if (typeof showToast === "function") showToast(err.detail || "Gagal menyimpan.", "warning");
      return;
    }

    if (typeof showToast === "function") {
      showToast("✅ Pengaturan notifikasi akun Anda berhasil disimpan secara aman!", "success");
    }
  } catch (err) {
    if (typeof showToast === "function") showToast(`Error: ${err.message}`, "warning");
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = "💾 Simpan Pengaturan Notifikasi";
    }
  }
}

async function testNotificationChannel(channel) {
  if (!state?.currentUser) {
    if (typeof showToast === "function") showToast("Silakan login terlebih dahulu.", "warning");
    return;
  }

  const payload = {
    channel: channel,
    telegram_bot_token: el("notifTelegramToken")?.value.trim() || null,
    telegram_chat_id: el("notifTelegramChatId")?.value.trim() || null,
    discord_webhook_url: el("notifDiscordWebhook")?.value.trim() || null,
    slack_webhook_url: el("notifSlackWebhook")?.value.trim() || null,
  };

  if (typeof showToast === "function") {
    showToast(`Mengirim pesan tes ke ${channel.toUpperCase()}...`, "info");
  }

  try {
    const res = await authFetch(`${API_BASE}/user/notifications/test`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json().catch(() => ({ detail: "Respons server tidak valid" }));
    if (!res.ok) {
      if (typeof showToast === "function") showToast(`❌ ${data.detail || "Tes gagal"}`, "warning");
      return;
    }

    if (typeof showToast === "function") {
      showToast(`🎉 ${data.detail || "Pesan tes berhasil terkirim!"}`, "success");
    }
  } catch (err) {
    if (typeof showToast === "function") showToast(`Gagal: ${err.message}`, "warning");
  }
}

window.loadUserNotificationsConfig = loadUserNotificationsConfig;
window.saveUserNotificationsConfig = saveUserNotificationsConfig;
window.testNotificationChannel = testNotificationChannel;

async function testSmartDiffNotification() {
  if (!state?.currentUser) {
    if (typeof showToast === "function") showToast("Silakan login terlebih dahulu.", "warning");
    return;
  }

  // Determine active channel
  let activeChannel = "telegram";
  if (el("notifTelegramEnabled")?.checked) activeChannel = "telegram";
  else if (el("notifDiscordEnabled")?.checked) activeChannel = "discord";
  else if (el("notifSlackEnabled")?.checked) activeChannel = "slack";

  const payload = {
    channel: activeChannel,
    telegram_bot_token: el("notifTelegramToken")?.value.trim() || null,
    telegram_chat_id: el("notifTelegramChatId")?.value.trim() || null,
    discord_webhook_url: el("notifDiscordWebhook")?.value.trim() || null,
    slack_webhook_url: el("notifSlackWebhook")?.value.trim() || null,
  };

  if (typeof showToast === "function") {
    showToast(`Menguji format Smart Diff ke ${activeChannel.toUpperCase()}...`, "info");
  }

  try {
    const res = await authFetch(`${API_BASE}/user/notifications/test-diff`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json().catch(() => ({ detail: "Respons server tidak valid" }));
    if (!res.ok) {
      if (typeof showToast === "function") showToast(`❌ ${data.detail || "Tes Smart Diff gagal"}`, "warning");
      return;
    }

    if (typeof showToast === "function") {
      showToast(`🎉 ${data.detail || "Simulasi Smart Diff berhasil terkirim!"}`, "success");
    }
  } catch (err) {
    if (typeof showToast === "function") showToast(`Gagal: ${err.message}`, "warning");
  }
}

window.testSmartDiffNotification = testSmartDiffNotification;
