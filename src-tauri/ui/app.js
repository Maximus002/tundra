const { invoke } = window.__TAURI__.core;

let statsInterval = null;
let connected = false;

const $ = (id) => document.getElementById(id);

function showToast(msg, type = "info") {
  const t = $("toast");
  t.textContent = msg;
  t.className = `toast ${type}`;
  setTimeout(() => t.classList.add("hidden"), 3000);
}

function formatBytes(n) {
  if (n === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(n) / Math.log(k));
  return parseFloat((n / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatUptime(secs) {
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  return `${m}:${String(s).padStart(2, "0")}`;
}

function getConfig() {
  return {
    name: $("profile-select").value || "Quick Connect",
    server_addr: $("server-addr").value.trim(),
    server_port: parseInt($("server-port").value) || 8443,
    socks_port: parseInt($("socks-port").value) || 1080,
    psk: $("psk").value.trim(),
    fme: $("fme-toggle").checked,
  };
}

function setConnected(val) {
  connected = val;
  const btn = $("btn-connect");
  const badge = $("status-badge");

  if (val) {
    btn.textContent = "Disconnect";
    btn.classList.add("active");
    badge.textContent = "Connected";
    badge.className = "badge connected";
    setInputsDisabled(true);
    startStatsPolling();
  } else {
    btn.textContent = "Connect";
    btn.classList.remove("active");
    badge.textContent = "Disconnected";
    badge.className = "badge disconnected";
    setInputsDisabled(false);
    stopStatsPolling();
    resetStats();
  }
}

function setInputsDisabled(val) {
  $("server-addr").disabled = val;
  $("server-port").disabled = val;
  $("socks-port").disabled = val;
  $("psk").disabled = val;
  $("fme-toggle").disabled = val;
  $("profile-select").disabled = val;
}

function resetStats() {
  $("stat-streams").textContent = "0";
  $("stat-sent").textContent = "0 B";
  $("stat-recv").textContent = "0 B";
  $("stat-uptime").textContent = "0:00";
}

function startStatsPolling() {
  stopStatsPolling();
  statsInterval = setInterval(async () => {
    try {
      const s = await invoke("get_stats");
      $("stat-streams").textContent = s.streams;
      $("stat-sent").textContent = formatBytes(s.bytes_sent);
      $("stat-recv").textContent = formatBytes(s.bytes_recv);
      $("stat-uptime").textContent = formatUptime(s.uptime_secs);
    } catch (e) {
      console.error("stats error:", e);
    }
  }, 1000);
}

function stopStatsPolling() {
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
}

async function loadProfiles() {
  try {
    const profiles = await invoke("get_profiles");
    const sel = $("profile-select");
    sel.innerHTML = '<option value="">-- Select profile --</option>';
    profiles.forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.name;
      opt.textContent = p.name;
      sel.appendChild(opt);
    });
  } catch (e) {
    console.error("load profiles error:", e);
  }
}

async function applyProfile(name) {
  if (!name) return;
  try {
    const profiles = await invoke("get_profiles");
    const p = profiles.find((x) => x.name === name);
    if (!p) return;
    $("server-addr").value = p.server_addr;
    $("server-port").value = p.server_port;
    $("socks-port").value = p.socks_port;
    $("psk").value = p.psk;
    $("fme-toggle").checked = p.fme;
  } catch (e) {
    console.error("apply profile error:", e);
  }
}

$("btn-connect").addEventListener("click", async () => {
  if (connected) {
    try {
      await invoke("disconnect");
      setConnected(false);
      showToast("Disconnected", "info");
    } catch (e) {
      showToast("Disconnect error: " + e, "error");
    }
    return;
  }

  const cfg = getConfig();
  if (!cfg.server_addr) {
    showToast("Server address is required", "error");
    return;
  }
  if (!cfg.psk || cfg.psk.length !== 64) {
    showToast("PSK must be 64 hex characters", "error");
    return;
  }

  const badge = $("status-badge");
  badge.textContent = "Connecting...";
  badge.className = "badge connecting";
  $("btn-connect").disabled = true;

  try {
    await invoke("connect", { config: cfg });
    setConnected(true);
    showToast("Connected!", "success");
  } catch (e) {
    setConnected(false);
    showToast("Connection failed: " + e, "error");
    console.error("connect error:", e);
  }
  $("btn-connect").disabled = false;
});

$("btn-save-profile").addEventListener("click", async () => {
  const cfg = getConfig();
  if (!cfg.server_addr) {
    showToast("Fill server address first", "error");
    return;
  }
  const name = $("profile-name-input").value.trim() || cfg.name;
  if (!name) {
    showToast("Enter profile name", "error");
    return;
  }
  cfg.name = name;
  try {
    await invoke("save_profile", { profile: cfg });
    showToast("Profile saved", "success");
    await loadProfiles();
    $("profile-select").value = name;
  } catch (e) {
    showToast("Save error: " + e, "error");
    console.error("save error:", e);
  }
});

$("btn-delete-profile").addEventListener("click", async () => {
  const name = $("profile-select").value;
  if (!name) {
    showToast("Select a profile first", "error");
    return;
  }
  try {
    await invoke("delete_profile", { name });
    showToast("Profile deleted", "info");
    await loadProfiles();
  } catch (e) {
    showToast("Delete error: " + e, "error");
  }
});

$("profile-select").addEventListener("change", (e) => {
  applyProfile(e.target.value);
});

loadProfiles();
