"use strict";

const RING_LENGTH = 2 * Math.PI * 42;
const $ = (id) => document.getElementById(id);
let state = null;
let alertFilter = "ALL";
let refreshMs = 2000;

// ---------- helpers ----------

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function pill(text) {
  return `<span class="pill ${esc(String(text).replace(/\s+/g, "-"))}">${esc(text)}</span>`;
}

function fmtBytes(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
  return `${bytes.toFixed(i >= 3 ? 1 : 0)} ${units[i]}`;
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const time = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  return d.toDateString() === new Date().toDateString() ? time : `${d.toLocaleDateString([], { month: "short", day: "numeric" })} ${time}`;
}

function fmtAgo(ts) {
  if (!ts) return "–";
  const s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

function fmtDuration(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

function levelColor(value, threshold) {
  if (value >= threshold) return cssVar("--danger");
  if (value >= threshold * 0.75) return cssVar("--warn");
  return cssVar("--ok");
}

function summarize(details) {
  if (!details) return "";
  const keys = ["path", "old_path", "name", "pid", "source", "user", "users", "attempts", "service", "value", "reason", "detail", "error"];
  return keys
    .filter((k) => details[k] !== undefined && details[k] !== "" && details[k] !== null)
    .map((k) => `${k}=${Array.isArray(details[k]) ? details[k].join(",") : details[k]}`)
    .join("  ");
}

function toast(message) {
  const el = $("toast");
  el.textContent = message;
  el.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove("show"), 2600);
}

// ---------- canvas setup ----------

function setupCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const { width, height } = canvas.getBoundingClientRect();
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return { ctx, width, height };
}

// ---------- gauges ----------

function setRing(id, percent, threshold) {
  const ring = $(`ring-${id}`);
  const value = Math.max(0, Math.min(100, percent));
  ring.style.strokeDashoffset = RING_LENGTH * (1 - value / 100);
  ring.style.stroke = levelColor(value, threshold);
  $(`ring-${id}-text`).textContent = `${Math.round(value)}%`;
}

function renderResources(res) {
  if (!res) return;
  const t = res.thresholds;
  setRing("cpu", res.cpu_percent, t.cpu);
  setRing("mem", res.memory.percent, t.memory);
  setRing("disk", res.disk_percent, t.disk);

  const load = res.load_average ? ` · load ${res.load_average.join(" ")}` : "";
  $("cpu-sub").textContent = `${res.cpu_count} logical cores${load}`;
  $("cores").innerHTML = res.per_cpu
    .map((v) => `<span title="${v.toFixed(0)}%"><i style="height:${Math.max(2, v)}%"></i></span>`)
    .join("");
  $("mem-sub").textContent = `${fmtBytes(res.memory.used)} of ${fmtBytes(res.memory.total)}`;
  $("swap-sub").textContent = `Swap ${res.swap.percent.toFixed(0)}% · ${fmtBytes(res.memory.available)} available`;
  const disk = res.disks[0];
  $("disk-sub").textContent = disk ? `${fmtBytes(disk.used)} of ${fmtBytes(disk.total)} (${disk.path})` : "No disk";
  $("net-sub").textContent = `Net ↑ ${fmtBytes(res.net.bytes_sent)} ↓ ${fmtBytes(res.net.bytes_recv)}`;
  $("host").textContent = `${res.hostname} · up ${fmtDuration(res.uptime_seconds)}`;
}

function renderProcessSummary(proc) {
  if (!proc) return;
  $("proc-count").textContent = proc.total;
  const colors = { running: "--ok", sleeping: "--chart-cpu", idle: "--info", "disk-sleep": "--warn", zombie: "--danger", stopped: "--chart-mem" };
  const entries = Object.entries(proc.statuses).sort((a, b) => b[1] - a[1]);
  $("proc-states").innerHTML = entries
    .map(([s, n]) => `<span title="${esc(s)}: ${n}" style="width:${(n / proc.total) * 100}%;background:${cssVar(colors[s] || "--muted")}"></span>`)
    .join("");
  $("proc-legend").textContent = entries.map(([s, n]) => `${s} ${n}`).join(" · ") + (proc.zombies ? ` · ⚠ ${proc.zombies} zombie` : "");
}

// ---------- charts ----------

function drawHistory(history) {
  const { ctx, width, height } = setupCanvas($("history-chart"));
  const pad = { l: 34, r: 8, t: 8, b: 22 };
  const w = width - pad.l - pad.r, h = height - pad.t - pad.b;
  const grid = cssVar("--grid"), muted = cssVar("--muted");

  // Scale the y-axis to the data so an idle system (CPU < 1%) is still readable.
  const peak = Math.max(0, ...history.flatMap((p) => [p.cpu, p.memory, p.disk]));
  const yMax = [10, 20, 25, 50, 75, 100].find((step) => peak * 1.15 <= step) ?? 100;

  const latest = history[history.length - 1];
  for (const key of ["cpu", "memory", "disk"]) {
    $(`lg-${key}`).textContent = latest ? `${latest[key].toFixed(1)}%` : "";
  }

  ctx.font = "11px system-ui, sans-serif";
  ctx.fillStyle = muted;
  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  for (const f of [0, 0.25, 0.5, 0.75, 1]) {
    const y = pad.t + h - f * h;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + w, y); ctx.stroke();
    ctx.textAlign = "right"; ctx.textBaseline = "middle";
    ctx.fillText(`${+(f * yMax).toFixed(1)}%`, pad.l - 6, y);
  }
  if (history.length < 2) return;

  const t0 = history[0].t, t1 = history[history.length - 1].t, span = Math.max(1, t1 - t0);
  const x = (t) => pad.l + ((t - t0) / span) * w;
  const y = (v) => pad.t + h - (Math.min(yMax, v) / yMax) * h;

  ctx.textBaseline = "top";
  ctx.textAlign = "left"; ctx.fillText(`-${fmtDuration(span).replace("0m", `${Math.round(span)}s`)}`, pad.l, pad.t + h + 6);
  ctx.textAlign = "right"; ctx.fillText("now", pad.l + w, pad.t + h + 6);

  const series = [["disk", "--chart-disk"], ["memory", "--chart-mem"], ["cpu", "--chart-cpu"]];
  for (const [key, colorVar] of series) {
    const color = cssVar(colorVar);
    ctx.beginPath();
    history.forEach((p, i) => (i ? ctx.lineTo(x(p.t), y(p[key])) : ctx.moveTo(x(p.t), y(p[key]))));
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round";
    ctx.stroke();
    if (key === "cpu") {
      ctx.lineTo(x(t1), pad.t + h); ctx.lineTo(x(t0), pad.t + h); ctx.closePath();
      const gradient = ctx.createLinearGradient(0, pad.t, 0, pad.t + h);
      gradient.addColorStop(0, color + "55"); gradient.addColorStop(1, color + "00");
      ctx.fillStyle = gradient; ctx.fill();
    }
  }
}

function drawTimeline(buckets) {
  const { ctx, width, height } = setupCanvas($("timeline-chart"));
  const pad = { l: 24, r: 4, t: 6, b: 18 };
  const w = width - pad.l - pad.r, h = height - pad.t - pad.b;
  const max = Math.max(1, ...buckets.map((b) => b.LOW + b.MEDIUM + b.HIGH));
  const slot = w / buckets.length, barW = Math.max(2, slot * 0.7);
  const colors = { LOW: cssVar("--low"), MEDIUM: cssVar("--warn"), HIGH: cssVar("--danger") };

  ctx.font = "10px system-ui, sans-serif";
  ctx.fillStyle = cssVar("--muted");
  ctx.textAlign = "right"; ctx.textBaseline = "middle";
  ctx.fillText(max, pad.l - 5, pad.t + 4);
  ctx.fillText("0", pad.l - 5, pad.t + h);
  ctx.strokeStyle = cssVar("--grid");
  ctx.beginPath(); ctx.moveTo(pad.l, pad.t + h + 0.5); ctx.lineTo(pad.l + w, pad.t + h + 0.5); ctx.stroke();

  buckets.forEach((b, i) => {
    let base = pad.t + h;
    const bx = pad.l + i * slot + (slot - barW) / 2;
    for (const sev of ["LOW", "MEDIUM", "HIGH"]) {
      const bh = (b[sev] / max) * h;
      if (bh <= 0) continue;
      ctx.fillStyle = colors[sev];
      ctx.fillRect(bx, base - bh, barW, bh);
      base -= bh;
    }
    if (i % 6 === 0 || i === buckets.length - 1) {
      ctx.fillStyle = cssVar("--muted"); ctx.textAlign = "center"; ctx.textBaseline = "top";
      const label = i === buckets.length - 1 ? "now" : new Date(b.hour * 1000).getHours().toString().padStart(2, "0") + ":00";
      ctx.fillText(label, bx + barW / 2, pad.t + h + 5);
    }
  });
}

// ---------- panels ----------

const MODULES = [
  ["process", "Process Monitor", '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 15l3-4 3 3 4-6"/>'],
  ["file", "File Integrity", '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M9 15l2 2 4-4"/>'],
  ["login", "Login Monitor", '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'],
  ["resource", "Resource Monitor", '<path d="M3 12h4l3-8 4 16 3-8h4"/>'],
];

function moduleSummary(name, m) {
  const s = m.snapshot;
  if (m.error) return m.error;
  if (!s) return "Starting…";
  switch (name) {
    case "process": return `${s.total} processes · ${s.flagged.length} flagged`;
    case "file": return `${s.total_files} files · scanned ${fmtAgo(s.last_scan)}`;
    case "login": return s.status !== "OK" ? s.message : `${s.failed_in_window}/${s.max_failed_attempts} failed in ${Math.round(s.window_seconds / 60)} min`;
    case "resource": return `CPU ${s.cpu_percent.toFixed(0)}% · RAM ${s.memory.percent.toFixed(0)}% · Disk ${s.disk_percent.toFixed(0)}%`;
  }
  return "";
}

function renderModules(modules) {
  $("modules").innerHTML = MODULES.map(([name, label, icon]) => {
    const m = modules[name];
    const status = m ? m.status : "DISABLED";
    const summary = m ? moduleSummary(name, m) : "Disabled in config.json";
    return `<li>
      <div class="module-icon"><svg viewBox="0 0 24 24">${icon}</svg></div>
      <div class="module-text"><strong>${label}</strong><span title="${esc(summary)}">${esc(summary)}</span></div>
      ${pill(status)}
    </li>`;
  }).join("");
}

function renderAlerts(alerts) {
  const rows = alerts.filter((a) => alertFilter === "ALL" || a.severity === alertFilter);
  $("alerts").innerHTML = rows.length
    ? rows.map((a) => `<tr>
        <td class="num">${esc(fmtTime(a.timestamp))}</td>
        <td>${pill(a.severity)}</td>
        <td>${esc(a.module)}</td>
        <td>${esc(a.title)}</td>
        <td class="details" title="${esc(summarize(a.details))}">${esc(summarize(a.details))}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="empty">No ${alertFilter === "ALL" ? "" : alertFilter.toLowerCase() + " "}alerts. System looks clean.</td></tr>`;
}

function renderProcesses(proc) {
  if (!proc) return;
  $("proc-thresholds").textContent = `${proc.block_heavy ? "Alert + block" : "Alert"} at CPU ≥ ${proc.cpu_threshold}% (of one core) or memory ≥ ${proc.memory_threshold}%`;
  const maxCpu = Math.max(100, ...proc.top.map((p) => p.cpu_percent));
  $("processes").innerHTML = proc.top.map((p) => `<tr class="${p.flags.length ? "flagged" : ""}" title="${esc(p.flags.join("; "))}">
      <td class="num">${p.pid}</td>
      <td><code>${esc(p.name)}</code></td>
      <td>${esc(p.user)}</td>
      <td><div class="cpu-cell"><div class="bar"><i class="${p.cpu_percent >= proc.cpu_threshold ? "hot" : ""}" style="width:${(p.cpu_percent / maxCpu) * 100}%"></i></div><span>${p.cpu_percent.toFixed(1)}%</span></div></td>
      <td class="num">${p.memory_percent.toFixed(1)}%</td>
      <td>${p.flags.length ? pill(p.state) : `<span class="muted small">${esc(p.status)}</span>`}</td>
    </tr>`).join("");
}

function renderAuth(auth) {
  if (!auth) return;
  const msg = $("auth-message");
  msg.textContent = auth.message || "";
  msg.classList.toggle("hidden", !auth.message);

  const limit = auth.max_failed_attempts;
  $("auth-window").textContent = `${auth.failed_in_window} / ${limit}`;
  const meter = $("auth-meter");
  meter.style.width = `${Math.min(100, (auth.failed_in_window / (limit + 1)) * 100)}%`;
  meter.style.background = auth.failed_in_window > limit ? cssVar("--danger") : auth.failed_in_window ? cssVar("--warn") : cssVar("--ok");
  $("auth-failed").textContent = auth.failed_total;
  $("auth-success").textContent = auth.success_total;
  $("auth-sudo").textContent = auth.sudo_total;

  $("auth-sources").innerHTML = auth.top_sources.length
    ? auth.top_sources.map(([src, n]) => `<li><code>${esc(src)}</code><strong>${n}</strong></li>`).join("")
    : `<li class="muted">No failures in the last ${Math.round(auth.window_seconds / 60)} minutes</li>`;

  const kinds = { failure: "HIGH", success: "SAFE", sudo_command: "NOTICE", user_created: "MEDIUM", privilege_grant: "HIGH", password_changed: "LOW" };
  const labels = { failure: "FAILED", success: "LOGIN", sudo_command: "SUDO", user_created: "NEW USER", privilege_grant: "ADMIN", password_changed: "PASSWD" };
  $("auth-recent").innerHTML = auth.recent.length
    ? auth.recent.map((r) => `<li>
        <span class="when">${esc(fmtTime(r.timestamp).slice(-8))}</span>
        <span class="what">${esc(r.service)} · ${esc(r.user || "?")}<small>${esc(r.detail)} · from ${esc(r.source)}</small></span>
        <span class="pill ${kinds[r.kind] || ""}">${labels[r.kind] || esc(r.kind)}</span>
      </li>`).join("")
    : `<li class="empty">No authentication events yet</li>`;
}

function renderFiles(fim) {
  if (!fim) return;
  $("fim-files").textContent = fim.total_files;
  $("fim-scan").textContent = `${(fim.scan_seconds * 1000).toFixed(0)} ms`;
  $("fim-last").textContent = fmtAgo(fim.last_scan);
  $("fim-roots").innerHTML = fim.roots.map((r) => `<li>
      <code title="${esc(r.path)}">${esc(r.path)}</code>
      <span>${r.exists ? `${r.files} file${r.files === 1 ? "" : "s"}` : '<span class="pill MISSING">MISSING</span>'}</span>
    </li>`).join("") || `<li class="muted">No watch paths configured</li>`;
  $("fim-changes").innerHTML = fim.recent_changes.length
    ? fim.recent_changes.map((c) => `<li>
        <span class="when">${esc(fmtTime(c.timestamp).slice(-8))}</span>
        <span class="what">${esc(c.title)}<small title="${esc(c.path)}">${esc(c.path)}${c.old_mode ? ` · ${esc(c.old_mode)} → ${esc(c.new_mode)}` : ""}${c.new_hash ? ` · ${esc(c.old_hash)}… → ${esc(c.new_hash)}…` : ""}</small></span>
        ${pill(c.severity)}
      </li>`).join("")
    : `<li class="empty">No changes detected since start</li>`;
  $("fim-errors").textContent = fim.error_count ? `${fim.error_count} path(s) could not be read: ${fim.errors.slice(0, 3).join("; ")}` : "";
}

function renderEvents(events) {
  $("events").innerHTML = events.length
    ? events.map((e) => `<li>
        <span class="when">${esc(fmtTime(e.timestamp).slice(-8))}</span>
        <span class="what">${esc(e.title)}<small title="${esc(summarize(e.details))}">${esc(e.module)} · ${esc(summarize(e.details))}</small></span>
        ${e.severity === "INFO" ? '<span class="pill">INFO</span>' : pill(e.severity)}
      </li>`).join("")
    : `<li class="empty">No events recorded yet</li>`;
}

// ---------- approvals (allow / block & rewind) ----------

const approval = { id: null, deadline: 0, total: 1, notified: new Set() };
const DETAIL_LABELS = { path: "File", old_path: "Renamed from", pid: "PID", name: "Process", exe: "Executable", old_mode: "Old mode", new_mode: "New mode", old_size: "Old size", new_size: "New size", paused: "Paused" };

function renderApprovals(info) {
  const badge = $("protection");
  if (!info || !info.enabled) {
    badge.className = "pill";
    badge.textContent = "PROTECTION OFF";
  } else {
    badge.className = "pill SAFE";
    badge.textContent = `PROTECTION ON${info.popup ? ` · ${info.popup} popup` : ""}`;
  }
  const pending = info?.pending || [];
  const modal = $("approval");
  if (!pending.length) {
    modal.classList.add("hidden");
    approval.id = null;
    return;
  }
  const req = pending[0];
  if (req.id !== approval.id) {
    approval.id = req.id;
    approval.total = Math.max(1, req.deadline - req.created);
    $("approval-module").textContent = `${req.module === "file" ? "File integrity" : "Process monitor"} · confirmation needed`;
    $("approval-title").textContent = req.title;
    $("approval-summary").textContent = req.summary;
    $("approval-details").innerHTML = Object.entries(req.details)
      .filter(([k, v]) => DETAIL_LABELS[k] && v !== null && v !== "" && !(k === "path" && v === req.summary))
      .map(([k, v]) => `<dt>${DETAIL_LABELS[k]}</dt><dd>${esc(v)}</dd>`)
      .join("");
    $("approval-allow").disabled = $("approval-deny").disabled = false;
    notifyDesktop(req);
  }
  approval.deadline = Date.now() + req.seconds_left * 1000;
  approval.onTimeout = info.on_timeout;
  $("approval-more").textContent = pending.length > 1 ? `${pending.length - 1} more waiting after this one` : "";
  modal.classList.remove("hidden");
  tickCountdown();
}

function tickCountdown() {
  if (!approval.id) return;
  const left = Math.max(0, (approval.deadline - Date.now()) / 1000);
  $("approval-bar").style.width = `${(left / approval.total) * 100}%`;
  const action = approval.onTimeout === "allow" ? "allowed" : "blocked and rewound";
  $("approval-timeout").textContent = `No answer in ${Math.ceil(left)}s → it will be ${action} automatically.`;
}
setInterval(tickCountdown, 250);

async function decide(decision) {
  if (!approval.id) return;
  $("approval-allow").disabled = $("approval-deny").disabled = true;
  try {
    const response = await fetch(`/api/approvals/${approval.id}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CyberShield": "1" },
      body: JSON.stringify({ decision }),
    });
    const result = await response.json();
    toast(result.result || result.error || "Done");
  } catch {
    toast("Could not reach CyberShield");
  }
  approval.id = null;
  refreshNow();
}

function notifyDesktop(req) {
  if (approval.notified.has(req.id) || !("Notification" in window) || Notification.permission !== "granted") return;
  approval.notified.add(req.id);
  const n = new Notification(`CyberShield: ${req.title}`, { body: `${req.summary}\nOpen the dashboard to allow or rewind.`, requireInteraction: true });
  n.onclick = () => { window.focus(); n.close(); };
}

// ---------- blocked processes (already stopped, just tell the user) ----------

const blocked = { lastId: null, items: [] };

function renderBlocked(alerts) {
  const newest = Math.max(0, ...alerts.map((a) => a.id));
  if (blocked.lastId === null) { blocked.lastId = newest; return; } // don't replay old blocks on page load
  const fresh = alerts.filter((a) => a.id > blocked.lastId && a.title === "Potentially harmful process blocked").reverse();
  blocked.lastId = Math.max(blocked.lastId, newest);
  if (!fresh.length) return;
  blocked.items.push(...fresh);
  $("blocked-list").innerHTML = blocked.items.map((a) => `<li>
      <strong><code>${esc(a.details.name)}</code> · PID ${esc(a.details.pid)}</strong>
      <small>${esc(fmtTime(a.timestamp))} · ${esc(a.details.reason)}</small>
    </li>`).join("");
  $("blocked").classList.remove("hidden");
  if ("Notification" in window && Notification.permission === "granted") {
    const names = fresh.map((a) => `${a.details.name} (PID ${a.details.pid})`).join(", ");
    new Notification("CyberShield: potentially harmful process blocked", { body: `${names} used too much CPU or memory and was stopped.` });
  }
}

$("blocked-ok").addEventListener("click", () => {
  $("blocked").classList.add("hidden");
  blocked.items = [];
});

function setupNotifyButton() {
  const button = $("notify");
  if (!("Notification" in window) || Notification.permission !== "default") return;
  button.classList.remove("hidden");
  button.addEventListener("click", async () => {
    await Notification.requestPermission();
    button.classList.add("hidden");
  });
}

function render() {
  if (!state) return;
  renderApprovals(state.approvals);
  renderBlocked(state.alerts);
  const overall = $("overall");
  overall.dataset.level = state.overall;
  $("overall-text").textContent = state.overall === "SECURE" ? "SECURE" : `SECURITY ${state.overall}`;
  $("updated").textContent = `Updated ${new Date(state.generated_at * 1000).toLocaleTimeString()}`;
  $("uptime").textContent = `Monitoring for ${fmtDuration(state.generated_at - state.started_at)}`;

  const m = state.modules;
  renderResources(m.resource?.snapshot);
  renderProcessSummary(m.process?.snapshot);
  renderModules(m);
  renderAlerts(state.alerts);
  renderProcesses(m.process?.snapshot);
  renderAuth(m.login?.snapshot);
  renderFiles(m.file?.snapshot);
  renderEvents(state.events);
  for (const sev of ["HIGH", "MEDIUM", "LOW"]) $(`count-${sev}`).textContent = state.severity_counts_24h[sev];
  drawHistory(state.history);
  drawTimeline(state.timeline_24h);
}

// ---------- data loop ----------

let refreshTimer = null;

function refreshNow() {
  clearTimeout(refreshTimer);
  refresh();
}

async function refresh() {
  try {
    const response = await fetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(response.statusText);
    state = await response.json();
    refreshMs = (state.refresh_seconds || 2) * 1000;
    render();
  } catch (err) {
    $("overall").dataset.level = "OFFLINE";
    $("overall-text").textContent = "DISCONNECTED";
    $("updated").textContent = "Cannot reach CyberShield. Is main.py running?";
  } finally {
    // Poll faster while a decision is waiting, so answers from the native popup close the dialog quickly.
    refreshTimer = setTimeout(refresh, approval.id ? 1000 : refreshMs);
  }
}

$("approval-allow").addEventListener("click", () => decide("allow"));
$("approval-deny").addEventListener("click", () => decide("rewind"));
setupNotifyButton();

$("alert-filter").addEventListener("click", (e) => {
  const chip = e.target.closest(".chip");
  if (!chip) return;
  alertFilter = chip.dataset.sev;
  document.querySelectorAll("#alert-filter .chip").forEach((c) => c.classList.toggle("active", c === chip));
  if (state) renderAlerts(state.alerts);
});

$("rebaseline").addEventListener("click", async () => {
  if (!confirm("Accept the current contents of all watched files as trusted?\nFuture changes will be compared against this new baseline.")) return;
  try {
    const response = await fetch("/api/files/rebaseline", { method: "POST", headers: { "X-CyberShield": "1" } });
    toast(response.ok ? "File baseline updated" : "Could not update baseline");
  } catch {
    toast("Could not reach CyberShield");
  }
});

window.addEventListener("resize", () => {
  if (state) { drawHistory(state.history); drawTimeline(state.timeline_24h); }
});

refresh();
