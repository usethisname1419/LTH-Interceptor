const aiFeed = document.getElementById("aiFeed");
const workBody = document.getElementById("workBody");
const promptEl = document.getElementById("prompt");
const sendBtn = document.getElementById("sendBtn");
const stopBtn = document.getElementById("stopBtn");
const stopBtn2 = document.getElementById("stopBtn2");
const statusPill = document.getElementById("statusPill");
const scopeLine = document.getElementById("scopeLine");
const statsEl = document.getElementById("stats");
const playbooksEl = document.getElementById("playbooks");
const diagLines = document.getElementById("diagLines");
const activityLine = document.getElementById("activityLine");
const modelName = document.getElementById("modelName");
const slot1 = document.getElementById("slot1");
const slot2 = document.getElementById("slot2");

let activeTab = "findings";
let busy = false;
let models = { 1: "qwen2.5-coder:14b", 2: "qwen2.5-coder:32b" };
let modelSlot = 2;
const FINDING_SEVS = ["info", "low", "medium", "high", "critical"];
/** Empty set = show all; otherwise only listed severities. */
let findingSevFilter = new Set(FINDING_SEVS);

const SPIN = ["|", "/", "-", "\\"];
let spinIdx = 0;
let activity = {
  tool: null,
  args: "",
  started: 0,
  elapsed: 0,
  command: "",
  timer: null,
  el: null,
};

function appendAi(role, text, cls, reasoning) {
  if (!text && !reasoning) return;
  const div = document.createElement("div");
  div.className = `msg ${cls || role}`;
  const label = document.createElement("div");
  label.className = "label";
  label.textContent = role;
  div.appendChild(label);
  if (reasoning) {
    const details = document.createElement("details");
    details.className = "reasoning";
    const summary = document.createElement("summary");
    summary.textContent = "Reasoning";
    const body = document.createElement("pre");
    body.className = "reasoning-body";
    body.textContent = reasoning;
    details.appendChild(summary);
    details.appendChild(body);
    div.appendChild(details);
  }
  if (text) {
    const content = document.createElement("div");
    content.className = "msg-body";
    content.textContent = text;
    div.appendChild(content);
  }
  aiFeed.appendChild(div);
  aiFeed.scrollTop = aiFeed.scrollHeight;
  return div;
}

function formatArgs(args) {
  if (!args) return "";
  try {
    const s = typeof args === "string" ? args : JSON.stringify(args);
    return s.length > 80 ? s.slice(0, 80) + "…" : s;
  } catch {
    return "";
  }
}

function clearActivityTimer() {
  if (activity.timer) {
    clearInterval(activity.timer);
    activity.timer = null;
  }
}

function renderActivity() {
  const frame = SPIN[spinIdx % SPIN.length];
  if (!activity.tool) {
    activityLine.className = "activity-line idle";
    activityLine.innerHTML = `<span class="spin idle">·</span> idle`;
    statusPill.textContent = busy ? "busy" : "idle";
    return;
  }
  const sec = activity.elapsed || ((Date.now() - activity.started) / 1000);
  const secTxt = sec.toFixed(1) + "s";
  const detail = activity.command || activity.args || "";
  activityLine.className = "activity-line";
  activityLine.innerHTML =
    `<span class="spin">${frame}</span> ${escapeHtml(activity.tool)} ` +
    `<span style="color:var(--muted)">${secTxt}</span>` +
    (detail ? ` · ${escapeHtml(detail)}` : "");
  statusPill.textContent = `${frame} ${secTxt}`;
  if (activity.el) {
    const body = activity.el.querySelector(".spin-body");
    if (body) {
      body.textContent = `${frame} ${activity.tool} running… ${secTxt}` +
        (activity.args ? `\n${activity.args}` : "");
    }
  }
}

function tickActivity() {
  spinIdx = (spinIdx + 1) % SPIN.length;
  if (activity.tool && activity.started && !activity.fromServer) {
    activity.elapsed = (Date.now() - activity.started) / 1000;
  }
  renderActivity();
}

function startToolActivity(tool, args) {
  clearActivityTimer();
  activity.tool = tool || "tool";
  activity.args = formatArgs(args);
  activity.command = "";
  activity.started = Date.now();
  activity.elapsed = 0;
  activity.fromServer = false;
  activity.el = appendAi("tool", "", "tool tool-running");
  if (activity.el) {
    const label = activity.el.querySelector(".label");
    if (label) label.textContent = "tool";
    // replace text node with spin body
    while (activity.el.childNodes.length > 1) activity.el.removeChild(activity.el.lastChild);
    const body = document.createElement("div");
    body.className = "spin-body";
    activity.el.appendChild(body);
  }
  activity.timer = setInterval(tickActivity, 180);
  tickActivity();
}

function updateToolProgress(msg) {
  if (!activity.tool) return;
  if (typeof msg.elapsed_sec === "number") {
    activity.elapsed = msg.elapsed_sec;
    activity.fromServer = true;
  }
  if (msg.command) activity.command = msg.command;
  renderActivity();
}

function finishToolActivity(preview) {
  clearActivityTimer();
  const tool = activity.tool;
  const elapsed = activity.elapsed || ((Date.now() - activity.started) / 1000);
  if (activity.el) {
    activity.el.classList.remove("tool-running");
    const body = activity.el.querySelector(".spin-body");
    const header = `* ${tool}  (${elapsed.toFixed(1)}s)`;
    if (body) {
      body.textContent = preview
        ? `${header}\n${preview}`
        : `${header} done`;
    }
  } else if (preview) {
    appendAi("tool", preview, "tool");
  }
  activity.tool = null;
  activity.el = null;
  activity.command = "";
  activity.fromServer = false;
  if (busy) {
    startBusySpinner("thinking");
  } else {
    renderActivity();
  }
}


function startBusySpinner(label) {
  // Keep spinning during thinking / working — not only during tools
  clearActivityTimer();
  activity.tool = label || "thinking";
  activity.args = "";
  activity.command = "";
  activity.started = Date.now();
  activity.elapsed = 0;
  activity.fromServer = false;
  activity.el = null;
  activity.timer = setInterval(tickActivity, 180);
  tickActivity();
}

function setBusy(v) {
  busy = v;
  statusPill.classList.toggle("busy", v);
  sendBtn.disabled = v;
  stopBtn.disabled = !v;
  stopBtn2.disabled = !v;
  playbooksEl.querySelectorAll("button").forEach((b) => {
    b.disabled = v;
  });
  const chartBtn = document.getElementById("chartBtn");
  // Chart can open anytime; generation is separate
  if (!v) {
    clearActivityTimer();
    activity.tool = null;
    activity.el = null;
    renderActivity();
    statusPill.textContent = "idle";
  } else if (!activity.timer || !activity.tool) {
    startBusySpinner("thinking");
  }
}


function setModelUI(slot, name) {
  modelSlot = slot;
  slot1.classList.toggle("active", slot === 1);
  slot2.classList.toggle("active", slot === 2);
  modelName.textContent = name || models[slot] || "";
}

function renderDiag(diag) {
  if (!diag || !diag.lines) {
    diagLines.innerHTML = `<div class="fail">No diagnostics yet</div>`;
    statusPill.classList.remove("ok", "bad");
    return;
  }
  diagLines.innerHTML = diag.lines
    .map((l) => {
      const cls = l.startsWith("[OK]") ? "ok" : l.startsWith("[FAIL]") ? "fail" : "";
      return `<div class="${cls}">${escapeHtml(l)}</div>`;
    })
    .join("");
  statusPill.classList.toggle("ok", !!diag.ok && !busy);
  statusPill.classList.toggle("bad", !diag.ok);
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  return res.json();
}

async function refreshHealth() {
  const h = await api("/api/health");
  const domains = (h.scope?.domains || []).join(", ") || "(none)";
  scopeLine.textContent = `${h.runtime} · scope ${domains}`;
  statsEl.textContent = `findings:${h.stats.open_findings}  todos:${h.stats.open_todos}  hi/crit:${h.stats.high_or_critical}`;
  models = h.models || models;
  setModelUI(h.model_slot || 2, h.model);
  setBusy(!!h.busy);
  if (h.diag_ok === false) statusPill.classList.add("bad");
  if (h.diag_ok === true && !h.busy) statusPill.classList.add("ok");
}

async function loadDiagnostics(refresh = false) {
  const q = refresh ? "?refresh=true" : "";
  const diag = await api(`/api/diagnostics${q}`);
  renderDiag(diag);
  if (diag.model_slot) setModelUI(diag.model_slot, diag.model);
  return diag;
}

async function loadPlaybooks() {
  const list = await api("/api/playbooks");
  playbooksEl.innerHTML = "";
  (list || []).forEach((p) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "pb";
    b.textContent = p.title;
    b.title = p.description;
    b.onclick = () => runPlaybook(p.name);
    playbooksEl.appendChild(b);
  });
  setBusy(busy);
}

async function setModel(slot) {
  const res = await api("/api/model", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slot }),
  });
  if (res.ok) {
    setModelUI(res.model_slot, res.model);
    appendAi("system", `Model slot ${res.model_slot}: ${res.model}`, "status");
  }
}

async function runPlaybook(name) {
  if (busy) return;
  setBusy(true);
  appendAi("system", `Queued playbook: ${name}`, "status");
  await api("/api/playbooks/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
}

async function sendPrompt() {
  const text = promptEl.value.trim();
  if (!text || busy) return;
  promptEl.value = "";
  setBusy(true);
  appendAi("you", text, "user");
  await api("/api/prompt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
}

async function stopJob() {
  appendAi("system", "Stop requested…", "status");
  await api("/api/stop", { method: "POST" });
}

async function refreshWork() {
  const filterBar = document.getElementById("findingFilters");
  if (filterBar) filterBar.classList.toggle("hidden", activeTab !== "findings");

  if (activeTab === "findings") {
    const rows = await api("/api/findings");
    const filtered = rows.filter((f) => {
      const sev = String(f.severity || "info").toLowerCase();
      return findingSevFilter.has(sev);
    });
    workBody.innerHTML = filtered.length
      ? filtered
          .map(
            (f) => `<div class="card" data-finding-id="${f.id}">
          <div class="sev ${f.severity}">[${f.severity}] ${escapeHtml(f.kind)}</div>
          <div>${escapeHtml(f.title)}</div>
          <div class="meta">${escapeHtml(f.url || f.host || "")}</div>
        </div>`
          )
          .join("")
      : `<div class="msg status">${
          rows.length
            ? "No findings match the selected severities."
            : "No findings yet. Run Recon or Surface Map."
        }</div>`;
    workBody.querySelectorAll("[data-finding-id]").forEach((card) => {
      card.onclick = () => openFinding(Number(card.dataset.findingId));
    });
    syncFindingFilterButtons();
  } else if (activeTab === "todos") {
    const rows = await api("/api/todos");
    const open = rows.filter((t) => t.status === "pending" || t.status === "doing");
    const done = rows.filter((t) => t.status === "done").slice(0, 12);
    const renderTodo = (t) => `<div class="card todo-row">
          <select data-id="${t.id}">
            <option value="pending" ${t.status === "pending" ? "selected" : ""}>pending</option>
            <option value="doing" ${t.status === "doing" ? "selected" : ""}>doing</option>
            <option value="done" ${t.status === "done" ? "selected" : ""}>done</option>
          </select>
          <div>
            <div>${escapeHtml(t.title)}</div>
            <div class="meta">p${t.priority}${t.playbook ? " · " + t.playbook : ""}${t.detail ? " · " + escapeHtml(String(t.detail).slice(0, 80)) : ""}</div>
          </div>
        </div>`;
    workBody.innerHTML = open.length || done.length
      ? `${open.map(renderTodo).join("")}${
          done.length
            ? `<div class="msg status" style="margin:0.8rem 0 0.4rem">Recently done</div>${done.map(renderTodo).join("")}`
            : ""
        }`
      : `<div class="msg status">No todos yet.</div>`;
    workBody.querySelectorAll("select").forEach((sel) => {
      sel.onchange = async () => {
        await api(`/api/todos/${sel.dataset.id}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: sel.value }),
        });
        refreshHealth();
        refreshWork();
      };
    });
  } else if (activeTab === "notes") {
    const rows = await api("/api/notes");
    workBody.innerHTML = rows.length
      ? rows
          .map(
            (a) => `<div class="card">
          <div class="sev info">note</div>
          <div><strong>${escapeHtml(a.title)}</strong></div>
          <pre class="note-body">${escapeHtml(a.body)}</pre>
          <div class="meta">${escapeHtml(a.created_at || "")}</div>
        </div>`
          )
          .join("")
      : `<div class="msg status">No agent notes yet. The model writes these via save_note while testing.</div>`;
  } else if (activeTab === "analysis") {
    const rows = await api("/api/analysis");
    workBody.innerHTML = rows.length
      ? rows
          .map(
            (a) => `<div class="card">
          <div class="sev info">${escapeHtml(a.kind)}</div>
          <div><strong>${escapeHtml(a.title)}</strong></div>
          <pre style="white-space:pre-wrap;margin:0.4rem 0 0;color:#c9d6ce">${escapeHtml(a.body)}</pre>
        </div>`
          )
          .join("")
      : `<div class="msg status">No analysis notes yet.</div>`;
  } else if (activeTab === "runs") {
    const rows = await api("/api/playbook-runs");
    workBody.innerHTML = rows.length
      ? rows
          .map(
            (r) => `<div class="card">
          <div class="sev info">${escapeHtml(r.status)}</div>
          <div><strong>${escapeHtml(r.name)}</strong> #${r.id}</div>
          <div class="meta">${escapeHtml(r.summary || "")}</div>
        </div>`
          )
          .join("")
      : `<div class="msg status">No playbook runs yet.</div>`;
  }
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onmessage = (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (msg.type === "hello") {
      if (msg.diag) renderDiag(msg.diag);
      if (msg.model_slot) setModelUI(msg.model_slot, msg.model);
      refreshHealth();
      refreshWork();
      return;
    }
    if (msg.type === "status") {
      appendAi("status", msg.content || "", "status");
      if (!/stop/i.test(msg.content || "")) {
        setBusy(true);
        if (/thinking|working|generating/i.test(msg.content || "")) {
          startBusySpinner(/generating/i.test(msg.content) ? "chart" : "thinking");
        } else if (!activity.timer) {
          startBusySpinner("working");
        }
      }
    } else if (msg.type === "chat" || msg.type === "assistant") {
      appendAi(
        msg.role || msg.type,
        msg.content || "",
        msg.role || "assistant",
        msg.reasoning || ""
      );
    } else if (msg.type === "tool_start") {
      if (msg.skipped) {
        appendAi("tool", `* ${msg.tool} (skipped)`, "tool");
        if (busy) startBusySpinner("thinking");
      } else {
        startToolActivity(msg.tool, msg.args);
      }
      setBusy(true);
    } else if (msg.type === "tool_progress") {
      updateToolProgress(msg);
      setBusy(true);
    } else if (msg.type === "tool_result") {
      if (activity.tool && activity.el) {
        finishToolActivity(msg.preview || "");
      } else {
        appendAi("tool", msg.preview || "", "tool");
        if (busy) startBusySpinner("thinking");
      }
      refreshWork();
      refreshHealth();
    } else if (msg.type === "playbook_start") {
      appendAi(
        "playbook",
        `Starting ${msg.name} on ${((msg.hosts || []).join(", ")) || "scope"}`,
        "status"
      );
      setBusy(true);
      startBusySpinner(`playbook:${msg.name}`);
    } else if (msg.type === "playbook_done") {
      appendAi("playbook", msg.summary || "done", "assistant");
      refreshWork();
      refreshHealth();
    } else if (msg.type === "playbook_error") {
      appendAi("error", msg.error || "playbook failed", "tool");
    } else if (msg.type === "idle") {
      setBusy(false);
      refreshWork();
      refreshHealth();
    } else if (msg.type === "session") {
      if (msg.action === "cleared") {
        aiFeed.innerHTML = "";
        refreshWork();
        refreshHealth();
      } else if (msg.action === "resumed" && msg.messages) {
        aiFeed.innerHTML = "";
        msg.messages.forEach((m) => {
          appendAi(
            m.role || "assistant",
            m.content || "",
            m.role === "you" ? "user" : m.role || "assistant"
          );
        });
      }
      refreshSessionButtons();
    }
  };
  ws.onclose = () => setTimeout(connectWs, 1500);
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeTab = btn.dataset.tab;
    refreshWork();
  };
});

function syncFindingFilterButtons() {
  const bar = document.getElementById("findingFilters");
  if (!bar) return;
  const allOn = FINDING_SEVS.every((s) => findingSevFilter.has(s));
  bar.querySelectorAll(".sev-filter").forEach((btn) => {
    const sev = btn.dataset.sev;
    if (sev === "all") {
      btn.classList.toggle("active", allOn);
    } else {
      btn.classList.toggle("active", findingSevFilter.has(sev));
    }
  });
}

document.getElementById("findingFilters")?.querySelectorAll(".sev-filter").forEach((btn) => {
  btn.onclick = () => {
    const sev = btn.dataset.sev;
    if (sev === "all") {
      findingSevFilter = new Set(FINDING_SEVS);
    } else if (findingSevFilter.has(sev) && findingSevFilter.size > 1) {
      findingSevFilter.delete(sev);
    } else if (findingSevFilter.has(sev) && findingSevFilter.size === 1) {
      // keep at least one — or flip to all others off means show only this; toggling off last => all
      findingSevFilter = new Set(FINDING_SEVS);
    } else {
      // if currently all selected, clicking one alone focuses that severity
      const allOn = FINDING_SEVS.every((s) => findingSevFilter.has(s));
      if (allOn) {
        findingSevFilter = new Set([sev]);
      } else {
        findingSevFilter.add(sev);
      }
    }
    syncFindingFilterButtons();
    refreshWork();
  };
});

document.getElementById("clearMemBtn").onclick = async () => {
  await api("/api/memory/clear", { method: "POST" });
  appendAi("system", "Tool memory cleared — duplicate scans allowed again.", "status");
};

const findingModal = document.getElementById("findingModal");
const findingTitle = document.getElementById("findingTitle");
const findingBody = document.getElementById("findingBody");

async function openFinding(id) {
  const res = await api(`/api/findings/${id}`);
  if (!res.ok || !res.finding) {
    appendAi("system", res.error || "Finding not found", "tool");
    return;
  }
  const f = res.finding;
  findingTitle.textContent = f.title || `Finding #${id}`;
  const parts = [
    `id: ${f.id}`,
    `kind: ${f.kind}`,
    `severity: ${f.severity}`,
    `status: ${f.status}`,
    f.host ? `host: ${f.host}` : "",
    f.url ? `url: ${f.url}` : "",
    f.source_tool ? `source: ${f.source_tool}` : "",
    f.created_at ? `created: ${f.created_at}` : "",
    "",
    "detail:",
    f.detail || "(none)",
    "",
    "evidence:",
    f.evidence || "(none)",
  ];
  if (f.meta && Object.keys(f.meta).length) {
    parts.push("", "meta:", JSON.stringify(f.meta, null, 2));
  }
  findingBody.textContent = parts.filter((p, i, arr) => !(p === "" && arr[i - 1] === "")).join("\n");
  findingModal.classList.remove("hidden");
}

document.getElementById("findingClose").onclick = () => findingModal.classList.add("hidden");
findingModal.addEventListener("click", (e) => {
  if (e.target === findingModal) findingModal.classList.add("hidden");
});

document.getElementById("chartBtn").onclick = () => {
  window.open("/chart", "lth-chart", "noopener,noreferrer");
};

async function refreshSessionButtons() {
  try {
    const s = await api("/api/session");
    const resumeBtn = document.getElementById("resumeSessionBtn");
    if (resumeBtn) {
      resumeBtn.disabled = !s.exists;
      resumeBtn.title = s.exists
        ? `Resume saved session (${s.turns || 0} turns, ${s.saved_at || ""})`
        : "No saved session";
    }
    if (s.exists && s.saved_at) {
      // soft hint in scope line suffix handled elsewhere if needed
    }
  } catch {
    /* ignore */
  }
}

document.getElementById("saveSessionBtn").onclick = async () => {
  if (busy) {
    appendAi("system", "Stop the agent before saving.", "status");
    return;
  }
  const res = await api("/api/session/save", { method: "POST" });
  appendAi("system", res.message || res.error || "Save done", res.ok ? "status" : "tool");
  refreshSessionButtons();
};

document.getElementById("clearSessionBtn").onclick = async () => {
  if (busy) {
    appendAi("system", "Stop the agent before clearing.", "status");
    return;
  }
  if (!confirm("Clear EVERYTHING? Chat, findings, todos, analysis, and runs will be wiped. Saved session file is kept.")) {
    return;
  }
  const res = await api("/api/session/clear", { method: "POST" });
  if (res.ok) {
    aiFeed.innerHTML = "";
    appendAi("system", res.message || "Cleared everything.", "status");
    refreshWork();
    refreshHealth();
  } else {
    appendAi("system", res.error || "Clear failed", "tool");
  }
  refreshSessionButtons();
};

document.getElementById("resumeSessionBtn").onclick = async () => {
  if (busy) {
    appendAi("system", "Stop the agent before resume.", "status");
    return;
  }
  const res = await api("/api/session/resume", { method: "POST" });
  if (!res.ok) {
    appendAi("system", res.error || "Resume failed", "tool");
    return;
  }
  aiFeed.innerHTML = "";
  (res.messages || []).forEach((m) => {
    appendAi(m.role || "assistant", m.content || "", m.role === "you" ? "user" : m.role || "assistant");
  });
  appendAi("system", res.message || "Session resumed", "status");
  refreshSessionButtons();
};

document.getElementById("refreshWork").onclick = () => refreshWork();
document.getElementById("recheckBtn").onclick = async () => {
  diagLines.innerHTML = `<div>Rechecking…</div>`;
  await loadDiagnostics(true);
  await refreshHealth();
};
slot1.onclick = () => setModel(1);
slot2.onclick = () => setModel(2);
sendBtn.onclick = sendPrompt;
stopBtn.onclick = stopJob;
stopBtn2.onclick = stopJob;
promptEl.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    sendPrompt();
  }
});

const configModal = document.getElementById("configModal");
const configEditor = document.getElementById("configEditor");
const configErr = document.getElementById("configErr");
const configPath = document.getElementById("configPath");
let configSnapshot = "";

async function openConfig() {
  configErr.textContent = "";
  const res = await api("/api/config");
  if (!res.ok) {
    configErr.textContent = res.error || "Failed to load config";
  }
  configSnapshot = res.text || "";
  configEditor.value = configSnapshot;
  configPath.textContent = res.path || "config.yaml";
  configModal.classList.remove("hidden");
  configEditor.focus();
}

function closeConfig() {
  configModal.classList.add("hidden");
  configErr.textContent = "";
}

async function saveConfig(restart) {
  const text = configEditor.value;
  if (!text.trim()) {
    configErr.textContent = "Refusing blank config — restore or cancel.";
    return;
  }
  configErr.textContent = "";
  const res = await api("/api/config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text, restart: !!restart }),
  });
  if (!res.ok) {
    configErr.textContent = res.error || "Save failed";
    return;
  }
  appendAi("system", res.message || "Config saved", "status");
  if (res.restarting) {
    configErr.textContent = "Restarting server…";
    setTimeout(() => location.reload(), 1800);
    return;
  }
  closeConfig();
  await refreshHealth();
  await loadDiagnostics(true);
}

document.getElementById("configBtn").onclick = openConfig;
document.getElementById("configCancel").onclick = () => {
  configEditor.value = configSnapshot;
  closeConfig();
};
document.getElementById("configSave").onclick = () => saveConfig(false);
document.getElementById("configRestart").onclick = () => saveConfig(true);
configModal.addEventListener("click", (e) => {
  if (e.target === configModal) {
    configEditor.value = configSnapshot;
    closeConfig();
  }
});

loadPlaybooks();
loadDiagnostics(false).then(() => refreshHealth());
refreshWork();
refreshSessionButtons();
connectWs();
