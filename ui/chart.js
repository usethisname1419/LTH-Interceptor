const meta = document.getElementById("meta");
const notes = document.getElementById("notes");
const canvas = document.getElementById("canvas");
const empty = document.getElementById("empty");
const status = document.getElementById("status");
const refreshBtn = document.getElementById("refreshBtn");
const stopBtn = document.getElementById("stopBtn");

const SPIN = ["|", "/", "-", "\\"];
let spinIdx = 0;
let spinTimer = null;
let generating = false;
let lastChart = null;

function setStatus(text) {
  status.textContent = text || "";
}

function startSpin(label) {
  stopSpin();
  spinTimer = setInterval(() => {
    spinIdx = (spinIdx + 1) % SPIN.length;
    setStatus(`${SPIN[spinIdx]} ${label}`);
  }, 160);
}

function stopSpin() {
  if (spinTimer) clearInterval(spinTimer);
  spinTimer = null;
}

function setGenerating(on) {
  generating = on;
  refreshBtn.disabled = on;
  stopBtn.disabled = !on;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  return res.json();
}

function renderChart(data) {
  lastChart = data;
  const nodes = data.nodes || [];
  const edges = data.edges || [];
  const highlight = new Set(data.highlight || []);
  empty.classList.toggle("hidden", nodes.length > 0);

  const w = canvas.clientWidth || 1000;
  const h = canvas.clientHeight || 700;
  canvas.setAttribute("viewBox", `0 0 ${w} ${h}`);
  canvas.innerHTML = "";

  const byKind = { root: [], host: [], url: [], service: [], finding: [] };
  nodes.forEach((n) => {
    const k = byKind[n.kind] ? n.kind : "finding";
    byKind[k].push(n);
  });
  const positions = {};
  const rings = [
    { kind: "root", r: Math.min(w, h) * 0.08 },
    { kind: "host", r: Math.min(w, h) * 0.22 },
    { kind: "url", r: Math.min(w, h) * 0.36 },
    { kind: "service", r: Math.min(w, h) * 0.44 },
    { kind: "finding", r: Math.min(w, h) * 0.48 },
  ];
  const cx = w / 2;
  const cy = h / 2;
  rings.forEach((ring) => {
    const list = byKind[ring.kind] || [];
    list.forEach((n, i) => {
      const ang = (Math.PI * 2 * i) / Math.max(list.length, 1) - Math.PI / 2;
      positions[n.id] = {
        x: cx + Math.cos(ang) * ring.r,
        y: cy + Math.sin(ang) * ring.r,
      };
    });
  });

  edges.forEach((e) => {
    const a = positions[e.from];
    const b = positions[e.to];
    if (!a || !b) return;
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", a.x);
    line.setAttribute("y1", a.y);
    line.setAttribute("x2", b.x);
    line.setAttribute("y2", b.y);
    line.setAttribute("class", "edge");
    canvas.appendChild(line);
  });

  nodes.forEach((n) => {
    const p = positions[n.id];
    if (!p) return;
    const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", p.x);
    circle.setAttribute("cy", p.y);
    circle.setAttribute(
      "r",
      n.kind === "root" ? 16 : n.kind === "host" ? 12 : n.kind === "service" ? 10 : 9
    );
    const kindClass = n.kind === "service" ? "finding" : n.kind;
    circle.setAttribute("class", `node-${kindClass}${highlight.has(n.id) ? " node-hi" : ""}`);
    const title = document.createElementNS("http://www.w3.org/2000/svg", "title");
    title.textContent = `${n.label}\n${n.full || n.detail || n.kind}`;
    circle.appendChild(title);
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("x", p.x + 14);
    text.setAttribute("y", p.y + 4);
    text.textContent = n.label;
    g.appendChild(circle);
    g.appendChild(text);
    canvas.appendChild(g);
  });

  const when = data.generated_at || "";
  const src = data.source || "";
  const model = data.model ? ` · ${data.model}` : "";
  meta.textContent = `${data.stats?.nodes || 0} nodes · ${data.stats?.edges || 0} edges · ${src}${model}${when ? " · " + when : ""}`;
  notes.textContent = data.notes || "(no notes)";
}

async function loadExisting() {
  const data = await api("/api/chart");
  if (data && data.ok && data.chart && (data.chart.nodes || []).length) {
    renderChart(data.chart);
    setStatus("");
  } else {
    empty.classList.remove("hidden");
    meta.textContent = "Not generated yet — click Refresh";
    notes.textContent =
      "Maps endpoints, services, and interesting items only (not every finding). LLM notes are capped ~90s.";
  }
  if (data && data.busy) {
    setGenerating(true);
    startSpin("chart still generating…");
  }
}

async function refresh() {
  if (generating) return;
  setGenerating(true);
  startSpin("mapping endpoints / services…");
  try {
    const data = await api("/api/chart/generate", { method: "POST" });
    stopSpin();
    if (!data.ok) {
      setStatus(data.error || "generate failed");
      if (data.stopped) {
        await loadExisting();
      }
      return;
    }
    renderChart(data.chart);
    setStatus("Chart updated");
    setTimeout(() => setStatus(""), 1800);
  } catch (e) {
    stopSpin();
    setStatus(String(e));
  } finally {
    setGenerating(false);
  }
}

async function stopChart() {
  setStatus("Stopping chart…");
  await api("/api/chart/cancel", { method: "POST" });
}

document.getElementById("backBtn").onclick = () => {
  window.open("/", "_blank");
};
refreshBtn.onclick = refresh;
stopBtn.onclick = stopChart;
loadExisting();
window.addEventListener("resize", () => {
  if (lastChart) renderChart(lastChart);
});
