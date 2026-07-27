const meta = document.getElementById("meta");
const notes = document.getElementById("notes");
const viewHint = document.getElementById("viewHint");
const canvas = document.getElementById("canvas");
const empty = document.getElementById("empty");
const status = document.getElementById("status");
const refreshBtn = document.getElementById("refreshBtn");
const stopBtn = document.getElementById("stopBtn");
const backViewBtn = document.getElementById("backViewBtn");

const SPIN = ["|", "/", "-", "\\"];
let spinIdx = 0;
let spinTimer = null;
let generating = false;
let lastChart = null;
/** null = domain overview; host id string = service drill-down */
let focusHostId = null;

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

function svgEl(name, attrs = {}) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", name);
  Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
  return el;
}

function wrapLabel(text, maxChars) {
  const t = String(text || "");
  if (t.length <= maxChars) return t;
  return t.slice(0, maxChars - 1) + "…";
}

function indexChart(data) {
  const nodes = data.nodes || [];
  const edges = data.edges || [];
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const children = {};
  edges.forEach((e) => {
    (children[e.from] = children[e.from] || []).push({ ...e, node: byId[e.to] });
  });
  const roots = nodes.filter((n) => n.kind === "root");
  const hosts = nodes.filter((n) => n.kind === "host" || n.kind === "root");
  return { nodes, edges, byId, children, roots, hosts, highlight: new Set(data.highlight || []) };
}

function hostChildren(idx, hostId) {
  const kids = idx.children[hostId] || [];
  return {
    subs: kids.filter((k) => k.node && k.node.kind === "host"),
    services: kids.filter((k) => k.node && k.node.kind === "service"),
    urls: kids.filter((k) => k.node && k.node.kind === "url"),
    findings: kids.filter((k) => k.node && k.node.kind === "finding"),
  };
}

function drawBox(parent, x, y, w, h, classes, label, opts = {}) {
  const g = svgEl("g", { class: "box-group", transform: `translate(${x},${y})` });
  const interesting = /\binteresting\b/.test(classes);
  const rect = svgEl("rect", {
    class: `box ${classes}`,
    x: 0,
    y: 0,
    width: w,
    height: h,
    rx: 2,
    ry: 2,
    fill: interesting ? "#fff5f4" : "#f4f6f5",
    stroke: interesting ? "#b42318" : "#1a1a1a",
    "stroke-width": interesting ? 2.5 : 2,
  });
  g.appendChild(rect);
  const lines = Array.isArray(label) ? label : [label];
  lines.forEach((line, i) => {
    const t = svgEl("text", {
      class: opts.hiLabel ? "box-label hi" : i === 0 ? "box-label" : "box-sublabel",
      x: 10,
      y: 18 + i * 14,
      fill: opts.hiLabel || (interesting && i === 0) ? "#b42318" : "#111",
      "font-family": "IBM Plex Mono, ui-monospace, monospace",
      "font-size": i === 0 ? "12" : "10",
    });
    t.textContent = wrapLabel(line, opts.maxChars || Math.floor((w - 16) / 7));
    g.appendChild(t);
  });
  if (opts.title) {
    const tip = svgEl("title");
    tip.textContent = opts.title;
    g.appendChild(tip);
  }
  if (opts.onClick) {
    rect.classList.add("clickable");
    g.style.cursor = "pointer";
    g.addEventListener("click", opts.onClick);
  }
  parent.appendChild(g);
  return { g, x, y, w, h, cx: x + w / 2, cy: y + h / 2, bottom: y + h, right: x + w };
}

function line(parent, x1, y1, x2, y2, cls) {
  parent.appendChild(
    svgEl("line", { x1, y1, x2, y2, class: cls || "branch" })
  );
}

/** Overview: domain backbone + subs hanging off + rolled-up services */
function renderOverview(data, idx) {
  const pad = 40;
  const boxW = 130;
  const boxH = 44;
  const svcW = 120;
  const svcH = 40;
  const roots = idx.roots.length ? idx.roots : idx.hosts.filter((h) => (data.scope || []).includes(h.label));
  const primary = roots[0] || idx.hosts[0];
  if (!primary) {
    empty.classList.remove("hidden");
    return;
  }

  const { subs, services, urls, findings } = hostChildren(idx, primary.id);
  // Also collect services from all hosts for overview spine (dedupe by label)
  const spineItems = [];
  const seen = new Set();
  const pushItem = (n, cls) => {
    if (!n || seen.has(n.id)) return;
    seen.add(n.id);
    spineItems.push({ node: n, cls });
  };
  services.forEach((k) => pushItem(k.node, "service"));
  // interesting urls/findings for the root host sit above spine
  const interesting = [
    ...urls.map((k) => k.node).filter((n) => n && (n.interesting || idx.highlight.has(n.id))),
    ...findings.map((k) => k.node).filter((n) => n && (n.interesting || idx.highlight.has(n.id))),
  ].slice(0, 8);

  // If root has few services, pull a sample from subs for overview context
  if (spineItems.length < 3) {
    subs.forEach((s) => {
      const ch = hostChildren(idx, s.node.id);
      ch.services.slice(0, 2).forEach((k) => pushItem(k.node, "service"));
    });
  }
  interesting.forEach((n) => {
    if (!spineItems.find((x) => x.node.id === n.id)) {
      spineItems.push({ node: n, cls: n.kind === "url" ? "url interesting" : "finding interesting", hi: true });
    }
  });

  const subBoxes = [
    ...subs.map((s) => s.node),
    ...idx.hosts.filter(
      (h) =>
        h.kind === "host" &&
        h.id !== primary.id &&
        !subs.find((s) => s.node.id === h.id) &&
        (h.label || "").endsWith("." + primary.label)
    ),
  ];

  const spineCount = Math.max(spineItems.length, 1);
  const contentW = Math.max(
    900,
    pad * 2 + boxW + 80 + spineCount * (svcW + 36) + 80
  );
  const contentH = Math.max(560, pad + 120 + boxH + 80 + Math.ceil(subBoxes.length / 3) * 90 + 80);

  canvas.setAttribute("viewBox", `0 0 ${contentW} ${contentH}`);
  canvas.style.minWidth = `${contentW}px`;
  canvas.style.minHeight = `${contentH}px`;
  canvas.innerHTML = "";

  const layer = svgEl("g");
  canvas.appendChild(layer);

  const title = svgEl("text", { class: "panel-title", x: pad, y: 28 });
  title.textContent = "Domain overview — click domain / subdomain for services";
  layer.appendChild(title);

  const spineY = 160;
  const domainX = pad + 20;
  const domainY = spineY - boxH / 2;

  // Backbone line
  const spineStart = domainX + boxW;
  const spineEnd = contentW - pad;
  line(layer, spineStart, spineY, spineEnd, spineY, "spine");

  const domainBox = drawBox(
    layer,
    domainX,
    domainY,
    boxW,
    boxH,
    "root clickable",
    ["domain target", wrapLabel(primary.label, 16)],
    {
      title: `${primary.label}\nClick for service matrix`,
      maxChars: 18,
      onClick: () => openHost(primary.id),
    }
  );

  // Service / interesting boxes along spine
  spineItems.slice(0, 12).forEach((item, i) => {
    const n = item.node;
    const x = spineStart + 50 + i * (svcW + 28);
    const above = item.hi || n.interesting || idx.highlight.has(n.id);
    const y = above ? spineY - svcH - 56 : spineY - svcH - 12;
    const cls = [
      item.cls || n.kind || "service",
      above || n.interesting || idx.highlight.has(n.id) ? "interesting" : "",
      "clickable",
    ]
      .filter(Boolean)
      .join(" ");
    const label = above
      ? ["interesting", wrapLabel(n.label, 16)]
      : [wrapLabel(n.label, 16)];
    const box = drawBox(layer, x, y, svcW, above ? svcH + 6 : svcH, cls, label, {
      title: `${n.label}\n${n.full || n.detail || n.kind}`,
      hiLabel: above,
      maxChars: 16,
      onClick: () => openHost(n.host ? `host:${n.host}` : primary.id),
    });
    // riser to spine
    line(layer, box.cx, box.bottom, box.cx, spineY, above ? "branch-hi" : "riser");
  });

  // Subdomains below
  const subStartY = spineY + 70;
  subBoxes.slice(0, 18).forEach((sub, i) => {
    const col = i % 3;
    const row = Math.floor(i / 3);
    const x = domainX - 10 + col * (boxW + 36);
    const y = subStartY + row * 78;
    const box = drawBox(
      layer,
      x,
      y,
      boxW,
      boxH + 4,
      "sub clickable",
      [wrapLabel(sub.label, 18)],
      {
        title: `${sub.label}\nClick for service matrix`,
        maxChars: 18,
        onClick: () => openHost(sub.id),
      }
    );
    // branch from domain bottom to sub
    line(layer, domainBox.cx, domainBox.bottom, box.cx, box.y, "branch");
  });

  viewHint.textContent = `Overview · ${primary.label}\n${subBoxes.length} subdomains · click a box to drill in`;
}

/** Secondary: one host's service / endpoint matrix */
function renderHostMatrix(data, idx, hostId) {
  const host = idx.byId[hostId];
  if (!host) {
    focusHostId = null;
    renderChart(data);
    return;
  }
  const { services, urls, findings } = hostChildren(idx, hostId);
  const pad = 40;
  const hostW = 150;
  const hostH = 48;
  const cellW = 128;
  const cellH = 42;

  const svcList = services.map((k) => k.node);
  const urlList = urls.map((k) => k.node);
  const findList = findings.map((k) => k.node);
  const interesting = [...urlList, ...findList].filter(
    (n) => n.interesting || idx.highlight.has(n.id) || ["critical", "high"].includes(n.severity)
  );
  const normalUrls = urlList.filter((n) => !interesting.includes(n)).slice(0, 24);

  const topCount = Math.max(interesting.length, svcList.length, 1);
  const contentW = Math.max(920, pad * 2 + hostW + 60 + topCount * (cellW + 24) + 40);
  const contentH = Math.max(
    580,
    pad + 200 + Math.ceil(Math.max(normalUrls.length, 1) / 4) * 70 + 120
  );

  canvas.setAttribute("viewBox", `0 0 ${contentW} ${contentH}`);
  canvas.style.minWidth = `${contentW}px`;
  canvas.style.minHeight = `${contentH}px`;
  canvas.innerHTML = "";
  const layer = svgEl("g");
  canvas.appendChild(layer);

  const title = svgEl("text", { class: "panel-title", x: pad, y: 28 });
  title.textContent = `Service matrix — ${host.label}`;
  layer.appendChild(title);

  const spineY = 180;
  const hostX = pad + 10;
  const hostY = spineY - hostH / 2;
  line(layer, hostX + hostW, spineY, contentW - pad, spineY, "spine");

  drawBox(layer, hostX, hostY, hostW, hostH, "root", ["host", wrapLabel(host.label, 18)], {
    title: host.label,
    maxChars: 18,
  });

  // Services on spine
  svcList.slice(0, 14).forEach((n, i) => {
    const x = hostX + hostW + 48 + i * (cellW + 22);
    const y = spineY - cellH - 14;
    const box = drawBox(
      layer,
      x,
      y,
      cellW,
      cellH,
      `service${idx.highlight.has(n.id) ? " interesting" : ""}`,
      [wrapLabel(n.label, 16)],
      { title: `${n.label}\n${n.detail || ""}`, maxChars: 16 }
    );
    line(layer, box.cx, box.bottom, box.cx, spineY, "riser");
  });

  // Interesting endpoints above (red)
  interesting.slice(0, 10).forEach((n, i) => {
    const x = hostX + hostW + 48 + i * (cellW + 22);
    const y = spineY - cellH - 100;
    const box = drawBox(
      layer,
      x,
      y,
      cellW,
      cellH + 8,
      `${n.kind} interesting`,
      ["interesting", wrapLabel(n.label, 15)],
      {
        title: `${n.label}\n${n.full || n.detail || ""}`,
        hiLabel: true,
        maxChars: 15,
      }
    );
    // attach to nearest service riser or spine
    const attachX = hostX + hostW + 48 + Math.min(i, Math.max(svcList.length - 1, 0)) * (cellW + 22) + cellW / 2;
    line(layer, box.cx, box.bottom, attachX || box.cx, spineY - cellH - 14, "branch-hi");
  });

  // Endpoint grid below spine
  const gridY = spineY + 56;
  const label = svgEl("text", { class: "panel-title", x: pad, y: gridY - 16 });
  label.textContent = "Endpoints";
  layer.appendChild(label);

  normalUrls.forEach((n, i) => {
    const col = i % 4;
    const row = Math.floor(i / 4);
    const x = pad + col * (cellW + 18);
    const y = gridY + row * (cellH + 16);
    drawBox(layer, x, y, cellW, cellH, "url", [wrapLabel(n.label, 17)], {
      title: n.full || n.label,
      maxChars: 17,
    });
  });

  if (!svcList.length && !urlList.length && !findList.length) {
    const t = svgEl("text", { class: "box-label", x: pad, y: spineY + 80 });
    t.setAttribute("fill", "#9aa");
    t.textContent = "No services/endpoints recorded for this host yet — run Surface / Ports.";
    layer.appendChild(t);
  }

  viewHint.textContent = `Services · ${host.label}\n${svcList.length} services · ${urlList.length} endpoints · ${interesting.length} interesting`;
  backViewBtn.classList.remove("hidden");
}

function openHost(hostId) {
  if (!hostId || !lastChart) return;
  // normalize
  let id = hostId;
  if (!id.startsWith("host:") && !lastChart.nodes?.find((n) => n.id === id)) {
    id = `host:${hostId}`;
  }
  focusHostId = id;
  renderChart(lastChart);
}

function renderChart(data) {
  lastChart = data;
  const nodes = data.nodes || [];
  empty.classList.toggle("hidden", nodes.length > 0);
  if (!nodes.length) return;

  try {
    const idx = indexChart(data);
    backViewBtn.classList.toggle("hidden", !focusHostId);

    if (focusHostId && idx.byId[focusHostId]) {
      renderHostMatrix(data, idx, focusHostId);
    } else {
      focusHostId = null;
      backViewBtn.classList.add("hidden");
      renderOverview(data, idx);
    }
  } catch (err) {
    console.error("chart render failed", err);
    setStatus(`Chart render error: ${err}`);
    return;
  }

  const when = data.generated_at || "";
  const src = data.source || "";
  const model = data.model ? ` · ${data.model}` : "";
  meta.textContent = `${data.stats?.nodes || 0} nodes · ${data.stats?.edges || 0} edges · matrix${model}${when ? " · " + when : ""} · ${src}`;
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
      "Domain backbone + services. Click a domain/sub for its service matrix. LLM notes capped ~90s.";
    viewHint.textContent = "Overview — domains & subs";
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
      if (data.stopped) await loadExisting();
      return;
    }
    focusHostId = null;
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

document.getElementById("backBtn").onclick = () => window.open("/", "_blank");
backViewBtn.onclick = () => {
  focusHostId = null;
  if (lastChart) renderChart(lastChart);
};
refreshBtn.onclick = refresh;
stopBtn.onclick = stopChart;
loadExisting();
window.addEventListener("resize", () => {
  if (lastChart) renderChart(lastChart);
});
