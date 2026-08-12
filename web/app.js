const scanForm = document.getElementById("scan-form");
const scanStatus = document.getElementById("scan-status");
const scanOutput = document.getElementById("scan-output");
const scanLog = document.getElementById("scan-log");
const scanProgress = document.getElementById("scan-progress");
const scanProgressBar = document.getElementById("scan-progress-bar");
const capabilityStatus = document.getElementById("capability-status");
const verificationStatus = document.getElementById("verification-status");
const identityCandidates = document.getElementById("identity-candidates");
const categorySelect = document.getElementById("category-select");
const phaseWarnings = document.getElementById("phase-warnings");
const jobStatus = document.getElementById("job-status");
const jobList = document.getElementById("job-list");
const investigatorSummary = document.getElementById("investigator-summary");
const briefHeadline = document.getElementById("brief-headline");
const briefPriorityScore = document.getElementById("brief-priority-score");
const briefConfidenceBand = document.getElementById("brief-confidence-band");
const briefOverview = document.getElementById("brief-overview");
const briefRisks = document.getElementById("brief-risks");
const briefNextSteps = document.getElementById("brief-next-steps");
const briefActionsBySeverity = document.getElementById("brief-actions-by-severity");
const scanCaseTarget = document.getElementById("scan-case-target");
const historyForm = document.getElementById("history-form");
const historyStatus = document.getElementById("history-status");
const historyDiff = document.getElementById("history-diff");
const historyList = document.getElementById("history-list");
const watchForm = document.getElementById("watch-form");
const watchList = document.getElementById("watch-list");
const graphForm = document.getElementById("graph-form");
const graphStatus = document.getElementById("graph-status");
const nodeDetail = document.getElementById("node-detail");
const heatmapForm = document.getElementById("heatmap-form");
const heatmapStatus = document.getElementById("heatmap-status");
const correlateForm = document.getElementById("correlate-form");
const correlateStatus = document.getElementById("correlate-status");
const correlateVerdict = document.getElementById("correlate-verdict");
const correlateSignals = document.getElementById("correlate-signals");
const compareForm = document.getElementById("compare-form");
const compareStatus = document.getElementById("compare-status");
const compareSummary = document.getElementById("compare-summary");
const compareSections = document.getElementById("compare-sections");

let cy = null;
let leafletMap = null;
let heatLayer = null;
let markerLayer = null;

const KIND_COLOR = {
  identity: "#ff4c60",
  platform: "#5fa8ff",
  email: "#ffd57a",
  breach: "#ff7a7a",
  phone: "#9ad0a5",
  crypto: "#c792ea",
  alias: "#e6edf3",
};

function buildFormBody() {
  const fd = new FormData(scanForm);
  const body = {
    username: fd.get("username"),
    smart: fd.get("smart") === "on",
    platform_scope: fd.get("platform_scope") || "core",
    email: fd.get("email") === "on",
    breach: fd.get("breach") === "on",
    web: fd.get("web") === "on",
    whois: fd.get("whois") === "on",
    dns: fd.get("dns") === "on",
    subdomain: fd.get("subdomain") === "on",
    photo: fd.get("photo") === "on",
    recursive: fd.get("recursive") === "on",
    passive: fd.get("passive") === "on",
    reverse_image: fd.get("reverse_image") === "on",
    past_usernames: fd.get("past_usernames") === "on",
    tor: fd.get("tor") === "on",
  };
  const cats = fd.getAll("categories").map((value) => value.toString()).filter(Boolean);
  if (cats.length) body.categories = cats;
  if (activeCaseId) body.case_id = activeCaseId;
  return body;
}

function updateScanCaseTarget() {
  if (!scanCaseTarget) return;
  if (!activeCaseId) {
    scanCaseTarget.textContent = "no active case selected";
    return;
  }
  scanCaseTarget.textContent = "new scans will be linked to case #" + activeCaseId;
}

async function refreshWatchlist() {
  try {
    const r = await fetch("/watchlist");
    if (!r.ok) return;
    const data = await r.json();
    watchList.innerHTML = "";
    for (const e of data.entries) {
      const li = document.createElement("li");
      const label = document.createElement("span");
      const tags = e.tags && e.tags.length ? " [" + e.tags.join(",") + "]" : "";
      label.textContent = "#" + e.id + "  " + e.username + tags;
      const btn = document.createElement("button");
      btn.className = "remove";
      btn.textContent = "remove";
      btn.onclick = async () => {
        await fetch("/watchlist/" + encodeURIComponent(e.username), { method: "DELETE" });
        refreshWatchlist();
      };
      li.appendChild(label);
      li.appendChild(btn);
      watchList.appendChild(li);
    }
  } catch (err) {
    console.error("watchlist fetch failed", err);
  }
}

function logLine(event) {
  const li = document.createElement("li");
  li.className = "kind-" + event.kind;
  const phase = event.phase ? "[" + event.phase + "] " : "";
  li.textContent = phase + event.kind + (event.message ? " — " + event.message : "");
  scanLog.appendChild(li);
  scanLog.scrollTop = scanLog.scrollHeight;
}

function renderBriefList(target, items, formatter) {
  target.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "none";
    target.appendChild(li);
    return;
  }
  for (const item of items) {
    const li = document.createElement("li");
    formatter(li, item);
    target.appendChild(li);
  }
}

function renderInvestigatorSummary(payload) {
  const platforms = (payload && payload.platforms) || [];
  const counts = { confirmed: 0, uncertain: 0, rejected: 0 };
  for (const platform of platforms) {
    const verdict = (platform.verification && platform.verification.verdict) ||
      (platform.exists ? "confirmed" : "rejected");
    if (verdict in counts) counts[verdict] += 1;
  }
  const totals = (payload && payload.verification_counts) || counts;
  verificationStatus.textContent =
    "confirmed " + totals.confirmed + " · uncertain " + totals.uncertain +
    " · rejected " + totals.rejected;
  phaseWarnings.innerHTML = "";
  const diagnosticWarnings = (payload && payload.diagnostics && payload.diagnostics.warnings) || [];
  for (const warning of [...((payload && payload.warnings) || []), ...diagnosticWarnings]) {
    const item = document.createElement("li");
    item.textContent = warning;
    phaseWarnings.appendChild(item);
  }
  renderIdentityCandidates((payload && payload.identity_candidates) || []);
  const brief = payload && payload.investigator_summary;
  if (!brief) {
    investigatorSummary.classList.remove("show");
    return;
  }
  investigatorSummary.classList.add("show");
  briefHeadline.textContent = brief.headline || "no analyst headline";
  briefPriorityScore.textContent = (brief.priority_score || 0) + "/100";
  briefConfidenceBand.textContent = (brief.confidence_band || "low").replaceAll("_", " ");
  renderBriefList(briefOverview, brief.overview || [], (li, item) => {
    li.textContent = item;
  });
  renderBriefList(briefRisks, brief.risk_flags || [], (li, item) => {
    const severity = (item.severity || "low").toLowerCase();
    li.className = "risk-" + severity;
    li.innerHTML =
      "<strong>" + item.title + "</strong>" +
      "<span>" + (item.detail || "") + "</span>";
  });
  renderBriefList(briefNextSteps, brief.next_steps || [], (li, item) => {
    li.textContent = item;
  });
  briefActionsBySeverity.innerHTML = "";
  const actionLabels = {
    high: "Immediate",
    medium: "Follow-up",
    low: "Background",
  };
  const actions = brief.recommended_actions_by_severity || {};
  for (const key of ["high", "medium", "low"]) {
    const items = actions[key] || [];
    if (!items.length) continue;
    const block = document.createElement("div");
    block.className = "brief-action-group";
    const heading = document.createElement("h4");
    heading.textContent = actionLabels[key];
    block.appendChild(heading);
    const list = document.createElement("ul");
    renderBriefList(list, items, (li, item) => {
      li.textContent = item;
    });
    block.appendChild(list);
    briefActionsBySeverity.appendChild(block);
  }
}

function renderIdentityCandidates(candidates) {
  identityCandidates.innerHTML = "";
  if (!candidates.length) return;
  const heading = document.createElement("h3");
  heading.textContent = "Similar usernames / Identity candidates";
  identityCandidates.appendChild(heading);
  const table = document.createElement("table");
  const header = document.createElement("tr");
  for (const label of ["Handle", "Platforms", "Verdict", "Score", "Evidence"]) {
    const th = document.createElement("th");
    th.textContent = label;
    header.appendChild(th);
  }
  table.appendChild(header);
  for (const candidate of candidates) {
    const row = document.createElement("tr");
    const values = [
      candidate.username || "",
      (candidate.profiles || []).map((profile) => profile.platform).join(", "),
      (candidate.verdict || "uncertain").replaceAll("_", " "),
      Number(candidate.score || 0).toFixed(2),
      (candidate.evidence || []).slice(0, 3).map((item) => item.detail).join("; "),
    ];
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }
    table.appendChild(row);
  }
  identityCandidates.appendChild(table);
}

async function refreshPlatformCatalog() {
  try {
    const response = await fetch("/platforms");
    if (!response.ok) return;
    const catalog = await response.json();
    categorySelect.innerHTML = "";
    for (const category of catalog.categories || []) {
      const option = document.createElement("option");
      option.value = category.value;
      option.textContent = category.label + " (" + category.core_count + "/" + category.full_count + ")";
      categorySelect.appendChild(option);
    }
  } catch (err) {
    console.error("platform catalog fetch failed", err);
  }
}

async function streamScan(body) {
  scanLog.innerHTML = "";
  scanProgress.classList.add("active");
  scanProgressBar.style.width = "2%";
  const createRes = await fetch("/scan-jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!createRes.ok) throw new Error("HTTP " + createRes.status);
  const created = await createRes.json();
  const jobId = created.id;
  scanStatus.textContent = "job " + jobId + " queued";
  refreshJobs();

  const r = await fetch("/scan-jobs/" + encodeURIComponent(jobId) + "/events");
  if (!r.ok || !r.body) throw new Error("HTTP " + r.status);

  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let totalPhases = 15; // approximate, engine has ~15 phases
  let doneCount = 0;
  let finalPayload = null;
  let lastStatus = "running";

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split("\n\n");
    buf = parts.pop() || "";
    for (const chunk of parts) {
      const line = chunk.trim();
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (!payload) continue;
      let event;
      try { event = JSON.parse(payload); } catch { continue; }
      logLine(event);
      if (event.kind === "job_finished" && event.data) {
        lastStatus = event.data.status || lastStatus;
      }
      if (event.kind === "phase_end") {
        doneCount += 1;
        scanProgressBar.style.width = Math.min(95, (doneCount / totalPhases) * 100) + "%";
      }
      if (event.kind === "result") {
        finalPayload = event.data && event.data.payload;
      }
    }
  }
  scanProgressBar.style.width = "100%";
  setTimeout(() => scanProgress.classList.remove("active"), 500);
  refreshJobs();
  if (!finalPayload && lastStatus !== "completed") {
    throw new Error("job " + jobId + " finished with status " + lastStatus);
  }
  return finalPayload;
}

async function pollJob(jobId) {
  scanProgress.classList.add("active");
  scanProgressBar.style.width = "8%";
  while (true) {
    const r = await fetch("/scan-jobs/" + encodeURIComponent(jobId));
    if (!r.ok) throw new Error("HTTP " + r.status);
    const job = await r.json();
    if (job.status === "completed" && job.result) {
      scanProgressBar.style.width = "100%";
      setTimeout(() => scanProgress.classList.remove("active"), 500);
      refreshJobs();
      return job.result;
    }
    if (job.status === "error") {
      throw new Error(job.error || "job failed");
    }
    scanProgressBar.style.width = Math.min(92, Number(scanProgressBar.style.width.replace("%", "") || "8") + 8) + "%";
    await new Promise((resolve) => setTimeout(resolve, 400));
  }
}

scanForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const body = buildFormBody();
  const stream = scanForm.querySelector("[name='stream']").checked;
  scanStatus.textContent = "scanning " + body.username + "...";
  scanOutput.textContent = "";

  try {
    let data;
    if (stream) {
      data = await streamScan(body);
    } else {
      const createRes = await fetch("/scan-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!createRes.ok) { scanStatus.textContent = "error: HTTP " + createRes.status; return; }
      const created = await createRes.json();
      scanStatus.textContent = "job " + created.id + " queued";
      refreshJobs();
      data = await pollJob(created.id);
    }
    if (!data) { scanStatus.textContent = "no result"; return; }
    const found = (data.platforms || []).filter((p) => p.exists).length;
    const warnings = data.warnings || [];
    scanStatus.textContent = "done — " + found + " platforms matched" +
      (data.scan_id ? " · scan #" + data.scan_id : "") +
      (warnings.length ? " · " + warnings.length + " warning(s)" : "");
    renderInvestigatorSummary(data);
    scanOutput.textContent = JSON.stringify(data, null, 2);
    // Auto-load graph for this username.
    loadGraph(body.username);
    refreshHistory(body.username);
  } catch (err) {
    scanStatus.textContent = "network error: " + err.message;
  }
});

async function refreshCapabilities() {
  try {
    const r = await fetch("/capabilities");
    if (!r.ok) return;
    const data = await r.json();
    const caps = data.capabilities || {};
    const ready = Object.entries(caps)
      .filter(([, meta]) => meta && meta.ready)
      .map(([name]) => name);
    const degraded = Object.entries(caps)
      .filter(([, meta]) => meta && meta.available && !meta.ready)
      .map(([name]) => name);
    const missing = Object.entries(caps)
      .filter(([, meta]) => !meta || !meta.available)
      .map(([name]) => name);
    capabilityStatus.textContent =
      "schema " + data.schema_version +
      " · ready: " + ready.slice(0, 6).join(", ") +
      (degraded.length ? " · partial: " + degraded.slice(0, 4).join(", ") : "") +
      (missing.length ? " · unavailable: " + missing.slice(0, 6).join(", ") : "");
  } catch (err) {
    capabilityStatus.textContent = "capabilities fetch error: " + err.message;
  }
}

function renderJobItem(job) {
  const li = document.createElement("li");
  const left = document.createElement("span");
  left.textContent = "#" + job.id.slice(0, 8) + "  " + job.username;
  const right = document.createElement("span");
  right.textContent = job.status + (job.scan_id ? " · scan #" + job.scan_id : "");
  right.className = "job-status-" + job.status;
  li.appendChild(left);
  li.appendChild(right);
  li.addEventListener("click", async () => {
    if (!job.scan_id) return;
    scanStatus.textContent = "loaded scan #" + job.scan_id + " from job " + job.id.slice(0, 8);
    const r = await fetch("/scan-jobs/" + encodeURIComponent(job.id) + "/result");
    if (!r.ok) return;
    const data = await r.json();
    renderInvestigatorSummary(data);
    scanOutput.textContent = JSON.stringify(data, null, 2);
    if (data.username) refreshHistory(data.username);
  });
  return li;
}

async function refreshJobs() {
  try {
    const r = await fetch("/scan-jobs?limit=8");
    if (!r.ok) return;
    const data = await r.json();
    jobList.innerHTML = "";
    const jobs = data.jobs || [];
    jobStatus.textContent = jobs.length ? jobs.length + " recent jobs" : "no jobs yet";
    for (const job of jobs) {
      jobList.appendChild(renderJobItem(job));
    }
  } catch (err) {
    jobStatus.textContent = "jobs fetch error: " + err.message;
  }
}

watchForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(watchForm);
  const username = (fd.get("username") || "").toString().trim();
  if (!username) return;
  const tagsRaw = (fd.get("tags") || "").toString().trim();
  const tags = tagsRaw ? tagsRaw.split(",").map((s) => s.trim()).filter(Boolean) : [];
  await fetch("/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, tags, notes: "" }),
  });
  watchForm.reset();
  refreshWatchlist();
});

function renderGraph(payload) {
  if (!window.cytoscape) {
    graphStatus.textContent = "cytoscape not loaded";
    return;
  }
  const elements = [...payload.nodes, ...payload.edges];
  if (cy) cy.destroy();
  cy = window.cytoscape({
    container: document.getElementById("cy"),
    elements,
    layout: { name: "cose", animate: false, padding: 30 },
    style: [
      {
        selector: "node",
        style: {
          "label": "data(label)",
          "background-color": (ele) => KIND_COLOR[ele.data("kind")] || "#7d8590",
          "color": "#e6edf3",
          "font-size": 10,
          "font-family": "JetBrains Mono, ui-monospace, monospace",
          "text-valign": "bottom",
          "text-margin-y": 4,
          "width": 18,
          "height": 18,
          "border-width": 1,
          "border-color": "#0b0d10",
        },
      },
      {
        selector: 'node[kind = "identity"]',
        style: { "width": 30, "height": 30, "font-size": 12 },
      },
      {
        selector: "edge",
        style: {
          "line-color": "#262c33",
          "target-arrow-color": "#262c33",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "width": 1,
        },
      },
    ],
  });
  cy.on("tap", "node", (evt) => {
    nodeDetail.textContent = JSON.stringify(evt.target.data(), null, 2);
  });
}

async function loadGraph(username) {
  graphStatus.textContent = "loading graph for " + username + "...";
  nodeDetail.textContent = "";
  try {
    const r = await fetch("/graph/" + encodeURIComponent(username));
    if (r.status === 404) {
      graphStatus.textContent = "no scans yet for " + username;
      return;
    }
    if (!r.ok) {
      graphStatus.textContent = "error: HTTP " + r.status;
      return;
    }
    const data = await r.json();
    graphStatus.textContent = data.nodes.length + " nodes · " + data.edges.length + " edges";
    renderGraph(data);
  } catch (err) {
    graphStatus.textContent = "network error: " + err.message;
  }
}

graphForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(graphForm);
  const username = (fd.get("username") || "").toString().trim();
  if (username) loadGraph(username);
});

function ensureMap() {
  if (leafletMap) return leafletMap;
  if (!window.L) return null;
  leafletMap = window.L.map("map", { worldCopyJump: true }).setView([20, 0], 2);
  window.L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap",
    maxZoom: 18,
  }).addTo(leafletMap);
  return leafletMap;
}

async function loadHeatmap(username) {
  const map = ensureMap();
  if (!map) {
    heatmapStatus.textContent = "leaflet not loaded";
    return;
  }
  heatmapStatus.textContent = "loading heatmap for " + username + "...";
  if (heatLayer) { map.removeLayer(heatLayer); heatLayer = null; }
  if (markerLayer) { map.removeLayer(markerLayer); markerLayer = null; }

  try {
    const r = await fetch("/heatmap/" + encodeURIComponent(username));
    if (r.status === 404) { heatmapStatus.textContent = "no scans yet for " + username; return; }
    if (!r.ok) { heatmapStatus.textContent = "error: HTTP " + r.status; return; }
    const data = await r.json();
    const points = data.points || [];
    const markers = data.markers || [];
    if (!points.length) {
      heatmapStatus.textContent = "no geocoded locations (run with --geocode)";
      return;
    }
    heatLayer = window.L.heatLayer(points, { radius: 28, blur: 22, maxZoom: 12 }).addTo(map);
    markerLayer = window.L.layerGroup(
      markers.map((m) => window.L.marker([m.lat, m.lng]).bindPopup(
        "<b>" + (m.label || "") + "</b><br/>source: " + (m.source || "?")
      ))
    ).addTo(map);
    const bounds = window.L.latLngBounds(markers.map((m) => [m.lat, m.lng]));
    if (bounds.isValid()) map.fitBounds(bounds.pad(0.2));
    heatmapStatus.textContent = points.length + " unique locations · " + markers.length + " hits";
  } catch (err) {
    heatmapStatus.textContent = "network error: " + err.message;
  }
}

heatmapForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(heatmapForm);
  const username = (fd.get("username") || "").toString().trim();
  if (username) loadHeatmap(username);
});

async function loadCorrelation(a, b) {
  correlateStatus.textContent = "scoring " + a + " vs " + b + "...";
  correlateVerdict.className = "";
  correlateSignals.innerHTML = "";
  try {
    const url = "/correlate?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b);
    const r = await fetch(url);
    if (r.status === 404) { correlateStatus.textContent = "no scan history for one of them — run a scan first"; return; }
    if (r.status === 400) { correlateStatus.textContent = "a and b must be different usernames"; return; }
    if (!r.ok) { correlateStatus.textContent = "error: HTTP " + r.status; return; }
    const data = await r.json();

    correlateStatus.textContent = "compared scan #" + data.scan_a.id + " vs #" + data.scan_b.id;
    const pct = Math.round(data.score * 100);
    correlateVerdict.className = "show verdict-" + data.verdict;
    correlateVerdict.innerHTML =
      "<span class='score'>" + pct + "%</span>" +
      " — same-person likelihood" +
      "<span class='verdict-tag verdict-" + data.verdict + "'>" + data.verdict.replace(/_/g, " ") + "</span>";

    if (!data.signals.length) {
      const li = document.createElement("li");
      li.textContent = "no shared signals found";
      correlateSignals.appendChild(li);
      return;
    }
    for (const s of data.signals) {
      const li = document.createElement("li");
      const kind = document.createElement("span");
      kind.className = "kind";
      kind.textContent = s.kind;
      const detail = document.createElement("span");
      detail.textContent = s.detail;
      const weight = document.createElement("span");
      weight.className = "weight";
      weight.textContent = "+" + Math.round(s.weight * 100) + "%";
      li.appendChild(kind);
      li.appendChild(detail);
      li.appendChild(weight);
      correlateSignals.appendChild(li);
    }
  } catch (err) {
    correlateStatus.textContent = "network error: " + err.message;
  }
}

function renderCompareBucket(title, bucket) {
  const wrap = document.createElement("div");
  wrap.className = "compare-section";
  const h = document.createElement("h3");
  const added = bucket.added || [];
  const removed = bucket.removed || [];
  h.textContent = title + "  ·  +" + added.length + " / -" + removed.length + "  ·  " + bucket.unchanged_count + " unchanged";
  wrap.appendChild(h);

  const cols = document.createElement("div");
  cols.className = "compare-cols";

  const makeCol = (label, items, cls) => {
    const col = document.createElement("div");
    col.className = "compare-col " + cls + (items.length ? "" : " empty");
    const h4 = document.createElement("h4");
    h4.textContent = label;
    col.appendChild(h4);
    const ul = document.createElement("ul");
    if (!items.length) {
      const li = document.createElement("li");
      li.textContent = "(none)";
      ul.appendChild(li);
    } else {
      for (const v of items) {
        const li = document.createElement("li");
        li.textContent = v;
        ul.appendChild(li);
      }
    }
    col.appendChild(ul);
    return col;
  };

  cols.appendChild(makeCol("added", added, "added"));
  cols.appendChild(makeCol("removed", removed, "removed"));
  wrap.appendChild(cols);
  return wrap;
}

function renderPlatformChanges(changes) {
  if (!changes.length) return null;
  const wrap = document.createElement("div");
  wrap.className = "compare-section";
  const h = document.createElement("h3");
  h.textContent = "platform profile changes · " + changes.length;
  wrap.appendChild(h);
  for (const pc of changes) {
    const block = document.createElement("div");
    block.className = "platform-change";
    const name = document.createElement("div");
    name.className = "name";
    name.textContent = pc.platform;
    block.appendChild(name);
    const table = document.createElement("table");
    const thead = document.createElement("tr");
    for (const h of ["field", "old", "new"]) {
      const th = document.createElement("th");
      th.textContent = h;
      thead.appendChild(th);
    }
    table.appendChild(thead);
    for (const c of pc.changes) {
      const tr = document.createElement("tr");
      const f = document.createElement("td");
      f.textContent = c.field;
      const o = document.createElement("td");
      o.className = "old";
      o.textContent = c.old == null ? "—" : String(c.old);
      const n = document.createElement("td");
      n.className = "new";
      n.textContent = c.new == null ? "—" : String(c.new);
      tr.appendChild(f);
      tr.appendChild(o);
      tr.appendChild(n);
      table.appendChild(tr);
    }
    block.appendChild(table);
    wrap.appendChild(block);
  }
  return wrap;
}

async function loadCompare(a, b, aScan, bScan) {
  compareStatus.textContent = "diffing " + a + " vs " + b + "...";
  compareSummary.className = "";
  compareSections.innerHTML = "";
  try {
    const params = new URLSearchParams({ a, b });
    if (aScan) params.set("a_scan", aScan);
    if (bScan) params.set("b_scan", bScan);
    const r = await fetch("/compare?" + params.toString());
    if (r.status === 404) { compareStatus.textContent = "no scan history for one of them"; return; }
    if (!r.ok) { compareStatus.textContent = "error: HTTP " + r.status; return; }
    const data = await r.json();

    compareStatus.textContent = "diff ready";
    compareSummary.className = "show";
    compareSummary.innerHTML =
      "<span class='scan-ids'>#" + data.scan_a.id + " → #" + data.scan_b.id + "</span>" +
      "<strong>" + data.summary + "</strong>" +
      "  ·  found-count Δ " + (data.found_count_delta >= 0 ? "+" : "") + data.found_count_delta;

    const sections = [
      ["platforms", data.platforms],
      ["emails", data.emails],
      ["breaches", data.breaches],
      ["phones", data.phones],
      ["crypto wallets", data.crypto],
      ["geo locations", data.geo],
    ];
    for (const [title, bucket] of sections) {
      compareSections.appendChild(renderCompareBucket(title, bucket));
    }
    const pcBlock = renderPlatformChanges(data.platform_changes || []);
    if (pcBlock) compareSections.appendChild(pcBlock);
  } catch (err) {
    compareStatus.textContent = "network error: " + err.message;
  }
}

compareForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(compareForm);
  const a = (fd.get("a") || "").toString().trim();
  const b = (fd.get("b") || "").toString().trim();
  if (!a || !b) return;
  const aScan = (fd.get("a_scan") || "").toString().trim();
  const bScan = (fd.get("b_scan") || "").toString().trim();
  loadCompare(a, b, aScan, bScan);
});

correlateForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(correlateForm);
  const a = (fd.get("a") || "").toString().trim();
  const b = (fd.get("b") || "").toString().trim();
  if (!a || !b) return;
  loadCorrelation(a, b);
});

const socialForm = document.getElementById("social-form");
const socialStatus = document.getElementById("social-status");
const socialSummary = document.getElementById("social-summary");
const socialLists = document.getElementById("social-lists");

function renderSocialList(title, logins) {
  const wrap = document.createElement("div");
  wrap.className = "social-list";
  const h = document.createElement("h3");
  h.textContent = title;
  wrap.appendChild(h);
  const ul = document.createElement("ul");
  if (!logins || logins.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "none";
    ul.appendChild(li);
  } else {
    for (const login of logins) {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = "https://github.com/" + encodeURIComponent(login);
      a.target = "_blank";
      a.rel = "noopener";
      a.textContent = login;
      li.appendChild(a);
      ul.appendChild(li);
    }
  }
  wrap.appendChild(ul);
  return wrap;
}

async function loadSocialGraph(a, b) {
  socialStatus.textContent = "fetching " + a + " vs " + b + "…";
  socialSummary.classList.remove("show");
  socialLists.innerHTML = "";
  try {
    const url = "/social-graph?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b);
    const res = await fetch(url);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      socialStatus.textContent = "error: " + (err.detail || res.status);
      return;
    }
    const data = await res.json();
    socialStatus.textContent = "";
    const pct = Math.round((data.combined_score || 0) * 100);
    socialSummary.textContent = "";
    const score = document.createElement("span");
    score.className = "score";
    score.textContent = pct + "%";
    socialSummary.appendChild(score);
    socialSummary.appendChild(document.createTextNode(
      " combined overlap — " +
      data.username_a + " (" + data.neighbors_a.follower_count + " followers, " +
      data.neighbors_a.following_count + " following) ↔ " +
      data.username_b + " (" + data.neighbors_b.follower_count + " followers, " +
      data.neighbors_b.following_count + " following)"
    ));
    socialSummary.classList.add("show");
    socialLists.appendChild(renderSocialList("shared followers", data.shared_followers));
    socialLists.appendChild(renderSocialList("shared following", data.shared_following));
  } catch (err) {
    socialStatus.textContent = "network error: " + err.message;
  }
}

socialForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(socialForm);
  const a = (fd.get("a") || "").toString().trim();
  const b = (fd.get("b") || "").toString().trim();
  if (!a || !b) return;
  loadSocialGraph(a, b);
});

const caseCreateForm = document.getElementById("case-create-form");
const caseStatus = document.getElementById("case-status");
const caseListEl = document.getElementById("case-list");
const caseDetail = document.getElementById("case-detail");
let activeCaseId = null;
let currentHistoryUsername = "";

function fmtTs(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toISOString().slice(0, 16).replace("T", " ");
}

async function refreshCases() {
  try {
    const res = await fetch("/cases");
    if (!res.ok) return;
    const data = await res.json();
    caseListEl.innerHTML = "";
    if (!data.entries || data.entries.length === 0) {
      activeCaseId = null;
      updateScanCaseTarget();
      const li = document.createElement("li");
      li.className = "empty";
      li.style.cursor = "default";
      li.textContent = "no cases yet — create one above";
      caseListEl.appendChild(li);
      return;
    }
    for (const c of data.entries) {
      const li = document.createElement("li");
      li.dataset.caseId = c.id;
      if (c.id === activeCaseId) li.classList.add("active");
      const name = document.createElement("span");
      name.className = "case-name";
      name.textContent = "#" + c.id + "  " + c.name;
      const meta = document.createElement("span");
      meta.className = "case-meta status-" + c.status;
      meta.textContent = c.status + " · " + fmtTs(c.created_ts);
      li.appendChild(name);
      li.appendChild(meta);
      li.addEventListener("click", () => loadCaseDetail(c.id));
      caseListEl.appendChild(li);
    }
  } catch (err) {
    caseStatus.textContent = "cases fetch error: " + err.message;
  }
}

async function loadCaseDetail(caseId) {
  activeCaseId = caseId;
  updateScanCaseTarget();
  await refreshCases();
  if (currentHistoryUsername) refreshHistory(currentHistoryUsername);
  try {
    const res = await fetch("/cases/" + caseId);
    if (!res.ok) {
      caseDetail.textContent = "case not found";
      caseDetail.classList.add("show");
      return;
    }
    const c = await res.json();
    caseDetail.innerHTML = "";
    const title = document.createElement("h3");
    title.textContent = "#" + c.id + "  " + c.name + "  (" + c.status + ")";
    caseDetail.appendChild(title);
    if (c.description) {
      const d = document.createElement("div");
      d.className = "description";
      d.textContent = c.description;
      caseDetail.appendChild(d);
    }

    const actions = document.createElement("div");
    actions.className = "case-actions";
    if (c.status !== "closed") {
      const closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.textContent = "Close case";
      closeBtn.addEventListener("click", async () => {
        await fetch("/cases/" + caseId, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: "closed" }),
        });
        loadCaseDetail(caseId);
      });
      actions.appendChild(closeBtn);
    }
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.textContent = "Delete";
      delBtn.addEventListener("click", async () => {
        if (!confirm("Delete case #" + caseId + "?")) return;
        await fetch("/cases/" + caseId, { method: "DELETE" });
        activeCaseId = null;
        updateScanCaseTarget();
        caseDetail.classList.remove("show");
        refreshCases();
      });
    actions.appendChild(delBtn);
    caseDetail.appendChild(actions);

    // Notes
    const notesH = document.createElement("h4");
    notesH.textContent = "Notes (" + (c.notes || []).length + ")";
    caseDetail.appendChild(notesH);
    for (const n of c.notes || []) {
      const row = document.createElement("div");
      row.className = "detail-row";
      const body = document.createElement("span");
      body.style.flex = "1";
      body.textContent = "[" + fmtTs(n.created_ts) + "] " + n.body;
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "remove";
      rm.textContent = "×";
      rm.addEventListener("click", async () => {
        await fetch("/cases/notes/" + n.id, { method: "DELETE" });
        loadCaseDetail(caseId);
      });
      row.appendChild(body);
      row.appendChild(rm);
      caseDetail.appendChild(row);
    }
    const noteForm = document.createElement("form");
    noteForm.className = "inline-form";
    const noteInput = document.createElement("input");
    noteInput.placeholder = "add note…";
    noteInput.required = true;
    const noteBtn = document.createElement("button");
    noteBtn.type = "submit";
    noteBtn.textContent = "Add";
    noteForm.appendChild(noteInput);
    noteForm.appendChild(noteBtn);
    noteForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = noteInput.value.trim();
      if (!body) return;
      await fetch("/cases/" + caseId + "/notes", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: body }),
      });
      noteInput.value = "";
      loadCaseDetail(caseId);
    });
    caseDetail.appendChild(noteForm);

    // Bookmarks
    const bmsH = document.createElement("h4");
    bmsH.textContent = "Bookmarks (" + (c.bookmarks || []).length + ")";
    caseDetail.appendChild(bmsH);
    for (const b of c.bookmarks || []) {
      const row = document.createElement("div");
      row.className = "detail-row";
      const body = document.createElement("span");
      body.style.flex = "1";
      body.textContent = b.target_type + ": " + b.target_value +
        (b.label ? " — " + b.label : "");
      const rm = document.createElement("button");
      rm.type = "button";
      rm.className = "remove";
      rm.textContent = "×";
      rm.addEventListener("click", async () => {
        await fetch("/cases/bookmarks/" + b.id, { method: "DELETE" });
        loadCaseDetail(caseId);
      });
      row.appendChild(body);
      row.appendChild(rm);
      caseDetail.appendChild(row);
    }
    const bmForm = document.createElement("form");
    bmForm.className = "inline-form";
    const typeSel = document.createElement("select");
    for (const t of ["scan", "platform", "email", "phone", "wallet", "url", "note"]) {
      const opt = document.createElement("option");
      opt.value = t;
      opt.textContent = t;
      typeSel.appendChild(opt);
    }
    const valInput = document.createElement("input");
    valInput.placeholder = "target value";
    valInput.required = true;
    const labelInput = document.createElement("input");
    labelInput.placeholder = "label (optional)";
    const bmBtn = document.createElement("button");
    bmBtn.type = "submit";
    bmBtn.textContent = "Add";
    bmForm.appendChild(typeSel);
    bmForm.appendChild(valInput);
    bmForm.appendChild(labelInput);
    bmForm.appendChild(bmBtn);
    bmForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const val = valInput.value.trim();
      if (!val) return;
      await fetch("/cases/" + caseId + "/bookmarks", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_type: typeSel.value,
          target_value: val,
          label: labelInput.value.trim(),
        }),
      });
      valInput.value = "";
      labelInput.value = "";
      loadCaseDetail(caseId);
    });
    caseDetail.appendChild(bmForm);
    caseDetail.classList.add("show");
  } catch (err) {
    caseStatus.textContent = "case detail error: " + err.message;
  }
}

caseCreateForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(caseCreateForm);
  const name = (fd.get("name") || "").toString().trim();
  const description = (fd.get("description") || "").toString().trim();
  if (!name) return;
  caseStatus.textContent = "creating…";
  try {
    const res = await fetch("/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name, description: description, tags: [] }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      caseStatus.textContent = "error: " + (err.detail || res.status);
      return;
    }
    caseStatus.textContent = "";
    caseCreateForm.reset();
    const c = await res.json();
    refreshCases();
    loadCaseDetail(c.id);
  } catch (err) {
    caseStatus.textContent = "network error: " + err.message;
  }
});

function renderHistoryDiff(data) {
  historyDiff.innerHTML = "";
  const added = data.added || [];
  const removed = data.removed || [];
  if (data.message && !added.length && !removed.length) {
    historyDiff.textContent = data.message;
    return;
  }
  const parts = [];
  if (added.length) parts.push("+" + added.join(", "));
  if (removed.length) parts.push("-" + removed.join(", "));
  historyDiff.textContent = parts.join("  ·  ") || "no changes";
}

async function linkHistoryScanToCase(scanId, username) {
  if (!activeCaseId) {
    historyStatus.textContent = "select a case first";
    return;
  }
  const res = await fetch("/cases/" + activeCaseId + "/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_id: scanId }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    historyStatus.textContent = "link error: " + (err.detail || res.status);
    return;
  }
  historyStatus.textContent = "linked scan #" + scanId + " to case #" + activeCaseId;
  loadCaseDetail(activeCaseId);
  refreshHistory(username);
}

function renderHistoryEntry(entry, username) {
  const li = document.createElement("li");
  const left = document.createElement("span");
  left.textContent = "#" + entry.id + "  " + fmtTs(entry.ts) + "  ·  " + entry.found_count + " found";
  li.appendChild(left);
  const actions = document.createElement("div");
  actions.className = "history-actions";

  const loadBtn = document.createElement("button");
  loadBtn.type = "button";
  loadBtn.textContent = "load";
  loadBtn.addEventListener("click", async () => {
    const res = await fetch("/history/scan/" + entry.id);
    if (!res.ok) return;
    const data = await res.json();
    renderInvestigatorSummary(data.payload || {});
    scanOutput.textContent = JSON.stringify(data.payload, null, 2);
    scanStatus.textContent = "loaded history scan #" + entry.id;
  });
  actions.appendChild(loadBtn);

  const linkBtn = document.createElement("button");
  linkBtn.type = "button";
  linkBtn.textContent = "link";
  linkBtn.disabled = !activeCaseId;
  linkBtn.addEventListener("click", () => linkHistoryScanToCase(entry.id, username));
  actions.appendChild(linkBtn);

  li.appendChild(actions);
  return li;
}

async function refreshHistory(username) {
  const clean = (username || "").trim();
  if (!clean) return;
  currentHistoryUsername = clean;
  historyStatus.textContent = "loading history for " + clean + "...";
  historyList.innerHTML = "";
  historyDiff.textContent = "";
  try {
    const [listRes, diffRes] = await Promise.all([
      fetch("/history/" + encodeURIComponent(clean)),
      fetch("/history/" + encodeURIComponent(clean) + "/diff"),
    ]);
    if (!listRes.ok) {
      historyStatus.textContent = "error: HTTP " + listRes.status;
      return;
    }
    const listData = await listRes.json();
    historyStatus.textContent = listData.count + " saved scan(s) for " + clean;
    for (const entry of listData.entries || []) {
      historyList.appendChild(renderHistoryEntry(entry, clean));
    }
    if (diffRes.ok) {
      renderHistoryDiff(await diffRes.json());
    } else if (diffRes.status === 404) {
      historyDiff.textContent = "no previous scan";
    }
  } catch (err) {
    historyStatus.textContent = "history error: " + err.message;
  }
}

historyForm.addEventListener("submit", (ev) => {
  ev.preventDefault();
  const fd = new FormData(historyForm);
  const username = (fd.get("username") || "").toString().trim();
  if (!username) return;
  refreshHistory(username);
});

refreshCases();
refreshWatchlist();
refreshCapabilities();
refreshPlatformCatalog();
refreshJobs();
updateScanCaseTarget();

const searchForm = document.getElementById("search-form");
const searchStatus = document.getElementById("search-status");
const searchResults = document.getElementById("search-results");

function fmtSearchTs(ts) {
  try {
    return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 16);
  } catch (_) {
    return String(ts);
  }
}

function renderSearchSnippet(raw) {
  return raw
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("[", "<mark>")
    .replaceAll("]", "</mark>");
}

searchForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(searchForm);
  const q = (fd.get("q") || "").toString().trim();
  const username = (fd.get("username") || "").toString().trim();
  searchResults.innerHTML = "";
  if (!q) {
    searchStatus.textContent = "empty query";
    return;
  }
  searchStatus.textContent = "searching…";
  const params = new URLSearchParams({ q: q, limit: "20" });
  if (username) params.set("username", username);
  try {
    const res = await fetch("/search?" + params.toString());
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      searchStatus.textContent = "error: " + (err.detail || res.status);
      return;
    }
    const data = await res.json();
    const n = data.count || 0;
    searchStatus.textContent = n + " match" + (n === 1 ? "" : "es");
    for (const hit of data.hits || []) {
      const li = document.createElement("li");
      li.className = "search-hit";
      const head = document.createElement("div");
      head.className = "search-hit-head";
      const who = document.createElement("strong");
      who.textContent = hit.username;
      const idTag = document.createElement("span");
      idTag.className = "search-hit-id";
      idTag.textContent = "#" + hit.id;
      const when = document.createElement("span");
      when.className = "search-hit-ts";
      when.textContent = fmtSearchTs(hit.ts);
      const badge = document.createElement("span");
      badge.className = "search-hit-count";
      badge.textContent = hit.found_count + " found";
      head.appendChild(who);
      head.appendChild(idTag);
      head.appendChild(when);
      head.appendChild(badge);
      li.appendChild(head);
      if (hit.snippet) {
        const snip = document.createElement("div");
        snip.className = "search-hit-snippet";
        snip.innerHTML = renderSearchSnippet(hit.snippet);
        li.appendChild(snip);
      }
      searchResults.appendChild(li);
    }
  } catch (err) {
    searchStatus.textContent = "network error: " + err.message;
  }
});
