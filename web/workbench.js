/* Case-scoped evidence view. No scans run without a lead-button action. */
(() => {
  "use strict";
  let graph = null;
  const el = (tag, text, className) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  async function api(path, options = {}) {
    const token = localStorage.getItem("osint_token");
    const response = await fetch(path, {
      ...options,
      headers: {"Content-Type": "application/json", ...(token ? {Authorization: `Bearer ${token}`} : {}), ...options.headers},
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    return data;
  }
  const when = ts => new Date(ts * 1000).toISOString();

  window.renderCaseWorkbench = async (caseId, host) => {
    const panel = el("section", undefined, "case-workbench");
    host.appendChild(panel);
    const title = el("h3", "Evidence workbench");
    const status = el("p", "Loading linked scans…");
    panel.append(title, status);
    const refresh = async () => {
      panel.remove();
      await window.renderCaseWorkbench(caseId, host);
    };
    try {
      const view = await api(`/cases/${caseId}/workbench`);
      if (!host.isConnected) return;
      const summary = view.summary;
      status.textContent = `${summary.scans} linked scans · ${summary.nodes} entities · ${summary.edges} evidence links`;
      const reload = el("button", "Refresh evidence / jobs");
      reload.type = "button";
      reload.onclick = refresh;
      panel.append(reload, el("p", "Query nodes are research subjects, not proven people. Analyst decisions never overwrite deterministic verdicts.", "muted"));
      if (view.warnings.length) panel.append(el("p", view.warnings.join(" · "), "workbench-warning"));

      const canvas = el("div", undefined, "case-evidence-graph");
      const inspector = el("div", "Select an evidence link to inspect its sources.", "evidence-inspector");
      panel.append(canvas, inspector);
      function inspect(edge) {
        inspector.replaceChildren(el("h4", `${edge.relation} — ${edge.verdict}`));
        if (edge.analyst_review) inspector.append(el("p", `Analyst: ${edge.analyst_review.decision} · ${edge.analyst_review.author} · ${edge.analyst_review.note}`));
        for (const proof of edge.observations) {
          inspector.append(el("p", `Scan #${proof.scan_id} · ${proof.checked_at || "observation time unknown"} · HTTP ${proof.http_status ?? "?"} · ${proof.presence}`));
          // Render sources as text, not navigable untrusted schemes.
          inspector.append(el("code", proof.source_url || "source URL unavailable"));
          inspector.append(el("p", `${proof.contract_revision || "legacy contract"} · ${(proof.reason_codes || []).join(", ")}`));
        }
        for (const proof of edge.identity_evidence || []) inspector.append(el("p", proof.detail || JSON.stringify(proof)));
        const note = el("input");
        note.placeholder = "Analyst rationale (optional)";
        note.maxLength = 2000;
        inspector.append(note);
        for (const decision of ["accepted", "rejected", "unreviewed"]) {
          const button = el("button", decision);
          button.type = "button";
          button.onclick = async () => {
            button.disabled = true;
            try {
              await api(`/cases/${caseId}/edges/${encodeURIComponent(edge.id)}/review`, {method: "PUT", body: JSON.stringify({decision, note: note.value})});
              await refresh();
            } catch (error) { status.textContent = error.message; button.disabled = false; }
          };
          inspector.append(button);
        }
      }
      if (graph) { graph.destroy(); graph = null; }
      if (typeof window.cytoscape === "function" && summary.nodes <= 500) {
        graph = window.cytoscape({
          container: canvas, elements: [...view.graph.nodes, ...view.graph.edges],
          style: [
            {selector: "node", style: {label: "data(label)", "background-color": "#4ca9bd", color: "#d9e4ee", "font-size": 11, "text-wrap": "wrap", "text-max-width": 130}},
            {selector: 'node[kind="query"]', style: {shape: "diamond", "background-color": "#f0b95c"}},
            {selector: "edge", style: {width: 2, "line-color": "#637789", "target-arrow-color": "#637789", "target-arrow-shape": "triangle", "curve-style": "bezier"}},
            {selector: 'edge[relation="identity_candidate"]', style: {"line-style": "dashed", "line-color": "#f0b95c"}},
          ],
          layout: {name: "cose", animate: false, randomize: false},
        });
        graph.on("tap", "edge", event => inspect(event.target.data()));
      } else {
        canvas.classList.add("graph-unavailable");
        canvas.textContent = "Graph renderer unavailable or graph exceeds 500 nodes. Evidence remains available below.";
      }
      const evidence = el("details");
      evidence.append(el("summary", "Evidence list (first 150 links)"));
      for (const {data} of view.graph.edges.slice(0, 150)) {
        const button = el("button", `${data.relation} · ${data.verdict} · ${data.observations.length} observations`);
        button.type = "button";
        button.onclick = () => inspect(data);
        evidence.append(button);
      }
      panel.append(evidence, el("h4", "Timeline — scan observations, not account creation dates"));
      const timeline = el("ol", undefined, "case-timeline");
      for (const event of view.timeline.slice(0, 100)) {
        const row = el("li", `${when(event.ts)} · scan #${event.scan_id} · ${event.kind}`);
        if (event.changes) row.append(el("pre", JSON.stringify(event.changes, null, 2)));
        if (event.evidence) row.append(el("code", event.evidence.source_url));
        timeline.append(row);
      }
      panel.append(timeline);
      if (view.timeline.length > 100) panel.append(el("p", "Showing latest 100 events; full timeline is available in the case workbench API."));

      panel.append(el("h4", "Controlled public-profile leads"));
      const budget = view.budget;
      panel.append(el("p", `Case reservations: ${budget.reserved_pivots}/${budget.max_pivots} pivots · ${budget.reserved_requests}/${budget.max_requests} HTTP attempts. Maximum depth: 2. No automatic follow-up.`));
      const choices = el("fieldset");
      choices.append(el("legend", "Allowed providers"));
      const checks = view.allowed_platforms.map((platform, index) => {
        const check = el("input"); check.type = "checkbox"; check.value = platform; check.checked = index < 4;
        const label = el("label", platform); label.prepend(check); choices.append(label);
        return check;
      });
      const requestBudget = el("input");
      requestBudget.type = "number"; requestBudget.min = "1"; requestBudget.max = "20"; requestBudget.value = "8";
      const budgetLabel = el("label", "HTTP attempts per lead (including retries): "); budgetLabel.append(requestBudget);
      panel.append(choices, budgetLabel);
      for (const lead of view.leads) {
        const row = el("div", undefined, "workbench-lead");
        row.append(el("span", `${lead.username} · depth ${lead.depth} · ${lead.verdict} · ${lead.reason} · scan #${lead.source_scan_id}`));
        const button = el("button", lead.eligible ? "Run this lead" : lead.blocked_reason);
        button.type = "button"; button.disabled = !lead.eligible;
        button.onclick = async () => {
          button.disabled = true;
          try {
            await api(`/cases/${caseId}/pivots`, {method: "POST", body: JSON.stringify({lead_id: lead.id, platforms: checks.filter(c => c.checked).map(c => c.value), request_budget: Number(requestBudget.value)})});
            await refresh();
          } catch (error) { status.textContent = error.message; button.disabled = false; }
        };
        row.append(button); panel.append(row);
      }
      if (!view.leads.length) panel.append(el("p", "No unscanned public-profile leads in these linked snapshots."));
      for (const pivot of view.pivots) {
        const row = el("p", `${pivot.username} · ${pivot.status} · reserved ${pivot.request_budget} requests`);
        if (["queued", "running"].includes(pivot.status)) {
          const stop = el("button", "Cancel"); stop.type = "button";
          stop.onclick = async () => {
            try { await api(`/scan-jobs/${encodeURIComponent(pivot.job_id)}/cancel`, {method: "POST"}); await refresh(); }
            catch (error) { status.textContent = error.message; }
          };
          row.append(stop);
        }
        panel.append(row);
      }
    } catch (error) { status.textContent = error.message; }
  };
})();
