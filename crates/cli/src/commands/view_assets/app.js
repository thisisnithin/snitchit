// snitchit view — inlined, no external scripts (offline by design).
// All data-derived text is set via textContent, never innerHTML, so nothing
// in a redacted summary/hash can be interpreted as markup. The timeline is a
// real <table>; clicking a row toggles a detail row beneath it.
(() => {
  const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const COLS = ["Time", "Source", "Type", "Tool", "Status", "Severity"];

  const severityRank = (sev) =>
    Object.hasOwn(SEVERITY_RANK, sev) ? SEVERITY_RANK[sev] : 0;

  const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

  const el = (tag, opts = {}) => {
    const e = document.createElement(tag);
    if (opts.className) e.className = opts.className;
    if (opts.text !== undefined) e.textContent = opts.text;
    return e;
  };

  const loadData = () =>
    JSON.parse(document.getElementById("snitchit-data").textContent);

  const renderHeader = (data) => {
    const meta = document.getElementById("session-meta");
    meta.textContent = `Session: ${data.session}  ·  ${plural(data.records.length, "record")}`;

    const banner = document.getElementById("chain-banner");
    const text = el("span");
    if (data.verify.ok) {
      banner.className = "intact";
      text.textContent = `Chain verified — ${plural(data.verify.count, "record")}, intact to the head`;
    } else {
      banner.className = "broken";
      const reason = data.verify.brokenAt
        ? `record ${data.verify.brokenAt.index} — ${data.verify.brokenAt.reason}`
        : "unknown break";
      text.textContent = `Chain broken — ${reason}`;
    }
    banner.replaceChildren(text);
  };

  const fieldRow = (label, valueText) => {
    const wrap = el("div", { className: "detail-field" });
    wrap.appendChild(el("div", { className: "label", text: label }));
    wrap.appendChild(el("div", { className: "value", text: valueText }));
    return wrap;
  };

  const buildDetail = (rec) => {
    const detail = el("div", { className: "detail" });

    detail.appendChild(fieldRow("Input", rec.action?.input?.summary || "(none)"));
    detail.appendChild(fieldRow("Outcome", rec.outcome?.summary || "(none)"));

    const findingsWrap = el("div", { className: "detail-field" });
    const count = rec.findings?.length || 0;
    findingsWrap.appendChild(el("div", { className: "label", text: `Findings (${count})` }));
    const findingsList = el("div", { className: "findings" });
    if (count > 0) {
      rec.findings.forEach((f) => {
        const row = el("div", { className: "finding-row" });
        row.appendChild(el("span", { className: "fkind", text: f.type }));
        row.appendChild(el("span", { text: f.severity }));
        row.appendChild(el("span", { text: f.sample }));
        findingsList.appendChild(row);
      });
    } else {
      findingsList.appendChild(el("div", { className: "none", text: "none" }));
    }
    findingsWrap.appendChild(findingsList);
    detail.appendChild(findingsWrap);

    const hashWrap = el("div", { className: "detail-field" });
    hashWrap.appendChild(el("div", { className: "label", text: "Integrity" }));
    const grid = el("div", { className: "hash-grid" });
    [
      ["record_id", rec.record_id || ""],
      ["prev_hash", rec.integrity?.prev_hash || ""],
      ["hash", rec.integrity?.hash || ""],
    ].forEach((pair) => {
      grid.appendChild(el("div", { className: "k", text: pair[0] }));
      grid.appendChild(el("div", { className: "v", text: pair[1] }));
    });
    hashWrap.appendChild(grid);
    detail.appendChild(hashWrap);

    return detail;
  };

  const cell = (className, child) => {
    const td = el("td", { className });
    if (child) td.appendChild(child);
    return td;
  };

  // Returns [dataRow, detailRow]. detailRow starts hidden; clicking the data
  // row toggles it. Filtering hides both together.
  const buildRows = (rec) => {
    const sourceAdapter = rec.source?.adapter || "?";
    const actionType = rec.action?.type || "?";
    const tool = rec.action?.tool || "-";
    const status = rec.outcome ? rec.outcome.status : null;
    const severity = rec.severity || "INFO";
    const summary = rec.action?.input?.summary || "—";

    const tr = el("tr", { className: "record" });
    tr.dataset.source = sourceAdapter;
    tr.dataset.type = actionType;
    tr.dataset.status = status || "__none__";
    tr.dataset.severityRank = String(severityRank(severity));
    tr.dataset.search = `${tool} ${summary} ${rec.outcome?.summary || ""}`.toLowerCase();

    tr.appendChild(cell("col-ts", el("span", { text: rec.ts || "" })));
    tr.appendChild(cell("col-tag", el("span", { className: `badge src-${sourceAdapter}`, text: sourceAdapter })));
    tr.appendChild(cell("col-tag", el("span", { className: `badge type-${actionType}`, text: actionType })));
    tr.appendChild(cell("col-tool", el("span", { className: "tool-name", text: tool })));

    let statusEl;
    if (status) {
      // Glyph-only (see CSS); the word is kept as a tooltip / a11y label.
      statusEl = el("span", { className: `status-pill ${status}` });
      statusEl.title = status;
      statusEl.setAttribute("aria-label", status);
    } else {
      statusEl = el("span", { className: "status-pill none", text: "—" });
    }
    tr.appendChild(cell("col-status", statusEl));
    tr.appendChild(cell("col-sev", el("span", { className: `severity-pill sev-${severity.toLowerCase()}`, text: severity })));

    const detailRow = el("tr", { className: "detail-row" });
    detailRow.style.display = "none";
    const dtd = el("td");
    dtd.colSpan = COLS.length;
    dtd.appendChild(buildDetail(rec));
    detailRow.appendChild(dtd);

    tr.addEventListener("click", () => {
      const open = tr.classList.toggle("expanded");
      detailRow.style.display = open ? "table-row" : "none";
    });

    return [tr, detailRow];
  };

  const currentFilters = () => ({
    sources: [...document.querySelectorAll(".f-source:checked")].map((i) => i.value),
    types: [...document.querySelectorAll(".f-type:checked")].map((i) => i.value),
    status: document.getElementById("f-status").value,
    minSeverity: parseInt(document.getElementById("f-severity").value, 10) || 0,
    search: document.getElementById("f-search").value.trim().toLowerCase(),
  });

  const matches = (tr, f) => {
    if (!f.sources.includes(tr.dataset.source)) return false;
    if (!f.types.includes(tr.dataset.type)) return false;
    if (f.status && tr.dataset.status !== f.status) return false;
    if (parseInt(tr.dataset.severityRank, 10) < f.minSeverity) return false;
    if (f.search && !tr.dataset.search.includes(f.search)) return false;
    return true;
  };

  const applyFilters = () => {
    const f = currentFilters();
    const rows = document.querySelectorAll("#timeline tr.record");
    let shown = 0;
    rows.forEach((tr) => {
      const ok = matches(tr, f);
      tr.style.display = ok ? "" : "none";
      if (ok) shown += 1;
      const d = tr.nextElementSibling;
      if (d?.classList.contains("detail-row")) {
        d.style.display = ok && tr.classList.contains("expanded") ? "table-row" : "none";
      }
    });
    document.getElementById("count").textContent = `Showing ${shown} of ${rows.length} records`;

    const empty = document.getElementById("empty-state");
    if (empty) empty.style.display = shown === 0 ? "block" : "none";
  };

  const wireControls = () => {
    document
      .querySelectorAll(".f-source, .f-type, #f-status, #f-severity, #f-search")
      .forEach((c) => {
        const evt = c.tagName === "INPUT" && c.type === "text" ? "input" : "change";
        c.addEventListener(evt, applyFilters);
      });
  };

  document.addEventListener("DOMContentLoaded", () => {
    const data = loadData();
    renderHeader(data);

    const timeline = document.getElementById("timeline");

    if (data.records.length === 0) {
      const empty = el("div", { text: "No records in this session." });
      empty.id = "empty-state";
      timeline.appendChild(empty);
      wireControls();
      applyFilters();
      return;
    }

    const table = el("table", { className: "log" });
    const thead = el("thead");
    const headRow = el("tr");
    COLS.forEach((label) => {
      headRow.appendChild(el("th", { text: label }));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = el("tbody");
    // Display in chronological order. On-disk order is append order, which is
    // not chronological (PTY events flush at session end; hook events write
    // live), so a typed prompt can appear after the tool calls it caused. The
    // chain banner above is computed over on-disk order server-side; this sort
    // is display-only. `ts` is RFC 3339 UTC, so lexicographic == chronological.
    const ordered = [...data.records].sort((a, b) =>
      (a.ts || "").localeCompare(b.ts || ""),
    );
    ordered.forEach((rec) => {
      const [dataRow, detailRow] = buildRows(rec);
      tbody.appendChild(dataRow);
      tbody.appendChild(detailRow);
    });
    table.appendChild(tbody);
    timeline.appendChild(table);

    const empty = el("div", { text: "No records match the current filters." });
    empty.id = "empty-state";
    empty.style.display = "none";
    timeline.appendChild(empty);

    wireControls();
    applyFilters();
  });
})();
