/* CISA IOC Extractor: frontend
 * All DOM is built with textContent (no innerHTML with data) so a crafted
 * STIX file can't inject markup.
 */
(() => {
  "use strict";

  // ------------------------------------------------------------------ state
  const state = {
    files: [],          // {name, size, content}
    result: null,       // last API response
  };

  // ------------------------------------------------------------------ dom
  const $ = (sel) => document.querySelector(sel);
  const dropzone = $("#dropzone");
  const fileInput = $("#file-input");
  const fileList = $("#file-list");
  const btnExtract = $("#btn-extract");
  const btnClear = $("#btn-clear");
  const statusEl = $("#status");
  const optScope = $("#opt-scope");
  const optEarliest = $("#opt-earliest");

  function el(tag, attrs = {}, ...children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k === "dataset") Object.assign(n.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return n;
  }

  const fmtSize = (b) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);

  function setStatus(msg, isError = false) {
    statusEl.textContent = msg;
    statusEl.classList.toggle("error", isError);
  }

  let toastTimer;
  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
  }

  // ------------------------------------------------------------------ clipboard
  async function copyText(text, btn) {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        ok = true;
      }
    } catch (_) { /* fall through */ }
    if (!ok) {
      // fallback for http://<lan-ip> (non-secure context)
      const ta = el("textarea", { style: "position:fixed;left:-9999px;top:0" });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
      ta.remove();
    }
    if (ok) {
      const lines = text.split("\n").filter(Boolean).length;
      toast(`Copied ${lines} line${lines === 1 ? "" : "s"}`);
      if (btn) {
        const orig = btn.textContent;
        btn.classList.add("copied");
        btn.textContent = "Copied";
        setTimeout(() => { btn.classList.remove("copied"); btn.textContent = orig; }, 1200);
      }
    } else {
      toast("Copy failed. Select the text and press Ctrl+C");
    }
  }

  // Excel: protect against formula injection & keep each cell on one line
  function cell(v) {
    let s = String(v ?? "").replace(/[\t\r\n]+/g, " ").trim();
    if (/^[=+\-@]/.test(s)) s = "'" + s;
    return s;
  }
  const csvCell = (v) => {
    const s = cell(v);
    return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };

  function download(name, text, type = "text/plain") {
    const blob = new Blob([text], { type: `${type};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = el("a", { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------------ file handling
  function readFile(file) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsText(file);
    });
  }

  async function addFiles(fileListObj) {
    const incoming = Array.from(fileListObj || []);
    for (const f of incoming) {
      if (state.files.some((x) => x.name === f.name && x.size === f.size)) continue;
      try {
        const content = await readFile(f);
        state.files.push({ name: f.name, size: f.size, content });
      } catch (e) {
        setStatus(`Could not read ${f.name}: ${e}`, true);
      }
    }
    renderFileList();
    if (state.files.length) extract();
  }

  function renderFileList() {
    fileList.replaceChildren(
      ...state.files.map((f, idx) =>
        el("li", {},
          el("span", { class: "fname", title: f.name, text: f.name }),
          el("span", { class: "fsize", text: fmtSize(f.size) }),
          el("button", {
            title: "Remove", "aria-label": `Remove ${f.name}`, text: "✕",
            onclick: () => { state.files.splice(idx, 1); renderFileList(); state.files.length ? extract() : clearResults(); },
          })
        )
      )
    );
    btnExtract.disabled = !state.files.length;
    btnClear.disabled = !state.files.length;
  }

  ["dragenter", "dragover"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add("drag"); })
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove("drag"); })
  );
  dropzone.addEventListener("drop", (e) => addFiles(e.dataTransfer.files));
  fileInput.addEventListener("change", () => { addFiles(fileInput.files); fileInput.value = ""; });
  btnExtract.addEventListener("click", extract);
  btnClear.addEventListener("click", () => { state.files = []; renderFileList(); clearResults(); });

  let optTimer;
  const onOptChange = () => { clearTimeout(optTimer); optTimer = setTimeout(() => state.files.length && extract(), 350); };
  optScope.addEventListener("input", onOptChange);
  optEarliest.addEventListener("change", onOptChange);

  // ------------------------------------------------------------------ API
  async function extract() {
    if (!state.files.length) return;
    btnExtract.disabled = true;
    setStatus("Extracting…");
    try {
      const res = await fetch("/api/extract", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          files: state.files.map(({ name, content }) => ({ name, content })),
          options: { scope: optScope.value.trim() || "index=*", earliest: optEarliest.value },
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || res.statusText);
      state.result = data;
      render(data);
      setStatus(`${data.total} unique items from ${data.reports.length} file(s).`);
    } catch (e) {
      setStatus(`Error: ${e.message}`, true);
    } finally {
      btnExtract.disabled = !state.files.length;
    }
  }

  function clearResults() {
    state.result = null;
    $("#results-body").hidden = true;
    $("#empty-state").hidden = false;
    $("#topbar-meta").textContent = "";
    setStatus("");
  }

  // ------------------------------------------------------------------ rendering helpers
  const SPL_CMDS = /^(\|\s*)(\w+)(.*)$/;
  function splPre(spl) {
    const pre = el("pre");
    spl.split("\n").forEach((line, i) => {
      if (i) pre.append("\n");
      const m = line.match(SPL_CMDS);
      if (m) {
        pre.append(el("span", { class: "pipe", text: m[1] }), el("span", { class: "kw", text: m[2] }), m[3]);
      } else {
        pre.append(line);
      }
    });
    return pre;
  }

  function splBlock(q, recommended) {
    const btn = el("button", { class: "btn btn-xs", text: "Copy SPL" });
    btn.addEventListener("click", () => copyText(q.spl, btn));
    return el("div", { class: "spl" },
      el("div", { class: "spl-head" },
        el("span", { class: "spl-title" }, recommended ? el("span", { class: "rec", text: "Recommended" }) : null, q.title),
        btn
      ),
      splPre(q.spl),
      q.note ? el("p", { class: "spl-note", text: q.note }) : null
    );
  }

  function splSection(queries) {
    if (!queries || !queries.length) return null;
    const [first, ...rest] = queries;
    return el("div", { class: "spl-section" },
      el("h4", { text: "Splunk: recommended broad search" }),
      splBlock(first, true),
      rest.length
        ? el("details", { class: "block" },
            el("summary", { text: `${rest.length} alternative search${rest.length > 1 ? "es" : ""} (CIM / accelerated)` }),
            el("div", { class: "inner" }, rest.map((q) => splBlock(q, false))))
        : null
    );
  }

  function contextTags(item) {
    return (item.context || []).map((c) => {
      let cls = "tag";
      if (/shared infrastructure|private/i.test(c)) cls += " warn";
      else if (/ransom|lockbit/i.test(c)) cls += " danger";
      return el("span", { class: cls, text: c });
    });
  }

  function detailsTable(cat) {
    const isCve = cat.key === "cve";
    const head = ["Value", "Context", isCve ? "Links" : "Related", "Source"];
    const rows = cat.items.map((i) =>
      el("tr", {},
        el("td", { class: "mono", text: i.value }),
        el("td", {}, contextTags(i).length ? contextTags(i) : el("span", { class: "muted", text: "—" })),
        isCve
          ? el("td", { class: "links" },
              i.extra?.nvd ? el("a", { href: i.extra.nvd, target: "_blank", rel: "noopener noreferrer", text: "NVD" }) : null,
              i.extra?.kev ? el("a", { href: i.extra.kev, target: "_blank", rel: "noopener noreferrer", text: "CISA KEV" }) : null)
          : el("td", { class: "mono muted", text: (i.related || []).join(", ") || "—" }),
        el("td", {}, (i.sources || []).map((s) => el("span", { class: "tag ok", text: s })))
      )
    );
    return el("div", { class: "table-wrap" },
      el("table", { class: "data-table" },
        el("thead", {}, el("tr", {}, head.map((h) => el("th", { text: h })))),
        el("tbody", {}, rows)));
  }

  function itemsToTSV(cat, withHeader = true) {
    const lines = cat.items.map((i) =>
      [cat.label, i.value, (i.context || []).join("; "), (i.related || []).join("; "), (i.sources || []).join("; ")].map(cell).join("\t"));
    return (withHeader ? ["Category\tValue\tContext\tRelated\tSource"] : []).concat(lines).join("\n");
  }

  function cardShell(cat, extraActions = []) {
    const listText = cat.items.map((i) => i.value).join("\n");
    const btnList = el("button", { class: "btn btn-small", text: "Copy list" });
    btnList.addEventListener("click", () => copyText(listText, btnList));
    const btnTable = el("button", { class: "btn btn-small", text: "Copy with context" });
    btnTable.addEventListener("click", () => copyText(itemsToTSV(cat), btnTable));
    return {
      listText,
      head: el("div", { class: "card-head" },
        el("h3", { class: "card-title" }, cat.label, el("span", { class: "badge", text: cat.items.length })),
        el("div", { class: "card-actions" }, btnList, btnTable, extraActions)),
    };
  }

  function standardCard(cat) {
    const { listText, head } = cardShell(cat);
    const ta = el("textarea", {
      class: "ioc-list", readonly: true, spellcheck: "false",
      rows: Math.min(Math.max(cat.items.length, 3), 12),
      "aria-label": `${cat.label} list`,
    });
    ta.value = listText;
    ta.addEventListener("focus", () => ta.select());

    return el("article", { class: "card", id: `cat-${cat.key}`, dataset: { group: cat.group } },
      head,
      el("div", { class: "card-body" },
        cat.note ? el("div", { class: "card-note", text: cat.note }) : null,
        ta,
        el("details", { class: "block" },
          el("summary", { text: "Details: context, related hashes/files, source advisory" }),
          el("div", { class: "inner" }, detailsTable(cat))),
        splSection(cat.splunk)
      )
    );
  }

  function techniqueCard(cat) {
    const { listText, head } = cardShell(cat);
    const withHunt = cat.items.filter((i) => i.extra?.hunts?.length);
    let onlyHunts = true;

    const tbody = el("tbody");
    const draw = () => {
      const items = onlyHunts ? withHunt : cat.items;
      tbody.replaceChildren(...items.flatMap((i) => {
        const tid = i.value;
        const url = i.extra?.url;
        const hunts = i.extra?.hunts || [];
        const row = el("tr", { class: "tech-row" },
          el("td", {}, url ? el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: tid }) : tid),
          el("td", {}, (i.context || []).join(" / ")),
          el("td", {}, (i.sources || []).map((s) => el("span", { class: "tag ok", text: s }))),
          el("td", {}, hunts.length ? el("span", { class: "tag ok", text: `${hunts.length} hunt${hunts.length > 1 ? "s" : ""}` })
                                    : el("span", { class: "tech-pointer", text: i.extra?.pointer || "" }))
        );
        if (!hunts.length) return [row];
        const huntRow = el("tr", {},
          el("td", { colspan: "4", class: "tech-hunts" },
            el("details", { class: "block" },
              el("summary", { text: `Splunk hunt for ${tid}` }),
              el("div", { class: "inner" }, hunts.map((q, n) => splBlock(q, n === 0))))));
        return [row, huntRow];
      }));
    };

    const toggle = el("input", { type: "checkbox", checked: true });
    toggle.addEventListener("change", () => { onlyHunts = toggle.checked; draw(); });
    draw();

    const ta = el("textarea", { class: "ioc-list", readonly: true, rows: 4, "aria-label": "Technique IDs" });
    ta.value = listText;

    return el("article", { class: "card", id: `cat-${cat.key}`, dataset: { group: cat.group } },
      head,
      el("div", { class: "card-body" },
        el("div", { class: "tech-toolbar" },
          el("label", {}, toggle, `Only show techniques with a Splunk hunt (${withHunt.length} of ${cat.items.length})`)),
        el("div", { class: "table-wrap" },
          el("table", { class: "data-table" },
            el("thead", {}, el("tr", {}, ["Technique", "Tactic / Name", "Source", "Hunt"].map((h) => el("th", { text: h })))),
            tbody)),
        el("details", { class: "block" }, el("summary", { text: "Plain list of technique IDs" }), el("div", { class: "inner" }, ta))
      )
    );
  }

  // ------------------------------------------------------------------ main render
  function render(data) {
    $("#empty-state").hidden = true;
    $("#results-body").hidden = false;
    $("#topbar-meta").textContent = `${data.reports.length} advisory file(s) · ${data.total} items`;

    // summary stats (by group)
    const groups = {};
    data.categories.forEach((c) => { groups[c.group] = (groups[c.group] || 0) + c.items.length; });
    $("#summary-stats").replaceChildren(
      ...Object.entries(groups).map(([g, n]) => el("div", { class: "stat", dataset: { group: g } }, el("b", { text: n }), el("span", { text: g })))
    );

    // reports
    $("#reports-table tbody").replaceChildren(
      ...data.reports.map((r) =>
        el("tr", {},
          el("td", { class: "mono", text: r.source }),
          el("td", { text: r.title || "" }),
          el("td", { class: "mono", text: r.published || "—" }),
          el("td", { class: "mono", text: r.indicators ?? "" }),
          el("td", { class: "mono muted", text: r.file + (r.note ? ` (${r.note})` : "") })))
    );
    $("#error-list").replaceChildren(...(data.errors || []).map((e) => el("li", { text: e })));

    // nav
    $("#cat-nav").replaceChildren(
      ...data.categories.map((c) =>
        el("a", { href: `#cat-${c.key}`, dataset: { group: c.group } },
          el("span", { class: "dot" }), c.label, el("span", { class: "n", text: c.items.length })))
    );

    // master sweep
    const master = $("#master-section");
    master.replaceChildren();
    if (data.master && data.master.length) {
      master.append(
        el("article", { class: "card", dataset: { group: "Master" } },
          el("div", { class: "card-head" }, el("h3", { class: "card-title", text: "Master sweep: start here" })),
          el("div", { class: "card-body" }, data.master.map((q, i) => splBlock(q, i === 0)))));
    }

    // categories grouped
    const wrap = $("#categories");
    wrap.replaceChildren();
    let lastGroup = null;
    data.categories.forEach((c) => {
      if (c.group !== lastGroup) {
        wrap.append(el("div", { class: "group-heading", dataset: { group: c.group }, text: c.group }));
        lastGroup = c.group;
      }
      wrap.append(c.key === "technique" ? techniqueCard(c) : standardCard(c));
    });
  }

  // ------------------------------------------------------------------ global exports
  $("#btn-copy-all").addEventListener("click", (e) => {
    if (!state.result) return;
    const lines = ["Category\tValue\tContext\tRelated\tSource"];
    state.result.categories.forEach((c) => lines.push(itemsToTSV(c, false)));
    copyText(lines.filter(Boolean).join("\n"), e.currentTarget);
  });

  $("#btn-csv").addEventListener("click", () => {
    if (!state.result) return;
    const rows = [["Category", "Value", "Context", "Related", "Source"]];
    state.result.categories.forEach((c) =>
      c.items.forEach((i) => rows.push([c.label, i.value, (i.context || []).join("; "), (i.related || []).join("; "), (i.sources || []).join("; ")])));
    const stamp = new Date().toISOString().slice(0, 10);
    download(`cisa_iocs_${stamp}.csv`, "﻿" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n"), "text/csv");
  });

  $("#btn-spl").addEventListener("click", () => {
    if (!state.result) return;
    const out = [];
    const sep = "=".repeat(78);
    const seen = new Set();
    const emit = (heading, q) => {
      if (seen.has(q.spl)) return;
      seen.add(q.spl);
      out.push(sep, `${heading} :: ${q.title}`, q.note ? `NOTE: ${q.note}` : null, sep, q.spl, "");
    };
    (state.result.master || []).forEach((q) => emit("MASTER", q));
    state.result.categories.forEach((c) => {
      (c.splunk || []).forEach((q) => emit(c.label.toUpperCase(), q));
      if (c.key === "technique") {
        c.items.forEach((i) => (i.extra?.hunts || []).forEach((q) => emit(`ATT&CK ${i.value}`, q)));
      }
    });
    const stamp = new Date().toISOString().slice(0, 10);
    download(`splunk_hunts_${stamp}.spl.txt`, out.filter((l) => l !== null).join("\n"));
  });
})();
