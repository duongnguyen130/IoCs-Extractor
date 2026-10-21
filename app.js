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
          el("span", { class: "fname", title: f.name },
            f.pasted ? el("span", { class: "tag-pasted", text: "pasted" }) : null, f.name),
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

  // ------------------------------------------------------------------ paste JSON / text
  const pasteBlock = $("#paste-block");
  const pasteInput = $("#paste-input");
  const pasteName = $("#paste-name");
  const pasteHint = $("#paste-hint");
  const btnPasteAdd = $("#btn-paste-add");
  const btnPasteFormat = $("#btn-paste-format");
  const AA_RE = /\bAA\d{2}-\d{3}[A-Z]?\b/i;
  let pasteCount = 0;

  function analyzePaste(text) {
    const t = text.trim();
    if (!t) return { kind: "empty" };
    if (/^[\[{]/.test(t)) {
      try {
        const obj = JSON.parse(t);
        const objs = Array.isArray(obj) ? obj : obj.objects || [obj];
        const n = objs.filter((o) => o && o.type === "indicator").length;
        const report = objs.find((o) => o && o.type === "report");
        return { kind: "json", obj, indicators: n, title: report?.name || "" };
      } catch (e) {
        return { kind: "badjson", error: e.message };
      }
    }
    return { kind: "text" };
  }

  function updatePasteHint() {
    const a = analyzePaste(pasteInput.value);
    pasteInput.classList.toggle("invalid", a.kind === "badjson");
    pasteHint.className = "";
    btnPasteAdd.disabled = a.kind === "empty";
    btnPasteFormat.disabled = a.kind !== "json";
    if (a.kind === "empty") pasteHint.textContent = "STIX JSON is parsed fully. Anything else is scanned with regex.";
    else if (a.kind === "json") {
      pasteHint.className = "ok";
      pasteHint.textContent = `Valid JSON: ${a.indicators} indicator(s)${a.title ? " · " + a.title : ""}`;
    } else if (a.kind === "badjson") {
      pasteHint.className = "bad";
      pasteHint.textContent = `Invalid JSON (${a.error}). It will be scanned as plain text if added.`;
    } else pasteHint.textContent = "Plain text, scanned with regex for IPs, domains, URLs, hashes, CVEs.";
    return a;
  }

  function addPasted(text, nameHint = "") {
    const a = analyzePaste(text);
    if (a.kind === "empty") return;
    let base = nameHint.trim() || ((a.title || "").match(AA_RE)?.[0]) || (text.match(AA_RE)?.[0]) || `pasted-${++pasteCount}`;
    base = base.replace(/[^\w.\- ]/g, "_").slice(0, 60);
    const ext = a.kind === "json" ? ".json" : ".txt";
    let name = base.toLowerCase().endsWith(ext) ? base : base + ext;
    if (state.files.some((f) => f.content === text)) { toast("That content is already loaded"); return; }
    while (state.files.some((f) => f.name === name)) name = `${base}-${++pasteCount}${ext}`;
    state.files.push({ name, size: new Blob([text]).size, content: text, pasted: true });
    renderFileList();
    extract();
    toast(`Added ${name}`);
  }

  pasteInput.addEventListener("input", updatePasteHint);
  btnPasteFormat.addEventListener("click", () => {
    const a = analyzePaste(pasteInput.value);
    if (a.kind === "json") { pasteInput.value = JSON.stringify(a.obj, null, 2); updatePasteHint(); }
  });
  btnPasteAdd.addEventListener("click", () => {
    addPasted(pasteInput.value, pasteName.value);
    pasteInput.value = "";
    pasteName.value = "";
    updatePasteHint();
  });
  pasteInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !btnPasteAdd.disabled) btnPasteAdd.click();
  });

  // Ctrl+V anywhere on the page (outside a text field) adds the clipboard directly
  document.addEventListener("paste", (e) => {
    const tgt = e.target;
    if (tgt instanceof HTMLElement && (tgt.closest("input, textarea, select") || tgt.isContentEditable)) return;
    const text = e.clipboardData?.getData("text") || "";
    if (!text.trim()) return;
    e.preventDefault();
    pasteBlock.open = true;
    addPasted(text);
  });

  let optTimer;
  const onOptChange = () => { clearTimeout(optTimer); optTimer = setTimeout(() => state.files.length && extract(), 350); };
  optScope.addEventListener("input", onOptChange);

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
          options: { scope: optScope.value.trim() || "index=*" },
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
  function splSection(spl) {
    if (!spl) return null;
    const btn = el("button", { class: "btn btn-xs", type: "button", text: "Copy SPL" });
    btn.addEventListener("click", () => copyText(spl, btn));
    return el("details", { class: "block spl-toggle" },
      el("summary", { text: "Splunk: recommended broad search" }),
      el("div", { class: "inner" },
        el("div", { class: "spl" },
          el("div", { class: "spl-head" }, el("span", { class: "spl-title", text: `${spl.length.toLocaleString()} characters` }), btn),
          el("pre", { text: spl }))));
  }

  function itemsToTSV(cat, withHeader = true) {
    const lines = cat.items.map((i) =>
      [cat.label, i.value, (i.context || []).join("; "), (i.related || []).join("; "), (i.sources || []).join("; ")].map(cell).join("\t"));
    return (withHeader ? ["Category\tValue\tContext\tRelated\tSource"] : []).concat(lines).join("\n");
  }

  function card(cat) {
    const listText = cat.items.map((i) => i.value).join("\n");
    const btnList = el("button", { class: "btn btn-small", type: "button", text: "Copy list" });
    btnList.addEventListener("click", () => copyText(listText, btnList));
    const btnTable = el("button", { class: "btn btn-small", type: "button", text: "Copy with context" });
    btnTable.addEventListener("click", () => copyText(itemsToTSV(cat), btnTable));

    const ta = el("textarea", {
      class: "ioc-list", readonly: true, spellcheck: "false",
      rows: Math.min(Math.max(cat.items.length, 3), 12),
      "aria-label": `${cat.label} list`,
    });
    ta.value = listText;
    ta.addEventListener("focus", () => ta.select());

    return el("article", { class: "card", id: `cat-${cat.key}`, dataset: { group: cat.group } },
      el("div", { class: "card-head" },
        el("h3", { class: "card-title" }, cat.label, el("span", { class: "badge", text: cat.items.length })),
        el("div", { class: "card-actions" }, btnList, btnTable)),
      el("div", { class: "card-body" },
        cat.note ? el("div", { class: "card-note", text: cat.note }) : null,
        ta,
        splSection(cat.spl)));
  }

  // ------------------------------------------------------------------ main render
  function render(data) {
    $("#empty-state").hidden = true;
    $("#results-body").hidden = false;
    $("#topbar-meta").textContent = `${data.reports.length} advisory file(s) · ${data.total} items`;

    const groups = {};
    data.categories.forEach((c) => { groups[c.group] = (groups[c.group] || 0) + c.items.length; });
    $("#summary-stats").replaceChildren(
      ...Object.entries(groups).map(([g, n]) => el("div", { class: "stat", dataset: { group: g } }, el("b", { text: n }), el("span", { text: g })))
    );

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

    $("#cat-nav").replaceChildren(
      ...data.categories.map((c) =>
        el("a", { href: `#cat-${c.key}`, dataset: { group: c.group } },
          el("span", { class: "dot" }), c.label, el("span", { class: "n", text: c.items.length })))
    );

    const wrap = $("#categories");
    wrap.replaceChildren();
    let lastGroup = null;
    data.categories.forEach((c) => {
      if (c.group !== lastGroup) {
        wrap.append(el("div", { class: "group-heading", dataset: { group: c.group }, text: c.group }));
        lastGroup = c.group;
      }
      wrap.append(card(c));
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
    state.result.categories.forEach((c) => {
      if (c.spl) out.push(`### ${c.label}`, c.spl, "");
    });
    const stamp = new Date().toISOString().slice(0, 10);
    download(`splunk_searches_${stamp}.txt`, out.join("\n"));
  });
})();
