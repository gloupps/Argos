// app/static/js/modules/case_report.js
// Generates a standalone HTML report file and triggers download.
// The file contains an executive summary + collapsible per-IOC annexe.
// Graph is captured via Cytoscape cy.png() (async Promise form).

window.CaseReport = {

    // ── Entry point ───────────────────────────────────────────────

    async generate(caseId) {
        if (!caseId) return;
        const caseName = document.getElementById("case-name-display")?.textContent?.trim() || caseId.slice(0, 8);
        JobLog?.push?.({ message: "📄 Building report…", status: "running" });

        try {
            const [allInfo, graphData] = await Promise.all([
                fetch(`/api/cases/${caseId}/info`).then(r => r.json()),
                fetch(`/api/cases/${caseId}/graph`).then(r => r.json()),
            ]);

            // Capture graph PNG — cy.png with full:true returns a string synchronously
            // when output:"base64uri", but we wrap in try/catch per instance
            const graphPng = this._captureGraph(caseId);

            const summary  = this._computeSummary(allInfo, graphData);
            const html     = this._buildHtml(caseName, summary, allInfo, graphPng);

            this._download(html, caseName);
            JobLog?.push?.({ message: "📄 Report downloaded", status: "done" });

        } catch (err) {
            console.error("[CaseReport] error", err);
            JobLog?.push?.({ message: `Report error: ${err.message}`, status: "failed" });
        }
    },

    // ── Graph capture ─────────────────────────────────────────────

    _captureGraph(caseId) {
        try {
            const instances = GraphModule?.instances || {};
            for (const inst of Object.values(instances)) {
                if (inst?.caseId !== caseId) continue;
                const cy = inst.cy;
                if (!cy || typeof cy.png !== "function") continue;
                // cy.png() with output:"base64uri" is synchronous in Cytoscape 3.x
                // full:true renders all elements regardless of viewport
                const png = cy.png({ output: "base64uri", bg: "#0f172a", full: true, scale: 2 });
                if (png && png.startsWith("data:image")) return png;
            }
        } catch (e) {
            console.warn("[CaseReport] graph capture failed:", e);
        }
        return null;
    },

    // ── Download helper ───────────────────────────────────────────

    _download(html, caseName) {
        const blob = new Blob([html], { type: "text/html;charset=utf-8" });
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        const safe = caseName.replace(/[^a-zA-Z0-9_\-]/g, "_").slice(0, 40);
        a.href     = url;
        a.download = `argos_report_${safe}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    },

    // ── Summary computation ───────────────────────────────────────

    _computeSummary(allInfo, graphData) {
        let malicious = 0, suspicious = 0, clean = 0, unknown = 0;
        let totalSiemHits = 0;
        const siemRows = [];
        const modules  = new Set();
        const iocEntries = Object.entries(allInfo || {});

        iocEntries.forEach(([ioc, data]) => {
            let maxScore = null;
            Object.entries(data.modules || {}).forEach(([mod, fields]) => {
                modules.add(mod);
                (fields || []).forEach(f => {
                    if (f.type === "score" && f.value !== null && f.value !== undefined) {
                        const v = Number(f.value);
                        if (!isNaN(v) && (maxScore === null || v > maxScore)) maxScore = v;
                    }
                    if (f.type === "siem_results" && Array.isArray(f.value)) {
                        f.value.forEach(row => {
                            const hits = parseInt(row.hits ?? row.count ?? 0, 10) || 0;
                            totalSiemHits += hits;
                            siemRows.push({
                                ioc,
                                source: mod,
                                index:  row.index || row.log_source || row.source || "—",
                                hits,
                                first:  row.first_seen || row.first || "—",
                                last:   row.last_seen  || row.last  || "—",
                            });
                        });
                    }
                });
            });
            if      (maxScore === null) unknown++;
            else if (maxScore > 70)     malicious++;
            else if (maxScore > 40)     suspicious++;
            else                        clean++;
        });

        let severity = "INFO";
        if      (malicious >= 3 || (malicious > 0 && totalSiemHits > 100)) severity = "HIGH";
        else if (malicious > 0 || suspicious >= 3)                          severity = "MEDIUM";
        else if (suspicious > 0)                                             severity = "LOW";

        let topMalicious = null, topScore = -1;
        iocEntries.forEach(([ioc, data]) => {
            let ms = -1;
            Object.values(data.modules || {}).forEach(fields => {
                (fields || []).forEach(f => { if (f.type === "score") { const v = Number(f.value); if (v > ms) ms = v; } });
            });
            if (ms > topScore) { topScore = ms; topMalicious = { ioc, score: ms, type: data.type }; }
        });

        const pivotCounts = {};
        (graphData.edges || []).forEach(e => {
            if (e.pivot_label) pivotCounts[e.pivot_label] = (pivotCounts[e.pivot_label] || 0) + 1;
        });
        let topPivot = null, maxLinks = 0;
        Object.entries(pivotCounts).forEach(([lbl, cnt]) => { if (cnt > maxLinks) { maxLinks = cnt; topPivot = { label: lbl, links: cnt }; } });

        const families = new Set();
        iocEntries.forEach(([, data]) => {
            Object.values(data.modules || {}).forEach(fields => {
                (fields || []).forEach(f => {
                    if (["Malware Family", "malware_family"].includes(f.name)) {
                        (Array.isArray(f.value) ? f.value : [f.value]).forEach(v => v && families.add(String(v)));
                    }
                });
            });
        });

        return {
            total: iocEntries.length,
            malicious, suspicious, clean, unknown,
            totalSiemHits, severity, siemRows,
            modules: [...modules],
            topMalicious, topPivot,
            families: [...families].slice(0, 3),
            nodeCount:  (graphData.nodes  || []).length,
            pivotCount: (graphData.pivots || []).length,
        };
    },

    // ── HTML builder ──────────────────────────────────────────────

    _buildHtml(caseName, summary, allInfo, graphPng) {
        const now      = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";
        const sevClass = summary.severity.toLowerCase();

        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Argos Report — ${this._esc(caseName)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=JetBrains+Mono&family=Cinzel:wght@400;700&display=swap" rel="stylesheet">
<style>
${this._css()}
</style>
</head>
<body>

<!-- ═══════════════════════════ PAGE 1 — EXECUTIVE SUMMARY ═══════════════════════════ -->
<div class="page">

  <div class="header">
    <div class="logo-row">
      <img class="logo" src="http://localhost:5555/static/images/argos-logo-full.svg" alt="Argos">
    </div>
    <div class="header-right">
      <div class="report-type">Case Report</div>
      <div class="meta">${now}</div>
    </div>
  </div>

  <div class="case-banner">
    <div>
      <div class="case-name">${this._esc(caseName)}</div>
      <div class="case-meta">${summary.total} IOCs &nbsp;·&nbsp; ${summary.modules.length} sources &nbsp;·&nbsp; ${summary.siemRows.length} SIEM results</div>
    </div>
    <div class="sev-badge ${sevClass}">
      <span class="sev-dot ${sevClass}"></span>${summary.severity}
    </div>
  </div>

  <div class="stats-row">
    <div class="stat-box"><div class="stat-val danger">${summary.malicious}</div><div class="stat-label">Malicious</div></div>
    <div class="stat-box"><div class="stat-val warn">${summary.suspicious}</div><div class="stat-label">Suspicious</div></div>
    <div class="stat-box"><div class="stat-val ok">${summary.clean}</div><div class="stat-label">Clean</div></div>
    <div class="stat-box"><div class="stat-val">${summary.totalSiemHits.toLocaleString()}</div><div class="stat-label">SIEM Hits</div></div>
  </div>

  <div class="split">
    <div class="split-col">
      <div class="section-title">Key findings</div>
      ${this._buildFindings(summary, allInfo)}
    </div>
    <div class="split-col">
      <div class="section-title">Recommended actions</div>
      ${this._buildActions(summary)}
    </div>
  </div>

  <div class="section">
    <div class="section-title">IOC overview</div>
    ${this._buildIocTable(allInfo)}
  </div>

  <div class="highlights">
    ${this._buildHighlights(summary)}
  </div>

  ${summary.siemRows.length > 0 ? `<div class="section">
    <div class="section-title">SIEM investigation results</div>
    ${this._buildSiemTable(summary.siemRows)}
  </div>` : ""}

  <div class="footer">
    <span>Argos © 2026 </span><span>Page 1</span>
  </div>
</div>

<!-- ═══════════════════════════ PAGE 2 — GRAPH ═══════════════════════════ -->
${graphPng ? `
<div class="page page-landscape graph-page">
  <div class="graph-header">
    <img class="logo logo-sm" src="http://localhost:5555/static/images/argos-logo-full.svg" alt="Argos">
    <span class="graph-title">Correlation Graph — ${this._esc(caseName)}</span>
    <span class="graph-meta">${summary.nodeCount} nodes · ${summary.pivotCount} pivot nodes</span>
  </div>
  <div class="graph-body">
    <img class="graph-img" src="${graphPng}" alt="Correlation graph">
  </div>
</div>` : ""}

<!-- ═══════════════════════════ PAGE 3+ — ANNEXE ═══════════════════════════ -->
<div class="page annexe-page">

  <div class="header header-sm">
    <div class="logo-row">
      <img class="logo logo-sm" src="http://localhost:5555/static/images/argos-logo-full.svg" alt="Argos">
    </div>
    <div class="header-right">
      <div class="report-type" style="font-size:11pt;">Annexe — Enrichment Detail</div>
      <div class="meta">${this._esc(caseName)}</div>
    </div>
  </div>

  <div class="annexe-intro">
    Click any IOC to expand its full enrichment detail.
  </div>

  ${this._buildAnnexe(allInfo)}

  <div class="footer">
    <span>Argos © 2026 </span><span>Annexe</span>
  </div>
</div>

</body>
</html>`;
    },

    // ── Findings ──────────────────────────────────────────────────

    _buildFindings(summary, allInfo) {
        const items = [];
        if (summary.malicious > 0) {
            const top = Object.entries(allInfo)
                .map(([ioc, d]) => { let ms = -1; Object.values(d.modules||{}).forEach(fs => fs.forEach(f => { if (f.type==="score") { const v=Number(f.value); if(v>ms) ms=v; }})); return {ioc,ms}; })
                .filter(x => x.ms > 70).sort((a,b) => b.ms-a.ms).slice(0,2)
                .map(x => `${x.ioc} (${x.ms})`).join(", ");
            items.push({ cls:"danger", title:`${summary.malicious} malicious IOC${summary.malicious>1?"s":""} confirmed`, desc: top||"Malicious indicators detected." });
        }
        if (summary.topPivot)
            items.push({ cls:"warn", title:"Infrastructure pivot detected", desc:`${summary.topPivot.label} links ${summary.topPivot.links} IOCs in the graph.` });
        if (summary.families.length)
            items.push({ cls:"warn", title:"Malware families identified", desc:`Attributed: ${summary.families.join(", ")}.` });
        if (summary.totalSiemHits > 0)
            items.push({ cls:"danger", title:`${summary.totalSiemHits.toLocaleString()} SIEM events matched`, desc:`Across ${[...new Set(summary.siemRows.map(r=>r.source))].length} source(s).` });
        if (!items.length)
            items.push({ cls:"info", title:"No critical findings", desc:"No malicious IOCs confirmed." });
        return items.slice(0,4).map(i =>
            `<div class="finding ${i.cls}"><div class="finding-title">${this._esc(i.title)}</div><div class="finding-desc">${this._esc(i.desc)}</div></div>`
        ).join("");
    },

    _buildActions(summary) {
        const acts = [];
        if (summary.malicious > 0)      acts.push("Block malicious IPs/domains at perimeter");
        if (summary.totalSiemHits > 0)  acts.push("Investigate matched hosts in SIEM");
        if (summary.topPivot)           acts.push(`Expand investigation on pivot: ${summary.topPivot.label}`);
        if (summary.families.length)    acts.push(`Hunt for ${summary.families[0]} indicators across endpoints`);
        acts.push("Export STIX2 bundle for partner sharing");
        return `<ul class="action-list">${acts.slice(0,5).map(a=>`<li>${this._esc(a)}</li>`).join("")}</ul>`;
    },

    // ── IOC overview table ────────────────────────────────────────

    _buildIocTable(allInfo) {
        const rows = Object.entries(allInfo).map(([ioc, data]) => {
            let maxScore = null;
            const srcHit = [], srcOk = [];
            Object.entries(data.modules||{}).forEach(([mod, fields]) => {
                let ms = -1;
                (fields||[]).forEach(f => { if (f.type==="score") { const v=Number(f.value); if(!isNaN(v)&&v>ms) ms=v; if(maxScore===null||v>maxScore) maxScore=v; } });
                const label = Modules?.registry?.[mod]?.name || mod;
                if (ms > 40) srcHit.push(label); else srcOk.push(label);
            });
            const verdict = maxScore===null?"unknown":maxScore>70?"malicious":maxScore>40?"suspicious":"clean";
            const short = ioc.length > 44 ? ioc.slice(0,42)+"…" : ioc;
            return `<tr>
              <td class="mono">${this._esc(short)}</td>
              <td><span class="badge type-${data.type||"unknown"}">${data.type||"?"}</span></td>
              <td><span class="badge verdict-${verdict}">${verdict}</span></td>
              <td>${srcHit.map(s=>`<span class="src hit">${this._esc(s)}</span>`).join("")}${srcOk.slice(0,3).map(s=>`<span class="src">${this._esc(s)}</span>`).join("")}</td>
            </tr>`;
        }).join("");
        return `<table><thead><tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Sources</th></tr></thead><tbody>${rows}</tbody></table>`;
    },

    // ── Highlights ────────────────────────────────────────────────

    _buildHighlights(summary) {
        const cards = [];
        if (summary.topMalicious) {
            const short = summary.topMalicious.ioc.length > 30 ? summary.topMalicious.ioc.slice(0,28)+"…" : summary.topMalicious.ioc;
            cards.push(`<div class="hl-card"><div class="hl-label">Top malicious IOC</div><div class="hl-val red">${this._esc(short)}</div><div class="hl-sub">Score: ${summary.topMalicious.score} · ${summary.topMalicious.type||"—"}</div></div>`);
        }
        if (summary.topPivot)
            cards.push(`<div class="hl-card"><div class="hl-label">Key pivot</div><div class="hl-val purple">${this._esc(summary.topPivot.label)}</div><div class="hl-sub">${summary.topPivot.links} linked IOCs</div></div>`);
        if (summary.families.length)
            cards.push(`<div class="hl-card"><div class="hl-label">Malware family</div><div class="hl-val amber">${this._esc(summary.families[0])}</div><div class="hl-sub">${summary.families.slice(1).join(", ")||"—"}</div></div>`);
        while (cards.length < 3)
            cards.push(`<div class="hl-card"><div class="hl-label">SIEM hits</div><div class="hl-val amber">${summary.totalSiemHits.toLocaleString()}</div><div class="hl-sub">${[...new Set(summary.siemRows.map(r=>r.source))].join(", ")||"—"}</div></div>`);
        return cards.slice(0,3).join("");
    },

    // ── SIEM table ────────────────────────────────────────────────

    _buildSiemTable(siemRows) {
        const rows = siemRows.sort((a,b)=>b.hits-a.hits).slice(0,30).map(r => {
            const cls = r.hits>100?"many":r.hits>0?"some":"none";
            const short = r.ioc.length>36 ? r.ioc.slice(0,34)+"…" : r.ioc;
            return `<tr><td class="mono">${this._esc(short)}</td><td>${this._esc(r.source)}</td><td class="mono">${this._esc(r.index)}</td><td><span class="badge hits-${cls}">${r.hits.toLocaleString()}</span></td><td>${this._esc(r.first)}</td><td>${this._esc(r.last)}</td></tr>`;
        }).join("");
        return `<table><thead><tr><th>IOC</th><th>Source</th><th>Index / Log source</th><th>Hits</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table>`;
    },

    // ── Annexe — collapsible IOC detail ──────────────────────────

    _buildAnnexe(allInfo) {
        return Object.entries(allInfo).map(([ioc, data]) => {
            let maxScore = null;
            Object.values(data.modules||{}).forEach(fields => fields.forEach(f => {
                if (f.type==="score") { const v=Number(f.value); if(!isNaN(v)&&(maxScore===null||v>maxScore)) maxScore=v; }
            }));
            const verdict = maxScore===null?"unknown":maxScore>70?"malicious":maxScore>40?"suspicious":"clean";

            const modBlocks = Object.entries(data.modules||{}).map(([mod, fields]) => {
                if (!fields?.length) return "";
                const modName = Modules?.registry?.[mod]?.name || mod;
                const fieldRows = fields
                    .filter(f => {
                        if (f.value===null||f.value===undefined||f.value==="") return false;
                        if (Array.isArray(f.value) && !f.value.length) return false;
                        if (["siem_results","text_modal"].includes(f.type)) return false;
                        return true;
                    })
                    .slice(0, 20)
                    .map(f => {
                        const val = Array.isArray(f.value)
                            ? f.value.slice(0,6).join(", ") + (f.value.length>6?` … (+${f.value.length-6})`:"")
                            : String(f.value);
                        const scoreClass = f.type==="score"
                            ? Number(f.value)>70?"score-high":Number(f.value)>40?"score-mid":"score-low"
                            : "";
                        return `<div class="field-row"><span class="field-key">${this._esc(f.name)}</span><span class="field-val ${scoreClass}">${this._esc(val)}</span></div>`;
                    }).join("");
                if (!fieldRows) return "";
                return `<div class="mod-block"><div class="mod-name">${this._esc(modName)}</div><div class="mod-fields">${fieldRows}</div></div>`;
            }).join("");

            if (!modBlocks.trim()) return "";

            const short = ioc.length > 55 ? ioc.slice(0,53)+"…" : ioc;
            return `
<details class="ioc-details">
  <summary class="ioc-summary">
    <span class="ioc-value mono">${this._esc(short)}</span>
    <span class="badge type-${data.type||"unknown"}">${data.type||"?"}</span>
    <span class="badge verdict-${verdict}">${verdict}</span>
    ${maxScore!==null?`<span class="score-inline score-${verdict}">${maxScore}</span>`:""}
    <span class="chevron">▶</span>
  </summary>
  <div class="ioc-body">
    ${modBlocks}
  </div>
</details>`;
        }).join("");
    },

    // ── Escape helper ─────────────────────────────────────────────

    _esc(v) {
        return String(v??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
    },

    // ── Inline CSS for the standalone HTML file ───────────────────

    _css() { return `
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
  font-size: 10pt;
  line-height: 1.5;
  background: #f1f5f9;
  color: #1e293b;
}

/* ── Pages ── */
.page {
  background: #ffffff;
  width: 210mm;
  min-height: 297mm;
  margin: 0 auto 24px;
  box-shadow: 0 2px 12px rgba(0,0,0,0.12);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.page-landscape {
  width: 297mm;
  min-height: 210mm;
}

.annexe-page {
  min-height: unset;
  margin-bottom: 40px;
}

/* ── Header ── */
.header {
  background: #0f172a;
  padding: 18px 28px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}
.header-sm { padding: 10px 28px; }
.logo-row  { display: flex; align-items: center; }
.logo      { height: 40px; width: auto; max-width: 180px; display: block; }
.logo-sm   { height: 28px; max-width: 130px; }
.header-right { text-align: right; }
.report-type  { font-size: 13pt; font-weight: 600; color: #f8fafc; }
.meta         { font-size: 8pt; color: #94a3b8; margin-top: 3px; }

/* ── Case banner ── */
.case-banner {
  background: #1e293b;
  padding: 14px 28px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #334155;
  flex-shrink: 0;
}
.case-name { font-size: 15pt; font-weight: 700; color: #e2e8f0; }
.case-meta { font-size: 8pt; color: #64748b; margin-top: 3px; }

/* ── Severity badge ── */
.sev-badge {
  display: inline-flex; align-items: center; gap: 6px;
  padding: 5px 14px; border-radius: 20px; font-size: 9pt; font-weight: 700;
}
.sev-badge.high   { background: #7f1d1d; color: #fca5a5; }
.sev-badge.medium { background: #78350f; color: #fcd34d; }
.sev-badge.low    { background: #14532d; color: #86efac; }
.sev-badge.info   { background: #1e3a5f; color: #93c5fd; }
.sev-dot { width: 7px; height: 7px; border-radius: 50%; }
.sev-dot.high   { background: #f87171; }
.sev-dot.medium { background: #fbbf24; }
.sev-dot.low    { background: #4ade80; }
.sev-dot.info   { background: #60a5fa; }

/* ── Stats ── */
.stats-row { display: grid; grid-template-columns: repeat(4,1fr); border-bottom: 1px solid #e2e8f0; flex-shrink: 0; }
.stat-box  { background: #f8fafc; padding: 14px 16px; text-align: center; border-right: 1px solid #e2e8f0; }
.stat-box:last-child { border-right: none; }
.stat-val  { font-size: 20pt; font-weight: 700; color: #0f172a; }
.stat-val.danger { color: #dc2626; }
.stat-val.warn   { color: #d97706; }
.stat-val.ok     { color: #16a34a; }
.stat-label { font-size: 7.5pt; color: #64748b; margin-top: 2px; text-transform: uppercase; letter-spacing: .5px; }

/* ── Sections ── */
.section       { padding: 16px 28px; border-bottom: 1px solid #f1f5f9; }
.section-title { font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: .8px; color: #64748b; margin-bottom: 12px; }

/* ── Split ── */
.split     { display: grid; grid-template-columns: 1fr 1fr; border-bottom: 1px solid #f1f5f9; }
.split-col { padding: 16px 28px; }
.split-col:first-child { border-right: 1px solid #f1f5f9; }

/* ── Findings ── */
.finding { border-left: 3px solid; border-radius: 0 5px 5px 0; padding: 9px 13px; margin-bottom: 8px; }
.finding.danger { background: #fef2f2; border-color: #ef4444; }
.finding.warn   { background: #fffbeb; border-color: #f59e0b; }
.finding.info   { background: #eff6ff; border-color: #3b82f6; }
.finding-title  { font-size: 9.5pt; font-weight: 600; color: #1e293b; }
.finding-desc   { font-size: 8.5pt; color: #64748b; margin-top: 3px; line-height: 1.5; }

/* ── Actions ── */
.action-list    { padding-left: 0; list-style: none; }
.action-list li { font-size: 9.5pt; color: #334155; line-height: 1.9; padding-left: 14px; position: relative; }
.action-list li::before { content: "•"; position: absolute; left: 0; color: #94a3b8; }

/* ── Tables ── */
table    { width: 100%; border-collapse: collapse; font-size: 8.5pt; }
th       { background: #f8fafc; padding: 7px 10px; text-align: left; font-size: 7.5pt; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid #e2e8f0; }
td       { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; color: #1e293b; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.mono    { font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 7.5pt; word-break: break-all; }

/* ── Badges ── */
.badge { display: inline-block; padding: 1px 7px; border-radius: 3px; font-size: 7.5pt; font-weight: 600; margin-right: 3px; margin-bottom: 2px; }
.type-ip     { background: #dbeafe; color: #1d4ed8; }
.type-domain { background: #ede9fe; color: #6d28d9; }
.type-hash   { background: #fef3c7; color: #b45309; }
.type-url    { background: #d1fae5; color: #065f46; }
.verdict-malicious  { background: #fee2e2; color: #b91c1c; }
.verdict-suspicious { background: #fef3c7; color: #92400e; }
.verdict-clean      { background: #d1fae5; color: #065f46; }
.verdict-unknown    { background: #f1f5f9; color: #64748b; }
.hits-many { background: #fee2e2; color: #b91c1c; }
.hits-some { background: #fef3c7; color: #92400e; }
.hits-none { background: #f1f5f9; color: #94a3b8; }
.src       { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 7pt; margin-right: 3px; margin-bottom: 2px; background: #f1f5f9; color: #475569; }
.src.hit   { background: #fde8e8; color: #c0392b; }

/* ── Highlights ── */
.highlights { display: grid; grid-template-columns: repeat(3,1fr); gap: 12px; padding: 16px 28px; border-bottom: 1px solid #f1f5f9; }
.hl-card    { background: #f8fafc; border: 0.5px solid #e2e8f0; border-radius: 7px; padding: 11px 13px; }
.hl-label   { font-size: 7.5pt; color: #64748b; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px; }
.hl-val     { font-family: 'JetBrains Mono', monospace; font-size: 9pt; font-weight: 600; word-break: break-all; }
.hl-val.red    { color: #dc2626; }
.hl-val.purple { color: #7c3aed; }
.hl-val.amber  { color: #b45309; font-family: 'Inter', sans-serif; }
.hl-sub     { font-size: 7.5pt; color: #94a3b8; margin-top: 2px; }

/* ── Footer ── */
.footer { background: #f8fafc; padding: 10px 28px; display: flex; justify-content: space-between; font-size: 7.5pt; color: #94a3b8; border-top: 1px solid #e2e8f0; margin-top: auto; }

/* ── Graph page ── */
.graph-page   { background: #0f172a; }
.graph-header { padding: 10px 20px; display: flex; align-items: center; gap: 16px; border-bottom: 1px solid #1e293b; }
.graph-title  { font-size: 12pt; font-weight: 600; color: #f8fafc; flex: 1; }
.graph-meta   { font-size: 9pt; color: #94a3b8; }
.graph-body   { flex: 1; display: flex; align-items: center; justify-content: center; padding: 12px; min-height: 0; }
.graph-img    { max-width: 100%; max-height: 100%; width: auto; height: auto; object-fit: contain; display: block; }

/* ── Annexe ── */
.annexe-intro { padding: 10px 28px 4px; font-size: 8.5pt; color: #94a3b8; font-style: italic; border-bottom: 1px solid #f1f5f9; }

/* ── Collapsible IOC ── */
.ioc-details { border-bottom: 1px solid #e8ecf1; }

.ioc-summary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 28px;
  cursor: pointer;
  list-style: none;
  user-select: none;
  background: #f8fafc;
  transition: background 0.15s;
}
.ioc-summary::-webkit-details-marker { display: none; }
.ioc-summary:hover { background: #f1f5f9; }

.ioc-details[open] > .ioc-summary { background: #eff6ff; border-bottom: 1px solid #bfdbfe; }

.ioc-value { font-size: 9pt; flex: 1; color: #1e293b; }

.score-inline {
  font-size: 8pt;
  font-weight: 700;
  padding: 1px 7px;
  border-radius: 3px;
}
.score-inline.score-malicious  { background: #fee2e2; color: #b91c1c; }
.score-inline.score-suspicious { background: #fef3c7; color: #92400e; }
.score-inline.score-clean      { background: #d1fae5; color: #065f46; }
.score-inline.score-unknown    { background: #f1f5f9; color: #64748b; }

.chevron {
  font-size: 8pt;
  color: #94a3b8;
  transition: transform 0.2s;
  flex-shrink: 0;
}
.ioc-details[open] .chevron { transform: rotate(90deg); }

.ioc-body {
  padding: 12px 28px 16px;
  background: #ffffff;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}

/* ── Module block ── */
.mod-block { background: #f8fafc; border: 0.5px solid #e2e8f0; border-radius: 7px; padding: 10px 13px; }
.mod-name  { font-size: 7.5pt; font-weight: 700; color: #3b82f6; text-transform: uppercase; letter-spacing: .6px; margin-bottom: 7px; }
.mod-fields { display: flex; flex-direction: column; gap: 4px; }
.field-row  { display: flex; flex-direction: column; }
.field-key  { font-size: 7pt; color: #94a3b8; text-transform: uppercase; letter-spacing: .3px; }
.field-val  { font-size: 8.5pt; color: #1e293b; word-break: break-all; }
.score-high { color: #dc2626; font-weight: 700; }
.score-mid  { color: #d97706; font-weight: 700; }
.score-low  { color: #16a34a; font-weight: 700; }

/* ── Print overrides ── */
@media print {
  body { background: white; }
  .page { box-shadow: none; margin: 0; page-break-after: always; break-after: always; }
  .page-landscape { size: A4 landscape; }
  .annexe-page { page-break-after: auto; break-after: auto; }
  .ioc-details[open] .ioc-body { display: grid; }
  .ioc-summary { background: #f8fafc !important; }
  * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
}
`; },

};