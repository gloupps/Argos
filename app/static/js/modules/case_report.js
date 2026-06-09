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

    // ══════════════════════════════════════════════════════════════
    // ── VERDICT COMPUTATION ──────────────────────────────────────
    // Multi-signal logic replacing the simple maxScore threshold.
    // Returns { verdict: "malicious"|"suspicious"|"clean"|"unknown", score, reasons[] }
    // ══════════════════════════════════════════════════════════════

    _computeVerdict(data) {
        const modules   = data?.modules || {};
        const allFields = Object.values(modules).flat().filter(Boolean);

        // Internal module keys (misp, opencti, misp_ext_*)
        const _internalKeys = () => {
            const reg = window.Modules?.registry || {};
            const keys = Object.entries(reg)
                .filter(([k, m]) => m.type === "internal" || k === "misp" || k.startsWith("misp_ext_"))
                .map(([k]) => k);
            return keys.length ? keys : ["opencti", "misp"];
        };

        const _isEmpty = v => {
            if (v === null || v === undefined || v === "") return true;
            if (typeof v === "number" && v === 0) return true;
            if (Array.isArray(v)) {
                if (v.length === 0) return true;
                if (v.some(x => x && typeof x === "object")) return false;
                return v.filter(x => x !== "" && x !== null).length === 0;
            }
            return false;
        };

        // 1. Detection score (base VT / any score field)
        let maxScore = null;
        allFields.forEach(f => {
            if (f.type === "score") {
                const v = Number(f.value);
                if (!isNaN(v) && (maxScore === null || v > maxScore)) maxScore = v;
            }
        });

        // 2. CTI signals
        const THREAT_FIELDS = new Set([
            "Threat Actors", "Related Threat Actors",
            "Malware Family", "Malware Families", "malware_family",
            "Malware Description",
            "Threat Type", "Threat Types",
            "ThreatFox Entry",
            "Verdict",
        ]);
        const REPORT_FIELDS = new Set([
            "Collections", "Reports", "Malware Refs",
            "Matching Events", "Events",
        ]);

        let hasThreat      = false;
        let communityMal   = 0;
        let communitySusp  = 0;
        let hasCollection  = false;
        let hasReport      = false;

        allFields.forEach(f => {
            const name = f.name || "";
            const val  = f.value;
            if (THREAT_FIELDS.has(name) && !_isEmpty(val)) hasThreat = true;
            // ThreatFox "Compromised" flag
            if (name === "Compromised" && String(val).toLowerCase() === "yes") hasThreat = true;
            // Community votes (VT Malicious / Suspicious counts)
            if (name === "Malicious"  && !_isEmpty(val)) communityMal  = Math.max(communityMal,  Number(val) || 0);
            if (name === "Suspicious" && !_isEmpty(val)) communitySusp = Math.max(communitySusp, Number(val) || 0);
            // Collections
            if (name === "Collections" && !_isEmpty(val)) hasCollection = true;
            // Reports / internal hits
            if (REPORT_FIELDS.has(name) && !_isEmpty(val)) hasReport = true;
        });

        // Internal modules: at least one non-empty field = internal hit
        let hasInternalHit = false;
        _internalKeys().forEach(k => {
            if (!modules[k]) return;
            if ((modules[k] || []).some(f => !_isEmpty(f.value))) hasInternalHit = true;
        });

        // 3. Decision tree
        //    Rule 1 – Threat identified → always malicious
        if (hasThreat) {
            return { verdict: "malicious", score: maxScore, reasons: ["threat"] };
        }
        //    Rule 2 – High detection score
        if (maxScore !== null && maxScore > 70) {
            return { verdict: "malicious", score: maxScore, reasons: ["detection"] };
        }
        //    Rule 3 – Medium score + aggravating context
        if (maxScore !== null && maxScore > 40) {
            if (communityMal > 0 || hasCollection || hasInternalHit) {
                return { verdict: "malicious", score: maxScore, reasons: ["detection+context"] };
            }
            return { verdict: "suspicious", score: maxScore, reasons: ["detection"] };
        }
        //    Rule 4 – Community votes without score
        if (communityMal > 0) {
            return { verdict: "suspicious", score: maxScore, reasons: ["community"] };
        }
        if (communitySusp > 0) {
            return { verdict: "suspicious", score: maxScore, reasons: ["community_susp"] };
        }
        //    Rule 5 – Reports / collections / internal only (no threat) → suspicious
        if (hasCollection || hasReport || hasInternalHit) {
            return { verdict: "suspicious", score: maxScore, reasons: ["reports"] };
        }
        //    Rule 6 – Low detection score
        if (maxScore !== null) {
            return { verdict: "clean", score: maxScore, reasons: ["detection"] };
        }
        return { verdict: "unknown", score: null, reasons: [] };
    },

    // ── Summary computation ───────────────────────────────────────

    _computeSummary(allInfo, graphData) {
        let malicious = 0, suspicious = 0, clean = 0, unknown = 0;
        let totalSiemHits = 0;
        const siemRows = [];
        const modules  = new Set();
        const iocEntries = Object.entries(allInfo || {});

        iocEntries.forEach(([ioc, data]) => {
            // Collect modules + SIEM rows
            Object.entries(data.modules || {}).forEach(([mod, fields]) => {
                modules.add(mod);
                (fields || []).forEach(f => {
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

            // Verdict using multi-signal logic
            const { verdict } = this._computeVerdict(data);
            if      (verdict === "malicious")  malicious++;
            else if (verdict === "suspicious") suspicious++;
            else if (verdict === "clean")      clean++;
            else                               unknown++;
        });

        let severity = "INFO";
        if      (malicious >= 3 || (malicious > 0 && totalSiemHits > 100)) severity = "HIGH";
        else if (malicious > 0 || suspicious >= 3)                          severity = "MEDIUM";
        else if (suspicious > 0)                                             severity = "LOW";

        // Top malicious IOC (highest detection score)
        let topMalicious = null, topScore = -1;
        iocEntries.forEach(([ioc, data]) => {
            const { verdict, score } = this._computeVerdict(data);
            if ((verdict === "malicious" || verdict === "suspicious") && (score || 0) > topScore) {
                topScore = score || 0;
                topMalicious = { ioc, score: score || 0, type: data.type, verdict };
            }
        });

        // Top pivot (most connected)
        const pivotCounts = {};
        (graphData.edges || []).forEach(e => {
            if (e.pivot_label) pivotCounts[e.pivot_label] = (pivotCounts[e.pivot_label] || 0) + 1;
        });
        let topPivot = null, maxLinks = 0;
        Object.entries(pivotCounts).forEach(([lbl, cnt]) => {
            if (cnt > maxLinks) { maxLinks = cnt; topPivot = { label: lbl, links: cnt }; }
        });

        // ── CTI extraction ────────────────────────────────────────
        const families    = new Set();
        const threatActors = new Set();
        const mitreTags   = new Set();
        const allTags     = new Set();
        const vulns       = new Set();
        const orgs        = new Set();
        const asns        = new Set();
        const countries   = new Set();
        const mispEvents  = new Set();
        const collections = new Set();
        const iocMeta     = {}; // ioc → { abuseScore, org, asn, country, threatTypes }

        const _grab = (fields, ...names) => {
            for (const f of (fields || [])) {
                if (names.includes(f.name)) {
                    const vals = Array.isArray(f.value) ? f.value : [f.value];
                    return vals.filter(Boolean).map(String);
                }
            }
            return [];
        };

        iocEntries.forEach(([ioc, data]) => {
            const meta = { abuseScore: null, org: null, asn: null, country: null, threatTypes: [] };
            Object.entries(data.modules || {}).forEach(([, fields]) => {
                (fields || []).forEach(f => {
                    const v = f.value; const n = f.name;
                    if (["Malware Family", "Malware Families", "malware_family"].includes(n)) {
                        (Array.isArray(v)?v:[v]).forEach(x => x && families.add(String(x)));
                    }
                    if (["Threat Actors", "Related Threat Actors"].includes(n)) {
                        (Array.isArray(v)?v:[v]).forEach(x => x && threatActors.add(String(x)));
                    }
                    if (n === "Tags") {
                        (Array.isArray(v)?v:[v]).forEach(x => {
                            if (!x) return;
                            const s = String(x);
                            if (s.toLowerCase().includes("mitre") || s.includes("attack."))
                                mitreTags.add(s);
                            else allTags.add(s);
                        });
                    }
                    if (n === "MITRE / Galaxies") {
                        (Array.isArray(v)?v:[v]).forEach(x => x && mitreTags.add(String(x)));
                    }
                    if (n === "Vulnerabilities") {
                        (Array.isArray(v)?v:[v]).forEach(x => x && vulns.add(String(x)));
                    }
                    if (n === "Organization" || n === "ISP") { if (v) { orgs.add(String(v)); meta.org = String(v); } }
                    if (n === "ASN")     { if (v) { asns.add(String(v)); meta.asn = String(v); } }
                    if (n === "Country" || n === "Country Name") { if (v) { countries.add(String(v)); meta.country = String(v); } }
                    if (n === "Abuse Confidence" || n === "abuse_confidence") {
                        const sc = parseInt(v, 10); if (!isNaN(sc)) meta.abuseScore = sc;
                    }
                    if (n === "Threat Types" || n === "Threat Type") {
                        (Array.isArray(v)?v:[v]).forEach(x => x && meta.threatTypes.push(String(x)));
                    }
                    if (n === "Events") {
                        (Array.isArray(v)?v:[v]).forEach(x => x && mispEvents.add(String(x)));
                    }
                    if (n === "Collections") {
                        (Array.isArray(v)?v:[v]).forEach(x => x && collections.add(String(x)));
                    }
                });
            });
            iocMeta[ioc] = meta;
        });

        // Top SIEM IOC (most hits)
        const siemByIoc = {};
        siemRows.forEach(r => { siemByIoc[r.ioc] = (siemByIoc[r.ioc] || 0) + r.hits; });
        const topSiemIoc = Object.entries(siemByIoc).sort((a, b) => b[1] - a[1])[0] || null;

        const allDates = siemRows.flatMap(r => [r.first, r.last]).filter(d => d && d !== "—").sort();
        const siemFirst = allDates[0] || null;
        const siemLast  = allDates[allDates.length - 1] || null;

        return {
            total: iocEntries.length,
            malicious, suspicious, clean, unknown,
            totalSiemHits, severity, siemRows,
            modules: [...modules],
            topMalicious, topPivot,
            families:     [...families].slice(0, 6),
            threatActors: [...threatActors].slice(0, 5),
            mitreTags:    [...mitreTags].slice(0, 8),
            allTags:      [...allTags].slice(0, 10),
            vulns:        [...vulns].slice(0, 8),
            orgs:         [...orgs].slice(0, 4),
            asns:         [...asns].slice(0, 4),
            countries:    [...countries].slice(0, 6),
            mispEvents:   [...mispEvents].slice(0, 5),
            collections:  [...collections].slice(0, 4),
            iocMeta,
            topSiemIoc,
            siemFirst, siemLast,
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

  ${this._buildThreatProfile(summary, allInfo)}

  <div class="footer">
    <span>Argos · Confidential</span><span>Page 1</span>
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
    <span>Argos · Confidential</span><span>Annexe</span>
  </div>
</div>

</body>
</html>`;
    },

    // ── Threat Profile (page 1) ───────────────────────────────────

    _buildThreatProfile(summary, allInfo) {
        const e = this._esc.bind(this);

        // ── Malicious/suspicious IOCs ranked ──────────────────────
        const rankedMalicious = Object.entries(allInfo)
            .map(([ioc, data]) => {
                const { verdict, score } = this._computeVerdict(data);
                const srcHit = [], srcAll = [];
                Object.entries(data.modules || {}).forEach(([mod, fields]) => {
                    let ms = -1;
                    (fields || []).forEach(f => {
                        if (f.type === "score") { const v = Number(f.value); if (!isNaN(v) && v > ms) ms = v; }
                    });
                    const label = window.Modules?.registry?.[mod]?.name || mod;
                    if (ms > 40) srcHit.push(label); else srcAll.push(label);
                });
                return { ioc, type: data.type || "unknown", verdict, score: score ?? -1, srcHit, meta: summary.iocMeta[ioc] || {} };
            })
            .filter(x => x.verdict === "malicious" || x.verdict === "suspicious")
            .sort((a, b) => {
                // malicious first, then by score
                if (a.verdict !== b.verdict) return a.verdict === "malicious" ? -1 : 1;
                return b.score - a.score;
            });

        const maliciousRows = rankedMalicious.slice(0, 8).map(x => {
            const verdictCls = x.verdict === "malicious" ? "malicious" : "suspicious";
            const shortIoc   = x.ioc.length > 46 ? x.ioc.slice(0, 44) + "…" : x.ioc;
            const meta       = x.meta;
            const detail     = [meta.org, meta.country, meta.asn].filter(Boolean).join(" · ");
            const scoreDisp  = x.score >= 0 ? String(x.score) : "—";
            const abuse      = meta.abuseScore !== null
                ? `<span class="badge hits-${meta.abuseScore > 70 ? "many" : meta.abuseScore > 30 ? "some" : "none"}">Abuse ${meta.abuseScore}%</span>`
                : "";
            return `<tr>
              <td class="mono">${e(shortIoc)}</td>
              <td><span class="badge type-${x.type}">${x.type}</span></td>
              <td><span class="badge verdict-${verdictCls}">${scoreDisp}</span></td>
              <td>${x.srcHit.slice(0, 4).map(s => `<span class="src hit">${e(s)}</span>`).join("")}</td>
              <td style="font-size:7.5pt;color:#64748b;">${e(detail)}${abuse}</td>
            </tr>`;
        }).join("");

        // ── Attribution ───────────────────────────────────────────
        const attrCards = [];
        if (summary.families.length)
            attrCards.push({ icon: "🦠", label: "Malware families", items: summary.families, cls: "red" });
        if (summary.threatActors.length)
            attrCards.push({ icon: "👤", label: "Threat actors", items: summary.threatActors, cls: "purple" });
        if (summary.mitreTags.length)
            attrCards.push({ icon: "⚔️", label: "MITRE techniques", items: summary.mitreTags.map(t => t.replace(/^attack\./i, "T")), cls: "orange" });
        if (summary.vulns.length)
            attrCards.push({ icon: "🔓", label: "Vulnerabilities", items: summary.vulns, cls: "red" });
        if (summary.mispEvents.size || summary.collections.length)
            attrCards.push({ icon: "📋", label: "Reports / collections", items: [...summary.mispEvents, ...summary.collections].slice(0, 5), cls: "blue" });

        const attrHtml = attrCards.map(c => `
          <div class="tp-card">
            <div class="tp-card-header">${c.icon} ${e(c.label)}</div>
            <div class="tp-pills">${c.items.map(i => `<span class="tp-pill tp-pill-${c.cls}">${e(i)}</span>`).join("")}</div>
          </div>`).join("");

        // ── Infrastructure ────────────────────────────────────────
        const infraItems = [];
        if (summary.countries.length) infraItems.push({ label: "Countries", items: summary.countries });
        if (summary.orgs.length)      infraItems.push({ label: "Organizations", items: summary.orgs });
        if (summary.asns.length)      infraItems.push({ label: "ASNs", items: summary.asns });

        const infraHtml = infraItems.map(it => `
          <div class="infra-item">
            <div class="infra-label">${e(it.label)}</div>
            ${it.items.map(v => `<div class="infra-val">${e(v)}</div>`).join("")}
          </div>`).join("");

        // ── SIEM exposure ─────────────────────────────────────────
        const topSiemRows = Object.entries(
            summary.siemRows.reduce((acc, r) => { acc[r.ioc] = (acc[r.ioc] || 0) + r.hits; return acc; }, {})
        ).sort((a, b) => b[1] - a[1]).slice(0, 5);

        const siemHtml = summary.totalSiemHits > 0
            ? `<div>
                <div class="siem-stats">
                  <div class="siem-stat"><div class="siem-val">${summary.totalSiemHits.toLocaleString()}</div><div class="siem-label">Total hits</div></div>
                  <div class="siem-stat"><div class="siem-val">${[...new Set(summary.siemRows.map(r => r.ioc))].length}</div><div class="siem-label">IOCs seen</div></div>
                  ${summary.siemFirst ? `<div class="siem-stat"><div class="siem-val" style="font-size:9pt">${e(summary.siemFirst)}</div><div class="siem-label">First seen</div></div>` : ""}
                  ${summary.siemLast  ? `<div class="siem-stat"><div class="siem-val" style="font-size:9pt">${e(summary.siemLast)}</div><div class="siem-label">Last seen</div></div>` : ""}
                </div>
                <div style="margin-top:10px;">
                  ${topSiemRows.map(([ioc, hits]) => {
                    const pct   = Math.round((hits / summary.totalSiemHits) * 100);
                    const short = ioc.length > 44 ? ioc.slice(0, 42) + "…" : ioc;
                    const cls   = hits > 100 ? "many" : hits > 10 ? "some" : "none";
                    return `<div class="siem-bar-row">
                      <span class="siem-bar-ioc mono">${e(short)}</span>
                      <div class="siem-bar-track"><div class="siem-bar-fill siem-bar-${cls}" style="width:${pct}%"></div></div>
                      <span class="siem-bar-count badge hits-${cls}">${hits.toLocaleString()}</span>
                    </div>`;
                  }).join("")}
                </div>
              </div>`
            : `<div class="tp-empty">No SIEM results for this case.</div>`;

        // ── Recommended actions ───────────────────────────────────
        const acts = [];
        if (summary.malicious > 0)     acts.push("Block malicious IPs/domains at perimeter firewall");
        if (summary.totalSiemHits > 0) acts.push(`Investigate activity timeline in SIEM`);
        if (summary.topPivot)          acts.push(`Pivot on ${summary.topPivot.label} to find related infrastructure`);
        if (summary.families.length)   acts.push(`Hunt for ${summary.families[0]} IOCs across endpoints`);
        if (summary.vulns.length)      acts.push(`Patch or mitigate: ${summary.vulns.slice(0, 2).join(", ")}`);
        if (summary.mitreTags.length)  acts.push("Map observed MITRE techniques to detection rules");
        acts.push("Export STIX2 bundle and share with CERT/partners");
        const actHtml = `<ul class="action-list">${acts.slice(0, 5).map(a => `<li>${e(a)}</li>`).join("")}</ul>`;

        return `
<div class="tp-grid">

  <!-- Left column -->
  <div class="tp-left">

    ${rankedMalicious.length > 0 ? `
    <div class="tp-section">
      <div class="section-title">Malicious &amp; suspicious IOCs</div>
      <table><thead><tr><th>IOC</th><th>Type</th><th>Score</th><th>Flagged by</th><th>Context</th></tr></thead>
      <tbody>${maliciousRows}</tbody></table>
    </div>` : `<div class="tp-section"><div class="section-title">IOCs</div>${this._buildIocTable(allInfo)}</div>`}

    ${attrCards.length > 0 ? `
    <div class="tp-section">
      <div class="section-title">Threat attribution</div>
      <div class="tp-cards">${attrHtml}</div>
    </div>` : ""}

    ${infraItems.length > 0 ? `
    <div class="tp-section">
      <div class="section-title">Infrastructure profile</div>
      <div class="infra-grid">${infraHtml}</div>
    </div>` : ""}

  </div>

  <!-- Right column -->
  <div class="tp-right">

    <div class="tp-section">
      <div class="section-title">SIEM exposure</div>
      ${siemHtml}
    </div>

    <div class="tp-section">
      <div class="section-title">Recommended actions</div>
      ${actHtml}
    </div>

  </div>

</div>`;
    },

    // ── IOC overview table (used when no malicious IOCs) ──────────

    _buildIocTable(allInfo) {
        const rows = Object.entries(allInfo).map(([ioc, data]) => {
            const { verdict, score } = this._computeVerdict(data);
            const srcHit = [], srcOk = [];
            Object.entries(data.modules || {}).forEach(([mod, fields]) => {
                let ms = -1;
                (fields || []).forEach(f => {
                    if (f.type === "score") { const v = Number(f.value); if (!isNaN(v) && v > ms) ms = v; }
                });
                const label = window.Modules?.registry?.[mod]?.name || mod;
                if (ms > 40) srcHit.push(label); else srcOk.push(label);
            });
            const short = ioc.length > 44 ? ioc.slice(0, 42) + "…" : ioc;
            return `<tr>
              <td class="mono">${this._esc(short)}</td>
              <td><span class="badge type-${data.type || "unknown"}">${data.type || "?"}</span></td>
              <td><span class="badge verdict-${verdict}">${verdict}</span></td>
              <td>${srcHit.map(s => `<span class="src hit">${this._esc(s)}</span>`).join("")}${srcOk.slice(0, 3).map(s => `<span class="src">${this._esc(s)}</span>`).join("")}</td>
            </tr>`;
        }).join("");
        return `<table><thead><tr><th>IOC</th><th>Type</th><th>Verdict</th><th>Sources</th></tr></thead><tbody>${rows}</tbody></table>`;
    },

    // ── SIEM table ────────────────────────────────────────────────

    _buildSiemTable(siemRows) {
        const rows = siemRows.sort((a, b) => b.hits - a.hits).slice(0, 30).map(r => {
            const cls   = r.hits > 100 ? "many" : r.hits > 0 ? "some" : "none";
            const short = r.ioc.length > 36 ? r.ioc.slice(0, 34) + "…" : r.ioc;
            return `<tr><td class="mono">${this._esc(short)}</td><td>${this._esc(r.source)}</td><td class="mono">${this._esc(r.index)}</td><td><span class="badge hits-${cls}">${r.hits.toLocaleString()}</span></td><td>${this._esc(r.first)}</td><td>${this._esc(r.last)}</td></tr>`;
        }).join("");
        return `<table><thead><tr><th>IOC</th><th>Source</th><th>Index / Log source</th><th>Hits</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${rows}</tbody></table>`;
    },

    // ── Annexe — collapsible IOC detail ──────────────────────────

    _buildAnnexe(allInfo) {
        return Object.entries(allInfo).map(([ioc, data]) => {
            const { verdict, score } = this._computeVerdict(data);

            const modBlocks = Object.entries(data.modules || {}).map(([mod, fields]) => {
                if (!fields?.length) return "";
                const modName = window.Modules?.registry?.[mod]?.name || mod;
                const fieldRows = fields
                    .filter(f => {
                        if (f.value === null || f.value === undefined || f.value === "") return false;
                        if (Array.isArray(f.value) && !f.value.length) return false;
                        if (["siem_results", "text_modal"].includes(f.type)) return false;
                        return true;
                    })
                    .slice(0, 20)
                    .map(f => {
                        const rendered = this._renderFieldValue(f);
                        return `<div class="field-row${rendered.block ? " field-row-block" : ""}">`
                             + `<span class="field-key">${this._esc(f.name)}</span>`
                             + rendered.html
                             + `</div>`;
                    }).join("");
                if (!fieldRows) return "";
                return `<div class="mod-block"><div class="mod-name">${this._esc(modName)}</div><div class="mod-fields">${fieldRows}</div></div>`;
            }).join("");

            if (!modBlocks.trim()) return "";

            const short      = ioc.length > 55 ? ioc.slice(0, 53) + "…" : ioc;
            const scoreDisp  = score !== null ? ` · ${score}` : "";
            const scoreCls   = verdict === "malicious" ? "score-malicious" : verdict === "suspicious" ? "score-suspicious" : verdict === "clean" ? "score-clean" : "score-unknown";
            return `
<details class="ioc-details">
  <summary class="ioc-summary">
    <span class="ioc-value mono">${this._esc(short)}</span>
    <span class="badge type-${data.type || "unknown"}">${data.type || "?"}</span>
    <span class="score-inline ${scoreCls}">${verdict}${scoreDisp}</span>
    <span class="chevron">▶</span>
  </summary>
  <div class="ioc-body">${modBlocks}</div>
</details>`;
        }).join("");
    },

    // ── Field value renderer ──────────────────────────────────────

    _renderFieldValue(f) {
        const val = f.value;

        // Score
        if (f.type === "score") {
            const n = Number(val);
            const cls = n > 70 ? "score-high" : n > 40 ? "score-mid" : "score-low";
            return { block: false, html: `<span class="field-val ${cls}">${n}</span>` };
        }

        // Object array → table
        if (Array.isArray(val) && val.length && typeof val[0] === "object" && val[0] !== null) {
            const keys = [...new Set(val.flatMap(o => Object.keys(o)))].slice(0, 8);
            const thead = keys.map(k => `<th>${this._esc(k)}</th>`).join("");
            const tbody = val.slice(0, 20).map(o =>
                `<tr>${keys.map(k => `<td>${this._esc(String(o[k] ?? ""))}</td>`).join("")}</tr>`
            ).join("");
            const more = val.length > 20 ? `<span class="list-more">+${val.length - 20} more</span>` : "";
            return {
                block: true,
                html: `<div class="field-table-wrap"><table class="field-table"><thead><tr>${thead}</tr></thead><tbody>${tbody}</tbody></table></div>${more}`,
            };
        }

        // String array → pills
        if (Array.isArray(val)) {
            const pills = val.slice(0, 30).map(v =>
                `<span class="field-pill">${this._esc(String(v))}</span>`
            ).join("");
            const more = val.length > 30 ? `<span class="list-more">+${val.length - 30} more</span>` : "";
            return { block: true, html: `<div class="field-pills">${pills}${more}</div>` };
        }

        // Plain scalar
        return { block: false, html: `<span class="field-val">${this._esc(String(val ?? ""))}</span>` };
    },

    // ── Escape helper ─────────────────────────────────────────────

    _esc(v) {
        return String(v ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
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
.page-landscape { width: 297mm; min-height: 210mm; }
.annexe-page    { min-height: unset; margin-bottom: 40px; }

/* ── Header ── */
.header {
  background: #0f172a;
  padding: 18px 28px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-shrink: 0;
}
.header-sm   { padding: 10px 28px; }
.logo-row    { display: flex; align-items: center; }
.logo        { height: 40px; width: auto; max-width: 180px; display: block; }
.logo-sm     { height: 28px; max-width: 130px; }
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
table { width: 100%; border-collapse: collapse; font-size: 8.5pt; }
th    { background: #f8fafc; padding: 7px 10px; text-align: left; font-size: 7.5pt; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid #e2e8f0; }
td    { padding: 7px 10px; border-bottom: 1px solid #f1f5f9; color: #1e293b; vertical-align: top; }
tr:last-child td { border-bottom: none; }

.mono { font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 7.5pt; word-break: break-all; }

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
  display: flex; align-items: center; gap: 8px;
  padding: 10px 28px; cursor: pointer; list-style: none;
  user-select: none; background: #f8fafc; transition: background 0.15s;
}
.ioc-summary::-webkit-details-marker { display: none; }
.ioc-summary:hover { background: #f1f5f9; }
.ioc-details[open] > .ioc-summary { background: #eff6ff; border-bottom: 1px solid #bfdbfe; }
.ioc-value { font-size: 9pt; flex: 1; color: #1e293b; }
.score-inline { font-size: 8pt; font-weight: 700; padding: 1px 7px; border-radius: 3px; }
.score-inline.score-malicious  { background: #fee2e2; color: #b91c1c; }
.score-inline.score-suspicious { background: #fef3c7; color: #92400e; }
.score-inline.score-clean      { background: #d1fae5; color: #065f46; }
.score-inline.score-unknown    { background: #f1f5f9; color: #64748b; }
.chevron { font-size: 8pt; color: #94a3b8; transition: transform 0.2s; flex-shrink: 0; }
.ioc-details[open] .chevron { transform: rotate(90deg); }
.ioc-body {
  padding: 12px 28px 16px; background: #ffffff;
  display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px;
}

/* ── Module block ── */
.mod-block  { background: #f8fafc; border: 0.5px solid #e2e8f0; border-radius: 7px; padding: 10px 13px; }
.mod-name   { font-size: 7.5pt; font-weight: 700; color: #3b82f6; text-transform: uppercase; letter-spacing: .6px; margin-bottom: 7px; }
.mod-fields { display: flex; flex-direction: column; gap: 4px; }
.field-row  { display: flex; flex-direction: column; }
.field-key  { font-size: 7pt; color: #94a3b8; text-transform: uppercase; letter-spacing: .3px; }
.field-val  { font-size: 8.5pt; color: #1e293b; word-break: break-all; }
.score-high { color: #dc2626; font-weight: 700; }
.score-mid  { color: #d97706; font-weight: 700; }
.score-low  { color: #16a34a; font-weight: 700; }

/* ── Field table (object arrays like Shodan services) ── */
.field-row-block { flex-direction: column; gap: 5px; grid-column: 1 / -1; }
.field-table-wrap { overflow-x: auto; border-radius: 4px; border: 0.5px solid #e2e8f0; margin-top: 2px; }
.field-table { width: 100%; border-collapse: collapse; font-size: 7.5pt; font-family: 'JetBrains Mono', monospace; }
.field-table th { background: #1e293b; color: #94a3b8; padding: 5px 8px; text-align: left; font-size: 7pt; text-transform: uppercase; letter-spacing: .4px; white-space: nowrap; border-bottom: 1px solid #334155; }
.field-table td { padding: 4px 8px; border-bottom: 1px solid #f1f5f9; color: #334155; vertical-align: top; max-width: 200px; word-break: break-all; }
.field-table tr:last-child td { border-bottom: none; }
.field-table tr:nth-child(even) td { background: #fafafa; }

/* ── Pill list ── */
.field-pills { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 3px; }
.field-pill  { display: inline-block; background: #f1f5f9; color: #475569; padding: 2px 7px; border-radius: 3px; font-size: 7.5pt; font-family: 'JetBrains Mono', monospace; }
.list-more   { font-size: 7pt; color: #94a3b8; padding: 2px 4px; font-style: italic; }

/* ── Threat Profile layout ── */
.tp-grid    { display: grid; grid-template-columns: 1fr 280px; gap: 0; flex: 1; border-top: 1px solid #f1f5f9; align-items: start; }
.tp-left    { padding: 0; border-right: 1px solid #f1f5f9; }
.tp-right   { padding: 0; background: #fafbfc; }
.tp-section { padding: 14px 20px; border-bottom: 1px solid #f1f5f9; }
.tp-section:last-child { border-bottom: none; }
.tp-empty   { font-size: 8.5pt; color: #94a3b8; font-style: italic; }

/* ── Attribution cards ── */
.tp-cards      { display: flex; flex-direction: column; gap: 8px; }
.tp-card       { background: #f8fafc; border: 0.5px solid #e2e8f0; border-radius: 6px; padding: 9px 12px; }
.tp-card-header { font-size: 8pt; font-weight: 700; color: #475569; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 6px; }
.tp-pills      { display: flex; flex-wrap: wrap; gap: 4px; }
.tp-pill       { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 7.5pt; font-weight: 500; }
.tp-pill-red    { background: #fee2e2; color: #b91c1c; }
.tp-pill-purple { background: #f3e8ff; color: #7c3aed; }
.tp-pill-orange { background: #fff7ed; color: #c2410c; }
.tp-pill-blue   { background: #eff6ff; color: #1d4ed8; }
.tp-pill-gray   { background: #f1f5f9; color: #475569; }

/* ── Infrastructure grid ── */
.infra-grid  { display: flex; flex-wrap: wrap; gap: 10px; }
.infra-item  { background: #f8fafc; border: 0.5px solid #e2e8f0; border-radius: 5px; padding: 7px 11px; min-width: 110px; }
.infra-label { font-size: 7pt; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: .4px; margin-bottom: 4px; }
.infra-val   { font-size: 8pt; color: #1e293b; line-height: 1.6; }

/* ── SIEM stats ── */
.siem-stats    { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
.siem-stat     { text-align: center; }
.siem-val      { font-size: 14pt; font-weight: 700; color: #0f172a; }
.siem-label    { font-size: 7pt; color: #94a3b8; text-transform: uppercase; letter-spacing: .4px; }
.siem-bar-row  { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; font-size: 7.5pt; }
.siem-bar-ioc  { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #334155; }
.siem-bar-track { width: 60px; height: 5px; background: #e2e8f0; border-radius: 3px; flex-shrink: 0; }
.siem-bar-fill  { height: 100%; border-radius: 3px; }
.siem-bar-many  { background: #ef4444; }
.siem-bar-some  { background: #f59e0b; }
.siem-bar-none  { background: #94a3b8; }
.siem-bar-count { flex-shrink: 0; }
`; },

};
