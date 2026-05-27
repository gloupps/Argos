window.EnrichPanel = {

    _current:   null,
    _abortCtrl: null,

    _internalKeys() {
        const reg = Modules?.registry || {};
        const keys = Object.entries(reg).filter(([,m]) => m.type === "internal").map(([k]) => k);
        return keys.length ? keys : ["opencti"];
    },
    _modLabel(k) { return Modules?.registry?.[k]?.name || k; },
    _modIcon(k) {
        const i = Modules?.registry?.[k]?.icon;
        if (i) return i;
        return { virustotal:"shield", shodan:"radar", abuseipdb:"ban",
                 urlscan:"scan-eye", viewdns:"globe", opencti:"database", misp:"share-2" }[k] || "box";
    },
    _isEmpty(v) {
        if (v === null || v === undefined || v === "") return true;
        if (typeof v === "number" && v === 0) return true;
        if (Array.isArray(v) && v.filter(x => x !== "" && x !== null).length === 0) return true;
        return false;
    },

    async load(nodeData, caseId) {
        if (this._abortCtrl) this._abortCtrl.abort();
        this._abortCtrl = new AbortController();
        this._current = { nodeData, caseId };
        this._renderHeader(nodeData);
        this._renderLoading();
        try {
            const res = await fetch(`/api/cases/${caseId}/info`, { signal: this._abortCtrl.signal });
            const all = await res.json();
            if (this._current?.nodeData?.label !== nodeData.label) return;
            this._renderInfo(nodeData, all[nodeData.label]);
        } catch (e) {
            if (e.name === "AbortError") return;
            this._renderError(e.message);
        }
    },

    clear() {
        if (this._abortCtrl) { this._abortCtrl.abort(); this._abortCtrl = null; }
        this._current = null;
        const h = document.getElementById("qualif-header");
        const p = document.getElementById("qualif-panel");
        if (h) h.innerHTML = `<p class="text-slate-500 text-[10px] italic">Right-click a node to enrich it.</p>`;
        if (p) p.innerHTML = "";
        document.getElementById("internal-intel-section")?.classList.add("hidden");
    },

    _renderHeader(nodeData) {
        const el = document.getElementById("qualif-header");
        if (!el) return;
        el.innerHTML = `
            <div class="flex items-center justify-between gap-2 min-w-0">
                <p class="text-[11px] font-bold font-mono truncate text-white" title="${nodeData.label}">${nodeData.label}</p>
                <button onclick="EnrichPanel._triggerEnrich()" title="Re-enrich"
                        class="text-slate-600 hover:text-blue-400 transition shrink-0">
                    <i data-lucide="refresh-cw" class="w-3 h-3"></i>
                </button>
            </div>
            <div class="flex gap-1 mt-1 flex-wrap" id="header-badges">
                <span class="bg-slate-800 text-slate-500 text-[9px] px-1.5 py-0.5 rounded uppercase">${nodeData.type}</span>
                <span class="bg-slate-800 text-slate-500 text-[9px] px-1.5 py-0.5 rounded uppercase">${nodeData.nodeType}</span>
            </div>`;
        lucide.createIcons({ nodes: [el] });
    },

    _injectVerdictBadge(maxScore) {
        const el = document.getElementById("header-badges");
        if (!el || maxScore === null) return;
        const label = maxScore > 70 ? "Malicious" : maxScore > 40 ? "Suspicious" : "Clean";
        const cls   = maxScore > 70 ? "bg-red-500/20 text-red-400 border border-red-500/30"
                    : maxScore > 40 ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    :                 "bg-green-500/20 text-green-400 border border-green-500/30";
        const dot   = maxScore > 70 ? "bg-red-500" : maxScore > 40 ? "bg-amber-500" : "bg-green-500";
        const b = document.createElement("span");
        b.className = `flex items-center gap-1 text-[9px] font-bold px-1.5 py-0.5 rounded border ${cls}`;
        b.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${dot} inline-block"></span>${label} · ${maxScore}`;
        el.appendChild(b);
    },

    _renderLoading() {
        const p = document.getElementById("qualif-panel");
        if (p) p.innerHTML = `<p class="text-slate-600 text-[10px] py-2 animate-pulse">Loading…</p>`;
        document.getElementById("internal-intel-section")?.classList.add("hidden");
    },

    // ── Mapping champ → thème ─────────────────────────────
    // Shodan et URLScan n'ont PAS de score — leurs champs vont dans host/dns/ports/vulns
    _THEME_MAP: {
        "Detection Score": "scores", "Confidence Score": "scores",
        "Malicious":       "detection", "Suspicious": "detection",
        "Reputation":      "detection", "Scan Count": "detection",
        "Organization":    "host", "ASN": "host", "ASN Owner": "host",
        "Country":         "host", "OS": "host", "Registrar": "host",
        "Last Seen":       "host", "Last Analysis": "host", "Last Scan": "host",
        "Usage":           "host", "Services": "host", "Name": "host",
        "Type":            "host", "Server Headers": "host",
        "Scan Report":     "urlscan_meta",
        "Screenshot":      "screenshot",
        "Open Ports":      "ports",
        "Hostnames":       "dns", "Domains": "dns", "Hosted Domains": "dns",
        "Domain Count":    "dns", "Last Resolved": "dns",
        "Resolved IPs":    "dns", "Associated IPs": "dns", "Subdomains Seen": "dns",
        "Vulnerabilities": "vulns",
        "Tags":            "tags", "Categories": "tags", "Indicator Types": "tags",
        "In OpenCTI":      "intel", "Detection": "intel", "Labels": "intel",
        "Reports":         "intel", "Report Count": "intel", "OpenCTI Link": "intel",
    },
    _getTheme(name) { return this._THEME_MAP[name] || "other"; },

    // ── Rendu principal ───────────────────────────────────

    _renderInfo(nodeData, info) {
        const p = document.getElementById("qualif-panel");
        if (!p) return;

        if (!info || !Object.keys(info.modules || {}).length) {
            p.innerHTML = `
                <div class="py-3 space-y-2">
                    <p class="text-slate-600 text-[10px]">No enrichment data yet.</p>
                    <button onclick="EnrichPanel._triggerEnrich()"
                            class="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 transition">
                        <i data-lucide="zap" class="w-3 h-3"></i> Enrich now
                    </button>
                </div>`;
            lucide.createIcons({ nodes: [p] });
            document.getElementById("internal-intel-section")?.classList.add("hidden");
            return;
        }

        const internalKeys = this._internalKeys();
        const entries  = Object.entries(info.modules);
        const external = entries.filter(([k]) => !internalKeys.includes(k));
        const internal = entries.filter(([k]) =>  internalKeys.includes(k));

        // Verdict global (scores uniquement — VT, AbuseIPDB)
        let maxScore = null;
        entries.forEach(([, fields]) => (fields || []).forEach(f => {
            if (f.type === "score" && !this._isEmpty(f.value)) {
                const v = Number(f.value);
                if (maxScore === null || v > maxScore) maxScore = v;
            }
        }));
        this._injectVerdictBadge(maxScore);

        // Collecter par thème
        const themes = {};
        external.forEach(([modKey, fields]) => {
            (fields || []).forEach(f => {
                if (this._isEmpty(f.value)) return;
                const theme = this._getTheme(f.name);
                if (!themes[theme]) themes[theme] = [];
                themes[theme].push({ mod: modKey, field: f });
            });
        });

        const ORDER = ["scores","detection","host","ports","vulns","dns","tags","urlscan_meta","screenshot","other"];
        const sections = ORDER
            .filter(t => themes[t]?.length)
            .map(t => this._renderThemeSection(t, themes[t]))
            .filter(Boolean);

        p.innerHTML = sections.length
            ? sections.join(`<div class="border-t border-slate-800/40 my-2"></div>`)
            : `<p class="text-slate-600 text-[10px] italic py-2">No external data.</p>`;

        lucide.createIcons({ nodes: [p] });
        this._renderInternalSection(internal);
    },

    // ── Sections thématiques ──────────────────────────────

    _sectionHeader(icon, label, count) {
        const countBadge = count != null
            ? `<span class="ml-auto text-[9px] text-slate-600">${count}</span>` : "";
        return `
            <div class="flex items-center gap-1.5 mb-2">
                <i data-lucide="${icon}" class="w-3 h-3 text-slate-500 shrink-0"></i>
                <span class="text-[9px] text-slate-500 uppercase tracking-widest font-semibold">${label}</span>
                ${countBadge}
            </div>`;
    },

    _renderThemeSection(theme, items) {

        // ── SCORES : barres comparatives (VT, AbuseIPDB uniquement) ──
        if (theme === "scores") {
            const bars = items.map(({ mod, field }) => {
                const pct    = Math.min(100, Math.max(0, Number(field.value)));
                const color  = pct > 70 ? "#ef4444" : pct > 40 ? "#f59e0b" : "#22c55e";
                const txtcls = pct > 70 ? "text-red-400" : pct > 40 ? "text-amber-400" : "text-green-400";
                return `
                    <div class="flex items-center gap-2">
                        <span class="flex items-center gap-1 text-[9px] text-slate-500 w-20 shrink-0 truncate"
                              title="${this._modLabel(mod)}">
                            <i data-lucide="${this._modIcon(mod)}" class="w-2.5 h-2.5 shrink-0"></i>
                            ${this._modLabel(mod)}
                        </span>
                        <div class="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div class="h-full rounded-full" style="width:${pct}%;background:${color}"></div>
                        </div>
                        <span class="text-[10px] font-bold ${txtcls} w-6 text-right shrink-0">${pct}</span>
                    </div>`;
            }).join("");
            return `${this._sectionHeader("shield-check", "Threat scores")}<div class="space-y-1.5">${bars}</div>`;
        }

        // ── DETECTION : KV (Malicious, Suspicious, Scan count…) ──
        if (theme === "detection") {
            const seen = {};
            items.forEach(({ mod, field }) => {
                const k = field.name, num = Number(field.value);
                if (!seen[k] || (!isNaN(num) && num > Number(seen[k].field.value)))
                    seen[k] = { mod, field };
            });
            const rows = Object.values(seen).map(({ mod, field }) => {
                const v   = String(field.value);
                const num = Number(v);
                const cls = !isNaN(num) && num > 0 ? "text-red-400 font-bold" : "text-slate-300";
                return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="text-[10px] ${cls} font-mono py-0.5">${v}</td>
                        <td class="text-[9px] text-slate-600 pl-2 py-0.5 whitespace-nowrap">${this._modLabel(mod)}</td>
                    </tr>`;
            }).join("");
            return `${this._sectionHeader("search", "Detection")}<table class="w-full">${rows}</table>`;
        }

        // ── HOST : KV dédupliqué ──
        if (theme === "host") {
            const seen = {};
            items.forEach(({ mod, field }) => { if (!seen[field.name]) seen[field.name] = { mod, field }; });
            const rows = Object.values(seen).map(({ mod, field }) => {
                const v    = String(field.value);
                const disp = v.length > 26 ? v.slice(0, 24) + "…" : v;
                if (field.link) return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap w-20">${field.name}</td>
                        <td class="py-0.5">
                            <a href="${field.link}" target="_blank" rel="noopener noreferrer" title="${v}"
                               class="text-[9px] text-blue-400 hover:text-blue-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2 h-2 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap w-20">${field.name}</td>
                        <td class="text-[9px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                    </tr>`;
            }).join("");
            return `${this._sectionHeader("server", "Host")}<table class="w-full">${rows}</table>`;
        }

        // ── PORTS : tags colorés par criticité ──
        if (theme === "ports") {
            const RISKY = new Set([21,22,23,25,53,80,110,135,139,143,443,445,
                                   1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017,6667]);
            const allPorts = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allPorts.add(String(v)));
            });
            const sorted = [...allPorts].sort((a,b) => Number(a) - Number(b));
            const tags = sorted.slice(0, 20).map(port => {
                const cls = RISKY.has(Number(port))
                    ? "bg-red-500/10 border-red-500/30 text-red-400"
                    : "bg-slate-800 border-slate-700/50 text-slate-400";
                return `<span class="text-[9px] font-mono px-1.5 py-px rounded border ${cls}">${port}</span>`;
            }).join("");
            const overflow = sorted.length > 20 ? `<span class="text-[9px] text-slate-600">+${sorted.length-20}</span>` : "";
            return `${this._sectionHeader("plug-zap", "Open ports", sorted.length)}<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`;
        }

        // ── VULNS : tags rouge/amber selon année ──
        if (theme === "vulns") {
            const allVulns = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allVulns.add(String(v)));
            });
            const sorted = [...allVulns].sort();
            const tags = sorted.slice(0, 15).map(cve => {
                const yr  = parseInt(cve.match(/CVE-(\d{4})/)?.[1] || "0");
                const cls = yr >= 2021
                    ? "bg-red-500/10 border-red-500/30 text-red-400"
                    : "bg-amber-500/10 border-amber-500/30 text-amber-400";
                return `<span class="text-[9px] font-mono px-1.5 py-px rounded border ${cls}">${cve}</span>`;
            }).join("");
            const overflow = sorted.length > 15 ? `<span class="text-[9px] text-slate-600">+${sorted.length-15}</span>` : "";
            return `${this._sectionHeader("bug", "Vulnerabilities", sorted.length)}<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`;
        }

        // ── DNS : tags neutres ──
        if (theme === "dns") {
            const allItems = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allItems.add(String(v)));
            });
            const arr = [...allItems];
            const tags = arr.slice(0, 12).map(v => {
                const disp = v.length > 32 ? v.slice(0,30)+"…" : v;
                return `<span class="text-[9px] font-mono px-1.5 py-px rounded border
                               bg-slate-800 border-slate-700/50 text-slate-400" title="${v}">${disp}</span>`;
            }).join("");
            const overflow = arr.length > 12 ? `<span class="text-[9px] text-slate-600">+${arr.length-12}</span>` : "";
            return `${this._sectionHeader("globe", "Passive DNS", arr.length)}<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`;
        }

        // ── TAGS / CATEGORIES ──
        if (theme === "tags") {
            const allItems = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allItems.add(String(v)));
            });
            const arr = [...allItems];
            const tags = arr.slice(0, 10).map(v =>
                `<span class="text-[9px] px-1.5 py-px rounded border
                              bg-slate-800 border-slate-700/50 text-slate-400">${v}</span>`
            ).join("");
            const overflow = arr.length > 10 ? `<span class="text-[9px] text-slate-600">+${arr.length-10}</span>` : "";
            return `${this._sectionHeader("tag", "Tags & categories")}<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`;
        }

        // ── URLSCAN META : lien rapport ──
        if (theme === "urlscan_meta") {
            const links = items.map(({ field }) => {
                if (!field.link) return "";
                return `
                    <a href="${field.link}" target="_blank" rel="noopener noreferrer"
                       class="flex items-center gap-1 text-[9px] text-blue-400 hover:text-blue-300 transition w-fit">
                        <i data-lucide="external-link" class="w-2.5 h-2.5 shrink-0"></i> ${field.value}
                    </a>`;
            }).filter(Boolean).join("");
            return links ? `${this._sectionHeader("scan-eye", "URLScan")}${links}` : "";
        }

        // ── SCREENSHOT : miniature cliquable ──
        if (theme === "screenshot") {
            const item = items[0];
            if (!item) return "";
            const src  = String(item.field.value);
            const href = item.field.link || src;
            return `
                ${this._sectionHeader("camera", "Screenshot")}
                <a href="${href}" target="_blank" rel="noopener noreferrer"
                   class="block rounded overflow-hidden border border-slate-700/60
                          hover:border-blue-500/40 transition w-full">
                    <img src="${src}" alt="URLScan screenshot"
                         class="w-full object-cover"
                         style="max-height:120px;object-position:top"
                         loading="lazy"
                         onerror="this.closest('a').style.display='none'">
                </a>`;
        }

        // ── OTHER / FALLBACK ──
        const seen = {};
        items.forEach(({ field }) => { if (!seen[field.name]) seen[field.name] = field; });
        const rows = Object.values(seen).map(field => {
            const v = Array.isArray(field.value) ? field.value.join(", ") : String(field.value ?? "");
            if (!v || v === "0") return "";
            const disp = v.length > 26 ? v.slice(0, 24) + "…" : v;
            return `
                <tr>
                    <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                    <td class="text-[9px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                </tr>`;
        }).filter(Boolean).join("");
        return rows ? `${this._sectionHeader("info", "Other")}<table class="w-full">${rows}</table>` : "";
    },

    // ── Internal intel ────────────────────────────────────

    _renderInternalSection(entries) {
        const section = document.getElementById("internal-intel-section");
        const panel   = document.getElementById("internal-intel-panel");
        if (!section || !panel) return;

        const filtered = entries.filter(([, fields]) =>
            (fields || []).some(f => !this._isEmpty(f.value))
        );
        if (!filtered.length) { section.classList.add("hidden"); return; }

        panel.innerHTML = "";
        filtered.forEach(([modKey, fields]) => {
            const visible = (fields || []).filter(f => !this._isEmpty(f.value));
            const seen = {};
            visible.forEach(f => { if (!seen[f.name]) seen[f.name] = f; });
            const rows = Object.values(seen).map(f => {
                const v    = Array.isArray(f.value) ? f.value.join(", ") : String(f.value);
                const disp = v.length > 28 ? v.slice(0, 26) + "…" : v;
                if (f.link) return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="py-0.5">
                            <a href="${f.link}" target="_blank" rel="noopener noreferrer" title="${v}"
                               class="text-[9px] text-violet-400 hover:text-violet-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2 h-2 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="text-[9px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                    </tr>`;
            }).join("");
            const card = document.createElement("div");
            card.innerHTML = `
                <div class="flex items-center gap-1.5 mb-1.5">
                    <i data-lucide="${this._modIcon(modKey)}" class="w-3 h-3 text-violet-400 shrink-0"></i>
                    <span class="text-[9px] text-violet-400 uppercase tracking-widest font-semibold">${this._modLabel(modKey)}</span>
                </div>
                <table class="w-full">${rows}</table>`;
            panel.appendChild(card);
        });
        lucide.createIcons({ nodes: [panel] });
        section.classList.remove("hidden");
    },

    _renderError(msg) {
        const p = document.getElementById("qualif-panel");
        if (p) p.innerHTML = `<p class="text-red-400 text-[9px] py-1">⚠ ${msg}</p>`;
    },

    async _triggerEnrich() {
        if (!this._current) return;
        const { nodeData, caseId } = this._current;
        JobLog?.push?.({ message: `🔍 Enrich ${nodeData.label}…`, status: "running" });
        const result = await App.runAction({ action: "enrich", case_id: caseId, indicator_filter: nodeData.label });
        if (result?.job_id) {
            App.socket?.on?.("job_update", function handler(d) {
                if (d.job_id === result.job_id && d.status === "done") {
                    App.socket.off("job_update", handler);
                    EnrichPanel.load(nodeData, caseId);
                }
            });
        }
    },
};