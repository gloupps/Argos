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
            urlscan:"scan-eye", viewdns:"globe", opencti:"database", misp:"share-2",
            threatfox:"bug" }[k] || "box";
    },
    _isEmpty(v) {
        if (v === null || v === undefined || v === "") return true;
        if (typeof v === "number" && v === 0) return true;
        if (Array.isArray(v) && v.filter(x => x !== "" && x !== null && typeof x !== "object").length === 0 && !v.some(x => x && typeof x === "object")) return true;
        return false;
    },

        _openShodanServiceModal(encoded) {
        let svc = {};
        try { svc = JSON.parse(decodeURIComponent(escape(atob(encoded)))); }
        catch(e) { svc = { error: "decode error" }; }
 
        const port      = svc.port      || "?";
        const transport = svc.transport || "tcp";
        const product   = svc.product   || svc.module || "—";
        const version   = svc.version   || "";
        const title     = `${port}/${transport}${product !== "—" ? ` · ${product}` : ""}`;
 
        // Helper pour rendre une section de détails
        const section = (icon, label, rows) => `
            <div class="border border-slate-800 rounded-lg overflow-hidden">
                <div class="flex items-center gap-2 px-3 py-2 bg-slate-900/60 border-b border-slate-800">
                    <i data-lucide="${icon}" class="w-3 h-3 text-slate-500 shrink-0"></i>
                    <span class="text-[9px] text-slate-400 uppercase tracking-wider font-semibold">${label}</span>
                </div>
                <table class="w-full p-2">
                    <tbody class="divide-y divide-slate-800/50">${rows}</tbody>
                </table>
            </div>`;
 
        const row = (k, v, cls = "text-slate-300") => {
            if (!v && v !== 0) return "";
            const disp = typeof v === "string"
                ? v.replace(/</g,"&lt;").replace(/>/g,"&gt;")
                : (Array.isArray(v) ? v.join(", ") : String(v));
            return `
                <tr>
                    <td class="text-[8.5px] text-slate-500 pr-3 py-1 pl-3 whitespace-nowrap align-top w-28">${k}</td>
                    <td class="text-[8.5px] ${cls} font-mono py-1 pr-3 break-all">${disp}</td>
                </tr>`;
        };
 
        const sections = [];
 
        // ── Général ──
        let genRows = "";
        genRows += row("Port", `${port}/${transport}`);
        if (product !== "—")  genRows += row("Product", `${product}${version ? ` ${version}` : ""}`);
        if (svc.info)         genRows += row("Info", svc.info);
        if (svc.module)       genRows += row("Module", svc.module);
        if (svc.timestamp)    genRows += row("Last seen", svc.timestamp);
        if (genRows) sections.push(section("server", "General", genRows));
 
        // ── HTTP ──
        if (svc.http) {
            let h = "";
            h += row("Status",     svc.http.status);
            h += row("Title",      svc.http.title);
            h += row("Server",     svc.http.server);
            h += row("WAF",        svc.http.waf);
            h += row("Redirects",  svc.http.redirects ? `${svc.http.redirects} redirect(s)` : null);
            if (svc.http.components?.length)
                h += row("Tech",   svc.http.components.join(", "), "text-cyan-300");
            if (h) sections.push(section("globe", "HTTP", h));
        }
 
        // ── SSL/TLS ──
        if (svc.ssl) {
            let s = "";
            s += row("CN",       svc.ssl.cn);
            s += row("Issuer",   svc.ssl.issuer);
            s += row("Expires",  svc.ssl.expires);
            if (svc.ssl.san?.length)
                s += row("SAN", svc.ssl.san.slice(0, 8).join(", ") + (svc.ssl.san.length > 8 ? ` +${svc.ssl.san.length - 8}` : ""), "text-blue-300");
            if (svc.ssl.versions?.length)
                s += row("Protocols", svc.ssl.versions.join(", "));
            if (s) sections.push(section("lock", "TLS / Certificate", s));
        }
 
        // ── SSH ──
        if (svc.ssh) {
            let sh = "";
            sh += row("Type", svc.ssh.type);
            Object.entries(svc.ssh).forEach(([k, v]) => {
                if (k !== "type") sh += row(k, v, "text-slate-400");
            });
            if (sh) sections.push(section("terminal", "SSH", sh));
        }
 
        // ── CPE ──
        if (svc.cpe?.length) {
            const cpeRows = svc.cpe.map(c => row("CPE", c, "text-slate-400")).join("");
            sections.push(section("package", "CPE", cpeRows));
        }
 
        // ── CVEs ──
        if (svc.vulns?.length) {
            const cveRows = svc.vulns.map(cve => {
                const yr  = parseInt(cve.match(/CVE-(\d{4})/)?.[1] || "0");
                const cls = yr >= 2021 ? "text-red-400" : "text-amber-400";
                return row("CVE", cve, cls);
            }).join("");
            sections.push(section("bug", `Vulnerabilities (${svc.vulns.length})`, cveRows));
        }
 
        // ── Banner ──
        if (svc.banner) {
            const escaped = svc.banner.replace(/</g,"&lt;").replace(/>/g,"&gt;");
            sections.push(`
                <div class="border border-slate-800 rounded-lg overflow-hidden">
                    <div class="flex items-center gap-2 px-3 py-2 bg-slate-900/60 border-b border-slate-800">
                        <i data-lucide="terminal" class="w-3 h-3 text-slate-500 shrink-0"></i>
                        <span class="text-[9px] text-slate-400 uppercase tracking-wider font-semibold">Banner</span>
                    </div>
                    <pre class="text-[8px] font-mono text-slate-400 p-3 overflow-auto max-h-40 whitespace-pre-wrap break-all leading-relaxed">${escaped}</pre>
                </div>`);
        }
 
        // ── Rendu modal ──
        let modal = document.getElementById("shodan-service-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "shodan-service-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4";
        modal.innerHTML = `
            <div class="relative w-full max-w-lg max-h-[85vh] flex flex-col
                        bg-slate-950 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
                <div class="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
                    <span class="text-[11px] font-bold text-slate-200 flex items-center gap-2">
                        <i data-lucide="layers" class="w-3.5 h-3.5 text-blue-400"></i>
                        ${title}
                    </span>
                    <button onclick="document.getElementById('shodan-service-modal').remove()"
                            class="text-slate-500 hover:text-white transition">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <div class="flex-1 overflow-auto p-4 space-y-3">
                    ${sections.length ? sections.join("") : '<p class="text-[9px] text-slate-600">No detail available.</p>'}
                </div>
            </div>`;
        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        lucide.createIcons({ nodes: [modal] });
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
    _THEME_MAP: {
        "Malware Family":  "threat",
        "Threat Type":     "threat",
        "Avg Confidence":  "threat",
        "IOC Count":       "threat",
        "Reporters":       "other",
        "ThreatFox Entry": "intel",
        "Collections":      "vt_refs",
        "Malware Names":    "vt_refs",
        "Reports":          "vt_refs",
        "Other Sightings":  "vt_refs",
        "Detection Score": "threat",  "Confidence Score": "threat",
        "Malicious":       "threat",  "Suspicious":       "threat",
        "Reputation":      "threat",  "Scan Count":       "threat",
        "Threat Actors":   "threat",
        "Organization":    "host", "ASN": "host", "ASN Owner": "host",
        "Country":         "host", "OS": "host", "Registrar": "host",
        "Last Seen":       "host", "Last Analysis": "host", "Last Scan": "host",
        "Usage":           "host", "Services": "shodan_services", "Name": "host",
        "Type":            "host", "Server Headers": "host",
        "Scan Report":     "urlscan_meta",
        "Screenshot":      "screenshot",
        "HTTP Transactions": "urlscan_web",
        "Redirects":         "urlscan_web",
        "Links":             "urlscan_web",
        "DOM":               "urlscan_content",
        "Text Content":      "urlscan_content",
        "TLS Cert Domains":  "dns",
        "Open Ports":      "ports",
        "Hostnames":       "dns", "Domains": "dns", "Hosted Domains": "dns",
        "Domain Count":    "dns", "Last Resolved": "dns",
        "Resolved IPs":    "dns", "Associated IPs": "dns", "Subdomains Seen": "dns",
        "Vulnerabilities": "vulns",
        "Tags":            "tags", "Categories": "tags", "Indicator Types": "tags",
        "In OpenCTI":      "intel", "Detection": "intel", "Labels": "intel",
        "VT Reports":      "intel", "Report Count": "intel", "OpenCTI Link": "intel",
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

        const ORDER = ["threat","vt_refs","host","ports","vulns","dns","tags","urlscan_meta","screenshot","urlscan_web","urlscan_content","shodan_services","other"];
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

        // ── THREAT ──
        if (theme === "threat") {
            const scoreItems = items.filter(({ field }) => field.type === "score");
            const kvItems    = items.filter(({ field }) => field.type !== "score");
            let html = "";
            if (scoreItems.length) {
                const bars = scoreItems.map(({ mod, field }) => {
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
                html += `<div class="space-y-1.5 mb-2">${bars}</div>`;
            }
            if (kvItems.length) {
                const seen = {};
                kvItems.forEach(({ mod, field }) => {
                    const k = field.name, num = Number(field.value);
                    if (!seen[k] || (!isNaN(num) && num > Number(seen[k].field.value)))
                        seen[k] = { mod, field };
                });
                const rows = Object.values(seen).map(({ mod, field }) => {
                    const v   = String(field.value);
                    const num = Number(v);
                    const isThreatCount = ["Malicious", "Suspicious"].includes(field.name);
                    const cls = isThreatCount && !isNaN(num) && num > 0
                        ? "text-red-400 font-bold"
                        : Array.isArray(field.value) ? "text-amber-400" : "text-slate-300";
                    const display = Array.isArray(field.value)
                        ? field.value.slice(0, 3).join(", ") + (field.value.length > 3 ? ` +${field.value.length - 3}` : "")
                        : v;
                    return `
                        <tr>
                            <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                            <td class="text-[10px] ${cls} font-mono py-0.5">${display}</td>
                            <td class="text-[9px] text-slate-600 pl-2 py-0.5 whitespace-nowrap">${this._modLabel(mod)}</td>
                        </tr>`;
                }).join("");
                html += `<table class="w-full">${rows}</table>`;
            }
            return `${this._sectionHeader("shield-alert", "Threat")}${html}`;
        }

        // ── HOST ──
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

        // ── PORTS ──
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

        // ── VULNS ──
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
        
        // ── SHODAN SERVICES ──
        if (theme === "shodan_services") {
            // La value est un tableau d'objets service
            const services = [];
            items.forEach(({ field }) => {
                const val = field.value;
                if (Array.isArray(val)) services.push(...val);
                else if (val && typeof val === "object") services.push(val);
            });
            if (!services.length) return "";
 
            const btns = services.map((svc, idx) => {
                const port      = svc.port      || "?";
                const transport = svc.transport || "tcp";
                const product   = svc.product   || svc.module || "";
                const version   = svc.version   || "";
                const httpTitle = svc.http?.title || "";
                const vulnCount = (svc.vulns || []).length;
                const hasSSL    = !!svc.ssl;
                const hasHTTP   = !!svc.http;
 
                // Couleur du badge port selon protocole/risque
                const RISKY = new Set([21,22,23,25,53,80,110,135,139,143,443,445,
                                       1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017,6667]);
                const portCls = RISKY.has(Number(port))
                    ? "bg-red-500/15 border-red-500/40 text-red-400"
                    : "bg-slate-800/80 border-slate-700/60 text-slate-300";
 
                // Ligne principale : port + transport + product
                const productLabel = product
                    ? `<span class="text-slate-400 truncate">${product}${version ? ` <span class="text-slate-600">${version}</span>` : ""}</span>`
                    : `<span class="text-slate-600 italic text-[8px]">unknown</span>`;
 
                // Badges contextuels
                const badges = [];
                if (hasSSL)    badges.push(`<span class="text-[7.5px] px-1 py-px rounded bg-blue-500/10 border border-blue-500/30 text-blue-400">TLS</span>`);
                if (hasHTTP)   badges.push(`<span class="text-[7.5px] px-1 py-px rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">HTTP</span>`);
                if (vulnCount) badges.push(`<span class="text-[7.5px] px-1 py-px rounded bg-red-500/10 border border-red-500/30 text-red-400">${vulnCount} CVE${vulnCount > 1 ? "s" : ""}</span>`);
 
                // Sous-titre : title HTTP ou banner preview
                const subtitle = httpTitle
                    ? `<div class="text-[8px] text-slate-500 font-mono truncate mt-0.5">${httpTitle.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</div>`
                    : (svc.banner
                        ? `<div class="text-[8px] text-slate-600 font-mono truncate mt-0.5">${svc.banner.slice(0,60).replace(/[\r\n]+/g," ").replace(/</g,"&lt;")}</div>`
                        : "");
 
                // Encodage du service pour la modal
                let encoded = "";
                try { encoded = btoa(unescape(encodeURIComponent(JSON.stringify(svc)))); }
                catch(e) { encoded = btoa(JSON.stringify(svc).replace(/[^\x00-\x7F]/g,"?")); }
 
                return `
                    <button onclick="EnrichPanel._openShodanServiceModal('${encoded}')"
                            class="flex items-start gap-2 w-full text-left rounded border border-slate-700/50
                                   hover:border-blue-500/40 bg-slate-900/30 hover:bg-slate-900/60
                                   px-2 py-1.5 transition group">
                        <span class="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${portCls}">${port}</span>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-1.5 flex-wrap">
                                <span class="text-[8.5px] text-slate-500">${transport}</span>
                                ${productLabel}
                                ${badges.join("")}
                            </div>
                            ${subtitle}
                        </div>
                        <i data-lucide="chevron-right" class="w-2.5 h-2.5 text-slate-700 group-hover:text-slate-400 shrink-0 mt-1 transition"></i>
                    </button>`;
            }).join("");
 
            return `${this._sectionHeader("layers", "Services", services.length)}<div class="space-y-1">${btns}</div>`;
        }


        // ── DNS ──
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

        // ── TAGS ──
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

        // ── URLSCAN META ──
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

        // ── SCREENSHOT ──
        if (theme === "screenshot") {
            const item = items[0];
            if (!item) return "";
            const src  = String(item.field.value);
            const href = item.field.link || src;
            return `
                ${this._sectionHeader("camera", "Screenshot")}
                <button onclick="EnrichPanel._openScreenshotModal('${src}', '${href}')"
                        class="block rounded overflow-hidden border border-slate-700/60
                               hover:border-blue-500/40 transition w-full text-left">
                    <img src="${src}" alt="URLScan screenshot"
                         class="w-full object-cover"
                         style="max-height:120px;object-position:top"
                         loading="lazy"
                         onerror="this.closest('button').style.display='none'">
                </button>`;
        }

        // ── URLSCAN WEB : transactions / redirects / links ──
        if (theme === "urlscan_web") {
            const iconMap = {
                "HTTP Transactions": "arrow-right-left",
                "Redirects":         "corner-right-down",
                "Links":             "link",
            };
            const sections = [];
            ["HTTP Transactions", "Redirects", "Links"].forEach(name => {
                const matched = items.filter(({ field }) => field.name === name);
                if (!matched.length) return;
                const allVals = [];
                matched.forEach(({ field }) => {
                    (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allVals.push(String(v)));
                });
                if (!allVals.length) return;
                const max = matched[0].field.max || 15;
                const rows = allVals.slice(0, max).map(v => {
                    const statusMatch = v.match(/^(\d{3})\s/);
                    let statusBadge = "";
                    let rest = v;
                    if (statusMatch) {
                        const code = parseInt(statusMatch[1]);
                        const cls  = code >= 500 ? "text-red-400" : code >= 400 ? "text-amber-400" : code >= 300 ? "text-blue-400" : "text-green-400";
                        statusBadge = `<span class="${cls} font-bold mr-1">${code}</span>`;
                        rest = v.slice(4);
                    }
                    const disp = rest.length > 90 ? rest.slice(0, 88) + "…" : rest;
                    return `<div class="text-[8.5px] font-mono text-slate-400 truncate py-px" title="${v}">${statusBadge}${disp}</div>`;
                }).join("");
                const overflow = allVals.length > max ? `<div class="text-[8px] text-slate-600 mt-0.5">+${allVals.length - max} more</div>` : "";
                const icon = iconMap[name] || "activity";
                sections.push(`
                    <div>
                        <div class="flex items-center gap-1 mb-1">
                            <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500 shrink-0"></i>
                            <span class="text-[8px] text-slate-500 uppercase tracking-wider">${name}</span>
                            <span class="text-[8px] text-slate-700 ml-auto">${allVals.length}</span>
                        </div>
                        <div class="space-y-px">${rows}${overflow}</div>
                    </div>`);
            });
            if (!sections.length) return "";
            return `${this._sectionHeader("activity", "Web Activity")}<div class="space-y-3">${sections.join("")}</div>`;
        }

        // ── URLSCAN CONTENT : DOM + Text Content → modal ──
        if (theme === "urlscan_content") {
            const btns = items.map(({ field }) => {
                if (field.type !== "text_modal") return "";
                const val     = String(field.value || "");
                const label   = field.name;
                const icon    = label === "DOM" ? "code-2" : "file-text";
                const preview = val.slice(0, 80).replace(/</g, "&lt;").replace(/>/g, "&gt;");
                let encoded = "";
                try { encoded = btoa(unescape(encodeURIComponent(val.slice(0, 50000)))); } catch(e) { encoded = btoa(val.slice(0, 50000)); }
                return `
                    <button onclick="EnrichPanel._openTextModal('${label}', '${encoded}')"
                            class="flex items-center gap-2 w-full text-left rounded border border-slate-700/60
                                   hover:border-blue-500/40 bg-slate-900/40 px-2 py-1.5 transition">
                        <i data-lucide="${icon}" class="w-3 h-3 text-slate-500 shrink-0"></i>
                        <div class="flex-1 min-w-0">
                            <div class="text-[9px] font-semibold text-slate-300">${label}</div>
                            <div class="text-[8px] text-slate-600 font-mono truncate">${preview}…</div>
                        </div>
                        <i data-lucide="maximize-2" class="w-2.5 h-2.5 text-slate-600 shrink-0"></i>
                    </button>`;
            }).filter(Boolean).join("");
            return btns ? `${this._sectionHeader("file-code", "Page Content")}<div class="space-y-1.5">${btns}</div>` : "";
        }

        // ── INTEL ──
        if (theme === "intel") {
            const seen = {};
            items.forEach(({ mod, field }) => { if (!seen[field.name]) seen[field.name] = { mod, field }; });
            const rows = Object.values(seen).map(({ mod, field }) => {
                const v    = Array.isArray(field.value) ? field.value.join(", ") : String(field.value);
                const disp = v.length > 28 ? v.slice(0, 26) + "…" : v;
                if (field.link) return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="py-0.5">
                            <a href="${field.link}" target="_blank" rel="noopener noreferrer" title="${v}"
                               class="text-[9px] text-violet-400 hover:text-violet-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2 h-2 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[9px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="text-[9px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                    </tr>`;
            }).join("");
            return rows ? `${this._sectionHeader("database", "Intel")}<table class="w-full">${rows}</table>` : "";
        }

        // ── VT REFS (Collections, Malware, Reports, Other Sightings) ──
        if (theme === "vt_refs") {
            const fieldOrder = [
                { name: "Malware Names",   icon: "bug",         color: "text-red-400"    },
                { name: "Reports",         icon: "file-text",   color: "text-blue-400"   },
                { name: "Other Sightings", icon: "eye",         color: "text-amber-400"  },
                { name: "Collections",     icon: "folder-open", color: "text-slate-400"  },
            ];
            const blocks = [];
            fieldOrder.forEach(({ name, icon, color }) => {
                const matched = items.filter(({ field }) => field.name === name);
                if (!matched.length) return;
                const vals = [];
                matched.forEach(({ field }) => {
                    (Array.isArray(field.value) ? field.value : [field.value])
                        .forEach(v => v && vals.push(String(v)));
                });
                if (!vals.length) return;
                const rows = vals.slice(0, 10).map(v => {
                    const sep = v.indexOf(" — ");
                    const title    = sep !== -1 ? v.slice(0, sep) : v;
                    const subtitle = sep !== -1 ? v.slice(sep + 3) : "";
                    const tDisp = title.length > 40 ? title.slice(0, 38) + "…" : title;
                    const sDisp = subtitle.length > 60 ? subtitle.slice(0, 58) + "…" : subtitle;
                    return `
                        <div class="flex items-start gap-1.5 py-1 border-b border-slate-800/40 last:border-0">
                            <i data-lucide="${icon}" class="w-2.5 h-2.5 ${color} shrink-0 mt-0.5"></i>
                            <div class="min-w-0">
                                <div class="text-[9px] text-slate-200 font-medium truncate" title="${title}">${tDisp}</div>
                                ${sDisp ? `<div class="text-[8px] text-slate-500 truncate">${sDisp}</div>` : ""}
                            </div>
                        </div>`;
                }).join("");
                const overflow = vals.length > 10
                    ? `<div class="text-[8px] text-slate-600 pt-0.5">+${vals.length - 10} more</div>` : "";
                blocks.push(`
                    <div class="mb-2">
                        <div class="flex items-center gap-1 mb-1">
                            <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500"></i>
                            <span class="text-[8px] text-slate-500 uppercase tracking-wider font-semibold">${name}</span>
                            <span class="text-[8px] text-slate-600 ml-1">${vals.length}</span>
                        </div>
                        ${rows}${overflow}
                    </div>`);
            });
            return blocks.length
                ? `${this._sectionHeader("layers", "VT Associations", items.length)}${blocks.join("")}`
                : "";
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

    // ── Modals ────────────────────────────────────────────

    _openScreenshotModal(src, reportHref) {
        let modal = document.getElementById("screenshot-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "screenshot-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm";
        modal.innerHTML = `
            <div class="relative max-w-4xl w-full mx-4">
                <div class="flex items-center justify-between mb-2 px-1">
                    <a id="screenshot-modal-link" href="${reportHref}" target="_blank" rel="noopener noreferrer"
                       class="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 transition">
                        <i data-lucide="external-link" class="w-3 h-3"></i> Open report
                    </a>
                    <button onclick="document.getElementById('screenshot-modal').remove()"
                            class="text-slate-400 hover:text-white transition">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <img src="${src}" alt="Screenshot"
                     class="w-full rounded border border-slate-700/60 shadow-2xl">
            </div>`;
        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        lucide.createIcons({ nodes: [modal] });
    },

    _openTextModal(label, encoded) {
        let text = "";
        try { text = decodeURIComponent(escape(atob(encoded))); } catch(e) { text = "(decode error)"; }
        let modal = document.getElementById("text-content-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "text-content-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4";
        const icon = label === "DOM" ? "code-2" : "file-text";
        modal.innerHTML = `
            <div class="relative w-full max-w-4xl max-h-[85vh] flex flex-col
                        bg-slate-950 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
                <div class="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
                    <span class="text-[11px] font-bold text-slate-200 flex items-center gap-2">
                        <i data-lucide="${icon}" class="w-3.5 h-3.5 text-blue-400"></i>
                        ${label}
                    </span>
                    <div class="flex items-center gap-3">
                        <button onclick="EnrichPanel._copyTextModal()" title="Copy"
                                class="text-slate-500 hover:text-slate-200 transition text-[10px] flex items-center gap-1">
                            <i data-lucide="copy" class="w-3 h-3"></i> Copy
                        </button>
                        <button onclick="document.getElementById('text-content-modal').remove()"
                                class="text-slate-500 hover:text-white transition">
                            <i data-lucide="x" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
                <pre id="text-modal-content"
                     class="flex-1 overflow-auto p-4 text-[9px] font-mono text-slate-300
                            leading-relaxed whitespace-pre-wrap break-words"></pre>
            </div>`;
        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        document.getElementById("text-modal-content").textContent = text;
        lucide.createIcons({ nodes: [modal] });
    },

    _copyTextModal() {
        const content = document.getElementById("text-modal-content")?.textContent || "";
        navigator.clipboard.writeText(content).catch(() => {});
    },

    // ── Helpers ───────────────────────────────────────────

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