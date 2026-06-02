// app/static/js/modules/qualif.js

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
            threatfox:"bug", elasticsearch:"database", censys:"scan-line" }[k] || "box";
    },
    _isEmpty(v) {
        if (v === null || v === undefined || v === "") return true;
        if (typeof v === "number" && v === 0) return true;
        if (Array.isArray(v) && v.filter(x => x !== "" && x !== null && typeof x !== "object").length === 0 && !v.some(x => x && typeof x === "object")) return true;
        return false;
    },

    // ── Modal service unifié (Shodan + Censys) ────────────

    _openServiceModal(encoded) {
        let payload = {};
        try { payload = JSON.parse(decodeURIComponent(escape(atob(encoded)))); } catch(e) { payload = {}; }

        const source = payload.source || "shodan";
        const svc    = payload.svc || {};

        const port      = svc.port      || "?";
        const proto     = svc.transport || "tcp";
        const product   = svc.product   || svc.module || svc.service || "";
        const version   = svc.version   || "";
        const srcLabel  = source === "shodan" ? "Shodan" : "Censys";
        const srcColor  = source === "shodan" ? "text-amber-400" : "text-cyan-400";
        const title     = `${port}/${proto}${product ? " — " + product : ""}`;

        const section = (icon, label, content) => `
            <div>
                <div class="flex items-center gap-2 mb-1.5">
                    <i data-lucide="${icon}" class="w-3 h-3 text-slate-500 shrink-0"></i>
                    <span class="text-[15px] text-slate-400 uppercase tracking-wider font-semibold">${label}</span>
                </div>
                ${content}
            </div>`;

        const kv = (rows) => `<table class="w-full">${rows.map(([k,v]) =>
            `<tr>
                <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap w-28">${k}</td>
                <td class="text-[15px] text-slate-300 font-mono py-0.5 break-all">${v}</td>
            </tr>`
        ).join("")}</table>`;

        const sections = [];

        // ── Info générale ──
        const infoRows = [["Port", `${port}/${proto}`]];
        if (product) infoRows.push(["Product", product]);
        if (version) infoRows.push(["Version", version]);
        if (svc.info)   infoRows.push(["Info", svc.info]);
        if (svc.os)     infoRows.push(["OS", svc.os]);
        if (svc.timestamp) infoRows.push(["Last Seen", svc.timestamp?.slice(0, 10)]);
        if (svc.service_name) infoRows.push(["Service Name", svc.service_name]);
        sections.push(section("info", "General", kv(infoRows)));

        // ── TLS / Cert ──
        const tlsRows = [];
        if (svc.tls_cn)     tlsRows.push(["CN", svc.tls_cn]);
        if (svc.tls_issuer) tlsRows.push(["Issuer", svc.tls_issuer]);
        if (svc.tls_expiry) tlsRows.push(["Expiry", svc.tls_expiry?.slice(0, 10)]);
        if (svc.jarm)       tlsRows.push(["JARM", svc.jarm]);
        if (svc.cert_sha256) tlsRows.push(["SHA-256", svc.cert_sha256.slice(0, 16) + "…"]);
        if (tlsRows.length) sections.push(section("lock", "TLS / Certificate", kv(tlsRows)));

        // ── SSH (Shodan) ──
        if (svc.ssh) {
            const ssh = svc.ssh;
            const sshRows = [];
            if (ssh.type)        sshRows.push(["Type", ssh.type]);
            if (ssh.fingerprint) sshRows.push(["Fingerprint", ssh.fingerprint]);
            if (ssh.kex?.kex_algorithms) sshRows.push(["KEX", ssh.kex.kex_algorithms.slice(0,2).join(", ")]);
            if (sshRows.length) sections.push(section("terminal-square", "SSH", kv(sshRows)));
        }

        // ── HTTP ──
        const httpRows = [];
        if (svc.http_status)       httpRows.push(["Status",       svc.http_status]);
        if (svc.http_reason)       httpRows.push(["Reason",       svc.http_reason]);
        if (svc.http_title)        httpRows.push(["Title",        svc.http_title]);
        if (svc.http_server)       httpRows.push(["Server",       svc.http_server]);
        if (svc.http?.title)       httpRows.push(["Title",        svc.http.title]);
        if (svc.http?.status_code) httpRows.push(["Status",       svc.http.status_code]);
        if (svc.http_content_type) httpRows.push(["Content-Type", svc.http_content_type]);
        if (svc.http_powered_by)   httpRows.push(["X-Powered-By", svc.http_powered_by]);
        if (svc.http_location)     httpRows.push(["Location",     svc.http_location]);
        if (svc.http_auth)         httpRows.push(["Auth",         svc.http_auth]);
        if (svc.http_x_frame)      httpRows.push(["X-Frame",      svc.http_x_frame]);
        if (svc.http_hsts)         httpRows.push(["HSTS",         svc.http_hsts]);
        if (svc.http_body_hash)    httpRows.push(["Body SHA256",  svc.http_body_hash]);
        if (httpRows.length) sections.push(section("globe", "HTTP", kv(httpRows)));

        // ── DNS (Censys) ──
        const dnsRows = [];
        if (svc.dns?.reverse_dns) dnsRows.push(["Reverse DNS", Array.isArray(svc.dns.reverse_dns) ? svc.dns.reverse_dns[0] : svc.dns.reverse_dns]);
        if (dnsRows.length) sections.push(section("globe-2", "DNS", kv(dnsRows)));

        // ── CVEs ──
        if (svc.vulns?.length) {
            const badges = svc.vulns.map(v =>
                `<a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" rel="noopener noreferrer"
                    class="text-[15px] px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30
                           text-red-400 hover:text-red-300 font-mono transition">${v}</a>`
            ).join("");
            sections.push(section("bug", "Vulnerabilities",
                `<div class="flex flex-wrap gap-1">${badges}</div>`));
        }

        // ── Banner ──
        if (svc.banner) {
            const esc = svc.banner.replace(/</g,"&lt;").replace(/>/g,"&gt;");
            sections.push(section("terminal", "Banner",
                `<pre class="text-[12px]  font-mono text-slate-400 whitespace-pre-wrap break-all
                             max-h-28 overflow-y-auto bg-slate-900/60 rounded p-2">${esc}</pre>`));
        }

        let modal = document.getElementById("service-detail-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "service-detail-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4";
        modal.innerHTML = `
            <div class="relative w-full max-w-lg max-h-[85vh] flex flex-col
                        bg-slate-950 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
                <div class="flex items-center justify-between px-4 py-3 border-b border-slate-800 shrink-0">
                    <span class="text-[15px] font-bold text-slate-200 flex items-center gap-2">
                        <i data-lucide="plug" class="w-3.5 h-3.5 ${srcColor}"></i>
                        ${title}
                        <span class="text-[12px]  ${srcColor} font-semibold ml-1">${srcLabel}</span>
                    </span>
                    <button onclick="document.getElementById('service-detail-modal').remove()"
                            class="text-slate-500 hover:text-white transition">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <div class="flex-1 overflow-auto p-4 space-y-4">
                    ${sections.join("")}
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
        if (h) h.innerHTML = `<p class="text-slate-500 text-[14px] italic">Right-click a node to enrich it.</p>`;
        if (p) p.innerHTML = "";
        document.getElementById("internal-intel-section")?.classList.add("hidden");
    },

    _renderHeader(nodeData) {
        const el = document.getElementById("qualif-header");
        if (!el) return;
        el.innerHTML = `
            <div class="flex items-center justify-between gap-2 min-w-0">
                <p class="text-[15px] font-bold font-mono truncate text-white" title="${nodeData.label}">${nodeData.label}</p>
                <button onclick="EnrichPanel._triggerEnrich()" title="Re-enrich"
                        class="text-slate-600 hover:text-blue-400 transition shrink-0">
                    <i data-lucide="refresh-cw" class="w-3 h-3"></i>
                </button>
            </div>
            <div class="flex gap-1 mt-1 flex-wrap" id="header-badges">
                <span class="bg-slate-800 text-slate-500 text-[15px] px-1.5 py-0.5 rounded uppercase">${nodeData.type}</span>
                <span class="bg-slate-800 text-slate-500 text-[15px] px-1.5 py-0.5 rounded uppercase">${nodeData.nodeType}</span>
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
        b.className = `flex items-center gap-1 text-[15px] font-bold px-1.5 py-0.5 rounded border ${cls}`;
        b.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${dot} inline-block"></span>${label} · ${maxScore}`;
        el.appendChild(b);
    },

    _renderLoading() {
        const grid = document.getElementById("enrich-grid");
        if (grid) grid.innerHTML = `<p class="text-slate-600 text-[15px] py-2 animate-pulse col-span-3">Loading…</p>`;
    },

    _clear() {
        if (this._abortCtrl) { this._abortCtrl.abort(); this._abortCtrl = null; }
        this._current = null;
        const h = document.getElementById("qualif-header");
        const grid = document.getElementById("enrich-grid");
        if (h) h.innerHTML = `<p class="text-slate-500 text-[15px] italic">Right-click a node to enrich it.</p>`;
        if (grid) grid.innerHTML = "";
    },

    // ── Mapping champ → thème ─────────────────────────────
    _THEME_MAP: {
        // ── THREAT ──
        "Detection Score":      "threat",
        "Malicious":            "threat",
        "Suspicious":           "threat",
        "Reputation":           "threat",
        "Scan Count":           "threat",
        "Threat Actors":        "threat",
        "Malware Family":       "threat",
        "Malware Description":  "threat",
        "Threat Type":          "threat",
        "Avg Confidence":       "threat",
        "IOC Count":            "threat",
        "ThreatFox Entry":      "threat",

        // ── HOST ──
        "Organization":         "host",
        "ASN":                  "host",
        "OS":                   "host",
        "Country":              "host",
        "City":                 "host",
        "ISP":                  "host",
        "Network":              "host",
        "Whois Org":            "host",
        "IP Address":           "host",
        "Reverse DNS":          "host",
        "Certificates Found":   "host",
        "Certificate Issuers":  "host",
        "Censys Results":       "host",
        "Censys Host":          "host",
        "Censys Certs":         "host",
        "Censys Certificate":   "host",
        "Censys Search":        "host",
        "Latest Expiry":        "host",
        "Subject DN":           "host",
        "Issuer DN":            "host",
        "Valid From":           "host",
        "Valid Until":          "host",
        "Sig Algorithm":        "host",
        "Key Type":             "host",
        "Last Seen":            "host",
        "First Seen":           "host",

        // ── SERVICES ──
        "Services":             "shodan_services",
        "Censys Services":      "censys_services",

        // ── VULNS ──
        "Vulnerabilities":      "vulns",
        "Open Ports":           "ports",

        // ── DNS ──
        "Passive DNS":          "dns",
        "Hostnames":            "dns",
        "Domains":              "dns",
        "DNS Names":            "dns",
        "Related Names (SAN)":  "dns",
        "SANs / Names":         "dns",
        "Hosts Using Cert":     "dns",
        "Cert SHA-256":         "dns",
        "IP Addresses":         "dns",

        // ── TAGS ──
        "Tags":                 "tags",
        "Certificate Issuers":  "tags",

        // ── WEB ──
        "URLScan":              "urlscan_meta",
        "HTTP Transactions":    "urlscan_web",
        "Redirects":            "urlscan_web",
        "Links":                "urlscan_web",
        "DOM":                  "urlscan_content",
        "Body Text":            "urlscan_content",
        "Screenshot":           "screenshot",

        // ── RELATIONS ──
        "Communicating Files":       "vt_refs",
        "Contacted IPs":             "vt_refs",
        "Contacted Domains":         "vt_refs",
        "Contacted URLs":            "vt_refs",
        "Related Threat Actors":     "vt_refs",
        "Related References":        "vt_refs",
        "Collections":               "vt_refs",
        "Comments":                  "vt_refs",
        "Referrer URLs":             "vt_refs",
        "Redirecting URLs":          "vt_refs",
        "Redirects To":              "vt_refs",
        "Subdomains":                "vt_refs",
        "CNAME Records":             "vt_refs",
        "MX Records":                "vt_refs",
        "NS Records":                "vt_refs",
        "SOA Records":               "vt_refs",
        "SSL Certificates":          "vt_refs",
    },
    _getTheme(name) { return this._THEME_MAP[name] || "other"; },

    // ── Grid layout ───────────────────────────────────────

    _gridCols: parseInt(localStorage.getItem("enrich-grid-cols") || "1", 10),

    _setGridCols(n) {
        this._gridCols = n;
        localStorage.setItem("enrich-grid-cols", String(n));
        const grid = document.getElementById("enrich-grid");
        if (grid) {
            grid.className = `grid gap-2 grid-cols-${n}`;
            // Adapter l'alignement vertical des boxes
            grid.style.alignItems = "start";
        }
        [1, 2, 3].forEach(i => {
            const btn = document.getElementById(`enrich-col-${i}`);
            if (!btn) return;
            btn.className = `enrich-col-btn px-2 py-1 rounded transition ${
                i === n
                    ? "bg-green-500/20 text-green-400"
                    : "text-slate-500 hover:text-slate-300 hover:bg-slate-800"
            }`;
        });
    },

    _initGrid() {
        const saved = parseInt(localStorage.getItem("enrich-grid-cols") || "1", 10);
        this._setGridCols(saved);
    },

    // ── Rendu principal ───────────────────────────────────

    _renderInfo(nodeData, info) {
        const grid = document.getElementById("enrich-grid");
        if (!grid) return;

        // Initialiser la grille au bon nombre de colonnes
        this._initGrid();

        if (!info || !Object.keys(info.modules || {}).length) {
            grid.innerHTML = `
                <div class="col-span-3 py-3 space-y-2">
                    <p class="text-slate-600 text-[15px]">No enrichment data yet.</p>
                    <button onclick="EnrichPanel._triggerEnrich()"
                            class="flex items-center gap-1 text-[15px] text-blue-400 hover:text-blue-300 transition">
                        <i data-lucide="zap" class="w-3 h-3"></i> Enrich now
                    </button>
                </div>`;
            lucide.createIcons({ nodes: [grid] });
            return;
        }

        const internalKeys = this._internalKeys();
        const entries  = Object.entries(info.modules);
        const external = entries.filter(([k]) => !internalKeys.includes(k));
        const internal = entries.filter(([k]) =>  internalKeys.includes(k));

        // Verdict global
        let maxScore = null;
        entries.forEach(([, fields]) => (fields || []).forEach(f => {
            if (f.type === "score" && !this._isEmpty(f.value)) {
                const v = Number(f.value);
                if (maxScore === null || v > maxScore) maxScore = v;
            }
        }));
        this._injectVerdictBadge(maxScore);

        // Collecter tous les champs externes par thème
        const themes = {};
        external.forEach(([modKey, fields]) => {
            (fields || []).forEach(f => {
                if (this._isEmpty(f.value)) return;
                const theme = this._getTheme(f.name);
                if (!themes[theme]) themes[theme] = [];
                themes[theme].push({ mod: modKey, field: f });
            });
        });

        const BOX_CONFIG = [
            { key: "threat",    icon: "shield-alert", label: "Threat",    color: "red",    open: true  },
            { key: "host",      icon: "server",       label: "Host",      color: "blue",   open: true  },
            { key: "services",  icon: "plug",         label: "Services",  color: "cyan",   open: false },
            { key: "vulns",     icon: "bug",          label: "Vulns",     color: "orange", open: false },
            { key: "dns",       icon: "globe-2",      label: "DNS",       color: "green",  open: false },
            { key: "tags",      icon: "tag",          label: "Tags",      color: "violet", open: false },
            { key: "web",       icon: "monitor",      label: "WEB",       color: "sky",    open: false },
            { key: "relations", icon: "git-fork",     label: "Relations", color: "amber",  open: false },
            { key: "other",     icon: "info",         label: "Other",     color: "slate",  open: false },
        ];

        const mergeMap = {
            "shodan_services": "services",
            "censys_services": "services",
            "vt_refs":         "relations",
            "urlscan_meta":    "web",
            "urlscan_web":     "web",
            "urlscan_content": "web",
            "screenshot":      "web",
        };
        const mergedThemes = {};
        Object.entries(themes).forEach(([t, items]) => {
            const dest = mergeMap[t] || t;
            if (!mergedThemes[dest]) mergedThemes[dest] = [];
            items.forEach(item => mergedThemes[dest].push({ ...item, origTheme: t }));
        });

        const colorMap = {
            red:    "text-red-400 border-red-500/20 bg-red-500/5",
            blue:   "text-blue-400 border-blue-500/20 bg-blue-500/5",
            cyan:   "text-cyan-400 border-cyan-500/20 bg-cyan-500/5",
            orange: "text-orange-400 border-orange-500/20 bg-orange-500/5",
            green:  "text-green-400 border-green-500/20 bg-green-500/5",
            violet: "text-violet-400 border-violet-500/20 bg-violet-500/5",
            sky:    "text-sky-400 border-sky-500/20 bg-sky-500/5",
            amber:  "text-amber-400 border-amber-500/20 bg-amber-500/5",
            slate:  "text-slate-400 border-slate-500/20 bg-slate-500/5",
        };

        // Vider la grille
        grid.innerHTML = "";

        // Injecter chaque box comme enfant direct de la grille
        BOX_CONFIG
            .filter(cfg => mergedThemes[cfg.key]?.length)
            .forEach(cfg => {
                const items = mergedThemes[cfg.key];
                const body  = this._renderThemeBody(cfg.key, items);
                if (!body) return;
                const clr   = colorMap[cfg.color] || colorMap.slate;
                const [iconCls, borderCls, bgCls] = clr.split(" ");
                const boxId  = `enrich-box-${cfg.key}`;
                const isOpen = cfg.open;

                const div = document.createElement("div");
                div.className = `rounded-lg border ${borderCls} ${bgCls} overflow-hidden self-start`;
                div.innerHTML = `
                    <button onclick="EnrichPanel._toggleBox('${boxId}')"
                            class="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-white/5 transition">
                        <i data-lucide="${cfg.icon}" class="w-3.5 h-3.5 ${iconCls} shrink-0"></i>
                        <span class="text-sm font-semibold uppercase tracking-widest ${iconCls} flex-1">${cfg.label}</span>
                        <span class="text-[14px] text-slate-600 mr-1">${items.length}</span>
                        <i data-lucide="${isOpen ? 'chevron-up' : 'chevron-down'}"
                           class="w-3.5 h-3.5 text-slate-600 shrink-0" id="${boxId}-chevron"></i>
                    </button>
                    <div id="${boxId}" class="${isOpen ? '' : 'hidden'} px-3 pb-3 pt-1">
                        ${body}
                    </div>`;
                grid.appendChild(div);
            });

        if (!grid.children.length) {
            grid.innerHTML = `<p class="text-slate-600 text-[15px] italic py-2 col-span-3">No external data.</p>`;
        }

        lucide.createIcons({ nodes: [grid] });
        this._renderInternalSection(internal, grid);
    },

    _toggleBox(id) {
        const el  = document.getElementById(id);
        const chv = document.getElementById(`${id}-chevron`);
        if (!el) return;
        const hidden = el.classList.toggle("hidden");
        if (chv) {
            chv.setAttribute("data-lucide", hidden ? "chevron-down" : "chevron-up");
            lucide.createIcons({ nodes: [chv] });
        }
    },

    // ── Rendu du corps d'une box ──────────────────────────

    _renderThemeBody(theme, items) {

        // ── THREAT ──
        if (theme === "threat") {
            const scoreItems = items.filter(({ field }) => field.type === "score");
            const kvItems    = items.filter(({ field }) => field.type !== "score");
            let html = "";

            if (scoreItems.length) {
                const bars = scoreItems.map(({ mod, field }) => {
                    const pct   = Math.min(100, Math.max(0, Number(field.value)));
                    const color = pct > 70 ? "#ef4444" : pct > 40 ? "#f59e0b" : "#22c55e";
                    const txtcls = pct > 70 ? "text-red-400" : pct > 40 ? "text-amber-400" : "text-green-400";
                    return `
                        <div class="flex items-center gap-2">
                            <span class="flex items-center gap-1 text-[15px] text-slate-500 w-20 shrink-0 truncate"
                                  title="${this._modLabel(mod)}">
                                <i data-lucide="${this._modIcon(mod)}" class="w-2.5 h-2.5 shrink-0"></i>
                                ${this._modLabel(mod)}
                            </span>
                            <div class="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                                <div class="h-full rounded-full" style="width:${pct}%;background:${color}"></div>
                            </div>
                            <span class="text-[14px] font-bold ${txtcls} w-6 text-right shrink-0">${pct}</span>
                        </div>`;
                }).join("");
                html += `<div class="space-y-1.5 mb-3">${bars}</div>`;
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
                        ? field.value.slice(0, 3).join(", ") + (field.value.length > 3 ? "…" : "")
                        : v.length > 26 ? v.slice(0, 24) + "…" : v;

                    // Champ texte long (ex: Malware Description)
                    if (field.type === "text") {
                        return `
                            <tr>
                                <td colspan="2" class="py-1">
                                    <div class="text-[15px] text-slate-500 mb-0.5">${field.name}</div>
                                    <div class="text-[15px] text-slate-300 italic leading-relaxed">${v}</div>
                                </td>
                            </tr>`;
                    }

                    return `
                        <tr>
                            <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap align-top">${field.name}</td>
                            <td class="text-[15px] ${cls} font-mono py-0.5 truncate" title="${v}">${display}</td>
                        </tr>`;
                }).filter(Boolean).join("");
                if (rows) html += `<table class="w-full">${rows}</table>`;
            }

            return html || null;
        }

        // ── HOST ──
        if (theme === "host") {
            const seen = {};
            items.forEach(({ mod, field }) => {
                if (!seen[field.name]) seen[field.name] = { mod, field };
            });
            const rows = Object.values(seen).map(({ mod, field }) => {
                const v    = Array.isArray(field.value) ? field.value.join(", ") : String(field.value);
                const disp = v.length > 28 ? v.slice(0, 26) + "…" : v;
                if (field.link) return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="py-0.5">
                            <a href="${field.link}" target="_blank" rel="noopener noreferrer" title="${v}"
                               class="text-[15px] text-blue-400 hover:text-blue-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2 h-2 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="text-[15px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                    </tr>`;
            }).join("");
            return rows ? `<table class="w-full">${rows}</table>` : null;
        }

        // ── SERVICES (Shodan + Censys fusionnés) ──
        if (theme === "services") {
            const allServices = [];
            items.forEach(({ mod, field, origTheme }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => {
                    if (v) allServices.push({ svc: v, source: origTheme === "shodan_services" ? "shodan" : "censys" });
                });
            });
            if (!allServices.length) return null;

            const btns = allServices.slice(0, 30).map(({ svc, source }) => {
                let encoded = "";
                try { encoded = btoa(unescape(encodeURIComponent(JSON.stringify({ svc, source })))); } catch(e) { encoded = ""; }

                const s       = typeof svc === "object" ? svc : {};
                const port    = s.port || "?";
                const proto   = s.transport || "tcp";
                const product = s.product || s.module || s.service || "";
                const hasVulns = s.vulns?.length > 0;
                const hasTLS   = !!s.tls_cn;

                const srcBadge = source === "shodan"
                    ? `<span class="text-[11px] text-amber-500/70 font-semibold ml-auto shrink-0">SHD</span>`
                    : `<span class="text-[11px] text-cyan-500/70 font-semibold ml-auto shrink-0">CSY</span>`;
                const vulnBadge = hasVulns
                    ? `<span class="text-[12px]  text-red-400 font-bold shrink-0">${s.vulns.length} CVE</span>` : "";
                const tlsBadge = hasTLS && !hasVulns
                    ? `<span class="text-[11px] text-cyan-600 shrink-0">TLS</span>` : "";

                return `
                    <button onclick="EnrichPanel._openServiceModal('${encoded}')"
                            class="flex items-center gap-2 w-full text-left rounded border border-slate-700/50
                                   hover:border-slate-600 bg-slate-900/40 px-2 py-1 transition">
                        <span class="text-[15px] font-mono text-cyan-400 shrink-0 w-20">${port}/${proto}</span>
                        ${product ? `<span class="text-[15px] text-slate-400 truncate flex-1">${product}</span>` : `<span class="flex-1"></span>`}
                        ${vulnBadge}${tlsBadge}${srcBadge}
                    </button>`;
            }).join("");
            const overflow = allServices.length > 30
                ? `<div class="text-[12px]  text-slate-600 pt-1">+${allServices.length - 30} more</div>` : "";
            return `<div class="space-y-0.5">${btns}${overflow}</div>`;
        }

        // ── VULNS ──
        if (theme === "vulns") {
            const allVulns = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allVulns.add(String(v)));
            });
            const arr = [...allVulns];
            if (!arr.length) return null;
            const badges = arr.slice(0, 20).map(v =>
                `<a href="https://nvd.nist.gov/vuln/detail/${v}" target="_blank" rel="noopener noreferrer"
                    class="text-[15px] px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30
                           text-red-400 hover:text-red-300 font-mono transition">${v}</a>`
            ).join("");
            const overflow = arr.length > 20 ? `<span class="text-[12px]  text-slate-600">+${arr.length - 20}</span>` : "";
            return `<div class="flex flex-wrap gap-1">${badges}${overflow}</div>`;
        }

        // ── DNS ──
        if (theme === "dns") {
            const byName = {};
            items.forEach(({ field }) => {
                const vals = Array.isArray(field.value) ? field.value : [field.value];
                if (!byName[field.name]) byName[field.name] = new Set();
                vals.forEach(v => v && byName[field.name].add(String(v)));
            });
            const sections = [];
            Object.entries(byName).forEach(([name, valSet]) => {
                const arr = [...valSet];
                const tags = arr.slice(0, 12).map(v =>
                    `<span class="text-[15px] px-1.5 py-0.5 rounded border bg-slate-800/60
                                  border-slate-700/50 text-slate-300 font-mono truncate max-w-full"
                           title="${v}">${v.length > 30 ? v.slice(0,28)+"…" : v}</span>`
                ).join("");
                const overflow = arr.length > 12 ? `<span class="text-[12px]  text-slate-600">+${arr.length-12}</span>` : "";
                sections.push(`
                    <div class="mb-2">
                        <div class="text-[12px]  text-slate-500 uppercase tracking-wider mb-1">${name}</div>
                        <div class="flex flex-wrap gap-1">${tags}${overflow}</div>
                    </div>`);
            });
            return sections.length ? sections.join("") : null;
        }

        // ── TAGS ──
        if (theme === "tags") {
            const allItems = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allItems.add(String(v)));
            });
            const arr = [...allItems];
            if (!arr.length) return null;
            const tags = arr.slice(0, 15).map(v =>
                `<span class="text-[15px] px-1.5 py-0.5 rounded border bg-slate-800 border-slate-700/50 text-slate-400">${v}</span>`
            ).join("");
            const overflow = arr.length > 15 ? `<span class="text-[15px] text-slate-600">+${arr.length-15}</span>` : "";
            return `<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`;
        }

        // ── WEB (URLScan : meta + screenshot + web activity + content) ──
        if (theme === "web") {
            const parts = [];

            // Meta links
            const metaItems = items.filter(i => i.origTheme === "urlscan_meta");
            if (metaItems.length) {
                const links = metaItems.map(({ field }) => {
                    if (!field.link) return "";
                    return `<a href="${field.link}" target="_blank" rel="noopener noreferrer"
                               class="flex items-center gap-1 text-[15px] text-blue-400 hover:text-blue-300 transition w-fit">
                                <i data-lucide="external-link" class="w-2.5 h-2.5 shrink-0"></i>${field.value}
                            </a>`;
                }).filter(Boolean).join("");
                if (links) parts.push(`<div class="space-y-0.5 mb-2">${links}</div>`);
            }

            // Screenshot
            const ssItem = items.find(i => i.origTheme === "screenshot");
            if (ssItem) {
                const src  = String(ssItem.field.value);
                const href = ssItem.field.link || src;
                parts.push(`
                    <button onclick="EnrichPanel._openScreenshotModal('${src}', '${href}')"
                            class="block rounded overflow-hidden border border-slate-700/60
                                   hover:border-blue-500/40 transition w-full text-left mb-2">
                        <img src="${src}" alt="URLScan screenshot"
                             class="w-full object-cover" style="max-height:120px;object-position:top"
                             loading="lazy" onerror="this.closest('button').style.display='none'">
                    </button>`);
            }

            // Web activity (HTTP Transactions, Redirects, Links)
            const webItems = items.filter(i => i.origTheme === "urlscan_web");
            if (webItems.length) {
                const iconMap = { "HTTP Transactions": "arrow-right-left", "Redirects": "corner-right-down", "Links": "link" };
                const subsections = [];
                ["HTTP Transactions", "Redirects", "Links"].forEach(name => {
                    const matched = webItems.filter(({ field }) => field.name === name);
                    if (!matched.length) return;
                    const allVals = [];
                    matched.forEach(({ field }) => {
                        (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => v && allVals.push(String(v)));
                    });
                    if (!allVals.length) return;
                    const max = matched[0].field.max || 15;
                    const rows = allVals.slice(0, max).map(v => {
                        const statusMatch = v.match(/^(\d{3})\s/);
                        let statusBadge = "", rest = v;
                        if (statusMatch) {
                            const code = parseInt(statusMatch[1]);
                            const cls  = code >= 500 ? "text-red-400" : code >= 400 ? "text-amber-400" : code >= 300 ? "text-blue-400" : "text-green-400";
                            statusBadge = `<span class="${cls} font-bold mr-1">${code}</span>`;
                            rest = v.slice(4);
                        }
                        const disp = rest.length > 90 ? rest.slice(0, 88) + "…" : rest;
                        return `<div class="text-[8.5px] font-mono text-slate-400 truncate py-px" title="${v}">${statusBadge}${disp}</div>`;
                    }).join("");
                    const overflow = allVals.length > max ? `<div class="text-[12px]  text-slate-600 mt-0.5">+${allVals.length - max} more</div>` : "";
                    const icon = iconMap[name] || "activity";
                    subsections.push(`
                        <div class="mb-2">
                            <div class="flex items-center gap-1 mb-1">
                                <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500 shrink-0"></i>
                                <span class="text-[12px]  text-slate-500 uppercase tracking-wider">${name}</span>
                                <span class="text-[12px]  text-slate-700 ml-auto">${allVals.length}</span>
                            </div>
                            <div class="space-y-px">${rows}${overflow}</div>
                        </div>`);
                });
                if (subsections.length) parts.push(subsections.join(""));
            }

            // Page content (DOM, body text modals)
            const contentItems = items.filter(i => i.origTheme === "urlscan_content");
            if (contentItems.length) {
                const btns = contentItems.map(({ field }) => {
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
                                <div class="text-[15px] font-semibold text-slate-300">${label}</div>
                                <div class="text-[12px]  text-slate-600 font-mono truncate">${preview}…</div>
                            </div>
                            <i data-lucide="maximize-2" class="w-2.5 h-2.5 text-slate-600 shrink-0"></i>
                        </button>`;
                }).filter(Boolean).join("");
                if (btns) parts.push(`<div class="space-y-1.5">${btns}</div>`);
            }

            return parts.length ? parts.join("") : null;
        }

        // ── RELATIONS (VT refs) ──
        if (theme === "relations") {
            const typeOrder = ["communicating_files", "contacted_domains", "contacted_ips", "contacted_urls",
                               "related_threat_actors", "related_references", "collections", "comments",
                               "referrer_urls", "redirecting_urls", "redirects_to", "subdomains",
                               "cname_records", "mx_records", "ns_records", "soa_records", "historical_ssl_certificates"];
            const grouped = {};
            items.forEach(({ field }) => {
                if (field.type !== "vt_relation") return;
                const vals = Array.isArray(field.value) ? field.value : [field.value];
                if (!grouped[field.name]) grouped[field.name] = [];
                vals.forEach(v => v && grouped[field.name].push(v));
            });
            const blocks = [];
            const iconMap2 = {
                "Communicating Files": "file-code", "Contacted IPs": "network", "Contacted Domains": "globe",
                "Contacted URLs": "link", "Related Threat Actors": "user-x", "Collections": "folder",
                "Comments": "message-circle", "SSL Certificates": "lock", "Subdomains": "layers",
            };
            Object.entries(grouped).forEach(([name, vals]) => {
                if (!vals.length) return;
                const icon = iconMap2[name] || "activity";
                const rows = vals.slice(0, 10).map(item => {
                    if (typeof item !== "object") return `<div class="text-[15px] text-slate-400 font-mono truncate">${item}</div>`;
                    const primary   = item.sha256 || item.name || item.hostname || item.url || item.ip || item.text || item.value || "";
                    const secondary = item.description || (item.detections != null ? `${item.detections} det.` : "") || item.date || "";
                    const pDisp = primary.length > 32 ? primary.slice(0, 30) + "…" : primary;
                    const sDisp = secondary.length > 28 ? secondary.slice(0, 26) + "…" : secondary;
                    return `
                        <div class="flex flex-col py-0.5">
                            <span class="text-[15px] text-slate-300 font-mono truncate" title="${primary}">${pDisp}</span>
                            ${sDisp ? `<span class="text-[12px]  text-slate-500 truncate">${sDisp}</span>` : ""}
                        </div>`;
                }).join("");
                const overflow = vals.length > 10 ? `<div class="text-[12px]  text-slate-600 pt-0.5">+${vals.length - 10} more</div>` : "";
                blocks.push(`
                    <div class="mb-2">
                        <div class="flex items-center gap-1 mb-1">
                            <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500"></i>
                            <span class="text-[12px]  text-slate-500 uppercase tracking-wider font-semibold">${name}</span>
                            <span class="text-[12px]  text-slate-600 ml-1">${vals.length}</span>
                        </div>
                        ${rows}${overflow}
                    </div>`);
            });
            return blocks.length ? blocks.join("") : null;
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
                    <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                    <td class="text-[15px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                </tr>`;
        }).filter(Boolean).join("");
        return rows ? `<table class="w-full">${rows}</table>` : null;
    },

    // ── Internal intel ────────────────────────────────────

    _renderInternalSection(entries, grid) {
        if (!grid) grid = document.getElementById("enrich-grid");
        if (!grid) return;

        const filtered = entries.filter(([, fields]) =>
            (fields || []).some(f => !this._isEmpty(f.value))
        );
        if (!filtered.length) return;

        let cardsHtml = "";
        filtered.forEach(([modKey, fields]) => {
            const visible = (fields || []).filter(f => !this._isEmpty(f.value));

            if (modKey === "elasticsearch") {
                cardsHtml += `<div class="mb-2">${this._renderElasticsearchCard(visible)}</div>`;
                return;
            }

            const seen = {};
            visible.forEach(f => { if (!seen[f.name]) seen[f.name] = f; });
            const rows = Object.values(seen).map(f => {
                const v    = Array.isArray(f.value) ? f.value.join(", ") : String(f.value);
                const disp = v.length > 32 ? v.slice(0, 30) + "…" : v;
                if (f.link) return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="py-0.5">
                            <a href="${f.link}" target="_blank" rel="noopener noreferrer" title="${v}"
                               class="text-[15px] text-violet-400 hover:text-violet-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2.5 h-2.5 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="text-[15px] text-slate-300 font-mono py-0.5 truncate" title="${v}">${disp}</td>
                    </tr>`;
            }).join("");
            if (rows) cardsHtml += `
                <div class="mb-2">
                    <div class="flex items-center gap-1.5 mb-1.5">
                        <i data-lucide="${this._modIcon(modKey)}" class="w-3.5 h-3.5 text-violet-400 shrink-0"></i>
                        <span class="text-sm text-violet-400 uppercase tracking-widest font-semibold">${this._modLabel(modKey)}</span>
                    </div>
                    <table class="w-full">${rows}</table>
                </div>`;
        });

        if (!cardsHtml) return;

        const boxId = "enrich-box-internal";
        const div = document.createElement("div");
        div.className = "rounded-lg border border-violet-500/20 bg-violet-500/5 overflow-hidden self-start";
        div.innerHTML = `
            <button onclick="EnrichPanel._toggleBox('${boxId}')"
                    class="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-white/5 transition">
                <i data-lucide="database" class="w-3.5 h-3.5 text-violet-400 shrink-0"></i>
                <span class="text-sm font-semibold uppercase tracking-widest text-violet-400 flex-1">Internal Intelligence</span>
                <i data-lucide="chevron-up" class="w-3.5 h-3.5 text-slate-600 shrink-0" id="${boxId}-chevron"></i>
            </button>
            <div id="${boxId}" class="px-3 pb-3 pt-1">
                ${cardsHtml}
            </div>`;
        grid.appendChild(div);
        lucide.createIcons({ nodes: [div] });
    },

    // ── Elasticsearch — renderer dédié ───────────────────

    _renderElasticsearchCard(fields) {
        const byName  = {};
        fields.forEach(f => { if (!byName[f.name]) byName[f.name] = f; });

        const get     = name => byName[name]?.value ?? null;
        const getList = name => { const v = get(name); if (!v) return []; return Array.isArray(v) ? v : [v]; };

        const inEs      = get("In Elasticsearch");
        const totalHits = get("Total Hits");
        const firstSeen = get("First Seen");
        const lastSeen  = get("Last Seen");
        const indices   = getList("Indices");
        const events    = getList("Recent Events");
        const hosts     = getList("Hosts Observed");
        const users     = getList("Users Observed");
        const procs     = getList("Processes Observed");

        const found = inEs && inEs.includes("Yes");
        const presenceCls = found
            ? "bg-green-500/15 text-green-400 border border-green-500/25"
            : "bg-slate-800 text-slate-500 border border-slate-700/40";
        const presenceDot = found ? "bg-green-500" : "bg-slate-600";
        const presenceTxt = found ? `Found · <span class="font-bold">${totalHits}</span> hits` : "Not found";

        let html = `
            <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-1.5">
                    <i data-lucide="database" class="w-3 h-3 text-amber-400 shrink-0"></i>
                    <span class="text-[15px] text-amber-400 uppercase tracking-widest font-semibold">Elasticsearch</span>
                </div>
                <span class="flex items-center gap-1 text-[15px] font-bold px-1.5 py-0.5 rounded ${presenceCls}">
                    <span class="w-1.5 h-1.5 rounded-full ${presenceDot} inline-block"></span>
                    ${presenceTxt}
                </span>
            </div>`;

        if (!found) return html;

        // Dates first / last seen
        if (firstSeen || lastSeen) {
            html += `<div class="flex gap-2 mb-2">`;
            if (firstSeen) html += `
                <div class="flex-1 bg-slate-900/60 border border-slate-800 rounded px-2 py-1">
                    <div class="text-[12px]  text-slate-600 uppercase tracking-wider mb-0.5">First seen</div>
                    <div class="text-[15px] text-slate-300 font-mono">${firstSeen}</div>
                </div>`;
            if (lastSeen) html += `
                <div class="flex-1 bg-slate-900/60 border border-slate-800 rounded px-2 py-1">
                    <div class="text-[12px]  text-slate-600 uppercase tracking-wider mb-0.5">Last seen</div>
                    <div class="text-[15px] text-slate-300 font-mono">${lastSeen}</div>
                </div>`;
            html += `</div>`;
        }

        // Indices
        if (indices.length) {
            const tags = indices.slice(0, 8).map(idx => {
                const short = idx.length > 28 ? idx.slice(0, 26) + "…" : idx;
                return `<span class="text-[12px]  px-1.5 py-px rounded border bg-slate-900 border-amber-900/40
                                     text-amber-500/80 font-mono" title="${idx}">${short}</span>`;
            }).join("");
            const overflow = indices.length > 8 ? `<span class="text-[12px]  text-slate-600">+${indices.length - 8}</span>` : "";
            html += `
                <div class="mb-2">
                    <div class="text-[12px]  text-slate-600 uppercase tracking-wider mb-1">Indices</div>
                    <div class="flex flex-wrap gap-1">${tags}${overflow}</div>
                </div>`;
        }

        // Metadata : hosts / users / processes
        const metaRows = [
            { label: "Hosts",     icon: "monitor",  items: hosts },
            { label: "Users",     icon: "user",      items: users },
            { label: "Processes", icon: "terminal",  items: procs },
        ].filter(r => r.items.length);

        if (metaRows.length) {
            const rows = metaRows.map(r => {
                const vals = r.items.slice(0, 5).join(", ");
                const more = r.items.length > 5 ? ` +${r.items.length - 5}` : "";
                return `
                    <tr>
                        <td class="py-0.5 pr-2 whitespace-nowrap align-top w-20">
                            <span class="flex items-center gap-1 text-[15px] text-slate-500">
                                <i data-lucide="${r.icon}" class="w-2.5 h-2.5 shrink-0"></i>${r.label}
                            </span>
                        </td>
                        <td class="text-[15px] text-slate-300 font-mono py-0.5 break-all">
                            ${vals}<span class="text-slate-600">${more}</span>
                        </td>
                    </tr>`;
            }).join("");
            html += `<table class="w-full mb-2">${rows}</table>`;
        }

        // Événements récents
        if (events.length) {
            html += `
                <div class="text-[12px]  text-slate-600 uppercase tracking-wider mb-1">Recent events</div>
                <div class="space-y-1">`;
            events.slice(0, 5).forEach(ev => {
                const parts = String(ev).split(" | ");
                const ts    = parts[0] || "";
                const rest  = parts.slice(1);
                const badges = rest.map(p => {
                    const eq = p.indexOf("=");
                    if (eq === -1) {
                        const short = p.length > 60 ? p.slice(0, 58) + "…" : p;
                        const esc   = short.replace(/</g, "&lt;").replace(/>/g, "&gt;");
                        return `<span class="text-[12px]  text-slate-400 italic">${esc}</span>`;
                    }
                    const k      = p.slice(0, eq);
                    const v      = p.slice(eq + 1).replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const vShort = v.length > 32 ? v.slice(0, 30) + "…" : v;
                    return `<span class="inline-flex items-baseline gap-0.5">
                        <span class="text-[7.5px] text-slate-600">${k}</span>
                        <span class="text-[12px]  text-slate-200 font-mono">${vShort}</span>
                    </span>`;
                }).join(`<span class="text-slate-700 mx-0.5 select-none">·</span>`);
                html += `
                    <div class="bg-slate-900/50 border border-slate-800/60 rounded px-2 py-1.5">
                        <div class="text-[12px]  text-slate-600 font-mono mb-1">${ts}</div>
                        <div class="flex flex-wrap items-baseline gap-x-1 gap-y-0.5 leading-snug">
                            ${badges || '<span class="text-[12px]  text-slate-600 italic">no context fields</span>'}
                        </div>
                    </div>`;
            });
            html += `</div>`;
            if (events.length > 5)
                html += `<div class="text-[12px]  text-slate-600 mt-1 text-right">+${events.length - 5} more events</div>`;
        }

        return html;
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
                       class="flex items-center gap-1 text-[14px] text-blue-400 hover:text-blue-300 transition">
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
                    <span class="text-[15px] font-bold text-slate-200 flex items-center gap-2">
                        <i data-lucide="${icon}" class="w-3.5 h-3.5 text-blue-400"></i>
                        ${label}
                    </span>
                    <div class="flex items-center gap-3">
                        <button onclick="EnrichPanel._copyTextModal()" title="Copy"
                                class="text-slate-500 hover:text-slate-200 transition text-[14px] flex items-center gap-1">
                            <i data-lucide="copy" class="w-3 h-3"></i> Copy
                        </button>
                        <button onclick="document.getElementById('text-content-modal').remove()"
                                class="text-slate-500 hover:text-white transition">
                            <i data-lucide="x" class="w-4 h-4"></i>
                        </button>
                    </div>
                </div>
                <pre id="text-modal-content"
                     class="flex-1 overflow-auto p-4 text-[15px] font-mono text-slate-300
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
        if (p) p.innerHTML = `<p class="text-red-400 text-[15px] py-1">⚠ ${msg}</p>`;
    },

    async _triggerEnrich() {
        if (!this._current) return;
        const { nodeData, caseId } = this._current;
        JobLog?.push?.({ message: `🔍 Enrich ${nodeData.label}…`, status: "running" });
        const result = await App.runAction({
            action:           "enrich",
            case_id:          caseId,
            indicator_filter: nodeData.label,
            api_keys:         App._collectAllApiKeys(),
        });
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
