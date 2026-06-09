// app/static/js/modules/qualif.js

window.EnrichPanel = {

    _current:   null,
    _abortCtrl: null,

    _internalKeys() {
        const reg = Modules?.registry || {};
        const keys = Object.entries(reg)
            .filter(([k, m]) => m.type === "internal" || k === "misp" || k.startsWith("misp_ext_"))
            .map(([k]) => k);
        return keys.length ? keys : ["opencti", "misp"];
    },

    _modLabel(k) { return Modules?.registry?.[k]?.name || k; },

    _modIcon(k) {
        const i = Modules?.registry?.[k]?.icon;
        if (i) return i;
        return { virustotal:"shield", shodan:"radar", abuseipdb:"ban",
            urlscan:"scan-eye", viewdns:"globe", opencti:"database", misp:"share-2",
            threatfox:"bug", elasticsearch:"database", censys:"scan-line",hybrid_analysis:"flask-conical"}[k] || "box";
    },

    _isEmpty(v) {
        if (v === null || v === undefined || v === "") return true;
        if (typeof v === "number" && v === 0) return true;
        if (Array.isArray(v)) {
            if (v.length === 0) return true;
            if (v.some(x => x && typeof x === "object")) return false;
            return v.filter(x => x !== "" && x !== null).length === 0;
        }
        return false;
    },

    // Échappe les caractères spéciaux HTML pour les attributs
    _esc(v) {
        return String(v)
            .replace(/&/g, "&amp;")
            .replace(/"/g, "&quot;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
    },

    _countRenderedFields(theme, items) {
        // THREAT : scores individuels + kv dédupliqués par nom
        if (theme === "threat") {
            const scores = items.filter(({ field }) => field.type === "score").length;
            const seen = new Set();
            items.filter(({ field }) => field.type !== "score")
                .forEach(({ field }) => seen.add(field.name));
            return scores + seen.size;
        }

        // HOST : déduplication par field.name (même logique que _renderThemeBody "host")
        if (theme === "host") {
            const seen = new Set();
            items.forEach(({ field }) => seen.add(field.name));
            return seen.size;
        }

        // SERVICES : compter les ports uniques toutes sources confondues
        if (theme === "services") {
            const ports = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value]).forEach(v => {
                    if (!v) return;
                    const port = (typeof v === "object" ? v.port : null) || "?";
                    const proto = (typeof v === "object" ? v.transport : null) || "tcp";
                    ports.add(`${port}/${proto}`);
                });
            });
            return ports.size || items.length;
        }

        // TAGS : valeurs uniques aplaties
        if (theme === "tags") {
            let count = 0;
            items.forEach(({ field }) => {
                if (field.type === "vt_comment") {
                    count += Array.isArray(field.value) ? field.value.length : 1;
                } else {
                    (Array.isArray(field.value) ? field.value : [field.value])
                        .forEach(v => v && count++);
                }
            });
            return count;
        }

        // VULNS : valeurs uniques (CVE ids)
        if (theme === "vulns") {
            const seen = new Set();
            items.forEach(({ field }) => {
                (Array.isArray(field.value) ? field.value : [field.value])
                    .forEach(v => v && seen.add(String(v)));
            });
            return seen.size;
        }

        // DEFAULT : déduplication par nom de champ
        const seen = new Set();
        items.forEach(({ field }) => seen.add(field.name));
        return seen.size || items.length;
    },

    // Bouton copie inline — utilise data-attribute pour éviter tout problème d'échappement
    _copyBtn(v) {
        const id = "cb-" + Math.random().toString(36).slice(2, 8);
        setTimeout(() => {
            const btn = document.getElementById(id);
            if (btn) btn.addEventListener("click", (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(btn.dataset.val).then(() => {
                    btn.classList.add("text-green-400");
                    setTimeout(() => btn.classList.remove("text-green-400"), 1200);
                });
            });
        }, 0);
        const safeAttr = this._esc(v);
        return `<button id="${id}" data-val="${safeAttr}"
                        class="ml-1 shrink-0 text-slate-600 hover:text-slate-300 transition align-middle"
                        title="Copy full value">
                    <i data-lucide="copy" class="w-2.5 h-2.5 inline"></i>
                </button>`;
    },
    
    // Bouton "voir tout" pour les listes tronquées
    _listExpandBtn(label, allItems) {
        let encTitle = "", encItems = "";
        try {
            encTitle = btoa(unescape(encodeURIComponent(label)));
            encItems = btoa(unescape(encodeURIComponent(JSON.stringify(allItems))));
        } catch(e) {
            try { encTitle = btoa(label); encItems = btoa(JSON.stringify(allItems)); } catch(e2) {}
        }
        return `<button onclick="EnrichPanel._openListModal('${encTitle}', '${encItems}')"
                        class="text-[11px] text-slate-500 hover:text-violet-400 transition flex items-center gap-1 shrink-0"
                        title="Show all ${allItems.length} items">
                    <i data-lucide="maximize-2" class="w-2.5 h-2.5"></i>
                    <span>+${allItems.length} more</span>
                </button>`;
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
        if (svc.http_redirects)    httpRows.push(["Redirects",    svc.http_redirects]);
        if (svc.http_title)        httpRows.push(["Title",        svc.http_title]);
        if (svc.http_server)       httpRows.push(["Server",       svc.http_server]);
        if (svc.http_content_type) httpRows.push(["Content-Type", svc.http_content_type]);
        if (httpRows.length) sections.push(section("globe", "HTTP", kv(httpRows)));

        // ── Vulns ──
        if (svc.vulns?.length) {
            const badges = svc.vulns.slice(0, 15).map(cv =>
                `<a href="https://nvd.nist.gov/vuln/detail/${cv}" target="_blank" rel="noopener noreferrer"
                    class="text-[15px] px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30
                           text-red-400 hover:text-red-300 font-mono transition">${cv}</a>`
            ).join("");
            const overflow = svc.vulns.length > 15 ? `<span class="text-[12px] text-slate-600">+${svc.vulns.length - 15}</span>` : "";
            sections.push(section("bug", `Vulnerabilities (${svc.vulns.length})`,
                `<div class="flex flex-wrap gap-1">${badges}${overflow}</div>`));
        }

        // ── Raw banner ──
        if (svc.data) {
            const raw = String(svc.data).slice(0, 400).replace(/</g, "&lt;").replace(/>/g, "&gt;");
            sections.push(section("terminal", "Banner",
                `<pre class="text-[11px] font-mono text-slate-400 bg-slate-900/60 rounded p-2 overflow-auto max-h-28 whitespace-pre-wrap break-all">${raw}</pre>`));
        }

        let modal = document.getElementById("service-detail-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "service-detail-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4";
        modal.innerHTML = `
            <div class="relative w-full max-w-lg max-h-[85vh] flex flex-col
                        bg-slate-950 border border-slate-700 rounded-xl shadow-2xl overflow-hidden">
                <div class="flex items-center justify-between px-4 py-3 border-b
                            border-slate-800 shrink-0">
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
                <p class="text-[15px] font-bold font-mono truncate text-white" title="${this._esc(nodeData.label)}">${nodeData.label}</p>
                <button onclick="EnrichPanel._triggerEnrich()" title="Re-enrich"
                        class="text-slate-600 hover:text-blue-400 transition shrink-0">
                    <i data-lucide="refresh-cw" class="w-3 h-3"></i>
                </button>
            </div>
            <div class="flex gap-1 mt-1 flex-wrap" id="header-badges">
                <span class="bg-slate-800 text-slate-500 text-[15px] px-1.5 py-0.5 rounded uppercase">${nodeData.type}</span>
                ${(() => {
                    const nt = nodeData.nodeType || "correlated";
                    const cls = nt === "root"       ? "bg-red-500/20 text-red-400 border border-red-500/30"
                              : nt === "pivoted"    ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                              : nt === "pivot"      ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30"
                              :                      "bg-violet-500/20 text-violet-400 border border-violet-500/30";
                    return `<span class="text-[11px] px-1.5 py-0.5 rounded uppercase font-semibold border ${cls}">${nt}</span>`;
                })()}
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
        "Threat Actors":        "threat",
        "Malware Family":       "threat",
        "Malware Description":  "threat",
        "Threat Type":          "threat",
        "Avg Confidence":       "threat",
        "ThreatFox Entry":      "threat",
        "Verdict":              "threat",
        "Compromised":          "threat",
        "Reference":            "threat",
        "HA Tags":              "tags",

        // ── HOST ──
        "Organization":         "host",
        "ASN":                  "host",
        "OS":                   "host",
        "Country":              "host",
        "City":                 "host",
        "ISP":                  "host",
        "Last Seen":            "host",
        "First Seen":           "host",
        "Hostnames":            "host",
        "Domains":              "host",
        "Tags":                 "tags",

        // ── HASH / FILE (VT + HA) ──
        "MD5":                  "host",
        "SHA1":                 "host",
        "SHA256":               "host",
        "Size":                 "host",
        "File Type":            "host",
        "File Names":           "host",
        "Last Analysis":        "host",
        "Sandbox Environments": "host",

        // ── SERVICES ──
        "Services":             "shodan_services",
        "Censys Services":      "censys_services",

        // ── VULNS ──
        "Vulnerabilities":      "vulns",
        "CVEs":                 "vulns",

        // ── DNS ──
        "A":                    "dns",
        "AAAA":                 "dns",
        "MX":                   "dns",
        "NS":                   "dns",
        "TXT":                  "dns",
        "PTR":                  "dns",
        "CNAME":                "dns",
        "SOA":                  "dns",
        "Subdomains":           "dns",
        "Reverse DNS":          "dns",
        "Passive DNS":          "dns",

        // ── WEB ──
        "URLScan Result":       "urlscan_meta",
        "URLScan Search":       "urlscan_meta",
        "Page Title":           "urlscan_web",
        "HTTP Status":          "urlscan_web",
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
        "Comments":                  "tags",
        "Referrer URLs":             "vt_refs",
        "Redirecting URLs":          "vt_refs",
        "Redirects To":              "vt_refs",
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
                        <span class="text-[14px] text-slate-600 mr-1">${this._countRenderedFields(cfg.key, items)}</span>
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
                    const pct    = Math.min(100, Math.max(0, Number(field.value)));
                    const color  = pct > 70 ? "#ef4444" : pct > 40 ? "#f59e0b" : "#22c55e";
                    const txtcls = pct > 70 ? "text-red-400" : pct > 40 ? "text-amber-400" : "text-green-400";
                    return `
                        <div class="flex items-center gap-2">
                            <span class="flex items-center gap-1 text-[15px] text-slate-500 w-24 shrink-0 truncate"
                                  title="${this._esc(this._modLabel(mod))}">
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
                    const isThreatCount = [
                        "Malicious", "Suspicious",
                        "Malicious Reports", "Suspicious Reports",
                    ].includes(field.name);
                    const isAmber = [
                        "Threat Actors", "MITRE ATT&CK", "Malware Family",
                        "Latest Verdict",
                    ].includes(field.name);
                    const isYesDanger = (["Verdict"].includes(field.name) && ["malicious","malware"].includes(v.toLowerCase()))
                        || (field.name === "Compromised" && v === "Yes");
                    const cls = (isThreatCount && !isNaN(num) && num > 0) || isYesDanger
                        ? "text-red-400 font-bold"
                        : isAmber
                            ? "text-amber-400"
                            : Array.isArray(field.value) ? "text-amber-400" : "text-slate-300";

                    const isTrunc = !Array.isArray(field.value) && v.length > 26;
                    const display = Array.isArray(field.value)
                        ? field.value.slice(0, 3).join(", ") + (field.value.length > 3 ? "…" : "")
                        : isTrunc ? v.slice(0, 24) + "…" : v;

                    return `
                        <tr>
                            <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap align-top">${field.name}</td>
                            <td class="text-[15px] ${cls} font-mono py-0.5" title="${this._esc(v)}">${display}${isTrunc ? this._copyBtn(v) : ""}</td>
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
                const v      = Array.isArray(field.value) ? field.value.join(", ") : String(field.value);
                const isTrunc = v.length > 28;
                const disp   = isTrunc ? v.slice(0, 26) + "…" : v;
                if (field.link) return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="py-0.5">
                            <a href="${field.link}" target="_blank" rel="noopener noreferrer" title="${this._esc(v)}"
                               class="text-[15px] text-blue-400 hover:text-blue-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2 h-2 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                        <td class="text-[15px] text-slate-300 font-mono py-0.5" title="${this._esc(v)}">${disp}${isTrunc ? this._copyBtn(v) : ""}</td>
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

                const s        = typeof svc === "object" ? svc : {};
                const port     = s.port || "?";
                const proto    = s.transport || "tcp";
                const product  = s.product || s.module || s.service || "";
                const hasVulns = s.vulns?.length > 0;
                const hasTLS   = !!s.tls_cn;

                const srcBadge = source === "shodan"
                    ? `<span class="text-[11px] text-amber-500/70 font-semibold ml-auto shrink-0">SHD</span>`
                    : `<span class="text-[11px] text-cyan-500/70 font-semibold ml-auto shrink-0">CSY</span>`;
                const vulnBadge = hasVulns
                    ? `<span class="text-[12px] text-red-400 font-bold shrink-0">${s.vulns.length} CVE</span>` : "";
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
            const overflow = allServices.length > 2 ? `<div class="pt-1">${this._listExpandBtn("Services", allServices.map(s => `${s.port}/${s.transport||"tcp"}${s.product?" ("+s.product+")":""}`))}</div>` : "";
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
            const overflow = arr.length > 2 ? this._listExpandBtn("Vulnerabilities", arr) : "";
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
                const tags = arr.slice(0, 12).map(v => {
                    const esc  = this._esc(v);
                    const data = this._esc(JSON.stringify(v));
                    return `<button onclick="EnrichPanel._copyDns(this, ${data})"
                                    class="inline-flex items-center gap-1.5 text-[15px] px-1.5 py-0.5 rounded border
                                           bg-slate-800/60 border-slate-700/50 text-slate-300 font-mono break-all text-left
                                           hover:border-slate-500 hover:bg-slate-700/60 transition cursor-pointer group"
                                    title="Click to copy">
                                <span>${esc}</span>
                                <i data-lucide="clipboard" class="w-3 h-3 shrink-0 text-slate-600 opacity-0 group-hover:opacity-100 transition-opacity"></i>
                            </button>`;
                }).join("");
                const overflow = arr.length > 2 ? this._listExpandBtn(name, arr) : "";
                sections.push(`
                    <div class="mb-2">
                        <div class="text-[12px] text-slate-500 uppercase tracking-wider mb-1">${name}</div>
                        <div class="flex flex-wrap gap-1">${tags}${overflow}</div>
                    </div>`);
            });
            return sections.length ? sections.join("") : null;
        }

        // ── TAGS ──
        if (theme === "tags") {
            const commentItems = items.filter(({ field }) => field.type === "vt_comment");
            const tagItems     = items.filter(({ field }) => field.type !== "vt_comment");
            const parts = [];

            // ── Tags génériques (badges) ──
            if (tagItems.length) {
                const allTags = new Set();
                tagItems.forEach(({ field }) => {
                    (Array.isArray(field.value) ? field.value : [field.value])
                        .forEach(v => v && allTags.add(String(v)));
                });
                const arr = [...allTags];
                if (arr.length) {
                    const tags = arr.slice(0, 15).map(v =>
                        `<span class="text-[15px] px-1.5 py-0.5 rounded border bg-slate-800 border-slate-700/50 text-slate-400">${this._esc(v)}</span>`
                    ).join("");
                    const overflow = arr.length > 2 ? this._listExpandBtn("Tags", arr) : "";
                    parts.push(`<div class="flex flex-wrap gap-1">${tags}${overflow}</div>`);
                }
            }

            // ── VT community comments (blog-cards) ──
            if (commentItems.length) {
                if (parts.length) parts.push(`<div class="border-t border-slate-800 my-2"></div>`);
                parts.push(`<p class="text-[10px] text-slate-600 uppercase tracking-wider mb-2">VT Community</p>`);
                const cards = commentItems.flatMap(({ field }) => {
                    const list = Array.isArray(field.value) ? field.value : [field.value];
                    return list.filter(Boolean).map(c => {
                        const obj      = typeof c === "object" ? c : { text: String(c) };
                        const text = this._esc(obj.text || "").replace(/\n/g, "<br>");
                        const ts       = obj.date ? new Date(obj.date * 1000).toISOString().slice(0, 10) : null;
                        const pos      = obj.votes_pos || 0;
                        const neg      = obj.votes_neg || 0;
                        const dateHtml = ts
                            ? `<span class="ml-auto text-[10px] font-mono text-slate-600">${ts}</span>`
                            : "";
                        const votesHtml = (pos > 0 || neg > 0) ? `
                            <div class="flex items-center gap-2 px-3 pb-2 pt-1">
                                ${pos > 0 ? `<span class="flex items-center gap-1 text-[10px] text-green-500/70 border border-green-500/20 rounded px-1.5 py-0.5"><i data-lucide="thumbs-up" class="w-2.5 h-2.5"></i>${pos}</span>` : ""}
                                ${neg > 0 ? `<span class="flex items-center gap-1 text-[10px] text-red-400/60 border border-red-400/20 rounded px-1.5 py-0.5"><i data-lucide="thumbs-down" class="w-2.5 h-2.5"></i>${neg}</span>` : ""}
                            </div>` : "";
                        return `
                            <div class="rounded-lg border border-slate-700/40 bg-slate-900/60 overflow-hidden mb-2">
                                <div class="flex items-center gap-2 px-3 py-1.5 bg-slate-800/50 border-b border-slate-700/30">
                                    <span class="w-5 h-5 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-[9px] font-bold shrink-0">VT</span>
                                    <span class="text-[11px] font-medium text-slate-400">VT Community</span>
                                    <i data-lucide="shield" class="w-2.5 h-2.5 text-slate-600"></i>
                                    ${dateHtml}
                                </div>
                                <p class="px-3 py-2 text-[12px] text-slate-300 leading-relaxed">${text}</p>
                                ${votesHtml}
                            </div>`;
                    });
                }).join("");
                if (cards) parts.push(cards);
            }

            return parts.length ? parts.join("") : null;
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
                        return `<div class="text-[8.5px] font-mono text-slate-400 truncate py-px" title="${this._esc(v)}">${statusBadge}${disp}</div>`;
                    }).join("");
                    const overflow = allVals.length > max ? `<div class="text-[12px] text-slate-600 mt-0.5">+${allVals.length - max} more</div>` : "";
                    const icon = iconMap[name] || "activity";
                    subsections.push(`
                        <div class="mb-2">
                            <div class="flex items-center gap-1 mb-1">
                                <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500 shrink-0"></i>
                                <span class="text-[12px] text-slate-500 uppercase tracking-wider">${name}</span>
                                <span class="text-[12px] text-slate-700 ml-auto">${allVals.length}</span>
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
                                <div class="text-[12px] text-slate-600 font-mono truncate">${preview}…</div>
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
                            <span class="text-[15px] text-slate-300 font-mono truncate" title="${this._esc(primary)}">${pDisp}</span>
                            ${sDisp ? `<span class="text-[12px] text-slate-500 truncate">${sDisp}</span>` : ""}
                        </div>`;
                }).join("");
                const overflow = vals.length > 10 ? `<div class="text-[12px] text-slate-600 pt-0.5">+${vals.length - 10} more</div>` : "";
                blocks.push(`
                    <div class="mb-2">
                        <div class="flex items-center gap-1 mb-1">
                            <i data-lucide="${icon}" class="w-2.5 h-2.5 text-slate-500"></i>
                            <span class="text-[12px] text-slate-500 uppercase tracking-wider font-semibold">${name}</span>
                            <span class="text-[12px] text-slate-600 ml-1">${vals.length}</span>
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
            if (Array.isArray(field.value) && field.value.length > 2) {
                const preview = field.value.slice(0, 3).map(x => String(x)).join(", ");
                const expandBtn = this._listExpandBtn(field.name, field.value.map(x => String(x)));
                return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap align-top">${field.name}</td>
                        <td class="py-0.5">
                            <span class="text-[15px] text-slate-300 font-mono">${this._esc(preview)}…</span>
                            <span class="inline-block ml-1 align-middle">${expandBtn}</span>
                        </td>
                    </tr>`;
            }
            const v = Array.isArray(field.value) ? field.value.join(", ") : String(field.value ?? "");
            if (!v || v === "0") return "";
            const isTrunc = v.length > 26;
            const disp = isTrunc ? v.slice(0, 24) + "…" : v;
            return `
                <tr>
                    <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${field.name}</td>
                    <td class="text-[15px] text-slate-300 font-mono py-0.5" title="${this._esc(v)}">${disp}${isTrunc ? this._copyBtn(v) : ""}</td>
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
                // List fields: show first few + expand button
                if (Array.isArray(f.value) && f.value.length >= 2 && (f.type === "list" || f.field_type === "list")) {
                    const preview = f.value.slice(0, 2).map(x => String(x)).join(", ");
                    const expandBtn = this._listExpandBtn(f.name, f.value.map(x => String(x)));
                    if (f.link) return `
                        <tr>
                            <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap align-top">${f.name}</td>
                            <td class="py-0.5">
                                <span class="text-[15px] text-slate-300 font-mono">${preview}… </span>
                                ${expandBtn}
                            </td>
                        </tr>`;
                    return `
                        <tr>
                            <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap align-top">${f.name}</td>
                            <td class="py-0.5 flex items-center gap-2 flex-wrap">
                                <span class="text-[15px] text-slate-300 font-mono">${this._esc(preview)}…</span>
                                ${expandBtn}
                            </td>
                        </tr>`;
                }
                const v      = Array.isArray(f.value) ? f.value.join(", ") : String(f.value);
                const isTrunc = v.length > 32;
                const disp   = isTrunc ? v.slice(0, 30) + "…" : v;
                if (f.link) return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="py-0.5">
                            <a href="${f.link}" target="_blank" rel="noopener noreferrer" title="${this._esc(v)}"
                               class="text-[15px] text-violet-400 hover:text-violet-300 font-mono flex items-center gap-0.5 transition">
                                ${disp}<i data-lucide="external-link" class="w-2.5 h-2.5 shrink-0"></i>
                            </a>
                        </td>
                    </tr>`;
                return `
                    <tr>
                        <td class="text-[15px] text-slate-500 pr-3 py-0.5 whitespace-nowrap">${f.name}</td>
                        <td class="text-[15px] text-slate-300 font-mono py-0.5" title="${this._esc(v)}">${disp}${isTrunc ? this._copyBtn(v) : ""}</td>
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
                    <div class="text-[12px] text-slate-600 uppercase tracking-wider mb-0.5">First seen</div>
                    <div class="text-[15px] text-slate-300 font-mono">${firstSeen}</div>
                </div>`;
            if (lastSeen) html += `
                <div class="flex-1 bg-slate-900/60 border border-slate-800 rounded px-2 py-1">
                    <div class="text-[12px] text-slate-600 uppercase tracking-wider mb-0.5">Last seen</div>
                    <div class="text-[15px] text-slate-300 font-mono">${lastSeen}</div>
                </div>`;
            html += `</div>`;
        }

        // Indices
        if (indices.length) {
            const tags = indices.slice(0, 8).map(idx => {
                const short = idx.length > 26 ? idx.slice(0, 24) + "…" : idx;
                return `<span class="text-[12px] px-1.5 py-px rounded border bg-slate-900 border-amber-900/40
                                     text-amber-500/80 font-mono" title="${this._esc(idx)}">${short}</span>`;
            }).join("");
            const overflow = indices.length > 8 ? `<span class="text-[12px] text-slate-600">+${indices.length - 8}</span>` : "";
            html += `
                <div class="mb-2">
                    <div class="text-[12px] text-slate-600 uppercase tracking-wider mb-1">Indices</div>
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
                <div class="text-[12px] text-slate-600 uppercase tracking-wider mb-1">Recent events</div>
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
                        return `<span class="text-[12px] text-slate-400 italic">${esc}</span>`;
                    }
                    const k      = p.slice(0, eq);
                    const v      = p.slice(eq + 1).replace(/</g, "&lt;").replace(/>/g, "&gt;");
                    const vShort = v.length > 32 ? v.slice(0, 30) + "…" : v;
                    return `<span class="text-[12px] text-slate-500">${k}=</span><span class="text-[12px] text-slate-300 font-mono">${vShort}</span>`;
                }).join(" ");
                html += `
                    <div class="bg-slate-900/60 rounded px-2 py-1 border border-slate-800/60">
                        <div class="text-[11px] text-slate-600 font-mono mb-0.5">${ts}</div>
                        <div class="flex flex-wrap gap-x-2 gap-y-0.5">${badges}</div>
                    </div>`;
            });
            const moreEv = events.length > 5 ? `<div class="text-[12px] text-slate-600 mt-0.5">+${events.length - 5} more events</div>` : "";
            html += `${moreEv}</div>`;
        }

        return html;
    },

    // ── Screenshot modal ──────────────────────────────────

    _openScreenshotModal(src, href) {
        let modal = document.getElementById("screenshot-modal");
        if (modal) modal.remove();
        modal = document.createElement("div");
        modal.id = "screenshot-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm p-4";
        modal.innerHTML = `
            <div class="relative w-full max-w-4xl">
                <div class="flex items-center justify-between mb-2">
                    <a href="${href}" target="_blank" rel="noopener noreferrer"
                       class="flex items-center gap-1 text-[15px] text-blue-400 hover:text-blue-300 transition">
                        <i data-lucide="external-link" class="w-3 h-3"></i> Open in URLScan
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
    
    // ── Modal liste complète (champs type "list") ─────────

    _openListModal(encodedTitle, encodedItems) {
        let title = "";
        let items = [];
        try { title = decodeURIComponent(escape(atob(encodedTitle))); } catch(e) { title = "List"; }
        try { items = JSON.parse(decodeURIComponent(escape(atob(encodedItems)))); } catch(e) { items = []; }

        document.getElementById("list-detail-modal")?.remove();
        const modal = document.createElement("div");
        modal.id = "list-detail-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4";

        // Search state
        const modalId = "list-detail-modal";

        const rows = items.map(v => {
            const s = String(v);
            const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
            const isDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s) && !isIp;
            const isHash = /^[a-f0-9]{32,64}$/i.test(s);
            const isCve = /^CVE-\d{4}-\d+$/i.test(s);
            const isPort = /^\d{1,5}(\/\w+)?$/.test(s);

            let badge = "";
            if (isIp)     badge = `<span class="text-[10px] px-1 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400 shrink-0">IP</span>`;
            else if (isDomain) badge = `<span class="text-[10px] px-1 py-0.5 rounded bg-violet-500/10 border border-violet-500/20 text-violet-400 shrink-0">domain</span>`;
            else if (isHash) badge = `<span class="text-[10px] px-1 py-0.5 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 shrink-0">hash</span>`;
            else if (isCve) badge = `<span class="text-[10px] px-1 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 shrink-0">CVE</span>`;
            else if (isPort) badge = `<span class="text-[10px] px-1 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 shrink-0">port</span>`;

            const copyId = "lm-" + Math.random().toString(36).slice(2, 8);
            return `
                <div class="list-modal-row flex items-center gap-2 px-3 py-1.5 rounded hover:bg-slate-800/60 group"
                     data-val="${this._esc(s.toLowerCase())}">
                    ${badge}
                    <span class="font-mono text-[13px] text-slate-300 flex-1 break-all select-all">${this._esc(s)}</span>
                    <button id="${copyId}" data-copy="${this._esc(s)}"
                            class="opacity-0 group-hover:opacity-100 text-slate-600 hover:text-slate-300 transition shrink-0"
                            title="Copy">
                        <i data-lucide="copy" class="w-3 h-3"></i>
                    </button>
                </div>`;
        }).join("");

        let titleEncSafe = "";
        try { titleEncSafe = btoa(unescape(encodeURIComponent(title))); } catch(e) { titleEncSafe = encodedTitle; }

        modal.innerHTML = `
            <div class="bg-slate-950 border border-slate-700 rounded-xl shadow-2xl w-full max-w-lg flex flex-col max-h-[80vh]">
                <!-- Header -->
                <div class="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
                    <i data-lucide="list" class="w-4 h-4 text-slate-400 shrink-0"></i>
                    <span class="text-sm font-semibold text-white flex-1 truncate">${this._esc(title)}</span>
                    <span class="text-xs text-slate-500 shrink-0">${items.length} items</span>
                    <button onclick="EnrichPanel._copyAllList('${titleEncSafe}', '${encodedItems}')"
                            class="text-slate-500 hover:text-slate-300 transition ml-1 shrink-0" title="Copy all">
                        <i data-lucide="clipboard-copy" class="w-4 h-4"></i>
                    </button>
                    <button onclick="document.getElementById('list-detail-modal').remove()"
                            class="text-slate-500 hover:text-white transition ml-1 shrink-0">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <!-- Search -->
                <div class="px-3 py-2 border-b border-slate-800/60 shrink-0">
                    <div class="flex items-center gap-2 bg-slate-900 border border-slate-700/60 rounded-lg px-2.5 py-1.5">
                        <i data-lucide="search" class="w-3.5 h-3.5 text-slate-600 shrink-0"></i>
                        <input id="list-modal-search" type="text" placeholder="Filter…"
                               class="bg-transparent text-sm text-slate-300 placeholder-slate-600 outline-none flex-1 min-w-0"
                               oninput="EnrichPanel._filterListModal(this.value)">
                        <span id="list-modal-count" class="text-xs text-slate-600 shrink-0">${items.length}</span>
                    </div>
                </div>
                <!-- List -->
                <div id="list-modal-body" class="flex-1 overflow-y-auto py-1">
                    ${rows}
                </div>
            </div>`;

        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        lucide.createIcons({ nodes: [modal] });

        // Wire copy buttons
        modal.querySelectorAll("[data-copy]").forEach(btn => {
            btn.addEventListener("click", e => {
                e.stopPropagation();
                navigator.clipboard.writeText(btn.dataset.copy).then(() => {
                    btn.classList.add("text-green-400");
                    setTimeout(() => btn.classList.remove("text-green-400"), 1200);
                });
            });
        });

        // Focus search
        setTimeout(() => document.getElementById("list-modal-search")?.focus(), 50);
    },

    _filterListModal(query) {
        const q = query.toLowerCase().trim();
        const body = document.getElementById("list-modal-body");
        if (!body) return;
        let visible = 0;
        body.querySelectorAll(".list-modal-row").forEach(row => {
            const match = !q || row.dataset.val.includes(q);
            row.style.display = match ? "" : "none";
            if (match) visible++;
        });
        const counter = document.getElementById("list-modal-count");
        if (counter) counter.textContent = q ? `${visible} / ${body.querySelectorAll(".list-modal-row").length}` : String(body.querySelectorAll(".list-modal-row").length);
    },

    _copyAllList(encodedTitle, encodedItems) {
        let items = [];
        try { items = JSON.parse(decodeURIComponent(escape(atob(encodedItems)))); } catch(e) {}
        navigator.clipboard.writeText(items.join("\n")).then(() => {
            JobLog?.push?.({ message: `Copied ${items.length} items to clipboard`, status: "running" });
        });
    },

    _copyTextModal() {
        const content = document.getElementById("text-modal-content")?.textContent || "";
        navigator.clipboard.writeText(content).catch(() => {});
    },

    // ── Helpers ───────────────────────────────────────────

    _copyDns(btn, text) {
        navigator.clipboard.writeText(text).then(() => {
            const icon = btn.querySelector("[data-lucide]");
            if (icon) {
                icon.setAttribute("data-lucide", "check");
                icon.classList.remove("text-slate-600", "opacity-0");
                icon.classList.add("text-green-400", "opacity-100");
                lucide.createIcons({ nodes: [btn] });
                setTimeout(() => {
                    icon.setAttribute("data-lucide", "clipboard");
                    icon.classList.remove("text-green-400", "opacity-100");
                    icon.classList.add("text-slate-600", "opacity-0");
                    lucide.createIcons({ nodes: [btn] });
                }, 1200);
            }
        });
    },

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

    // ══════════════════════════════════════════════════════
    // ── IOC COMPARE ──────────────────────────────────────
    // ══════════════════════════════════════════════════════

    // Fields that are not meaningful to compare across IOCs
    _COMPARE_SKIP: new Set([
        "malicious", "suspicious", "reputation", "misp_link", "link", "Labels", "Domain Count", "In OpenCTI", "Last Seen", "Detection",
        "MISP Link", "Malicious", "Suspicious", "Reputation", "Censys Host", "Tags", "Last Scanned", "OpenCTI Link",
        "Detection Score", "detection_score", "scan_count", "Scan Count", "In MISP", "Matching Events", "Report Count", "Comments", "IOC Count",
    ]),

    _startCompare() {
        if (!this._current) {
            JobLog?.push?.({ message: "Select an IOC first", status: "running" });
            return;
        }
        const caseId = this._current.caseId;
        fetch(`/api/cases/${caseId}/info`)
            .then(r => r.json())
            .then(all => {
                const keys = Object.keys(all).filter(k => k !== this._current.nodeData.label);
                if (!keys.length) {
                    JobLog?.push?.({ message: "No other IOC to compare with", status: "running" });
                    return;
                }
                this._showComparePickerModal(keys, all);
            });
    },

    _showComparePickerModal(keys, allInfo) {
        document.getElementById("compare-picker-modal")?.remove();
        const modal = document.createElement("div");
        modal.id = "compare-picker-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm";

        const list = keys.map((k, i) => {
            const fields = allInfo[k];
            const hasData = fields && Object.keys(fields.modules || {}).length > 0;
            return `
                <label class="w-full text-left px-3 py-2 rounded-lg border border-slate-700/60
                    bg-slate-900 hover:bg-slate-800 hover:border-violet-500/40 transition
                    flex items-center gap-2 cursor-pointer group">
                    <input type="checkbox" data-ioc="${this._esc(k)}" value="${this._esc(k)}"
                           class="compare-ioc-checkbox accent-violet-500 w-3.5 h-3.5 shrink-0">
                    <span class="font-mono text-sm text-slate-200 flex-1 truncate">${this._esc(k)}</span>
                    ${hasData
                        ? `<span class="text-[11px] text-green-400 border border-green-500/20 bg-green-500/10 px-1.5 py-0.5 rounded">enriched</span>`
                        : `<span class="text-[11px] text-slate-600 border border-slate-700 px-1.5 py-0.5 rounded">no data</span>`}
                </label>`;
        }).join("");

        modal.innerHTML = `
            <div class="bg-slate-950 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 flex flex-col max-h-[70vh]">
                <div class="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
                    <i data-lucide="diff" class="w-4 h-4 text-violet-400"></i>
                    <span class="text-sm font-semibold text-white flex-1">Compare with…</span>
                    <span class="text-xs text-slate-500 font-mono truncate max-w-[160px]">${this._esc(this._current.nodeData.label)}</span>
                    <button onclick="document.getElementById('compare-picker-modal').remove()"
                            class="text-slate-500 hover:text-white transition ml-2">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <div class="flex-1 overflow-y-auto p-3 space-y-1.5">${list}</div>
                <div class="px-4 py-3 border-t border-slate-800 shrink-0 flex items-center justify-between gap-2">
                    <span class="text-xs text-slate-600" id="compare-selection-count">0 selected</span>
                    <button onclick="EnrichPanel._runCompareMulti()"
                            class="flex items-center gap-1.5 px-3 py-1.5 rounded bg-violet-600 hover:bg-violet-500
                                text-white text-xs font-semibold transition">
                        <i data-lucide="diff" class="w-3 h-3"></i> Compare
                    </button>
                </div>
            </div>`;

        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        lucide.createIcons({ nodes: [modal] });

        // Live selection counter
        modal.querySelectorAll(".compare-ioc-checkbox").forEach(cb => {
            cb.addEventListener("change", () => {
                const n = modal.querySelectorAll(".compare-ioc-checkbox:checked").length;
                modal.querySelector("#compare-selection-count").textContent =
                    n === 0 ? "0 selected" : `${n} selected`;
            });
        });
    },

    async _runCompareMulti() {
        const modal = document.getElementById("compare-picker-modal");
        const checked = [...(modal?.querySelectorAll(".compare-ioc-checkbox:checked") || [])];
        if (!checked.length) {
            JobLog?.push?.({ message: "Select at least one IOC to compare", status: "running" });
            return;
        }
        modal?.remove();

        const { nodeData, caseId } = this._current;
        const srcLabel = nodeData.label;
        const targetLabels = checked.map(cb => cb.value);

        const res = await fetch(`/api/cases/${caseId}/info`);
        const all = await res.json();

        const allLabels = [srcLabel, ...targetLabels];

        // ── Field types that are list-like and should be exploded item-by-item ──
        const LIST_TYPES = new Set(["list", "vt_relation", "censys_services", "shodan_services"]);

        // ── For vt_relation objects, extract a stable pivot string ──
        const _pivotVtRelation = (obj) => {
            if (typeof obj === "string") return obj;
            if (!obj || typeof obj !== "object") return null;
            // resolutions: {hostname, ip, date} → hostname or ip
            return obj.hostname || obj.ip || obj.url || obj.hash ||
                   obj.sha256 || obj.name || obj.value || JSON.stringify(obj);
        };

        // ── For censys_services objects, extract a stable pivot key and a display label ──
        const _pivotService = (obj) => {
            if (typeof obj !== "object" || !obj) return null;
            const port = obj.port || "?";
            const proto = (obj.transport || "tcp").toLowerCase();
            const key = `${port}/${proto}`;
            const label = obj.product || obj.service || obj.module || proto;
            return { key, display: label ? `${key} (${label})` : key };
        };

        // ── Flatten: expand list/relation/service fields into atomic entries ──
        // Returns Map<canonicalKey, { val: displayString, mod, name, type }>
        const flatten = (info) => {
            const map = new Map();
            Object.entries(info?.modules || {}).forEach(([mod, fields]) => {
                (fields || []).forEach(f => {
                    if (this._isEmpty(f.value)) return;
                    if (this._COMPARE_SKIP.has(f.name)) return;

                    if (LIST_TYPES.has(f.type) && Array.isArray(f.value)) {
                        f.value.forEach((item, idx) => {
                            if (!item && item !== 0) return;

                            let atomicKey, displayVal;

                            if (f.type === "censys_services" || f.type === "shodan_services") {
                                const parsed = _pivotService(item);
                                if (!parsed) return;
                                atomicKey = `${mod}::${f.name}::svc::${parsed.key}`;
                                displayVal = parsed.display;
                            } else if (f.type === "vt_relation") {
                                const pivot = _pivotVtRelation(item);
                                if (!pivot) return;
                                atomicKey = `${mod}::${f.name}::${pivot}`;
                                displayVal = pivot.length > 60 ? pivot.slice(0, 58) + "…" : pivot;
                            } else {
                                // plain list: strings or primitives
                                const s = String(item);
                                if (!s) return;
                                atomicKey = `${mod}::${f.name}::${s}`;
                                displayVal = s;
                            }

                            // Display name: "Field › item"
                            const displayName = `${f.name}`;
                            map.set(atomicKey, {
                                val: displayVal,
                                mod,
                                name: displayName,
                                subItem: displayVal,   // the atomic value itself
                                type: f.type,
                                isListItem: true,
                            });
                        });
                    } else {
                        // Scalar field: string/number/label-capsule/score etc.
                        const key = `${mod}::${f.name}`;
                        const val = Array.isArray(f.value)
                            ? f.value.join(", ")
                            : String(f.value);
                        map.set(key, { val, mod, name: f.name, type: f.type, isListItem: false });
                    }
                });
            });
            return map;
        };

        // Build a map per IOC label
        const maps = {};
        allLabels.forEach(lbl => { maps[lbl] = flatten(all[lbl]); });

        // Collect all canonical keys across all IOCs
        const allKeys = new Set(allLabels.flatMap(lbl => [...maps[lbl].keys()]));

        // Build rows: for each key, collect presence + value per IOC
        const rows = [];
        allKeys.forEach(k => {
            const entries = allLabels.map(lbl => maps[lbl].get(k) ?? null);
            const presentEntries = entries.filter(Boolean);
            if (!presentEntries.length) return;

            const firstVal = presentEntries[0].val;
            const allSame  = presentEntries.every(e => e.val === firstVal);
            const allPresent = entries.every(Boolean);
            const ref = presentEntries[0];

            rows.push({
                key: k,
                mod: ref.mod,
                name: ref.name,
                subItem: ref.subItem || null,
                isListItem: ref.isListItem || false,
                vals: entries.map(e => e ? { val: e.val } : null),
                allSame,
                allPresent,
            });
        });

        this._showCompareResultMultiModal(allLabels, rows);
    },

    _showCompareResultMultiModal(labels, rows) {
        document.getElementById("compare-result-modal")?.remove();

        // Color palette per IOC column
        const COLORS = [
            { text: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   dot: "bg-blue-400"   },
            { text: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/30", dot: "bg-violet-400" },
            { text: "text-emerald-400",bg: "bg-emerald-500/10",border: "border-emerald-500/30",dot: "bg-emerald-400"},
            { text: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30",  dot: "bg-amber-400"  },
            { text: "text-rose-400",   bg: "bg-rose-500/10",   border: "border-rose-500/30",   dot: "bg-rose-400"   },
            { text: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30",   dot: "bg-cyan-400"   },
        ];

        const colCount = labels.length;

        // Header labels row
        const headerCells = labels.map((lbl, i) => {
            const c = COLORS[i % COLORS.length];
            return `<th class="text-left px-2 py-1.5 text-[11px] font-semibold ${c.text} max-w-[140px]">
                <span class="font-mono truncate block max-w-[120px]" title="${this._esc(lbl)}">${this._esc(lbl.slice(0, 22))}${lbl.length > 22 ? "…" : ""}</span>
            </th>`;
        }).join("");

        const renderTableRow = (row) => {
            const { mod, name, subItem, isListItem, vals, allSame, allPresent } = row;
            const statusCls = allSame && allPresent
                ? "bg-green-500/5 border-l-2 border-l-green-500/40"
                : allSame && !allPresent
                    ? "bg-slate-800/30 border-l-2 border-l-slate-600/40"
                    : "bg-amber-500/5 border-l-2 border-l-amber-500/40";

            // For list items, show the item value once in the Field column
            // and just a presence indicator (✓ / —) per IOC column
            if (isListItem) {
                const itemDisplay = subItem && subItem.length > 36
                    ? subItem.slice(0, 34) + "…"
                    : (subItem || "");

                const presenceCells = vals.map((v, i) => {
                    const c = COLORS[i % COLORS.length];
                    if (!v) return `<td class="px-2 py-1 text-center"><span class="text-slate-700 text-[12px]">—</span></td>`;
                    return `<td class="px-2 py-1 text-center">
                        <span class="inline-block w-4 h-4 rounded-full ${c.dot} opacity-80" title="${this._esc(v.val)}"></span>
                    </td>`;
                }).join("");

                return `
                    <tr class="${statusCls}" data-mod="${EnrichPanel._esc(mod)}">
                        <td class="px-2 py-1 whitespace-nowrap">
                            <span class="text-[11px] text-slate-500">${this._esc(mod)}</span>
                            <span class="text-[11px] text-slate-400 ml-1">${this._esc(name)}</span>
                            <span class="font-mono text-[12px] text-slate-200 ml-2" title="${this._esc(subItem || "")}">${this._esc(itemDisplay)}</span>
                        </td>
                        ${presenceCells}
                    </tr>`;
            }

            // Scalar field: show value in each IOC column
            const cells = vals.map((v, i) => {
                const c = COLORS[i % COLORS.length];
                if (!v) return `<td class="px-2 py-1.5"><span class="text-slate-700 text-[12px]">—</span></td>`;
                const display = v.val.length > 28 ? v.val.slice(0, 26) + "…" : v.val;
                return `<td class="px-2 py-1.5">
                    <span class="font-mono text-[12px] ${c.text} block truncate max-w-[140px]"
                          title="${this._esc(v.val)}">${this._esc(display)}</span>
                </td>`;
            }).join("");

            return `
                <tr class="${statusCls}" data-mod="${this._esc(mod || '')}">
                    <td class="px-2 py-1.5 whitespace-nowrap">
                        <span class="text-[11px] text-slate-500">${this._esc(mod)}</span>
                        <span class="text-[11px] text-slate-300 ml-1 font-medium">${this._esc(name)}</span>
                    </td>
                    ${cells}
                </tr>`;
                    };

        // Split into sections: identical / divergent / partial
        const identical  = rows.filter(r => r.allSame && r.allPresent);
        const divergent  = rows.filter(r => !r.allSame);
        const partialSame = rows.filter(r => r.allSame && !r.allPresent);

        const section = (title, icon, colorCls, sectionRows) => {
            if (!sectionRows.length) return "";
            return `
                <div class="mb-5 compare-section">
                    <div class="flex items-center gap-1.5 mb-2 px-1">
                        <i data-lucide="${icon}" class="w-3.5 h-3.5 ${colorCls}"></i>
                        <span class="text-xs font-semibold uppercase tracking-widest ${colorCls}">${title}</span>
                        <span class="text-slate-600 text-xs ml-1">${sectionRows.length}</span>
                    </div>
                    <div class="rounded-lg border border-slate-800 overflow-hidden">
                        <table class="w-full">
                            <thead class="bg-slate-900/60 border-b border-slate-800">
                                <tr>
                                    <th class="text-left px-2 py-1.5 text-[11px] font-semibold text-slate-500">Field</th>
                                    ${headerCells}
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-slate-800/50">
                                ${sectionRows.map(renderTableRow).join("")}
                            </tbody>
                        </table>
                    </div>
                </div>`;
        };

        // Legend pills
        const legendPills = labels.map((lbl, i) => {
            const c = COLORS[i % COLORS.length];
            return `<span class="flex items-center gap-1">
                <span class="w-2 h-2 rounded-full ${c.dot} inline-block shrink-0"></span>
                <span class="font-mono text-[11px] ${c.text} truncate max-w-[100px]" title="${this._esc(lbl)}">${this._esc(lbl.slice(0,16))}${lbl.length>16?"…":""}</span>
            </span>`;
        }).join("");

        const modal = document.createElement("div");
        modal.id = "compare-result-modal";
        modal.className = "fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm";
        // Collect unique modules present in rows
        const allMods = [...new Set(rows.map(r => r.mod))].sort();

        const modPills = allMods.map(m =>
            `<button data-mod="${this._esc(m)}"
                     onclick="EnrichPanel._toggleCompareMod(this)"
                     class="compare-mod-pill text-[11px] px-2 py-0.5 rounded border
                           bg-violet-600/30 border-violet-500/60 text-white
                           transition whitespace-nowrap font-mono" data-active="true">
                ${this._esc(m)}
             </button>`
        ).join("");

        modal.innerHTML = `
            <div class="bg-slate-950 border border-slate-700 rounded-xl shadow-2xl w-full max-w-5xl mx-4
                        flex flex-col max-h-[90vh]">
                <!-- Header -->
                <div class="flex items-center gap-3 px-4 py-3 border-b border-slate-800 shrink-0 flex-wrap gap-y-2">
                    <i data-lucide="diff" class="w-4 h-4 text-violet-400 shrink-0"></i>
                    <span class="text-sm font-semibold text-white shrink-0">IOC Comparison</span>
                    <div class="flex-1 flex items-center gap-3 flex-wrap min-w-0">
                        ${legendPills}
                    </div>
                    <div class="flex items-center gap-3 text-[11px] text-slate-500 shrink-0">
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-green-500/40 inline-block"></span>Identical</span>
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-amber-500/40 inline-block"></span>Divergent</span>
                        <span class="flex items-center gap-1"><span class="w-2 h-2 rounded bg-slate-600/40 inline-block"></span>Partial</span>
                    </div>
                    <button onclick="document.getElementById('compare-result-modal').remove()"
                            class="text-slate-500 hover:text-white transition shrink-0">
                        <i data-lucide="x" class="w-4 h-4"></i>
                    </button>
                </div>
                <!-- Module filter bar -->
                ${allMods.length > 1 ? `
                <div class="flex items-center gap-2 px-4 py-2 border-b border-slate-800/60 shrink-0 flex-wrap">
                    <i data-lucide="filter" class="w-3 h-3 text-slate-600 shrink-0"></i>
                    <span class="text-[11px] text-slate-600 shrink-0 mr-1">Module</span>
                    <button onclick="EnrichPanel._selectAllCompareMods(true)"
                            class="text-[11px] text-slate-600 hover:text-violet-400 transition px-1">all</button>
                    <span class="text-slate-700 text-[11px]">·</span>
                    <button onclick="EnrichPanel._selectAllCompareMods(false)"
                            class="text-[11px] text-slate-600 hover:text-violet-400 transition px-1">none</button>
                    <div class="flex items-center gap-1.5 flex-wrap" id="compare-mod-pills">
                        ${modPills}
                    </div>
                </div>` : ""}
                <!-- Body -->
                <div class="flex-1 overflow-y-auto p-4" id="compare-result-body">
                    ${section("Identical across all IOCs", "check-circle-2", "text-green-400", identical)}
                    ${section("Divergent fields", "alert-triangle", "text-amber-400", divergent)}
                    ${section("Partial — not present in all IOCs", "minus-circle", "text-slate-400", partialSame)}
                    ${!rows.length ? `<p class="text-slate-600 italic text-sm text-center py-8">No enrichment data to compare.</p>` : ""}
                </div>
            </div>`;
        
        // ── Module filter helpers (scoped to this modal instance) ──
        EnrichPanel._toggleCompareMod = function(btn) {
            const active = btn.dataset.active === "true";
            btn.dataset.active = active ? "false" : "true";
            btn.classList.toggle("bg-violet-600/30", !active);
            btn.classList.toggle("border-violet-500/60", !active);
            btn.classList.toggle("text-violet-300", !active);
            btn.classList.toggle("bg-slate-800", active);
            btn.classList.toggle("border-slate-700", active);
            btn.classList.toggle("text-slate-400", active);
            EnrichPanel._applyCompareModFilter();
        };

        EnrichPanel._selectAllCompareMods = function(selectAll) {
            document.querySelectorAll(".compare-mod-pill").forEach(btn => {
                btn.dataset.active = selectAll ? "true" : "false";
                btn.classList.toggle("bg-violet-600/30", !selectAll);
                btn.classList.toggle("border-violet-500/60", !selectAll);
                btn.classList.toggle("text-violet-300", !selectAll);
                btn.classList.toggle("bg-slate-800", selectAll);
                btn.classList.toggle("border-slate-700", selectAll);
                btn.classList.toggle("text-slate-400", selectAll);
            });
            EnrichPanel._applyCompareModFilter();
        };

        EnrichPanel._applyCompareModFilter = function() {
            const activeMods = new Set(
                [...document.querySelectorAll(".compare-mod-pill[data-active='true']")]
                    .map(b => b.dataset.mod)
            );
            document.querySelectorAll("#compare-result-body tr[data-mod]").forEach(tr => {
                tr.style.display = activeMods.has(tr.dataset.mod) ? "" : "none";
            });
            // Hide section wrappers that have no visible rows
            document.querySelectorAll("#compare-result-body .compare-section").forEach(sec => {
                const visible = [...sec.querySelectorAll("tr[data-mod]")]
                    .some(tr => tr.style.display !== "none");
                sec.style.display = visible ? "" : "none";
            });
        };

        modal.addEventListener("click", e => { if (e.target === modal) modal.remove(); });
        document.body.appendChild(modal);
        lucide.createIcons({ nodes: [modal] });
    },
};
