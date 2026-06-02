window.Modules = {

    // ── registry FLAT { key → modDef }
    registry: {},

    // ── données groupées brutes du backend
    _grouped: null,

    // ── état ON/OFF enrichissement par module (persisté)
    state: { enabled: {} },

    // ── état ON/OFF corrélation par module (persisté)
    _correlateEnabled: {},

    // ── config corrélation par module (valeurs des sliders)
    _correlationState: {},
    
    // ── cache quota { modKey → {remaining, limit, exhausted, low} }
    _quotaCache: {},

    // ══════════════════════════════════════════
    // INIT
    // ══════════════════════════════════════════
    async init() {
        console.log("[Modules] init");
        try {
            const se = localStorage.getItem("pivotlens_enrich_enabled");
            if (se) this.state.enabled = JSON.parse(se);
            const sc = localStorage.getItem("pivotlens_correlate_enabled");
            if (sc) this._correlateEnabled = JSON.parse(sc);
            const ss = localStorage.getItem("pivotlens_correlation");
            if (ss) this._correlationState = JSON.parse(ss);
        } catch (_) {}

        await this._load();
    },

    async _load() {
        try {
            const res     = await fetch("/api/modules");
            this._grouped = await res.json();

            this.registry = {};
            Object.values(this._grouped).forEach(list => {
                list.forEach(mod => {
                    this.registry[mod.key] = mod;
                    if (this.state.enabled[mod.key]     === undefined) this.state.enabled[mod.key]     = true;
                    if (this._correlateEnabled[mod.key] === undefined) this._correlateEnabled[mod.key] = true;
                });
            });

            // ── Injecter les modules MISP externes depuis SecretStore ──────
            this._injectExternalMispModules();

            console.log("[Modules] registry:", Object.keys(this.registry));

            await this._loadCorrelationSchema();
            this.renderSidebar();

        } catch (err) {
            console.error("[Modules] load error", err);
        }
    },
    
    _injectExternalMispModules() {
        const instances = SecretStore.getJSON?.("misp_instances", []) ?? [];
        instances.forEach(inst => {
            const key = `misp_ext_${inst.id}`;
            this.registry[key] = {
                key,
                name:            `MISP — ${inst.label}`,
                description:     `External MISP instance: ${inst.label}`,
                type:            "external",
                icon:            "share-2",
                url:             "",
                supported_types: ["ip", "domain", "url", "hash"],
                correlation:     [],
                // settings_fields vide : l'URL/key sont gérés directement dans
                // le bloc MISPInstances (pas dans la section "API Keys" standard)
                settings_fields: [],
            };
            if (this.state.enabled[key]     === undefined) this.state.enabled[key]     = true;
            if (this._correlateEnabled[key] === undefined) this._correlateEnabled[key] = true;
        });
    },


    async _loadCorrelationSchema() {
        try {
            const res    = await fetch("/api/modules/correlation");
            const schema = await res.json();

            // ── Injecter les instances MISP externes dans le schema ──
            // Elles ne sont pas retournées par le backend (instanciées dynamiquement),
            // mais elles partagent les mêmes correlation_fields que MISPModule.
            const mispInstances = SecretStore.getJSON?.("misp_instances", []) ?? [];
            mispInstances.forEach(inst => {
                const key = `misp_ext_${inst.id}`;
                if (!schema[key] && SecretStore.has(key)) {
                    schema[key] = {
                        name:   `MISP — ${inst.label}`,
                        icon:   "share-2",
                        fields: [
                            {
                                key:     "misp_min_shared_roots",
                                type:    "range",
                                label:   "Min graph IOCs in same co-event to pivot",
                                min:     1,
                                max:     10,
                                default: 2,
                            },
                            {
                                key:     "misp_max_events",
                                type:    "range",
                                label:   "Max reports per pivot",
                                min:     1,
                                max:     20,
                                default: 3,
                            },
                            {
                                key:     "misp_include_correlated",
                                type:    "checkbox",
                                label:   "Include correlated IOCs (not only roots)",
                                default: false,
                            },
                        ],
                    };
                }
            });
            // ────────────────────────────────────────────────────────

            Object.entries(schema).forEach(([modKey, mod]) => {
                if (!this._correlationState[modKey]) this._correlationState[modKey] = {};
                (mod.fields || []).forEach(f => {
                    if (this._correlationState[modKey][f.key] === undefined)
                        this._correlationState[modKey][f.key] = f.default;
                });
            });

            this._renderCorrelationPanel(schema);
        } catch (err) {
            console.error("[Modules] correlation schema error", err);
        }
    },

    // ══════════════════════════════════════════
    // SIDEBAR — toggle enrichissement ON/OFF
    // ══════════════════════════════════════════
    renderSidebar() {
        if (!this._grouped) return;

        const internalEl = document.getElementById("modules-internal");
        const externalEl = document.getElementById("modules-external");
        if (internalEl) internalEl.innerHTML = "";
        if (externalEl) externalEl.innerHTML = "";

        Object.entries(this._grouped).forEach(([group, modules]) => {
            const isInternal = group.toLowerCase().includes("internal");
            const container  = isInternal ? internalEl : externalEl;
            if (!container) return;

            modules.forEach(mod => {
                const hasKey = SecretStore?.has?.(mod.key) ?? false;
                const on     = hasKey && (this.state.enabled[mod.key] !== false);
                container.appendChild(this._buildSidebarItem(mod, hasKey, on));
            });
        });
        
        // ── Injecter les instances MISP externes dans External Sources ──
        if (externalEl) {
            const instances = SecretStore.getJSON?.("misp_instances", []) ?? [];
            instances.forEach(inst => {
                const key    = `misp_ext_${inst.id}`;
                const mod    = this.registry[key];
                if (!mod) return;
                const hasKey = SecretStore?.has?.(key) ?? false;
                const on     = hasKey && (this.state.enabled[key] !== false);
                externalEl.appendChild(this._buildSidebarItem(mod, hasKey, on));
            });
        }

        lucide.createIcons();
        document.dispatchEvent(new Event("modules:rendered"));
    },

    _buildSidebarItem(mod, hasKey, on) {
        const wrap = document.createElement("div");
        wrap.className = "flex items-center justify-between px-2 py-1.5 rounded transition group " +
                         (hasKey ? "hover:bg-slate-800" : "opacity-30");
        wrap.title = mod.description || mod.name;

        // Label + icon (cliquable pour lancer enrichissement si ON)
        const labelSpan = document.createElement("span");
        labelSpan.className = "flex items-center gap-2 flex-1 min-w-0 " +
                              (hasKey && on ? "cursor-pointer" : "cursor-default");
        // Badge quota (EXHAUSTED / LOW) — alimenté par _quotaCache via _updateSidebarQuotaBadge()
        const qc = this._quotaCache[mod.key];
        const quotaBadgeClass = qc?.exhausted
            ? "text-[9px] px-1.5 py-0.5 rounded-full font-semibold shrink-0 bg-red-500/20 text-red-400 border border-red-500/30"
            : qc?.low
            ? "text-[9px] px-1.5 py-0.5 rounded-full font-semibold shrink-0 bg-amber-500/20 text-amber-400 border border-amber-500/30"
            : "text-[9px] px-1.5 py-0.5 rounded-full font-semibold shrink-0 hidden";
        const quotaBadgeText = qc?.exhausted ? "EXHAUSTED" : qc?.low ? "LOW" : "";

        labelSpan.innerHTML = `
            <i data-lucide="${mod.icon}" class="w-4 h-4 text-slate-300 shrink-0"></i>
            <span class="text-sm truncate ${on ? "" : "text-slate-500"}">${mod.name}</span>
            <span id="sidebar-quota-badge-${mod.key}" class="${quotaBadgeClass}">${quotaBadgeText}</span>
        `;
        if (hasKey && on) {
            labelSpan.addEventListener("click", () => {
                const tabId  = App?.state?.activeTab;
                const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;
                if (!caseId) { JobLog?.push?.({ message: "⚠ Open a case first", status: "running" }); return; }
                this._runModule(mod, caseId);
            });
        }

        wrap.appendChild(labelSpan);

        if (!hasKey) {
            // Juste un badge NO KEY, pas de toggle
            const badge = document.createElement("span");
            badge.className = "text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-500 shrink-0";
            badge.textContent = "NO KEY";
            wrap.appendChild(badge);
            return wrap;
        }

        // Toggle switch pill
        const toggleLabel = document.createElement("label");
        toggleLabel.className = "relative shrink-0 ml-2 cursor-pointer";
        toggleLabel.title = on ? "Enabled — click to disable" : "Disabled — click to enable";
        toggleLabel.innerHTML = `
            <input type="checkbox" class="sr-only peer" ${on ? "checked" : ""}>
            <div class="w-9 h-5 bg-slate-700 rounded-full transition-colors
                        peer-checked:bg-blue-500"></div>
            <div class="absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow
                        transition-transform peer-checked:translate-x-4"></div>
        `;
        toggleLabel.querySelector("input").addEventListener("change", e => {
            this._setEnrichEnabled(mod.key, e.target.checked);
            // Refresh just this item
            const newOn = e.target.checked;
            const nameEl = wrap.querySelector("span.text-sm");
            if (nameEl) nameEl.className = `text-sm truncate ${newOn ? "" : "text-slate-500"}`;
            toggleLabel.title = newOn ? "Enabled — click to disable" : "Disabled — click to enable";
            // Reconnect click handler on label
            labelSpan.className = "flex items-center gap-2 flex-1 min-w-0 " +
                                  (newOn ? "cursor-pointer" : "cursor-default");
        });

        wrap.appendChild(toggleLabel);
        return wrap;
    },

    // ══════════════════════════════════════════
    // CORRELATION PANEL
    // Checkbox par module → affiche/masque les paramètres
    // Modules sans clé API : section absente
    // ══════════════════════════════════════════
    _renderCorrelationPanel(schema) {
        // Modules pivot (recon surface) vs corrélation (cross-IOC intel)
        const PIVOT_KEYS = new Set(["shodan", "censys", "viewdns", "urlscan"]);

        const pivotEl = document.getElementById("pivot-container");
        const corrEl  = document.getElementById("correlation-container");
        if (pivotEl) pivotEl.innerHTML = "";
        if (corrEl)  corrEl.innerHTML  = "";

        const entries = Object.entries(schema);
        if (!entries.length) {
            if (corrEl) corrEl.innerHTML = `<p class="text-slate-600 text-xs italic">No correlation modules.</p>`;
            return;
        }

        entries.forEach(([modKey, mod]) => {
            const hasKey = SecretStore?.has?.(modKey) ?? false;
            if (!hasKey) return;

            const isPivot   = PIVOT_KEYS.has(modKey);
            const container = isPivot ? pivotEl : corrEl;
            if (!container) return;

            // Couleur selon le type de module
            const accentColor  = isPivot ? "text-amber-400"  : "text-violet-400";
            const toggleColor  = isPivot ? "peer-checked:bg-amber-500"  : "peer-checked:bg-violet-500";
            const rangeAccent  = isPivot ? "accent-amber-500"  : "accent-violet-500";
            const valColor     = isPivot ? "text-amber-500"   : "text-violet-400";

            const isOn = this._correlateEnabled[modKey] !== false;

            const block = document.createElement("div");
            block.className = "border border-slate-800 rounded-lg overflow-hidden";

            // ── Header avec checkbox ──
            const header = document.createElement("label");
            header.className = "flex items-center justify-between px-3 py-2.5 cursor-pointer " +
                               "bg-slate-900/60 hover:bg-slate-900 transition select-none";
            header.innerHTML = `
                <span class="flex items-center gap-2 text-xs font-bold ${accentColor}">
                    <i data-lucide="${mod.icon}" class="w-3.5 h-3.5"></i>
                    ${mod.name}
                </span>
                <div class="relative shrink-0">
                    <input type="checkbox" class="sr-only peer" ${isOn ? "checked" : ""}>
                    <div class="w-8 h-4 bg-slate-700 rounded-full ${toggleColor} transition-colors"></div>
                    <div class="absolute top-0.5 left-0.5 w-3 h-3 bg-white rounded-full shadow-sm
                                transition-transform peer-checked:translate-x-4"></div>
                </div>
            `;

            // ── Params body (hidden si OFF) ──
            const body = document.createElement("div");
            body.className = "px-3 pb-3 pt-2 space-y-3 bg-slate-900/30 " +
                             (isOn ? "" : "hidden");

            const fields = mod.fields || [];
            if (fields.length) {
                fields.forEach(field => {
                    const value = this._correlationState[modKey]?.[field.key] ?? field.default;
                    const id    = `corr_${modKey}_${field.key}`;

                    const fieldEl = document.createElement("div");

                    if (field.type === "range") {
                        fieldEl.innerHTML = `
                            <div class="flex justify-between text-[10px] mb-1">
                                <span class="text-slate-400">${field.label}</span>
                                <span class="${valColor} font-bold" id="${id}_val">${value}</span>
                            </div>
                            <input type="range" id="${id}"
                                   min="${field.min}" max="${field.max}" value="${value}"
                                   class="w-full ${rangeAccent}">
                        `;
                        fieldEl.querySelector("input[type=range]").addEventListener("input", e => {
                            document.getElementById(`${id}_val`).textContent = e.target.value;
                            this.setCorrelationConfig(modKey, field.key, +e.target.value);
                        });
                    }

                    if (field.type === "checkbox") {
                        fieldEl.innerHTML = `
                            <label class="flex items-center gap-2 cursor-pointer">
                                <input type="checkbox" ${value ? "checked" : ""} class="${rangeAccent}">
                                <span class="text-[10px] text-slate-300">${field.label}</span>
                            </label>
                        `;
                        fieldEl.querySelector("input[type=checkbox]").addEventListener("change", e => {
                            this.setCorrelationConfig(modKey, field.key, e.target.checked);
                        });
                    }

                    body.appendChild(fieldEl);
                });
            } else {
                body.innerHTML = `<p class="text-[10px] text-slate-600 italic">No configurable parameters.</p>`;
            }

            // Toggle checkbox → show/hide body + persist
            header.querySelector("input[type=checkbox]").addEventListener("change", e => {
                this._setCorrelateEnabled(modKey, e.target.checked);
                if (e.target.checked) body.classList.remove("hidden");
                else                  body.classList.add("hidden");
            });

            block.appendChild(header);
            block.appendChild(body);
            container.appendChild(block);
        });

        lucide.createIcons();
    },

    // ══════════════════════════════════════════
    // API PUBLIQUE
    // ══════════════════════════════════════════
    setCorrelationConfig(modKey, field, value) {
        if (!this._correlationState[modKey]) this._correlationState[modKey] = {};
        this._correlationState[modKey][field] = value;
        localStorage.setItem("pivotlens_correlation", JSON.stringify(this._correlationState));
    },

    getCorrelationConfig(modKey) {
        return this._correlationState[modKey] || {};
    },
    
    collectCorrelationConfig() {
        // Retourne { modKey: { field: value, ... }, ... } — structuré par module
        const out = {};
        Object.keys(this._correlationState).forEach(modKey => {
            const cfg = this._correlationState[modKey];
            if (cfg && Object.keys(cfg).length) out[modKey] = { ...cfg };
        });
        return out;
    },

    isAvailable(key)        { return SecretStore?.has?.(key) ?? false; },
    isEnabled(key)          { return this.state.enabled[key] !== false; },
    isCorrelateEnabled(key) { return this._correlateEnabled[key] !== false; },

    getEnabledEnrichKeys()    { return Object.keys(this.registry).filter(k => this.isEnabled(k)); },
    getEnabledCorrelateKeys() { return Object.keys(this.registry).filter(k => this.isCorrelateEnabled(k)); },

    collectExtraConfig() {
        const extra = {};

        // Champs extra déclarés par chaque module (opencti_url, misp_url, etc.)
        Object.values(this.registry).forEach(mod => {
            (mod.settings_fields || []).forEach(sf => {
                const val = SecretStore?.get(`extra_${sf.key}`);
                if (val) extra[sf.key] = val;
            });
        });

        // Liste des instances MISP externes (pour que le backend puisse les instancier)
        const mispInstances = SecretStore.getJSON?.("misp_instances", []) ?? [];
        if (mispInstances.length) {
            extra["misp_instances"] = mispInstances;
            // Inclure l'URL de chaque instance
            mispInstances.forEach(inst => {
                const urlKey = `extra_misp_ext_${inst.id}_url`;
                const url    = SecretStore.get(urlKey);
                if (url) extra[`misp_ext_${inst.id}_url`] = url;
            });
        }

        return extra;
    },


    // ══════════════════════════════════════════
    // SETTINGS — API keys + extra fields
    // ══════════════════════════════════════════
    renderSettingsKeys() {
        const container = document.getElementById("settings-keys");
        if (!container) return;
        container.innerHTML = "";
        if (!this._grouped) return;

        Object.entries(this._grouped).forEach(([group, modules]) => {
            const title = document.createElement("p");
            title.className = "text-[10px] text-slate-500 uppercase tracking-wider mt-4 mb-2 font-semibold";
            title.textContent = group;
            container.appendChild(title);

            modules.forEach(mod => {
                const current = SecretStore?.get(mod.key) || "";
                const isSet   = !!current;

                // Extra fields (URL, etc.)
                const extraHtml = (mod.settings_fields || []).map(sf => {
                    const stored = SecretStore?.get(`extra_${sf.key}`) || "";
                    return `
                        <div class="mt-2">
                            <label class="text-[10px] text-slate-500 block mb-1">${sf.label}</label>
                            <input type="${sf.type === 'url' ? 'url' : 'text'}"
                                   id="extra-input-${sf.key}"
                                   data-extra-key="${sf.key}"
                                   value="${stored}"
                                   placeholder="${sf.placeholder || ''}"
                                   class="w-full bg-slate-950 border border-slate-700/60 rounded-md
                                          px-3 py-1.5 text-xs font-mono text-slate-200
                                          focus:outline-none focus:ring-1 focus:ring-blue-500/70 placeholder-slate-600">
                        </div>`;
                }).join("");

                const card = document.createElement("div");
                card.className = "rounded-lg border " +
                    (isSet ? "border-slate-700/60 bg-slate-900/50" : "border-slate-800/60 bg-slate-900/30 opacity-60") +
                    " p-3 mb-3 space-y-2";

                card.innerHTML = `
                    <!-- Card header: icon + name + status badge + refresh -->
                    <div class="flex items-center gap-2">
                        <div class="w-7 h-7 rounded-md bg-slate-800 flex items-center justify-center shrink-0">
                            <i data-lucide="${mod.icon}" class="w-3.5 h-3.5 text-slate-400"></i>
                        </div>
                        <span class="flex-1 text-sm font-semibold text-slate-200">${mod.name}</span>
                        <span id="status-badge-${mod.key}" class="text-[9px] px-2 py-0.5 rounded-full font-semibold shrink-0 ${
                            isSet ? 'bg-green-500/15 text-green-400 border border-green-500/20'
                                  : 'bg-red-500/15 text-red-400 border border-red-500/20'}">
                            ${isSet ? "SET" : "MISSING"}
                        </span>
                        ${isSet ? `<button type="button"
                                onclick="Modules._fetchQuota('${mod.key}')"
                                class="text-slate-600 hover:text-blue-400 transition ml-1" title="Refresh quota">
                            <i data-lucide="refresh-cw" class="w-3.5 h-3.5" id="quota-spin-${mod.key}"></i>
                        </button>` : ""}
                    </div>

                    <!-- API key input row -->
                    <div class="flex items-center gap-2">
                        <div class="relative flex-1">
                            <input type="password"
                                   id="key-input-${mod.key}"
                                   data-key="${mod.key}"
                                   value="${current}"
                                   placeholder="API key…"
                                   class="w-full bg-slate-950 border border-slate-700/60 rounded-md
                                          px-3 py-1.5 pr-8 text-xs font-mono text-slate-200
                                          focus:outline-none focus:ring-1 focus:ring-blue-500/70
                                          placeholder-slate-600">
                            <button type="button"
                                    onclick="Modules._toggleKeyVisibility('${mod.key}')"
                                    class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-300 transition"
                                    title="Show / hide">
                                <i data-lucide="eye" class="w-3.5 h-3.5" id="eye-icon-${mod.key}"></i>
                            </button>
                        </div>
                    </div>

                    ${extraHtml}

                    <!-- Quota zone -->
                    <div id="quota-row-${mod.key}" class="hidden"></div>
                `;
                container.appendChild(card);
                if (isSet) this._fetchQuota(mod.key);
            });
        });

        lucide.createIcons();
    },

    // ── Quota fetch ───────────────────────────────────────
    async _fetchQuota(modKey) {
        const apiKey = SecretStore?.get(modKey);
        if (!apiKey) return;
        const spinEl = document.getElementById(`quota-spin-${modKey}`);
        spinEl?.classList.add("animate-spin");
        const result = await App.runAction({
            action: "check_quotas",
            api_keys: { [modKey]: apiKey },
            extra_config: this.collectExtraConfig(),
        });
        spinEl?.classList.remove("animate-spin");
        const row = document.getElementById(`quota-row-${modKey}`);
        if (!row) return;

        const quota = result?.[modKey];
        if (quota) {
            // Mettre à jour le cache + rafraîchir le badge sidebar
            const exhausted = quota.remaining === 0 && quota.limit != null && quota.limit > 0;
            const pct = (quota.limit > 0 && quota.remaining != null)
                ? Math.round((quota.remaining / quota.limit) * 100) : null;
            const low = pct !== null && pct <= 15 && !exhausted;
            this._quotaCache[modKey] = { ...quota, exhausted, low };
            this._updateSidebarQuotaBadge(modKey);
            this._renderQuota(row, quota);
        } else {
            row.innerHTML = `<p class="text-[10px] text-slate-600 italic">No quota data available.</p>`;
            row.classList.remove("hidden");
        }
    },

    // Rafraîchit uniquement le badge capsule quota sur l'item sidebar (sans reconstruire tout le sidebar)
    _updateSidebarQuotaBadge(modKey) {
        const badgeId = `sidebar-quota-badge-${modKey}`;
        const existing = document.getElementById(badgeId);
        if (!existing) return; // sidebar item peut ne pas exister
        const q = this._quotaCache[modKey];
        if (!q) { existing.classList.add("hidden"); return; }
        if (q.exhausted) {
            existing.className = "text-[9px] px-1.5 py-0.5 rounded-full font-semibold shrink-0 " +
                "bg-red-500/20 text-red-400 border border-red-500/30";
            existing.textContent = "EXHAUSTED";
            existing.classList.remove("hidden");
        } else if (q.low) {
            existing.className = "text-[9px] px-1.5 py-0.5 rounded-full font-semibold shrink-0 " +
                "bg-amber-500/20 text-amber-400 border border-amber-500/30";
            existing.textContent = "LOW";
            existing.classList.remove("hidden");
        } else {
            existing.classList.add("hidden");
        }
    },

    _renderQuota(row, quota) {
        row.classList.remove("hidden");

        if (quota.error) {
            row.innerHTML = `
                <div class="flex items-center gap-1.5 text-[10px] text-red-400 bg-red-500/10
                            border border-red-500/20 rounded-md px-2.5 py-1.5">
                    <i data-lucide="alert-circle" class="w-3 h-3 shrink-0"></i>
                    <span>${quota.error}</span>
                </div>`;
            lucide.createIcons({ nodes: [row] });
            return;
        }

        if (quota.plan_type === "internal") {
            row.innerHTML = `
                <div class="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-violet-500/10
                            border border-violet-500/20 text-[10px]">
                    <i data-lucide="server" class="w-3 h-3 text-violet-400 shrink-0"></i>
                    <span class="text-violet-400 font-semibold">Internal instance</span>
                    ${quota.version ? `<span class="ml-auto text-slate-500 font-mono">${quota.version}</span>` : ""}
                </div>`;
            lucide.createIcons({ nodes: [row] });
            return;
        }

        if (quota.plan_type === "public" || (quota.remaining == null && quota.limit == null)) {
            row.innerHTML = `
                <div class="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-slate-800/60
                            border border-slate-700/40 text-[10px] text-slate-400">
                    <i data-lucide="globe" class="w-3 h-3 shrink-0"></i>
                    Public / no quota tracking
                </div>`;
            lucide.createIcons({ nodes: [row] });
            return;
        }

        const pct = (quota.limit > 0 && quota.remaining != null)
            ? Math.round((quota.remaining / quota.limit) * 100) : null;
        const exhausted = quota.remaining === 0 && quota.limit > 0;
        const low       = pct !== null && pct <= 15 && !exhausted;

        const barColor  = exhausted ? "bg-red-500"
                        : low       ? "bg-amber-500"
                        : pct !== null && pct <= 40 ? "bg-yellow-500"
                        : "bg-emerald-500";

        const planColor = quota.plan_type === "pro+" ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                        : quota.plan_type === "pro"  ? "text-blue-400 bg-blue-500/10 border-blue-500/20"
                        : quota.plan_type === "free" ? "text-slate-400 bg-slate-700/40 border-slate-600/30"
                        : "text-slate-400 bg-slate-700/40 border-slate-600/30";

        row.innerHTML = `
            <div class="rounded-md border border-slate-700/40 bg-slate-950/60 px-3 py-2.5 space-y-2">
                <!-- Plan + counters -->
                <div class="flex items-center justify-between gap-3">
                    <span class="text-[9px] px-1.5 py-0.5 rounded-full border font-semibold uppercase ${planColor}">
                        ${quota.plan_type || "unknown"}
                    </span>
                    ${quota.limit != null ? `
                    <span class="text-[10px] font-mono text-slate-300 ml-auto">
                        ${exhausted
                            ? `<span class="text-red-400 font-bold">0</span> / ${quota.limit}`
                            : `<span class="${low ? 'text-amber-400 font-semibold' : 'text-slate-200'}">${quota.remaining ?? "–"}</span>
                               <span class="text-slate-600"> / ${quota.limit}</span>`
                        }
                    </span>
                    <span class="text-[10px] text-slate-500">${pct !== null ? pct + "%" : ""}</span>
                    ` : ""}
                </div>
                <!-- Progress bar -->
                ${quota.limit != null && quota.limit > 0 ? `
                <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                    <div class="${barColor} h-1.5 rounded-full transition-all duration-500"
                         style="width: ${pct ?? 0}%"></div>
                </div>` : ""}
                <!-- Alert banner si exhausted ou low -->
                ${exhausted ? `
                <div class="flex items-center gap-1.5 text-[10px] text-red-400">
                    <i data-lucide="ban" class="w-3 h-3 shrink-0"></i>
                    <span>Credits exhausted — enrichment will fail for this module</span>
                </div>` : low ? `
                <div class="flex items-center gap-1.5 text-[10px] text-amber-400">
                    <i data-lucide="triangle-alert" class="w-3 h-3 shrink-0"></i>
                    <span>Low credits — consider renewing soon</span>
                </div>` : ""}
            </div>`;
        lucide.createIcons({ nodes: [row] });
    },

    _toggleKeyVisibility(modKey) {
        const input = document.getElementById(`key-input-${modKey}`);
        const icon  = document.getElementById(`eye-icon-${modKey}`);
        if (!input) return;
        const hidden = input.type === "password";
        input.type = hidden ? "text" : "password";
        if (icon) {
            icon.setAttribute("data-lucide", hidden ? "eye-off" : "eye");
            lucide.createIcons({ nodes: [icon.parentElement] });
        }
    },

    // ── Persist ───────────────────────────────────────────
    _setEnrichEnabled(key, val) {
        this.state.enabled[key] = val;
        localStorage.setItem("pivotlens_enrich_enabled", JSON.stringify(this.state.enabled));
    },
    _setCorrelateEnabled(key, val) {
        this._correlateEnabled[key] = val;
        localStorage.setItem("pivotlens_correlate_enabled", JSON.stringify(this._correlateEnabled));
    },

    // ── Run module (click sidebar label) ─────────────────
    _runModule(mod, caseId) {
        const apiKeys   = App._collectApiKeys(false);
        const extraConf = this.collectExtraConfig();

        App.runAction({
            action: "enrich", case_id: caseId,
            api_keys: apiKeys, extra_config: extraConf,
        }).then(r => {
            if (r?.job_id)
                JobLog?.push?.({ message: `[${mod.name}] Enrichment started`, status: "running" });
        });

        if (this.isCorrelateEnabled(mod.key)) {
            const corrKeys = App._collectApiKeys(true);
            App.runAction({
                action: "correlate", case_id: caseId,
                api_keys: corrKeys, extra_config: extraConf,
                correlation_config: { [mod.key]: this.getCorrelationConfig(mod.key) },
            }).then(r => {
                if (r?.job_id)
                    JobLog?.push?.({ message: `[${mod.name}] Correlation started`, status: "running" });
            });
        }
    },
};
