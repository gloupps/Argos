window.Modules = {

    registry: {},
    _correlationState: {},

    async init() {
        console.log("[Modules] init");
        const raw = localStorage.getItem("pivotlens_correlation");
        if (raw) this._correlationState = JSON.parse(raw);

        await this.loadRegistry();

        document.addEventListener("settings:updated", () => {
            this.renderSidebar();
            this.renderSettingsKeys();
        });
    },

    // ── Registry ──────────────────────────────────────────

    async loadRegistry() {
        try {
            const res = await fetch("/api/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "get_modules" }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            this.registry = await res.json();
            console.log("[Modules] registry loaded:", Object.keys(this.registry));
            this.renderSidebar();
            this.renderCorrelationPanel();
            // Don't render settings keys here — only when modal opens
        } catch (err) {
            console.error("[Modules] loadRegistry error", err);
        }
    },

    // ── Sidebar ───────────────────────────────────────────

    renderSidebar() {
        const containers = {
            internal: document.getElementById("modules-internal"),
            external: document.getElementById("modules-external"),
            siem:     document.getElementById("modules-siem"),
        };
        Object.values(containers).forEach(el => { if (el) el.innerHTML = ""; });

        Object.values(this.registry).forEach(mod => {
            const target = containers[mod.type] || containers.external;
            if (!target) return;
            target.appendChild(this._buildModuleItem(mod));
        });

        lucide.createIcons();
        document.dispatchEvent(new Event("modules:rendered"));
    },

    // ── Correlation panel ─────────────────────────────────

    renderCorrelationPanel() {
        const container = document.getElementById("correlation-container");
        if (!container) return;
        container.innerHTML = "";

        const withCorr = Object.values(this.registry).filter(m => m.correlation?.length);
        if (!withCorr.length) {
            container.innerHTML = `<p class="text-slate-600 text-xs italic">No correlation modules.</p>`;
            return;
        }

        withCorr.forEach(mod => {
            const block = document.createElement("div");
            block.className = "bg-slate-900/50 p-3 rounded-lg border border-slate-800 space-y-3";
            block.innerHTML = `
                <div class="text-xs font-bold text-amber-400 flex items-center gap-2">
                    <i data-lucide="${mod.icon}" class="w-4 h-4"></i> ${mod.name}
                </div>`;
            mod.correlation.forEach(field => {
                const val = this._getCorrelationValue(mod.key, field.key, field.default);
                block.appendChild(this._buildCorrelationField(mod.key, field, val));
            });
            container.appendChild(block);
        });
        lucide.createIcons();
    },

    // ── Settings keys + quotas ────────────────────────────

    renderSettingsKeys() {
        const container = document.getElementById("settings-keys");
        if (!container) return;
        container.innerHTML = "";

        const groups = {};
        Object.values(this.registry).forEach(mod => {
            const g = mod.type || "external";
            if (!groups[g]) groups[g] = [];
            groups[g].push(mod);
        });

        Object.entries(groups).forEach(([group, modules]) => {
            const title = document.createElement("p");
            title.className = "text-[10px] text-slate-500 uppercase tracking-wider mt-4 mb-2 font-semibold";
            title.textContent = group;
            container.appendChild(title);

            modules.forEach(mod => {
                const current = SecretStore?.get(mod.key) || "";
                const isSet   = !!current;
                const row     = document.createElement("div");
                row.className = "space-y-2";
                row.innerHTML = `
                    <!-- Key row -->
                    <div class="flex items-center gap-3">
                        <div class="w-32 text-sm flex items-center gap-2 shrink-0">
                            <i data-lucide="${mod.icon}" class="w-4 h-4 text-slate-400"></i>
                            <span class="font-medium">${mod.name}</span>
                        </div>

                        <div class="relative flex-1">
                            <input type="password"
                                   id="key-input-${mod.key}"
                                   data-key="${mod.key}"
                                   value="${current}"
                                   placeholder="API key…"
                                   class="w-full bg-slate-900 border border-slate-700 rounded
                                          p-2 pr-8 text-sm font-mono
                                          focus:outline-none focus:ring-1 focus:ring-blue-500">
                            <!-- Toggle visibility -->
                            <button type="button"
                                    onclick="Modules._toggleKeyVisibility('${mod.key}')"
                                    class="absolute right-2 top-1/2 -translate-y-1/2
                                           text-slate-500 hover:text-slate-300 transition"
                                    title="Show / hide key">
                                <i data-lucide="eye" class="w-3.5 h-3.5"
                                   id="eye-icon-${mod.key}"></i>
                            </button>
                        </div>

                        <span class="text-[10px] px-2 py-1 rounded shrink-0
                                     ${isSet
                                        ? 'bg-green-500/20 text-green-400'
                                        : 'bg-red-500/20 text-red-400'}">
                            ${isSet ? "SET" : "MISSING"}
                        </span>

                        ${isSet ? `
                        <button type="button"
                                onclick="Modules._fetchQuota('${mod.key}')"
                                class="shrink-0 text-slate-500 hover:text-blue-400 transition"
                                title="Check quota">
                            <i data-lucide="refresh-cw" class="w-3.5 h-3.5"
                               id="quota-spin-${mod.key}"></i>
                        </button>` : ""}
                    </div>

                    <!-- Quota row (hidden until fetched) -->
                    <div id="quota-row-${mod.key}" class="hidden ml-36 px-3 py-2
                         bg-slate-900/60 border border-slate-800 rounded text-xs space-y-1">
                    </div>
                `;
                container.appendChild(row);

                // Auto-fetch quota if key already set
                if (isSet) {
                    this._fetchQuota(mod.key);
                }
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

        // check_quotas is synchronous — returns { modKey: {plan_type, remaining, limit} }
        const result = await App.runAction({
            action:   "check_quotas",
            api_keys: { [modKey]: apiKey },
        });

        spinEl?.classList.remove("animate-spin");

        const row = document.getElementById(`quota-row-${modKey}`);
        if (!row) return;

        if (result?.[modKey]) {
            this._renderQuota(row, result[modKey]);
        } else {
            row.innerHTML = `<span class="text-slate-500 italic">No quota data available.</span>`;
            row.classList.remove("hidden");
        }
    },

    _renderQuota(row, quota) {
        if (quota.error) {
            row.innerHTML = `<span class="text-red-400">Error: ${quota.error}</span>`;
            row.classList.remove("hidden");
            return;
        }

        const planColor = quota.plan_type === "pro+"
            ? "text-green-400"
            : quota.plan_type === "pro"
            ? "text-blue-400"
            : "text-slate-400";

        row.innerHTML = `
            <div class="flex items-center justify-between">
                <span class="text-slate-400">Plan</span>
                <span class="${planColor} font-semibold uppercase">${quota.plan_type || "–"}</span>
            </div>
            ${quota.limit != null ? `
            <div class="flex items-center justify-between">
                <span class="text-slate-400">Credits remaining</span>
                <span class="text-white font-mono">${quota.remaining ?? "–"} / ${quota.limit}</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-1 mt-1">
                <div class="h-1 rounded-full bg-blue-500 transition-all"
                     style="width:${quota.limit > 0 ? Math.round((quota.remaining / quota.limit) * 100) : 0}%">
                </div>
            </div>` : ""}
        `;
        row.classList.remove("hidden");
    },

    // ── Toggle key visibility ─────────────────────────────

    _toggleKeyVisibility(modKey) {
        const input   = document.getElementById(`key-input-${modKey}`);
        const icon    = document.getElementById(`eye-icon-${modKey}`);
        if (!input) return;
        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        // Swap icon
        if (icon) {
            icon.setAttribute("data-lucide", isHidden ? "eye-off" : "eye");
            lucide.createIcons({ nodes: [icon.parentElement] });
        }
    },

    // ── Correlation state ─────────────────────────────────

    _getCorrelationValue(modKey, fieldKey, def) {
        return this._correlationState[modKey]?.[fieldKey] ?? def;
    },

    _setCorrelationValue(modKey, fieldKey, value) {
        if (!this._correlationState[modKey]) this._correlationState[modKey] = {};
        this._correlationState[modKey][fieldKey] = value;
        localStorage.setItem("pivotlens_correlation", JSON.stringify(this._correlationState));
    },

    getCorrelationConfig(modKey) {
        return this._correlationState[modKey] || {};
    },

    // ── Module sidebar item ───────────────────────────────

    _buildModuleItem(mod) {
        const hasKey = SecretStore?.has?.(mod.key) ?? false;
        const item   = document.createElement("div");
        item.className = `flex items-center justify-between p-2 rounded transition
            ${hasKey ? "hover:bg-slate-800 cursor-pointer" : "opacity-40 cursor-not-allowed"}`;
        item.dataset.moduleKey = mod.key;
        item.title = `${mod.description || ""}\nSupports: ${(mod.supported_types || []).join(", ")}`;
        item.innerHTML = `
            <span class="flex items-center gap-2 text-sm">
                <i data-lucide="${mod.icon}" class="w-4 h-4 text-slate-300"></i>
                <span>${mod.name}</span>
            </span>
            <span class="module-badge text-[10px] px-2 py-0.5 rounded
                         ${hasKey ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}">
                ${hasKey ? "READY" : "NO KEY"}
            </span>`;
        item.addEventListener("click", () => {
            if (!hasKey) return;
            const tabId  = App?.state?.activeTab;
            const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;
            if (!caseId) {
                JobLog?.push?.({ message: "⚠ Open a case first", status: "running" });
                return;
            }
            this._runModule(mod, caseId);
        });
        return item;
    },

    // ── Correlation field ─────────────────────────────────

    _buildCorrelationField(modKey, field, value) {
        const wrap = document.createElement("div");
        const id   = `corr_${modKey}_${field.key}`;
        if (field.type === "range") {
            wrap.innerHTML = `
                <div>
                    <div class="flex justify-between text-[10px] mb-1">
                        <span class="text-slate-400">${field.label}</span>
                        <span class="text-amber-500 font-bold" id="${id}_val">${value}</span>
                    </div>
                    <input type="range" id="${id}" min="${field.min}" max="${field.max}"
                           value="${value}" class="w-full accent-amber-500">
                </div>`;
            wrap.querySelector("input").addEventListener("input", e => {
                document.getElementById(`${id}_val`).textContent = e.target.value;
                this._setCorrelationValue(modKey, field.key, Number(e.target.value));
            });
        }
        if (field.type === "checkbox") {
            wrap.innerHTML = `
                <label class="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" id="${id}" ${value ? "checked" : ""}
                           class="accent-amber-500">
                    <span class="text-[10px] text-slate-300">${field.label}</span>
                </label>`;
            wrap.querySelector("input").addEventListener("change", e => {
                this._setCorrelationValue(modKey, field.key, e.target.checked);
            });
        }
        return wrap;
    },

    // ── Run module ────────────────────────────────────────

    _runModule(mod, caseId) {
        const apiKeys = App._collectApiKeys();
        App.runAction({ action: "enrich", case_id: caseId, api_keys: apiKeys })
            .then(r => {
                if (r?.job_id)
                    JobLog?.push?.({ message: `[${mod.name}] Enrichment started`, status: "running" });
            });
        if (mod.correlation?.length) {
            App.runAction({
                action: "correlate", case_id: caseId,
                api_keys: apiKeys,
                correlation_config: this.getCorrelationConfig(mod.key),
            }).then(r => {
                if (r?.job_id)
                    JobLog?.push?.({ message: `[${mod.name}] Correlation started`, status: "running" });
            });
        }
    },
};
