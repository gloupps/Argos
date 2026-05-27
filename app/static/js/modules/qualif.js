window.EnrichPanel = {

    _current:     null,
    _abortCtrl:   null,   // AbortController pour annuler un fetch en cours

    _internalKeys() {
        const reg = Modules?.registry || {};
        const internal = Object.entries(reg)
            .filter(([, m]) => m.type === "internal")
            .map(([k]) => k);
        return internal.length ? internal : ["opencti"];
    },

    async load(nodeData, caseId) {
        // Annuler tout fetch précédent pour éviter le double-rendu
        if (this._abortCtrl) this._abortCtrl.abort();
        this._abortCtrl = new AbortController();

        this._current = { nodeData, caseId };
        this._renderHeader(nodeData);
        this._renderLoading();

        try {
            const res = await fetch(`/api/cases/${caseId}/info`,
                                    { signal: this._abortCtrl.signal });
            const all = await res.json();
            // Vérifie que ce fetch est toujours le courant
            if (this._current?.nodeData?.label !== nodeData.label) return;
            this._renderInfo(nodeData, all[nodeData.label]);
        } catch (e) {
            if (e.name === "AbortError") return;  // fetch annulé, pas d'erreur à afficher
            this._renderError(e.message);
        }
    },

    clear() {
        if (this._abortCtrl) { this._abortCtrl.abort(); this._abortCtrl = null; }
        this._current = null;
        const h = document.getElementById("qualif-header");
        const p = document.getElementById("qualif-panel");
        if (h) h.innerHTML = `<p class="text-slate-600 text-xs italic">Click a node to qualify it.</p>`;
        if (p) p.innerHTML = "";
        document.getElementById("internal-intel-section")?.classList.add("hidden");
    },

    // ── Header ────────────────────────────────────────────

    _renderHeader(nodeData) {
        const el = document.getElementById("qualif-header");
        if (!el) return;
        el.innerHTML = `
            <div class="flex items-center justify-between gap-2">
                <p class="text-sm font-bold mono truncate text-white"
                   title="${nodeData.label}">${nodeData.label}</p>
                <button onclick="EnrichPanel._triggerEnrich()"
                        title="Re-enrich"
                        class="text-slate-500 hover:text-blue-400 transition shrink-0">
                    <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
                </button>
            </div>
            <div class="flex gap-1 mt-1 flex-wrap">
                <span class="bg-blue-500/20 text-blue-300 text-[9px] px-1.5 py-0.5 rounded uppercase">${nodeData.type}</span>
                <span class="bg-slate-700 text-slate-300 text-[9px] px-1.5 py-0.5 rounded uppercase">${nodeData.nodeType}</span>
            </div>
        `;
        lucide.createIcons();
    },

    _renderLoading() {
        const p = document.getElementById("qualif-panel");
        if (p) p.innerHTML = `<p class="text-slate-500 text-xs animate-pulse px-1">Loading…</p>`;
        document.getElementById("internal-intel-section")?.classList.add("hidden");
    },

    // ── Info ──────────────────────────────────────────────

    _renderInfo(nodeData, info) {
        const p = document.getElementById("qualif-panel");
        if (!p) return;

        if (!info || !Object.keys(info.modules || {}).length) {
            p.innerHTML = `
                <p class="text-slate-500 text-xs italic px-1">No enrichment data.</p>
                <button onclick="EnrichPanel._triggerEnrich()"
                        class="mt-2 w-full bg-slate-800 hover:bg-blue-600 py-1.5 rounded
                               text-xs font-semibold transition">
                    ⚡ Run enrichment
                </button>
            `;
            document.getElementById("internal-intel-section")?.classList.add("hidden");
            return;
        }

        const internalKeys = this._internalKeys();
        const entries      = Object.entries(info.modules);
        const external     = entries.filter(([k]) => !internalKeys.includes(k));
        const internal     = entries.filter(([k]) =>  internalKeys.includes(k));

        let html = "";
        if (external.length) {
            html = external.map(([modKey, fields]) => `
                <div class="module-section mb-3">
                    <p class="text-[9px] text-blue-400 uppercase tracking-widest font-bold mb-1
                              flex items-center gap-1">
                        <i data-lucide="${this._modIcon(modKey)}" class="w-3 h-3"></i> ${modKey}
                    </p>
                    ${(fields || []).map(f => this._renderField(f)).join("")}
                </div>
            `).join("");
        } else {
            html = `<p class="text-slate-600 text-xs italic px-1">No external enrichment data.</p>`;
        }
        p.innerHTML = html;
        lucide.createIcons();

        this._renderInternalSection(internal);
    },

    _renderInternalSection(entries) {
        const section = document.getElementById("internal-intel-section");
        const panel   = document.getElementById("internal-intel-panel");
        if (!section || !panel) return;

        if (!entries.length) { section.classList.add("hidden"); return; }

        panel.innerHTML = "";
        entries.forEach(([modKey, fields]) => {
            const card = document.createElement("div");
            card.className = "bg-violet-950/30 border border-violet-900/40 rounded-lg p-3 space-y-1";
            card.innerHTML = `
                <p class="text-[9px] font-bold text-violet-300 uppercase tracking-widest
                          flex items-center gap-1 mb-2">
                    <i data-lucide="${this._modIcon(modKey)}" class="w-3 h-3"></i> ${modKey}
                </p>
                ${(fields || []).map(f => this._renderField(f)).join("")}
            `;
            panel.appendChild(card);
        });
        lucide.createIcons({ nodes: [panel] });
        section.classList.remove("hidden");
    },

    _renderError(msg) {
        const p = document.getElementById("qualif-panel");
        if (p) p.innerHTML = `<p class="text-red-400 text-xs px-1">Error: ${msg}</p>`;
    },

    // ── Enrich ────────────────────────────────────────────

    async _triggerEnrich() {
        if (!this._current) return;
        const { nodeData, caseId } = this._current;
        JobLog?.push?.({ message: `🔍 Enrich ${nodeData.label}…`, status: "running" });
        const result = await App.runAction({
            action: "enrich", case_id: caseId, indicator_filter: nodeData.label,
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

    // ── Field renderers ───────────────────────────────────

    _renderField(f) {
        if (f.type === "label-capsule") {
            if (f.link) return `
                <div class="flex items-center justify-between py-1 border-b border-slate-800/60 gap-2">
                    <span class="text-[10px] text-slate-400 uppercase tracking-wider shrink-0
                                 flex items-center gap-1">
                        ${f.icon ? `<i data-lucide="${f.icon}" class="w-3 h-3"></i>` : ""}
                        ${f.name}
                    </span>
                    <a href="${f.link}" target="_blank" rel="noopener noreferrer"
                       class="bg-violet-800/50 text-violet-200 text-[10px] px-2 py-0.5 rounded-full
                              hover:bg-violet-700/60 transition flex items-center gap-1 truncate"
                       title="${f.value}">
                        <i data-lucide="external-link" class="w-2.5 h-2.5 shrink-0"></i> View
                    </a>
                </div>`;
            return `
                <div class="flex items-center justify-between py-1 border-b border-slate-800/60 gap-2">
                    <span class="text-[10px] text-slate-400 uppercase tracking-wider shrink-0">${f.name}</span>
                    <span class="bg-slate-700/80 text-slate-200 text-[10px] px-2 py-0.5 rounded-full truncate"
                          title="${f.value}">${f.value}</span>
                </div>`;
        }

        if (f.type === "list") {
            const items = (Array.isArray(f.value) ? f.value : [f.value])
                .slice(0, f.max || 10)
                .map(v => `<span class="bg-slate-800 text-slate-300 text-[10px] px-1.5 py-0.5 rounded
                                        border border-slate-700/50 font-mono">${v}</span>`).join("");
            return `
                <div class="py-1 border-b border-slate-800/60">
                    <p class="text-[10px] text-slate-400 uppercase tracking-wider mb-1">${f.name}</p>
                    <div class="flex flex-wrap gap-1">${items || "–"}</div>
                </div>`;
        }

        if (f.type === "score") {
            const pct   = Math.min(100, Math.max(0, Number(f.value) || 0));
            const color = pct > 70 ? "#ef4444" : pct > 40 ? "#f59e0b" : "#22c55e";
            return `
                <div class="py-1 border-b border-slate-800/60">
                    <div class="flex justify-between items-center mb-1">
                        <span class="text-[10px] text-slate-400 uppercase tracking-wider">${f.name}</span>
                        <span class="text-xs font-bold" style="color:${color}">${pct}</span>
                    </div>
                    <div class="w-full bg-slate-800 rounded-full h-1">
                        <div class="h-1 rounded-full" style="width:${pct}%;background:${color}"></div>
                    </div>
                </div>`;
        }

        return `
            <div class="flex items-center justify-between py-1 border-b border-slate-800/60 gap-2">
                <span class="text-[10px] text-slate-400 uppercase tracking-wider shrink-0">${f.name}</span>
                <span class="text-slate-300 text-[10px] truncate">${f.value ?? "–"}</span>
            </div>`;
    },

    _modIcon(key) {
        const icons = {
            shodan:     "radar",
            virustotal: "shield",
            viewdns:    "globe",
            urlscan:    "scan-search",
            opencti:    "database",
            abuseipdb:  "alert-triangle",
            misp:       "share-2",
        };
        return icons[key] || Modules?.registry?.[key]?.icon || "box";
    },
};