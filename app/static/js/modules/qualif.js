window.QualifPanel = {

    _current: null,

    async load(nodeData, caseId) {
        this._current = { nodeData, caseId };
        this._renderHeader(nodeData);
        this._renderLoading();

        try {
            const res = await fetch(`/api/cases/${caseId}/info`);
            const all = await res.json();
            this._renderInfo(nodeData, all[nodeData.label]);
        } catch (e) {
            this._renderError(e.message);
        }
    },

    clear() {
        this._current = null;
        const h = document.getElementById("qualif-header");
        const p = document.getElementById("qualif-panel");
        if (h) h.innerHTML = `<p class="text-slate-600 text-xs italic">Click a node to qualify it.</p>`;
        if (p) p.innerHTML = "";
    },

    // ── Render ────────────────────────────────────────────

    _renderHeader(nodeData) {
        const el = document.getElementById("qualif-header");
        if (!el) return;
        el.innerHTML = `
            <div class="flex items-center justify-between gap-2">
                <p class="text-sm font-bold mono truncate text-white" title="${nodeData.label}">${nodeData.label}</p>
                <button onclick="QualifPanel._triggerEnrich()"
                        title="Re-enrich" class="text-slate-500 hover:text-blue-400 transition shrink-0">
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
    },

    _renderInfo(nodeData, info) {
        const p = document.getElementById("qualif-panel");
        if (!p) return;

        if (!info || !Object.keys(info.modules || {}).length) {
            p.innerHTML = `
                <p class="text-slate-500 text-xs italic px-1">No enrichment data.</p>
                <button onclick="QualifPanel._triggerEnrich()"
                        class="mt-2 w-full bg-slate-800 hover:bg-blue-600 py-1.5 rounded text-xs font-semibold transition">
                    ⚡ Run enrichment
                </button>
            `;
            return;
        }

        let html = "";
        Object.entries(info.modules).forEach(([modKey, fields]) => {
            html += `
                <div class="module-section mb-3">
                    <p class="text-[9px] text-blue-400 uppercase tracking-widest font-bold mb-1 flex items-center gap-1">
                        <i data-lucide="${this._modIcon(modKey)}" class="w-3 h-3"></i> ${modKey}
                    </p>
                    ${(fields || []).map(f => this._renderField(f)).join("")}
                </div>
            `;
        });

        p.innerHTML = html;
        lucide.createIcons();
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
            action:           "enrich",
            case_id:          caseId,
            indicator_filter: nodeData.label,
        });

        if (result?.job_id) {
            // Recharge après fin du job
            App.socket?.on?.("job_update", function handler(d) {
                if (d.job_id === result.job_id && d.status === "done") {
                    App.socket.off("job_update", handler);
                    QualifPanel.load(nodeData, caseId);
                }
            });
        }
    },

    // ── Field renderers ───────────────────────────────────

    _renderField(f) {
        if (f.type === "label-capsule") return `
            <div class="flex items-center justify-between py-1 border-b border-slate-800/60 gap-2">
                <span class="text-[10px] text-slate-400 uppercase tracking-wider shrink-0">${f.name}</span>
                <span class="bg-slate-700/80 text-slate-200 text-[10px] px-2 py-0.5 rounded-full truncate"
                      title="${f.value}">${f.value}</span>
            </div>`;

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
        const icons = { shodan: "radar", virustotal: "shield", abuseipdb: "alert-triangle", opencti: "database", misp: "share-2" };
        return icons[key] || "box";
    },
};
