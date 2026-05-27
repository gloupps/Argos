window.GraphModule = {

    instances: {},

    init() { console.log("[Graph] init"); },

    create(tabId, caseId) {
        const container = document.getElementById("cy");
        if (!container) { console.warn("[Graph] #cy not found"); return; }
        this.instances[tabId]?.cy?.destroy();

        const cy = cytoscape({
            container,
            style:              this._styles(),
            elements:           [],
            layout:             { name: "preset" },
            userZoomingEnabled: true,
            userPanningEnabled: true,
            minZoom: 0.2, maxZoom: 4,
        });

        this.instances[tabId] = { cy, caseId };

        // Clic gauche → sélectionner uniquement
        cy.on("tap", "node", evt => {
            const data = evt.target.data();
            this._selectNode(tabId, data.id);
        });

        // Clic sur fond → désélectionner + vider panel enrichissement
        cy.on("tap", evt => {
            if (evt.target === cy) {
                inst.cy?.elements().removeClass("selected-node");
                EnrichPanel?.clear?.();
            }
        });

        // Clic droit → menu contextuel actions (pivot, enrich) SANS auto-qualif
        cy.on("cxttap", "node", evt => {
            evt.originalEvent.preventDefault();
            const data = evt.target.data();
            if (data.synthetic) return;
            this._selectNode(tabId, data.id);
            ContextMenu.show(data, caseId, evt.originalEvent.clientX, evt.originalEvent.clientY);
        });
        cy.on("cxttap", evt => { if (evt.target === cy) ContextMenu.hide(); });
        cy.on("viewport", () => ContextMenu.hide());
    },

    async loadCase(tabId, caseId) {
        this.create(tabId, caseId);
        try {
            const res  = await fetch(`/api/cases/${caseId}/graph`);
            const data = await res.json();
            this.render(tabId, data);
        } catch (err) {
            console.error("[Graph] loadCase error", err);
        }
    },

    render(tabId, data) {
        const inst = this.instances[tabId];
        if (!inst) return;
        const { cy } = inst;
        cy.elements().remove();

        const elements  = [];
        const nodeIndex = new Set();

        // ── 1. Real indicator nodes ───────────────────────
        (data.nodes || []).forEach(n => {
            const id = String(n.id || n.value);
            nodeIndex.add(id);
            elements.push({
                group:   "nodes",
                data:    {
                    id,
                    label:    n.value || id,
                    type:     n.type      || "ioc",
                    nodeType: n.node_type || "correlated",
                    synthetic: false,
                },
                classes: n.node_type || "correlated",
            });
        });

        // ── 2. Edges → pivot label nodes ──────────────────
        (data.edges || []).forEach(e => {
            const src = String(e.src_indicator_id || e.src_value  || e.source);
            const tgt = String(e.tgt_indicator_id || e.tgt_value  || e.target);

            if (!nodeIndex.has(src) || !nodeIndex.has(tgt)) return;

            const pivotText = e.pivot;

            if (pivotText && pivotText !== "true" && pivotText !== "True") {
                const pivotId = `pivot::${src}::${pivotText}`;

                if (!nodeIndex.has(pivotId)) {
                    nodeIndex.add(pivotId);
                    const display = pivotText.length > 40 ? pivotText.slice(0, 37) + "…" : pivotText;
                    elements.push({
                        group:   "nodes",
                        data:    {
                            id: pivotId, label: display,
                            type: "pivot", nodeType: "pivot",
                            synthetic: true, fullLabel: pivotText,
                        },
                        classes: "pivot",
                    });
                }

                elements.push({
                    group: "edges",
                    data:  { id: `${src}__${pivotId}`, source: src, target: pivotId, module: e.module || "" },
                });
                elements.push({
                    group: "edges",
                    data:  { id: `${pivotId}__${tgt}`, source: pivotId, target: tgt, module: e.module || "" },
                });
            } else {
                elements.push({
                    group: "edges",
                    data:  { id: `${src}__${tgt}`, source: src, target: tgt, module: e.module || "" },
                });
            }
        });

        if (elements.length === 0) return;
        cy.add(elements);
        this._runLayout(cy, elements.length);
    },

    handleGraphUpdate(caseId, graphData) {
        const tabId = Object.keys(this.instances).find(
            tid => this.instances[tid].caseId === caseId
        );
        if (tabId) this.render(tabId, graphData);
    },

    _selectNode(tabId, nodeId) {
        const inst = this.instances[tabId];
        if (!inst) return;
        inst.cy.elements().removeClass("selected-node");
        inst.cy.$(`#${CSS.escape(String(nodeId))}`).addClass("selected-node");
    },

    _runLayout(cy, count) {
        if (!cy || !cy.container() || count === 0) return;
        let layout;
        if (count === 1) {
            layout = cy.layout({ name: "grid", fit: true, padding: 60 });
        } else {
            try {
                layout = cy.layout({
                    name: "cose", animate: false, fit: true, padding: 40,
                    nodeRepulsion: () => 8000, idealEdgeLength: () => 100,
                    gravity: 0.4, numIter: 500,
                });
            } catch (_) {
                layout = cy.layout({ name: "grid", fit: true, padding: 40 });
            }
        }
        layout.run();
    },

    _styles() {
        return [
            { selector: "node", style: {
                "label": "data(label)", "font-size": 9, "color": "#e2e8f0",
                "text-valign": "bottom", "text-halign": "center", "text-margin-y": 4,
                "background-color": "#3b82f6", "width": 36, "height": 36,
                "border-width": 2, "border-color": "#1e40af",
            }},
            { selector: "node.root", style: {
                "background-color": "#ef4444", "border-color": "#7f1d1d",
                "width": 48, "height": 48, "font-size": 10, "font-weight": "bold",
            }},
            { selector: "node.pivot", style: {
                "background-color": "#f59e0b", "border-color": "#78350f",
                "width": 34, "height": 34, "font-size": 8,
                "color": "#fef3c7", "shape": "diamond",
            }},
            { selector: "node.correlated", style: {
                "background-color": "#8b5cf6", "border-color": "#4c1d95",
            }},
            { selector: "node.selected-node", style: {
                "border-width": 3, "border-color": "#ffffff",
                "overlay-color": "#ffffff", "overlay-opacity": 0.12,
            }},
            { selector: "edge", style: {
                "width": 1.5, "line-color": "#334155",
                "target-arrow-color": "#334155", "target-arrow-shape": "triangle",
                "curve-style": "bezier", "opacity": 0.7,
            }},
        ];
    },
};

// ══════════════════════════════════════════════════════════
// CONTEXT MENU — clic droit : actions sur un nœud
// Pas d'auto-qualif ici, uniquement les actions manuelles
// ══════════════════════════════════════════════════════════
window.ContextMenu = {

    _el: null,

    show(nodeData, caseId, x, y) {
        this.hide();
        const menu = document.createElement("div");
        menu.id = "ctx-menu";
        menu.className =
            "fixed z-50 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl py-1 min-w-[180px] text-sm";
        menu.style.left = `${x}px`;
        menu.style.top  = `${y}px`;

        this._buildItems(nodeData, caseId).forEach(item => menu.appendChild(item));
        document.body.appendChild(menu);
        this._el = menu;

        setTimeout(() => {
            document.addEventListener("click", this._onOutsideClick, { once: true });
        }, 0);

        const rect = menu.getBoundingClientRect();
        if (rect.right  > window.innerWidth)  menu.style.left = `${x - rect.width}px`;
        if (rect.bottom > window.innerHeight) menu.style.top  = `${y - rect.height}px`;
    },

    hide() { this._el?.remove(); this._el = null; },
    _onOutsideClick() { ContextMenu.hide(); },

    _buildItems(nodeData, caseId) {
        const { nodeType, type: iocType, label } = nodeData;
        const items = [];
        items.push(this._header(label, iocType));

        if (nodeType === "pivot") {
            items.push(this._item("share-2", "Re-pivot",
                "Re-run correlation on this pivot", "amber",
                () => this._runPivot(label, iocType, caseId)));
        } else {
            items.push(this._item("zap", "Qualify",
                "Enrich via all active modules", "blue",
                () => this._runQualify(label, iocType, caseId, nodeData)));
            items.push(this._item("share-2", "Pivot",
                "Find correlated indicators", "amber",
                () => this._runPivot(label, iocType, caseId)));
            items.push(this._separator());
            items.push(this._item("crosshair", "Qualify + Pivot",
                "Enrich then correlate", "violet",
                () => this._runQualifyAndPivot(label, iocType, caseId, nodeData)));
        }
        return items;
    },

    async _runQualify(label, iocType, caseId, nodeData) {
        this.hide();
        await App.runAction({ action: "add_ioc", case_id: caseId, value: label });
        const result = await App.runAction({
            action: "enrich", case_id: caseId, indicator_filter: label,
        });
        if (result?.job_id) {
            App.socket?.on?.("job_update", function handler(d) {
                if (d.job_id === result.job_id && d.status === "done") {
                    App.socket.off("job_update", handler);
                    EnrichPanel?.load?.(nodeData, caseId);
                }
            });
        }
    },

    async _runPivot(label, iocType, caseId) {
        this.hide();
        await App.runAction({ action: "add_ioc", case_id: caseId, value: label });
        const corrConfig = Object.keys(Modules?.registry || {}).reduce((acc, k) => ({
            ...acc, ...(Modules.getCorrelationConfig(k) || {}),
        }), {});
        await App.runAction({
            action: "correlate", case_id: caseId,
            indicator_filter: label, correlation_config: corrConfig,
        });
    },

    async _runQualifyAndPivot(label, iocType, caseId, nodeData) {
        this.hide();
        await App.runAction({ action: "add_ioc", case_id: caseId, value: label });
        const corrConfig = Object.keys(Modules?.registry || {}).reduce((acc, k) => ({
            ...acc, ...(Modules.getCorrelationConfig(k) || {}),
        }), {});
        const result = await App.runAction({
            action: "enrich_and_correlate", case_id: caseId,
            indicator_filter: label, correlation_config: corrConfig,
        });
        if (result?.job_id) {
            App.socket?.on?.("job_update", function handler(d) {
                if (d.job_id === result.job_id && d.status === "done") {
                    App.socket.off("job_update", handler);
                    EnrichPanel?.load?.(nodeData, caseId);
                }
            });
        }
    },

    _header(label, type) {
        const el = document.createElement("div");
        el.className = "px-3 py-2 border-b border-slate-800 flex items-center gap-2";
        el.innerHTML = `
            <span class="text-slate-200 text-xs font-bold mono truncate max-w-[140px]"
                  title="${label}">${label}</span>
            <span class="bg-slate-700 text-slate-400 text-[9px] px-1.5 py-0.5 rounded uppercase shrink-0">${type}</span>
        `;
        return el;
    },

    _item(icon, label, tooltip, color, onClick) {
        const colors = {
            blue:   "text-blue-400 hover:bg-blue-500/10",
            amber:  "text-amber-400 hover:bg-amber-500/10",
            violet: "text-violet-400 hover:bg-violet-500/10",
        };
        const el = document.createElement("button");
        el.className = `w-full flex items-center gap-3 px-3 py-2 transition text-left
                        ${colors[color] || "text-slate-300 hover:bg-slate-800"}`;
        el.title = tooltip;
        el.innerHTML = `
            <i data-lucide="${icon}" class="w-4 h-4 shrink-0"></i>
            <span class="text-xs font-medium">${label}</span>
        `;
        el.addEventListener("click", e => { e.stopPropagation(); onClick(); });
        lucide.createIcons({ nodes: [el] });
        return el;
    },

    _separator() {
        const el = document.createElement("div");
        el.className = "my-1 border-t border-slate-800";
        return el;
    },
};