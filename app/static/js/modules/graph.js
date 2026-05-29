// ══════════════════════════════════════════════════════════
// GRAPH MODULE
// ══════════════════════════════════════════════════════════
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

        cy.on("tap", "node", evt => {
            const data = evt.target.data();
            this._selectNode(tabId, data.id);
            if (!data.synthetic) EnrichPanel?.load?.(data, caseId);
        });

        cy.on("tap", evt => {
            if (evt.target === cy) {
                cy.elements().removeClass("selected-node");
                EnrichPanel?.clear?.();
                LinkDrag.cancel();
            }
        });

        cy.on("cxttap", "node", evt => {
            if (LinkDrag.isActive()) return;
            evt.originalEvent.preventDefault();
            const data = evt.target.data();
            this._selectNode(tabId, data.id);
            ContextMenu.showNode(data, caseId, evt.originalEvent.clientX, evt.originalEvent.clientY);
        });

        cy.on("cxttap", evt => {
            if (LinkDrag.isActive()) return;
            if (evt.target !== cy) return;
            evt.originalEvent.preventDefault();
            ContextMenu.showCanvas(caseId, evt.originalEvent.clientX, evt.originalEvent.clientY);
        });

        cy.on("viewport", () => ContextMenu.hide());

        // ── Drag-to-link : clic droit maintenu ──────────────
        // mousedown  → hit-test manuel → start()
        // mousemove  → update SVG line (toujours actif sur container)
        // mouseup    → sur document pour capturer même hors container
        // contextmenu → annuler si drag actif

        const _hitNode = (clientX, clientY) => {
            const rect = container.getBoundingClientRect();
            const x = clientX - rect.left;
            const y = clientY - rect.top;
            return cy.nodes().filter(n => {
                const np = n.renderedPosition();
                const w  = n.renderedWidth()  / 2 + 12;
                const h  = n.renderedHeight() / 2 + 12;
                return Math.abs(np.x - x) <= w && Math.abs(np.y - y) <= h;
            })[0] || null;
        };

        container.addEventListener("mousedown", e => {
            if (e.button !== 2) return;
            const node = _hitNode(e.clientX, e.clientY);
            if (!node) return;
            e.preventDefault();
            LinkDrag.start(node, caseId, cy, tabId);
        });

        container.addEventListener("mousemove", e => {
            LinkDrag.move(e, cy);
        });

        // mouseup sur document pour capturer le relâché hors container
        const _onDocMouseUp = e => {
            if (e.button !== 2) return;
            if (!LinkDrag.isActive()) return;
            e.preventDefault();
            const node = _hitNode(e.clientX, e.clientY);
            if (node && node.id() !== LinkDrag.srcId()) {
                LinkDrag.end(node, tabId);
            } else {
                LinkDrag.cancel();
            }
        };
        document.addEventListener("mouseup", _onDocMouseUp);

        container.addEventListener("contextmenu", e => {
            if (LinkDrag.isActive()) { e.preventDefault(); LinkDrag.cancel(); }
        });
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

    async refreshGraph(tabId, caseId) {
        const inst = this.instances[tabId];
        if (!inst || inst.caseId !== caseId) return this.loadCase(tabId, caseId);
        try {
            const res  = await fetch(`/api/cases/${caseId}/graph`);
            const data = await res.json();
            this._mergeRender(tabId, data);
        } catch (err) {
            console.error("[Graph] refreshGraph error", err);
        }
    },

    handleGraphUpdate(caseId, graphData) {
        const tabId = Object.keys(this.instances).find(tid => this.instances[tid].caseId === caseId);
        if (tabId) this._mergeRender(tabId, graphData);
    },

    // ── Helpers de construction d'éléments ────────────────

    _buildElements(data, savedPos) {
        const elements  = [];
        const nodeIndex = new Set();

        // ── IOC nodes ─────────────────────────────────────
        (data.nodes || []).forEach(n => {
            const id = String(n.id);
            nodeIndex.add(id);
            const el = {
                group:   "nodes",
                data:    { id, label: n.value || id, type: n.type || "ioc",
                           nodeType: n.node_type || "correlated", synthetic: false },
                classes: n.node_type || "correlated",
            };
            if (savedPos && savedPos[id]) el.position = savedPos[id];
            elements.push(el);
        });

        // ── Pivot nodes depuis la table pivots ──────────────
        // Indexer les pivots par id pour déduplication dans legacy_edges
        const pivotById = {};
        (data.pivots || []).forEach(p => {
            const pivotId = `pivot::${p.id}`;
            pivotById[p.id] = pivotId;
            if (!nodeIndex.has(pivotId)) {
                nodeIndex.add(pivotId);
                const display = p.label.length > 40 ? p.label.slice(0, 37) + "…" : p.label;
                const el = {
                    group:   "nodes",
                    data:    { id: pivotId, label: display, type: "pivot",
                               nodeType: "pivot", synthetic: true,
                               fullLabel: p.label, pivotDbId: p.id, pivotModule: p.module },
                    classes: "pivot",
                };
                if (savedPos && savedPos[pivotId]) el.position = savedPos[pivotId];
                elements.push(el);
            }
        });

        // ── Edges pivot↔IOC depuis pivot_links (avec direction) ──
        // direction="out" → IOC --→ pivot   (l'analyste est parti de l'IOC)
        // direction="in"  → pivot --→ IOC   (le pivot a découvert l'IOC)
        const edgeIndex = new Set();
        (data.edges || []).forEach(e => {
            const pivotId = `pivot::${e.pivot_id}`;
            const indId   = String(e.indicator_id);
            if (!nodeIndex.has(pivotId) || !nodeIndex.has(indId)) return;
            const dir     = e.direction || "out";
            const edgeSrc = dir === "out" ? indId   : pivotId;
            const edgeTgt = dir === "out" ? pivotId : indId;
            const edgeId  = `pl__${e.pivot_id}__${indId}`;
            if (edgeIndex.has(edgeId)) return;
            edgeIndex.add(edgeId);
            elements.push({ group: "edges", data: {
                id: edgeId, source: edgeSrc, target: edgeTgt,
                module: e.pivot_module || "manual"
            }});
        });

        // ── Legacy edges (table correlation) ─────────────
        // Seulement les edges dont le pivot n'est PAS déjà dans data.pivots
        // pour éviter le double rendu
        const pivotLabelToId = {};
        (data.pivots || []).forEach(p => { pivotLabelToId[p.label] = `pivot::${p.id}`; });

        (data.legacy_edges || []).forEach(e => {
            const src = String(e.src_indicator_id);
            const tgt = String(e.tgt_indicator_id);
            if (!nodeIndex.has(src) || !nodeIndex.has(tgt)) return;
            if (src === tgt) return;

            const pivotText = e.pivot;
            if (pivotText && pivotText !== "true" && pivotText !== "True") {
                // Si ce pivot est déjà dans pivot_links → ses edges sont déjà rendus, skip
                if (pivotLabelToId[pivotText]) return;

                // Pivot legacy non migré
                const pivotId = `pivot::legacy::${pivotText}`;
                if (!nodeIndex.has(pivotId)) {
                    nodeIndex.add(pivotId);
                    const display = pivotText.length > 40 ? pivotText.slice(0, 37) + "…" : pivotText;
                    elements.push({
                        group: "nodes",
                        data:  { id: pivotId, label: display, type: "pivot",
                                 nodeType: "pivot", synthetic: true, fullLabel: pivotText },
                        classes: "pivot",
                        ...(savedPos && savedPos[pivotId] ? { position: savedPos[pivotId] } : {}),
                    });
                }
                const e1 = `${src}__${pivotId}`;
                const e2 = `${pivotId}__${tgt}`;
                if (!edgeIndex.has(e1)) { edgeIndex.add(e1); elements.push({ group: "edges", data: { id: e1, source: src,     target: pivotId, module: e.module || "" } }); }
                if (!edgeIndex.has(e2)) { edgeIndex.add(e2); elements.push({ group: "edges", data: { id: e2, source: pivotId, target: tgt,     module: e.module || "" } }); }
            } else {
                const eid = `${src}__${tgt}`;
                if (!edgeIndex.has(eid)) { edgeIndex.add(eid); elements.push({ group: "edges", data: { id: eid, source: src, target: tgt, module: e.module || "" } }); }
            }
        });

        return { elements, nodeIndex };
    },

    render(tabId, data) {
        const inst = this.instances[tabId];
        if (!inst) return;
        const { cy } = inst;
        cy.elements().remove();
        const { elements } = this._buildElements(data, null);
        if (elements.length === 0) return;
        cy.add(elements);
        this._runLayout(cy, elements.length);
    },

    _mergeRender(tabId, data) {
        const inst = this.instances[tabId];
        if (!inst) return;
        const { cy } = inst;

        const savedPos = {};
        cy.nodes().forEach(n => { savedPos[n.id()] = { ...n.position() }; });
        cy.elements().remove();

        const { elements } = this._buildElements(data, savedPos);
        if (elements.length === 0) return;
        cy.add(elements);

        const unsettled = cy.nodes().filter(n => !savedPos[n.id()]);
        if (unsettled.length === 0) return;

        if (cy.nodes().length <= unsettled.length) {
            this._runLayout(cy, elements.length);
        } else {
            unsettled.forEach(n => {
                const neighbors = n.neighborhood("node").filter(nb => savedPos[nb.id()]);
                if (neighbors.length > 0) {
                    const avg = neighbors.reduce((acc, nb) => {
                        const p = nb.position();
                        return { x: acc.x + p.x, y: acc.y + p.y };
                    }, { x: 0, y: 0 });
                    n.position({
                        x: avg.x / neighbors.length + (Math.random() - 0.5) * 80,
                        y: avg.y / neighbors.length + (Math.random() - 0.5) * 80,
                    });
                } else {
                    const ext = cy.extent();
                    n.position({
                        x: ext.x1 + Math.random() * (ext.x2 - ext.x1),
                        y: ext.y1 + Math.random() * (ext.y2 - ext.y1),
                    });
                }
            });
        }
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
            { selector: "node.link-source", style: {
                "border-width": 3, "border-color": "#3b82f6",
                "overlay-color": "#3b82f6", "overlay-opacity": 0.2,
            }},
            { selector: "edge", style: {
                "width": 1.5, "line-color": "#334155",
                "target-arrow-color": "#334155", "target-arrow-shape": "triangle",
                "curve-style": "bezier", "opacity": 0.7,
            }},
            { selector: "edge.manual", style: {
                "line-color": "#3b82f6", "target-arrow-color": "#3b82f6",
                "line-style": "dashed", "opacity": 0.9,
            }},
        ];
    },
};

// ══════════════════════════════════════════════════════════
// LINK DRAG
// ══════════════════════════════════════════════════════════
window.LinkDrag = {

    _srcNode:  null,
    _srcData:  null,   // copie des data() avant cancel()
    _caseId:   null,
    _cy:       null,
    _tabId:    null,
    _line:     null,
    _active:   false,

    isActive() { return this._active; },
    srcId()    { return this._srcNode?.id(); },

    start(node, caseId, cy, tabId) {
        this._srcNode = node;
        this._srcData = { ...node.data() };   // snapshot immédiat
        this._caseId  = caseId;
        this._cy      = cy;
        this._tabId   = tabId;
        this._active  = true;
        node.addClass("link-source");
        this._createLine(cy);
    },

    move(mouseEvt, cy) {
        if (!this._active || !this._line) return;
        const rect = cy.container().getBoundingClientRect();
        const x = mouseEvt.clientX - rect.left;
        const y = mouseEvt.clientY - rect.top;
        const src = this._srcNode.renderedPosition();
        this._line.setAttribute("x1", src.x);
        this._line.setAttribute("y1", src.y);
        this._line.setAttribute("x2", x);
        this._line.setAttribute("y2", y);
    },

    async end(targetNode, tabId) {
        if (!this._active) return;

        const srcData    = this._srcData;
        const tgtData    = { ...targetNode.data() };
        const caseId     = this._caseId;
        const srcIsPivot = srcData.nodeType === "pivot";
        const tgtIsPivot = tgtData.nodeType === "pivot";
        const srcLabel   = srcData.fullLabel || srcData.label;
        const tgtLabel   = tgtData.fullLabel || tgtData.label;

        this.cancel();

        // ── IOC → IOC : créer un nouveau pivot ───────────
        if (!srcIsPivot && !tgtIsPivot) {
            const pivotName = prompt(`Name the pivot connecting:\n${srcLabel}  ↔  ${tgtLabel}`, "");
            if (pivotName === null) return;
            const result = await App.runAction({
                action:        "add_manual_edge",
                case_id:       caseId,
                src:           srcLabel,
                tgt:           tgtLabel,
                pivot_label:   pivotName.trim() || "manual",
                src_direction: "out",   // src --→ pivot --→ tgt
            });
            if (result?.ok) {
                JobLog?.push?.({ message: `✓ pivot "${pivotName.trim() || "manual"}" created`, status: "done" });
                GraphModule?.refreshGraph?.(tabId, caseId);
            } else {
                JobLog?.push?.({ message: result?.error || "Failed", status: "failed" });
            }
            return;
        }

        // ── IOC → Pivot (drag depuis l'IOC vers le pivot) ──
        // IOC --→ pivot : direction "out"
        if (!srcIsPivot && tgtIsPivot) {
            const result = await App.runAction({
                action:        "add_manual_edge",
                case_id:       caseId,
                src:           srcLabel,
                pivot_label:   tgtLabel,
                src_direction: "out",
            });
            if (result?.ok) {
                JobLog?.push?.({ message: `✓ ${srcLabel} → pivot "${tgtLabel}"`, status: "done" });
                GraphModule?.refreshGraph?.(tabId, caseId);
            } else {
                JobLog?.push?.({ message: result?.error || "Failed", status: "failed" });
            }
            return;
        }

        // ── Pivot → IOC (drag depuis le pivot vers l'IOC) ──
        // pivot --→ IOC : direction "in" (du point de vue de l'IOC)
        if (srcIsPivot && !tgtIsPivot) {
            const result = await App.runAction({
                action:        "add_manual_edge",
                case_id:       caseId,
                src:           tgtLabel,
                pivot_label:   srcLabel,
                src_direction: "in",
            });
            if (result?.ok) {
                JobLog?.push?.({ message: `✓ pivot "${srcLabel}" → ${tgtLabel}`, status: "done" });
                GraphModule?.refreshGraph?.(tabId, caseId);
            } else {
                JobLog?.push?.({ message: result?.error || "Failed", status: "failed" });
            }
            return;
        }

        // ── Pivot → Pivot : non supporté ──
        JobLog?.push?.({ message: "Cannot link two pivots directly", status: "failed" });
    },
    cancel() {
        this._active = false;
        this._srcNode?.removeClass("link-source");
        this._srcNode = null;
        this._srcData = null;
        this._line?.remove();
        this._line = null;
    },

    _createLine(cy) {
        const container = cy.container();
        let svg = container.querySelector(".link-drag-svg");
        if (!svg) {
            svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
            svg.classList.add("link-drag-svg");
            svg.style.cssText = "position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:10";
            container.style.position = "relative";
            container.appendChild(svg);
        }
        const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
        line.setAttribute("stroke", "#3b82f6");
        line.setAttribute("stroke-width", "2");
        line.setAttribute("stroke-dasharray", "6,3");
        line.setAttribute("opacity", "0.8");
        const pos = this._srcNode.renderedPosition();
        line.setAttribute("x1", pos.x); line.setAttribute("y1", pos.y);
        line.setAttribute("x2", pos.x); line.setAttribute("y2", pos.y);
        svg.appendChild(line);
        this._line = line;
    },
};

// ══════════════════════════════════════════════════════════
// CONTEXT MENU
// ══════════════════════════════════════════════════════════
window.ContextMenu = {

    _el: null,

    showNode(nodeData, caseId, x, y) {
        this._show(this._buildNodeItems(nodeData, caseId), x, y);
    },

    showCanvas(caseId, x, y) {
        this._show(this._buildCanvasItems(caseId), x, y);
    },

    _show(items, x, y) {
        this.hide();
        const menu = document.createElement("div");
        menu.id = "ctx-menu";
        menu.className = "fixed z-50 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl py-1 min-w-[190px] text-sm";
        menu.style.left = `${x}px`;
        menu.style.top  = `${y}px`;
        items.forEach(item => menu.appendChild(item));
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

    _buildNodeItems(nodeData, caseId) {
        const { nodeType, type: iocType, label } = nodeData;
        const items = [];
        items.push(this._header(label, iocType));

        if (nodeType === "pivot") {
            items.push(this._item("pencil",  "Rename pivot", "Rename this pivot label", "blue",
                () => this._runRenamePivot(nodeData, caseId)));
            items.push(this._item("share-2", "Re-pivot",     "Re-run correlation",      "amber",
                () => this._runPivot(label, iocType, caseId)));
            items.push(this._separator());
            items.push(this._item("trash-2", "Delete pivot", "Remove pivot and its edges", "red",
                () => this._runDeleteNode(nodeData, caseId)));
        } else if (nodeType == ("root"||"correlated")) {
            items.push(this._item("zap",       "Qualify",         "Enrich via all active modules", "blue",
                () => this._runQualify(label, iocType, caseId, nodeData)));
            items.push(this._item("share-2",   "Pivot",           "Find correlated indicators",    "amber",
                () => this._runPivot(label, iocType, caseId)));
            items.push(this._item("crosshair", "Qualify + Pivot", "Enrich then correlate",         "violet",
                () => this._runQualifyAndPivot(label, iocType, caseId, nodeData)));
            items.push(this._separator());
            items.push(this._item("trash-2", "Delete node", "Remove this indicator", "red",
                () => this._runDeleteNode(nodeData, caseId)));
        } else {
            items.push(this._sectionLabel("Add indicator"));
            items.push(this._item("circle-dot", "Root",       "Add as root indicator",       "red",
                () => this._runAddIndicator(caseId, "root")));
            items.push(this._item("diamond",    "Pivot",      "Add as pivot indicator",      "amber",
                () => this._runAddIndicator(caseId, "pivot")));
            items.push(this._item("circle",     "Correlated", "Add as correlated indicator", "violet",
                () => this._runAddIndicator(caseId, "correlated")));
        }
        return items;
    },

    _buildCanvasItems(caseId) {
        const items = [];
        items.push(this._canvasHeader());
        items.push(this._sectionLabel("Add indicator"));
        items.push(this._item("circle-dot", "Root",       "Add as root indicator",       "red",
            () => this._runAddIndicator(caseId, "root")));
        items.push(this._item("diamond",    "Pivot",      "Add as pivot indicator",      "amber",
            () => this._runAddIndicator(caseId, "pivot")));
        items.push(this._item("circle",     "Correlated", "Add as correlated indicator", "violet",
            () => this._runAddIndicator(caseId, "correlated")));
        return items;
    },

    async _runQualify(label, iocType, caseId, nodeData) {
        this.hide();
        const result = await App.runAction({ action: "enrich", case_id: caseId, indicator_filter: label });
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
        const corrConfig = Object.keys(Modules?.registry || {}).reduce((acc, k) => ({
            ...acc, ...(Modules.getCorrelationConfig(k) || {}),
        }), {});
        await App.runAction({ action: "correlate", case_id: caseId, indicator_filter: label, correlation_config: corrConfig });
    },

    async _runQualifyAndPivot(label, iocType, caseId, nodeData) {
        this.hide();
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

    async _runRenamePivot(nodeData, caseId) {
        this.hide();
        const currentLabel = nodeData.fullLabel || nodeData.label;
        const newLabel = prompt("Rename pivot:", currentLabel);
        if (!newLabel?.trim() || newLabel.trim() === currentLabel) return;
        const tabId = App?.state?.activeTab;
        const result = await App.runAction({
            action:    "rename_pivot",
            case_id:   caseId,
            old_label: currentLabel,
            new_label: newLabel.trim(),
        });
        if (result?.ok) {
            JobLog?.push?.({ message: `✓ Pivot renamed to "${newLabel.trim()}"`, status: "done" });
            GraphModule?.refreshGraph?.(tabId, caseId);
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to rename pivot", status: "failed" });
        }
    },

    async _runDeleteNode(nodeData, caseId) {
        this.hide();
        const label       = nodeData.fullLabel || nodeData.label;
        const isSynthetic = nodeData.synthetic === true;
        if (!confirm(`Delete "${label}"?\nThis will also remove its correlations.`)) return;
        const tabId = App?.state?.activeTab;
        const result = isSynthetic
            ? await App.runAction({ action: "delete_pivot",     case_id: caseId, pivot_label: label })
            : await App.runAction({ action: "delete_indicator", case_id: caseId, value: label });
        if (result?.ok) {
            JobLog?.push?.({ message: `✓ ${label} deleted`, status: "done" });
            GraphModule?.refreshGraph?.(tabId, caseId);
            EnrichPanel?.clear?.();
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to delete", status: "failed" });
        }
    },

    async _runAddIndicator(caseId, nodeType) {
        this.hide();
        const value = prompt(`Add a new ${nodeType} indicator:`);
        if (!value?.trim()) return;
        const tabId = App?.state?.activeTab;
        const result = await App.runAction({
            action: "add_ioc", case_id: caseId,
            value: value.trim(), node_type: nodeType,
        });
        if (result?.ok) {
            JobLog?.push?.({ message: `✓ ${value.trim()} added as ${nodeType}`, status: "done" });
            GraphModule?.refreshGraph?.(tabId, caseId);
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to add indicator", status: "failed" });
        }
    },

    _header(label, type) {
        const el = document.createElement("div");
        el.className = "px-3 py-2 border-b border-slate-800 flex items-center gap-2";
        el.innerHTML = `
            <span class="text-slate-200 text-xs font-bold mono truncate max-w-[140px]" title="${label}">${label}</span>
            <span class="bg-slate-700 text-slate-400 text-[9px] px-1.5 py-0.5 rounded uppercase shrink-0">${type}</span>`;
        return el;
    },

    _canvasHeader() {
        const el = document.createElement("div");
        el.className = "px-3 py-2 border-b border-slate-800";
        el.innerHTML = `<span class="text-slate-500 text-[10px] italic">Graph canvas</span>`;
        return el;
    },

    _sectionLabel(text) {
        const el = document.createElement("div");
        el.className = "px-3 pt-2 pb-0.5 text-[9px] text-slate-500 uppercase tracking-widest font-semibold";
        el.textContent = text;
        return el;
    },

    _item(icon, label, tooltip, color, onClick) {
        const colors = {
            blue:   "text-blue-400 hover:bg-blue-500/10",
            amber:  "text-amber-400 hover:bg-amber-500/10",
            violet: "text-violet-400 hover:bg-violet-500/10",
            red:    "text-red-400 hover:bg-red-500/10",
        };
        const el = document.createElement("button");
        el.className = `w-full flex items-center gap-3 px-3 py-1.5 transition text-left
                        ${colors[color] || "text-slate-300 hover:bg-slate-800"}`;
        el.title = tooltip;
        el.innerHTML = `
            <i data-lucide="${icon}" class="w-3.5 h-3.5 shrink-0"></i>
            <span class="text-xs font-medium">${label}</span>`;
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