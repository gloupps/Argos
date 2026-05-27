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

        // ── Clic gauche nœud : sélection + enrichissement ──
        cy.on("tap", "node", evt => {
            const data = evt.target.data();
            this._selectNode(tabId, data.id);
            if (!data.synthetic) EnrichPanel?.load?.(data, caseId);
        });

        // ── Clic gauche fond : désélection ─────────────────
        cy.on("tap", evt => {
            if (evt.target === cy) {
                cy.elements().removeClass("selected-node");
                EnrichPanel?.clear?.();
                LinkDrag.cancel();
            }
        });

        // ── Clic droit nœud : context menu ─────────────────
        cy.on("cxttap", "node", evt => {
            evt.originalEvent.preventDefault();
            const data = evt.target.data();
            this._selectNode(tabId, data.id);
            ContextMenu.showNode(data, caseId, evt.originalEvent.clientX, evt.originalEvent.clientY);
        });

        // ── Clic droit fond : context menu "Add indicator" ─
        cy.on("cxttap", evt => {
            if (evt.target !== cy) return;
            evt.originalEvent.preventDefault();
            ContextMenu.showCanvas(caseId, evt.originalEvent.clientX, evt.originalEvent.clientY);
        });

        cy.on("viewport", () => ContextMenu.hide());

        // ── Drag-to-link : maintien clic DROIT ─────────────
        // On démarre le drag sur mousedown droit (contextmenu supprimé)
        // puis on écoute mousemove + mouseup nativement.
        container.addEventListener("mousedown", e => {
            if (e.button !== 2) return; // uniquement clic droit
            // Trouver le nœud sous le curseur
            const rect = container.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const pos = cy.renderer().projectIntoViewport(e.clientX, e.clientY);
            const hits = cy.nodes().filter(n => {
                const np = n.renderedPosition();
                const w  = n.renderedWidth()  / 2 + 8;
                const h  = n.renderedHeight() / 2 + 8;
                return Math.abs(np.x - x) <= w && Math.abs(np.y - y) <= h;
            });
            if (hits.length === 0) return; // pas de nœud → laisser le cxttap gérer
            const node = hits[0];
            // Empêche le context menu natif du navigateur pendant le drag
            e.preventDefault();
            LinkDrag.start(node, caseId, cy, tabId);
        });

        container.addEventListener("mousemove", e => LinkDrag.move(e, cy));

        container.addEventListener("mouseup", e => {
            if (e.button !== 2) return;
            if (!LinkDrag.isActive()) return;
            const rect = container.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const hits = cy.nodes().filter(n => {
                const np = n.renderedPosition();
                const w  = n.renderedWidth()  / 2 + 8;
                const h  = n.renderedHeight() / 2 + 8;
                return Math.abs(np.x - x) <= w && Math.abs(np.y - y) <= h;
            });
            if (hits.length > 0 && hits[0].id() !== LinkDrag.srcId()) {
                LinkDrag.end(hits[0], tabId);
            } else {
                LinkDrag.cancel();
            }
        });

        // Empêcher le menu contextuel natif quand on est en mode link
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

    // Rafraîchit le graph SANS recréer Cytoscape — préserve les positions.
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

    // Rerender en préservant les positions existantes ; layout uniquement sur les nouveaux nœuds.
    _mergeRender(tabId, data) {
        const inst = this.instances[tabId];
        if (!inst) return;
        const { cy } = inst;

        const savedPos = {};
        cy.nodes().forEach(n => { savedPos[n.id()] = { ...n.position() }; });
        cy.elements().remove();

        const elements  = [];
        const nodeIndex = new Set();

        (data.nodes || []).forEach(n => {
            const id = String(n.id || n.value);
            nodeIndex.add(id);
            const el = {
                group:   "nodes",
                data:    { id, label: n.value || id, type: n.type || "ioc",
                           nodeType: n.node_type || "correlated", synthetic: false },
                classes: n.node_type || "correlated",
            };
            if (savedPos[id]) el.position = savedPos[id];
            elements.push(el);
        });

        (data.edges || []).forEach(e => {
            const src = String(e.src_indicator_id || e.src_value  || e.source);
            const tgt = String(e.tgt_indicator_id || e.tgt_value  || e.target);
            if (!nodeIndex.has(src) || !nodeIndex.has(tgt)) return;

            const pivotText = e.pivot;
            if (pivotText && pivotText !== "true" && pivotText !== "True") {
                const pivotId = `pivot::${src}::${pivotText}`;
                if (!nodeIndex.has(pivotId)) {
                    nodeIndex.add(pivotId);
                    const display = pivotText.length > 40 ? pivotText.slice(0, 37) + "..." : pivotText;
                    const el = {
                        group:   "nodes",
                        data:    { id: pivotId, label: display, type: "pivot", nodeType: "pivot",
                                   synthetic: true, fullLabel: pivotText },
                        classes: "pivot",
                    };
                    if (savedPos[pivotId]) el.position = savedPos[pivotId];
                    elements.push(el);
                }
                elements.push({ group: "edges", data: { id: `${src}__${pivotId}`, source: src, target: pivotId, module: e.module || "" } });
                elements.push({ group: "edges", data: { id: `${pivotId}__${tgt}`, source: pivotId, target: tgt, module: e.module || "" } });
            } else {
                elements.push({ group: "edges", data: { id: `${src}__${tgt}`, source: src, target: tgt, module: e.module || "" } });
            }
        });

        if (elements.length === 0) return;
        cy.add(elements);

        // Nouveaux noeuds sans position sauvegardee
        const unsettled = cy.nodes().filter(n => !savedPos[n.id()]);
        if (unsettled.length === 0) return;

        if (cy.nodes().length <= unsettled.length) {
            this._runLayout(cy, elements.length);
        } else {
            unsettled.forEach(n => {
                const neighbors = n.neighborhood("node").filter(nb => !!savedPos[nb.id()]);
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

    render(tabId, data) {
        const inst = this.instances[tabId];
        if (!inst) return;
        const { cy } = inst;
        cy.elements().remove();

        const elements  = [];
        const nodeIndex = new Set();

        (data.nodes || []).forEach(n => {
            const id = String(n.id || n.value);
            nodeIndex.add(id);
            elements.push({
                group:   "nodes",
                data:    { id, label: n.value || id, type: n.type || "ioc",
                           nodeType: n.node_type || "correlated", synthetic: false },
                classes: n.node_type || "correlated",
            });
        });

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
                        data:    { id: pivotId, label: display, type: "pivot", nodeType: "pivot",
                                   synthetic: true, fullLabel: pivotText },
                        classes: "pivot",
                    });
                }
                elements.push({ group: "edges", data: { id: `${src}__${pivotId}`, source: src, target: pivotId, module: e.module || "" } });
                elements.push({ group: "edges", data: { id: `${pivotId}__${tgt}`, source: pivotId, target: tgt, module: e.module || "" } });
            } else {
                elements.push({ group: "edges", data: { id: `${src}__${tgt}`, source: src, target: tgt, module: e.module || "" } });
            }
        });

        if (elements.length === 0) return;
        cy.add(elements);
        this._runLayout(cy, elements.length);
    },

    handleGraphUpdate(caseId, graphData) {
        const tabId = Object.keys(this.instances).find(tid => this.instances[tid].caseId === caseId);
        if (tabId) this._mergeRender(tabId, graphData);
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
// LINK DRAG — clic droit maintenu entre deux nœuds
// ══════════════════════════════════════════════════════════
window.LinkDrag = {

    _srcNode: null,
    _caseId:  null,
    _cy:      null,
    _tabId:   null,
    _line:    null,
    _active:  false,

    isActive() { return this._active; },
    srcId()    { return this._srcNode?.id(); },

    start(node, caseId, cy, tabId) {
        this._srcNode = node;
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

        const srcData    = this._srcNode.data();
        const tgtData    = targetNode.data();
        const caseId     = this._caseId;
        const srcIsPivot = srcData.nodeType === "pivot";
        const tgtIsPivot = tgtData.nodeType === "pivot";

        // Texte réel en DB (fullLabel pour les pivots synthétiques)
        const srcLabel = srcData.fullLabel || srcData.label;
        const tgtLabel = tgtData.fullLabel || tgtData.label;

        this.cancel();

        if (!srcIsPivot && !tgtIsPivot) {
            // ── IOC → IOC : créer un nouveau pivot ───────────
            const pivotName = prompt(
                `Name the pivot connecting:\n${srcLabel}  ↔  ${tgtLabel}`,
                ""
            );
            if (pivotName === null) return;
            const result = await App.runAction({
                action:        "add_manual_edge",
                case_id:       caseId,
                src:           srcLabel,
                tgt:           tgtLabel,
                pivot_label:   pivotName.trim() || "manual",
                is_pivot_link: false,
            });
            if (result?.ok) {
                JobLog?.push?.({ message: `✓ pivot "${pivotName.trim() || "manual"}" created`, status: "done" });
                GraphModule?.refreshGraph?.(tabId, caseId);
            } else {
                JobLog?.push?.({ message: result?.error || "Failed to create link", status: "failed" });
            }
            return;
        }

        // ── IOC ↔ Pivot : lien direct sans popup ─────────────
        // Règle : src → tgt respecte le sens du drag.
        // Le pivot est toujours le "milieu" en DB ; src et tgt sont les deux IOC réels.
        // On connecte l'IOC draggé vers/depuis le pivot existant.
        const iocNode   = srcIsPivot ? targetNode : this._srcNode;
        const pivotNode = srcIsPivot ? this._srcNode : targetNode;
        const iocLabel  = iocNode.data("label");
        const pivotText = pivotNode.data("fullLabel") || pivotNode.data("label");

        // Trouver un IOC réel déjà relié au pivot (sera le src ou tgt en DB)
        // On cherche les voisins non-synthétiques du pivot dans le graph actuel
        const realNeighbors = pivotNode.neighborhood("node")
            .filter(n => !n.data("synthetic") && n.data("label") !== iocLabel);

        let anchorLabel = realNeighbors.length > 0 ? realNeighbors[0].data("label") : null;

        // Si src=IOC et tgt=pivot → lien IOC→pivot → en DB : ancre→iocLabel via pivotText
        // Si src=pivot et tgt=IOC → lien pivot→IOC → en DB : iocLabel→ancre via pivotText
        // On respecte le sens : si drag part du pivot, l'IOC est la destination
        const edgeSrc = srcIsPivot ? (anchorLabel || iocLabel) : iocLabel;
        const edgeTgt = srcIsPivot ? iocLabel : (anchorLabel || iocLabel);

        const result = await App.runAction({
            action:        "add_manual_edge",
            case_id:       caseId,
            src:           edgeSrc,
            tgt:           edgeTgt,
            pivot_label:   pivotText,
            is_pivot_link: true,
        });

        if (result?.ok) {
            JobLog?.push?.({ message: `✓ ${edgeSrc} → ${edgeTgt} via ${pivotText}`, status: "done" });
            GraphModule?.refreshGraph?.(tabId, caseId);
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to create link", status: "failed" });
        }
    },

    cancel() {
        this._active = false;
        this._srcNode?.removeClass("link-source");
        this._srcNode = null;
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

    // Menu sur un nœud
    showNode(nodeData, caseId, x, y) {
        this._show(this._buildNodeItems(nodeData, caseId), x, y);
    },

    // Menu sur le fond du canvas (vide)
    showCanvas(caseId, x, y) {
        this._show(this._buildCanvasItems(caseId), x, y);
    },

    _show(items, x, y) {
        this.hide();
        const menu = document.createElement("div");
        menu.id = "ctx-menu";
        menu.className =
            "fixed z-50 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl py-1 min-w-[190px] text-sm";
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

    // ── Items pour un nœud ────────────────────────────────

    _buildNodeItems(nodeData, caseId) {
        const { nodeType, type: iocType, label } = nodeData;
        const items = [];
        items.push(this._header(label, iocType));

        if (nodeType === "pivot") {
            // Pivot : renommer + re-pivot
            items.push(this._item("pencil",   "Rename pivot", "Rename this pivot label", "blue",
                () => this._runRenamePivot(nodeData, caseId)));
            items.push(this._item("share-2",  "Re-pivot",     "Re-run correlation",       "amber",
                () => this._runPivot(label, iocType, caseId)));
        } else {
            items.push(this._item("zap",       "Qualify",         "Enrich via all active modules", "blue",
                () => this._runQualify(label, iocType, caseId, nodeData)));
            items.push(this._item("share-2",   "Pivot",           "Find correlated indicators",    "amber",
                () => this._runPivot(label, iocType, caseId)));
            items.push(this._item("crosshair", "Qualify + Pivot", "Enrich then correlate",         "violet",
                () => this._runQualifyAndPivot(label, iocType, caseId, nodeData)));
        }

        items.push(this._separator());

        // Add indicator (disponible aussi depuis un nœud)
        items.push(this._sectionLabel("Add indicator"));
        items.push(this._item("circle-dot", "Root",       "Add as root indicator",       "red",
            () => this._runAddIndicator(caseId, "root")));
        items.push(this._item("diamond",    "Pivot",      "Add as pivot indicator",      "amber",
            () => this._runAddIndicator(caseId, "pivot")));
        items.push(this._item("circle",     "Correlated", "Add as correlated indicator", "violet",
            () => this._runAddIndicator(caseId, "correlated")));

        items.push(this._separator());

        items.push(this._item("trash-2", "Delete node",
            "Remove this indicator from the case", "red",
            () => this._runDeleteNode(label, caseId)));

        return items;
    },

    // ── Items pour le fond du canvas ──────────────────────

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

    // ── Actions ───────────────────────────────────────────

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
        // Les pivots synthétiques ont id = "pivot::<src>::<label>", les réels ont leur propre value
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

    async _runDeleteNode(label, caseId) {
        this.hide();
        if (!confirm(`Delete "${label}" from this case?\nThis will also remove its correlations and enrichment data.`)) return;
        const result = await App.runAction({ action: "delete_indicator", case_id: caseId, value: label });
        if (result?.ok) {
            JobLog?.push?.({ message: `✓ ${label} deleted`, status: "done" });
            const tabId = App?.state?.activeTab;
            GraphModule?.refreshGraph?.(tabId, caseId);
            EnrichPanel?.clear?.();
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to delete", status: "failed" });
        }
    },

    // ── UI helpers ────────────────────────────────────────

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