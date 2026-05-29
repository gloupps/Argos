const App = {

    state: { tabs: {}, activeTab: null },
    container: null,
    socket:    null,

    _STATE_KEY: "pivotlens_app_state",

    async init() {
        console.log("[APP] init");

        this.container = document.getElementById("case-container");
        if (!this.container) { console.error("[APP] #case-container not found"); return; }

        this._initSocket();
        this._bindGlobalEvents();

        await Modules?.init?.();

        JobLog?.init?.();
        Settings?.init?.();
        SIEMModule?.init?.();
        CorrelationModule?.init?.();
        GraphModule?.init?.();

        // Restaurer l'état AVANT Tabs.init() pour que ensureTab() trouve les tabs
        this._loadState();
        
        // CaseModule écoute uniquement view:loaded pour binder le formulaire.
        // Le chargement initial est entièrement délégué à Tabs.
        CaseModule?.init?.();
        Tabs?.init?.();


        

        console.log("[APP] ready");
    },

    // ── Persistance sessionStorage ────────────────────────

    _loadState() {
        try {
            const raw = sessionStorage.getItem(this._STATE_KEY);
            if (!raw) return;
            const saved = JSON.parse(raw);
            if (saved?.tabs && typeof saved.tabs === "object") {
                this.state.tabs      = saved.tabs;
                this.state.activeTab = saved.activeTab || null;
                console.log("[APP] state restored:", Object.keys(this.state.tabs).length, "tab(s)");
            }
        } catch (_) {}
    },

    _saveState() {
        try {
            sessionStorage.setItem(this._STATE_KEY, JSON.stringify({
                tabs:      this.state.tabs,
                activeTab: this.state.activeTab,
            }));
        } catch (_) {}
    },

    // ── Socket ────────────────────────────────────────────

    _initSocket() {
        if (typeof io === "undefined") { console.warn("[APP] socket.io not loaded"); return; }
        this.socket = io();
        this.socket.on("job_update",   data => JobLog?.push?.(data));
        this.socket.on("graph_update", data => {
            if (data.case_id && data.graph)
                GraphModule.handleGraphUpdate(data.case_id, data.graph);
        });
    },

    // ── Tabs ──────────────────────────────────────────────

    createTab(data) {
        const id = data.id || crypto.randomUUID();
        this.state.tabs[id] = {
            id,
            name:   data.name   || `Case ${Object.keys(this.state.tabs).length + 1}`,
            caseId: data.caseId || null,
        };
        this.state.activeTab = id;
        this._saveState();
        return id;
    },

    switchTab(id) {
        const tab = this.state.tabs[id];
        if (!tab) return;
        this.state.activeTab = id;
        this._saveState();
        tab.caseId
            ? this.loadView(`/view/case/${tab.caseId}`)
            : this.loadView("/view/new-case");
    },

    closeTab(id) {
        if (!this.state.tabs[id]) return;
        delete this.state.tabs[id];
        if (this.state.activeTab === id) {
            const rem = Object.keys(this.state.tabs);
            rem.length
                ? this.switchTab(rem[0])
                : (this.state.activeTab = null, Tabs?.ensureTab?.());
        }
        this._saveState();
    },

    // ── View loader ───────────────────────────────────────

    async loadView(url) {
        try {
            const res = await fetch(url);
            if (!res.ok) {
                console.error("[APP] view error", res.status, url);
                // Case supprimé en DB → nettoyer l'état et afficher le formulaire
                if (url.includes("/view/case/") && res.status === 404) {
                    const tabId = this.state.activeTab;
                    if (tabId && this.state.tabs[tabId]) {
                        this.state.tabs[tabId].caseId = null;
                        this.state.tabs[tabId].name   = "Case 1";
                        Tabs?.updateLabel?.(tabId, "Case 1");
                        this._saveState();
                    }
                    return this.loadView("/view/new-case");
                }
                return;
            }
            this.container.innerHTML = await res.text();
            lucide.createIcons();
            requestAnimationFrame(() => {
                document.dispatchEvent(new CustomEvent("view:loaded", { detail: { url } }));
                this._onViewLoaded(url);
            });
        } catch (err) {
            console.error("[APP] loadView failed", err);
        }
    },

    _onViewLoaded(url) {
        if (url.includes("/view/case/")) {
            const caseId = url.split("/view/case/")[1];
            this.socket?.emit("subscribe_case", { case_id: caseId });
            GraphModule?.loadCase?.(this.state.activeTab, caseId);
            IocInput?.init?.();
            EnrichPanel?.clear?.();
            Modules?.renderSidebar?.();
        }
    },

    // ── Action runner ─────────────────────────────────────

    async runAction(payload) {
        if (!payload.api_keys) {
            const forCorr = payload.action === "correlate";
            payload = { ...payload, api_keys: this._collectApiKeys(forCorr) };
        }
        if (!payload.extra_config) {
            payload = { ...payload, extra_config: this._collectExtraConfig() };
        }
        try {
            const res  = await fetch("/api/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const json = await res.json();
            if (!res.ok) { console.error("[APP] runAction error", json); return null; }
            return json;
        } catch (err) {
            console.error("[APP] runAction failed", err);
            return null;
        }
    },

    _collectApiKeys(forCorrelation = false) {
        const keys = {};
        Object.keys(Modules?.registry || {}).forEach(k => {
            const enabled = forCorrelation
                ? Modules?.isCorrelateEnabled?.(k) !== false
                : Modules?.isEnabled?.(k) !== false;
            if (enabled && SecretStore?.has?.(k)) keys[k] = SecretStore.get(k);
        });
        return keys;
    },

    _collectExtraConfig() {
        return Modules?.collectExtraConfig?.() || {};
    },

    _bindGlobalEvents() {
        document.addEventListener("click", e => {
            const el = e.target.closest("[data-action]");
            if (!el) return;
            switch (el.dataset.action) {
                case "open-settings":  Settings?.open?.();  break;
                case "close-settings": Settings?.close?.(); break;
                case "save-settings":  Settings?.save?.();  break;
                case "close-node-panel":
                    document.getElementById("node-panel")?.classList.add("hidden"); break;
                case "rename-case":
                    CaseHeader?.startRename?.(); break;
            }
        });
        window.addEventListener("beforeunload", () => this._saveState());
    },
};

// ── Job log ───────────────────────────────────────────────

window.JobLog = {
    el: null, _timer: null,
    init() { this.el = document.getElementById("job-log"); },
    push({ message, status }) {
        if (!this.el) return;
        this.el.classList.remove("hidden");
        const line = document.createElement("div");
        line.className = `text-[10px] font-mono flex gap-2 ${
            status === "done"   ? "text-green-400" :
            status === "failed" ? "text-red-400"   : "text-slate-300"
        }`;
        const icon = status === "done" ? "✓" : status === "failed" ? "✗" : "›";
        line.innerHTML = `<span class="text-slate-500 shrink-0">${icon}</span><span class="break-all">${message}</span>`;
        this.el.appendChild(line);
        this.el.scrollTop = this.el.scrollHeight;
        if (status === "done" || status === "failed") {
            clearTimeout(this._timer);
            this._timer = setTimeout(() => {
                this.el?.classList.add("hidden");
                if (this.el) this.el.innerHTML = "";
            }, 8000);
        }
    },
};

window.App = App;
document.addEventListener("DOMContentLoaded", () => App.init());
