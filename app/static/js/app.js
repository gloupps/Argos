const App = {

    state: { tabs: {}, activeTab: null },
    container: null,
    socket:    null,

    // ═══════════════════════════════════════════════════════
    // INIT — Modules.init() is awaited first so the registry
    // is populated before any action that needs api_keys.
    // ═══════════════════════════════════════════════════════
    async init() {
        console.log("[APP] init");

        this.container = document.getElementById("case-container");
        if (!this.container) { console.error("[APP] #case-container not found"); return; }

        this._initSocket();
        this._bindGlobalEvents();

        // 1. Load module registry first — everything else depends on it
        await Modules?.init?.();

        // 2. Boot the rest synchronously
        JobLog?.init?.();
        Settings?.init?.();
        SIEMModule?.init?.();
        CorrelationModule?.init?.();
        GraphModule?.init?.();
        Tabs?.init?.();          // triggers ensureTab → CaseModule.init via loadView
        CaseModule?.init?.();

        console.log("[APP] ready");
    },

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
        return id;
    },

    switchTab(id) {
        const tab = this.state.tabs[id];
        if (!tab) return;
        this.state.activeTab = id;
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
    },

    // ── View loader ───────────────────────────────────────

    async loadView(url) {
        try {
            const res = await fetch(url);
            if (!res.ok) { console.error("[APP] view error", res.status, url); return; }
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
        // bindForm is handled by CaseModule's own view:loaded listener
        if (url.includes("/view/case/")) {
            const caseId = url.split("/view/case/")[1];
            this.socket?.emit("subscribe_case", { case_id: caseId });
            GraphModule?.loadCase?.(this.state.activeTab, caseId);
            IocInput?.init?.();
            QualifPanel?.clear?.();
            Modules?.renderSidebar?.();
        }
    },

    // ── Action runner ─────────────────────────────────────
    // api_keys are always collected from SecretStore using the
    // loaded registry — no static fallback needed since we await
    // Modules.init() before any user action can fire.

    async runAction(payload) {
        if (!payload.api_keys) {
            payload = { ...payload, api_keys: this._collectApiKeys() };
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

    // Collects all keys from SecretStore using the registry keys.
    // Registry is guaranteed to be loaded when this is called.
    _collectApiKeys() {
        const keys = {};
        Object.keys(Modules?.registry || {}).forEach(k => {
            if (SecretStore?.has?.(k)) keys[k] = SecretStore.get(k);
        });
        return keys;
    },

    // ── Global events ─────────────────────────────────────

    _bindGlobalEvents() {
        document.addEventListener("click", e => {
            const el = e.target.closest("[data-action]");
            if (!el) return;
            switch (el.dataset.action) {
                case "open-settings":     Settings?.open?.();  break;
                case "close-settings":    Settings?.close?.(); break;
                case "save-settings":     Settings?.save?.();  break;
                case "close-node-panel":
                    document.getElementById("node-panel")?.classList.add("hidden"); break;
                case "rename-case":
                    CaseHeader?.startRename?.(); break;
            }
        });
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
