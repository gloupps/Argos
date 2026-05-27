window.SIEMModule = {
    modules: {}, state: {},

    init() {
        console.log("[SIEM] init");
        this._loadState();
        this._fetchModules();
    },

    async _fetchModules() {
        try {
            // Le schéma SIEM vient maintenant du registry global si disponible
            // sinon fallback sur l'endpoint legacy
            const res = await fetch("/api/run", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "get_modules" }),
            });
            const all = await res.json();
            // Filtre les modules de type "siem"
            this.modules = Object.fromEntries(
                Object.entries(all).filter(([, m]) => m.type === "siem")
            );
            this._render();
        } catch (e) { console.error("[SIEM] fetch error", e); }
    },

    _loadState() { const r = localStorage.getItem("cti_siem"); this.state = r ? JSON.parse(r) : {}; },
    _saveState()  { localStorage.setItem("cti_siem", JSON.stringify(this.state)); },

    _render() {
        const container = document.getElementById("siem-container");
        if (!container) return;
        if (!Object.keys(this.modules).length) {
            container.innerHTML = `<p class="text-slate-600 text-xs italic">No SIEM modules configured.</p>`;
            return;
        }
        container.innerHTML = "";
        // render logic here when SIEM modules are added
        lucide.createIcons();
    },

    update(key, value) { this.state[key] = value; this._saveState(); },

    run() {
        const tabId  = App?.state?.activeTab;
        const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;
        if (!caseId) return;
        App.runAction({ action: "siem", case_id: caseId, ...this.state });
    },
};
