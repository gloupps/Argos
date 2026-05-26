
const App = {

    // ==========================
    // CORE STATE
    // ==========================
    state: {
        tabs: {},
        activeTab: null
    },

    container: null,

    // ==========================
    // INIT
    // ==========================
    init() {
        console.log("[APP] init");

        this.container = document.getElementById("case-container");

        if (!this.container) {
            console.error("[APP] case-container not found");
            return;
        }

        this.initModules();
        this.bindGlobalEvents();

        console.log("[APP] ready");
    },

    // ==========================
    // MODULES
    // ==========================
    initModules() {

        console.log("[APP] init modules");

        Tabs?.init?.();
        CaseModule?.init?.();
        GraphModule?.init?.();
        Settings?.init?.();
        Modules?.init?.(); // 🔥 important for sidebar dynamic modules
    },

    // ==========================
    // TAB STATE
    // ==========================
    createTab(data) {

        const id = data.id || crypto.randomUUID();

        this.state.tabs[id] = {
            id,
            name: data.name || `Case ${Object.keys(this.state.tabs).length + 1}`,
            data: data.data || {}
        };

        this.state.activeTab = id;

        console.log("[APP] createTab", id);

        return id;
    },

    // ==========================
    // SWITCH TAB
    // ==========================
    switchTab(id) {

        const tab = this.state.tabs[id];

        if (!tab) {
            console.warn("[APP] unknown tab", id);
            return;
        }

        this.state.activeTab = id;

        console.log("[APP] switchTab", id);

        this.loadView("/new_case_form");
    },

    // ==========================
    // CLOSE TAB
    // ==========================
    closeTab(id) {

        if (!this.state.tabs[id]) return;

        delete this.state.tabs[id];

        console.log("[APP] closeTab", id);

        if (this.state.activeTab === id) {

            const remaining = Object.keys(this.state.tabs);

            if (remaining.length > 0) {
                this.switchTab(remaining[0]);
            } else {
                this.state.activeTab = null;

                // 🔥 auto recovery
                Tabs?.ensureTab?.();
            }
        }
    },

    // ==========================
    // GLOBAL EVENTS
    // ==========================
    bindGlobalEvents() {

        document.addEventListener("click", (e) => {

            console.log("[CLICK]", e.target);

            const action = e.target.closest("[data-action]");
            console.log("[ACTION FOUND]", action);

            if (!action) return;

            const type = action.dataset.action;

            console.log("[APP ACTION]", type);

            switch (type) {

                case "switch-tab":
                    this.switchTab(action.dataset.id);
                    break;

                case "close-tab":
                    this.closeTab(action.dataset.id);
                    break;
                
                case "new-case":
                    
                    break;

                case "open-settings":
                    console.log("[APP] opening settings modal...");

                    if (window.Settings?.open) {
                        Settings.open();
                    }

                    break;
            }
        });
    },

    // ==========================
    // VIEW LOADER (CORE ENGINE)
    // ==========================
    async loadView(url) {

        try {
            const res = await fetch(url);
            const html = await res.text();

            this.container.innerHTML = html;

            lucide.createIcons();

            // 🔥 lifecycle hook (VERY IMPORTANT)
            requestAnimationFrame(() => {

                console.log("[APP] view loaded:", url);

                document.dispatchEvent(new Event("view:loaded"));

                // re-init view-specific modules
                this.onViewLoaded(url);
            });

        } catch (err) {
            console.error("[APP] view load error", err);
        }
    },

    // ==========================
    // VIEW LIFECYCLE HOOK
    // ==========================
    onViewLoaded(url) {

        if (url.includes("new_case_form")) {
            CaseModule?.bindForm?.();
        }

        // future:
        // graph init per case
        // SIEM init per case
        // correlation init
    }
};


// ==========================
// BOOTSTRAP
// ==========================
console.log("[APP] script loaded");

window.App = App;

document.addEventListener("DOMContentLoaded", () => {
    App.init();
});