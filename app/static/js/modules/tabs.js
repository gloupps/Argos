// modules/tabs.js

window.Tabs = {

    container: null,
    newBtn: null,
    createLock: false,

    tabs: {},

    // ==========================
    // INIT
    // ==========================
    init() {
        console.log("[Tabs] init");

        this.container = document.getElementById("tabs");
        this.newBtn = document.getElementById("new-tab-btn");

        if (!this.container || !this.newBtn) {
            console.error("[Tabs] missing DOM elements");
            return;
        }

        this.newBtn.addEventListener("click", () => this.create());

        // 🔥 ENSURE DEFAULT TAB
        this.ensureTab();
    },

    // ==========================
    // ENSURE AT LEAST ONE TAB
    // ==========================
    ensureTab() {

        const hasTabs = Object.keys(App.state.tabs).length > 0;

        if (!hasTabs) {
            console.log("[Tabs] ensuring default tab");

            const id = App.createTab({
                name: "Case 1"
            });

            this.render(id);
            this.activate(id);
        } else {
            // restore existing state if App already has tabs
            this.restoreFromState();
        }
    },

    // ==========================
    // CREATE TAB
    // ==========================
    create() {

        if (this.createLock) return;

        this.createLock = true;

        setTimeout(() => {
            this.createLock = false;
        }, 200);

        const tabId = App.createTab({
            name: `Case ${Object.keys(App.state.tabs).length + 1}`
        });

        this.render(tabId);
        this.activate(tabId);

        return tabId;
    },

    // ==========================
    // RENDER TAB
    // ==========================
    render(tabId) {

        const tabData = App.state.tabs[tabId];
        if (!tabData) return;

        const tab = document.createElement("div");

        tab.className = `
            px-4 py-1 bg-slate-800 text-xs rounded-t
            flex items-center gap-2 cursor-pointer
            hover:bg-slate-700 transition
        `;

        tab.dataset.id = tabId;

        tab.innerHTML = `
            <span class="truncate max-w-[140px]">
                ${tabData.name}
            </span>

            <span class="ml-2 text-slate-400 hover:text-red-400 cursor-pointer"
                  data-close="true">
                ×
            </span>
        `;

        // SWITCH
        tab.addEventListener("click", (e) => {
            if (e.target.dataset.close) return;
            this.activate(tabId);
        });

        // CLOSE
        tab.querySelector("[data-close]").addEventListener("click", (e) => {
            e.stopPropagation();
            this.close(tabId);
        });

        this.container.insertBefore(tab, this.newBtn);

        this.tabs[tabId] = tab;
    },

    // ==========================
    // ACTIVATE TAB
    // ==========================
    activate(tabId) {

        if (!App.state.tabs[tabId]) return;

        console.log("[Tabs] activate", tabId);

        // UI reset
        Object.values(this.tabs).forEach(tab => {
            tab.classList.remove(
                "bg-slate-700",
                "border-t-2",
                "border-blue-500"
            );
            tab.classList.add("bg-slate-800");
        });

        const tab = this.tabs[tabId];
        if (!tab) return;

        tab.classList.add(
            "bg-slate-700",
            "border-t-2",
            "border-blue-500"
        );

        App.switchTab(tabId);
    },

    // ==========================
    // CLOSE TAB (SAFE)
    // ==========================
    close(tabId) {

        const tab = this.tabs[tabId];
        if (!tab) return;

        console.log("[Tabs] close", tabId);

        // 1. remove UI
        tab.remove();
        delete this.tabs[tabId];

        // 2. remove state
        App.closeTab(tabId);

        // 3. fallback logic
        const remaining = Object.keys(App.state.tabs);

        if (remaining.length > 0) {
            this.activate(remaining[0]);
            return;
        }

        // 4. 🔥 NO TAB LEFT → RECREATE DEFAULT CASE
        console.log("[Tabs] no tab left → ensuring default");

        setTimeout(() => {
            this.ensureTab(); // <- your safety net
        }, 0);
    },

    // ==========================
    // RESTORE STATE (future-proof)
    // ==========================
    restoreFromState() {

        console.log("[Tabs] restoring state");

        // clear UI
        Object.values(this.tabs).forEach(t => t.remove());
        this.tabs = {};

        // rebuild
        Object.keys(App.state.tabs).forEach(tabId => {
            this.render(tabId);
        });

        const active = App.state.activeTab;

        if (active && this.tabs[active]) {
            this.activate(active);
        } else {
            const first = Object.keys(App.state.tabs)[0];
            if (first) this.activate(first);
        }
    }
};