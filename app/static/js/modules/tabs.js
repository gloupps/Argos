window.Tabs = {
    container: null, newBtn: null, createLock: false,
    tabs: {},

    init() {
        this.container = document.getElementById("tabs");
        this.newBtn    = document.getElementById("new-tab-btn");
        if (!this.container || !this.newBtn) { console.error("[Tabs] DOM missing"); return; }
        this.newBtn.addEventListener("click", () => this.create());
        this.container.addEventListener("dragstart", e => {
            const t = e.target.closest("[data-id]");
            if (t) this._draggingId = t.dataset.id;
        });
        this.container.addEventListener("dragend", () => { this._draggingId = null; });
        this.ensureTab();
    },

    ensureTab() {
        if (!Object.keys(App.state.tabs).length) {
            const id = App.createTab({ name: "Case 1" });
            this._render(id);
            this.activate(id);
        } else {
            this._restoreFromState();
        }
    },

    create() {
        if (this.createLock) return;
        this.createLock = true;
        setTimeout(() => { this.createLock = false; }, 200);
        const id = App.createTab({ name: `Case ${Object.keys(App.state.tabs).length}` });
        this._render(id);
        this.activate(id);
        return id;
    },

    _render(tabId) {
        const tabData = App.state.tabs[tabId];
        if (!tabData) return;
        const tab = document.createElement("div");
        tab.className = "px-4 py-1 bg-slate-800 text-xs rounded-t flex items-center gap-2 cursor-pointer hover:bg-slate-700 transition select-none";
        tab.dataset.id = tabId;
        tab.draggable = true;
        tab.innerHTML = `
            <span class="tab-label truncate max-w-[140px]">${tabData.name}</span>
            <span class="ml-1 text-slate-400 hover:text-red-400 cursor-pointer leading-none" data-close="true">×</span>
        `;
        tab.addEventListener("click", e => { if (!e.target.dataset.close) this.activate(tabId); });
        tab.querySelector("[data-close]").addEventListener("click", e => { e.stopPropagation(); this.close(tabId); });

        // ── Drag & drop ──
        tab.addEventListener("dragstart", e => {
            e.dataTransfer.effectAllowed = "move";
            e.dataTransfer.setData("text/plain", tabId);
            tab.classList.add("opacity-40");
        });
        tab.addEventListener("dragend", () => tab.classList.remove("opacity-40"));
        tab.addEventListener("dragover", e => {
            e.preventDefault();
            e.dataTransfer.dropEffect = "move";
            const draggingId = this._draggingId;
            if (!draggingId || draggingId === tabId) return;
            const allTabs = [...this.container.querySelectorAll("[data-id]")];
            const fromIdx = allTabs.findIndex(t => t.dataset.id === draggingId);
            const toIdx   = allTabs.findIndex(t => t.dataset.id === tabId);
            if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;
            const fromEl = allTabs[fromIdx];
            if (fromIdx < toIdx) this.container.insertBefore(fromEl, tab.nextSibling);
            else                  this.container.insertBefore(fromEl, tab);
        });
        tab.addEventListener("dragenter", e => { e.preventDefault(); });

        this.container.insertBefore(tab, this.newBtn);
        this.tabs[tabId] = tab;
    },

    activate(tabId) {
        if (!App.state.tabs[tabId]) return;
        Object.values(this.tabs).forEach(t => {
            t.classList.remove("bg-slate-700", "border-t-2", "border-blue-500");
            t.classList.add("bg-slate-800");
        });
        const tab = this.tabs[tabId];
        if (!tab) return;
        tab.classList.remove("bg-slate-800");
        tab.classList.add("bg-slate-700", "border-t-2", "border-blue-500");
        App.switchTab(tabId);
    },

    updateLabel(tabId, label) {
        const span = this.tabs[tabId]?.querySelector(".tab-label");
        if (span) span.textContent = label;
    },

    close(tabId) {
        this.tabs[tabId]?.remove();
        delete this.tabs[tabId];
        App.closeTab(tabId);
        const rem = Object.keys(App.state.tabs);
        if (rem.length) { this.activate(rem[0]); return; }
        setTimeout(() => this.ensureTab(), 0);
    },

    _restoreFromState() {
        Object.values(this.tabs).forEach(t => t.remove());
        this.tabs = {};
        Object.keys(App.state.tabs).forEach(id => this._render(id));
        const active = App.state.activeTab;
        const first  = Object.keys(App.state.tabs)[0];
        this.activate(active && this.tabs[active] ? active : first);
    },
};
