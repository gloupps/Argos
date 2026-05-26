
window.Modules = {

    data: null,

    state: {
        enabled: {}, // runtime activation (future per-case)
    },

    // ==========================
    // INIT
    // ==========================
    async init() {
        console.log("[Modules] init");

        await this.load();
    },

    // ==========================
    // LOAD FROM BACKEND
    // ==========================
    async load() {

        try {
            const res = await fetch("/api/modules");
            this.data = await res.json();

            console.log("[Modules] loaded", this.data);

            this.render();

        } catch (err) {
            console.error("[Modules] load error", err);
        }
    },

    // ==========================
    // CHECK IF MODULE IS AVAILABLE
    // ==========================
    isAvailable(moduleKey) {

        return SecretStore?.has?.(moduleKey);
    },

    // ==========================
    // CHECK IF MODULE IS ACTIVE (per case future)
    // ==========================
    isEnabled(moduleKey) {

        return this.state.enabled[moduleKey] ?? false;
    },

    // ==========================
    // TOGGLE MODULE (future per case usage)
    // ==========================
    toggle(moduleKey) {

        this.state.enabled[moduleKey] = !this.isEnabled(moduleKey);

        console.log("[Modules] toggle", moduleKey, this.state.enabled[moduleKey]);

        this.render();
    },

    // ==========================
    // RENDER SIDEBAR
    // ==========================
    render() {

        const container = document.getElementById("modules-container");

        if (!container) {
            console.warn("[Modules] container not found");
            return;
        }

        if (!this.data) return;

        container.innerHTML = "";

        Object.entries(this.data).forEach(([group, modules]) => {

            const section = document.createElement("section");

            section.innerHTML = `
                <h3 class="text-xs font-semibold text-slate-500 uppercase mb-3 tracking-wider">
                    ${group}
                </h3>
                <div class="space-y-2 text-sm"></div>
            `;

            const list = section.querySelector("div");

            modules.forEach(mod => {

                const hasKey = this.isAvailable(mod.key);
                const enabled = this.isEnabled(mod.key);

                const item = document.createElement("div");

                item.className = `
                    flex items-center justify-between p-2 rounded transition
                    ${hasKey
                        ? "hover:bg-slate-800 cursor-pointer"
                        : "opacity-30 cursor-not-allowed"}
                `;

                item.title = mod.description;

                item.innerHTML = `
                    <span class="flex items-center gap-2">
                        <i data-lucide="${mod.icon}" class="w-4 h-4 text-slate-300"></i>
                        <span>${mod.name}</span>
                    </span>

                    <span class="text-[10px] px-2 py-0.5 rounded
                        ${hasKey ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}">
                        ${hasKey ? (enabled ? "ON" : "OFF") : "LOCKED"}
                    </span>
                `;

                // ==========================
                // CLICK BEHAVIOR
                // ==========================
                item.addEventListener("click", () => {

                    if (!hasKey) {
                        console.warn(`[Modules] ${mod.name} locked (missing API key)`);
                        return;
                    }

                    this.toggle(mod.key);
                });

                list.appendChild(item);
            });

            container.appendChild(section);
        });

        lucide.createIcons();
    },

    // ==========================
    // GET ACTIVE MODULES (for case engine later)
    // ==========================
    getActiveModules() {

        return Object.keys(this.state.enabled)
            .filter(k => this.state.enabled[k]);
    }
};