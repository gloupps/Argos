
window.Settings = {

    data: {},

    modules: null,

    init() {
        console.log("[Settings] init");

        this.load();
        this.bind();
        this.fetchModules();
    },

    // ==========================
    // LOAD LOCAL KEYS ONLY
    // ==========================
    load() {

        const raw = localStorage.getItem("cti_settings");

        this.data = raw ? JSON.parse(raw) : {};

    },

    // ==========================
    // FETCH MODULES FROM BACKEND
    // ==========================
    async fetchModules() {

        try {
            const res = await fetch("/api/modules");
            this.modules = await res.json();

        } catch (err) {
            console.error("[Settings] modules fetch error", err);
        }
    },

    // ==========================
    // OPEN MODAL
    // ==========================
    open() {
        document.getElementById("settings-modal")?.classList.remove("hidden");
        this.render();
    },

    close() {
        document.getElementById("settings-modal")?.classList.add("hidden");
    },

    // ==========================
    // RENDER DYNAMIC MODULES
    // ==========================
    render() {

        const container = document.getElementById("settings-keys");
        if (!container || !this.modules) return;

        container.innerHTML = "";

        Object.entries(this.modules).forEach(([group, modules]) => {

            // GROUP TITLE
            const title = document.createElement("div");
            title.className = "text-xs text-slate-500 uppercase mt-4 mb-2";
            title.textContent = group;

            container.appendChild(title);

            // MODULES LIST
            modules.forEach(mod => {

                const key = mod.key;
                const value = this.data[key] || "";

                const status =
                    value
                        ? "bg-green-500/20 text-green-400"
                        : "bg-red-500/20 text-red-400";

                const row = document.createElement("div");

                row.className = "flex items-center gap-3 mb-2";

                row.innerHTML = `
                    <div class="w-40 text-sm flex items-center gap-2">
                        <i data-lucide="${mod.icon}" class="w-4 h-4"></i>
                        ${mod.name}
                    </div>

                    <input type="password"
                           data-key="${key}"
                           value="${value}"
                           class="flex-1 bg-slate-900 border border-slate-700 rounded p-2 text-sm">

                    <span class="text-[10px] px-2 py-1 rounded ${status}">
                        ${value ? "SET" : "MISSING"}
                    </span>

                    <span class="text-[10px] text-slate-500 quota"
                          data-quota="${key}">
                        --
                    </span>
                `;

                container.appendChild(row);
            });
        });

        lucide.createIcons();

        this.fetchQuotas();
    },

    // ==========================
    // SAVE ALL KEYS
    // ==========================
    save() {

        document.querySelectorAll("#settings-keys input").forEach(input => {
            this.data[input.dataset.key] = input.value;
        });

        localStorage.setItem("cti_settings", JSON.stringify(this.data));

        console.log("[Settings] saved");

        this.close();

        // optional: notify modules
        document.dispatchEvent(new Event("settings:updated"));
    },

    // ==========================
    // QUOTAS (OPTIONAL BACKEND)
    // ==========================
    async fetchQuotas() {

        try {
            const res = await fetch("/api/settings/quotas");
            const quotas = await res.json();

            Object.entries(quotas).forEach(([key, value]) => {

                const el = document.querySelector(`[data-quota="${key}"]`);

                if (el) el.textContent = value;
            });

        } catch (err) {
            console.warn("[Settings] quota fetch failed");
        }
    },

    // ==========================
    // EVENTS
    // ==========================
    bind() {

        document.addEventListener("click", (e) => {

            if (e.target.closest('[data-action="open-settings"]')) {
                this.open();
            }

            if (e.target.closest('[data-action="close-settings"]')) {
                this.close();
            }

            if (e.target.closest('[data-action="save-settings"]')) {
                this.save();
            }
        });
    }
};