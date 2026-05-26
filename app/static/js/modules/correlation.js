window.CorrelationModule = {

    modules: {}, // backend data
    state: {},   // user config

    init() {
        console.log("[Correlation] init");
        this.loadState();
        this.fetchModules();
    },

    // ==========================
    // FETCH MODULES (BACKEND SCHEMA)
    // ==========================
    async fetchModules() {

        try {
            const res = await fetch("/api/modules/correlation");
            this.modules = await res.json();

            this.render();

        } catch (e) {
            console.error("[Correlation] fetch error", e);
        }
    },

    // ==========================
    // LOAD STATE
    // ==========================
    loadState() {
        const raw = localStorage.getItem("cti_correlation");
        this.state = raw ? JSON.parse(raw) : {};
    },

    saveState() {
        localStorage.setItem("cti_correlation", JSON.stringify(this.state));
    },

    // ==========================
    // RENDER DYNAMIC UI
    // ==========================
    render() {

        const container = document.getElementById("correlation-container");
        if (!container || !this.modules) return;

        container.innerHTML = "";

        Object.entries(this.modules).forEach(([key, mod]) => {

            const block = document.createElement("div");
            block.className = "bg-slate-900/50 p-3 rounded-lg border border-slate-800 space-y-3";

            let html = `
                <div class="text-xs font-bold text-amber-400 flex items-center gap-2">
                    <i data-lucide="${mod.icon}" class="w-4 h-4"></i>
                    ${mod.name}
                </div>
            `;

            mod.fields.forEach(field => {

                const value = this.state[key]?.[field.key] ?? field.default;

                html += this.renderField(key, field, value);
            });

            block.innerHTML = html;

            container.appendChild(block);
        });

        lucide.createIcons();
    },

    // ==========================
    // FIELD FACTORY
    // ==========================
    renderField(moduleKey, field, value) {

        const id = `${moduleKey}_${field.key}`;

        if (field.type === "range") {
            return `
                <div>
                    <div class="flex justify-between text-[10px]">
                        <span class="text-slate-400">${field.label}</span>
                        <span class="text-amber-500 font-bold" id="${id}_val">${value}</span>
                    </div>

                    <input type="range"
                        min="${field.min}"
                        max="${field.max}"
                        value="${value}"
                        class="w-full accent-amber-500"
                        oninput="
                            document.getElementById('${id}_val').innerText = this.value;
                            window.CorrelationModule.update('${moduleKey}','${field.key}', this.value)
                        ">
                </div>
            `;
        }

        if (field.type === "checkbox") {
            return `
                <div class="flex items-center gap-2">
                    <input type="checkbox"
                        ${value ? "checked" : ""}
                        onchange="window.CorrelationModule.update('${moduleKey}','${field.key}', this.checked)">
                    <span class="text-[10px] text-slate-300">${field.label}</span>
                </div>
            `;
        }

        return "";
    },

    // ==========================
    // UPDATE STATE
    // ==========================
    update(module, key, value) {

        if (!this.state[module]) {
            this.state[module] = {};
        }

        this.state[module][key] = value;

        this.saveState();
    },

    // ==========================
    // EXECUTE CORRELATION
    // ==========================
    run(tabId, indicator) {

        console.log("[Correlation] run", tabId, indicator);

        // backend call later
        // fetch("/api/correlation/run", {...})
    }
};