window.SIEMModule = {

    modules: {},
    state: {},

    init() {
        console.log("[SIEM] init");

        this.loadState();
        this.fetchModules();
    },

    // ==========================
    // FETCH BACKEND SCHEMA
    // ==========================
    async fetchModules() {

        try {
            const res = await fetch("/api/modules/siem");
            this.modules = await res.json();

            this.render();

        } catch (e) {
            console.error("[SIEM] fetch error", e);
        }
    },

    // ==========================
    // STATE
    // ==========================
    loadState() {
        const raw = localStorage.getItem("cti_siem");
        this.state = raw ? JSON.parse(raw) : {};
    },

    saveState() {
        localStorage.setItem("cti_siem", JSON.stringify(this.state));
    },

    // ==========================
    // RENDER
    // ==========================
    render() {

        const container = document.getElementById("siem-container");
        if (!container || !this.modules) return;

        container.innerHTML = "";

        Object.entries(this.modules).forEach(([key, mod]) => {

            const block = document.createElement("div");
            block.className = "bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-3";

            let html = `
                <div class="text-xs font-bold text-blue-400 flex items-center gap-2">
                    <i data-lucide="${mod.icon}" class="w-4 h-4"></i>
                    ${mod.name}
                </div>
            `;

            mod.fields.forEach(field => {
                const value = this.state[field.key] ?? field.default;
                html += this.renderField(field, value);
            });

            html += `
                <button
                    class="w-full bg-slate-800 hover:bg-blue-600 py-2 rounded text-[11px] font-bold transition"
                    onclick="window.SIEMModule.run()">
                    Run SIEM Investigation
                </button>
            `;

            block.innerHTML = html;

            container.appendChild(block);
        });

        lucide.createIcons();
    },

    // ==========================
    // FIELD FACTORY
    // ==========================
    renderField(field, value) {

        const key = field.key;

        // RADIO
        if (field.type === "radio") {

            return `
                <div class="flex p-1 bg-slate-900 rounded-md border border-slate-800">
                    ${field.options.map(opt => `
                        <label class="flex-1 text-center py-1.5 text-[10px] font-bold rounded cursor-pointer has-[:checked]:bg-blue-600 transition">
                            <input type="radio"
                                   name="${key}"
                                   value="${opt}"
                                   ${value === opt ? "checked" : ""}
                                   onchange="window.SIEMModule.update('${key}', this.value)"
                                   class="hidden">
                            ${opt.toUpperCase()}
                        </label>
                    `).join("")}
                </div>
            `;
        }

        // DATETIME
        if (field.type === "datetime") {

            return `
                <div class="space-y-1">
                    <p class="text-[9px] text-slate-500 uppercase">${field.label}</p>
                    <input type="datetime-local"
                        value="${value || ""}"
                        onchange="window.SIEMModule.update('${key}', this.value)"
                        class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs">
                </div>
            `;
        }

        // SELECT
        if (field.type === "select") {

            return `
                <div class="space-y-1">
                    <p class="text-[9px] text-slate-500 uppercase">${field.label}</p>
                    <select
                        onchange="window.SIEMModule.update('${key}', this.value)"
                        class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-xs">

                        ${field.options.map(opt => `
                            <option value="${opt}" ${value === opt ? "selected" : ""}>
                                ${opt}
                            </option>
                        `).join("")}

                    </select>
                </div>
            `;
        }

        return "";
    },

    // ==========================
    // UPDATE STATE
    // ==========================
    update(key, value) {

        this.state[key] = value;
        this.saveState();
    },

    // ==========================
    // RUN SIEM QUERY
    // ==========================
    run() {

        console.log("[SIEM] run", this.state);

        fetch("/api/siem/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.state)
        });
    }
};