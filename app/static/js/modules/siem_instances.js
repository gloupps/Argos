// app/static/js/modules/siem_instances.js
// Gestion des Index/LogSources SIEM (QRadar & Splunk)
// Stockage SecretStore :
//   "siem_logsources_qradar" → JSON [{id, name, ioc_type, output_fields}, ...]
//   "siem_logsources_splunk" → JSON [{id, name, ioc_type, output_fields}, ...]

window.SIEMInstances = {

    IOC_TYPES: ["IP", "Domain", "URL", "Hash-MD5", "Hash-SHA1", "Hash-SHA256"],

    getSources(siemType) {
        return SecretStore.getJSON(`siem_logsources_${siemType}`, []);
    },

    saveSources(siemType, list) {
        SecretStore.setJSON(`siem_logsources_${siemType}`, list);
    },

    render(container, siemType) {
        const section = document.createElement("div");
        section.id        = `siem-sources-section-${siemType}`;
        section.innerHTML = `
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-xs uppercase text-slate-500 tracking-wider flex items-center gap-2">
                    <i data-lucide="layers" class="w-3.5 h-3.5 text-teal-400"></i>
                    ${siemType === "qradar" ? "LogSources" : "Indexes"}
                </h3>
                <button id="siem-add-btn-${siemType}"
                        class="flex items-center gap-1.5 text-[11px]
                               bg-teal-600/20 hover:bg-teal-600/40
                               text-teal-300 border border-teal-700/40
                               px-2.5 py-1 rounded transition-colors">
                    <i data-lucide="plus" class="w-3 h-3"></i> Add
                </button>
            </div>
            <div id="siem-sources-list-${siemType}" class="space-y-2"></div>
            <p class="text-[10px] text-slate-600 mt-2 leading-relaxed">
                Each entry defines a <strong class="text-slate-500">source name</strong>,
                the <strong class="text-slate-500">IOC type</strong> it covers, and
                the <strong class="text-slate-500">output fields</strong> to display.
            </p>
        `;
        container.appendChild(section);

        document.getElementById(`siem-add-btn-${siemType}`)
            ?.addEventListener("click", () => this._addRow(siemType));

        this._renderList(siemType);
        lucide.createIcons({ nodes: [section] });
    },

    _renderList(siemType) {
        const list = document.getElementById(`siem-sources-list-${siemType}`);
        if (!list) return;
        list.innerHTML = "";

        const sources = this.getSources(siemType);

        if (!sources.length) {
            list.innerHTML = `<p class="text-[11px] text-slate-600 italic">No sources configured.</p>`;
            return;
        }

        const typeOptions = this.IOC_TYPES.map(t =>
            `<option value="${t}">${t}</option>`
        ).join("");

        sources.forEach((src, idx) => {
            const row = document.createElement("div");
            row.className   = "bg-slate-900/70 border border-slate-700/60 rounded-lg p-3 space-y-2";
            row.dataset.idx = idx;
            row.innerHTML   = `
                <!-- Header: name + delete -->
                <div class="flex items-center gap-2">
                    <i data-lucide="layers" class="w-3.5 h-3.5 text-teal-400 shrink-0"></i>
                    <input type="hidden" class="siem-src-id" value="${this._esc(src.id)}">
                    <input type="text"
                           class="siem-src-name flex-1 bg-transparent border-b border-slate-700
                                  text-sm font-semibold focus:outline-none focus:border-teal-500 px-1"
                           placeholder="${siemType === 'qradar' ? 'LogSource name (e.g. Windows_Events)' : 'Index name (e.g. main)'}"
                           value="${this._esc(src.name)}">
                    <button class="siem-del-btn text-slate-600 hover:text-red-400 transition shrink-0" title="Remove">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    </button>
                </div>
                <!-- IOC type -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">IOC Type</label>
                    <select class="siem-src-ioc-type flex-1 bg-slate-800 border border-slate-700 rounded
                                   px-2 py-1 text-[11px] focus:outline-none focus:ring-1 focus:ring-teal-500">
                        <option value="">— any —</option>
                        ${typeOptions}
                    </select>
                </div>
                <!-- Output fields -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">Output fields</label>
                    <input type="text"
                           class="siem-src-fields flex-1 bg-slate-800 border border-slate-700 rounded
                                  px-2 py-1 text-[11px] font-mono
                                  focus:outline-none focus:ring-1 focus:ring-teal-500"
                           placeholder="sourceIP, destinationIP, EventName"
                           value="${this._esc(src.output_fields || '')}">
                </div>
            `;

            // Set IOC type select value
            const sel = row.querySelector(".siem-src-ioc-type");
            sel.value = src.ioc_type || "";

            // Delete
            row.querySelector(".siem-del-btn").addEventListener("click", () => {
                const updated = this.getSources(siemType).filter((_, i) => i !== idx);
                this.saveSources(siemType, updated);
                this._renderList(siemType);
            });

            list.appendChild(row);
        });

        lucide.createIcons({ nodes: [list] });
    },

    _addRow(siemType) {
        const id      = `src${Date.now()}`;
        const updated = [...this.getSources(siemType), { id, name: "", ioc_type: "", output_fields: "" }];
        this.saveSources(siemType, updated);
        this._renderList(siemType);
        const names = document.querySelectorAll(`#siem-sources-list-${siemType} .siem-src-name`);
        names[names.length - 1]?.focus();
    },

    collect(siemType) {
        const rows    = document.querySelectorAll(`#siem-sources-list-${siemType} [data-idx]`);
        const updated = [];
        rows.forEach(row => {
            const id           = row.querySelector(".siem-src-id")?.value.trim();
            const name         = row.querySelector(".siem-src-name")?.value.trim();
            const ioc_type     = row.querySelector(".siem-src-ioc-type")?.value;
            const output_fields = row.querySelector(".siem-src-fields")?.value.trim();
            if (!name) return;
            updated.push({ id: id || `src${Date.now()}`, name, ioc_type, output_fields });
        });
        this.saveSources(siemType, updated);
    },

    _esc(str) {
        return String(str ?? "")
            .replace(/&/g, "&amp;").replace(/"/g, "&quot;")
            .replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },
};