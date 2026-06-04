// app/static/js/modules/es_instances.js
// Gestion des instances internes Elasticsearch
// Stockage SecretStore :
//   "es_instances"              → JSON [{id, label}, ...]
//   "es_inst_<id>"              → clé API (ApiKey token, optionnel)
//   "extra_es_inst_<id>_url"    → URL de l'instance
//   "extra_es_inst_<id>_user"   → username Basic Auth (optionnel)
//   "extra_es_inst_<id>_pass"   → password Basic Auth (optionnel)
//   "es_inst_<id>_indexes"      → JSON [{id, name, ioc_type, search_field, output_fields}, ...]

window.EsInstances = {

    IOC_TYPES: ["IP", "Domain", "URL", "Hash-MD5", "Hash-SHA1", "Hash-SHA256"],

    getInstances() {
        return SecretStore.getJSON("es_instances", []);
    },

    saveInstances(list) {
        SecretStore.setJSON("es_instances", list);
    },

    getIndexes(instId) {
        return SecretStore.getJSON(`es_inst_${instId}_indexes`, []);
    },

    saveIndexes(instId, list) {
        SecretStore.setJSON(`es_inst_${instId}_indexes`, list);
    },

    // ── Rendu dans Settings ───────────────────────────────

    render(container) {
        const section = document.createElement("div");
        section.id = "es-instances-section";
        section.innerHTML = `
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-xs uppercase text-slate-500 tracking-wider flex items-center gap-2">
                    <i data-lucide="database" class="w-3.5 h-3.5 text-cyan-400"></i>
                    Internal Elastic Instances
                </h3>
                <button id="es-add-btn"
                        class="flex items-center gap-1.5 text-[11px]
                               bg-cyan-600/20 hover:bg-cyan-600/40
                               text-cyan-300 border border-cyan-700/40
                               px-2.5 py-1 rounded transition-colors">
                    <i data-lucide="plus" class="w-3 h-3"></i> Add instance
                </button>
            </div>
            <div id="es-instances-list" class="space-y-3"></div>
            <p class="text-[10px] text-slate-600 mt-2 leading-relaxed">
                Each instance needs a <strong class="text-slate-500">label</strong> and
                <strong class="text-slate-500">URL</strong>. Results appear in the
                <strong class="text-slate-500">enrichment panel</strong>.
            </p>
        `;
        container.appendChild(section);
        document.getElementById("es-add-btn")?.addEventListener("click", () => this._addInstance());
        this._renderList();
        lucide.createIcons({ nodes: [section] });
    },

    _renderList() {
        const list = document.getElementById("es-instances-list");
        if (!list) return;
        list.innerHTML = "";

        const instances = this.getInstances();
        if (!instances.length) {
            list.innerHTML = `<p class="text-[11px] text-slate-600 italic">No instances — click "Add instance".</p>`;
            return;
        }

        instances.forEach((inst, idx) => {
            const storedUrl  = SecretStore.get(`extra_es_inst_${inst.id}_url`) || "";
            const storedKey  = SecretStore.get(`es_inst_${inst.id}`) || "";
            const storedUser = SecretStore.get(`extra_es_inst_${inst.id}_user`) || "";
            const storedPass = SecretStore.get(`extra_es_inst_${inst.id}_pass`) || "";
            const keySet     = !!storedUrl;

            const row = document.createElement("div");
            row.className   = "bg-slate-900/70 border border-slate-700/60 rounded-lg p-3 space-y-2";
            row.dataset.idx = idx;
            row.innerHTML   = `
                <!-- Header -->
                <div class="flex items-center gap-2">
                    <i data-lucide="database" class="w-3.5 h-3.5 text-cyan-400 shrink-0"></i>
                    <input type="text" class="es-inst-label flex-1 bg-transparent border-b border-slate-700
                                              text-sm font-semibold focus:outline-none focus:border-cyan-500 px-1"
                           placeholder="e.g. SIEM-Prod"
                           value="${this._esc(inst.label)}">
                    <input type="hidden" class="es-inst-id" value="${this._esc(inst.id)}">
                    <span class="text-[9px] px-1.5 py-0.5 rounded shrink-0
                                 ${keySet ? 'bg-green-500/20 text-green-400' : 'bg-amber-500/20 text-amber-400'}">
                        ${keySet ? "URL SET" : "NO URL"}
                    </span>
                    <button class="es-del-btn text-slate-600 hover:text-red-400 transition shrink-0" title="Remove">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    </button>
                </div>
                <!-- URL -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">URL</label>
                    <input type="url" class="es-inst-url flex-1 bg-slate-800 border border-slate-700 rounded
                                            px-2 py-1 text-[11px] font-mono
                                            focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="https://elasticsearch.corp:9200"
                           value="${this._esc(storedUrl)}">
                </div>
                <!-- ApiKey -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">ApiKey</label>
                    <input type="password" class="es-inst-key flex-1 bg-slate-800 border border-slate-700 rounded
                                                  px-2 py-1 text-[11px] font-mono
                                                  focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="ApiKey token (optional)"
                           value="${this._esc(storedKey)}">
                </div>
                <!-- Basic Auth -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">User</label>
                    <input type="text" class="es-inst-user flex-1 bg-slate-800 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="elastic (optional)"
                           value="${this._esc(storedUser)}">
                </div>
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">Pass</label>
                    <input type="password" class="es-inst-pass flex-1 bg-slate-800 border border-slate-700 rounded
                                                  px-2 py-1 text-[11px] font-mono
                                                  focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="password (optional)"
                           value="${this._esc(storedPass)}">
                </div>
                <!-- Indexes sub-section -->
                <div class="pl-5 pt-1 border-t border-slate-700/50 space-y-2">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] text-slate-500 uppercase tracking-wider">Indexes</span>
                        <button class="es-idx-add-btn flex items-center gap-1 text-[10px]
                                       text-cyan-400 hover:text-cyan-300 transition">
                            <i data-lucide="plus" class="w-3 h-3"></i> Add index
                        </button>
                    </div>
                    <div class="es-idx-list space-y-2"></div>
                </div>
            `;

            // Delete instance
            row.querySelector(".es-del-btn").addEventListener("click", () => {
                const id = row.querySelector(".es-inst-id").value;
                SecretStore.remove(`es_inst_${id}`);
                SecretStore.remove(`extra_es_inst_${id}_url`);
                SecretStore.remove(`extra_es_inst_${id}_user`);
                SecretStore.remove(`extra_es_inst_${id}_pass`);
                SecretStore.remove(`es_inst_${id}_indexes`);
                const updated = this.getInstances().filter(i => i.id !== id);
                this.saveInstances(updated);
                this._renderList();
                Modules?._load?.();
            });

            // Add index
            row.querySelector(".es-idx-add-btn").addEventListener("click", () => {
                const id      = row.querySelector(".es-inst-id").value;
                const idxs    = this.getIndexes(id);
                idxs.push({ id: `idx${Date.now()}`, name: "", ioc_type: "", search_field: "", output_fields: "" });
                this.saveIndexes(id, idxs);
                this._renderIndexes(row, id);
            });

            this._renderIndexes(row, inst.id);
            list.appendChild(row);
        });

        lucide.createIcons({ nodes: [list] });
    },

    _renderIndexes(rowEl, instId) {
        const container = rowEl.querySelector(".es-idx-list");
        if (!container) return;
        container.innerHTML = "";
        const indexes = this.getIndexes(instId);
        const typeOpts = this.IOC_TYPES.map(t => `<option value="${t}">${t}</option>`).join("");

        indexes.forEach((idx, i) => {
            const idxRow = document.createElement("div");
            idxRow.className   = "bg-slate-800/60 border border-slate-700/40 rounded p-2 space-y-1.5";
            idxRow.dataset.idx = i;
            idxRow.innerHTML   = `
                <div class="flex items-center gap-2">
                    <i data-lucide="layers" class="w-3 h-3 text-cyan-500 shrink-0"></i>
                    <input type="hidden" class="es-idx-id" value="${this._esc(idx.id)}">
                    <input type="text" class="es-idx-name flex-1 bg-transparent border-b border-slate-700
                                              text-[11px] font-mono focus:outline-none focus:border-cyan-500 px-1"
                           placeholder="Index name (e.g. logs-*)"
                           value="${this._esc(idx.name)}">
                    <button class="es-idx-del-btn text-slate-600 hover:text-red-400 transition shrink-0">
                        <i data-lucide="trash-2" class="w-3 h-3"></i>
                    </button>
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">IOC Type</label>
                    <select class="es-idx-ioc-type flex-1 bg-slate-800 border border-slate-700 rounded
                                   px-2 py-1 text-[11px] focus:outline-none focus:ring-1 focus:ring-cyan-500">
                        <option value="">— any —</option>
                        ${typeOpts}
                    </select>
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">Search field</label>
                    <input type="text" class="es-idx-search-field flex-1 bg-slate-800/60 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="e.g. source.ip, dns.question.name"
                           value="${this._esc(idx.search_field || '')}">
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">Output fields</label>
                    <input type="text" class="es-idx-output-fields flex-1 bg-slate-800 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-cyan-500"
                           placeholder="host.name, user.name, event.action"
                           value="${this._esc(idx.output_fields || '')}">
                </div>
            `;

            // Set select value
            idxRow.querySelector(".es-idx-ioc-type").value = idx.ioc_type || "";

            // Delete index
            idxRow.querySelector(".es-idx-del-btn").addEventListener("click", () => {
                const updated = this.getIndexes(instId).filter((_, ii) => ii !== i);
                this.saveIndexes(instId, updated);
                this._renderIndexes(rowEl, instId);
            });

            container.appendChild(idxRow);
        });
        lucide.createIcons({ nodes: [container] });
    },

    _addInstance() {
        const id      = `esi${Date.now()}`;
        const updated = [...this.getInstances(), { id, label: "" }];
        this.saveInstances(updated);
        this._renderList();
        const labels = document.querySelectorAll("#es-instances-list .es-inst-label");
        labels[labels.length - 1]?.focus();
    },

    collect() {
        const rows = document.querySelectorAll("#es-instances-list [data-idx]");
        const updatedInstances = [];

        rows.forEach(row => {
            const id    = row.querySelector(".es-inst-id")?.value.trim();
            const label = row.querySelector(".es-inst-label")?.value.trim();
            if (!id || !label) return;

            const url  = row.querySelector(".es-inst-url")?.value.trim();
            const key  = row.querySelector(".es-inst-key")?.value.trim();
            const user = row.querySelector(".es-inst-user")?.value.trim();
            const pass = row.querySelector(".es-inst-pass")?.value.trim();

            if (url)  SecretStore.set(`extra_es_inst_${id}_url`,  url);
            if (key)  SecretStore.set(`es_inst_${id}`,            key);
            if (user) SecretStore.set(`extra_es_inst_${id}_user`, user);
            if (pass) SecretStore.set(`extra_es_inst_${id}_pass`, pass);

            // Collecter les index
            const idxRows = row.querySelectorAll(".es-idx-list [data-idx]");
            const indexes = [];
            idxRows.forEach(ir => {
                const idxId       = ir.querySelector(".es-idx-id")?.value.trim();
                const name        = ir.querySelector(".es-idx-name")?.value.trim();
                const ioc_type    = ir.querySelector(".es-idx-ioc-type")?.value;
                const search_field  = ir.querySelector(".es-idx-search-field")?.value.trim() || "";
                const output_fields = ir.querySelector(".es-idx-output-fields")?.value.trim() || "";
                if (!name) return;
                indexes.push({ id: idxId || `idx${Date.now()}`, name, ioc_type, search_field, output_fields });
            });
            this.saveIndexes(id, indexes);

            updatedInstances.push({ id, label });
        });

        this.saveInstances(updatedInstances);
    },

    _esc(str) {
        return String(str ?? "")
            .replace(/&/g, "&amp;").replace(/"/g, "&quot;")
            .replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },
};
