// app/static/js/modules/kibana_instances.js
// Gestion des instances internes Kibana (recherche ES via /api/console/proxy)
// Stockage SecretStore :
//   "kibana_instances"              → JSON [{id, label}, ...]
//   "kibana_inst_<id>"              → clé API Kibana (ApiKey, optionnel)
//   "extra_kibana_inst_<id>_url"    → URL Kibana de l'instance
//   "extra_kibana_inst_<id>_user"   → username Basic Auth (optionnel)
//   "extra_kibana_inst_<id>_pass"   → password Basic Auth (optionnel)
//   "kibana_inst_<id>_indexes"      → JSON [{id, name, ioc_type, search_field, output_fields}, ...]

window.KibanaInstances = {

    IOC_TYPES: ["IP", "Domain", "URL", "Hash-MD5", "Hash-SHA1", "Hash-SHA256"],

    getInstances() {
        return SecretStore.getJSON("kibana_instances", []);
    },

    saveInstances(list) {
        SecretStore.setJSON("kibana_instances", list);
    },

    getIndexes(instId) {
        return SecretStore.getJSON(`kibana_inst_${instId}_indexes`, []);
    },

    saveIndexes(instId, list) {
        SecretStore.setJSON(`kibana_inst_${instId}_indexes`, list);
    },

    // ── Rendu dans Settings ───────────────────────────────

    render(container) {
        const section = document.createElement("div");
        section.id = "kibana-instances-section";
        section.innerHTML = `
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-xs uppercase text-slate-500 tracking-wider flex items-center gap-2">
                    <i data-lucide="compass" class="w-3.5 h-3.5 text-violet-400"></i>
                    Internal Kibana Instances
                </h3>
                <button id="kibana-add-btn"
                        class="flex items-center gap-1.5 text-[11px]
                               bg-violet-600/20 hover:bg-violet-600/40
                               text-violet-300 border border-violet-700/40
                               px-2.5 py-1 rounded transition-colors">
                    <i data-lucide="plus" class="w-3 h-3"></i> Add instance
                </button>
            </div>
            <div id="kibana-instances-list" class="space-y-3"></div>
            <p class="text-[10px] text-slate-600 mt-2 leading-relaxed">
                Each instance needs a <strong class="text-slate-500">label</strong> and
                <strong class="text-slate-500">URL</strong>. Results appear in the
                <strong class="text-slate-500">enrichment panel</strong>.
            </p>
        `;
        container.appendChild(section);
        document.getElementById("kibana-add-btn")?.addEventListener("click", () => this._addInstance());
        this._renderList();
        lucide.createIcons({ nodes: [section] });
    },

    _renderList() {
        const list = document.getElementById("kibana-instances-list");
        if (!list) return;
        list.innerHTML = "";

        const instances = this.getInstances();
        if (!instances.length) {
            list.innerHTML = `<p class="text-[11px] text-slate-600 italic">No instances — click "Add instance".</p>`;
            return;
        }

        instances.forEach((inst, idx) => {
            const storedUrl  = SecretStore.get(`extra_kibana_inst_${inst.id}_url`) || "";
            const storedKey  = SecretStore.get(`kibana_inst_${inst.id}`) || "";
            const storedUser = SecretStore.get(`extra_kibana_inst_${inst.id}_user`) || "";
            const storedPass = SecretStore.get(`extra_kibana_inst_${inst.id}_pass`) || "";
            const keySet     = !!storedUrl;

            const row = document.createElement("div");
            row.className   = "bg-slate-900/70 border border-slate-700/60 rounded-lg p-3 space-y-2";
            row.dataset.idx = idx;
            row.innerHTML   = `
                <!-- Header -->
                <div class="flex items-center gap-2">
                    <i data-lucide="compass" class="w-3.5 h-3.5 text-violet-400 shrink-0"></i>
                    <input type="text" class="kibana-inst-label flex-1 bg-transparent border-b border-slate-700
                                              text-sm font-semibold focus:outline-none focus:border-violet-500 px-1"
                           placeholder="e.g. SIEM-Prod"
                           value="${this._esc(inst.label)}">
                    <input type="hidden" class="kibana-inst-id" value="${this._esc(inst.id)}">
                    <span class="text-[9px] px-1.5 py-0.5 rounded shrink-0
                                 ${keySet ? 'bg-green-500/20 text-green-400' : 'bg-amber-500/20 text-amber-400'}">
                        ${keySet ? "URL SET" : "NO URL"}
                    </span>
                    <button class="kibana-del-btn text-slate-600 hover:text-red-400 transition shrink-0" title="Remove">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    </button>
                </div>
                <!-- URL -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">URL</label>
                    <input type="url" class="kibana-inst-url flex-1 bg-slate-800 border border-slate-700 rounded
                                            px-2 py-1 text-[11px] font-mono
                                            focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="https://kibana.corp:5601"
                           value="${this._esc(storedUrl)}">
                </div>
                <!-- ApiKey -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">ApiKey</label>
                    <input type="password" class="kibana-inst-key flex-1 bg-slate-800 border border-slate-700 rounded
                                                  px-2 py-1 text-[11px] font-mono
                                                  focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="ApiKey (Kibana) — optional if using user/pass"
                           value="${this._esc(storedKey)}">
                </div>
                <!-- Basic Auth -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">User</label>
                    <input type="text" class="kibana-inst-user flex-1 bg-slate-800 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="elastic (optional)"
                           value="${this._esc(storedUser)}">
                </div>
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">Pass</label>
                    <input type="password" class="kibana-inst-pass flex-1 bg-slate-800 border border-slate-700 rounded
                                                  px-2 py-1 text-[11px] font-mono
                                                  focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="password (optional)"
                           value="${this._esc(storedPass)}">
                </div>
                <!-- Indexes sub-section -->
                <div class="pl-5 pt-1 border-t border-slate-700/50 space-y-2">
                    <div class="flex items-center justify-between">
                        <span class="text-[10px] text-slate-500 uppercase tracking-wider">Indexes</span>
                        <button class="kibana-idx-add-btn flex items-center gap-1 text-[10px]
                                       text-violet-400 hover:text-violet-300 transition">
                            <i data-lucide="plus" class="w-3 h-3"></i> Add index
                        </button>
                    </div>
                    <div class="kibana-idx-list space-y-2"></div>
                </div>
            `;

            // Delete instance
            row.querySelector(".kibana-del-btn").addEventListener("click", () => {
                const id = row.querySelector(".kibana-inst-id").value;
                SecretStore.remove(`kibana_inst_${id}`);
                SecretStore.remove(`extra_kibana_inst_${id}_url`);
                SecretStore.remove(`extra_kibana_inst_${id}_user`);
                SecretStore.remove(`extra_kibana_inst_${id}_pass`);
                SecretStore.remove(`kibana_inst_${id}_indexes`);
                const updated = this.getInstances().filter(i => i.id !== id);
                this.saveInstances(updated);
                this._renderList();
                Modules?._load?.();
            });

            // Add index
            row.querySelector(".kibana-idx-add-btn").addEventListener("click", () => {
                const id      = row.querySelector(".kibana-inst-id").value;
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
        const container = rowEl.querySelector(".kibana-idx-list");
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
                    <i data-lucide="layers" class="w-3 h-3 text-violet-500 shrink-0"></i>
                    <input type="hidden" class="kibana-idx-id" value="${this._esc(idx.id)}">
                    <input type="text" class="kibana-idx-name flex-1 bg-transparent border-b border-slate-700
                                              text-[11px] font-mono focus:outline-none focus:border-violet-500 px-1"
                           placeholder="Index pattern (logs-*) or Data View ID/name"
                           value="${this._esc(idx.name)}">
                    <button class="kibana-idx-del-btn text-slate-600 hover:text-red-400 transition shrink-0">
                        <i data-lucide="trash-2" class="w-3 h-3"></i>
                    </button>
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">IOC Type</label>
                    <select class="kibana-idx-ioc-type flex-1 bg-slate-800 border border-slate-700 rounded
                                   px-2 py-1 text-[11px] focus:outline-none focus:ring-1 focus:ring-violet-500">
                        <option value="">— any —</option>
                        ${typeOpts}
                    </select>
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">Search field</label>
                    <input type="text" class="kibana-idx-search-field flex-1 bg-slate-800/60 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="e.g. source.ip, dns.question.name"
                           value="${this._esc(idx.search_field || '')}">
                </div>
                <div class="flex items-center gap-2 pl-4">
                    <label class="text-[10px] text-slate-500 w-16 shrink-0">Output fields</label>
                    <input type="text" class="kibana-idx-output-fields flex-1 bg-slate-800 border border-slate-700 rounded
                                              px-2 py-1 text-[11px] font-mono
                                              focus:outline-none focus:ring-1 focus:ring-violet-500"
                           placeholder="host.name, user.name, event.action"
                           value="${this._esc(idx.output_fields || '')}">
                </div>
            `;

            // Set select value
            idxRow.querySelector(".kibana-idx-ioc-type").value = idx.ioc_type || "";

            // Delete index
            idxRow.querySelector(".kibana-idx-del-btn").addEventListener("click", () => {
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
        const labels = document.querySelectorAll("#kibana-instances-list .kibana-inst-label");
        labels[labels.length - 1]?.focus();
    },

    collect() {
        const rows = document.querySelectorAll("#kibana-instances-list [data-idx]");
        const updatedInstances = [];

        rows.forEach(row => {
            const id    = row.querySelector(".kibana-inst-id")?.value.trim();
            const label = row.querySelector(".kibana-inst-label")?.value.trim();
            if (!id || !label) return;

            const url  = row.querySelector(".kibana-inst-url")?.value.trim();
            const key  = row.querySelector(".kibana-inst-key")?.value.trim();
            const user = row.querySelector(".kibana-inst-user")?.value.trim();
            const pass = row.querySelector(".kibana-inst-pass")?.value.trim();

            if (url)  SecretStore.set(`extra_kibana_inst_${id}_url`,  url);
            if (key)  SecretStore.set(`kibana_inst_${id}`,            key);
            if (user) SecretStore.set(`extra_kibana_inst_${id}_user`, user);
            if (pass) SecretStore.set(`extra_kibana_inst_${id}_pass`, pass);

            // Collecter les index
            const idxRows = row.querySelectorAll(".kibana-idx-list [data-idx]");
            const indexes = [];
            idxRows.forEach(ir => {
                const idxId       = ir.querySelector(".kibana-idx-id")?.value.trim();
                const name        = ir.querySelector(".kibana-idx-name")?.value.trim();
                const ioc_type    = ir.querySelector(".kibana-idx-ioc-type")?.value;
                const search_field  = ir.querySelector(".kibana-idx-search-field")?.value.trim() || "";
                const output_fields = ir.querySelector(".kibana-idx-output-fields")?.value.trim() || "";
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
