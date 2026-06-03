// ──────────────────────────────────────────────────────────────────────────────
// app/static/js/modules/misp_instances.js  (v2 — SecretStore only)
//
// Tout est stocké dans localStorage via SecretStore :
//   SecretStore("misp_instances")          → JSON [{id, label}, ...]
//   SecretStore("misp_ext_<id>")           → clé API de l'instance
//   SecretStore("extra_misp_ext_<id>_url") → URL de l'instance
//
// Aucun appel backend, aucun fichier JSON serveur.
// ──────────────────────────────────────────────────────────────────────────────

window.MISPInstances = {

    // ── Lecture / écriture ────────────────────────────────

    getInstances() {
        return SecretStore.getJSON("misp_instances", []);
    },

    saveInstances(list) {
        SecretStore.setJSON("misp_instances", list);
    },

    // ── Rendu du bloc dans les Settings ───────────────────

    /**
     * Injecte le bloc "External MISP Instances" dans le container fourni.
     * @param {HTMLElement} container
     */
    render(container) {
        const section = document.createElement("div");
        section.id        = "misp-instances-section";
        section.innerHTML = `
            <div class="flex items-center justify-between mb-3">
                <h3 class="text-xs uppercase text-slate-500 tracking-wider flex items-center gap-2">
                    <i data-lucide="share-2" class="w-3.5 h-3.5 text-orange-400"></i>
                    External MISP Instances
                </h3>
                <button id="misp-add-btn"
                        class="flex items-center gap-1.5 text-[11px]
                               bg-orange-600/20 hover:bg-orange-600/40
                               text-orange-300 border border-orange-700/40
                               px-2.5 py-1 rounded transition-colors">
                    <i data-lucide="plus" class="w-3 h-3"></i> Add instance
                </button>
            </div>
            <div id="misp-instances-list" class="space-y-2"></div>
            <p class="text-[10px] text-slate-600 mt-2 leading-relaxed">
                Each instance needs a <strong class="text-slate-500">label</strong>,
                an <strong class="text-slate-500">URL</strong> and an
                <strong class="text-slate-500">API key</strong> — all stored locally.
            </p>
        `;
        container.appendChild(section);

        document.getElementById("misp-add-btn")
            ?.addEventListener("click", () => this._addRow());

        this._renderList();
        lucide.createIcons({ nodes: [section] });
    },

    _renderList() {
        const list = document.getElementById("misp-instances-list");
        if (!list) return;
        list.innerHTML = "";

        const instances = this.getInstances();

        if (!instances.length) {
            list.innerHTML = `
                <p class="text-[11px] text-slate-600 italic">
                    No external MISP instances — click "Add instance" to add one.
                </p>`;
            return;
        }

        instances.forEach((inst, idx) => {
            const storedUrl = SecretStore.get(`extra_misp_ext_${inst.id}_url`) || "";
            const storedKey = SecretStore.get(`misp_ext_${inst.id}`) || "";
            const keySet    = !!storedKey;

            const row = document.createElement("div");
            row.className   = "bg-slate-900/70 border border-slate-700/60 rounded-lg p-3 space-y-2";
            row.dataset.idx = idx;
            row.innerHTML   = `
                <!-- Header row : icône + label + badge + delete -->
                <div class="flex items-center gap-2">
                    <i data-lucide="share-2" class="w-3.5 h-3.5 text-orange-400 shrink-0"></i>
                    <input type="text"
                           class="misp-inst-label flex-1 bg-transparent border-b border-slate-700
                                  text-sm font-semibold focus:outline-none focus:border-orange-500 px-1"
                           placeholder="Instance label  (e.g. Partner MISP)"
                           value="${this._esc(inst.label)}">
                    <input type="hidden" class="misp-inst-id" value="${this._esc(inst.id)}">
                    <span class="text-[9px] px-1.5 py-0.5 rounded shrink-0
                                 ${keySet
                                     ? 'bg-green-500/20 text-green-400'
                                     : 'bg-red-500/20 text-red-400'}">
                        ${keySet ? "KEY SET" : "NO KEY"}
                    </span>
                    <button class="misp-del-btn text-slate-600 hover:text-red-400 transition shrink-0"
                            title="Remove this instance">
                        <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                    </button>
                </div>

                <!-- URL -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">URL</label>
                    <input type="url"
                           class="misp-inst-url flex-1 bg-slate-800 border border-slate-700 rounded
                                  px-2 py-1 text-[11px] font-mono
                                  focus:outline-none focus:ring-1 focus:ring-orange-500"
                           placeholder="https://misp.partner.com"
                           value="${this._esc(storedUrl)}">
                </div>

                <!-- API Key -->
                <div class="flex items-center gap-2 pl-5">
                    <label class="text-[10px] text-slate-500 w-8 shrink-0">Key</label>
                    <div class="relative flex-1">
                        <input type="password"
                               class="misp-inst-key w-full bg-slate-800 border border-slate-700 rounded
                                      px-2 py-1 pr-7 text-[11px] font-mono
                                      focus:outline-none focus:ring-1 focus:ring-orange-500"
                               placeholder="MISP authkey…"
                               value="${this._esc(storedKey)}">
                        <button type="button"
                                class="misp-eye-btn absolute right-1.5 top-1/2 -translate-y-1/2
                                       text-slate-500 hover:text-slate-300 transition"
                                title="Show / hide">
                            <i data-lucide="eye" class="w-3 h-3"></i>
                        </button>
                    </div>
                </div>
            `;

            // Delete
            row.querySelector(".misp-del-btn").addEventListener("click", () => {
                // Nettoyer SecretStore
                const id = row.querySelector(".misp-inst-id").value;
                SecretStore.remove(`misp_ext_${id}`);
                SecretStore.remove(`extra_misp_ext_${id}_url`);
                // Retirer de la liste persistée
                const updated = this.getInstances().filter(i => i.id !== id);
                this.saveInstances(updated);
                this._renderList();
                // Informer Modules de recharger son registry
                Modules?._load?.();
            });

            // Eye toggle
            row.querySelector(".misp-eye-btn").addEventListener("click", () => {
                const inp = row.querySelector(".misp-inst-key");
                const ico = row.querySelector(".misp-eye-btn i");
                const hidden = inp.type === "password";
                inp.type = hidden ? "text" : "password";
                ico.setAttribute("data-lucide", hidden ? "eye-off" : "eye");
                lucide.createIcons({ nodes: [ico.parentElement] });
            });

            list.appendChild(row);
        });

        lucide.createIcons({ nodes: [list] });
    },

    _addRow() {
        const id       = `ext${Date.now()}`;
        const updated  = [...this.getInstances(), { id, label: "" }];
        this.saveInstances(updated);
        this._renderList();
        // Focus sur le label de la nouvelle ligne
        const labels = document.querySelectorAll("#misp-instances-list .misp-inst-label");
        labels[labels.length - 1]?.focus();
    },

    // ── Appelé par Settings.save() ────────────────────────
    /**
     * Collecte les valeurs du DOM et les persiste dans SecretStore.
     * Met aussi à jour la liste des instances (labels).
     */
    collect() {
        const rows     = document.querySelectorAll("#misp-instances-list [data-idx]");
        const updated  = [];

        rows.forEach(row => {
            const id    = row.querySelector(".misp-inst-id")?.value.trim();
            const label = row.querySelector(".misp-inst-label")?.value.trim();
            const url   = row.querySelector(".misp-inst-url")?.value.trim();
            const key   = row.querySelector(".misp-inst-key")?.value.trim();

            if (!id || !label) return;

            updated.push({ id, label });

            if (url) SecretStore.set(`extra_misp_ext_${id}_url`, url);
            if (key) SecretStore.set(`misp_ext_${id}`, key);
        });

        this.saveInstances(updated);
        // Recharger le registry Modules (nouvelles instances = nouveaux modules)
        Modules?._load?.();
    },

    // ── Helpers ───────────────────────────────────────────
    _esc(str) {
        return String(str ?? "")
            .replace(/&/g, "&amp;").replace(/"/g, "&quot;")
            .replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },
};
