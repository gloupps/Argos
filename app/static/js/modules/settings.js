window.Settings = {

    init() {
        console.log("[Settings] init");
        this._bind();
    },

    open() {
        const modalBody = document.querySelector("#settings-modal > div");
        if (!modalBody) {
            document.getElementById("settings-modal")?.classList.remove("hidden");
            return;
        }

        // ── Reconstruire le body proprement ─────────────────────────
        const header  = modalBody.querySelector(".flex.items-center.justify-between");
        const divider = modalBody.querySelector(".argos-divider");
        modalBody.innerHTML = "";
        if (header)  modalBody.appendChild(header);
        if (divider) modalBody.appendChild(divider);

        // ── Grid 3 colonnes ──────────────────────────────────────────
        const grid = document.createElement("div");
        grid.className = "grid grid-cols-4 gap-4 items-start";

        // Colonne 1 : Internal
        const colInternal = document.createElement("div");
        colInternal.innerHTML = `
            <p class="text-[11px] text-slate-500 uppercase tracking-wider mb-3 font-semibold flex items-center gap-1.5">
                <i data-lucide="server" class="w-3.5 h-3.5 text-teal-400"></i> Internal
            </p>`;
        const keysInternal = document.createElement("div");
        keysInternal.id = "settings-keys-internal";
        keysInternal.className = "space-y-2";
        colInternal.appendChild(keysInternal);

        // Colonne 2 : External
        const colExternal = document.createElement("div");
        colExternal.innerHTML = `
            <p class="text-[11px] text-slate-500 uppercase tracking-wider mb-3 font-semibold flex items-center gap-1.5">
                <i data-lucide="globe" class="w-3.5 h-3.5 text-blue-400"></i> External
            </p>`;
        const keysExternal = document.createElement("div");
        keysExternal.id = "settings-keys-external";
        keysExternal.className = "space-y-2";
        colExternal.appendChild(keysExternal);

        // Colonne 3 : External MISP Instances
        const colMisp = document.createElement("div");
        
        // Colonne 4 : SIEM  (dans open(), à la place de colSiem actuel)
        const colSiem = document.createElement("div");
        colSiem.innerHTML = `
            <p class="text-[11px] text-slate-500 uppercase tracking-wider mb-3 font-semibold flex items-center gap-1.5">
                <i data-lucide="database" class="w-3.5 h-3.5 text-teal-400"></i> SIEM
            </p>`;
        const keysSiem = document.createElement("div");
        keysSiem.id = "settings-keys-siem";
        keysSiem.className = "space-y-2";
        colSiem.appendChild(keysSiem);

        // Sous-section QRadar LogSources
        const siemSourcesQradar = document.createElement("div");
        siemSourcesQradar.className = "mt-4";
        colSiem.appendChild(siemSourcesQradar);

        // Sous-section Splunk Indexes
        const siemSourcesSplunk = document.createElement("div");
        siemSourcesSplunk.className = "mt-4";
        colSiem.appendChild(siemSourcesSplunk);

        grid.appendChild(colInternal);
        grid.appendChild(colExternal);
        grid.appendChild(colSiem);
        grid.appendChild(colMisp);
        modalBody.appendChild(grid);

        // ── Save bar ─────────────────────────────────────────────────
        const saveBar = document.createElement("div");
        saveBar.className = "flex justify-end pt-3";
        saveBar.style.borderTop = "1px solid var(--border-default)";
        saveBar.innerHTML = `
            <button data-action="save-settings" class="argos-btn argos-btn-primary">
                <i data-lucide="save" class="w-4 h-4"></i> Save
            </button>`;
        modalBody.appendChild(saveBar);

        // ── Remplir les colonnes APRÈS insertion dans le DOM ─────────
        Modules?.renderSettingsKeys?.();

        // Nettoyer l'éventuelle ancienne section avant de re-rendre
        document.getElementById("misp-instances-section")?.remove();
        MISPInstances?.render?.(colMisp);
        
        document.getElementById(`siem-sources-section-qradar`)?.remove();
        document.getElementById(`siem-sources-section-splunk`)?.remove();
        SIEMInstances?.render?.(siemSourcesQradar, "qradar");
        SIEMInstances?.render?.(siemSourcesSplunk, "splunk");

        document.getElementById("settings-modal")?.classList.remove("hidden");
        lucide.createIcons({ nodes: [modalBody] });
    },

    close() {
        document.getElementById("settings-modal")?.classList.add("hidden");
    },

    save() {
        document.querySelectorAll("#settings-modal input[data-key]").forEach(input => {
            const val = input.value.trim();
            if (val) SecretStore.set(input.dataset.key, val);
        });
        document.querySelectorAll("#settings-modal input[data-extra-key]").forEach(input => {
            const val = input.value.trim();
            SecretStore.set(`extra_${input.dataset.extraKey}`, val);
        });
        MISPInstances?.collect?.();

        SIEMInstances?.collect?.("qradar");
        SIEMInstances?.collect?.("splunk");
        
        this.close();
        document.dispatchEvent(new Event("settings:updated"));
    },

    _bind() {
        document.addEventListener("click", e => {
            const action = e.target.closest("[data-action]")?.dataset.action;
            if (action === "open-settings")  this.open();
            if (action === "close-settings") this.close();
            if (action === "save-settings")  this.save();
        });
    },
};
