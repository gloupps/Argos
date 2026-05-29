window.CaseModule = {

    _formBound: false,

    init() {
        console.log("[Case] init");
        // Tabs.init() → ensureTab() → activate() → App.switchTab() → App.loadView()
        // gère entièrement le chargement initial.
        // CaseModule écoute uniquement view:loaded pour binder le formulaire new-case.
        document.addEventListener("view:loaded", e => {
            if (e.detail?.url?.includes("/view/new-case")) this.bindForm();
        });
    },

    bindForm() {
        this._formBound = false;
        this._initModeSwitch();

        const form = document.querySelector("form[data-case-form]");
        if (!form) { console.warn("[Case] form not found"); return; }
        if (this._formBound) return;
        this._formBound = true;

        form.addEventListener("submit", async e => {
            e.preventDefault();
            await this._handleSubmit(form);
        });
    },

    async _handleSubmit(form) {
        const fd         = new FormData(form);
        const sourceMode = fd.get("source_mode") || "ioc";

        const payload = {
            action:        "create_case",
            case_name:     fd.get("case_name")     || "",
            source_mode:   sourceMode,
            existing_case: fd.get("existing_case") || "",
            source_url:    fd.get("source_url")    || "",
            ioc_list:      fd.get("ioc_list")      || "",
            auto_enrich:   form.querySelector('[name="auto_enrich"]')?.checked ?? false,
            siem:          form.querySelector('[name="siem"]')?.checked         ?? false,
            correlation:   form.querySelector('[name="correlation"]')?.checked  ?? false,
        };

        if (sourceMode !== "db" && !payload.case_name) {
            this._showError(form, "Please enter a case name.");
            return;
        }

        const btn = form.querySelector("[data-action='new-case']");
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<i data-lucide="loader" class="w-4 h-4 animate-spin"></i> Creating…`;
            lucide.createIcons();
        }
        this._clearError(form);

        const corrConfig = Object.keys(Modules?.registry || {}).reduce((acc, k) => ({
            ...acc, ...(Modules.getCorrelationConfig(k) || {}),
        }), {});
        const result = await App.runAction({
            ...payload,
            api_keys:           App._collectApiKeys(true),   // true = inclure les clés correlate
            correlation_config: corrConfig,
        });
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i> Create Case`;
            lucide.createIcons();
        }

        if (!result?.case_id) {
            this._showError(form, result?.error || "Failed to create case.");
            return;
        }

        const tabId = App.state.activeTab;
        if (tabId && App.state.tabs[tabId]) {
            App.state.tabs[tabId].caseId = result.case_id;
            App.state.tabs[tabId].name   = result.case_name || payload.case_name || "Case";
            Tabs?.updateLabel?.(tabId, App.state.tabs[tabId].name);
            App._saveState();
        }

        await App.loadView(`/view/case/${result.case_id}`);
    },

    _initModeSwitch() {
        const buttons     = document.querySelectorAll(".mode-btn");
        const sections    = document.querySelectorAll(".form-section");
        const input       = document.getElementById("source-mode");
        const configSect  = document.getElementById("case-config-section");
        const nameInput   = document.querySelector('[name="case_name"]');
        if (!buttons.length) return;

        buttons.forEach(btn => {
            btn.addEventListener("click", () => {
                const mode = btn.dataset.mode;

                sections.forEach(s => s.classList.add("hidden"));
                buttons.forEach(b => {
                    b.classList.remove("ring-2", "ring-blue-500", "bg-slate-700");
                    b.classList.add("bg-slate-800");
                });

                document.getElementById(`form-${mode}`)?.classList.remove("hidden");
                btn.classList.add("ring-2", "ring-blue-500", "bg-slate-700");
                btn.classList.remove("bg-slate-800");
                if (input) input.value = mode;

                if (configSect) configSect.style.display = mode === "db" ? "none" : "";
                if (nameInput)  nameInput.required = mode !== "db";
            });
        });

        document.querySelector('[data-mode="ioc"]')?.click();
    },

    _showError(form, msg) {
        let el = form.querySelector(".case-error");
        if (!el) {
            el = document.createElement("p");
            el.className = "case-error text-xs text-red-400 mt-3 px-1";
            form.appendChild(el);
        }
        el.textContent = `⚠ ${msg}`;
    },
    _clearError(form) { form.querySelector(".case-error")?.remove(); },
};
