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

        // ── STIX2 file : lire et parser côté client ──────────
        let stixIocList = "";
        if (sourceMode === "file") {
            const fileInput = form.querySelector('[name="stix_file"]');
            const file = fileInput?.files?.[0];
            if (!file) { this._showError(form, "Please select a STIX2 JSON file."); return; }
            try {
                stixIocList = await this._parseStix2File(file);
            } catch (e) {
                this._showError(form, `STIX2 parse error: ${e.message}`);
                return;
            }
            if (!stixIocList) { this._showError(form, "No indicators found in this STIX2 bundle."); return; }
        }

        const payload = {
            action:               "create_case",
            case_name:            fd.get("case_name")           || "",
            source_mode:          sourceMode === "file" ? "ioc" : sourceMode,
            existing_case:        fd.get("existing_case")        || "",
            source_url:           fd.get("source_url")           || "",
            internal_source_url:  fd.get("internal_source_url") || "",
            internal_source_type: fd.get("internal_source_type") || "opencti",
            ioc_list:             sourceMode === "file" ? stixIocList : (fd.get("ioc_list") || ""),
            auto_enrich:          form.querySelector('[name="auto_enrich"]')?.checked ?? false,
            siem:                 form.querySelector('[name="siem"]')?.checked         ?? false,
            correlation:          form.querySelector('[name="correlation"]')?.checked  ?? false,
        };

        // Pour internal_source, on passe le mode tel quel au backend
        if (sourceMode === "internal_source") {
            payload.source_mode = "internal_source";
        }

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

        const corrConfig = Modules?.collectCorrelationConfig?.() || {};
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

        // Observer les jobs auto-lancés (enrich / correlate)
        const jobIds = result.job_ids || {};
        Object.entries(jobIds).forEach(([type, jobId]) => {
            if (!jobId) return;
            const label = type === "enrich" ? "Auto Qualify" : "Auto Correlation";
            JobLog?.push?.({ message: `▶ ${label} started`, status: "running" });
            App.socket?.on?.("job_update", function handler(d) {
                if (d.job_id === jobId && d.status === "done") {
                    App.socket.off("job_update", handler);
                    JobLog?.push?.({ message: `✓ ${label} done`, status: "done" });
                }
            });
        });
    },
    
    // ── Parser STIX2 côté client ─────────────────────────────
    async _parseStix2File(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const raw    = JSON.parse(e.target.result);
                    // Accepte bundle {type:"bundle", objects:[]} ou tableau direct
                    const objects = raw.objects ?? (Array.isArray(raw) ? raw : [raw]);
                    const iocs   = [];
                    for (const obj of objects) {
                        if (!obj || obj.type !== "indicator") continue;
                        const pattern = obj.pattern || "";
                        // Extrait toutes les valeurs = '...' dans le pattern
                        const matches = [...pattern.matchAll(/=\s*['"]([^'"]+)['"]/g)];
                        for (const m of matches) {
                            const val = m[1].trim();
                            if (val) iocs.push(val);
                        }
                    }
                    resolve(iocs.join("\n"));
                } catch (err) {
                    reject(err);
                }
            };
            reader.onerror = () => reject(new Error("File read failed"));
            reader.readAsText(file);
        });
    },

    _extractPatternValue(pattern) {
        // Patterns STIX2 courants :
        // [domain-name:value = 'evil.com']
        // [ipv4-addr:value = '1.2.3.4']
        // [file:hashes.MD5 = 'abc123']
        // [url:value = 'http://...']
        const m = pattern.match(/=\s*['"]([^'"]+)['"]/);
        return m ? m[1] : null;
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
        
        document.getElementById("stix-file-input")?.addEventListener("change", async (e) => {
            const file = e.target.files?.[0];
            const preview = document.getElementById("stix-preview");
            if (!file || !preview) return;
            try {
                const text = await file.text();
                const bundle = JSON.parse(text);
                const objects = bundle.objects || [];
                const indicators = objects.filter(o => o.type === "indicator");
                const names = indicators.slice(0, 10).map(o => {
                    const m = (o.pattern||"").match(/=\s*['"]([^'"]+)['"]/);
                    return m ? m[1] : o.name || "?";
                });
                preview.innerHTML = `
                    <span class="text-green-400 font-medium">${indicators.length} indicator(s) found</span>
                    ${indicators.length > 0 ? `<div class="mt-1 space-y-0.5 mono">${names.map(n => `<div>• ${n}</div>`).join("")}${indicators.length > 10 ? `<div class="text-slate-600">… and ${indicators.length - 10} more</div>` : ""}</div>` : ""}
                `;
                preview.classList.remove("hidden");
            } catch(err) {
                preview.innerHTML = `<span class="text-red-400">⚠ Invalid JSON: ${err.message}</span>`;
                preview.classList.remove("hidden");
            }
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
