// app/static/js/modules/siem.js
window.SIEMModule = {

    state: {},

    init() {
        this._loadState();
        this._render();
        App?.socket?.on("siem_result", d => this._onResult(d));
    },

    _loadState() {
        try {
            const r = localStorage.getItem("pivotlens_siem");
            this.state = r ? JSON.parse(r) : {
                include_correlated:     false,
                "ipv4-addr_checkbox":   true,
                "domain-name_checkbox": true,
                "url_checkbox":         true,
                "stixfile_checkbox":    true,
                date_start: "",
                date_end:   "",
            };
        } catch (_) { this.state = {}; }
    },

    _saveState() {
        localStorage.setItem("pivotlens_siem", JSON.stringify(this.state));
    },

    update(key, value) {
        this.state[key] = value;
        this._saveState();
    },

    // ─────────────────────────────────────────────────────
    // Render right-navbar panel into #siem-container
    // ─────────────────────────────────────────────────────
    _render() {
        const container = document.getElementById("siem-container");
        if (!container) return;

        // ── SIEM type sélectionné (défaut: qradar) ──
        const siemType = this.state.siem_type || "qradar";

        const isConfigured = !!SecretStore?.has?.(siemType)

        const now  = new Date();
        const week = new Date(now - 7 * 86400000);
        const fmt  = d => d.toISOString().slice(0, 16);

        const ds = this.state.date_start || fmt(week);
        const de = this.state.date_end   || fmt(now);

        // Labels des SIEM dispo (extensible)
        const siemOptions = [
            { key: "splunk",  label: "SPLUNK",  soon: false  },
            { key: "qradar",  label: "QRADAR",  soon: false },
        ];

        const typePickerHtml = `
            <div class="flex p-1 bg-slate-900 rounded-md border border-slate-800">
                ${siemOptions.map(opt => `
                <label class="relative flex-1 text-center py-1.5 text-[10px] font-bold rounded cursor-pointer transition
                              ${siemType === opt.key ? "bg-teal-600/80 text-white" : "text-slate-400 hover:text-slate-200"}
                              ${opt.soon ? "opacity-40 cursor-not-allowed" : ""}">
                    <input type="radio" name="siem_type" class="hidden"
                           ${siemType === opt.key ? "checked" : ""}
                           ${opt.soon ? "disabled" : ""}
                           onchange="SIEMModule.update('siem_type', '${opt.key}'); SIEMModule._render()">
                    ${opt.label}
                    ${opt.soon ? `<span class="absolute -top-1.5 -right-1 text-[8px] bg-slate-700 text-slate-400 px-1 rounded">soon</span>` : ""}
                </label>`).join("")}
            </div>`;

        container.innerHTML = `
            <div class="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-3">

                <!-- SIEM type picker -->
                ${typePickerHtml}

                ${!isConfigured ? `
                <div class="flex items-center gap-2 text-[10px] text-amber-400/80
                            bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1.5">
                    <i data-lucide="alert-triangle" class="w-3 h-3 shrink-0"></i>
                    ${siemType === "qradar" ? "QRadar" : siemType} token missing — check Settings
                </div>` : ""}

                <!-- Date range -->
                <div class="grid grid-cols-2 gap-2">
                    <div class="space-y-1">
                        <p class="text-[9px] text-slate-500 uppercase">Start Date</p>
                        <input type="datetime-local" value="${ds}"
                               onchange="SIEMModule.update('date_start', this.value)"
                               class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-[13px] font-mono text-slate-300
                                      focus:outline-none focus:ring-1 focus:ring-teal-500/50 [color-scheme:dark]">
                    </div>
                    <div class="space-y-1">
                        <p class="text-[9px] text-slate-500 uppercase">End Date</p>
                        <input type="datetime-local" value="${de}"
                               onchange="SIEMModule.update('date_end', this.value)"
                               class="w-full bg-slate-900 border border-slate-700 rounded p-1.5 text-[13px] font-mono text-slate-300
                                      focus:outline-none focus:ring-1 focus:ring-teal-500/50 [color-scheme:dark]">
                    </div>
                </div>

                <!-- Scope toggle -->
                <div class="flex p-1 bg-slate-900 rounded-md border border-slate-800">
                    <label class="flex-1 text-center py-1.5 text-[10px] font-bold rounded cursor-pointer transition
                                  ${!this.state.include_correlated ? "bg-teal-600 text-white" : "text-slate-400 hover:text-slate-200"}">
                        <input type="radio" name="siem_scope" class="hidden"
                               ${!this.state.include_correlated ? "checked" : ""}
                               onchange="SIEMModule.update('include_correlated', false); SIEMModule._render()">
                        ROOT IOC
                    </label>
                    <label class="flex-1 text-center py-1.5 text-[10px] font-bold rounded cursor-pointer transition
                                  ${this.state.include_correlated ? "bg-teal-600 text-white" : "text-slate-400 hover:text-slate-200"}">
                        <input type="radio" name="siem_scope" class="hidden"
                               ${this.state.include_correlated ? "checked" : ""}
                               onchange="SIEMModule.update('include_correlated', true); SIEMModule._render()">
                        ALL IOC
                    </label>
                </div>

                <!-- IOC type filters -->
                <div class="flex items-center justify-center gap-1">
                    ${[
                        ["ipv4-addr_checkbox",   "IPv4"],
                        ["domain-name_checkbox", "Domain"],
                        ["url_checkbox",         "URL"],
                        ["stixfile_checkbox",    "Hash"],
                    ].map(([key, label]) => {
                        const on = this.state[key] !== false;
                        return `
                        <label class="flex items-center gap-1 px-2 py-0.5 rounded-full border cursor-pointer transition text-[10px] font-bold
                                      ${on ? "bg-teal-600/20 border-teal-500/40 text-teal-300" : "bg-slate-800 border-slate-700 text-slate-500"}">
                            <input type="checkbox" class="hidden" ${on ? "checked" : ""}
                                   onchange="SIEMModule.update('${key}', this.checked); SIEMModule._render()">
                            ${label}
                        </label>`;
                    }).join("")}
                </div>

                <!-- Run -->
                <button onclick="SIEMModule.run()"
                        ${!isConfigured ? "disabled" : ""}
                        class="w-full bg-slate-800 hover:bg-teal-600/30 border border-slate-700 hover:border-teal-500/40
                               py-2 rounded text-[11px] font-bold text-teal-300 transition flex items-center justify-center gap-2
                               disabled:opacity-40 disabled:cursor-not-allowed">
                    <i data-lucide="play" class="w-3 h-3"></i> Run Investigation
                </button>
            </div>
        `;

        lucide.createIcons();
    },
    
    // ─────────────────────────────────────────────────────
    // Run
    // ─────────────────────────────────────────────────────
    run() {
        const tabId  = App?.state?.activeTab;
        const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;
        if (!caseId) { console.warn("[SIEM] no active case"); return; }

        // Compute date strings → ISO or null
        const ds = this.state.date_start || null;
        const de = this.state.date_end   || null;

        const extraConfig = {
            siem_type: siemType,

            // ── QRadar ──────────────────────────────────────────
            qradar:              SecretStore?.get("qradar")           || "",
            qradar_url:          SecretStore?.get("extra_qradar_url") || "",
            qradar_result_key:   SecretStore?.get("extra_qradar_result_key") || "qradar",
            qradar_anonymize:    SecretStore?.get("extra_qradar_anonymize")  || "false",
            qradar_logsources:   SecretStore?.getJSON("siem_logsources_qradar", []),

            // ── Splunk ──────────────────────────────────────────
            splunk:              SecretStore?.get("splunk")             || "",
            splunk_url:          SecretStore?.get("extra_splunk_url")   || "",
            splunk_result_key:   SecretStore?.get("extra_splunk_result_key") || "splunk",
            splunk_indexes:      SecretStore?.getJSON("siem_logsources_splunk", []),
        };


        // Show spinner in SIEM row result panel if present
        const panel = document.getElementById("siem-results-panel");
        if (panel) {
            panel.innerHTML = `
            <div class="flex items-center gap-2 text-[11px] text-slate-500 py-2">
                <i data-lucide="loader" class="w-3.5 h-3.5 animate-spin text-teal-400"></i>
                ${siemType === "splunk" ? "Running SPL searches…" : "Running AQL queries…"}
            </div>`;
            lucide.createIcons();
        }

        App.runAction({
            action:              "siem",
            case_id:             caseId,
            include_correlated:  this.state.include_correlated ?? false,
            "ipv4-addr_checkbox":   this.state["ipv4-addr_checkbox"]   ?? true,
            "domain-name_checkbox": this.state["domain-name_checkbox"] ?? true,
            "url_checkbox":         this.state["url_checkbox"]         ?? true,
            "stixfile_checkbox":    this.state["stixfile_checkbox"]    ?? true,
            date_start:          ds,
            date_end:            de,
            extra_config:        extraConfig,
        });
    },

    // ─────────────────────────────────────────────────────
    // Result handler (socket siem_result)
    // ─────────────────────────────────────────────────────
    _onResult(data) {
        const tabId  = App?.state?.activeTab;
        const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;
        if (data.case_id && caseId && data.case_id !== caseId) return;

        const panel = document.getElementById("siem-results-panel");
        if (!panel) return;

        const results = data.results || {};
        const iocs    = Object.keys(results);

        if (!iocs.length) {
            panel.innerHTML = `<p class="text-[11px] text-slate-600 italic py-2">No hits found.</p>`;
            return;
        }

        const totalHits = iocs.reduce((acc, ioc) => acc + ((results[ioc]["qradar"] || {}).events || 0), 0);

        let html = `
        <div class="flex items-center justify-between mb-3 text-[10px]">
            <span class="text-slate-400">
                <span class="text-teal-400 font-bold font-mono">${iocs.length}</span> IOCs ·
                <span class="text-teal-400 font-bold font-mono">${totalHits}</span> total hits
            </span>
        </div>
        <div class="space-y-1.5">`;

        const sorted = iocs.sort((a, b) =>
            ((results[b]["qradar"]||{}).events||0) - ((results[a]["qradar"]||{}).events||0)
        );

        for (const ioc of sorted) {
            const src      = results[ioc]["qradar"] || {};
            const hits     = src.events || 0;
            const rows     = src.rows || src.event_rows || [];
            const flows    = src.flows || [];
            const link     = src.link || "";
            const flowLink = src.flow_link || "";

            const hitColor = hits > 0
                ? "text-red-400 bg-red-500/10 border-red-500/30"
                : "text-slate-600 bg-slate-800 border-slate-700";

            // Preview: first 3 rows, pick meaningful cols
            const allRows  = [...rows, ...flows];
            const preview  = allRows.slice(0, 3);
            const headers  = preview.length ? Object.keys(preview[0]).slice(0, 4) : [];

            const tableHtml = preview.length ? `
            <div class="overflow-x-auto mt-1.5 rounded border border-slate-800/80">
                <table class="w-full text-[9px] font-mono">
                    <thead><tr class="bg-slate-900 text-slate-600">
                        ${headers.map(h => `<th class="px-1.5 py-0.5 text-left whitespace-nowrap">${h}</th>`).join("")}
                    </tr></thead>
                    <tbody class="divide-y divide-slate-800/60">
                        ${preview.map(row => `
                        <tr class="hover:bg-slate-800/30">
                            ${headers.map(h => `
                            <td class="px-1.5 py-0.5 text-slate-400 max-w-[90px] truncate"
                                title="${String(row[h]||"").replace(/"/g,"&quot;")}">${row[h]||""}</td>
                            `).join("")}
                        </tr>`).join("")}
                    </tbody>
                </table>
            </div>
            ${allRows.length > 3 ? `<p class="text-[9px] text-slate-700 px-1 pt-0.5">+${allRows.length - 3} more rows</p>` : ""}
            ` : "";

            html += `
            <div class="rounded-lg border border-slate-800 bg-slate-900/40 overflow-hidden">
                <div class="flex items-center gap-2 px-2.5 py-1.5">
                    <span class="flex-1 font-mono text-[10px] text-slate-200 truncate" title="${ioc}">${ioc}</span>
                    <span class="text-[9px] px-1.5 py-0.5 rounded border font-bold shrink-0 ${hitColor}">
                        ${hits} hit${hits !== 1 ? "s" : ""}
                    </span>
                    ${link ? `<a href="${link}" target="_blank" rel="noopener"
                                 title="Events in QRadar"
                                 class="text-slate-600 hover:text-teal-400 transition shrink-0">
                                 <i data-lucide="external-link" class="w-3 h-3"></i></a>` : ""}
                    ${flowLink ? `<a href="${flowLink}" target="_blank" rel="noopener"
                                     title="Flows in QRadar"
                                     class="text-slate-600 hover:text-blue-400 transition shrink-0">
                                     <i data-lucide="activity" class="w-3 h-3"></i></a>` : ""}
                </div>
                ${tableHtml}
            </div>`;
        }

        html += "</div>";
        panel.innerHTML = html;
        lucide.createIcons();
    },
};
