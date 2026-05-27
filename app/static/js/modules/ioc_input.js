/**
 * IocInput — gère le champ "New root indicator" de la left_navbar.
 * Ajoute l'IOC saisi au case actif via POST /api/run { action: "add_ioc" }
 * puis recharge le graph.
 */
window.IocInput = {

    init() {
        const btn   = document.getElementById("new-ioc-btn");
        const input = document.getElementById("new-ioc-input");
        if (!btn || !input) return;

        btn.addEventListener("click",   () => this._submit(input));
        input.addEventListener("keydown", e => { if (e.key === "Enter") this._submit(input); });
    },

    async _submit(input) {
        const value = input.value.trim();
        if (!value) return;

        const tabId  = App?.state?.activeTab;
        const caseId = tabId ? App?.state?.tabs[tabId]?.caseId : null;

        if (!caseId) {
            JobLog?.push?.({ message: "⚠ Create a case first", status: "running" });
            return;
        }

        const btn = document.getElementById("new-ioc-btn");
        if (btn) btn.disabled = true;

        const result = await App.runAction({
            action:  "add_ioc",
            case_id: caseId,
            value,
        });

        if (btn) btn.disabled = false;

        if (result?.ok) {
            input.value = "";
            JobLog?.push?.({ message: `✓ ${value} added`, status: "done" });
            // Recharge le graph pour afficher le nouveau nœud
            GraphModule?.loadCase?.(tabId, caseId);
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to add IOC", status: "failed" });
        }
    },
};
