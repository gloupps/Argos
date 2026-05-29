/**
 * CaseHeader — inline rename for the case title in ongoing_case.html
 */
window.CaseHeader = {

    startRename() {
        const display = document.getElementById("case-name-display");
        const input   = document.getElementById("case-name-input");
        const actions = document.getElementById("case-name-actions");
        if (!display || !input) return;

        input.value = display.textContent.trim();
        display.classList.add("hidden");
        input.classList.remove("hidden");
        actions?.classList.remove("hidden");
        input.focus();
        input.select();
    },

    async confirmRename() {
        const display  = document.getElementById("case-name-display");
        const input    = document.getElementById("case-name-input");
        const actions  = document.getElementById("case-name-actions");
        const caseId   = document.getElementById("case-id-value")?.dataset.caseId;
        const newName  = input?.value.trim();

        if (!newName || !caseId) { this.cancelRename(); return; }

        const result = await App.runAction({
            action:   "rename_case",
            case_id:  caseId,
            new_name: newName,
        });

        if (result?.ok) {
            display.textContent = newName;
            // Update tab label
            const tabId = App.state.activeTab;
            if (tabId && App.state.tabs[tabId]) {
                App.state.tabs[tabId].name = newName;
                Tabs?.updateLabel?.(tabId, newName);
            }
        }

        this._showDisplay();
    },

    cancelRename() { this._showDisplay(); },

    _showDisplay() {
        document.getElementById("case-name-display")?.classList.remove("hidden");
        document.getElementById("case-name-input")?.classList.add("hidden");
        document.getElementById("case-name-actions")?.classList.add("hidden");
    },
};
