/**
 * CaseActions — Undo, Export STIX, Delete case
 */
window.CaseActions = {

    async undo(caseId) {
        if (!caseId) return;
        const result = await App.runAction({ action: "undo_correlation", case_id: caseId });
        if (result?.ok) {
            JobLog?.push?.({ message: "↩ Correlation undone", status: "done" });
        } else {
            JobLog?.push?.({ message: "No previous state to restore", status: "running" });
        }
    },

    exportStix(caseId) {
        if (!caseId) return;
        // Direct download via <a> tag — no fetch needed
        const a = document.createElement("a");
        a.href     = `/api/cases/${caseId}/export/stix`;
        a.download = `case_${caseId.slice(0, 8)}.stix.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        JobLog?.push?.({ message: "STIX export downloaded", status: "done" });
    },

    async deleteCase(caseId) {
        if (!caseId) return;

        // Confirmation dialog
        const name = document.getElementById("case-name-display")?.textContent?.trim() || caseId.slice(0, 8);
        if (!confirm(`Delete case "${name}"?\n\nThis will permanently remove all indicators, enrichment data, and correlations.`)) return;

        const result = await App.runAction({ action: "delete_case", case_id: caseId });

        if (result?.ok) {
            JobLog?.push?.({ message: `Case "${name}" deleted`, status: "done" });
            // Close the current tab and go back to new case form
            const tabId = App.state.activeTab;
            if (tabId) {
                Tabs?.close?.(tabId);
            } else {
                await App.loadView("/view/new-case");
            }
        } else {
            JobLog?.push?.({ message: result?.error || "Failed to delete case", status: "failed" });
        }
    },
};
