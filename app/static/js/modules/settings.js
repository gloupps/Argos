window.Settings = {

    init() {
        console.log("[Settings] init");
        this._bind();
    },

    open() {
        Modules?.renderSettingsKeys?.();
        document.getElementById("settings-modal")?.classList.remove("hidden");
    },

    close() {
        document.getElementById("settings-modal")?.classList.add("hidden");
    },

    save() {
        // Save API keys
        document.querySelectorAll("#settings-keys input[data-key]").forEach(input => {
            const val = input.value.trim();
            if (val) SecretStore.set(input.dataset.key, val);
        });
        // Save extra settings fields (e.g. opencti_url)
        document.querySelectorAll("#settings-keys input[data-extra-key]").forEach(input => {
            const val = input.value.trim();
            SecretStore.set(`extra_${input.dataset.extraKey}`, val);
        });
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
