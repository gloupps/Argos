window.Settings = {

    init() {
        console.log("[Settings] init");
        this._bind();
    },

    open() {
        Modules?.renderSettingsKeys?.();

        // Injecter le bloc "External MISP Instances" dans le modal
        const modalBody = document.querySelector("#settings-modal > div");
        document.getElementById("misp-instances-section")?.remove();
        if (modalBody) {
            const saveBar = modalBody.lastElementChild;
            const wrapper = document.createElement("div");
            modalBody.insertBefore(wrapper, saveBar);
            MISPInstances?.render?.(wrapper);
        }

        document.getElementById("settings-modal")?.classList.remove("hidden");
    },

    close() {
        document.getElementById("settings-modal")?.classList.add("hidden");
    },

    save() {
        // API keys
        document.querySelectorAll("#settings-keys input[data-key]").forEach(input => {
            const val = input.value.trim();
            if (val) SecretStore.set(input.dataset.key, val);
        });
        // Champs extra (opencti_url, misp_url…)
        document.querySelectorAll("#settings-keys input[data-extra-key]").forEach(input => {
            const val = input.value.trim();
            SecretStore.set(`extra_${input.dataset.extraKey}`, val);
        });
        // Instances MISP externes — tout dans SecretStore
        MISPInstances?.collect?.();

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
