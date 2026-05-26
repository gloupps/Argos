window.CaseModule = {

    init() {
        console.log("[Case] init");

        this.bindEvents();

        // IMPORTANT: ne pas load direct sans App ready
        this.loadForm();
    },

    bindEvents() {
        document.addEventListener("view:loaded", () => {
            console.log("[Case] view loaded");
            this.bindForm();
        });
    },

    loadForm() {
        if (!window.App) {
            console.warn("[Case] App not ready yet");
            return;
        }

        App.loadView("/new_case_form");
    },

    bindForm() {
        this.initModeSwitch();
        this.bindFormSubmit();
    },

    bindFormSubmit() {
        const form = document.querySelector('form');
        if (!form) {
            return;
        }

        form.addEventListener('submit', async (event) => {
            event.preventDefault();

            const formData = new FormData(form);
            const response = await fetch('/create_case', {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                console.error('[Case] create_case failed', response.statusText);
                return;
            }

            const html = await response.text();
            const container = document.getElementById('case-container');
            if (container) {
                container.innerHTML = html;
                lucide.createIcons();
                document.dispatchEvent(new Event('view:loaded'));
            }
        });
    },

    initModeSwitch() {
        const buttons = document.querySelectorAll('.mode-btn');
        const sections = document.querySelectorAll('.form-section');
        const modeInput = document.getElementById('source-mode');

        console.log("[Case] binding form switch");

        buttons.forEach(btn => {
            btn.onclick = () => {

                sections.forEach(s => s.classList.add('hidden'));
                buttons.forEach(b => b.classList.remove('ring', 'ring-blue-500'));

                const target = document.getElementById(`form-${btn.dataset.mode}`);
                if (target) target.classList.remove('hidden');

                btn.classList.add('ring', 'ring-blue-500');
                if (modeInput) {
                    modeInput.value = btn.dataset.mode;
                }
            };
        });

        const defaultBtn = document.querySelector('[data-mode="ioc"]');
        if (defaultBtn) defaultBtn.click();
    }
};