<div id="settings-modal"
     class="hidden fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
    <div class="w-[760px] max-h-[85vh] overflow-y-auto glass rounded-xl border border-slate-700 p-6 space-y-6">

        <!-- Header -->
        <div class="flex items-center justify-between">
            <h2 class="text-lg font-bold flex items-center gap-2">
                <i data-lucide="settings" class="w-5 h-5"></i> Settings
            </h2>
            <button data-action="close-settings" class="text-slate-400 hover:text-white">
                <i data-lucide="x" class="w-5 h-5"></i>
            </button>
        </div>

        <!-- API Keys + Quotas -->
        <section>
            <h3 class="text-xs uppercase text-slate-500 tracking-wider mb-4">API Keys</h3>
            <!-- Populated dynamically by Modules.renderSettingsKeys() -->
            <div id="settings-keys" class="space-y-3"></div>
        </section>

        <!-- Save -->
        <div class="flex justify-end border-t border-slate-800 pt-4">
            <button data-action="save-settings"
                    class="bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm
                           font-semibold flex items-center gap-2">
                <i data-lucide="save" class="w-4 h-4"></i> Save
            </button>
        </div>

    </div>
</div>
