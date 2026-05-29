window.CorrelationModule = {
    // État géré par Modules.js (_correlationState) depuis le registry.
    // Ce fichier expose uniquement l'API publique utilisée ailleurs.

    init() { console.log("[Correlation] init"); },

    getConfig(moduleKey) {
        return Modules?._correlationState?.[moduleKey] || {};
    },
};
