window.SecretStore = {
    prefix: "pivotlens_",

    set(key, value)  { localStorage.setItem(this.prefix + key, value); },
    get(key)         { return localStorage.getItem(this.prefix + key); },
    has(key)         { const v = this.get(key); return v !== null && v !== ""; },
    remove(key)      { localStorage.removeItem(this.prefix + key); },

    // Retourne toutes les clés gérées par SecretStore (sans préfixe)
    keys() {
        const out = [];
        for (let i = 0; i < localStorage.length; i++) {
            const raw = localStorage.key(i);
            if (raw && raw.startsWith(this.prefix))
                out.push(raw.slice(this.prefix.length));
        }
        return out;
    },

    // Helpers JSON (pour stocker des listes/objets)
    setJSON(key, value) { this.set(key, JSON.stringify(value)); },
    getJSON(key, fallback = null) {
        try {
            const v = this.get(key);
            return v ? JSON.parse(v) : fallback;
        } catch (_) { return fallback; }
    },
};
