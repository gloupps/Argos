window.SecretStore = {
    prefix: "pivotlens_",
    set(key, value)  { localStorage.setItem(this.prefix + key, value); },
    get(key)         { return localStorage.getItem(this.prefix + key); },
    has(key)         { const v = this.get(key); return v !== null && v !== ""; },
};
