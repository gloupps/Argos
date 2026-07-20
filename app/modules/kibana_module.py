# app/modules/kibana_module.py
"""
Kibana SIEM module — PivotLens / Argos.

Contexte : certains environnements bloquent l'accès direct à l'API
Elasticsearch (`{es_url}/{index}/_search`) mais autorisent l'accès à Kibana
(souvent en frontal, avec son propre auth — API key ou Basic). Ce module
route donc les recherches SIEM via le proxy interne de Kibana :

    POST {kibana_url}/api/console/proxy?path=%2F{index}%2F_search&method=POST

Ce endpoint est celui utilisé par Kibana Dev Tools → Console : Kibana
exécute la requête ES avec ses PROPRES credentials côté cluster (configurés
côté serveur Kibana), donc ça fonctionne même si le compte utilisateur n'a
pas d'accès direct à Elasticsearch — seulement à Kibana.

Toute requête vers l'API Kibana (hors GET) nécessite le header `kbn-xsrf`.

Credentials / extra_config keys :
  api_key            → soit une clé API Kibana au format brut "id:api_key"
                        (encodée en base64 automatiquement), soit déjà
                        encodée en base64, envoyée en "Authorization: ApiKey …"
  kibana_url         → URL de base Kibana (ex. https://kibana.corp:5601)
  kibana_user/pass   → Basic Auth alternative si pas de clé API
  kibana_indexes     → list of dicts [{id, name, ioc_type, search_field, output_fields}, ...]
                        stored in SecretStore as "siem_logsources_kibana"
                        "name" accepte soit un pattern d'index brut (ex. "urlfeed-*"),
                        soit un Data View ID ou nom Kibana — résolu automatiquement
                        au pattern réel via /api/data_views (cf. _resolve_index_pattern).
  date_start/date_end → ISO datetime string

ioc_type ("— any —" / vide) : matche tous les types d'IOC présents dans le case
(pas de skip silencieux — cf. bug corrigé sur Splunk/Elasticsearch).
"""

import asyncio
import base64
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .module import Module


# ─────────────────────────────────────────────────────────────
# Helpers (mêmes conventions que elasticsearch_module.py)
# ─────────────────────────────────────────────────────────────

_IOC_FRONT_MAP: Dict[str, str] = {
    "IP":          "ip",
    "Domain":      "domain",
    "URL":         "url",
    "Hash-MD5":    "hash",
    "Hash-SHA1":   "hash",
    "Hash-SHA256": "hash",
}

# dict_indicators (le case graph classifié par classify_indicators() dans
# qradar_module.py) utilise des clés "IPv4-Addr"/"Domain-Name"/"Url"/
# "StixFile-MD5"/... — PAS "ip"/"domain"/"url"/"hash".
_FRONT_TO_DICTKEY: Dict[str, str] = {
    "IP":          "IPv4-Addr",
    "Domain":      "Domain-Name",
    "URL":         "Url",
    "Hash-MD5":    "StixFile-MD5",
    "Hash-SHA1":   "StixFile-SHA1",
    "Hash-SHA256": "StixFile-SHA256",
}

_IOC_FIELD_MAP: Dict[str, List[str]] = {
    "ip": [
        "src_ip", "dst_ip", "ip", "source.ip", "destination.ip",
        "host.ip", "client.ip", "server.ip", "network.forwarded_ip", "related.ip",
    ],
    "domain": [
        "domain", "dns.question.name", "dns.answers.data",
        "url.domain", "host.name", "source.domain", "destination.domain", "related.hosts",
    ],
    "url": ["url.full", "url.original", "http.request.referrer", "event.url", "url"],
    "hash": [
        "file.hash.md5", "file.hash.sha1", "file.hash.sha256",
        "process.hash.md5", "process.hash.sha1", "process.hash.sha256",
        "hash.md5", "hash.sha1", "hash.sha256",
    ],
}

_INTERNAL_TO_FRONT: Dict[str, List[str]] = {
    "ip":     ["IP"],
    "domain": ["Domain"],
    "url":    ["URL"],
    "hash":   ["Hash-MD5", "Hash-SHA1", "Hash-SHA256"],
}

_TIMESTAMP_FIELDS = ["@timestamp", "event.created", "timestamp", "time"]

_DEFAULT_CONTEXT_FIELDS = [
    "@timestamp", "event.created",
    "source.ip", "destination.ip", "src_ip", "dst_ip",
    "url.full", "url.original", "host.name", "user.name",
    "process.name", "process.executable", "file.path", "file.name",
    "event.action", "event.category", "event.type", "event.outcome",
    "rule.name", "rule.description", "alert.severity",
    "winlog.event_id", "event.code",
    "dns.question.name", "dns.answers.data", "message",
]


def _nested_get(obj: dict, dotted_key: str):
    parts = dotted_key.split(".")
    cur = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur if cur not in (None, "", []) else None


def _date_filter(date_start: Optional[str], date_end: Optional[str]) -> Optional[Dict]:
    if not date_start and not date_end:
        return None
    r: Dict[str, str] = {}
    if date_start:
        r["gte"] = date_start
    if date_end:
        r["lte"] = date_end
    return r


def _build_es_query(
    indicator: str,
    fields: List[str],
    source_fields: List[str],
    size: int = 10,
    date_range: Optional[Dict] = None,
) -> Dict:
    must: List[Dict] = [
        {
            "bool": {
                "should": [
                    {"multi_match": {"query": indicator, "fields": fields, "type": "phrase"}},
                    {"bool": {
                        "should": [{"term": {f"{f}.keyword": indicator}} for f in fields],
                        "minimum_should_match": 1,
                    }},
                ],
                "minimum_should_match": 1,
            }
        }
    ]
    if date_range:
        must.append({"range": {"@timestamp": date_range}})
    return {
        "size": size,
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": source_fields,
    }


def _build_kibana_headers(context: Dict) -> Dict[str, str]:
    """
    Authorization : ApiKey (clé Kibana, brute "id:key" → base64 auto, ou déjà
    encodée) en priorité, sinon Basic Auth user/pass Kibana.
    `kbn-xsrf` est OBLIGATOIRE pour toute requête non-GET vers l'API Kibana.
    """
    headers = {"Content-Type": "application/json", "kbn-xsrf": "true"}
    token    = (context.get("api_key") or "").strip()
    user     = (context.get("kibana_user") or "").strip()
    password = (context.get("kibana_pass") or "").strip()

    if token:
        encoded = base64.b64encode(token.encode()).decode() if ":" in token else token
        headers["Authorization"] = f"ApiKey {encoded}"
    elif user and password:
        encoded = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"
    return headers


def _proxy_url(kibana_url: str, idx_name: str) -> str:
    """URL du endpoint console proxy pour un _search sur idx_name."""
    path = urllib.parse.quote(f"/{idx_name}/_search", safe="")
    return f"{kibana_url}/api/console/proxy?path={path}&method=POST"


# Cache de résolution Data View → pattern d'index, en mémoire process.
# Best-effort : évite de re-résoudre le même Data View à chaque IOC/tâche
# parallèle dans un même job. Pas de TTL — un redémarrage du process vide
# le cache (suffisant pour un outil local-only).
_DV_CACHE: Dict[str, str] = {}


async def _resolve_index_pattern(
    requester, kibana_url: str, headers: Dict[str, str], value: str,
) -> str:
    """
    Résout `value` en pattern d'index Elasticsearch réel.

    `value` peut être :
      - un pattern d'index brut (ex. "urlfeed-*")     → renvoyé tel quel si non résolvable en Data View
      - un Data View ID Kibana (UUID)                  → résolu via /api/data_views/data_view/{id}
      - un nom de Data View (ex. "Threat Feed Logs")   → résolu via /api/data_views (match par name/id)

    Résolution best-effort : si aucune correspondance Data View n'est trouvée
    (erreur API, 404, pas de match), `value` est utilisé tel quel comme pattern
    d'index — fallback silencieux, garde la compatibilité avec les configs
    existantes en pattern brut.
    """
    if not value or value == "*":
        return value or "*"

    cache_key = f"{kibana_url}::{value}"
    if cache_key in _DV_CACHE:
        return _DV_CACHE[cache_key]

    resolved = value  # fallback par défaut : value utilisé tel quel

    # 1) Tentative directe par ID (cas le plus courant : l'utilisateur colle
    #    l'ID du Data View copié depuis Kibana → Stack Management → Data Views)
    get_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
    try:
        data = await requester.get(
            f"{kibana_url}/api/data_views/data_view/{urllib.parse.quote(value, safe='')}",
            headers=get_headers,
        )
        title = ((data or {}).get("data_view") or {}).get("title")
        if title:
            resolved = title
    except Exception:
        pass

    # 2) Sinon, tentative par nom (liste tous les Data Views, match par name/id)
    if resolved == value:
        try:
            listing = await requester.get(f"{kibana_url}/api/data_views", headers=get_headers)
            for dv in (listing or {}).get("data_view", []):
                if dv.get("name") == value or dv.get("id") == value:
                    if dv.get("title"):
                        resolved = dv["title"]
                    break
        except Exception:
            pass

    _DV_CACHE[cache_key] = resolved
    return resolved


def _extract_hits(indicator: str, total: int, hits: List[Dict],
                  idx_label: str, output_fields: List[str],
                  f_fn) -> List[Dict]:
    """Transforme des hits ES (reçus via le proxy Kibana) en champs UI. f_fn = self._f d'un module."""
    prefix = f"[{idx_label}] "
    res = []
    res.append(f_fn(indicator, f"{prefix}In Elasticsearch (via Kibana)", "label-capsule", "Yes ✓"))
    res.append(f_fn(indicator, f"{prefix}Total Hits",        "label-capsule", str(total)))

    index_names = sorted({h.get("_index", "") for h in hits if h.get("_index")})
    if index_names:
        res.append(f_fn(indicator, f"{prefix}Indices", "list", index_names[:10]))

    timestamps = []
    for h in hits:
        src = h.get("_source", {})
        for tf in _TIMESTAMP_FIELDS:
            ts = _nested_get(src, tf)
            if ts:
                timestamps.append(str(ts)[:19])
                break
    if timestamps := sorted(timestamps):
        res.append(f_fn(indicator, f"{prefix}First Seen", "label-capsule", timestamps[0]))
        res.append(f_fn(indicator, f"{prefix}Last Seen",  "label-capsule", timestamps[-1]))

    rows_display = []
    for h in hits[:10]:
        src = h.get("_source", {})
        ts = next((_nested_get(src, tf) for tf in _TIMESTAMP_FIELDS if _nested_get(src, tf)), None)
        parts = [str(ts)[:19]] if ts else []
        display_fields = output_fields if output_fields else [
            "host.name", "source.ip", "destination.ip",
            "user.name", "process.name", "event.action",
            "rule.name", "dns.question.name",
        ]
        for of in display_fields:
            val = _nested_get(src, of)
            if val:
                parts.append(f"{of.split('.')[-1]}={val}")
        if parts:
            rows_display.append(" | ".join(parts))
    if rows_display:
        res.append(f_fn(indicator, f"{prefix}Recent Events", "list", rows_display))
    return res


# ══════════════════════════════════════════════════════════════
# KibanaModule — SIEM Investigation (right_navbar), via console proxy
# ══════════════════════════════════════════════════════════════

class KibanaModule(Module):

    name        = "Kibana"
    description = "Elasticsearch search via Kibana's console proxy (for restricted direct-ES access)"
    src_type    = "siem"
    supported_types = ["ip", "domain", "url", "hash"]
    icon        = "compass"
    url         = ""
    # Basic Auth (kibana_user/kibana_pass) est une alternative valide à l'ApiKey
    # → ne pas bloquer/afficher MISSING sur la seule absence de clé API.
    requires_api_key = False

    settings_fields = [
        {
            "key":         "kibana_url",
            "type":        "url",
            "label":       "Kibana URL",
            "placeholder": "https://kibana.yourdomain.com:5601",
        },
        {
            "key":         "kibana_user",
            "type":        "text",
            "label":       "Username (Basic Auth, optional — alternative to API key)",
            "placeholder": "kibana_user",
        },
        {
            "key":         "kibana_pass",
            "type":        "text",
            "label":       "Password (Basic Auth, optional)",
            "placeholder": "••••••••",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "kibana"
        return base

    async def get_info(self, indicator, context):        return []
    async def get_correlation(self, indicator, context): return []

    async def get_quotas(self, context):
        """Healthcheck léger via /api/status (toujours dispo, ne nécessite pas d'index)."""
        base_url = (context.get("kibana_url") or "").rstrip("/")
        if not base_url:
            return {"reachable": False, "reason": "missing_config"}
        headers = _build_kibana_headers(context)
        headers.pop("Content-Type", None)  # GET, pas de body
        data = await self.requester.get(f"{base_url}/api/status", headers=headers)
        if not data:
            return {"reachable": False}
        return {
            "plan_type": "siem",
            "reachable": True,
            "kibana_version": (data.get("version") or {}).get("number", "unknown"),
            "status": (data.get("status") or {}).get("overall", {}).get("level", "unknown"),
        }

    # ── Point d'entrée SIEM ────────────────────────────────
    async def investigate(
        self,
        dict_indicators: Dict[str, List[str]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        base_url = (context.get("kibana_url") or "").rstrip("/")
        if not base_url:
            return {}

        indexes    = context.get("kibana_indexes") or []
        date_range = _date_filter(context.get("date_start"), context.get("date_end"))
        headers    = _build_kibana_headers(context)
        results: Dict[str, Any] = {}
        tasks = []

        for idx_cfg in indexes:
            idx_name      = (idx_cfg.get("name") or "").strip()
            ioc_type_raw  = idx_cfg.get("ioc_type") or ""
            search_field  = (idx_cfg.get("search_field") or "").strip()
            output_fields = [
                f.strip()
                for f in (idx_cfg.get("output_fields") or "").split(",")
                if f.strip()
            ]

            if not idx_name:
                continue

            # "— any —" (ioc_type_raw vide) → matche tous les types d'IOC
            # présents dans le case, au lieu de skip silencieusement.
            front_labels = [ioc_type_raw] if ioc_type_raw else list(_FRONT_TO_DICTKEY.keys())

            for front_label in front_labels:
                dict_key   = _FRONT_TO_DICTKEY.get(front_label)
                simple_key = _IOC_FRONT_MAP.get(front_label)
                ioc_values = dict_indicators.get(dict_key, []) if dict_key else []
                if not simple_key or not ioc_values:
                    continue

                tasks.append(self._query_index(
                    base_url, headers, idx_name, simple_key, ioc_values,
                    search_field, output_fields, date_range, results,
                ))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _query_index(
        self, base_url, headers, idx_name, ioc_key, values,
        search_field, output_fields, date_range, results,
    ):
        fields = [search_field] if search_field else _IOC_FIELD_MAP.get(ioc_key, [])
        if not fields:
            return

        resolved_idx  = await _resolve_index_pattern(self.requester, base_url, headers, idx_name)
        source_fields = output_fields if output_fields else _DEFAULT_CONTEXT_FIELDS
        url = _proxy_url(base_url, resolved_idx)
        result_label = f"kibana:{idx_name}"   # label affiché = valeur saisie (nom/ID Data View ou pattern)

        for val in values:
            query = _build_es_query(val, fields, source_fields, date_range=date_range)
            data = await self.requester.post(url, json=query, headers=headers)

            hits_obj  = (data or {}).get("hits", {})
            total_raw = hits_obj.get("total", {})
            total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
            hits  = hits_obj.get("hits", [])

            matched_rows = []
            for h in hits[:200]:
                src = h.get("_source", {})
                row: Dict[str, Any] = {}
                ts = next((_nested_get(src, tf) for tf in _TIMESTAMP_FIELDS if _nested_get(src, tf)), None)
                if ts:
                    row["_time"] = str(ts)[:19]
                for of in (output_fields or []):
                    v = _nested_get(src, of)
                    if v:
                        row[of] = v
                if not output_fields:
                    for f in ["host.name", "source.ip", "destination.ip",
                              "user.name", "event.action", "rule.name"]:
                        v = _nested_get(src, f)
                        if v:
                            row[f.split(".")[-1]] = v
                matched_rows.append(row)

            results.setdefault(val, {})[result_label] = {
                "events": total,
                "rows":   matched_rows,
                # Lien de debug : à coller dans Kibana Dev Tools Console
                # (retirer le préfixe /api/console/proxy?path= et décoder l'URL).
                "link":   url,
            }


# ══════════════════════════════════════════════════════════════
# KibanaInstanceModule — Instance interne (enrichment, left_navbar)
# Calqué sur EsInstanceModule, mais via le proxy Kibana (/api/console/proxy)
# au lieu de l'API Elasticsearch directe.
# ══════════════════════════════════════════════════════════════

class KibanaInstanceModule(Module):
    """
    Instance Kibana interne configurée par l'utilisateur.
    Apparaît dans le left_navbar (Internal Sources) et alimente la vue
    enrichment, en passant par /api/console/proxy — utile quand l'accès
    direct à Elasticsearch est restreint mais Kibana est joignable.
    """

    src_type          = "internal"
    supported_types   = ["ip", "domain", "url", "hash"]
    icon              = "compass"
    # Basic Auth (ou clé API Kibana) sont des alternatives valides :
    # ne pas bloquer l'exécution sur l'absence de api_keys[mod_key].
    requires_api_key  = False

    def __init__(self, requester, instance_id: str, label: str):
        self.requester    = requester
        self._instance_id = instance_id
        self._label       = label
        self.name         = f"Kibana — {label}"
        self.description  = f"Internal Kibana instance (via console proxy): {label}"
        self.url          = ""

    def get_fields(self) -> Dict[str, Any]:
        iid = self._instance_id
        return {
            "key":            f"kibana_inst_{iid}",
            "name":           self.name,
            "description":    self.description,
            "type":           self.src_type,
            "icon":           self.icon,
            "url":            "",
            "supported_types": self.supported_types,
            "correlation":    [],
            "settings_fields": [
                {
                    "key":         f"kibana_inst_{iid}_url",
                    "type":        "url",
                    "label":       f"{self._label} — Kibana URL",
                    "placeholder": "https://kibana.corp:5601",
                },
                {
                    "key":         f"kibana_inst_{iid}_user",
                    "type":        "text",
                    "label":       f"{self._label} — Username (optional)",
                    "placeholder": "kibana_user",
                },
                {
                    "key":         f"kibana_inst_{iid}_pass",
                    "type":        "text",
                    "label":       f"{self._label} — Password (optional)",
                    "placeholder": "••••••••",
                },
            ],
        }

    def _f(self, indicator, name, field_type, value) -> Dict[str, Any]:
        return {
            "indicator":      indicator,
            "indicator_type": "ioc",
            "field_name":     name,
            "field_type":     field_type,
            "value":          value,
            "icon":           None,
            "link":           None,
            "max":            None,
        }

    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        iid      = self._instance_id
        base_url = (context.get(f"kibana_inst_{iid}_url") or "").rstrip("/")
        if not base_url:
            return []

        ioc_type   = context.get("ioc_type", "ip")
        indexes    = context.get(f"kibana_inst_{iid}_indexes") or []
        date_range = _date_filter(context.get("date_start"), context.get("date_end"))
        headers    = _build_kibana_headers({
            "api_key":     context.get(f"kibana_inst_{iid}") or context.get("api_key", ""),
            "kibana_user": context.get(f"kibana_inst_{iid}_user", ""),
            "kibana_pass": context.get(f"kibana_inst_{iid}_pass", ""),
        })

        front_types = _INTERNAL_TO_FRONT.get(ioc_type, [])
        matching = [
            idx for idx in indexes
            if not idx.get("ioc_type") or idx.get("ioc_type") in front_types
        ]

        # Fallback : pas d'index configuré → recherche sur * avec champs candidats
        if not matching:
            fallback_fields = _IOC_FIELD_MAP.get(ioc_type, [])
            if not fallback_fields:
                return []
            q = _build_es_query(indicator, fallback_fields, _DEFAULT_CONTEXT_FIELDS,
                                 date_range=date_range)
            data = await self.requester.post(
                _proxy_url(base_url, "*"), json=q, headers=headers,
            )
            return self._parse(indicator, data, "*", [])

        tasks = [
            self._query_enrich_index(indicator, ioc_type, idx_cfg, base_url, headers, date_range)
            for idx_cfg in matching
        ]
        results_nested = await asyncio.gather(*tasks, return_exceptions=True)
        merged = []
        for r in results_nested:
            if isinstance(r, list):
                merged.extend(r)
        return merged

    async def _query_enrich_index(
        self, indicator, ioc_type, idx_cfg, base_url, headers, date_range
    ) -> List[Dict]:
        idx_name      = (idx_cfg.get("name") or "").strip() or "*"
        search_field  = (idx_cfg.get("search_field") or "").strip()
        output_fields = [
            f.strip()
            for f in (idx_cfg.get("output_fields") or "").split(",")
            if f.strip()
        ]
        search_fields = [search_field] if search_field else _IOC_FIELD_MAP.get(ioc_type, [])
        if not search_fields:
            return []
        resolved_idx  = await _resolve_index_pattern(self.requester, base_url, headers, idx_name)
        source_fields = output_fields if output_fields else _DEFAULT_CONTEXT_FIELDS
        q = _build_es_query(indicator, search_fields, source_fields, date_range=date_range)
        data = await self.requester.post(
            _proxy_url(base_url, resolved_idx), json=q, headers=headers,
        )
        return self._parse(indicator, data, idx_name, output_fields)  # label affiché = valeur saisie

    def _parse(self, indicator, data, idx_label, output_fields) -> List[Dict]:
        if not data:
            return [self._f(indicator, f"[{idx_label}] In Elasticsearch (via Kibana)", "label-capsule", "Not found")]
        if data.get("error"):
            err = data["error"]
            reason = (err.get("reason") if isinstance(err, dict) else str(err)) or "unknown"
            return [self._f(indicator, f"[{idx_label}] Error", "label-capsule", reason[:120])]

        hits_obj  = data.get("hits", {})
        total_raw = hits_obj.get("total", {})
        total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
        if total == 0:
            return [self._f(indicator, f"[{idx_label}] In Elasticsearch (via Kibana)", "label-capsule", "Not found")]

        return _extract_hits(indicator, total, hits_obj.get("hits", []),
                             idx_label, output_fields, self._f)

    async def get_correlation(self, indicator, context): return []
    async def get_quotas(self, context):                 return {}
