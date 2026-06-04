# app/modules/elasticsearch_module.py
import asyncio
import base64
from typing import Any, Dict, List, Optional, Tuple
from .module import Module


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

_IOC_FRONT_MAP: Dict[str, str] = {
    "IP":          "ip",
    "Domain":      "domain",
    "URL":         "url",
    "Hash-MD5":    "hash",
    "Hash-SHA1":   "hash",
    "Hash-SHA256": "hash",
}

_INTERNAL_TO_FRONT: Dict[str, List[str]] = {
    "ip":     ["IP"],
    "domain": ["Domain"],
    "url":    ["URL"],
    "hash":   ["Hash-MD5", "Hash-SHA1", "Hash-SHA256"],
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
        "dll.hash.md5", "dll.hash.sha256",
        "hash.md5", "hash.sha1", "hash.sha256",
    ],
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
        "aggs": {
            "indices":   {"terms":         {"field": "_index", "size": 20}},
            "over_time": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}},
        },
    }


def _build_headers(context_or_cfg: Dict) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key  = (context_or_cfg.get("api_key") or "").strip()
    user     = (context_or_cfg.get("elasticsearch_user") or "").strip()
    password = (context_or_cfg.get("elasticsearch_pass") or "").strip()
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif user and password:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return headers


def _extract_hits(indicator: str, total: int, hits: List[Dict],
                  idx_label: str, output_fields: List[str],
                  f_fn) -> List[Dict]:
    """Transforme des hits ES en champs UI. f_fn = self._f d'un module."""
    prefix = f"[{idx_label}] "
    res = []
    res.append(f_fn(indicator, f"{prefix}In Elasticsearch", "label-capsule", "Yes ✓"))
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
# ElasticsearchModule  — SIEM Investigation (right_navbar)
# Même architecture que Splunk : investigate() multi-index
# ══════════════════════════════════════════════════════════════

class ElasticsearchModule(Module):
    """
    Module Elasticsearch SIEM — apparaît dans le right_navbar SIEM Investigation.
    Utilise investigate() avec des index configurés via SIEMInstances.
    Credentials / extra_config keys :
      api_key                   → ApiKey token
      elasticsearch_url         → URL du cluster
      elasticsearch_indexes     → [{id, name, ioc_type, search_field, output_fields}, ...]
                                   stocké dans SecretStore "siem_logsources_elasticsearch"
      elasticsearch_user / elasticsearch_pass → Basic Auth optionnel
      date_start / date_end     → filtre temporel
    """

    name        = "Elasticsearch"
    description = "Elasticsearch SIEM — DSL search across configured indices"
    src_type    = "siem"
    supported_types = ["ip", "domain", "url", "hash"]
    icon        = "database"
    url         = ""

    settings_fields = [
        {
            "key":         "elasticsearch_url",
            "type":        "url",
            "label":       "Elasticsearch URL",
            "placeholder": "https://elasticsearch.yourdomain.com:9200",
        },
        {
            "key":         "elasticsearch_user",
            "type":        "text",
            "label":       "Username (Basic Auth, optional)",
            "placeholder": "elastic",
        },
        {
            "key":         "elasticsearch_pass",
            "type":        "text",
            "label":       "Password (Basic Auth, optional)",
            "placeholder": "••••••••",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "elasticsearch"
        return base

    async def get_info(self, indicator, context):        return []
    async def get_correlation(self, indicator, context): return []
    async def get_quotas(self, context):
        base_url = (context.get("elasticsearch_url") or "").rstrip("/")
        if not base_url:
            return {"reachable": False, "reason": "missing_config"}
        data = await self.requester.get(
            f"{base_url}/_cluster/health",
            headers=_build_headers(context),
        )
        if not data:
            return {"reachable": False}
        return {
            "plan_type":       "siem",
            "reachable":       True,
            "cluster_name":    data.get("cluster_name", "unknown"),
            "status":          data.get("status", "unknown"),
            "number_of_nodes": data.get("number_of_nodes"),
        }

    # ── Point d'entrée SIEM ────────────────────────────────
    async def investigate(
        self,
        dict_indicators: Dict[str, List[str]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        base_url = (context.get("elasticsearch_url") or "").rstrip("/")
        if not base_url:
            return {}

        indexes    = context.get("elasticsearch_indexes") or []
        date_range = _date_filter(context.get("date_start"), context.get("date_end"))
        headers    = _build_headers(context)
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
            ioc_key    = _IOC_FRONT_MAP.get(ioc_type_raw)
            ioc_values = dict_indicators.get(ioc_key, []) if ioc_key else []
            if not idx_name or not ioc_key or not ioc_values:
                continue

            tasks.append(self._query_siem_index(
                base_url, headers, idx_name, ioc_key, ioc_values,
                search_field, output_fields, date_range, results,
            ))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return results

    async def _query_siem_index(
        self, base_url, headers, idx_name, ioc_key, values,
        search_field, output_fields, date_range, results,
    ):
        spl_fields = [search_field] if search_field else _IOC_FIELD_MAP.get(ioc_key, [])
        if not spl_fields:
            return

        source_fields = output_fields if output_fields else _DEFAULT_CONTEXT_FIELDS
        query = _build_es_query(
            values[0], spl_fields, source_fields, date_range=date_range
        )
        # Pour plusieurs valeurs, on fait une requête par valeur
        for val in values:
            q = _build_es_query(val, spl_fields, source_fields, date_range=date_range)
            data = await self.requester.post(
                f"{base_url}/{idx_name}/_search", json=q, headers=headers,
            )
            hits_obj  = (data or {}).get("hits", {})
            total_raw = hits_obj.get("total", {})
            total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
            hits  = hits_obj.get("hits", [])

            result_label = f"elasticsearch:{idx_name}"
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
                "link":   f"{base_url}/{idx_name}/_search",
            }


# ══════════════════════════════════════════════════════════════
# EsInstanceModule  — Instance interne (enrichment, left_navbar)
# Calqué sur ExternalMISPModule
# ══════════════════════════════════════════════════════════════

class EsInstanceModule(Module):
    """
    Instance Elasticsearch interne configurée par l'utilisateur.
    Apparaît dans le left_navbar (Internal Sources) et alimente la vue enrichment.
    Chaque instance possède ses propres index avec ioc_type / search_field / output_fields.
    """

    src_type        = "internal"
    supported_types = ["ip", "domain", "url", "hash"]
    icon            = "database"

    def __init__(self, requester, instance_id: str, label: str):
        self.requester    = requester
        self._instance_id = instance_id
        self._label       = label
        self.name         = f"Elasticsearch — {label}"
        self.description  = f"Internal Elasticsearch instance: {label}"
        self.url          = ""

    def get_fields(self) -> Dict[str, Any]:
        iid = self._instance_id
        return {
            "key":            f"es_inst_{iid}",
            "name":           self.name,
            "description":    self.description,
            "type":           self.src_type,
            "icon":           self.icon,
            "url":            "",
            "supported_types": self.supported_types,
            "correlation":    [],
            "settings_fields": [
                {
                    "key":         f"es_inst_{iid}_url",
                    "type":        "url",
                    "label":       f"{self._label} — URL",
                    "placeholder": "https://elasticsearch.corp:9200",
                },
                {
                    "key":         f"es_inst_{iid}_user",
                    "type":        "text",
                    "label":       f"{self._label} — Username (optional)",
                    "placeholder": "elastic",
                },
                {
                    "key":         f"es_inst_{iid}_pass",
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
        base_url = (context.get(f"es_inst_{iid}_url") or "").rstrip("/")
        if not base_url:
            return []

        ioc_type  = context.get("ioc_type", "ip")
        # Index configurés pour cette instance
        indexes   = context.get(f"es_inst_{iid}_indexes") or []
        date_range = _date_filter(context.get("date_start"), context.get("date_end"))
        headers   = _build_headers({
            "api_key":            context.get(f"es_inst_{iid}") or context.get("api_key", ""),
            "elasticsearch_user": context.get(f"es_inst_{iid}_user", ""),
            "elasticsearch_pass": context.get(f"es_inst_{iid}_pass", ""),
        })

        front_types = _INTERNAL_TO_FRONT.get(ioc_type, [])
        matching = [
            idx for idx in indexes
            if not idx.get("ioc_type") or idx.get("ioc_type") in front_types
        ]

        # Fallback : pas d'index → recherche sur * avec champs candidats
        if not matching:
            fallback_fields = _IOC_FIELD_MAP.get(ioc_type, [])
            if not fallback_fields:
                return []
            q = _build_es_query(indicator, fallback_fields, _DEFAULT_CONTEXT_FIELDS,
                                 date_range=date_range)
            data = await self.requester.post(
                f"{base_url}/*/_search", json=q, headers=headers,
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
        source_fields = output_fields if output_fields else _DEFAULT_CONTEXT_FIELDS
        q = _build_es_query(indicator, search_fields, source_fields, date_range=date_range)
        data = await self.requester.post(
            f"{base_url}/{idx_name}/_search", json=q, headers=headers,
        )
        return self._parse(indicator, data, idx_name, output_fields)

    def _parse(self, indicator, data, idx_label, output_fields) -> List[Dict]:
        if not data:
            return [self._f(indicator, f"[{idx_label}] In Elasticsearch", "label-capsule", "Not found")]
        if data.get("error"):
            reason = (data["error"].get("reason") or str(data["error"]))[:120]
            return [self._f(indicator, f"[{idx_label}] Error", "label-capsule", reason)]

        hits_obj  = data.get("hits", {})
        total_raw = hits_obj.get("total", {})
        total = total_raw.get("value", 0) if isinstance(total_raw, dict) else int(total_raw or 0)
        if total == 0:
            return [self._f(indicator, f"[{idx_label}] In Elasticsearch", "label-capsule", "Not found")]

        return _extract_hits(indicator, total, hits_obj.get("hits", []),
                             idx_label, output_fields, self._f)

    async def get_correlation(self, indicator, context): return []
    async def get_quotas(self, context):                 return {}
