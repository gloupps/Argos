# app/modules/elasticsearch_module.py
import asyncio
from typing import List, Dict, Any
from .module import Module


# ──────────────────────────────────────────────────────────────
# Mapping IOC type → champs Elasticsearch à interroger
# ──────────────────────────────────────────────────────────────
_IOC_FIELD_MAP: Dict[str, List[str]] = {
    "ip": [
        "src_ip", "dst_ip", "ip", "source.ip", "destination.ip",
        "host.ip", "client.ip", "server.ip", "network.forwarded_ip",
        "related.ip",
    ],
    "domain": [
        "domain", "dns.question.name", "dns.answers.data",
        "url.domain", "host.name", "source.domain", "destination.domain",
        "related.hosts",
    ],
    "url": [
        "url.full", "url.original", "http.request.referrer",
        "event.url", "url",
    ],
    "hash": [
        "file.hash.md5", "file.hash.sha1", "file.hash.sha256",
        "process.hash.md5", "process.hash.sha1", "process.hash.sha256",
        "dll.hash.md5", "dll.hash.sha256",
        "hash.md5", "hash.sha1", "hash.sha256",
    ],
}

# Champs de timestamp courants (premier trouvé utilisé pour tri)
_TIMESTAMP_FIELDS = ["@timestamp", "event.created", "timestamp", "time"]

# Champs utiles à extraire pour afficher le contexte d'un hit
_CONTEXT_FIELDS = [
    "@timestamp", "event.created",
    "source.ip", "destination.ip", "src_ip", "dst_ip",
    "url.full", "url.original",
    "host.name", "user.name", "process.name", "process.executable",
    "file.path", "file.name",
    "event.action", "event.category", "event.type", "event.outcome",
    "rule.name", "rule.description", "alert.severity",
    "winlog.event_id", "event.code",
    "dns.question.name", "dns.answers.data",
    "message",
]


class ElasticsearchModule(Module):
    """
    Module Elasticsearch interne — qualification IOC.

    Interroge un cluster Elasticsearch (ou OpenSearch compatible)
    via l'API REST _search pour rechercher un indicateur dans les
    index configurés.

    Paramètres attendus dans le contexte (settings_fields) :
        - api_key            : clé API Elasticsearch (ou token Bearer)
        - elasticsearch_url  : URL du cluster (ex. https://es.corp:9200)
        - elasticsearch_index: pattern d'index à interroger (ex. logs-*,winlogbeat-*)
        - elasticsearch_user : (optionnel) login HTTP Basic
        - elasticsearch_pass : (optionnel) mot de passe HTTP Basic

    Fonctionnement :
        Pour chaque type IOC, construit une requête multi_match sur
        les champs pertinents, récupère les N premiers hits, et restitue :
          - un compteur de hits totaux
          - les index touchés
          - un timestamp premier/dernier hit
          - un aperçu des N hits les plus récents (champs de contexte)
    """

    name = "Elasticsearch"
    description = "Internal SIEM/log search — IOC lookup across configured indices"
    src_type = "internal"
    supported_types = ["ip", "domain", "url", "hash"]
    icon = "database"
    url = ""  # défini à l'exécution depuis les settings

    settings_fields = [
        {
            "key": "elasticsearch_url",
            "type": "url",
            "label": "Elasticsearch URL",
            "placeholder": "https://elasticsearch.yourdomain.com:9200",
        },
        {
            "key": "elasticsearch_index",
            "type": "text",
            "label": "Index pattern",
            "placeholder": "logs-*,winlogbeat-*,filebeat-*",
        },
        {
            "key": "elasticsearch_user",
            "type": "text",
            "label": "Username (Basic Auth, optional)",
            "placeholder": "elastic",
        },
        {
            "key": "elasticsearch_pass",
            "type": "text",
            "label": "Password (Basic Auth, optional)",
            "placeholder": "••••••••",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_fields  — surcharge pour fixer la clé "elasticsearch"
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "elasticsearch"
        return base

    # ──────────────────────────────────────────────────────
    # get_info  — qualification IOC
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        cfg = self._build_config(context)
        if not cfg:
            return []

        ioc_type = context.get("ioc_type", "ip")
        fields = _IOC_FIELD_MAP.get(ioc_type, [])
        if not fields:
            return []

        query = self._build_query(indicator, fields, size=10)
        url = f"{cfg['url']}/{cfg['index']}/_search"

        data = await self.requester.post(
            url,
            json=query,
            headers=self._build_headers(cfg),
        )
        if not data:
            return [self._f(indicator, "In Elasticsearch", "label-capsule", "Not found")]

        # Erreur retournée par ES (ex: index introuvable)
        if data.get("error"):
            reason = (data["error"].get("reason") or str(data["error"]))[:120]
            return [self._f(indicator, "Elasticsearch Error", "label-capsule", reason)]

        hits_obj = data.get("hits", {})
        total_raw = hits_obj.get("total", {})
        total = (
            total_raw.get("value", 0)
            if isinstance(total_raw, dict)
            else int(total_raw or 0)
        )

        if total == 0:
            return [self._f(indicator, "In Elasticsearch", "label-capsule", "Not found")]

        hits = hits_obj.get("hits", [])
        return self._extract_fields(indicator, total, hits)

    # ──────────────────────────────────────────────────────
    # get_correlation  — désactivé (qualification seulement)
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        return []

    # ──────────────────────────────────────────────────────
    # get_quotas  — health check du cluster
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self._build_config(context)
        if not cfg:
            return {"reachable": False, "reason": "missing_config"}

        data = await self.requester.get(
            f"{cfg['url']}/_cluster/health",
            headers=self._build_headers(cfg),
        )
        if not data:
            return {"reachable": False}

        return {
            "plan_type": "internal",
            "reachable": True,
            "cluster_name": data.get("cluster_name", "unknown"),
            "status": data.get("status", "unknown"),
            "number_of_nodes": data.get("number_of_nodes"),
            "active_shards": data.get("active_shards"),
        }

    # ──────────────────────────────────────────────────────
    # _build_config  — valide et rassemble la config
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _build_config(context: Dict[str, Any]) -> Dict[str, Any] | None:
        url = context.get("elasticsearch_url", "").rstrip("/")
        index = context.get("elasticsearch_index", "").strip() or "*"

        # api_key = token Bearer (prioritaire) ou Basic Auth
        api_key = context.get("api_key", "").strip()
        user = context.get("elasticsearch_user", "").strip()
        password = context.get("elasticsearch_pass", "").strip()

        if not url:
            return None

        return {
            "url": url,
            "index": index,
            "api_key": api_key,
            "user": user,
            "password": password,
        }

    # ──────────────────────────────────────────────────────
    # _build_headers  — construit les headers HTTP
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _build_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}

        if cfg.get("api_key"):
            headers["Authorization"] = f"ApiKey {cfg['api_key']}"
        elif cfg.get("user") and cfg.get("password"):
            import base64
            token = base64.b64encode(
                f"{cfg['user']}:{cfg['password']}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"

        return headers

    # ──────────────────────────────────────────────────────
    # _build_query  — construit la requête DSL Elasticsearch
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _build_query(indicator: str, fields: List[str], size: int = 10) -> Dict:
        """
        Construit une requête ES :
          - should = multi_match sur tous les champs candidats
          - trié par @timestamp desc pour avoir les hits les plus récents en premier
        """
        return {
            "size": size,
            "query": {
                "bool": {
                    "should": [
                        {
                            "multi_match": {
                                "query": indicator,
                                "fields": fields,
                                "type": "phrase",
                            }
                        },
                        # Terme exact en supplément (pour les champs keyword)
                        {
                            "bool": {
                                "should": [
                                    {"term": {f"{field}.keyword": indicator}}
                                    for field in fields
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            },
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "_source": _CONTEXT_FIELDS,
            "aggs": {
                "indices": {
                    "terms": {"field": "_index", "size": 20}
                },
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "day",
                    }
                },
            },
        }

    # ──────────────────────────────────────────────────────
    # _extract_fields  — transforme les hits en champs UI
    # ──────────────────────────────────────────────────────
    def _extract_fields(
        self,
        indicator: str,
        total: int,
        hits: List[Dict],
    ) -> List[Dict[str, Any]]:
        res = []

        # ── Présence confirmée ────────────────────────────
        res.append(self._f(indicator, "In Elasticsearch", "label-capsule", "Yes ✓"))
        res.append(self._f(indicator, "Total Hits", "label-capsule", str(total)))

        # ── Index touchés ─────────────────────────────────
        index_names = sorted({h.get("_index", "") for h in hits if h.get("_index")})
        if index_names:
            res.append(self._f(indicator, "Indices", "list", index_names[:10]))

        # ── Dates premier / dernier hit ───────────────────
        timestamps = []
        for h in hits:
            src = h.get("_source", {})
            for tf in _TIMESTAMP_FIELDS:
                ts = _nested_get(src, tf)
                if ts:
                    timestamps.append(str(ts)[:19])
                    break

        timestamps_sorted = sorted(timestamps)
        if timestamps_sorted:
            res.append(
                self._f(indicator, "First Seen", "label-capsule", timestamps_sorted[0])
            )
            res.append(
                self._f(indicator, "Last Seen", "label-capsule", timestamps_sorted[-1])
            )

        # ── Aperçu des hits (champs de contexte) ──────────
        summaries = []
        for h in hits[:5]:
            src = h.get("_source", {})
            parts = []

            ts = None
            for tf in _TIMESTAMP_FIELDS:
                ts = _nested_get(src, tf)
                if ts:
                    break
            if ts:
                parts.append(str(ts)[:19])

            for field in [
                "host.name", "source.ip", "destination.ip",
                "user.name", "process.name", "event.action",
                "rule.name", "dns.question.name", "event.code",
            ]:
                val = _nested_get(src, field)
                if val:
                    label = field.split(".")[-1]
                    parts.append(f"{label}={val}")

            msg = _nested_get(src, "message")
            if msg and isinstance(msg, str):
                parts.append(msg[:120])

            if parts:
                summaries.append(" | ".join(str(p) for p in parts))

        if summaries:
            res.append(self._f(indicator, "Recent Events", "list", summaries))

        # ── Hosts observés ────────────────────────────────
        hosts = list({
            _nested_get(h.get("_source", {}), "host.name")
            for h in hits
            if _nested_get(h.get("_source", {}), "host.name")
        })
        if hosts:
            res.append(self._f(indicator, "Hosts Observed", "list", sorted(hosts)[:10]))

        # ── Users observés ────────────────────────────────
        users = list({
            _nested_get(h.get("_source", {}), "user.name")
            for h in hits
            if _nested_get(h.get("_source", {}), "user.name")
        })
        if users:
            res.append(self._f(indicator, "Users Observed", "list", sorted(users)[:10]))

        # ── Process names observés ────────────────────────
        procs = list({
            _nested_get(h.get("_source", {}), "process.name")
            for h in hits
            if _nested_get(h.get("_source", {}), "process.name")
        })
        if procs:
            res.append(
                self._f(indicator, "Processes Observed", "list", sorted(procs)[:10])
            )

        return res

    # ──────────────────────────────────────────────────────
    # _f  — helper construction d'un champ UI
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _f(
        indicator: str,
        name: str,
        field_type: str,
        value: Any,
        max_: int | None = None,
    ) -> Dict[str, Any]:
        return {
            "indicator": indicator,
            "indicator_type": "ioc",
            "field_name": name,
            "field_type": field_type,
            "value": value,
            "icon": None,
            "link": None,
            "max": max_,
        }


# ──────────────────────────────────────────────────────────────
# Helper — accès à un champ dot-notation dans un dict imbriqué
# ──────────────────────────────────────────────────────────────
def _nested_get(obj: Dict, path: str) -> Any:
    """
    Retourne la valeur de obj[a][b][c] pour un chemin "a.b.c".
    Retourne None si le chemin n'existe pas.
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current
