# app/modules/splunk_module.py
"""
Splunk SIEM module — PivotLens.

Credentials / extra_config keys :
  api_key              → Bearer token (ou user:pass pour Basic Auth)
  splunk_url           → Splunk base URL  (ex. https://splunk.corp:8089)
  splunk_indexes       → list of dicts [{id, name, ioc_type, search_field, output_fields}, ...]
                         stored in SecretStore as "siem_logsources_splunk"
  date_start           → ISO datetime string (ex. "2026-05-01T00:00")
  date_end             → ISO datetime string (ex. "2026-05-31T23:59")

IOC type values (ioc_type field) :
  "IP" | "Domain" | "URL" | "Hash-MD5" | "Hash-SHA1" | "Hash-SHA256"

search_field (optional) :
  Champ SPL exact dans lequel rechercher la valeur de l'IOC.
  Si vide, les champs candidats hardcodés (_IOC_SPL_FIELDS) sont utilisés en OR.
  Ex : "src_ip", "destinationIP", "query", "sha256"

Each index entry generates one SPL search scoped to:
  - index=<name>  (or no index filter if name is "*" or empty)
  - the matching IOC field(s) via OR in the base search
  - the configured date range (earliest/latest)
  - table columns = _time + user-defined output_fields
"""

import asyncio
import base64
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .module import Module


# ─────────────────────────────────────────────────────────────
# SPL helpers
# ─────────────────────────────────────────────────────────────

def _time_range(date_start: str, date_end: str) -> Tuple[str, str]:
    """Retourne (earliest, latest) au format Splunk ISO (avec secondes)."""
    def _iso(dt: str) -> str:
        if not dt:
            return ""
        dt = dt.replace(" ", "T")
        # <input type="datetime-local"> envoie "YYYY-MM-DDTHH:MM" (pas de secondes) :
        # Splunk a besoin du format complet pour bien parser earliest/latest_time.
        if len(dt) == 16:  # "YYYY-MM-DDTHH:MM"
            dt += ":00"
        return dt

    earliest = _iso(date_start) if date_start else "-30d@d"
    latest   = _iso(date_end)   if date_end   else "now"
    return earliest, latest


def _index_expr(index: str) -> str:
    """
    Convertit "main,security" → '(index=main OR index=security)'.
    "*" ou vide → "" (pas de filtre d'index).
    """
    if not index or index.strip() in ("*", ""):
        return ""
    parts = [f"index={i.strip()}" for i in index.split(",") if i.strip()]
    return "(" + " OR ".join(parts) + ")" if parts else ""


def _spl_values(values: List[str]) -> str:
    """Formate une liste de valeurs en OR SPL : "v1" OR "v2" …"""
    return " OR ".join(f'"{v}"' for v in values)


# ─────────────────────────────────────────────────────────────
# IOC type → SPL search fields (fallback si search_field vide)
# ─────────────────────────────────────────────────────────────

# Maps internal IOC key → candidate SPL field names
_IOC_SPL_FIELDS: Dict[str, List[str]] = {
    "IPv4-Addr":       ["src", "dest", "src_ip", "dest_ip", "sourceIP", "destinationIP"],
    "Domain-Name":     ["query", "dns_query", "domain", "dest_host", "hostname"],
    "Url":             ["url", "http_url", "uri", "uri_path"],
    "StixFile-MD5":    ["md5", "file_hash_md5", "file_hash", "hash"],
    "StixFile-SHA1":   ["sha1", "file_hash_sha1", "file_hash", "hash"],
    "StixFile-SHA256": ["sha256", "file_hash_sha256", "file_hash", "hash"],
}

# Front-end label → internal IOC key
_IOC_FRONT_MAP: Dict[str, str] = {
    "IP":          "IPv4-Addr",
    "Domain":      "Domain-Name",
    "URL":         "Url",
    "Hash-MD5":    "StixFile-MD5",
    "Hash-SHA1":   "StixFile-SHA1",
    "Hash-SHA256": "StixFile-SHA256",
}

# eval matched_<type>=case(...) alias par type
_IOC_MATCH_ALIAS: Dict[str, str] = {
    "IPv4-Addr":       "matched_ip",
    "Domain-Name":     "matched_domain",
    "Url":             "matched_url",
    "StixFile-MD5":    "matched_hash",
    "StixFile-SHA1":   "matched_hash",
    "StixFile-SHA256": "matched_hash",
}


# ─────────────────────────────────────────────────────────────
# Module
# ─────────────────────────────────────────────────────────────

class SplunkModule(Module):

    name        = "Splunk"
    description = "Splunk SIEM — SPL search for IOC investigation"
    src_type    = "siem"
    icon        = "database"
    supported_types = ["ip", "domain", "hash", "url"]

    # Champs simples affichés dans Settings (URL uniquement).
    # Les Index sont gérés par SIEMInstances (siem_instances.js).
    settings_fields = [
        {
            "key":         "splunk_url",
            "type":        "url",
            "label":       "Splunk REST URL",
            "placeholder": "https://splunk.corp:8089",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "splunk"
        return base

    async def get_info(self, indicator, context):        return []
    async def get_correlation(self, indicator, context): return []
    async def get_quotas(self, context):                 return {}

    # ─────────────────────────────────────────────────────
    # PUBLIC — point d'entrée principal
    # ─────────────────────────────────────────────────────

    async def investigate(
        self,
        dict_indicators: Dict[str, List[str]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        base  = (context.get("splunk_url") or "").rstrip("/")
        token = context.get("api_key") or ""

        if not base or not token:
            return {}

        indexes = context.get("splunk_indexes") or []  # list[dict]

        earliest, latest = _time_range(
            context.get("date_start", ""),
            context.get("date_end",   ""),
        )

        # Compat : si le caller utilise encore "StixFile" groupé
        old_hashes = dict_indicators.get("StixFile", [])
        if old_hashes:
            dict_indicators.setdefault("StixFile-MD5",    []).extend(
                h for h in old_hashes if len(h) == 32)
            dict_indicators.setdefault("StixFile-SHA1",   []).extend(
                h for h in old_hashes if len(h) == 40)
            dict_indicators.setdefault("StixFile-SHA256", []).extend(
                h for h in old_hashes if len(h) == 64)

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

            # "— any —" (ioc_type_raw vide) → on matche sur TOUS les types
            # d'IOC présents dans le case, au lieu de skip silencieusement.
            if ioc_type_raw:
                ioc_keys = [_IOC_FRONT_MAP.get(ioc_type_raw)]
            else:
                ioc_keys = list(dict.fromkeys(_IOC_FRONT_MAP.values()))

            for ioc_key in ioc_keys:
                ioc_values = dict_indicators.get(ioc_key, []) if ioc_key else []
                if not ioc_key or not ioc_values:
                    continue

                tasks.append(
                    self._query_index(
                        base, token,
                        idx_name, ioc_key, ioc_values,
                        output_fields, earliest, latest,
                        results,
                        search_field=search_field,
                    )
                )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return results

    # ─────────────────────────────────────────────────────
    # Core query — 1 SPL per (index × ioc_type)
    # ─────────────────────────────────────────────────────

    async def _query_index(
        self,
        base: str,
        token: str,
        idx_name: str,
        ioc_key: str,
        values: List[str],
        output_fields: List[str],
        earliest: str,
        latest: str,
        results: Dict,
        search_field: str = "",
    ) -> None:
        # Résolution des champs de recherche :
        # - search_field non vide → champ unique explicite configuré par l'utilisateur
        # - sinon → liste de champs candidats hardcodés (fallback)
        if search_field:
            spl_fields = [search_field]
        else:
            spl_fields = _IOC_SPL_FIELDS.get(ioc_key, [])

        if not spl_fields:
            return

        match_alias = _IOC_MATCH_ALIAS.get(ioc_key, "matched_value")
        idx_expr    = _index_expr(idx_name)
        prefix      = f"{idx_expr} " if idx_expr else ""

        # Clause de base : OR des valeurs sur tous les champs retenus
        base_filter = " OR ".join(
            f'{field}="{v}"'
            for field in spl_fields
            for v in values
        )

        # eval matched = case(field="val","val", ..., true(), null())
        case_branches = " ".join(
            f'{field}="{v}", "{v}",'
            for field in spl_fields
            for v in values
        ).rstrip(",")

        # Colonnes output : _time + champs configurés par l'utilisateur
        if output_fields:
            table_fields = "_time, " + ", ".join(output_fields)
        else:
            table_fields = "_time, host, user, " + ", ".join(spl_fields[:2])

        spl = (
            f"{prefix}({base_filter}) "
            f"| eval {match_alias}=case({case_branches}, true(), null()) "
            f"| where isnotnull({match_alias}) "
            f"| table {match_alias}, {table_fields}"
        )

        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        # Distribuer par IOC
        result_label = f"splunk:{idx_name}"
        matched_map: Dict[str, List[Dict]] = {}
        for row in rows:
            key = str(row.get(match_alias, "")).lower()
            matched_map.setdefault(key, []).append(row)

        for val in values:
            val_rows = matched_map.get(val.lower(), [])
            results.setdefault(val, {})[result_label] = {
                "events": len(val_rows),
                "rows":   val_rows[:200],
                "link":   link,
            }

    # ─────────────────────────────────────────────────────
    # Auth
    # ─────────────────────────────────────────────────────

    def _auth_headers(self, token: str) -> Dict[str, str]:
        if ":" in token:
            encoded = base64.b64encode(token.encode()).decode()
            return {
                "Authorization": f"Basic {encoded}",
                "Content-Type":  "application/x-www-form-urlencoded",
            }
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/x-www-form-urlencoded",
        }

    # ─────────────────────────────────────────────────────
    # Core search executor (oneshot)
    # ─────────────────────────────────────────────────────

    async def _run_search(
        self,
        base: str,
        token: str,
        spl: str,
        earliest: str,
        latest: str,
        count: int = 500,
        poll_attempts: int = 15,
        poll_interval: float = 1.0,
    ) -> Optional[Dict]:
        url     = f"{base}/services/search/jobs"
        headers = self._auth_headers(token)
        payload = {
            "search":        f"search {spl}",
            "exec_mode":     "oneshot",
            "earliest_time": earliest,
            "latest_time":   latest,
            # Force le format de parsing pour earliest/latest_time : sans ça,
            # une instance Splunk avec un TIME_FORMAT custom (LDAP/locale) peut
            # rejeter ou mal interpréter la date envoyée par le front.
            "time_format":   "%Y-%m-%dT%H:%M:%S",
            "count":         str(count),
            "output_mode":   "json",
        }
        data = await self.requester.post(url, headers=headers, data=payload)

        # Cas standard "oneshot" : les résultats arrivent directement.
        if data and "results" in data:
            return data

        # Cas job asynchrone (certains gateways/proxies LDAP ne supportent
        # pas exec_mode=oneshot et renvoient une référence de job à poller,
        # ex. {"job_id": "...", "status": "started"} ou {"sid": "..."}).
        job_id = None
        if isinstance(data, dict):
            job_id = data.get("job_id") or data.get("sid") or data.get("id")
        if not job_id:
            return data

        return await self._poll_job(base, headers, job_id, count, poll_attempts, poll_interval)

    _DONE_STATES  = {"done", "completed", "finished", "succeeded", "success"}
    _WAIT_STATES  = {"started", "running", "queued", "parsing", "pending", "in_progress"}

    async def _poll_job(
        self, base: str, headers: Dict[str, str], job_id: str,
        count: int, poll_attempts: int, poll_interval: float,
    ) -> Optional[Dict]:
        status_url = f"{base}/services/search/jobs/{job_id}"

        for _ in range(poll_attempts):
            status_data = await self.requester.get(
                status_url, headers=headers, params={"output_mode": "json"}
            )
            if not status_data:
                return None

            # Si le statut est déjà accompagné des résultats (certains
            # wrappers custom les embarquent directement une fois "done").
            if "results" in status_data:
                return status_data

            state = self._extract_state(status_data)
            if state in self._DONE_STATES:
                break
            if state and state not in self._WAIT_STATES:
                # État inconnu (ex. "failed", "error") → on arrête de poller.
                return status_data

            await asyncio.sleep(poll_interval)
        else:
            # Timeout de polling atteint sans état "done" confirmé.
            return None

        # Job terminé → récupérer les résultats.
        results_url = f"{status_url}/results"
        return await self.requester.get(
            results_url,
            headers=headers,
            params={"output_mode": "json", "count": str(count)},
        )

    @staticmethod
    def _extract_state(data: Dict) -> str:
        """Cherche l'état du job dans les formats connus (custom gateway ou Splunk natif)."""
        for key in ("status", "state"):
            if isinstance(data.get(key), str):
                return data[key].lower()
        # Format Splunk natif : {"entry": [{"content": {"dispatchState": "DONE"}}]}
        entries = data.get("entry") or []
        if entries and isinstance(entries, list):
            content = entries[0].get("content", {})
            ds = content.get("dispatchState")
            if isinstance(ds, str):
                return ds.lower()
        return ""

    def _extract_rows(self, data: Optional[Dict], max_rows: int = 200) -> List[Dict]:
        if not data:
            return []
        results = data.get("results") or []
        return [
            {
                k: v
                for k, v in row.items()
                if not k.startswith("_") or k in ("_time", "_raw")
            }
            for row in results[:max_rows]
        ]

    def _make_link(self, base: str, spl: str, earliest: str, latest: str) -> str:
        q = urllib.parse.quote(f"search {spl}")
        return f"{base}/en-US/app/search/search?q={q}&earliest={earliest}&latest={latest}"
