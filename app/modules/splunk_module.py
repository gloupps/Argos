# app/modules/splunk_module.py
"""
Splunk SIEM module — PivotLens.

Credentials / extra_config keys :
  api_key              → Bearer token (ou user:pass pour Basic Auth)
  splunk_url           → Splunk base URL  (ex. https://splunk.corp:8089)
  splunk_indexes       → list of dicts [{id, name, ioc_type, output_fields}, ...]
                         stored in SecretStore as "siem_logsources_splunk"
  date_start           → ISO datetime string (ex. "2026-05-01T00:00")
  date_end             → ISO datetime string (ex. "2026-05-31T23:59")

IOC type values (ioc_type field) :
  "IP" | "Domain" | "URL" | "Hash-MD5" | "Hash-SHA1" | "Hash-SHA256"

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
    """Retourne (earliest, latest) au format Splunk ISO."""
    def _iso(dt: str) -> str:
        return dt.replace(" ", "T") if dt else ""

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
# IOC type → SPL search fields
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

    # Champs simples affichés dans Settings (URL + result key uniquement).
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

        indexes    = context.get("splunk_indexes") or []   # list[dict]

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
            output_fields = [
                f.strip()
                for f in (idx_cfg.get("output_fields") or "").split(",")
                if f.strip()
            ]
            ioc_key    = _IOC_FRONT_MAP.get(ioc_type_raw)
            ioc_values = dict_indicators.get(ioc_key, []) if ioc_key else []

            if not idx_name or not ioc_key or not ioc_values:
                continue

            tasks.append(
                self._query_index(
                    base, token,
                    idx_name, ioc_key, ioc_values,
                    output_fields, earliest, latest,
                    results,
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
    ) -> None:
        spl_fields  = _IOC_SPL_FIELDS.get(ioc_key, [])
        match_alias = _IOC_MATCH_ALIAS.get(ioc_key, "matched_value")
        idx_expr    = _index_expr(idx_name)
        prefix      = f"{idx_expr} " if idx_expr else ""

        # Clause de base : OR des valeurs sur tous les champs candidats
        base_filter = " OR ".join(
            f'{field}="{v}"'
            for field in spl_fields[:3]   # limiter pour ne pas exploser l'AQL
            for v in values
        )

        # eval matched = case(field="val","val", ..., true(), null())
        case_branches = " ".join(
            f'{field}="{v}", "{v}",'
            for field in spl_fields[:3]
            for v in values
        ).rstrip(",")

        # Colonnes output : _time + champs configurés par l'utilisateur
        table_fields = "_time"
        if output_fields:
            table_fields += ", " + ", ".join(output_fields)
        else:
            table_fields += ", host, user, src, dest"

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
    ) -> Optional[Dict]:
        url     = f"{base}/services/search/jobs"
        headers = self._auth_headers(token)
        payload = {
            "search":        f"search {spl}",
            "exec_mode":     "oneshot",
            "earliest_time": earliest,
            "latest_time":   latest,
            "count":         str(count),
            "output_mode":   "json",
        }
        return await self.requester.post(url, headers=headers, data=payload)

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
