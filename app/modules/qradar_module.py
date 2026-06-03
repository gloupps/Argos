# app/modules/qradar_module.py
"""
QRadar SIEM module — PivotLens.

Credentials / extra_config keys :
  api_key              → API token (SEC header)
  qradar_url           → Console base URL  (ex. https://qradar.corp)
  qradar_result_key    → key name in result dict (default "qradar")
  qradar_logsources    → list of dicts [{id, name, ioc_type, output_fields}, ...]
                         stored in SecretStore as "siem_logsources_qradar"
  date_start           → ISO datetime string (ex. "2026-05-01T00:00")
  date_end             → ISO datetime string (ex. "2026-05-31T23:59")

IOC type values (ioc_type field) :
  "IP" | "Domain" | "URL" | "Hash-MD5" | "Hash-SHA1" | "Hash-SHA256"

Each logsource entry generates one AQL query scoped to:
  - LOGSOURCENAME(logSourceId) ILIKE '<name>%'
  - the matching IOC field(s)
  - the configured date range (START/STOP always used when both dates provided)
  - SELECT columns = startTime + LogSource + user-defined output_fields
"""

import re
import asyncio
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .module import Module


# ─────────────────────────────────────────────────────────────
# IOC helpers
# ─────────────────────────────────────────────────────────────

def _detect_indicator_type(value: str) -> Optional[str]:
    value = value.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return "Url"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
        return "IPv4-Addr"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "StixFile-MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "StixFile-SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "StixFile-SHA256"
    if re.fullmatch(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", value):
        return "Domain-Name"
    return None


def classify_indicators(indicators: List[str]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for value in indicators:
        ioc_type = _detect_indicator_type(value)
        if not ioc_type:
            continue
        result.setdefault(ioc_type, []).append(value)
    for k in result:
        result[k] = list(set(result[k]))
    return result


def clean_results(results_by_ioc: Dict[str, Any]) -> Dict[str, Any]:
    """Supprime les entrées sans événements."""
    cleaned = {}
    for ioc, sources in results_by_ioc.items():
        filtered = {
            src: data
            for src, data in sources.items()
            if isinstance(data, dict) and data.get("events", 0) > 0
        }
        if filtered:
            cleaned[ioc] = filtered
    return cleaned


# ─────────────────────────────────────────────────────────────
# AQL helpers
# ─────────────────────────────────────────────────────────────

def _fmt(values: List[str]) -> str:
    return ",".join(f"'{v}'" for v in values)


def _time_clause(date_start: str, date_end: str) -> str:
    """
    Génère la clause temporelle AQL.
    - START + STOP si les deux dates sont fournies (priorité absolue).
    - START seul si uniquement date_start.
    - LAST 30 DAYS sinon.
    """
    def _norm(dt: str) -> str:
        return dt.replace("T", " ").replace("Z", "")[:16]

    if date_start and date_end:
        return f"START '{_norm(date_start)}' STOP '{_norm(date_end)}'"
    if date_start:
        return f"START '{_norm(date_start)}' STOP NOW"
    if date_end:
        return f"START '2000-01-01 00:00' STOP '{_norm(date_end)}'"
    return "LAST 30 DAYS"


# ─────────────────────────────────────────────────────────────
# IOC type → AQL search fields + table alias
# ─────────────────────────────────────────────────────────────

# Maps internal IOC key → (search_fields_tuple, match_alias)
#   search_fields_tuple : champs AQL utilisés dans le WHERE
#   match_alias         : alias utilisé pour retrouver la valeur dans chaque row
_IOC_AQL_MAP: Dict[str, Tuple[Tuple[str, ...], str]] = {
    "IPv4-Addr":      (("sourceIP", "destinationIP"), "sourceIP"),
    "Domain-Name":    (("DNS Query",),                "DNS Query"),
    "Url":            (("Filename",),                 "Filename"),
    "StixFile-MD5":   (("MD5 Hash",),                 "MD5 Hash"),
    "StixFile-SHA1":  (("SHA1 Hash",),                "SHA1 Hash"),
    "StixFile-SHA256":(("SHA256 Hash",),              "SHA256 Hash"),
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


# ─────────────────────────────────────────────────────────────
# Module
# ─────────────────────────────────────────────────────────────

class QRadarModule(Module):

    name        = "QRadar"
    description = "IBM QRadar — AQL event/flow search for IOC investigation"
    src_type    = "siem"
    icon        = "database"
    supported_types = ["ip", "domain", "hash", "url"]

    # Champs simples affichés dans Settings (URL + result key uniquement).
    # Les LogSources sont gérés par SIEMInstances (siem_instances.js).
    settings_fields = [
        {
            "key":         "qradar_url",
            "type":        "url",
            "label":       "QRadar Console URL",
            "placeholder": "https://qradar.corp",
        },
        {
            "key":         "qradar_result_key",
            "type":        "text",
            "label":       "Result key name (default: qradar)",
            "placeholder": "qradar",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "qradar"
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
        base  = (context.get("qradar_url") or "").rstrip("/")
        token = context.get("api_key") or ""

        if not base or not token:
            return {}

        result_key  = context.get("qradar_result_key") or "qradar"
        logsources  = context.get("qradar_logsources") or []   # list[dict]
        tc          = _time_clause(
            context.get("date_start", ""),
            context.get("date_end",   ""),
        )

        # Compat : si le caller utilise encore "StixFile" groupé (ancien classify)
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

        for src in logsources:
            src_name      = (src.get("name") or "").strip()
            ioc_type_raw  = src.get("ioc_type") or ""
            output_fields = [
                f.strip()
                for f in (src.get("output_fields") or "").split(",")
                if f.strip()
            ]
            ioc_key   = _IOC_FRONT_MAP.get(ioc_type_raw)
            ioc_values = dict_indicators.get(ioc_key, []) if ioc_key else []

            if not src_name or not ioc_key or not ioc_values:
                continue

            tasks.append(
                self._query_logsource(
                    base, token,
                    src_name, ioc_key, ioc_values,
                    output_fields, tc,
                    results, result_key,
                )
            )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return clean_results(results)

    # ─────────────────────────────────────────────────────
    # Core query — 1 AQL per (logsource × ioc_type)
    # ─────────────────────────────────────────────────────

    async def _query_logsource(
        self,
        base: str,
        token: str,
        src_name: str,
        ioc_key: str,
        values: List[str],
        output_fields: List[str],
        tc: str,
        results: Dict,
        rkey: str,
    ) -> None:
        aql_meta = _IOC_AQL_MAP.get(ioc_key)
        if not aql_meta:
            return

        search_fields, match_alias = aql_meta

        # ── SELECT columns ─────────────────────────────
        always = [
            "LOGSOURCENAME(logSourceId) as 'LogSource'",
            "DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime'",
        ]
        # Ajouter les search_fields s'ils ne sont pas déjà dans output_fields
        base_fields = list(search_fields)
        extra = [
            f'"{f}"' for f in output_fields
            if f not in ("LogSource", "startTime") + search_fields
        ]
        select_parts = always + [f'"{f}"' for f in base_fields] + extra
        select_clause = ", ".join(select_parts)

        # ── WHERE IOC ──────────────────────────────────
        fmt_vals = _fmt(values)
        if len(search_fields) == 2:
            # IP : source OU destination
            where_ioc = (
                f'("{search_fields[0]}" IN ({fmt_vals}) '
                f'OR "{search_fields[1]}" IN ({fmt_vals}))'
            )
        else:
            where_ioc = f'"{search_fields[0]}" IN ({fmt_vals})'

        # ── WHERE LogSource ────────────────────────────
        safe_name = src_name.replace("'", "\\'")
        where_src = f"LOGSOURCENAME(logSourceId) ILIKE '{safe_name}%'"

        aql = (
            f"SELECT {select_clause} "
            f"FROM events "
            f"WHERE {where_src} "
            f"  AND {where_ioc} "
            f"ORDER BY startTime DESC "
            f"{tc}"
        )

        rows = await self._run_aql(base, token, aql) or []

        # ── Distribuer par IOC ────────────────────────
        result_label = f"{rkey}:{src_name}"
        for val in values:
            if ioc_key == "IPv4-Addr":
                # IP peut apparaître dans src ou dst
                val_rows = [
                    r for r in rows
                    if r.get("sourceIP") == val or r.get("destinationIP") == val
                ]
            else:
                val_rows = [
                    r for r in rows
                    if str(r.get(match_alias, "")).lower() == val.lower()
                ]
            results.setdefault(val, {})[result_label] = {
                "events": len(val_rows),
                "rows":   val_rows[:200],
                "link":   self._event_link(base, aql),
            }

    # ─────────────────────────────────────────────────────
    # AQL execution (polling)
    # ─────────────────────────────────────────────────────

    async def _run_aql(self, base: str, token: str, aql: str) -> Optional[List[Dict]]:
        headers = {"SEC": token, "Content-Type": "application/json"}
        encoded = urllib.parse.quote(aql)

        submit = await self.requester.post(
            f"{base}/api/ariel/searches?query_expression={encoded}",
            headers=headers,
        )
        if not submit:
            return None
        search_id = submit.get("search_id")
        if not search_id:
            return None

        status_url = f"{base}/api/ariel/searches/{search_id}"
        for _ in range(60):
            await asyncio.sleep(2)
            status = await self.requester.get(status_url, headers=headers)
            if not status:
                return None
            if status.get("status") in ("COMPLETED", "FAILED", "CANCELED"):
                break

        if status.get("status") != "COMPLETED":
            return None

        results_url = f"{base}/api/ariel/searches/{search_id}/results"
        data = await self.requester.get(results_url, headers=headers)
        if not data:
            return None
        return data.get("events") or data.get("flows") or []

    # ─────────────────────────────────────────────────────
    # Link builders
    # ─────────────────────────────────────────────────────

    def _event_link(self, base: str, aql: str) -> str:
        encoded = urllib.parse.quote(aql)
        return (
            f"{base}/console/do/ariel/arielSearch"
            f"?appName=EventViewer&pageId=EventList&searchMode=AQL&aql={encoded}"
        )
