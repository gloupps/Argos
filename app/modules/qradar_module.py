# app/modules/qradar_module.py
"""
QRadar SIEM module — PivotLens.

Credentials / extra_config keys :
  qradar                      → API token
  extra_qradar_url            → Console base URL  (ex. https://qradar.corp)
  extra_qradar_md5_sources    → logSourceIds for MD5   (comma-sep)
  extra_qradar_sha1_sources   → logSourceIds for SHA1  (comma-sep)
  extra_qradar_sha256_sources → logSourceIds for SHA256 (comma-sep, optional)
  extra_qradar_url_sources    → logSourceIds for URL searches (comma-sep, costly — optional)
  extra_qradar_result_key     → key name in result dict (default "qradar")
  extra_qradar_anonymize      → "true" to replace logSourceId with anonymized label
"""

import re
import asyncio
import urllib.parse
from typing import Any, Dict, List, Optional

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
    cleaned = {}
    for ioc, sources in results_by_ioc.items():
        filtered = {
            src: data
            for src, data in sources.items()
            if isinstance(data, dict) and data.get("events", 0) > 0
        }
        cleaned[ioc] = filtered
    return cleaned


# ─────────────────────────────────────────────────────────────
# AQL helpers
# ─────────────────────────────────────────────────────────────

def _fmt(values: List[str]) -> str:
    return ",".join(f"'{v}'" for v in values)


def _source_filter(ids: List[str]) -> str:
    return " OR ".join(f"logSourceId = '{i.strip()}'" for i in ids if i.strip())


def _time_clause(date_start: str, date_end: str) -> str:
    """START/STOP quand les deux dates sont fournies, sinon LAST 30 DAYS."""
    if date_start and date_end:
        ds = date_start.replace("T", " ").replace("Z", "")[:16]
        de = date_end.replace("T", " ").replace("Z", "")[:16]
        return f"START '{ds}' STOP '{de}'"
    if date_start:
        ds = date_start.replace("T", " ").replace("Z", "")[:16]
        return f"START '{ds}' STOP NOW"
    return "LAST 30 DAYS"


def _anonymize_rows(rows: List[Dict], field: str = "LogSource") -> List[Dict]:
    """Remplace les valeurs du champ LogSource par des labels anonymes."""
    mapping: Dict[str, str] = {}
    counter = 1
    out = []
    for row in rows:
        new_row = dict(row)
        val = new_row.get(field)
        if val:
            if val not in mapping:
                mapping[val] = f"LogSource-{counter:02d}"
                counter += 1
            new_row[field] = mapping[val]
        out.append(new_row)
    return out


# ─────────────────────────────────────────────────────────────
# Module
# ─────────────────────────────────────────────────────────────

class QRadarModule(Module):

    name        = "QRadar"
    description = "IBM QRadar — AQL event/flow search for IOC investigation"
    src_type    = "siem"
    icon        = "database"
    supported_types = ["ip", "domain", "hash", "url"]

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
        {
            "key":         "qradar_anonymize",
            "type":        "text",
            "label":       "Anonymize LogSource names (true/false)",
            "placeholder": "false",
        },
        {
            "key":         "qradar_md5_sources",
            "type":        "text",
            "label":       "MD5 — logSourceIds (comma-separated)",
            "placeholder": "18865,40100",
        },
        {
            "key":         "qradar_sha1_sources",
            "type":        "text",
            "label":       "SHA-1 — logSourceIds (comma-separated)",
            "placeholder": "879,5711",
        },
        {
            "key":         "qradar_sha256_sources",
            "type":        "text",
            "label":       "SHA-256 — logSourceIds (comma-separated, optional)",
            "placeholder": "",
        },
        {
            "key":         "qradar_url_sources",
            "type":        "text",
            "label":       "URL — logSourceIds (comma-sep, costly — leave empty to skip)",
            "placeholder": "",
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
    # PUBLIC
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

        # ── LogSource IDs ────────────────────────────────
        def _ids(key: str) -> List[str]:
            raw = context.get(key, "")
            return [x.strip() for x in raw.split(",") if x.strip()] if raw else []

        md5_ids    = _ids("qradar_md5_sources")
        sha1_ids   = _ids("qradar_sha1_sources")
        sha256_ids = _ids("qradar_sha256_sources")
        url_ids    = _ids("qradar_url_sources")   # empty → no logSource filter

        # ── Options ──────────────────────────────────────
        result_key = context.get("qradar_result_key") or "qradar"
        anonymize  = str(context.get("qradar_anonymize", "false")).lower() == "true"

        # ── Time clause ──────────────────────────────────
        tc = _time_clause(
            context.get("date_start", ""),
            context.get("date_end",   ""),
        )

        results: Dict[str, Any] = {}
        tasks = []

        ips     = dict_indicators.get("IPv4-Addr",       [])
        domains = dict_indicators.get("Domain-Name",     [])
        urls    = dict_indicators.get("Url",             [])
        md5s    = dict_indicators.get("StixFile-MD5",    [])
        sha1s   = dict_indicators.get("StixFile-SHA1",   [])
        sha256s = dict_indicators.get("StixFile-SHA256", [])

        # Compat : si le caller utilise encore "StixFile" groupé (ancien classify)
        old_hashes = dict_indicators.get("StixFile", [])
        if old_hashes:
            md5s    += [h for h in old_hashes if len(h) == 32]
            sha1s   += [h for h in old_hashes if len(h) == 40]
            sha256s += [h for h in old_hashes if len(h) == 64]

        if ips:                          tasks.append(self._query_ips    (base, token, ips,     tc, results, result_key, anonymize))
        if domains:                      tasks.append(self._query_domains(base, token, domains, tc, results, result_key, anonymize))
        if urls:                         tasks.append(self._query_urls   (base, token, urls,    tc, results, result_key, anonymize, url_ids))
        if md5s    and md5_ids:          tasks.append(self._query_md5    (base, token, md5s,    md5_ids,    tc, results, result_key, anonymize))
        if sha1s   and sha1_ids:         tasks.append(self._query_sha1   (base, token, sha1s,   sha1_ids,   tc, results, result_key, anonymize))
        if sha256s and sha256_ids:       tasks.append(self._query_sha256 (base, token, sha256s, sha256_ids, tc, results, result_key, anonymize))

        await asyncio.gather(*tasks, return_exceptions=True)
        return results

    # ─────────────────────────────────────────────────────
    # Query builders
    # ─────────────────────────────────────────────────────

    async def _query_ips(self, base, token, ips, tc, results, rkey, anon):
        fmt = _fmt(ips)
        flow_aql = f"""
SELECT "sourceIP","destinationIP",
       DATEFORMAT(firstPacketTime,'YYYY-MM-dd HH:mm') as 'firstPacketTime',
       "flowInterface" AS 'Interface', QIDNAME(qid) as 'EventName'
FROM flows
WHERE ("sourceIP" IN ({fmt}) OR "destinationIP" IN ({fmt}))
{tc}"""

        evt_aql = f"""
SELECT QIDNAME(qid) as 'EventName',
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "sourceIP","destinationIP",
       LOGSOURCENAME(logSourceId) AS 'LogSource'
FROM events
WHERE ("sourceIP" IN ({fmt}) OR "destinationIP" IN ({fmt}))
{tc}"""

        flow_rows, evt_rows = await asyncio.gather(
            self._run_aql(base, token, flow_aql),
            self._run_aql(base, token, evt_aql),
        )
        flow_rows = flow_rows or []
        evt_rows  = evt_rows  or []
        if anon:
            flow_rows = _anonymize_rows(flow_rows, "Interface")
            evt_rows  = _anonymize_rows(evt_rows,  "LogSource")

        for ip in ips:
            ip_flows = [r for r in flow_rows if r.get("sourceIP") == ip or r.get("destinationIP") == ip]
            ip_evts  = [r for r in evt_rows  if r.get("sourceIP") == ip or r.get("destinationIP") == ip]
            results.setdefault(ip, {})[rkey] = {
                "events":     len(ip_flows) + len(ip_evts),
                "event_rows": ip_evts[:200],
                "flows":      ip_flows[:200],
                "link":       self._event_link(base, evt_aql),
                "flow_link":  self._flow_link(base, flow_aql),
            }

    async def _query_domains(self, base, token, domains, tc, results, rkey, anon):
        aql = f"""
SELECT "DNS Query" AS 'DNS Query',
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "sourceIP","destinationIP",
       LOGSOURCENAME(logSourceId) AS 'LogSource', QIDNAME(qid) as 'EventName'
FROM events
WHERE "DNS Query" IN ({_fmt(domains)})
ORDER BY "startTime" DESC
{tc}"""
        rows = await self._run_aql(base, token, aql) or []
        if anon:
            rows = _anonymize_rows(rows, "LogSource")
        for d in domains:
            d_rows = [r for r in rows if r.get("DNS Query", "").lower() == d.lower()]
            results.setdefault(d, {})[rkey] = {
                "events": len(d_rows),
                "rows":   d_rows[:200],
                "link":   self._event_link(base, aql),
            }

    async def _query_urls(self, base, token, urls, tc, results, rkey, anon, src_ids: List[str]):
        in_vals    = []
        like_conds = []
        for u in urls:
            u_n = (u.replace("https://", "hxxps://")
                    .replace("http://",  "hxxp://")
                    .replace(".", "[dot]")
                    .replace("'", "\\'"))
            if "#" in u_n:
                like_conds.append(f'"Filename" LIKE \'{u_n.split("#")[0]}%\'')
            else:
                in_vals.append(f"'{u_n}'")

        parts = []
        if in_vals:    parts.append(f'"Filename" IN ({",".join(in_vals)})')
        if like_conds: parts.append("(" + " OR ".join(like_conds) + ")")

        if not parts:
            return

        # Filtre sur logsource si configuré, sinon pas de filtre
        src_clause = f"({_source_filter(src_ids)}) AND " if src_ids else ""

        aql = f"""
SELECT "Filename",
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "sourceIP","destinationIP",
       LOGSOURCENAME(logSourceId) AS 'LogSource', QIDNAME(qid) as 'EventName'
FROM events
WHERE {src_clause}({" OR ".join(parts)})
ORDER BY "startTime" DESC
{tc}"""
        rows = await self._run_aql(base, token, aql) or []
        if anon:
            rows = _anonymize_rows(rows, "LogSource")
        for u in urls:
            results.setdefault(u, {})[rkey] = {
                "events": len(rows),
                "rows":   rows[:200],
                "link":   self._event_link(base, aql),
            }

    async def _query_md5(self, base, token, md5s, src_ids, tc, results, rkey, anon):
        aql = f"""
SELECT LOGSOURCENAME(logSourceId) as 'LogSource',
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "Hostname","MD5 Hash" as 'MD5 Hash', QIDNAME(qid) as 'EventName'
FROM events
WHERE ({_source_filter(src_ids)})
  AND "MD5 Hash" IN ({_fmt(md5s)})
  AND "File Path" NOT ILIKE '%LNKProcessing%'
  AND "File Path" NOT ILIKE 'C:\\Program Files%'
  AND "Threat Name" NOT ILIKE '%KMSActivator%'
  AND "Threat Name" NOT ILIKE '%Application.Generic%'
  AND "Threat Name" NOT ILIKE '%KMS%'
ORDER BY "startTime" DESC
{tc}"""
        rows = await self._run_aql(base, token, aql) or []
        if anon:
            rows = _anonymize_rows(rows, "LogSource")
        for h in md5s:
            h_rows = [r for r in rows if r.get("MD5 Hash", "").upper() == h.upper()]
            results.setdefault(h, {})[rkey] = {
                "events": len(h_rows),
                "rows":   h_rows[:200],
                "link":   self._event_link(base, aql),
            }

    async def _query_sha1(self, base, token, sha1s, src_ids, tc, results, rkey, anon):
        aql = f"""
SELECT LOGSOURCENAME(logSourceId) as 'LogSource',
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "SHA1 Hash" as 'SHA1 Hash', "Hostname", QIDNAME(qid) as 'EventName'
FROM events
WHERE ({_source_filter(src_ids)})
  AND "SHA1 Hash" IN ({_fmt(sha1s)})
  AND "File Path" NOT ILIKE '%LNKProcessing%'
  AND "Threat Name" NOT ILIKE '%KMSAuto%'
ORDER BY "startTime" DESC
{tc}"""
        rows = await self._run_aql(base, token, aql) or []
        if anon:
            rows = _anonymize_rows(rows, "LogSource")
        for h in sha1s:
            h_rows = [r for r in rows if r.get("SHA1 Hash", "").upper() == h.upper()]
            results.setdefault(h, {})[rkey] = {
                "events": len(h_rows),
                "rows":   h_rows[:200],
                "link":   self._event_link(base, aql),
            }

    async def _query_sha256(self, base, token, sha256s, src_ids, tc, results, rkey, anon):
        aql = f"""
SELECT LOGSOURCENAME(logSourceId) as 'LogSource',
       DATEFORMAT(startTime,'YYYY-MM-dd HH:mm') as 'startTime',
       "SHA256 Hash" as 'SHA256 Hash', "Hostname", QIDNAME(qid) as 'EventName'
FROM events
WHERE ({_source_filter(src_ids)})
  AND "SHA256 Hash" IN ({_fmt(sha256s)})
  AND "File Path" NOT ILIKE '%LNKProcessing%'
  AND "Threat Name" NOT ILIKE '%KMSAuto%'
ORDER BY "startTime" DESC
{tc}"""
        rows = await self._run_aql(base, token, aql) or []
        if anon:
            rows = _anonymize_rows(rows, "LogSource")
        for h in sha256s:
            h_rows = [r for r in rows if r.get("SHA256 Hash", "").upper() == h.upper()]
            results.setdefault(h, {})[rkey] = {
                "events": len(h_rows),
                "rows":   h_rows[:200],
                "link":   self._event_link(base, aql),
            }

    # ─────────────────────────────────────────────────────
    # AQL execution
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

    def _event_link(self, base: str, aql: str) -> str:
        encoded = urllib.parse.quote(aql)
        return f"{base}/console/do/ariel/arielSearch?appName=EventViewer&pageId=EventList&searchMode=AQL&aql={encoded}"

    def _flow_link(self, base: str, aql: str) -> str:
        encoded = urllib.parse.quote(aql)
        return f"{base}/console/do/ariel/arielSearch?appName=Flows&pageId=FlowList&searchMode=AQL&aql={encoded}"
