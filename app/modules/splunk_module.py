# app/modules/splunk_module.py
"""
Splunk SIEM module — PivotLens.

Credentials / extra_config keys :
  splunk                    → Bearer token (ou user:pass en Basic Auth)
  extra_splunk_url          → Splunk base URL  (ex. https://splunk.corp:8089)
  extra_splunk_index        → index par défaut (ex. "main,security", défaut "*")
  extra_splunk_index_ip     → index(es) pour les IP      (override)
  extra_splunk_index_domain → index(es) pour les domaines (override)
  extra_splunk_index_url    → index(es) pour les URLs     (override)
  extra_splunk_index_hash   → index(es) pour les hashes   (override)
  extra_splunk_result_key   → nom de la clé dans les résultats (défaut "splunk")
  extra_splunk_earliest     → override earliest (ex. "-30d@d")
  extra_splunk_latest       → override latest   (ex. "now")

Stratégie :
  - Une seule SPL groupée par type d'IOC (eval matched_X + stats … by matched_X).
  - Chaque type peut avoir ses propres index(es), avec fallback sur splunk_index.
  - Résultats normalisés : { ioc_value: { <result_key>: { events, rows, link } } }
"""

import asyncio
import base64
import urllib.parse
from typing import Any, Dict, List, Optional
from .module import Module


# ─────────────────────────────────────────────────────────────
# Helpers SPL
# ─────────────────────────────────────────────────────────────

def _time_range(date_start: str, date_end: str):
    """Retourne (earliest, latest) au format Splunk."""
    def _iso(dt: str) -> str:
        return dt.replace(" ", "T") if dt else ""

    earliest = _iso(date_start) if date_start else "-30d@d"
    latest   = _iso(date_end)   if date_end   else "now"
    return earliest, latest


def _index_expr(index: str) -> str:
    """Convertit "main,security" → '(index=main OR index=security)'.
       "*" ou vide → "" (pas de filtre d'index)."""
    if not index or index.strip() == "*":
        return ""
    parts = [f"index={i.strip()}" for i in index.split(",") if i.strip()]
    if not parts:
        return ""
    return "(" + " OR ".join(parts) + ")"


def _spl_values(values: List[str]) -> str:
    """Formate une liste de valeurs en OR SPL : "v1" OR "v2" …"""
    return " OR ".join(f'"{v}"' for v in values)


# ─────────────────────────────────────────────────────────────
# Module
# ─────────────────────────────────────────────────────────────

class SplunkModule(Module):

    name        = "Splunk"
    description = "Splunk SIEM — grouped SPL search for IOC investigation"
    src_type    = "siem"
    icon        = "database"
    supported_types = ["ip", "domain", "hash", "url"]

    settings_fields = [
        {
            "key":         "splunk_url",
            "type":        "url",
            "label":       "Splunk REST URL",
            "placeholder": "https://splunk.corp:8089",
        },
        {
            "key":         "splunk_result_key",
            "type":        "text",
            "label":       "Result key name (default: splunk)",
            "placeholder": "splunk",
        },
        {
            "key":         "splunk_index",
            "type":        "text",
            "label":       "Default index(es) (comma-separated, * = all)",
            "placeholder": "main,security",
        },
        {
            "key":         "splunk_index_ip",
            "type":        "text",
            "label":       "Index(es) for IP lookups (overrides default)",
            "placeholder": "",
        },
        {
            "key":         "splunk_index_domain",
            "type":        "text",
            "label":       "Index(es) for Domain lookups (overrides default)",
            "placeholder": "",
        },
        {
            "key":         "splunk_index_url",
            "type":        "text",
            "label":       "Index(es) for URL lookups (overrides default)",
            "placeholder": "",
        },
        {
            "key":         "splunk_index_hash",
            "type":        "text",
            "label":       "Index(es) for Hash lookups (overrides default)",
            "placeholder": "",
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
    # PUBLIC
    # ─────────────────────────────────────────────────────

    async def investigate(
        self,
        dict_indicators: Dict[str, List[str]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        base      = (context.get("splunk_url") or "").rstrip("/")
        token     = context.get("api_key") or ""

        if not base or not token:
            return {}

        default_index = context.get("splunk_index") or "*"
        result_key    = context.get("splunk_result_key") or "splunk"

        earliest, latest = _time_range(
            context.get("date_start", ""),
            context.get("date_end",   ""),
        )

        def _idx(type_key: str) -> str:
            return context.get(f"splunk_index_{type_key}") or default_index

        results: Dict[str, Any] = {}
        tasks = []

        ips     = dict_indicators.get("IPv4-Addr",       [])
        domains = dict_indicators.get("Domain-Name",     [])
        urls    = dict_indicators.get("Url",             [])
        # Support both old "StixFile" and new split keys
        hashes  = list(set(
            dict_indicators.get("StixFile",        []) +
            dict_indicators.get("StixFile-MD5",    []) +
            dict_indicators.get("StixFile-SHA1",   []) +
            dict_indicators.get("StixFile-SHA256", [])
        ))

        if ips:     tasks.append(self._query_ips    (base, token, ips,     _idx("ip"),     earliest, latest, result_key, results))
        if domains: tasks.append(self._query_domains(base, token, domains, _idx("domain"), earliest, latest, result_key, results))
        if urls:    tasks.append(self._query_urls   (base, token, urls,    _idx("url"),    earliest, latest, result_key, results))
        if hashes:  tasks.append(self._query_hashes (base, token, hashes,  _idx("hash"),   earliest, latest, result_key, results))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return results

    # ─────────────────────────────────────────────────────
    # Auth
    # ─────────────────────────────────────────────────────

    def _auth_headers(self, token: str) -> Dict[str, str]:
        if ":" in token:
            encoded = base64.b64encode(token.encode()).decode()
            return {"Authorization": f"Basic {encoded}", "Content-Type": "application/x-www-form-urlencoded"}
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"}

    # ─────────────────────────────────────────────────────
    # Core search executor
    # ─────────────────────────────────────────────────────

    async def _run_search(self, base: str, token: str, spl: str, earliest: str, latest: str, count: int = 500) -> Optional[Dict]:
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
            {k: v for k, v in row.items() if not k.startswith("_") or k in ("_time", "_raw")}
            for row in results[:max_rows]
        ]

    def _make_link(self, base: str, spl: str, earliest: str, latest: str) -> str:
        q = urllib.parse.quote(f"search {spl}")
        return f"{base}/en-US/app/search/search?q={q}&earliest={earliest}&latest={latest}"

    # ─────────────────────────────────────────────────────
    # Grouped query builders — 1 SPL per IOC type
    # ─────────────────────────────────────────────────────

    async def _query_ips(self, base, token, ips, index, earliest, latest, rkey, results):
        idx    = _index_expr(index)
        prefix = f"{idx} " if idx else ""
        vals   = _spl_values(ips)
        # Build eval cases: src="ip" OR dest="ip" → matched_ip
        cases  = " ".join(f'src="{ip}", "{ip}", dest="{ip}", "{ip}",' for ip in ips).rstrip(",")
        spl = (
            f'{prefix}({vals}) '
            f'| eval matched_ip=case({cases}, true(), null()) '
            f'| stats count as events, '
            f'earliest(_time) as first_seen, latest(_time) as last_seen, '
            f'values(host) as hosts, values(user) as users '
            f'by matched_ip '
            f'| where isnotnull(matched_ip)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        matched = {row.get("matched_ip"): row for row in rows if row.get("matched_ip")}
        for ip in ips:
            row = matched.get(ip)
            if row:
                results.setdefault(ip, {})[rkey] = {
                    "events":     int(row.get("events", 0)),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen":  row.get("last_seen", ""),
                    "hosts":      row.get("hosts", ""),
                    "users":      row.get("users", ""),
                    "rows":       [row],
                    "link":       link,
                }

    async def _query_domains(self, base, token, domains, index, earliest, latest, rkey, results):
        idx    = _index_expr(index)
        prefix = f"{idx} " if idx else ""
        vals   = _spl_values(domains)
        cases  = " ".join(f'query="{d}", "{d}", dest_hostname="{d}", "{d}", url="{d}", "{d}",' for d in domains).rstrip(",")
        spl = (
            f'{prefix}({vals}) '
            f'| eval matched_domain=case({cases}, true(), null()) '
            f'| stats count as events, '
            f'earliest(_time) as first_seen, latest(_time) as last_seen, '
            f'values(src) as sources '
            f'by matched_domain '
            f'| where isnotnull(matched_domain)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        matched = {row.get("matched_domain"): row for row in rows if row.get("matched_domain")}
        for d in domains:
            row = matched.get(d)
            if row:
                results.setdefault(d, {})[rkey] = {
                    "events":     int(row.get("events", 0)),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen":  row.get("last_seen", ""),
                    "sources":    row.get("sources", ""),
                    "rows":       [row],
                    "link":       link,
                }

    async def _query_urls(self, base, token, urls, index, earliest, latest, rkey, results):
        idx    = _index_expr(index)
        prefix = f"{idx} " if idx else ""
        vals   = _spl_values(urls)
        cases  = " ".join(f'url="{u}", "{u}",' for u in urls).rstrip(",")
        spl = (
            f'{prefix}({vals}) '
            f'| eval matched_url=case({cases}, true(), null()) '
            f'| stats count as events, '
            f'earliest(_time) as first_seen, latest(_time) as last_seen, '
            f'values(src) as sources '
            f'by matched_url '
            f'| where isnotnull(matched_url)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        matched = {row.get("matched_url"): row for row in rows if row.get("matched_url")}
        for u in urls:
            row = matched.get(u)
            if row:
                results.setdefault(u, {})[rkey] = {
                    "events":     int(row.get("events", 0)),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen":  row.get("last_seen", ""),
                    "sources":    row.get("sources", ""),
                    "rows":       [row],
                    "link":       link,
                }

    async def _query_hashes(self, base, token, hashes, index, earliest, latest, rkey, results):
        idx    = _index_expr(index)
        prefix = f"{idx} " if idx else ""
        vals   = _spl_values(hashes)
        # Les champs hash courants dans Splunk : file_hash, md5, sha1, sha256, hash
        cases  = " ".join(
            f'file_hash="{h}", "{h}", md5="{h}", "{h}", sha1="{h}", "{h}", sha256="{h}", "{h}", hash="{h}", "{h}",'
            for h in hashes
        ).rstrip(",")
        spl = (
            f'{prefix}({vals}) '
            f'| eval matched_hash=case({cases}, true(), null()) '
            f'| stats count as events, '
            f'earliest(_time) as first_seen, latest(_time) as last_seen, '
            f'values(host) as hosts, values(user) as users '
            f'by matched_hash '
            f'| where isnotnull(matched_hash)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        matched = {row.get("matched_hash"): row for row in rows if row.get("matched_hash")}
        for h in hashes:
            row = matched.get(h)
            if row:
                results.setdefault(h, {})[rkey] = {
                    "events":     int(row.get("events", 0)),
                    "first_seen": row.get("first_seen", ""),
                    "last_seen":  row.get("last_seen", ""),
                    "hosts":      row.get("hosts", ""),
                    "users":      row.get("users", ""),
                    "rows":       [row],
                    "link":       link,
                }
