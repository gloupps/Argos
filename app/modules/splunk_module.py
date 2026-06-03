# app/modules/splunk_module.py
"""
Splunk SIEM module — PivotLens.

Credentials (SecretStore / extra_config) :
  splunk          → Bearer token (ou user:pass en Basic Auth)
  extra_splunk_url  → Splunk base URL (ex. https://splunk.corp:8089)
  extra_splunk_index → index(es) à interroger (ex. "main,security", défaut "*")
  extra_splunk_earliest → override earliest (ex. "-30d@d"), sinon calculé depuis date_start
  extra_splunk_latest   → override latest (ex. "now"),    sinon calculé depuis date_end

Fonctionnement :
  - Utilise l'API REST Splunk (/services/search/jobs) en mode « one-shot »
    (exec_mode=oneshot) pour ne pas gérer de polling de job.
  - Une recherche SPL par type d'IOC (IP, domain, URL, hash) est lancée
    en parallèle via asyncio.gather.
  - Les résultats sont normalisés dans le même format que QRadar :
      { ioc_value: { "splunk": { "events": N, "rows": [...], "link": "..." } } }
"""

import asyncio
import base64
from typing import Any, Dict, List, Optional
from .module import Module


# ─────────────────────────────────────────────────────────────
# Helpers SPL
# ─────────────────────────────────────────────────────────────

def _time_range(date_start: str, date_end: str):
    """Retourne (earliest, latest) au format Splunk."""
    def _iso_to_splunk(dt: str) -> str:
        # Splunk accepte ISO 8601 directement
        return dt.replace("T", "T").replace(" ", "T") if dt else ""

    earliest = _iso_to_splunk(date_start) if date_start else "-30d@d"
    latest   = _iso_to_splunk(date_end)   if date_end   else "now"
    return earliest, latest


def _spl_values(values: List[str]) -> str:
    """Formate une liste de valeurs pour un IN SPL : "v1" OR "v2" …"""
    return " OR ".join(f'"{v}"' for v in values)


# ─────────────────────────────────────────────────────────────
# Module
# ─────────────────────────────────────────────────────────────

class SplunkModule(Module):

    name        = "Splunk"
    description = "Splunk SIEM — SPL one-shot search for IOC investigation"
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
            "key":         "splunk_index",
            "type":        "text",
            "label":       "Index(es) (comma-separated, * = all)",
            "placeholder": "main,security",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "splunk"
        return base

    async def get_info(self, indicator, context):    return []
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
        index     = context.get("splunk_index") or "*"
        earliest, latest = _time_range(
            context.get("date_start", ""),
            context.get("date_end", ""),
        )

        if not base or not token:
            return {}

        results: Dict[str, Any] = {}
        tasks = []

        ips     = dict_indicators.get("IPv4-Addr",   [])
        domains = dict_indicators.get("Domain-Name", [])
        urls    = dict_indicators.get("Url",         [])
        hashes  = dict_indicators.get("StixFile",    [])

        if ips:     tasks.append(self._query_ips    (base, token, ips,     index, earliest, latest, results))
        if domains: tasks.append(self._query_domains(base, token, domains, index, earliest, latest, results))
        if urls:    tasks.append(self._query_urls   (base, token, urls,    index, earliest, latest, results))
        if hashes:  tasks.append(self._query_hashes (base, token, hashes,  index, earliest, latest, results))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return results

    # ─────────────────────────────────────────────────────
    # PRIVATE — one SPL search per IOC type
    # ─────────────────────────────────────────────────────

    def _auth_headers(self, token: str) -> Dict[str, str]:
        """Supporte Bearer token ET Basic auth (user:pass)."""
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

    async def _run_search(
        self,
        base: str,
        token: str,
        spl: str,
        earliest: str,
        latest: str,
        count: int = 100,
    ) -> Optional[Dict]:
        """
        Exécute une recherche en mode one-shot et retourne le dict résultat
        ou None en cas d'échec.
        """
        url     = f"{base}/services/search/jobs"
        headers = self._auth_headers(token)
        payload = {
            "search":    f"search {spl}",
            "exec_mode": "oneshot",
            "earliest_time": earliest,
            "latest_time":   latest,
            "count":         str(count),
            "output_mode":   "json",
        }

        data = await self.requester.post(url, headers=headers, data=payload)
        return data

    def _extract_rows(self, data: Optional[Dict], max_rows: int = 10) -> List[Dict]:
        if not data:
            return []
        results = data.get("results") or []
        return [
            {k: v for k, v in row.items() if not k.startswith("_") or k in ("_time", "_raw")}
            for row in results[:max_rows]
        ]

    def _make_link(self, base: str, spl: str, earliest: str, latest: str) -> str:
        import urllib.parse
        q = urllib.parse.quote(f"search {spl}")
        return f"{base}/en-US/app/search/search?q={q}&earliest={earliest}&latest={latest}"

    # ── IPs ──────────────────────────────────────────────

    async def _query_ips(self, base, token, ips, index, earliest, latest, results):
        vals = _spl_values(ips)
        spl  = (
            f'index={index} '
            f'({vals}) '
            f'| eval matched_ip=case('
            + ", ".join(f'src="{ip}", "{ip}", dest="{ip}", "{ip}"' for ip in ips)
            + f') '
            f'| stats count as events, earliest(_time) as first_seen, '
            f'latest(_time) as last_seen, values(host) as hosts '
            f'by matched_ip '
            f'| where isnotnull(matched_ip)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        if rows:
            for row in rows:
                ioc = row.get("matched_ip") or row.get("src") or row.get("dest", "")
                if ioc in ips:
                    results.setdefault(ioc, {})["splunk"] = {
                        "events":    int(row.get("events", 0)),
                        "first_seen": row.get("first_seen", ""),
                        "last_seen":  row.get("last_seen", ""),
                        "hosts":      row.get("hosts", ""),
                        "rows":       [row],
                        "link":       link,
                    }
        else:
            # Aucun hit — on fait quand même une recherche brute par IOC
            await asyncio.gather(*[
                self._query_single_ioc(base, token, ip, "ip", index, earliest, latest, results, link)
                for ip in ips
            ], return_exceptions=True)

    # ── Domains ──────────────────────────────────────────

    async def _query_domains(self, base, token, domains, index, earliest, latest, results):
        vals = _spl_values(domains)
        spl  = (
            f'index={index} '
            f'({vals}) '
            f'| eval matched_domain=case('
            + ", ".join(f'query="{d}", "{d}", dest_hostname="{d}", "{d}", url="{d}", "{d}"' for d in domains)
            + f') '
            f'| stats count as events, earliest(_time) as first_seen, '
            f'latest(_time) as last_seen, values(src) as sources '
            f'by matched_domain '
            f'| where isnotnull(matched_domain)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        if rows:
            for row in rows:
                ioc = row.get("matched_domain", "")
                if ioc in domains:
                    results.setdefault(ioc, {})["splunk"] = {
                        "events":     int(row.get("events", 0)),
                        "first_seen": row.get("first_seen", ""),
                        "last_seen":  row.get("last_seen", ""),
                        "sources":    row.get("sources", ""),
                        "rows":       [row],
                        "link":       link,
                    }
        else:
            await asyncio.gather(*[
                self._query_single_ioc(base, token, d, "domain", index, earliest, latest, results, link)
                for d in domains
            ], return_exceptions=True)

    # ── URLs ─────────────────────────────────────────────

    async def _query_urls(self, base, token, urls, index, earliest, latest, results):
        vals = _spl_values(urls)
        spl  = (
            f'index={index} '
            f'({vals}) '
            f'| eval matched_url=case('
            + ", ".join(f'url="{u}", "{u}"' for u in urls)
            + f') '
            f'| stats count as events, earliest(_time) as first_seen, '
            f'latest(_time) as last_seen, values(src) as sources '
            f'by matched_url '
            f'| where isnotnull(matched_url)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        if rows:
            for row in rows:
                ioc = row.get("matched_url", "")
                if ioc in urls:
                    results.setdefault(ioc, {})["splunk"] = {
                        "events":     int(row.get("events", 0)),
                        "first_seen": row.get("first_seen", ""),
                        "last_seen":  row.get("last_seen", ""),
                        "sources":    row.get("sources", ""),
                        "rows":       [row],
                        "link":       link,
                    }
        else:
            await asyncio.gather(*[
                self._query_single_ioc(base, token, u, "url", index, earliest, latest, results, link)
                for u in urls
            ], return_exceptions=True)

    # ── Hashes ───────────────────────────────────────────

    async def _query_hashes(self, base, token, hashes, index, earliest, latest, results):
        vals = _spl_values(hashes)
        spl  = (
            f'index={index} '
            f'({vals}) '
            f'| eval matched_hash=case('
            + ", ".join(
                f'file_hash="{h}", "{h}", md5="{h}", "{h}", sha1="{h}", "{h}", sha256="{h}", "{h}"'
                for h in hashes
            )
            + f') '
            f'| stats count as events, earliest(_time) as first_seen, '
            f'latest(_time) as last_seen, values(host) as hosts, values(user) as users '
            f'by matched_hash '
            f'| where isnotnull(matched_hash)'
        )
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        link = self._make_link(base, spl, earliest, latest)

        if rows:
            for row in rows:
                ioc = row.get("matched_hash", "")
                if ioc in hashes:
                    results.setdefault(ioc, {})["splunk"] = {
                        "events":     int(row.get("events", 0)),
                        "first_seen": row.get("first_seen", ""),
                        "last_seen":  row.get("last_seen", ""),
                        "hosts":      row.get("hosts", ""),
                        "users":      row.get("users", ""),
                        "rows":       [row],
                        "link":       link,
                    }
        else:
            await asyncio.gather(*[
                self._query_single_ioc(base, token, h, "hash", index, earliest, latest, results, link)
                for h in hashes
            ], return_exceptions=True)

    # ── Fallback : recherche brute par IOC individuel ────

    async def _query_single_ioc(self, base, token, ioc, ioc_type, index, earliest, latest, results, link):
        spl  = f'index={index} "{ioc}" | stats count as events, earliest(_time) as first_seen, latest(_time) as last_seen'
        data = await self._run_search(base, token, spl, earliest, latest)
        rows = self._extract_rows(data)
        n    = int((rows[0].get("events") if rows else None) or 0)
        if n > 0:
            results.setdefault(ioc, {})["splunk"] = {
                "events":     n,
                "first_seen": rows[0].get("first_seen", "") if rows else "",
                "last_seen":  rows[0].get("last_seen",  "") if rows else "",
                "rows":       rows,
                "link":       link,
            }