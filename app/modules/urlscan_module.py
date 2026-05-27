import base64
from typing import List, Dict, Any
from .module import Module


class URLScanModule(Module):

    name             = "URLScan"
    description      = "Passive web scanning — page metadata, IPs, domains, screenshots"
    src_type         = "external"
    supported_types  = ["url", "domain"]
    icon             = "scan-search"
    url              = "https://urlscan.io/api/v1"

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        api_key  = context.get("api_key")
        ioc_type = context.get("ioc_type", "domain")
        if not api_key:
            return []

        headers = {"API-Key": api_key}

        if ioc_type == "url":
            data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f'page.url:"{indicator}"'},
                headers=headers,
            )
        else:
            data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f"domain:{indicator}"},
                headers=headers,
            )

        if not data or "results" not in data:
            return []

        return self._extract_fields(indicator, ioc_type, data)

    # ──────────────────────────────────────────────────────
    # get_correlation  (no active pivoting for URLScan)
    # ──────────────────────────────────────────────────────
    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        # URLScan is enrichment-only — no active cross-indicator pivoting
        return []

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        if not api_key:
            return {}
        data = await self.requester.get(f"{self.url}/quotas", headers={"API-Key": api_key})
        if not data:
            return {}
        return self._parse_quota(data)

    # ──────────────────────────────────────────────────────
    # get_fields
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "urlscan"
        return base

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    def _extract_fields(self, indicator, ioc_type, data) -> List[Dict[str, Any]]:
        results_raw = data.get("results", [])
        total       = len(results_raw)
        res         = []

        res.append(self._f(indicator, "Scan Count", "label-capsule", str(total)))

        # Collect unique IPs / servers / subdomains from scan results
        ips       = set()
        servers   = set()
        subs      = set()
        last_time = None

        for item in results_raw[:50]:
            page = item.get("page", {})
            task = item.get("task", {})
            if page.get("ip"):
                ips.add(page["ip"])
            if page.get("server"):
                servers.add(page["server"])
            t = task.get("time")
            if t and (last_time is None or t > last_time):
                last_time = t
            if ioc_type == "domain":
                domain_found = (page.get("domain") or "").lower()
                if domain_found and domain_found != indicator and domain_found.endswith(f".{indicator}"):
                    subs.add(domain_found)

        if ips:
            res.append(self._f(indicator, "Associated IPs", "list", sorted(ips)[:10]))
        if servers:
            res.append(self._f(indicator, "Server Headers", "list", sorted(servers)[:5]))
        if subs:
            res.append(self._f(indicator, "Subdomains Seen", "list", sorted(subs)[:10]))
        if last_time:
            res.append(self._f(indicator, "Last Scan", "label-capsule", last_time[:10]))

        return res

    def _parse_quota(self, data) -> Dict[str, Any]:
        limits    = data.get("limits", {})
        search_d  = limits.get("search", {}).get("day", {})
        try:
            limit = int(search_d.get("limit", 0))
            used  = int(search_d.get("used",  0))
        except (ValueError, TypeError):
            limit, used = 0, 0
        plan = "pro" if limit > 1000 else "free"
        return {"used": used, "limit": limit,
                "remaining": max(0, limit - used), "plan_type": plan}

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict[str, Any]:
        return {
            "indicator": indicator, "indicator_type": "ioc",
            "field_name": name, "field_type": field_type,
            "value": value, "icon": None, "link": None, "max": max_,
        }
