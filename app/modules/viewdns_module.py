from typing import List, Dict, Any
from .module import Module


class ViewDNSModule(Module):

    name = "ViewDNS"
    description = (
        "Passive DNS — reverse IP, domain resolution, pivot via shared hosting"
    )
    src_type = "external"
    supported_types = ["ip", "domain"]
    icon = "globe"
    url = "https://api.viewdns.info"

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        ioc_type = context.get("ioc_type", "ip")
        if not api_key:
            return []

        results = []

        if ioc_type == "ip":
            data = await self._request("reverseip", {"host": indicator}, api_key)
            domains = self._extract_domains(data)
            if domains:
                names = [d["domain"] for d in domains if d.get("domain")]
                results.append(self._f(indicator, "Hosted Domains", "list", names[:20]))
                results.append(
                    self._f(
                        indicator, "Domain Count", "label-capsule", str(len(domains))
                    )
                )
                if domains[0].get("last_resolved"):
                    results.append(
                        self._f(
                            indicator,
                            "Last Resolved",
                            "label-capsule",
                            domains[0]["last_resolved"],
                        )
                    )

        elif ioc_type == "domain":
            data = await self._request(
                "dnsrecord", {"domain": indicator, "recordtype": "ANY"}, api_key
            )
            ips = self._extract_ips(data)
            if ips:
                results.append(self._f(indicator, "Resolved IPs", "list", ips))
            all_records = self._extract_records(data)
            if all_records:
                results.append(
                    self._f(indicator, "DNS Records", "list", all_records[:10])
                )

        return results

    # ──────────────────────────────────────────────────────
    # get_correlation
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        ioc_type = context.get("ioc_type", "ip")
        max_items = int(context.get("viewdns_max_pivots", 20))
        if not api_key:
            return []

        results = []

        if ioc_type == "ip":
            data = await self._request("reverseip", {"host": indicator}, api_key)
            domains = self._extract_domains(data)
            if len(domains) > max_items:
                return []  # too noisy
            for d in domains[:max_items]:
                domain = d.get("domain")
                if not domain:
                    continue
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "ip",
                        "target_indicator": domain,
                        "target_type": "domain",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": f"ViewDNS reverse IP ({len(domains)} domains on host)",
                    }
                )

        elif ioc_type == "domain":
            data = await self._request(
                "dnsrecord", {"domain": indicator, "recordtype": "ANY"}, api_key
            )
            ips = self._extract_ips(data)
            if len(ips) > max_items:
                return []
            for ip in ips[:max_items]:
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "domain",
                        "target_indicator": ip,
                        "target_type": "ip",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": "ViewDNS DNS resolution",
                    }
                )

        return results

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        if not api_key:
            return {}
        data = await self._request("account", {"action": "balance"}, api_key)
        return self._parse_quota(data)

    # ──────────────────────────────────────────────────────
    # get_fields
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "viewdns"
        return base

    def get_correlation_fields(self):
        return [
            {
                "key": "viewdns_max_pivots",
                "type": "range",
                "label": "Max domains/IPs per pivot",
                "min": 1,
                "max": 50,
                "default": 5,
            },
        ]

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    async def _request(self, endpoint, params, api_key):
        return await self.requester.get(
            f"{self.url}/{endpoint}/",
            params={**params, "apikey": api_key, "output": "json"},
        )

    def _extract_domains(self, data) -> List[Dict]:
        if not data:
            return []
        return [
            {
                "domain": d.get("name"),
                "ip": d.get("ip_address"),
                "last_resolved": d.get("last_resolved"),
            }
            for d in data.get("response", {}).get("domains", [])
        ]

    def _extract_ips(self, data) -> List[str]:
        if not data:
            return []
        return list(
            set(
                r["data"]
                for r in data.get("response", {}).get("records", [])
                if r.get("type") == "A" and r.get("data")
            )
        )

    def _extract_records(self, data) -> List[str]:
        if not data:
            return []
        records = []
        for r in data.get("response", {}).get("records", []):
            t = r.get("type", "")
            d = r.get("data", "")
            if t and d:
                records.append(f"{t}: {d}")
        return records

    def _parse_quota(self, data) -> Dict[str, Any]:
        if not data:
            return {"used": 0, "limit": 0, "remaining": 0, "plan_type": "unknown"}
        response = data.get("response", {})
        for plan_key in ("monthly", "trial"):
            if plan_key in response:
                quota = response[plan_key]
                try:
                    limit = int(quota.get("limit", 0))
                    used = int(quota.get("usage", 0))
                except (ValueError, TypeError):
                    limit, used = 0, 0
                return {
                    "used": used,
                    "limit": limit,
                    "remaining": max(0, limit - used),
                    "plan_type": plan_key,
                }
        return {"used": 0, "limit": 0, "remaining": 0, "plan_type": "unknown"}

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict[str, Any]:
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
