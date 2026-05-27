from typing import List, Dict, Any
from .module import Module


class ShodanModule(Module):

    name = "Shodan"
    description = "IP intelligence — ports, vulns, orgs, pivots par hash de service"
    src_type = "external"
    supported_types = ["ip"]
    icon = "radar"
    url = "https://api.shodan.io"

    def __init__(self, requester):
        self.requester = requester

    # ─────────────────────────────────────────────
    # get_info
    # ─────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        if not api_key:
            return []

        raw = await self.requester.get(
            f"{self.url}/shodan/host/{indicator}",
            params={"key": api_key},
        )
        if not raw or raw.get("error"):
            return []

        results = []
        if raw.get("org"):
            results.append(
                self._f(indicator, "Organization", "label-capsule", raw["org"])
            )
        if raw.get("asn"):
            results.append(self._f(indicator, "ASN", "label-capsule", raw["asn"]))
        if raw.get("os"):
            results.append(self._f(indicator, "OS", "label-capsule", raw["os"]))
        if raw.get("country_name"):
            results.append(
                self._f(indicator, "Country", "label-capsule", raw["country_name"])
            )
        ports = raw.get("ports", [])
        if ports:
            results.append(
                self._f(
                    indicator,
                    "Open Ports",
                    "list",
                    sorted(ports),
                    max_=context.get("max_results", 10),
                )
            )
        hostnames = raw.get("hostnames", [])
        if hostnames:
            results.append(self._f(indicator, "Hostnames", "list", hostnames, max_=5))
        domains = raw.get("domains", [])
        if domains:
            results.append(self._f(indicator, "Domains", "list", domains, max_=5))
        vulns = (
            list(raw.get("vulns", {}).keys())
            if isinstance(raw.get("vulns"), dict)
            else list(raw.get("vulns", []))
        )
        if vulns:
            results.append(
                self._f(indicator, "Vulnerabilities", "list", sorted(vulns), max_=10)
            )
        data_items = raw.get("data", [])
        if data_items:
            results.append(
                self._f(indicator, "Services", "label-capsule", str(len(data_items)))
            )
        tags = raw.get("tags", [])
        if tags:
            results.append(self._f(indicator, "Tags", "list", tags))
        last_update = raw.get("last_update")
        if last_update:
            results.append(
                self._f(indicator, "Last Seen", "label-capsule", last_update[:10])
            )
        return results

    # ─────────────────────────────────────────────
    # get_correlation
    #
    # Logique : pour chaque service de l'IP, récupérer le hash de bannière.
    # Si le nombre d'hôtes partageant ce hash est <= correlation_threshold,
    # pivote et retourne les IPs corrélées.
    # ─────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        if not api_key:
            return []

        # Seul paramètre : seuil maximum d'hôtes pour considérer le hash comme "pivot utile"
        max_count = int(context.get("correlation_threshold", 100))

        raw = await self.requester.get(
            f"{self.url}/shodan/host/{indicator}",
            params={"key": api_key},
        )
        if not raw or raw.get("error"):
            return []

        results: List[Dict[str, Any]] = []
        seen: set = set()

        for service in raw.get("data", []):
            hash_value = service.get("hash")
            if not hash_value:
                continue

            count_data = await self.requester.get(
                f"{self.url}/shodan/host/count",
                params={"key": api_key, "query": f"hash:{hash_value}"},
            )
            if not count_data:
                continue

            total = count_data.get("total", 0)
            # Skip si trop répandu (bruit) ou trivial (1 seul hôte = l'IP elle-même)
            if total <= 1 or total > max_count:
                continue

            search_data = await self.requester.get(
                f"{self.url}/shodan/host/search",
                params={
                    "key": api_key,
                    "query": f"hash:{hash_value}",
                    "fields": "ip_str",
                },
            )
            if not search_data:
                continue

            for match in search_data.get("matches", []):
                ip = match.get("ip_str")
                if not ip or ip == indicator or ip in seen:
                    continue
                seen.add(ip)
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "ip",
                        "target_indicator": ip,
                        "target_type": "ip",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": f"shared banner hash {hash_value} ({total} hosts)",
                    }
                )

        return results

    # ─────────────────────────────────────────────
    # get_quotas
    # ─────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        if not api_key:
            return {}
        data = await self.requester.get(
            f"{self.url}/account/profile",
            params={"key": api_key},
        )
        if not data:
            return {}

        credits = int(data.get("credits", 0))
        member = data.get("member", False)
        plan = "pro+" if (member and credits > 0) else ("pro" if member else "free")
        credits = (
            "unlimited"
            if (member and credits > 0)
            else ("unlimited" if member else "limited")
        )
        return {"used": 0, "limit": credits, "remaining": credits, "plan_type": plan}

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "shodan"
        return base

    def get_correlation_fields(self):
        return [
            {
                "key": "correlation_threshold",
                "type": "range",
                "label": "Max host count per pivot",
                "min": 2,
                "max": 50,
                "default": 5,
            },
        ]

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict[str, Any]:
        return {
            "indicator": indicator,
            "indicator_type": "ip",
            "field_name": name,
            "field_type": field_type,
            "value": value,
            "icon": None,
            "link": None,
            "max": max_,
        }
