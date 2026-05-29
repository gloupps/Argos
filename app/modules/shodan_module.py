import asyncio
from typing import List, Dict, Any, Optional
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
    # Nouvelle logique :
    #   1. Récupérer l'IP source (host data)
    #   2. Construire la liste de hash queries (http.* + banner hash)
    #   3. COUNT en parallèle sur tous les hashes
    #   4. Filtrer : garder uniquement 1 < total <= max_hash_results
    #   5. SEARCH en parallèle uniquement sur les hashes retenus
    #   6. Dédupliquer + exclure l'IP source → résultats de corrélation
    # ─────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        if not api_key:
            return []

        max_hash_results = int(context.get("correlation_threshold", 100))

        # ── 1. Récupérer les données de l'IP source ──────
        ip_data = await self.requester.get(
            f"{self.url}/shodan/host/{indicator}",
            params={"key": api_key},
        )
        if not ip_data or ip_data.get("error"):
            return []

        # ── 2. Construire la liste de hash queries ────────
        seen_keys: set = set()
        hash_queries: List[Dict] = []

        for service in ip_data.get("data", []):
            # Hashes HTTP (html, title, headers, robots, sitemap, dom)
            http = service.get("http")
            if http:
                for hash_name in [
                    "robots_hash",
                    "title_hash",
                    "sitemap_hash",
                    "html_hash",
                    "dom_hash",
                    "headers_hash",
                ]:
                    value = http.get(hash_name)
                    if value:
                        key = f"http.{hash_name}:{value}"
                        if key not in seen_keys:
                            seen_keys.add(key)
                            hash_queries.append(
                                {
                                    "key": key,
                                    "query": f"http.{hash_name}",
                                    "value": value,
                                }
                            )

            # Hash de bannière
            banner_hash = service.get("hash")
            if banner_hash:
                key = f"hash:{banner_hash}"
                if key not in seen_keys:
                    seen_keys.add(key)
                    hash_queries.append(
                        {"key": key, "query": "hash", "value": banner_hash}
                    )

        if not hash_queries:
            return []

        # ── 3. COUNT en parallèle ─────────────────────────
        count_tasks = [self._count_ips_by_hash(api_key, h) for h in hash_queries]
        counts = await asyncio.gather(*count_tasks, return_exceptions=True)
        
        # ── 4. Filtrer les hashes utiles ──────────────────
        search_tasks = []
        valid_hashes = []
        for h, count in zip(hash_queries, counts):
            if isinstance(count, Exception):
                continue
            total = int(count)
            if total <= 1:  # seul résultat = l'IP elle-même
                continue
            if total > max_hash_results:  # trop répandu = bruit
                continue
            valid_hashes.append((h, total))
            search_tasks.append(self._search_ips_by_hash(api_key, h, max_hash_results))

        print(valid_hashes)
        print(search_tasks)
        if not search_tasks:
            return []

        # ── 5. SEARCH en parallèle ────────────────────────
        responses = await asyncio.gather(*search_tasks, return_exceptions=True)
        print(responses)
        # ── 6. Construire les résultats ───────────────────
        results: List[Dict[str, Any]] = []
        seen_ips: set = set()

        for (h, total), response in zip(valid_hashes, responses):
            if isinstance(response, Exception):
                continue

            for ip in response:
                if not ip or ip == indicator or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "ip",
                        "target_indicator": ip,
                        "target_type": "ip",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": f"{h['key']} (shared by {total} hosts)",
                    }
                )

        return results

    # ─────────────────────────────────────────────
    # Helpers count / search
    # ─────────────────────────────────────────────

    async def _count_ips_by_hash(self, api_key: str, hash_data: Dict) -> int:
        query = f"{hash_data['query']}:{hash_data['value']}"
        data = await self.requester.get(
            f"{self.url}/shodan/host/count",
            params={"key": api_key, "query": query},
        )
        if not data:
            return 0
        return data.get("total", 0)

    async def _search_ips_by_hash(
        self, api_key: str, hash_data: Dict, max_results: int
    ) -> List[str]:
        query = f"{hash_data['query']}:{hash_data['value']}"
        data = await self.requester.get(
            f"{self.url}/shodan/host/search",
            params={"key": api_key, "query": query},
        )
        print(data)
        if not data:
            return []
        matches = data.get("matches", [])[:max_results]
        return [m.get("ip_str") for m in matches if m.get("ip_str")]

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
        credits_label = (
            "unlimited"
            if (member and credits > 0)
            else ("unlimited" if member else "limited")
        )
        return {
            "used": 0,
            "limit": credits_label,
            "remaining": credits_label,
            "plan_type": plan,
        }

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
