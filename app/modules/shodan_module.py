from typing import List, Dict, Any


class ShodanModule(Module):

    name = "Shodan"
    type = "external"
    supported_types = ["ip"]
    url = "https://api.shodan.io"

    def __init__(self, requester):
        self.requester = requester

    # -------------------------
    # GET INFO
    # -------------------------
    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:

        api_key = context.get("api_key")
        if not api_key:
            return []

        raw = await self.requester.get(
            f"{self.url}/shodan/host/{indicator}",
            params={"key": api_key}
        )

        if not raw:
            return []

        results = []

        if raw.get("org"):
            results.append({
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "Organization",
                "field_type": "label-capsule",
                "value": raw["org"],
                "icon": None,
                "link": None,
                "max": None
            })

        if raw.get("os"):
            results.append({
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "OS",
                "field_type": "label-capsule",
                "value": raw["os"],
                "icon": None,
                "link": None,
                "max": None
            })

        ports = raw.get("ports", [])
        if ports:
            results.append({
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "Open Ports",
                "field_type": "list",
                "value": ports,
                "icon": None,
                "link": None,
                "max": context.get("max_results", 5)
            })

        hostnames = raw.get("hostnames", [])
        if hostnames:
            results.append({
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "Hostnames",
                "field_type": "list",
                "value": hostnames,
                "icon": None,
                "link": None,
                "max": 5
            })

        vulns = raw.get("vulns", [])
        if vulns:
            results.append({
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "Vulnerabilities",
                "field_type": "list",
                "value": list(vulns),
                "icon": None,
                "link": None,
                "max": 5
            })

        return results

    # -------------------------
    # CORRELATION
    # -------------------------
    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:

        api_key = context.get("api_key")
        if not api_key:
            return []

        threshold = context.get("correlation_threshold", 5)
        max_pivots = context.get("max_pivots", 5)

        raw = await self.requester.get(
            f"{self.url}/shodan/host/{indicator}",
            params={"key": api_key}
        )

        if not raw:
            return []

        results = []
        seen = set()

        for service in raw.get("data", []):

            hash_value = service.get("hash")
            if not hash_value:
                continue

            query = f"hash:{hash_value}"

            count_data = await self.requester.get(
                f"{self.url}/shodan/host/count",
                params={"key": api_key, "query": query}
            )

            if not count_data:
                continue

            total = count_data.get("total", 0)

            # filtre CTI
            if total <= 1 or total > max_pivots:
                continue

            search_data = await self.requester.get(
                f"{self.url}/shodan/host/search",
                params={"key": api_key, "query": query}
            )

            if not search_data:
                continue

            for match in search_data.get("matches", []):

                ip = match.get("ip_str")

                if not ip or ip == indicator:
                    continue

                if ip in seen:
                    continue

                seen.add(ip)

                results.append({
                    "source_indicator": indicator,
                    "source_type": "ip",
                    "target_indicator": ip,
                    "target_type": "ip",
                    "score": 1,
                    "pivot": True
                })

                # limite globale
                if len(results) >= threshold:
                    return results

        return results

    # -------------------------
    # QUOTAS
    # -------------------------
    async def get_quotas(self, context: Dict[str, Any]):

        api_key = context.get("api_key")
        if not api_key:
            return None

        data = await self.requester.get(
            f"{self.url}/account/profile",
            params={"key": api_key}
        )

        if not data:
            return None

        credits = int(data.get("credits", 0))
        member = data.get("member", False)

        if member and credits > 0:
            plan = "pro+"
        elif member:
            plan = "pro"
        else:
            plan = "free"

        return {
            "used": 0,
            "limit": credits,
            "remaining": credits,
            "plan_type": plan
        }

    # -------------------------
    # UI CONFIG
    # -------------------------
    def get_fields(self):
        return {
            "name": self.name,
            "type": self.type,
            "url": self.url,
            "supported_types": self.supported_types,
            "correlation": [
                {
                    "name": "correlation_threshold",
                    "type": "number",
                    "min": 1,
                    "max": 20,
                    "default": 5
                },
            ]
        }