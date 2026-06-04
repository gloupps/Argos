# app/modules/hurricane_electric_module.py
import re
import base64
from typing import List, Dict, Any
from .module import Module


class HurricaneElectricModule(Module):
    """
    Module Hurricane Electric BGP Toolkit — bgp.he.net
    Auth : HTTP Basic Auth (username + password)

    Endpoints scrappés / utilisés :
      - /dns/<domain>        → NS, MX, résolution IP, SOA
      - /ip/<ip>             → ASN, préfixe, organisation, géo
      - /bgp/search?search=  → recherche ASN par nom / IP / préfixe

    Note : bgp.he.net n'expose pas d'API officielle REST.
    On utilise l'endpoint JSON non documenté mais stable :
      https://bgp.he.net/ip/<ip>#_prefixes
      https://bgp.he.net/dns/<domain>#_ipinfo
    et le endpoint de recherche générique JSON :
      https://bgp.he.net/search?q=<indicator>&callback=he_data
    """

    name = "Hurricane Electric"
    description = "BGP & DNS intelligence — ASN, prefixes, routing, DNS records"
    src_type = "external"
    supported_types = ["ip", "domain"]
    icon = "network"
    url = "https://bgp.he.net"

    # Champs de config supplémentaires (username + password pour Basic Auth)
    settings_fields = [
        {
            "key": "he_username",
            "type": "text",
            "label": "HE Username",
            "placeholder": "your_he_username",
        },
        {
            "key": "he_password",
            "type": "text",
            "label": "HE Password",
            "placeholder": "your_he_password",
        },
    ]

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_fields — force la clé "hurricane_electric"
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "hurricane_electric"
        return base

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "he_pivot_asn",
                "type": "checkbox",
                "label": "Pivot on shared ASN (IP)",
                "default": True,
            },
            {
                "key": "he_max_peers",
                "type": "range",
                "label": "Max ASN peers to pivot on",
                "min": 2,
                "max": 30,
                "default": 10,
            },
        ]

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    def _auth_headers(self, context: Dict[str, Any]) -> Dict[str, str]:
        """
        Construit l'entête Authorization Basic à partir du contexte.
        L'api_key est utilisé en priorité (format "username:password"),
        sinon on tombe sur he_username / he_password.
        """
        api_key = (context.get("api_key") or "").strip()
        if ":" in api_key:
            token = base64.b64encode(api_key.encode()).decode()
            return {"Authorization": f"Basic {token}"}

        username = (context.get("he_username") or "").strip()
        password = (context.get("he_password") or "").strip()
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            return {"Authorization": f"Basic {token}"}

        # Pas d'auth — bgp.he.net accepte les requêtes anonymes en lecture
        return {}

    @staticmethod
    def _f(
        indicator: str,
        name: str,
        field_type: str,
        value: Any,
        max_: int | None = None,
        link: str | None = None,
    ) -> Dict[str, Any]:
        return {
            "indicator": indicator,
            "indicator_type": "ioc",
            "field_name": name,
            "field_type": field_type,
            "value": value,
            "icon": None,
            "link": link,
            "max": max_,
        }

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "")
        headers = self._auth_headers(context)

        if ioc_type == "ip":
            return await self._enrich_ip(indicator, headers)
        elif ioc_type == "domain":
            return await self._enrich_domain(indicator, headers)
        return []

    # ── IP enrichment ──────────────────────────────────────
    async def _enrich_ip(self, ip: str, headers: Dict) -> List[Dict]:
        res: List[Dict] = []

        # Endpoint JSON non officiel mais stable pour les infos IP
        data = await self.requester.get(
            f"https://bgp.he.net/ip/{ip}",
            headers={**headers, "Accept": "application/json"},
            params={"output": "json"},
        )

        if not data or not isinstance(data, dict):
            # Fallback : tenter l'endpoint de recherche générique
            data = await self.requester.get(
                "https://bgp.he.net/search",
                headers=headers,
                params={"q": ip},
            )

        if not data:
            return res

        # ── ASN ──
        asn = data.get("asn") or data.get("originating_asn")
        if asn:
            res.append(self._f(ip, "ASN", "label-capsule", str(asn),
                               link=f"https://bgp.he.net/AS{asn}"))

        # ── AS Name ──
        as_name = data.get("asname") or data.get("as_name")
        if as_name:
            res.append(self._f(ip, "AS Name", "label-capsule", as_name))

        # ── Préfixe réseau ──
        prefix = data.get("prefix") or data.get("network")
        if prefix:
            res.append(self._f(ip, "BGP Prefix", "label-capsule", prefix))

        # ── Pays / Géo ──
        country = data.get("country") or data.get("cc")
        if country:
            res.append(self._f(ip, "Country", "label-capsule", country))

        # ── Organisation ──
        org = data.get("description") or data.get("org") or data.get("organization")
        if org:
            res.append(self._f(ip, "Organization", "label-capsule", org))

        # ── Reverse DNS ──
        rdns = data.get("rdns") or data.get("reverse_dns")
        if rdns:
            res.append(self._f(ip, "Reverse DNS", "label-capsule", rdns))

        # ── Peers ──
        peers = data.get("peers") or []
        if peers:
            peer_list = [str(p) for p in peers[:20]]
            res.append(self._f(ip, "BGP Peers", "list", peer_list, max_=20))

        # ── Route Origin ──
        route_origin = data.get("route_origin") or data.get("origin")
        if route_origin and route_origin != asn:
            res.append(self._f(ip, "Route Origin", "label-capsule", str(route_origin)))

        return res

    # ── Domain enrichment ──────────────────────────────────
    async def _enrich_domain(self, domain: str, headers: Dict) -> List[Dict]:
        res: List[Dict] = []

        data = await self.requester.get(
            f"https://bgp.he.net/dns/{domain}",
            headers={**headers, "Accept": "application/json"},
            params={"output": "json"},
        )

        if not data or not isinstance(data, dict):
            return res

        # ── IPs résolues ──
        ips = data.get("ips") or data.get("a_records") or []
        if ips:
            res.append(self._f(domain, "Resolved IPs", "list", [str(i) for i in ips[:10]], max_=10))

        # ── NS Records ──
        ns = data.get("ns") or data.get("ns_records") or []
        if ns:
            res.append(self._f(domain, "NS Records", "list", ns[:10], max_=10))

        # ── MX Records ──
        mx = data.get("mx") or data.get("mx_records") or []
        if mx:
            res.append(self._f(domain, "MX Records", "list", mx[:10], max_=10))

        # ── SOA ──
        soa = data.get("soa") or data.get("soa_record")
        if soa:
            res.append(self._f(domain, "SOA", "label-capsule", soa))

        # ── Hébergeur / ASN du domaine ──
        asn = data.get("asn")
        if asn:
            res.append(self._f(domain, "Hosting ASN", "label-capsule", str(asn),
                               link=f"https://bgp.he.net/AS{asn}"))

        as_name = data.get("asname") or data.get("as_name")
        if as_name:
            res.append(self._f(domain, "Hosting AS Name", "label-capsule", as_name))

        return res

    # ──────────────────────────────────────────────────────
    # get_correlation
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "")
        if ioc_type != "ip":
            return []

        cfg = context.get("hurricane_electric") or {}
        pivot_asn = cfg.get("he_pivot_asn", True)
        if not pivot_asn:
            return []

        headers = self._auth_headers(context)
        max_peers = int(cfg.get("he_max_peers", 10))

        data = await self.requester.get(
            f"https://bgp.he.net/ip/{indicator}",
            headers={**headers, "Accept": "application/json"},
            params={"output": "json"},
        )
        if not data or not isinstance(data, dict):
            return []

        asn = data.get("asn") or data.get("originating_asn")
        if not asn:
            return []

        # Récupération des préfixes de l'ASN pour trouver d'autres hôtes
        asn_data = await self.requester.get(
            f"https://bgp.he.net/AS{asn}",
            headers={**headers, "Accept": "application/json"},
            params={"output": "json"},
        )
        if not asn_data or not isinstance(asn_data, dict):
            return []

        correlations = []
        peers = (asn_data.get("peers") or [])[:max_peers]
        for peer_asn in peers:
            correlations.append({
                "indicator": str(peer_asn),
                "type": "asn",
                "pivot_reason": f"BGP peer of AS{asn}",
                "pivot": f"HE BGP peer AS{asn}",
            })

        return correlations

    # ──────────────────────────────────────────────────────
    # get_quotas — bgp.he.net n'expose pas de quota
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        headers = self._auth_headers(context)
        # Simple probe de disponibilité
        data = await self.requester.get(
            "https://bgp.he.net/ip/8.8.8.8",
            headers=headers,
            params={"output": "json"},
        )
        reachable = data is not None
        return {
            "plan_type": "external",
            "reachable": reachable,
        }
