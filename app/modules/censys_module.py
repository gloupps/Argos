# app/modules/censys_module.py
import asyncio
from typing import List, Dict, Any, Optional
from .module import Module


class CensysModule(Module):
    """
    Module Censys — Platform API v3.
    Auth : Personal Access Token (PAT) en Bearer header.

    Structure réponse /v3/global/asset/host/{ip} :
        raw["result"]["resource"] → host data
            .autonomous_system   → asn, name, bgp_prefix, country_code
            .location            → country, city, continent
            .services[]          → port, protocol, transport_protocol,
                                   cert.parsed, tls.fingerprint_sha256,
                                   software[], dns{}, http{}
            .dns                 → reverse_dns.names[], names[], forward_dns{}
            .whois               → organization.name, network.cidrs
    """

    name = "Censys"
    description = "Internet scan data — hosts, services, certificates, ASN pivots"
    src_type = "external"
    supported_types = ["ip", "domain", "hash"]
    icon = "scan-line"
    base_url = "https://api.platform.censys.io"

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "censys"
        return base

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "censys_max_hosts",
                "type": "range",
                "label": "Max hosts per pivot (IP correlation)",
                "min": 2,
                "max": 50,
                "default": 10,
            },
            {
                "key": "censys_pivot_asn",
                "type": "checkbox",
                "label": "Pivot on shared ASN (IP)",
                "default": True,
            },
            {
                "key": "censys_pivot_cert",
                "type": "checkbox",
                "label": "Pivot on shared TLS certificate",
                "default": True,
            },
            {
                "key": "censys_pivot_jarm",
                "type": "checkbox",
                "label": "Pivot on JARM fingerprint",
                "default": False,
            },
        ]

    # ─────────────────────────────────────────────────────
    # get_info
    # ─────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "ip")
        headers = self._headers(context)
        if not headers:
            return []

        if ioc_type == "ip":
            return await self._info_ip(indicator, headers)
        elif ioc_type == "domain":
            return await self._info_domain(indicator, headers)
        elif ioc_type == "hash":
            return await self._info_certificate(indicator, headers)
        return []

    # ─────────────────────────────────────────────────────
    # IP — GET /v3/global/asset/host/{ip}
    # ─────────────────────────────────────────────────────
    async def _info_ip(self, indicator: str, headers: dict) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.base_url}/v3/global/asset/host/{indicator}",
            headers=headers,
        )
        if not raw or not isinstance(raw, dict):
            return []

        # Désencapsulation : result.resource contient le vrai host
        host = (raw.get("result") or {}).get("resource") or {}
        if not host:
            return []

        results: List[Dict[str, Any]] = []

        # ── ASN / Réseau ──────────────────────────────────
        asn = host.get("autonomous_system") or {}
        if asn.get("asn"):
            results.append(
                self._f(indicator, "ASN", "label-capsule", f"AS{asn['asn']}")
            )
        if asn.get("name"):
            results.append(self._f(indicator, "AS Name", "label-capsule", asn["name"]))
        if asn.get("bgp_prefix"):
            results.append(
                self._f(indicator, "BGP Prefix", "label-capsule", asn["bgp_prefix"])
            )
        if asn.get("country_code"):
            results.append(
                self._f(indicator, "Country", "label-capsule", asn["country_code"])
            )

        # ── Localisation ──────────────────────────────────
        loc = host.get("location") or {}
        if loc.get("city") and loc.get("country"):
            results.append(
                self._f(
                    indicator,
                    "Location",
                    "label-capsule",
                    f"{loc['city']}, {loc['country']}",
                )
            )

        # ── WHOIS organisation ────────────────────────────
        whois_org = ((host.get("whois") or {}).get("organization") or {}).get(
            "name"
        ) or ""
        if whois_org and whois_org != asn.get("name", ""):
            results.append(
                self._f(indicator, "Organization", "label-capsule", whois_org)
            )

        # ── Services ──────────────────────────────────────
        services = host.get("services") or []
        if services:
            svc_list = []
            tls_names: set = set()
            cert_fps: set = set()

            for svc in services:
                entry = self._parse_service(svc)
                if entry:
                    svc_list.append(entry)

                # Collecte des noms TLS depuis cert.parsed.names
                cert_obj = svc.get("cert") or {}
                for n in cert_obj.get("names") or []:
                    if n and not n.replace(".", "").isdigit():  # exclure les IPs
                        tls_names.add(n)

                # Fingerprint depuis tls.fingerprint_sha256
                tls_obj = svc.get("tls") or {}
                fp = tls_obj.get("fingerprint_sha256") or ""
                if fp:
                    cert_fps.add(fp)

            if svc_list:
                results.append(
                    self._f(indicator, "Censys Services", "censys_services", svc_list)
                )

            # Ports ouverts résumé
            ports = sorted({s["port"] for s in svc_list if s.get("port")})
            if ports:
                results.append(
                    self._f(
                        indicator,
                        "Open Ports",
                        "list",
                        [str(p) for p in ports],
                        max_=20,
                    )
                )

            if tls_names:
                results.append(
                    self._f(
                        indicator, "TLS Names", "list", sorted(tls_names)[:10], max_=10
                    )
                )
            if cert_fps:
                results.append(
                    self._f(
                        indicator,
                        "Cert Fingerprints",
                        "list",
                        list(cert_fps)[:3],
                        max_=3,
                    )
                )

        # ── DNS ───────────────────────────────────────────
        dns = host.get("dns") or {}

        # Reverse DNS
        rdns_names = (dns.get("reverse_dns") or {}).get("names") or []
        if rdns_names:
            results.append(
                self._f(indicator, "Reverse DNS", "list", rdns_names[:5], max_=5)
            )

        # Forward DNS (domaines qui pointent vers cette IP)
        fwd_names = list((dns.get("forward_dns") or {}).keys())
        if fwd_names:
            results.append(
                self._f(
                    indicator, "Hosted Domains", "list", sorted(fwd_names)[:20], max_=20
                )
            )
            results.append(
                self._f(indicator, "Domain Count", "label-capsule", str(len(fwd_names)))
            )

        # DNS names (passive DNS étendu)
        all_dns_names = dns.get("names") or []
        # Filtrer pour ne garder que les noms "intéressants" (pas les zoomonprem.com etc.)
        notable = [
            n
            for n in all_dns_names
            if not any(noise in n for noise in ["zoomonprem.com", "pubmmr-", "pubzc-"])
        ]
        if notable:
            results.append(
                self._f(indicator, "DNS Names", "list", notable[:15], max_=15)
            )

        # ── Dernière mise à jour ──────────────────────────
        # scan_time est dans chaque service, on prend le plus récent
        scan_times = [
            svc.get("scan_time", "") for svc in services if svc.get("scan_time")
        ]
        if scan_times:
            last_scan = sorted(scan_times)[-1]
            results.append(
                self._f(indicator, "Last Scanned", "label-capsule", last_scan[:10])
            )

        # ── Lien Censys ───────────────────────────────────
        results.append(
            {
                "indicator": indicator,
                "indicator_type": "ip",
                "field_name": "Censys Host",
                "field_type": "label-capsule",
                "value": "View on Censys",
                "icon": "external-link",
                "link": f"https://search.censys.io/hosts/{indicator}",
                "max": None,
            }
        )

        return results

    # ─────────────────────────────────────────────────────
    # _parse_service — structure v3
    # svc = {
    #   port, protocol, transport_protocol,
    #   cert: { parsed: { subject_dn, issuer_dn, subject.common_name[], names[] },
    #           names[] },
    #   tls: { fingerprint_sha256 },
    #   software: [{ vendor, product }],
    #   dns: { version, r_code },
    #   scan_time
    # }
    # ─────────────────────────────────────────────────────
    @staticmethod
    def _parse_service(svc: Dict) -> Optional[Dict]:
        port = svc.get("port")
        if not port:
            return None

        proto = (svc.get("transport_protocol") or "tcp").lower()
        svc_name = svc.get("protocol") or ""

        entry: Dict[str, Any] = {"port": port, "transport": proto}
        if svc_name:
            entry["service"] = svc_name

        # ── Software ──────────────────────────────────────
        software = svc.get("software") or []
        if software and isinstance(software, list):
            first = software[0] if isinstance(software[0], dict) else {}
            product = first.get("product") or ""
            vendor = first.get("vendor") or ""
            if product:
                entry["product"] = f"{vendor} {product}".strip() if vendor else product

        # ── Certificat TLS (cert.parsed) ──────────────────
        cert_obj = svc.get("cert") or {}
        parsed = cert_obj.get("parsed") or {}
        if parsed:
            subject = parsed.get("subject") or {}
            cn_list = subject.get("common_name") or []
            cn = cn_list[0] if isinstance(cn_list, list) and cn_list else ""
            if cn:
                entry["tls_cn"] = cn

            issuer = parsed.get("issuer") or {}
            issuer_cn_list = issuer.get("common_name") or []
            issuer_cn = (
                issuer_cn_list[0]
                if isinstance(issuer_cn_list, list) and issuer_cn_list
                else ""
            )
            if issuer_cn:
                entry["tls_issuer"] = issuer_cn

            validity = parsed.get("validity_period") or {}
            if validity.get("not_after"):
                entry["tls_expiry"] = validity["not_after"][:10]

            sig_alg = (parsed.get("signature") or {}).get(
                "signature_algorithm", {}
            ).get("name") or ""
            if sig_alg:
                entry["tls_sig_alg"] = sig_alg

            key_info = parsed.get("subject_key_info") or {}
            key_alg = (key_info.get("key_algorithm") or {}).get("name") or ""
            key_len = (key_info.get("ecdsa") or key_info.get("rsa") or {}).get(
                "length"
            ) or ""
            if key_alg:
                entry["tls_key"] = (
                    f"{key_alg} {key_len}".strip() if key_len else key_alg
                )

            # SANs (noms du cert) — utile pour le pivot
            names = cert_obj.get("names") or []
            if names:
                entry["tls_names"] = [
                    n for n in names if not n.replace(".", "").isdigit()
                ][:10]

        # TLS fingerprint
        tls_fp = (svc.get("tls") or {}).get("fingerprint_sha256") or ""
        if tls_fp:
            entry["tls_fp"] = tls_fp

        # ── HTTP (endpoints[0]) ───────────────────────────
        endpoints = svc.get("endpoints") or []
        if endpoints:
            http = endpoints[0].get("http") or {}
            if http.get("status_code"):
                entry["http_status"] = str(http["status_code"])
            if http.get("status_reason"):
                entry["http_reason"] = http["status_reason"]
            # Headers
            headers_raw = http.get("headers") or {}
            server = (headers_raw.get("Server") or {}).get("headers", [])
            if server:
                entry["http_server"] = server[0]
            # Extraire headers HTTP utiles supplémentaires
            interesting_headers = {
                "Content-Type": "http_content_type",
                "X-Powered-By": "http_powered_by",
                "Location": "http_location",
                "WWW-Authenticate": "http_auth",
                "X-Frame-Options": "http_x_frame",
                "Strict-Transport-Security": "http_hsts",
            }
            for hname, hkey in interesting_headers.items():
                hvals = (headers_raw.get(hname) or {}).get("headers", [])
                if hvals:
                    entry[hkey] = hvals[0]
            # Body hash (sha256)
            body_hash = http.get("body_hash") or http.get("body_sha256") or ""
            if body_hash:
                entry["http_body_hash"] = body_hash
            # Body snippet
            body = http.get("body") or ""
            if body and len(body) > 10:
                entry["banner"] = body[:300]

        # ── DNS service ───────────────────────────────────
        dns_info = svc.get("dns") or {}
        if dns_info:
            if dns_info.get("version"):
                entry["dns_version"] = dns_info["version"]
            if dns_info.get("r_code"):
                entry["dns_rcode"] = dns_info["r_code"]

        # ── Scan time ─────────────────────────────────────
        if svc.get("scan_time"):
            entry["scan_time"] = svc["scan_time"][:10]

        return entry

    # ─────────────────────────────────────────────────────
    # Domaine — search via POST /v3/global/search/query
    # ─────────────────────────────────────────────────────
    async def _info_domain(self, indicator: str, headers: dict) -> List[Dict[str, Any]]:
        data = await self.requester.post(
            f"{self.base_url}/v3/global/search/query",
            headers=headers,
            json={
                "query": f'host.dns.names: "{indicator}"',
                "page_size": 10,
            },
        )

        results: List[Dict[str, Any]] = []
        hits = (data or {}).get("results") or []

        if not hits:
            results.append(self._f(indicator, "Censys Results", "label-capsule", "0"))
        else:
            results.append(
                self._f(indicator, "Censys Results", "label-capsule", str(len(hits)))
            )
            ips = list({h.get("ip") for h in hits if h.get("ip")})
            if ips:
                results.append(
                    self._f(indicator, "Associated IPs", "list", ips[:10], max_=10)
                )

        results.append(
            {
                "indicator": indicator,
                "indicator_type": "domain",
                "field_name": "Censys Search",
                "field_type": "label-capsule",
                "value": "Search on Censys",
                "icon": "external-link",
                "link": f"https://search.censys.io/search?resource=hosts&q=host.dns.names%3A{indicator}",
                "max": None,
            }
        )
        return results

    # ─────────────────────────────────────────────────────
    # Certificat — GET /v3/global/asset/certificate/{fp}
    # ─────────────────────────────────────────────────────
    async def _info_certificate(
        self, indicator: str, headers: dict
    ) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.base_url}/v3/global/asset/certificate/{indicator}",
            headers=headers,
        )
        if not raw or not isinstance(raw, dict):
            return []

        resource = (raw.get("result") or {}).get("resource") or raw
        parsed = resource.get("parsed") or {}
        results: List[Dict[str, Any]] = []

        for field, label in [("subject_dn", "Subject DN"), ("issuer_dn", "Issuer DN")]:
            val = parsed.get(field) or ""
            if val:
                results.append(self._f(indicator, label, "label-capsule", val))

        names = parsed.get("names") or []
        if names:
            results.append(
                self._f(indicator, "SANs / Names", "list", names[:15], max_=15)
            )

        validity = parsed.get("validity_period") or {}
        if validity.get("not_before"):
            results.append(
                self._f(
                    indicator,
                    "Valid From",
                    "label-capsule",
                    validity["not_before"][:10],
                )
            )
        if validity.get("not_after"):
            results.append(
                self._f(
                    indicator,
                    "Valid Until",
                    "label-capsule",
                    validity["not_after"][:10],
                )
            )

        results.append(
            {
                "indicator": indicator,
                "indicator_type": "hash",
                "field_name": "Censys Certificate",
                "field_type": "label-capsule",
                "value": "View on Censys",
                "icon": "external-link",
                "link": f"https://search.censys.io/certificates/{indicator}",
                "max": None,
            }
        )
        return results

    # ─────────────────────────────────────────────────────
    # get_correlation
    # ─────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "ip")
        headers = self._headers(context)
        if not headers:
            return []

        if ioc_type == "ip":
            return await self._correlate_ip(indicator, context, headers)
        elif ioc_type == "domain":
            return await self._correlate_domain(indicator, context, headers)
        return []

    async def _correlate_ip(
        self, indicator: str, context: Dict[str, Any], headers: dict
    ) -> List[Dict[str, Any]]:

        max_hosts = int(context.get("censys_max_hosts", 10))
        do_asn = bool(context.get("censys_pivot_asn", True))
        do_cert = bool(context.get("censys_pivot_cert", True))
        do_jarm = bool(context.get("censys_pivot_jarm", False))

        raw = await self.requester.get(
            f"{self.base_url}/v3/global/asset/host/{indicator}",
            headers=headers,
        )
        if not raw or not isinstance(raw, dict):
            return []

        host = (raw.get("result") or {}).get("resource") or {}
        services = host.get("services") or []
        asn_info = host.get("autonomous_system") or {}
        pivot_tasks = []  # list of (label, query)

        # ── Pivot ASN + ports communs ─────────────────────
        if do_asn and asn_info.get("asn"):
            asn_num = asn_info["asn"]
            open_ports = sorted({s["port"] for s in services if s.get("port")})[:4]
            if open_ports:
                port_clause = " OR ".join(f"host.services.port={p}" for p in open_ports)
                pivot_tasks.append(
                    (
                        f"AS{asn_num}",
                        f"host.autonomous_system.asn={asn_num} AND ({port_clause})",
                    )
                )

        # ── Pivot certificat TLS ──────────────────────────
        if do_cert:
            seen_fps: set = set()
            for svc in services:
                fp = (svc.get("tls") or {}).get("fingerprint_sha256") or ""
                if fp and fp not in seen_fps:
                    seen_fps.add(fp)
                    pivot_tasks.append(
                        (
                            f"TLS cert {fp[:16]}…",
                            f'host.services.tls.fingerprint_sha256="{fp}"',
                        )
                    )
                if len(seen_fps) >= 2:
                    break

        if not pivot_tasks:
            return []

        responses = await asyncio.gather(
            *[self._search_hosts(q, max_hosts, headers) for (_, q) in pivot_tasks],
            return_exceptions=True,
        )

        results: List[Dict[str, Any]] = []
        seen_ips: set = {indicator}

        for (pivot_label, _), response in zip(pivot_tasks, responses):
            if isinstance(response, Exception):
                continue
            for ip in response or []:
                if not ip or ip in seen_ips:
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
                        "pivot_reason": pivot_label,
                    }
                )

        return results

    async def _correlate_domain(
        self, indicator: str, context: Dict[str, Any], headers: dict
    ) -> List[Dict[str, Any]]:
        data = await self.requester.post(
            f"{self.base_url}/v3/global/search/query",
            headers=headers,
            json={"query": f'host.dns.names: "{indicator}"', "page_size": 20},
        )
        if not data:
            return []

        results: List[Dict[str, Any]] = []
        seen_ips: set = set()

        for hit in data.get("results") or []:
            ip = hit.get("ip") or ""
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "domain",
                        "target_indicator": ip,
                        "target_type": "ip",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": f"Hosts {indicator}",
                    }
                )

        return results

    # ─────────────────────────────────────────────────────
    # get_quotas
    # ─────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_id = (context.get("api_key") or "").strip()
        api_secret = (context.get("censys_api_secret") or "").strip()
        if not api_id or not api_secret:
            return {}

        data = await self.requester.get(
            "https://search.censys.io/api/v1/account",
            auth=(api_id, api_secret),
        )
        if not data or not isinstance(data, dict):
            return {}

        quota = data.get("quota") or {}
        try:
            used = int(quota.get("used", 0))
            allowance = int(quota.get("allowance", 0))
        except (ValueError, TypeError):
            used, allowance = 0, 0

        remaining = max(0, allowance - used)
        plan_type = "free" if allowance <= 250 else "pro"

        return {
            "used": used,
            "limit": allowance,
            "remaining": remaining,
            "plan_type": plan_type,
        }

    # ─────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────
    def _headers(self, context: Dict[str, Any]) -> Optional[dict]:
        api_key = (context.get("api_key") or "").strip()
        if not api_key:
            return None
        return {"Authorization": f"Bearer {api_key}"}

    async def _search_hosts(
        self, query: str, max_results: int, headers: dict
    ) -> List[str]:
        data = await self.requester.post(
            f"{self.base_url}/v3/global/search/query",
            headers=headers,
            json={"query": query, "page_size": max_results},
        )
        if not data or not isinstance(data, dict):
            return []
        return [h.get("ip") for h in (data.get("results") or []) if h.get("ip")]

    @staticmethod
    def _f(
        indicator: str,
        name: str,
        field_type: str,
        value: Any,
        max_: Optional[int] = None,
    ) -> Dict[str, Any]:
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
