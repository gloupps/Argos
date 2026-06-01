# app/modules/censys_module.py
import asyncio
from typing import List, Dict, Any, Optional
from .module import Module


class CensysModule(Module):
    """
    Module Censys — Internet-wide scan data.
    Couvre : IP (hosts), domaines (certificates + DNS), certificats (SHA-256).

    Endpoints utilisés :
        - /v2/hosts/{ip}                         → enrichissement IP
        - /v2/certificates/search                → enrichissement domaine (CN/SAN)
        - /v1/view/certificates/{sha256}         → enrichissement hash de certificat
        - /v2/hosts/search                       → corrélation IP (pivot AS, port, service)
        - /v2/certificates/search (bulk)         → corrélation domaine (co-SAN pivot)

    Auth : HTTP Basic (API_ID:API_SECRET) passés dans le contexte comme
           api_key = "<app_id>:<secret>"
    """

    name = "Censys"
    description = "Internet scan data — hosts, services, certificates, ASN pivots"
    src_type = "external"
    supported_types = ["ip", "domain", "hash"]
    icon = "scan-line"
    url_v2 = "https://search.censys.io/api/v2"
    url_v1 = "https://search.censys.io/api/v1"

    def __init__(self, requester):
        self.requester = requester

    # ─────────────────────────────────────────────────────
    # get_fields / key override
    # ─────────────────────────────────────────────────────
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
                "key": "censys_max_certs",
                "type": "range",
                "label": "Max certs per domain pivot",
                "min": 2,
                "max": 30,
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
                "label": "Pivot on shared TLS certificate (IP/domain)",
                "default": True,
            },
            {
                "key": "censys_pivot_jarm",
                "type": "checkbox",
                "label": "Pivot on JARM fingerprint (IP)",
                "default": False,
            },
        ]

    # ─────────────────────────────────────────────────────
    # get_info — dispatcher selon type IOC
    # ─────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "ip")
        auth = self._auth(context)
        if not auth:
            return []

        if ioc_type == "ip":
            return await self._info_ip(indicator, auth)
        elif ioc_type == "domain":
            return await self._info_domain(indicator, auth)
        elif ioc_type == "hash":
            # On suppose que hash = SHA-256 d'un certificat
            return await self._info_certificate(indicator, auth)
        return []

    # ─────────────────────────────────────────────────────
    # get_info — IP  (/v2/hosts/{ip})
    # ─────────────────────────────────────────────────────
    async def _info_ip(self, indicator: str, auth: tuple) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.url_v2}/hosts/{indicator}",
            auth=auth,
        )
        if not raw or raw.get("code") not in (None, 200) and "result" not in raw:
            return []

        host = raw.get("result") or raw
        results: List[Dict[str, Any]] = []

        # ── Identité ──────────────────────────────────────
        asn = host.get("autonomous_system", {})
        if asn.get("asn"):
            results.append(self._f(indicator, "ASN", "label-capsule",
                                   f"AS{asn['asn']}"))
        if asn.get("name"):
            results.append(self._f(indicator, "AS Name", "label-capsule",
                                   asn["name"]))
        if asn.get("bgp_prefix"):
            results.append(self._f(indicator, "BGP Prefix", "label-capsule",
                                   asn["bgp_prefix"]))
        if asn.get("country_code"):
            results.append(self._f(indicator, "Country", "label-capsule",
                                   asn["country_code"]))

        # ── Services ──────────────────────────────────────
        services = host.get("services", [])
        if services:
            svc_list = []
            tls_fps = []
            jarm_fps = set()
            cert_fps = set()

            for svc in services:
                port = svc.get("port")
                proto = svc.get("transport_protocol", "TCP")
                svc_name = svc.get("service_name", "")
                product = (svc.get("software") or [{}])[0].get("product", "") if svc.get("software") else ""

                entry: Dict[str, Any] = {"port": port, "transport": proto.lower()}
                if svc_name:
                    entry["service"] = svc_name
                if product:
                    entry["product"] = product

                # TLS
                tls = svc.get("tls", {})
                cert = tls.get("certificates", {}).get("leaf_data", {})
                if cert:
                    subject = cert.get("subject", {})
                    cn = subject.get("common_name", [""])[0] if isinstance(subject.get("common_name"), list) else subject.get("common_name", "")
                    fp = cert.get("fingerprint")
                    if cn:
                        entry["tls_cn"] = cn
                    if fp:
                        entry["tls_fp"] = fp[:16] + "…"
                        cert_fps.add(fp)
                    issued_to = cert.get("names", [])
                    if issued_to:
                        tls_fps.append({"port": port, "cn": cn, "names": issued_to[:5], "fp": fp})

                # JARM
                jarm = svc.get("jarm", {})
                if jarm.get("fingerprint"):
                    entry["jarm"] = jarm["fingerprint"]
                    jarm_fps.add(jarm["fingerprint"])

                # Banner
                banner = svc.get("banner")
                if banner and len(banner) > 4:
                    entry["banner"] = banner[:200]

                svc_list.append(entry)

            if svc_list:
                results.append(self._f(indicator, "Services", "censys_services", svc_list))

            # Certificats TLS uniques trouvés sur l'hôte
            if tls_fps:
                cert_names = list({n for t in tls_fps for n in t.get("names", [])})
                if cert_names:
                    results.append(self._f(indicator, "TLS Names", "list",
                                           cert_names[:10], max_=10))
            if cert_fps:
                results.append(self._f(indicator, "Cert Fingerprints", "list",
                                       list(cert_fps)[:5], max_=5))
            if jarm_fps:
                results.append(self._f(indicator, "JARM Fingerprints", "list",
                                       list(jarm_fps)[:3], max_=3))

        # ── Open ports résumé ─────────────────────────────
        ports = sorted({s["port"] for s in services if s.get("port")})
        if ports:
            results.append(self._f(indicator, "Open Ports", "list",
                                   [str(p) for p in ports], max_=20))

        # ── Dernière mise à jour ──────────────────────────
        last_updated = host.get("last_updated_at")
        if last_updated:
            results.append(self._f(indicator, "Last Scanned", "label-capsule",
                                   last_updated[:10]))

        # ── Lien Censys ───────────────────────────────────
        results.append({
            "indicator": indicator,
            "indicator_type": "ip",
            "field_name": "Censys Host",
            "field_type": "label-capsule",
            "value": "View on Censys",
            "icon": "external-link",
            "link": f"https://search.censys.io/hosts/{indicator}",
            "max": None,
        })

        return results

    # ─────────────────────────────────────────────────────
    # get_info — Domaine  (search certs par CN/SAN)
    # ─────────────────────────────────────────────────────
    async def _info_domain(self, indicator: str, auth: tuple) -> List[Dict[str, Any]]:
        # Recherche dans les certificats (CN ou SAN)
        query = f'names: "{indicator}"'
        data = await self.requester.get(
            f"{self.url_v2}/certificates/search",
            params={"q": query, "per_page": 20, "fields": "parsed.subject_dn,parsed.issuer.organization,parsed.names,parsed.validity_period,parsed.fingerprint_sha256"},
            auth=auth,
        )
        results: List[Dict[str, Any]] = []

        hits = (data or {}).get("result", {}).get("hits", []) if data else []

        if not hits:
            results.append(self._f(indicator, "Certificates Found", "label-capsule", "0"))
            return results

        results.append(self._f(indicator, "Certificates Found", "label-capsule",
                                str(len(hits))))

        # Collecte des issuers, SANs, fingerprints
        issuers: set = set()
        all_names: set = set()
        fps: List[str] = []
        validity_info: List[str] = []

        for cert in hits[:20]:
            parsed = cert.get("parsed", {})

            issuer_org = parsed.get("issuer", {}).get("organization", [])
            if isinstance(issuer_org, list) and issuer_org:
                issuers.add(issuer_org[0])
            elif isinstance(issuer_org, str):
                issuers.add(issuer_org)

            names = parsed.get("names", [])
            for n in names:
                if n and n != indicator:
                    all_names.add(n)

            fp = parsed.get("fingerprint_sha256") or cert.get("fingerprint_sha256")
            if fp and fp not in fps:
                fps.append(fp)

            validity = parsed.get("validity_period", {})
            not_after = validity.get("not_after", "")
            if not_after:
                validity_info.append(not_after[:10])

        if issuers:
            results.append(self._f(indicator, "Certificate Issuers", "list",
                                   sorted(issuers)[:5], max_=5))

        related_names = sorted(n for n in all_names if indicator not in n)[:10]
        if related_names:
            results.append(self._f(indicator, "Related Names (SAN)", "list",
                                   related_names, max_=10))

        if fps:
            results.append(self._f(indicator, "Cert SHA-256", "list",
                                   fps[:3], max_=3))

        if validity_info:
            latest = sorted(validity_info)[-1]
            results.append(self._f(indicator, "Latest Expiry", "label-capsule", latest))

        # Lien Censys
        results.append({
            "indicator": indicator,
            "indicator_type": "domain",
            "field_name": "Censys Certs",
            "field_type": "label-capsule",
            "value": "Search on Censys",
            "icon": "external-link",
            "link": f"https://search.censys.io/certificates?q=names%3A%22{indicator}%22",
            "max": None,
        })

        return results

    # ─────────────────────────────────────────────────────
    # get_info — Certificat (SHA-256)  /v1/view/certificates
    # ─────────────────────────────────────────────────────
    async def _info_certificate(self, indicator: str, auth: tuple) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.url_v1}/view/certificates/{indicator}",
            auth=auth,
        )
        if not raw:
            return []

        parsed = raw.get("parsed", {})
        results: List[Dict[str, Any]] = []

        subject_dn = parsed.get("subject_dn", "")
        if subject_dn:
            results.append(self._f(indicator, "Subject DN", "label-capsule", subject_dn))

        issuer_dn = parsed.get("issuer_dn", "")
        if issuer_dn:
            results.append(self._f(indicator, "Issuer DN", "label-capsule", issuer_dn))

        names = parsed.get("names", [])
        if names:
            results.append(self._f(indicator, "SANs / Names", "list", names[:15], max_=15))

        validity = parsed.get("validity_period", {})
        if validity.get("not_before"):
            results.append(self._f(indicator, "Valid From", "label-capsule",
                                   validity["not_before"][:10]))
        if validity.get("not_after"):
            results.append(self._f(indicator, "Valid Until", "label-capsule",
                                   validity["not_after"][:10]))

        sig_alg = parsed.get("signature_algorithm", {}).get("name", "")
        if sig_alg:
            results.append(self._f(indicator, "Sig Algorithm", "label-capsule", sig_alg))

        key_type = parsed.get("subject_key_info", {}).get("key_algorithm", {}).get("name", "")
        if key_type:
            results.append(self._f(indicator, "Key Type", "label-capsule", key_type))

        # Hosts qui utilisent ce certificat
        hosts_data = raw.get("hosts", [])
        if hosts_data:
            host_ips = [h.get("ip") for h in hosts_data if h.get("ip")]
            if host_ips:
                results.append(self._f(indicator, "Hosts Using Cert", "list",
                                       host_ips[:10], max_=10))

        # Lien
        results.append({
            "indicator": indicator,
            "indicator_type": "hash",
            "field_name": "Censys Certificate",
            "field_type": "label-capsule",
            "value": "View on Censys",
            "icon": "external-link",
            "link": f"https://search.censys.io/certificates/{indicator}",
            "max": None,
        })

        return results

    # ─────────────────────────────────────────────────────
    # get_correlation — dispatcher
    # ─────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "ip")
        auth = self._auth(context)
        if not auth:
            return []

        if ioc_type == "ip":
            return await self._correlate_ip(indicator, context, auth)
        elif ioc_type == "domain":
            return await self._correlate_domain(indicator, context, auth)
        return []

    # ─────────────────────────────────────────────────────
    # Corrélation IP
    # Pivots :
    #   1. ASN partagé  — hosts avec même AS + mêmes ports ouverts
    #   2. Certificat TLS partagé  — hosts utilisant le même leaf cert
    #   3. JARM fingerprint  — hosts avec même JARM sur même port
    # ─────────────────────────────────────────────────────
    async def _correlate_ip(
        self, indicator: str, context: Dict[str, Any], auth: tuple
    ) -> List[Dict[str, Any]]:

        max_hosts = int(context.get("censys_max_hosts", 10))
        do_asn    = context.get("censys_pivot_asn",  True)
        do_cert   = context.get("censys_pivot_cert", True)
        do_jarm   = context.get("censys_pivot_jarm", False)

        # Récupérer l'hôte source
        raw = await self.requester.get(
            f"{self.url_v2}/hosts/{indicator}",
            auth=auth,
        )
        if not raw or "result" not in raw and "services" not in raw:
            return []

        host = raw.get("result") or raw
        services = host.get("services", [])
        asn_info = host.get("autonomous_system", {})

        pivot_tasks = []

        # ── Pivot 1 : ASN ────────────────────────────────
        if do_asn and asn_info.get("asn"):
            asn_num = asn_info["asn"]
            # On cherche des hosts dans le même ASN avec au moins un port commun
            open_ports = sorted({s["port"] for s in services if s.get("port")})
            if open_ports:
                port_clause = " OR ".join(f"services.port={p}" for p in open_ports[:3])
                q = f"autonomous_system.asn={asn_num} AND ({port_clause})"
                pivot_tasks.append(("asn", f"AS{asn_num}", q))

        # ── Pivot 2 : Certificat TLS ─────────────────────
        cert_fps: List[str] = []
        if do_cert:
            for svc in services:
                tls = svc.get("tls", {})
                fp = tls.get("certificates", {}).get("leaf_data", {}).get("fingerprint")
                if fp and fp not in cert_fps:
                    cert_fps.append(fp)

            for fp in cert_fps[:2]:
                q = f'services.tls.certificates.leaf_data.fingerprint: "{fp}"'
                pivot_tasks.append(("cert_fp", f"TLS cert {fp[:16]}…", q))

        # ── Pivot 3 : JARM ───────────────────────────────
        if do_jarm:
            for svc in services:
                jarm = svc.get("jarm", {}).get("fingerprint")
                port = svc.get("port")
                if jarm and port:
                    q = f'services.jarm.fingerprint: "{jarm}" AND services.port={port}'
                    pivot_tasks.append(("jarm", f"JARM:{jarm[:16]}…", q))

        if not pivot_tasks:
            return []

        # Exécuter les recherches en parallèle
        search_coros = [
            self._search_hosts(q, max_hosts, auth)
            for (_, _, q) in pivot_tasks
        ]
        responses = await asyncio.gather(*search_coros, return_exceptions=True)

        results: List[Dict[str, Any]] = []
        seen_ips: set = {indicator}

        for (pivot_type, pivot_label, _), response in zip(pivot_tasks, responses):
            if isinstance(response, Exception):
                continue
            for ip in response:
                if not ip or ip in seen_ips:
                    continue
                seen_ips.add(ip)
                results.append({
                    "source_indicator": indicator,
                    "source_type":      "ip",
                    "target_indicator": ip,
                    "target_type":      "ip",
                    "score":            1,
                    "pivot":            True,
                    "pivot_reason":     pivot_label,
                })

        return results

    # ─────────────────────────────────────────────────────
    # Corrélation Domaine
    # Pivots :
    #   1. Co-SAN — domaines partageant le même certificat TLS
    #   2. Issuer partagé — domaines avec même CA et même organisation
    # ─────────────────────────────────────────────────────
    async def _correlate_domain(
        self, indicator: str, context: Dict[str, Any], auth: tuple
    ) -> List[Dict[str, Any]]:

        max_certs = int(context.get("censys_max_certs", 10))
        do_cert   = context.get("censys_pivot_cert", True)

        if not do_cert:
            return []

        # Trouver les certs qui contiennent ce domaine
        query = f'names: "{indicator}"'
        data = await self.requester.get(
            f"{self.url_v2}/certificates/search",
            params={"q": query, "per_page": 10},
            auth=auth,
        )
        if not data:
            return []

        hits = data.get("result", {}).get("hits", [])
        if not hits:
            return []

        results: List[Dict[str, Any]] = []
        seen_domains: set = {indicator}

        for cert in hits[:5]:
            parsed = cert.get("parsed", {})
            names  = parsed.get("names", [])
            fp     = parsed.get("fingerprint_sha256") or cert.get("fingerprint_sha256", "")

            subject_dn = parsed.get("subject_dn", "")
            pivot_label = f"Shared TLS cert ({fp[:12]}…)" if fp else "Shared TLS cert"

            for name in names:
                # Ne pas injecter l'indicateur lui-même, ni les wildcards purs
                if not name or name == indicator or name in seen_domains:
                    continue
                if name.startswith("*."):
                    # Garder la racine du wildcard comme domaine pivot
                    name = name[2:]
                if not name or name in seen_domains:
                    continue
                seen_domains.add(name)
                results.append({
                    "source_indicator": indicator,
                    "source_type":      "domain",
                    "target_indicator": name,
                    "target_type":      "domain",
                    "score":            1,
                    "pivot":            True,
                    "pivot_reason":     pivot_label,
                })

            if len(results) >= max_certs:
                break

        return results

    # ─────────────────────────────────────────────────────
    # get_quotas  — /v2/account
    # ─────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        auth = self._auth(context)
        if not auth:
            return {}

        data = await self.requester.get(
            f"{self.url_v2}/account",
            auth=auth,
        )
        if not data:
            return {"plan_type": "unknown"}

        quota = data.get("quota", {})
        allowance  = quota.get("allowance", 0)
        used       = quota.get("used", 0)
        reset_date = quota.get("reset_timestamp", "")

        plan = "free" if allowance <= 250 else ("starter" if allowance <= 2000 else "pro")

        return {
            "used":      used,
            "limit":     allowance,
            "remaining": max(0, allowance - used),
            "plan_type": plan,
            "reset":     reset_date[:10] if reset_date else None,
        }

    # ─────────────────────────────────────────────────────
    # Helpers privés
    # ─────────────────────────────────────────────────────
    def _auth(self, context: Dict[str, Any]) -> Optional[tuple]:
        """
        Censys utilise HTTP Basic Auth avec app_id:secret.
        On accepte deux formats dans api_key :
          - "app_id:secret"   (séparé par le premier ":")
          - Seulement app_id (dégradé, pas d'auth possible)
        """
        api_key = context.get("api_key", "")
        if not api_key:
            return None
        if ":" in api_key:
            parts = api_key.split(":", 1)
            return (parts[0].strip(), parts[1].strip())
        # Tentative avec l'ID seul (échouera côté API mais ne crashe pas)
        return (api_key, "")

    async def _search_hosts(
        self, query: str, max_results: int, auth: tuple
    ) -> List[str]:
        """Lance une recherche /v2/hosts/search et retourne la liste des IPs."""
        data = await self.requester.get(
            f"{self.url_v2}/hosts/search",
            params={"q": query, "per_page": max_results},
            auth=auth,
        )
        if not data:
            return []
        hits = data.get("result", {}).get("hits", [])
        return [h.get("ip") for h in hits if h.get("ip")]

    @staticmethod
    def _f(indicator: str, name: str, field_type: str,
           value: Any, max_: Optional[int] = None) -> Dict[str, Any]:
        return {
            "indicator":      indicator,
            "indicator_type": "ioc",
            "field_name":     name,
            "field_type":     field_type,
            "value":          value,
            "icon":           None,
            "link":           None,
            "max":            max_,
        }
