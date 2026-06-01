# app/modules/censys_module.py
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from .module import Module


class CensysModule(Module):
    """
    Module Censys — Internet-wide scan data.
    Couvre : IP (hosts), domaines (certificates + DNS), certificats (SHA-256).

    Endpoints utilisés :
        - /v2/hosts/{ip}                         → enrichissement IP
        - /v2/certificates/search                → enrichissement domaine (CN/SAN)
        - /v1/view/certificates/{sha256}         → enrichissement hash de certificat
        - /v2/hosts/search                       → corrélation IP (pivot AS, port, cert, JARM)
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
            return await self._info_certificate(indicator, auth)
        return []

    # ─────────────────────────────────────────────────────
    # get_info — IP  (/v2/hosts/{ip})
    # Structure réelle : {"code": 200, "status": "OK", "result": {"ip": ..., "services": [...], ...}}
    # ─────────────────────────────────────────────────────
    async def _info_ip(
        self, indicator: str, auth: Tuple[str, str]
    ) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.url_v2}/hosts/{indicator}",
            auth=auth,
        )
        print(f"[Censys] raw={raw}")  # ← ajoute ça

        if not raw or not isinstance(raw, dict):
            print(f"[Censys] guard 1 — raw invalide: {type(raw)}")  # ← et ça
            return []
        if "result" not in raw:
            print(
                f"[Censys] guard 2 — pas de 'result', clés présentes: {list(raw.keys())}"
            )  # ← et ça
            return []

        host = raw["result"]
        results: List[Dict[str, Any]] = []

        # ── Identité réseau ───────────────────────────────
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

        # ── Services ──────────────────────────────────────
        services = host.get("services") or []
        if services:
            svc_list = []
            tls_names: set = set()
            cert_fps: set = set()
            jarm_fps: set = set()

            for svc in services:
                entry = self._parse_service(svc)
                if entry:
                    svc_list.append(entry)
                    # Collecter les noms TLS pour la section dns
                    tls = svc.get("tls") or {}
                    leaf = (tls.get("certificates") or {}).get("leaf_data") or {}
                    for name in leaf.get("names") or []:
                        if name:
                            tls_names.add(name)
                    fp = leaf.get("fingerprint_sha256") or leaf.get("fingerprint")
                    if fp:
                        cert_fps.add(fp)
                    # JARM
                    jarm = svc.get("jarm") or {}
                    if jarm.get("fingerprint"):
                        jarm_fps.add(jarm["fingerprint"])

            if svc_list:
                results.append(
                    self._f(indicator, "Services", "censys_services", svc_list)
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
            if jarm_fps:
                results.append(
                    self._f(
                        indicator,
                        "JARM Fingerprints",
                        "list",
                        list(jarm_fps)[:3],
                        max_=3,
                    )
                )

        # ── Open ports résumé ─────────────────────────────
        ports = sorted({s["port"] for s in services if s.get("port")})
        if ports:
            results.append(
                self._f(
                    indicator, "Open Ports", "list", [str(p) for p in ports], max_=20
                )
            )

        # ── Dernière mise à jour ──────────────────────────
        last_updated = host.get("last_updated_at") or ""
        if last_updated:
            results.append(
                self._f(indicator, "Last Scanned", "label-capsule", last_updated[:10])
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
    # _parse_service — construit le dict d'un service Censys
    # Structure réelle d'un service :
    # {
    #   "port": 443,
    #   "transport_protocol": "TCP",
    #   "service_name": "HTTP",
    #   "extended_service_name": "HTTPS",
    #   "software": [{"uniform_resource_identifier": "cpe:...", "product": "nginx", "version": "1.x"}],
    #   "tls": {"certificates": {"leaf_data": {"fingerprint_sha256": "...", "names": [...], "subject": {...}}}},
    #   "jarm": {"fingerprint": "..."},
    #   "banner": "...",
    # }
    # ─────────────────────────────────────────────────────
    @staticmethod
    def _parse_service(svc: Dict) -> Optional[Dict]:
        port = svc.get("port")
        if not port:
            return None

        proto = (svc.get("transport_protocol") or "TCP").lower()
        svc_name = svc.get("extended_service_name") or svc.get("service_name") or ""

        entry: Dict[str, Any] = {
            "port": port,
            "transport": proto,
        }
        if svc_name:
            entry["service"] = svc_name

        # Produit / version depuis le tableau software
        software = svc.get("software") or []
        if software and isinstance(software, list):
            first = software[0] if isinstance(software[0], dict) else {}
            product = first.get("product") or ""
            version = first.get("version") or ""
            if not product:
                # Fallback : parser le CPE "cpe:2.3:a:vendor:product:version:..."
                cpe = first.get("uniform_resource_identifier") or ""
                parts = cpe.split(":")
                if len(parts) >= 5:
                    product = parts[4].replace("_", " ").title()
                    if len(parts) >= 6 and parts[5] not in ("*", "-", ""):
                        version = parts[5]
            if product:
                entry["product"] = product
            if version:
                entry["version"] = version

        # TLS
        tls = svc.get("tls") or {}
        leaf = (tls.get("certificates") or {}).get("leaf_data") or {}
        if leaf:
            subject = leaf.get("subject") or {}
            cn_list = subject.get("common_name") or []
            cn = (
                cn_list[0]
                if isinstance(cn_list, list) and cn_list
                else (cn_list if isinstance(cn_list, str) else "")
            )
            fp = leaf.get("fingerprint_sha256") or leaf.get("fingerprint") or ""
            if cn:
                entry["tls_cn"] = cn
            if fp:
                entry["tls_fp"] = fp[:32] + ("…" if len(fp) > 32 else "")

        # JARM
        jarm_fp = (svc.get("jarm") or {}).get("fingerprint") or ""
        if jarm_fp:
            entry["jarm"] = jarm_fp

        # Banner
        banner = svc.get("banner") or ""
        if banner and len(banner) > 4:
            entry["banner"] = banner[:300]

        return entry

    # ─────────────────────────────────────────────────────
    # get_info — Domaine  (/v2/certificates/search)
    # ─────────────────────────────────────────────────────
    async def _info_domain(
        self, indicator: str, auth: Tuple[str, str]
    ) -> List[Dict[str, Any]]:
        data = await self.requester.get(
            f"{self.url_v2}/certificates/search",
            params={"q": f'names: "{indicator}"', "per_page": 20},
            auth=auth,
        )

        results: List[Dict[str, Any]] = []
        hits = ((data or {}).get("result") or {}).get("hits") or []

        if not hits:
            results.append(
                self._f(indicator, "Certificates Found", "label-capsule", "0")
            )
            return results

        results.append(
            self._f(indicator, "Certificates Found", "label-capsule", str(len(hits)))
        )

        issuers: set = set()
        all_names: set = set()
        fps: List[str] = []
        validity_info: List[str] = []

        for cert in hits[:20]:
            parsed = cert.get("parsed") or {}

            # Issuer
            issuer_org = (parsed.get("issuer") or {}).get("organization") or []
            if isinstance(issuer_org, list) and issuer_org:
                issuers.add(issuer_org[0])
            elif isinstance(issuer_org, str) and issuer_org:
                issuers.add(issuer_org)

            # SANs / noms
            for n in parsed.get("names") or []:
                if n and n != indicator:
                    all_names.add(n)

            # Fingerprint
            fp = (
                parsed.get("fingerprint_sha256") or cert.get("fingerprint_sha256") or ""
            )
            if fp and fp not in fps:
                fps.append(fp)

            # Expiry
            not_after = (parsed.get("validity_period") or {}).get("not_after") or ""
            if not_after:
                validity_info.append(not_after)

        if issuers:
            results.append(
                self._f(
                    indicator,
                    "Certificate Issuers",
                    "list",
                    sorted(issuers)[:5],
                    max_=5,
                )
            )

        related = sorted(n for n in all_names if indicator not in n)[:10]
        if related:
            results.append(
                self._f(indicator, "Related Names (SAN)", "list", related, max_=10)
            )

        if fps:
            results.append(self._f(indicator, "Cert SHA-256", "list", fps[:3], max_=3))

        if validity_info:
            results.append(
                self._f(
                    indicator,
                    "Latest Expiry",
                    "label-capsule",
                    sorted(validity_info)[-1][:10],
                )
            )

        results.append(
            {
                "indicator": indicator,
                "indicator_type": "domain",
                "field_name": "Censys Certs",
                "field_type": "label-capsule",
                "value": "Search on Censys",
                "icon": "external-link",
                "link": f"https://search.censys.io/certificates?q=names%3A%22{indicator}%22",
                "max": None,
            }
        )

        return results

    # ─────────────────────────────────────────────────────
    # get_info — Certificat SHA-256  (/v1/view/certificates/{sha256})
    # ─────────────────────────────────────────────────────
    async def _info_certificate(
        self, indicator: str, auth: Tuple[str, str]
    ) -> List[Dict[str, Any]]:
        raw = await self.requester.get(
            f"{self.url_v1}/view/certificates/{indicator}",
            auth=auth,
        )
        if not raw or not isinstance(raw, dict):
            return []

        parsed = raw.get("parsed") or {}
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

        sig_alg = (parsed.get("signature_algorithm") or {}).get("name") or ""
        if sig_alg:
            results.append(
                self._f(indicator, "Sig Algorithm", "label-capsule", sig_alg)
            )

        key_type = (
            (parsed.get("subject_key_info") or {}).get("key_algorithm") or {}
        ).get("name") or ""
        if key_type:
            results.append(self._f(indicator, "Key Type", "label-capsule", key_type))

        # Hosts présentant ce cert
        host_ips = [h.get("ip") for h in (raw.get("hosts") or []) if h.get("ip")]
        if host_ips:
            results.append(
                self._f(indicator, "Hosts Using Cert", "list", host_ips[:10], max_=10)
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
    # Corrélation IP — ASN + cert TLS + JARM
    # ─────────────────────────────────────────────────────
    async def _correlate_ip(
        self, indicator: str, context: Dict[str, Any], auth: Tuple[str, str]
    ) -> List[Dict[str, Any]]:

        max_hosts = int(context.get("censys_max_hosts", 10))
        do_asn = bool(context.get("censys_pivot_asn", True))
        do_cert = bool(context.get("censys_pivot_cert", True))
        do_jarm = bool(context.get("censys_pivot_jarm", False))

        raw = await self.requester.get(
            f"{self.url_v2}/hosts/{indicator}",
            auth=auth,
        )
        if not raw or "result" not in raw:
            return []

        host = raw["result"]
        services = host.get("services") or []
        asn_info = host.get("autonomous_system") or {}

        pivot_tasks = []  # list of (pivot_label, query_string)

        # ── Pivot 1 : ASN ────────────────────────────────
        if do_asn and asn_info.get("asn"):
            asn_num = asn_info["asn"]
            open_ports = sorted({s["port"] for s in services if s.get("port")})[:4]
            if open_ports:
                port_clause = " OR ".join(f"services.port={p}" for p in open_ports)
                pivot_tasks.append(
                    (
                        f"AS{asn_num}",
                        f"autonomous_system.asn={asn_num} AND ({port_clause})",
                    )
                )

        # ── Pivot 2 : Certificat TLS ─────────────────────
        if do_cert:
            seen_fps: set = set()
            for svc in services:
                leaf = ((svc.get("tls") or {}).get("certificates") or {}).get(
                    "leaf_data"
                ) or {}
                fp = leaf.get("fingerprint_sha256") or leaf.get("fingerprint") or ""
                if fp and fp not in seen_fps:
                    seen_fps.add(fp)
                    pivot_tasks.append(
                        (
                            f"TLS cert {fp[:16]}…",
                            f'services.tls.certificates.leaf_data.fingerprint_sha256: "{fp}"',
                        )
                    )
                if len(seen_fps) >= 2:
                    break  # Limiter à 2 certs pour ne pas exploser les requêtes

        # ── Pivot 3 : JARM ───────────────────────────────
        if do_jarm:
            seen_jarm: set = set()
            for svc in services:
                jarm_fp = (svc.get("jarm") or {}).get("fingerprint") or ""
                port = svc.get("port")
                if jarm_fp and port and jarm_fp not in seen_jarm:
                    seen_jarm.add(jarm_fp)
                    pivot_tasks.append(
                        (
                            f"JARM {jarm_fp[:16]}…",
                            f'services.jarm.fingerprint: "{jarm_fp}" AND services.port={port}',
                        )
                    )
                if len(seen_jarm) >= 2:
                    break

        if not pivot_tasks:
            return []

        responses = await asyncio.gather(
            *[self._search_hosts(q, max_hosts, auth) for (_, q) in pivot_tasks],
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

    # ─────────────────────────────────────────────────────
    # Corrélation Domaine — co-SAN via certificats partagés
    # ─────────────────────────────────────────────────────
    async def _correlate_domain(
        self, indicator: str, context: Dict[str, Any], auth: Tuple[str, str]
    ) -> List[Dict[str, Any]]:

        max_certs = int(context.get("censys_max_certs", 10))

        data = await self.requester.get(
            f"{self.url_v2}/certificates/search",
            params={"q": f'names: "{indicator}"', "per_page": 10},
            auth=auth,
        )
        if not data:
            return []

        hits = (data.get("result") or {}).get("hits") or []
        if not hits:
            return []

        results: List[Dict[str, Any]] = []
        seen_domains: set = {indicator}

        for cert in hits[:5]:
            parsed = cert.get("parsed") or {}
            fp = (
                parsed.get("fingerprint_sha256") or cert.get("fingerprint_sha256") or ""
            )
            label = f"Shared TLS cert ({fp[:12]}…)" if fp else "Shared TLS cert"

            for name in parsed.get("names") or []:
                if not name or name in seen_domains:
                    continue
                # Dé-wildcarder
                clean = name[2:] if name.startswith("*.") else name
                if not clean or clean in seen_domains:
                    continue
                seen_domains.add(clean)
                results.append(
                    {
                        "source_indicator": indicator,
                        "source_type": "domain",
                        "target_indicator": clean,
                        "target_type": "domain",
                        "score": 1,
                        "pivot": True,
                        "pivot_reason": label,
                    }
                )

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

        data = await self.requester.get(f"{self.url_v2}/account", auth=auth)
        if not data or not isinstance(data, dict):
            return {"plan_type": "unknown"}

        quota = data.get("quota") or {}
        allowance = int(quota.get("allowance") or 0)
        used = int(quota.get("used") or 0)
        reset_date = quota.get("reset_timestamp") or ""

        plan = (
            "free" if allowance <= 250 else ("starter" if allowance <= 2000 else "pro")
        )

        return {
            "used": used,
            "limit": allowance,
            "remaining": max(0, allowance - used),
            "plan_type": plan,
            "reset": reset_date[:10] if reset_date else None,
        }

    # ─────────────────────────────────────────────────────
    # Helpers privés
    # ─────────────────────────────────────────────────────
    def _auth(self, context: Dict[str, Any]) -> Optional[Tuple[str, str]]:
        """
        Censys utilise HTTP Basic Auth : app_id:api_secret.
        La clé dans SecretStore doit être au format "app_id:api_secret".
        """
        api_key = (context.get("api_key") or "").strip()
        if not api_key:
            return None
        if ":" in api_key:
            app_id, secret = api_key.split(":", 1)
            return (app_id.strip(), secret.strip()) if app_id.strip() else None
        return None  # Sans secret, l'auth Basic échouera — on retourne None directement

    async def _search_hosts(
        self, query: str, max_results: int, auth: Tuple[str, str]
    ) -> List[str]:
        data = await self.requester.get(
            f"{self.url_v2}/hosts/search",
            params={"q": query, "per_page": max_results},
            auth=auth,
        )
        if not data or not isinstance(data, dict):
            return []
        return [
            h.get("ip")
            for h in ((data.get("result") or {}).get("hits") or [])
            if h.get("ip")
        ]

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
