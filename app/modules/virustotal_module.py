import asyncio
import base64
from typing import List, Dict, Any
from .module import Module


class VirusTotalModule(Module):

    name = "VirusTotal"
    description = "Threat intelligence — detections, cross-IOC relations"
    src_type = "external"
    supported_types = ["ip", "domain", "url", "hash"]
    icon = "shield"
    url = "https://www.virustotal.com/api/v3"

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # Relation endpoints per IOC type
    # ──────────────────────────────────────────────────────
    _REL_ENDPOINTS = {
        "ip": [
            "urls",
            "resolutions",
            "communicating_files",
            "historical_ssl_certificates",
            "related_threat_actors",
            "referrer_files",
            "comments",
        ],
        "domain": [
            "caa_records",
            "cname_records",
            "communicating_files",
            "historical_ssl_certificates",
            "mx_records",
            "ns_records",
            "referrer_files",
            "related_threat_actors",
            "resolutions",
            "soa_records",
            "urls",
            "subdomains",
            "comments",
        ],
        "url": [
            "communicating_files",
            "contacted_domains",
            "contacted_ips",
            "downloaded_files",
            "redirecting_urls",
            "redirects_to",
            "referrer_files",
            "referrer_urls",
            "related_threat_actors",
            "comments",
        ],
        "hash": [
            "bundled_files",
            "comments",
            "compressed_parents",
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "dropped_files",
            "email_parents",
            "execution_parents",
            "related_threat_actors",
            "submissions",
        ],
    }

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

        headers = {"x-apikey": api_key}
        base_endpoint, ioc_id = self._endpoint(indicator, ioc_type)
        if not base_endpoint:
            return []

        rel_names = self._REL_ENDPOINTS.get(ioc_type, [])

        # Build parallel tasks: relation endpoints + main endpoint last
        tasks = [
            self.requester.get(f"{base_endpoint}/{rel}?limit=10", headers=headers)
            for rel in rel_names
        ]
        tasks.append(self.requester.get(base_endpoint, headers=headers))

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Split results
        rel_responses = responses[:-1]
        main_response = responses[-1]

        if (
            not main_response
            or isinstance(main_response, Exception)
            or main_response.get("error")
        ):
            return []

        attrs = main_response.get("data", {}).get("attributes", {})

        # Parse relation data into a flat dict keyed by endpoint name
        relations: Dict[str, List[Dict]] = {}
        for rel_name, data in zip(rel_names, rel_responses):
            if not data or isinstance(data, Exception):
                relations[rel_name] = []
                continue
            relations[rel_name] = self._parse_relation(rel_name, data.get("data") or [])

        return self._extract_fields(indicator, ioc_type, attrs, relations)

    # ──────────────────────────────────────────────────────
    # _parse_relation  — normalize raw items per endpoint
    # ──────────────────────────────────────────────────────
    def _parse_relation(self, endpoint: str, items: list) -> List[Dict]:
        result = []
        for item in items:
            if isinstance(item, str):
                result.append({"value": item})
                continue

            attrs = item.get("attributes", {}) or {}

            if endpoint == "urls":
                result.append(
                    {
                        "url": attrs.get("url"),
                        "date": attrs.get("first_submission_date")
                        or attrs.get("last_submission_date"),
                    }
                )

            elif endpoint == "resolutions":
                result.append(
                    {
                        "hostname": attrs.get("host_name"),
                        "ip": attrs.get("ip_address"),
                        "date": attrs.get("date"),
                    }
                )

            elif endpoint in (
                "communicating_files",
                "referrer_files",
                "downloaded_files",
                "dropped_files",
                "bundled_files",
                "compressed_parents",
                "email_parents",
                "execution_parents",
            ):
                result.append(
                    {
                        "md5": attrs.get("md5"),
                        "sha256": attrs.get("sha256"),
                        "name": (attrs.get("names") or [None])[0],
                        "detections": attrs.get("last_analysis_stats", {}).get(
                            "malicious"
                        ),
                    }
                )

            elif endpoint == "historical_ssl_certificates":
                result.append(
                    {
                        "thumbprint": attrs.get("thumbprint_sha256"),
                        "date": attrs.get("first_seen_date"),
                    }
                )

            elif endpoint == "related_threat_actors":
                name = attrs.get("name") or item.get("id")
                if name:
                    result.append({"name": name})

            elif endpoint == "comments":
                result.append(
                    {
                        "text": attrs.get("text", "")[:200],
                        "date": attrs.get("date"),
                    }
                )

            elif endpoint == "subdomains":
                result.append({"value": item.get("id")})

            elif endpoint in (
                "cname_records",
                "mx_records",
                "ns_records",
                "soa_records",
                "caa_records",
            ):
                value = attrs.get("value") or attrs.get("host_name") or item.get("id")
                if value:
                    result.append({"value": value})

            elif endpoint == "contacted_ips":
                result.append({"ip": attrs.get("ip_address") or item.get("id")})

            elif endpoint == "contacted_domains":
                result.append({"hostname": attrs.get("domain") or item.get("id")})

            elif endpoint in ("contacted_urls",):
                result.append({"url": attrs.get("url")})

            elif endpoint in ("referrer_urls", "redirecting_urls", "redirects_to"):
                result.append({"url": attrs.get("url")})

            elif endpoint == "submissions":
                result.append(
                    {
                        "date": attrs.get("date"),
                        "source_key": attrs.get("source_key"),
                    }
                )

        return [r for r in result if any(v for v in r.values())]

    # ──────────────────────────────────────────────────────
    # _extract_fields  — build the field list for the UI
    # ──────────────────────────────────────────────────────
    def _extract_fields(
        self,
        indicator: str,
        ioc_type: str,
        attrs: Dict,
        relations: Dict[str, List[Dict]] = None,
    ) -> List[Dict[str, Any]]:
        res = []
        relations = relations or {}

        # ── Detection score (all types) ──────────────────
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = round(((malicious + suspicious) / total) * 100)

        # Valeurs émises en string pour que _isEmpty(0) ne filtre pas les scores à zéro
        res.append(self._f(indicator, "Detection Score", "score", str(score)))
        res.append(self._f(indicator, "Malicious", "label-capsule", str(malicious)))
        res.append(self._f(indicator, "Suspicious", "label-capsule", str(suspicious)))

        # ── Reputation VT (all types) ──
        if attrs.get("reputation") is not None:
            res.append(
                self._f(
                    indicator, "Reputation", "label-capsule", str(attrs["reputation"])
                )
            )

        # ── Last analysis date (all types) ───────────────
        last = attrs.get("last_analysis_date") or attrs.get("last_modification_date")
        if last:
            import datetime

            dt = datetime.datetime.utcfromtimestamp(last).strftime("%Y-%m-%d")
            res.append(self._f(indicator, "Last Analysis", "label-capsule", dt))

        # ── Tags (all types) ────────────────────────────
        tags = attrs.get("tags", [])
        if tags:
            res.append(self._f(indicator, "Tags", "list", tags))

        # ════════════════════════════════════════════════
        # IP
        # ════════════════════════════════════════════════
        if ioc_type == "ip":
            if attrs.get("asn"):
                res.append(
                    self._f(indicator, "ASN", "label-capsule", str(attrs["asn"]))
                )
            if attrs.get("as_owner"):
                res.append(
                    self._f(
                        indicator, "Organization", "label-capsule", attrs["as_owner"]
                    )
                )
            if attrs.get("country"):
                res.append(
                    self._f(indicator, "Country", "label-capsule", attrs["country"])
                )
            if attrs.get("network"):
                res.append(
                    self._f(indicator, "Network", "label-capsule", attrs["network"])
                )

            # Resolutions
            resolutions = [
                r["hostname"]
                for r in relations.get("resolutions", [])
                if r.get("hostname")
            ]
            if resolutions:
                res.append(
                    self._f(indicator, "Resolutions", "list", resolutions, max_=10)
                )

            # URLs seen
            urls = [r["url"] for r in relations.get("urls", []) if r.get("url")]
            if urls:
                res.append(self._f(indicator, "URLs Seen", "list", urls, max_=10))

            # Communicating files
            comm_files = self._format_files(relations.get("communicating_files", []))
            if comm_files:
                res.append(
                    self._f(
                        indicator, "Communicating Files", "list", comm_files, max_=10
                    )
                )

            # SSL certificates
            certs = [
                r["thumbprint"]
                for r in relations.get("historical_ssl_certificates", [])
                if r.get("thumbprint")
            ]
            if certs:
                res.append(
                    self._f(indicator, "SSL Certificates", "list", certs, max_=5)
                )

            # Threat actors
            actors = [
                r["name"]
                for r in relations.get("related_threat_actors", [])
                if r.get("name")
            ]
            if actors:
                res.append(self._f(indicator, "Threat Actors", "list", actors, max_=10))

            # Comments
            comments = [
                r["text"] for r in relations.get("comments", []) if r.get("text")
            ]
            if comments:
                res.append(self._f(indicator, "Comments", "list", comments, max_=5))

        # ════════════════════════════════════════════════
        # Domain
        # ════════════════════════════════════════════════
        elif ioc_type == "domain":
            if attrs.get("registrar"):
                res.append(
                    self._f(indicator, "Registrar", "label-capsule", attrs["registrar"])
                )

            # Parse WHOIS for creation/expiry dates
            whois_str = attrs.get("whois", "")
            if whois_str:
                whois = self._parse_whois(whois_str)
                creation = whois.get("create_date") or attrs.get("creation_date")
                expiry = whois.get("expiry_date") or attrs.get("expiration_date")
                if creation:
                    res.append(
                        self._f(
                            indicator,
                            "Creation Date",
                            "label-capsule",
                            str(creation)[:10],
                        )
                    )
                if expiry:
                    res.append(
                        self._f(
                            indicator, "Expiry Date", "label-capsule", str(expiry)[:10]
                        )
                    )

            # Resolutions (IP)
            resolved_ips = [
                r["ip"] for r in relations.get("resolutions", []) if r.get("ip")
            ]
            if resolved_ips:
                res.append(
                    self._f(indicator, "Resolved IPs", "list", resolved_ips, max_=10)
                )

            # Subdomains
            subs = [
                r["value"] for r in relations.get("subdomains", []) if r.get("value")
            ]
            if subs:
                res.append(self._f(indicator, "Subdomains", "list", subs, max_=10))

            # NS records
            ns = [r["value"] for r in relations.get("ns_records", []) if r.get("value")]
            if ns:
                res.append(self._f(indicator, "NS Records", "list", ns, max_=5))

            # MX records
            mx = [r["value"] for r in relations.get("mx_records", []) if r.get("value")]
            if mx:
                res.append(self._f(indicator, "MX Records", "list", mx, max_=5))

            # SSL certificates
            certs = [
                r["thumbprint"]
                for r in relations.get("historical_ssl_certificates", [])
                if r.get("thumbprint")
            ]
            if certs:
                res.append(
                    self._f(indicator, "SSL Certificates", "list", certs, max_=5)
                )

            # URLs seen
            urls = [r["url"] for r in relations.get("urls", []) if r.get("url")]
            if urls:
                res.append(self._f(indicator, "URLs Seen", "list", urls, max_=10))

            # Communicating files
            comm_files = self._format_files(relations.get("communicating_files", []))
            if comm_files:
                res.append(
                    self._f(
                        indicator, "Communicating Files", "list", comm_files, max_=10
                    )
                )

            # Threat actors
            actors = [
                r["name"]
                for r in relations.get("related_threat_actors", [])
                if r.get("name")
            ]
            if actors:
                res.append(self._f(indicator, "Threat Actors", "list", actors, max_=10))

            # Comments
            comments = [
                r["text"] for r in relations.get("comments", []) if r.get("text")
            ]
            if comments:
                res.append(self._f(indicator, "Comments", "list", comments, max_=5))

        # ════════════════════════════════════════════════
        # URL
        # ════════════════════════════════════════════════
        elif ioc_type == "url":
            if attrs.get("host"):
                res.append(self._f(indicator, "Domain", "label-capsule", attrs["host"]))
            if attrs.get("last_final_url") and attrs["last_final_url"] != indicator:
                res.append(
                    self._f(
                        indicator, "Final URL", "label-capsule", attrs["last_final_url"]
                    )
                )

            redirects = attrs.get("redirection_chain", [])
            if redirects:
                res.append(
                    self._f(indicator, "Redirect Chain", "list", redirects, max_=5)
                )

            # Contacted IPs
            c_ips = [r["ip"] for r in relations.get("contacted_ips", []) if r.get("ip")]
            if c_ips:
                res.append(self._f(indicator, "Contacted IPs", "list", c_ips, max_=10))

            # Contacted domains
            c_domains = [
                r["hostname"]
                for r in relations.get("contacted_domains", [])
                if r.get("hostname")
            ]
            if c_domains:
                res.append(
                    self._f(indicator, "Contacted Domains", "list", c_domains, max_=10)
                )

            # Downloaded files
            dl_files = self._format_files(relations.get("downloaded_files", []))
            if dl_files:
                res.append(
                    self._f(indicator, "Downloaded Files", "list", dl_files, max_=10)
                )

            # Redirects to
            redir_to = [
                r["url"] for r in relations.get("redirects_to", []) if r.get("url")
            ]
            if redir_to:
                res.append(self._f(indicator, "Redirects To", "list", redir_to, max_=5))

            # Referrer URLs
            ref_urls = [
                r["url"] for r in relations.get("referrer_urls", []) if r.get("url")
            ]
            if ref_urls:
                res.append(
                    self._f(indicator, "Referrer URLs", "list", ref_urls, max_=5)
                )

            # Threat actors
            actors = [
                r["name"]
                for r in relations.get("related_threat_actors", [])
                if r.get("name")
            ]
            if actors:
                res.append(self._f(indicator, "Threat Actors", "list", actors, max_=10))

            # Comments
            comments = [
                r["text"] for r in relations.get("comments", []) if r.get("text")
            ]
            if comments:
                res.append(self._f(indicator, "Comments", "list", comments, max_=5))

        # ════════════════════════════════════════════════
        # Hash / File
        # ════════════════════════════════════════════════
        elif ioc_type == "hash":
            if attrs.get("md5"):
                res.append(self._f(indicator, "MD5", "label-capsule", attrs["md5"]))
            if attrs.get("sha1"):
                res.append(self._f(indicator, "SHA1", "label-capsule", attrs["sha1"]))
            if attrs.get("sha256"):
                res.append(
                    self._f(indicator, "SHA256", "label-capsule", attrs["sha256"])
                )
            if attrs.get("size"):
                res.append(
                    self._f(
                        indicator, "Size", "label-capsule", f"{attrs['size']} bytes"
                    )
                )
            if attrs.get("type_description"):
                res.append(
                    self._f(
                        indicator,
                        "File Type",
                        "label-capsule",
                        attrs["type_description"],
                    )
                )

            names = attrs.get("names", [])
            if names:
                res.append(self._f(indicator, "File Names", "list", names[:5], max_=5))

            # Contacted IPs
            c_ips = [r["ip"] for r in relations.get("contacted_ips", []) if r.get("ip")]
            if c_ips:
                res.append(self._f(indicator, "Contacted IPs", "list", c_ips, max_=10))

            # Contacted domains
            c_domains = [
                r["hostname"]
                for r in relations.get("contacted_domains", [])
                if r.get("hostname")
            ]
            if c_domains:
                res.append(
                    self._f(indicator, "Contacted Domains", "list", c_domains, max_=10)
                )

            # Contacted URLs
            c_urls = [
                r["url"] for r in relations.get("contacted_urls", []) if r.get("url")
            ]
            if c_urls:
                res.append(
                    self._f(indicator, "Contacted URLs", "list", c_urls, max_=10)
                )

            # Dropped files
            dropped = self._format_files(relations.get("dropped_files", []))
            if dropped:
                res.append(
                    self._f(indicator, "Dropped Files", "list", dropped, max_=10)
                )

            # Execution parents
            exec_parents = self._format_files(relations.get("execution_parents", []))
            if exec_parents:
                res.append(
                    self._f(
                        indicator, "Execution Parents", "list", exec_parents, max_=5
                    )
                )

            # Threat actors
            actors = [
                r["name"]
                for r in relations.get("related_threat_actors", [])
                if r.get("name")
            ]
            if actors:
                res.append(self._f(indicator, "Threat Actors", "list", actors, max_=10))

            # Submissions count
            submissions = relations.get("submissions", [])
            if submissions:
                res.append(
                    self._f(
                        indicator,
                        "Submission Count",
                        "label-capsule",
                        str(len(submissions)),
                    )
                )

            # Comments
            comments = [
                r["text"] for r in relations.get("comments", []) if r.get("text")
            ]
            if comments:
                res.append(self._f(indicator, "Comments", "list", comments, max_=5))

        return res

    # ──────────────────────────────────────────────────────
    # get_correlation  (unchanged logic)
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        ioc_type = context.get("ioc_type", "ip")
        all_roots = context.get("all_root_indicators", [])
        threshold = int(context.get("vt_detection_threshold", 3))
        min_shared_roots = int(context.get("vt_min_shared_roots", 2))

        if not api_key:
            return []

        other_roots = [
            r["value"]
            for r in all_roots
            if r["value"] != indicator and r["type"] == ioc_type
        ]
        if not other_roots:
            return []

        headers = {"x-apikey": api_key}
        rel_map = {
            "ip": [("resolutions", "domain"), ("communicating_files", "hash")],
            "domain": [("resolutions", "ip"), ("communicating_files", "hash")],
            "url": [("network_location", "domain")],
            "hash": [("contacted_ips", "ip"), ("contacted_domains", "domain")],
        }

        my_relations: Dict[str, str] = {}
        base, _ = self._endpoint(indicator, ioc_type)
        if not base:
            return []

        for rel_name, target_type in rel_map.get(ioc_type, []):
            rel_url = f"{base}/relationships/{rel_name}?limit=20"
            data = await self.requester.get(rel_url, headers=headers)
            if not data:
                continue
            for item in data.get("data", []):
                attrs = item.get("attributes", {})
                val = self._extract_rel_value(item, attrs, target_type)
                if not val or val == indicator:
                    continue
                if target_type == "hash":
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    if malicious < threshold:
                        continue
                my_relations[val] = target_type

        if not my_relations:
            return []

        shared_counts: Dict[str, int] = {}   # val → nombre de roots qui partagent cette relation
        shared_types:  Dict[str, str] = {}   # val → type

        for other in other_roots:
            other_base, _ = self._endpoint(other, ioc_type)
            if not other_base:
                continue
            for rel_name, target_type in rel_map.get(ioc_type, []):
                rel_url = f"{other_base}/relationships/{rel_name}?limit=20"
                data = await self.requester.get(rel_url, headers=headers)
                if not data:
                    continue
                for item in data.get("data", []):
                    attrs = item.get("attributes", {})
                    val = self._extract_rel_value(item, attrs, target_type)
                    if val and val in my_relations:
                        shared_counts[val] = shared_counts.get(val, 0) + 1
                        shared_types[val]  = my_relations[val]

        results = []
        for val, count in shared_counts.items():
            if count < min_shared_roots:      # ← filtre : doit être partagé par assez de roots
                continue
            results.append({
                "source_indicator": indicator,
                "source_type":      ioc_type,
                "target_indicator": val,
                "target_type":      shared_types[val],
                "score":            1,
                "pivot":            True,
                "pivot_reason":     f"VT cross-IOC relation (shared with {count}/{len(other_roots)} root(s))",
            })

        return results

    # ──────────────────────────────────────────────────────
    # get_quotas  (unchanged)
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        if not api_key:
            return {}
        headers = {"x-apikey": api_key}
        raw = await self.requester.get(f"{self.url}/users/{api_key}", headers=headers)
        if not raw:
            return {}
        attributes = raw.get("data", {}).get("attributes", {})
        quotas = attributes.get("quotas", {})

        daily = quotas.get("api_requests_daily", {})
        monthly = quotas.get("api_requests_monthly", {})
        hourly = quotas.get("api_requests_hourly", {})

        selected = daily or monthly or hourly or {}

        try:
            limit = int(selected.get("allowed", 0))
            used = int(selected.get("used", 0))
        except Exception:
            limit = 0
            used = 0

        PUBLIC_DAILY_LIMIT = 500
        if limit == 0:
            plan_type = "unknown"
        elif limit <= PUBLIC_DAILY_LIMIT:
            plan_type = "free"
        else:
            plan_type = "pro"

        return {
            "used": used,
            "limit": limit,
            "remaining": (limit - used) if limit else 0,
            "plan_type": plan_type,
        }

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "virustotal"
        return base

    def get_correlation_fields(self):
        return [
            {
                "key": "vt_detection_threshold",
                "type": "range",
                "label": "Min detections on pivot",
                "min": 0,
                "max": 91,
                "default": 3,
            },
            {
                "key": "vt_min_shared_roots",       # ← clé renommée
                "type": "range",
                "label": "Min shared relations between roots",
                "min": 1,
                "max": 10,
                "default": 2,
            },
        ]

    # ── Helpers ───────────────────────────────────────────

    def _endpoint(self, indicator: str, ioc_type: str):
        if ioc_type == "ip":
            return f"{self.url}/ip_addresses/{indicator}", indicator
        if ioc_type == "domain":
            return f"{self.url}/domains/{indicator}", indicator
        if ioc_type == "url":
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            return f"{self.url}/urls/{url_id}", url_id
        if ioc_type == "hash":
            return f"{self.url}/files/{indicator}", indicator
        return None, None

    def _extract_rel_value(self, item, attrs, target_type):
        if target_type == "domain":
            return attrs.get("host_name") or item.get("id")
        if target_type == "ip":
            return attrs.get("ip_address") or item.get("id")
        if target_type == "hash":
            return attrs.get("sha256") or item.get("id")
        return item.get("id")

    def _format_files(self, file_list: List[Dict]) -> List[str]:
        """Return compact string representation of file entries."""
        out = []
        for f in file_list:
            name = f.get("name")
            sha256 = f.get("sha256", "")
            det = f.get("detections")
            label = name or (sha256[:16] + "…" if sha256 else "unknown")
            if det is not None:
                label = f"{label} ({det} detections)"
            out.append(label)
        return out

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

    @staticmethod
    def _parse_whois(whois_str: str) -> Dict[str, str]:
        data = {}
        if not whois_str:
            return data
        for line in whois_str.splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                data[key.strip().lower().replace(" ", "_")] = value.strip()
        return data
