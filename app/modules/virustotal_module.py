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
        endpoint, _ = self._endpoint(indicator, ioc_type)
        if not endpoint:
            return []
        raw = await self.requester.get(endpoint, headers=headers)
        if not raw or raw.get("error"):
            return []
        attrs = raw.get("data", {}).get("attributes", {})
        return self._extract_fields(indicator, ioc_type, attrs)

    # ──────────────────────────────────────────────────────
    # get_correlation
    #
    # Croisement des relations VT entre IOCs root du même case.
    # Le contexte reçoit "all_root_indicators" (liste de valeurs)
    # injectée par services.py.
    # Pour chaque IOC, on récupère ses relations (résolutions, fichiers…)
    # et on ne retient que ceux qui apparaissent dans les relations
    # d'AU MOINS un autre IOC root → corrélation croisée.
    # Si un seul IOC root, aucune corrélation croisée possible.
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        ioc_type = context.get("ioc_type", "ip")
        all_roots = context.get("all_root_indicators", [])
        threshold = int(context.get("vt_detection_threshold", 3))
        max_rel = int(context.get("vt_max_relations", 10))

        if not api_key:
            return []

        # Croisement uniquement possible avec ≥ 2 IOCs root
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

        # Collecte les relations de l'IOC courant
        my_relations: Dict[str, str] = {}  # value → target_type
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

        # Collecte les relations de chaque autre IOC root pour le croisement
        shared: Dict[str, str] = {}
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
                        shared[val] = my_relations[val]

        # Ne retenir que les éléments partagés avec au moins un autre IOC root
        results = []
        for val, target_type in list(shared.items())[:max_rel]:
            results.append(
                {
                    "source_indicator": indicator,
                    "source_type": ioc_type,
                    "target_indicator": val,
                    "target_type": target_type,
                    "score": 1,
                    "pivot": True,
                    "pivot_reason": f"VT cross-IOC relation (shared with {len(other_roots)} root(s))",
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
        headers = {"x-apikey": api_key}
        raw = await self.requester.get(f"{self.url}/users/{api_key}", headers=headers)
        if not raw:
            return {}
        attributes = raw.get("data", {}).get("attributes", {})
        quotas = attributes.get("quotas", {})

        daily = quotas.get("api_requests_daily", {})
        monthly = quotas.get("api_requests_monthly", {})
        hourly = quotas.get("api_requests_hourly", {})

        if daily:
            selected = daily
        elif monthly:
            selected = monthly
        elif hourly:
            selected = hourly
        else:
            selected = {}

        try:
            limit = int(selected.get("allowed", 0))
            used = int(selected.get("used", 0))
        except:
            limit = 0
            used = 0

        # Public API constraints (FREE RULE)
        PUBLIC_DAILY_LIMIT = 500

        plan_type = "free"

        # condition 1: small quota → free
        if limit <= PUBLIC_DAILY_LIMIT:
            plan_type = "free"

        # condition 2: enterprise / paid (large quota)
        elif limit > PUBLIC_DAILY_LIMIT:
            plan_type = "pro"

        # fallback safety
        if limit == 0:
            plan_type = "unknown"

        # =========================
        # FINAL OUTPUT
        # =========================
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
                "key": "vt_max_relations",
                "type": "range",
                "label": "Max shared relations",
                "min": 1,
                "max": 30,
                "default": 10,
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

    def _extract_fields(self, indicator, ioc_type, attrs) -> List[Dict[str, Any]]:
        res = []
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = round(((malicious + suspicious) / total) * 100)

        res.append(self._f(indicator, "Detection Score", "score", score))
        res.append(self._f(indicator, "Malicious", "label-capsule", malicious))
        res.append(self._f(indicator, "Suspicious", "label-capsule", suspicious))

        if attrs.get("reputation") is not None:
            res.append(
                self._f(indicator, "Reputation", "label-capsule", attrs["reputation"])
            )
        if ioc_type == "ip":
            if attrs.get("country"):
                res.append(
                    self._f(indicator, "Country", "label-capsule", attrs["country"])
                )
            if attrs.get("as_owner"):
                res.append(
                    self._f(indicator, "ASN Owner", "label-capsule", attrs["as_owner"])
                )
        if ioc_type == "domain":
            if attrs.get("registrar"):
                res.append(
                    self._f(indicator, "Registrar", "label-capsule", attrs["registrar"])
                )
            cats = list((attrs.get("categories") or {}).values())
            if cats:
                res.append(self._f(indicator, "Categories", "list", cats[:5]))
        if ioc_type == "hash":
            if attrs.get("meaningful_name"):
                res.append(
                    self._f(
                        indicator, "Name", "label-capsule", attrs["meaningful_name"]
                    )
                )
            if attrs.get("type_description"):
                res.append(
                    self._f(
                        indicator, "Type", "label-capsule", attrs["type_description"]
                    )
                )
        tags = attrs.get("tags", [])
        if tags:
            res.append(self._f(indicator, "Tags", "list", tags[:8]))
        last = attrs.get("last_analysis_date") or attrs.get("last_modification_date")
        if last:
            import datetime

            dt = datetime.datetime.utcfromtimestamp(last).strftime("%Y-%m-%d")
            res.append(self._f(indicator, "Last Analysis", "label-capsule", dt))
        return res

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
