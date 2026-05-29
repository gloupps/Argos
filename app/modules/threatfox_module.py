# app/modules/threatfox_module.py
import re
from typing import List, Dict, Any
from .module import Module


class ThreatFoxModule(Module):
    """
    Module ThreatFox (abuse.ch) — enrichissement uniquement.
    Endpoints utilisés :
      - search_ioc  (exact_match: False pour IP/domain, True pour URL)  → IP, domain, URL
      - search_hash                                                       → hash MD5/SHA256

    Pour les IPs, ThreatFox stocke les entrées au format ip:port.
    On recherche donc sans exact_match, puis on filtre côté client
    pour ne garder que les résultats qui correspondent bien à l'IP,
    et on regroupe les ports découverts.
    """

    name = "ThreatFox"
    description = (
        "Malware IOC database — malware families, threat types, ports, confidence"
    )
    src_type = "external"
    supported_types = ["ip", "domain", "url", "hash"]
    icon = "bug"
    url = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        ioc_type = context.get("ioc_type", "domain")
        headers = self._build_headers(context)

        if ioc_type == "hash":
            payload = {"query": "search_hash", "hash": indicator}
        elif ioc_type == "ip":
            # exact_match: False pour capturer toutes les entrées ip:port
            payload = {
                "query": "search_ioc",
                "search_term": indicator,
                "exact_match": False,
            }
        else:
            # domain / url : exact_match True
            payload = {
                "query": "search_ioc",
                "search_term": indicator,
                "exact_match": True,
            }

        data = await self.requester.post(self.url, json=payload, headers=headers)
        if not data:
            return []

        status = data.get("query_status", "")
        if status not in ("ok", "no_results"):
            return []

        # Filtrer les items non-dict (ex: ["no_results"])
        raw_iocs = data.get("data") or []
        iocs = [i for i in raw_iocs if isinstance(i, dict)]
        if not iocs:
            return []

        # Pour les IPs : filtrer pour ne garder que les IOCs dont
        # la partie hôte correspond bien à l'indicateur recherché
        if ioc_type == "ip":
            iocs = self._filter_ip_iocs(indicator, iocs)
        if not iocs:
            return []

        return self._extract_fields(indicator, ioc_type, iocs)

    # ──────────────────────────────────────────────────────
    # get_correlation  — désactivé
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        return []

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return {"plan_type": "public", "remaining": None, "limit": None}

    # ──────────────────────────────────────────────────────
    # _filter_ip_iocs
    # Garde uniquement les entrées où la partie IP de l'IOC
    # correspond exactement à l'indicateur (pour éviter les
    # faux positifs d'un search sans exact_match).
    # Ex : "217.196.98.61:4444" → host = "217.196.98.61" ✓
    #      "217.196.98.61.evil.com" → host ≠ "217.196.98.61" ✗
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _filter_ip_iocs(ip: str, iocs: List[Dict]) -> List[Dict]:
        filtered = []
        for ioc in iocs:
            ioc_val = (ioc.get("ioc") or "").strip()
            # Extraire la partie host : soit "ip:port" soit "ip" seul
            host = ioc_val.split(":")[0] if ":" in ioc_val else ioc_val
            if host == ip:
                filtered.append(ioc)
        return filtered

    # ──────────────────────────────────────────────────────
    # _extract_fields
    # ──────────────────────────────────────────────────────
    def _extract_fields(
        self, indicator: str, ioc_type: str, iocs: List[Dict]
    ) -> List[Dict[str, Any]]:
        res = []

        # ── Ports (uniquement pour les IPs) ───────────────
        ports: List[int] = []
        if ioc_type == "ip":
            seen_ports = set()
            for ioc in iocs:
                ioc_val = (ioc.get("ioc") or "").strip()
                if ":" in ioc_val:
                    try:
                        port = int(ioc_val.split(":")[-1])
                        if port not in seen_ports:
                            seen_ports.add(port)
                            ports.append(port)
                    except ValueError:
                        pass
            ports.sort()

        # ── Agrégation commune ────────────────────────────
        malware_printable = list(
            {
                i.get("malware_printable") or i.get("malware", "")
                for i in iocs
                if i.get("malware_printable") or i.get("malware")
            }
        )
        threat_types = list(
            {
                i.get("threat_type_desc") or i.get("threat_type", "")
                for i in iocs
                if i.get("threat_type")
            }
        )
        tags = list(
            {t for i in iocs for t in (i.get("tags") or []) if isinstance(t, str)}
        )
        reporters = list({i["reporter"] for i in iocs if i.get("reporter")})

        confidences = [
            int(i["confidence_level"])
            for i in iocs
            if i.get("confidence_level") is not None
        ]
        avg_conf = int(sum(confidences) / len(confidences)) if confidences else None

        dates = sorted(i["first_seen"] for i in iocs if i.get("first_seen"))

        # ── Construction des champs ───────────────────────

        # Nombre d'entrées (ou nombre de combinaisons ip:port)
        label = f"{len(iocs)} entries ({len(ports)} ports)" if ports else str(len(iocs))
        res.append(self._f(indicator, "IOC Count", "label-capsule", label))

        # Ports regroupés → thème "ports" dans qualif.js
        if ports:
            res.append(
                self._f(indicator, "Open Ports", "list", [str(p) for p in ports])
            )

        if malware_printable:
            res.append(
                self._f(indicator, "Malware Family", "list", malware_printable[:10])
            )

        if threat_types:
            res.append(self._f(indicator, "Threat Type", "list", threat_types[:5]))

        if avg_conf is not None:
            res.append(
                self._f(
                    indicator, "Avg Confidence", "label-capsule", f"{avg_conf} / 100"
                )
            )

        if dates:
            res.append(self._f(indicator, "First Seen", "label-capsule", dates[0][:10]))
            if len(dates) > 1:
                res.append(
                    self._f(indicator, "Last Seen", "label-capsule", dates[-1][:10])
                )

        if tags:
            res.append(self._f(indicator, "Tags", "list", tags[:15]))

        if reporters:
            res.append(self._f(indicator, "Reporters", "list", reporters[:5]))

        # Lien vers la fiche du premier IOC
        first = iocs[0]
        ioc_id = first.get("id")
        if ioc_id:
            res.append(
                {
                    "indicator": indicator,
                    "indicator_type": "ioc",
                    "field_name": "ThreatFox Entry",
                    "field_type": "label-capsule",
                    "value": "View on ThreatFox",
                    "icon": "external-link",
                    "link": f"https://threatfox.abuse.ch/ioc/{ioc_id}/",
                    "max": None,
                }
            )

        return res

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _build_headers(context: Dict[str, Any]) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        api_key = context.get("api_key")
        if api_key:
            headers["Auth-Key"] = api_key
        return headers

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
