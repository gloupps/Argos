# app/modules/phishtank_module.py
import re
from typing import List, Dict, Any
from .module import Module


class PhishTankModule(Module):
    """
    Module PhishTank — checkurl API v2.
    Auth : api_key passé en paramètre POST (format=json).

    Endpoint :
      POST https://checkurl.phishtank.com/checkurl/
      Params : url=<encoded_url>, format=json, app_key=<api_key>

    Supporte : URL, domain
    Pour un domaine, on le passe directement comme URL (http://domain/).
    """

    name = "PhishTank"
    description = "Phishing URL verification — community-verified phish database"
    src_type = "external"
    supported_types = ["url", "domain"]
    icon = "fish"
    url = "https://www.phishtank.com"

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "phishtank"
        return base

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "phishtank_pivot_phish",
                "type": "checkbox",
                "label": "Pivot on confirmed phish URLs (domain correlation)",
                "default": True,
            },
        ]

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
    # _normalize_url — force un schéma HTTP si absent
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _normalize_url(indicator: str, ioc_type: str) -> str:
        if ioc_type == "domain":
            return f"http://{indicator}/"
        if not re.match(r"^https?://", indicator):
            return f"http://{indicator}"
        return indicator

    # ──────────────────────────────────────────────────────
    # _query_phishtank — appel API checkurl
    # ──────────────────────────────────────────────────────
    async def _query_phishtank(
        self, url_to_check: str, api_key: str
    ) -> Dict | None:
        payload: Dict[str, str] = {
            "url": url_to_check,
            "format": "json",
        }
        if api_key:
            payload["app_key"] = api_key

        return await self.requester.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload,
            headers={"User-Agent": "phishtank/PivotLens"},
        )

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key  = (context.get("api_key") or "").strip()
        ioc_type = context.get("ioc_type", "url")
        res: List[Dict] = []

        url_to_check = self._normalize_url(indicator, ioc_type)
        data = await self._query_phishtank(url_to_check, api_key)

        if not data or not isinstance(data, dict):
            return res

        result = data.get("results") or {}

        # ── Dans la base ? ──────────────────────────────
        in_database = result.get("in_database", False)
        res.append(self._f(
            indicator,
            "In PhishTank DB",
            "label-capsule",
            "Yes" if in_database else "No",
        ))

        if not in_database:
            return res

        # ── ID PhishTank ──
        phish_id = result.get("phish_id")
        if phish_id:
            res.append(self._f(
                indicator, "PhishTank ID", "label-capsule",
                str(phish_id),
                link=f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}",
            ))

        # ── Vérifié comme phish ? ──
        verified = result.get("verified", False)
        res.append(self._f(
            indicator,
            "Verified Phish",
            "label-capsule",
            "Yes" if verified else "Pending",
        ))

        # ── Encore actif ? ──
        online = result.get("online")
        if online is not None:
            res.append(self._f(
                indicator, "Still Online", "label-capsule",
                "Yes" if online else "No",
            ))

        # ── Date de soumission ──
        submitted = result.get("submission_time") or result.get("phish_submission_time")
        if submitted:
            res.append(self._f(indicator, "Submitted", "label-capsule", str(submitted)[:10]))

        # ── Date de vérification ──
        verified_at = result.get("verification_time")
        if verified_at:
            res.append(self._f(indicator, "Verified At", "label-capsule", str(verified_at)[:10]))

        # ── Cibles possibles (target) ──
        target = result.get("target") or result.get("details", {}).get("target")
        if target:
            res.append(self._f(indicator, "Phishing Target", "label-capsule", target))

        return res

    # ──────────────────────────────────────────────────────
    # get_correlation
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Pour les domaines : vérifie si le domaine lui-même est connu comme phish.
        Pas de vrai pivot multi-IOC disponible sans l'API premium.
        """
        ioc_type = context.get("ioc_type", "")
        if ioc_type not in ("url", "domain"):
            return []

        api_key = (context.get("api_key") or "").strip()
        cfg     = context.get("phishtank") or {}
        if not cfg.get("phishtank_pivot_phish", True):
            return []

        url_to_check = self._normalize_url(indicator, ioc_type)
        data = await self._query_phishtank(url_to_check, api_key)
        if not data:
            return []

        result = data.get("results") or {}
        if not result.get("in_database") or not result.get("verified"):
            return []

        # Retourner le phish_id comme pivot — permet de lier des URLs du même phishing kit
        phish_id = result.get("phish_id")
        if not phish_id:
            return []

        return [
            {
                "indicator": str(phish_id),
                "type": "phish_id",
                "pivot_reason": "Confirmed phishing URL in PhishTank",
                "pivot": f"PhishTank phish #{phish_id}",
            }
        ]

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """PhishTank ne fournit pas d'endpoint quota — on probe simplement."""
        api_key = (context.get("api_key") or "").strip()
        data = await self._query_phishtank("http://example.com/", api_key)
        if data is None:
            return {"plan_type": "external", "reachable": False}
        return {
            "plan_type": "external",
            "reachable": True,
            "note": "No quota endpoint — community rate-limited",
        }
