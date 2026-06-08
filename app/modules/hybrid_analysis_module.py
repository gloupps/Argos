# app/modules/hybrid_analysis_module.py
import asyncio
from typing import List, Dict, Any
from .module import Module


class HybridAnalysisModule(Module):
    """
    Hybrid Analysis — recherche de fichiers existants via l'API publique.
    Endpoints utilisés :
      POST /search/hashes          → hash (MD5, SHA1, SHA256)
      POST /search/terms           → domain, ip, url (champ "domain"/"host"/"url")

    Pas de soumission, d'analyse, ni de rapport.
    Auth : header "api-key: <key>" + "User-Agent: Falcon Sandbox"
    """

    name            = "Hybrid Analysis"
    description     = "Sandbox search — threat scores, malware families, tags (no submission)"
    src_type        = "external"
    supported_types = ["hash", "domain", "ip", "url"]
    icon            = "flask-conical"
    url             = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, requester):
        self.requester = requester

    # ─────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────

    def _headers(self, context: Dict) -> Dict:
        return {
            "api-key":    context.get("api_key", ""),
            "User-Agent": "Falcon Sandbox",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict:
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

    # ─────────────────────────────────────────────────────
    # get_info
    # ─────────────────────────────────────────────────────

    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key  = context.get("api_key", "")
        if not api_key:
            return []

        ioc_type = context.get("ioc_type", "hash")
        headers  = self._headers(context)

        if ioc_type == "hash":
            data = await self.requester.post(
                f"{self.url}/search/hashes",
                data=f"hashes[]={indicator}",
                headers=headers,
            )
            results = data if isinstance(data, list) else []
        else:
            # domain, ip, url → /search/terms
            field_map = {"domain": "domain", "ip": "host", "url": "url"}
            field = field_map.get(ioc_type, "domain")
            data = await self.requester.post(
                f"{self.url}/search/terms",
                data=f"{field}={indicator}",
                headers=headers,
            )
            results = (data or {}).get("result", []) if isinstance(data, dict) else []

        if not results:
            return []

        return self._extract_fields(indicator, results)

    # ─────────────────────────────────────────────────────
    # _extract_fields
    # ─────────────────────────────────────────────────────

    def _extract_fields(
        self, indicator: str, results: List[Dict]
    ) -> List[Dict[str, Any]]:
        out = []

        # Agréger les verdicts pour un score global
        threat_scores = [
            r.get("threat_score")
            for r in results
            if r.get("threat_score") is not None
        ]
        if threat_scores:
            max_score = max(threat_scores)
            out.append(self._f(indicator, "Detection Score", "score", max_score))

        # Verdict global (consolidated)
        verdicts = list({
            r.get("verdict")
            for r in results
            if r.get("verdict") and r["verdict"] != "no verdict"
        })
        if verdicts:
            out.append(self._f(indicator, "Verdict", "label-capsule", verdicts[0]))

        # Familles de malware (dédupliquées)
        families: list = []
        seen_f: set = set()
        for r in results:
            for tag in r.get("vx_family") and [r["vx_family"]] or []:
                if tag and tag not in seen_f:
                    seen_f.add(tag)
                    families.append(tag)
        if families:
            out.append(self._f(indicator, "Malware Family", "list", families, max_=5))

        # Tags (dédupliqués)
        tags: list = []
        seen_t: set = set()
        for r in results:
            for tag in r.get("tags") or []:
                if tag and tag not in seen_t:
                    seen_t.add(tag)
                    tags.append(tag)
        if tags:
            out.append(self._f(indicator, "HA Tags", "list", tags, max_=10))

        # Environnements d'analyse
        envs: list = []
        seen_e: set = set()
        for r in results:
            env = r.get("environment_description")
            if env and env not in seen_e:
                seen_e.add(env)
                envs.append(env)
        if envs:
            out.append(self._f(indicator, "Sandbox Environments", "list", envs, max_=5))

        # Nombre de soumissions
        if len(results) > 1:
            out.append(self._f(indicator, "Submission Count", "label-capsule", str(len(results))))

        # SHA256 du premier résultat (pour les recherches domain/ip/url)
        sha256 = next((r.get("sha256") for r in results if r.get("sha256")), None)
        if sha256:
            out.append(self._f(indicator, "SHA256", "label-capsule", sha256))

        # Type de fichier
        filetypes = list({r.get("type") for r in results if r.get("type")})
        if filetypes:
            out.append(self._f(indicator, "File Type", "label-capsule", filetypes[0]))

        return out

    # ─────────────────────────────────────────────────────
    # get_correlation — désactivé
    # ─────────────────────────────────────────────────────

    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        return []

    # ─────────────────────────────────────────────────────
    # get_quotas
    # ─────────────────────────────────────────────────────

    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key", "")
        if not api_key:
            return {}
        # L'API HA ne fournit pas d'endpoint quota public standard
        return {"plan_type": "api", "remaining": None, "limit": None}
