import aiohttp
import asyncio
from typing import List, Dict, Any
from .module import Module


class MISPModule(Module):
    """
    Module MISP interne.
    Interroge l'API REST MISP pour enrichir IP, domaines, URLs et hashes.
    Paramètres attendus dans le contexte :
        - api_key   : clé d'authentification MISP (Authorization header)
        - misp_url  : URL de base de l'instance MISP interne
    """

    name             = "MISP"
    description      = "Internal threat intelligence — events, attributes, tags, galaxies"
    src_type         = "internal"
    supported_types  = ["ip", "domain", "url", "hash"]
    icon             = "share-2"
    url              = ""   # défini à l'exécution depuis les settings

    # Champ extra affiché dans les Settings (URL de l'instance interne)
    settings_fields = [
        {
            "key":         "misp_url",
            "type":        "url",
            "label":       "MISP URL",
            "placeholder": "https://misp.yourdomain.com",
        }
    ]

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        api_key  = context.get("api_key")
        base_url = context.get("misp_url", "").rstrip("/")
        if not api_key or not base_url:
            return []

        headers = {
            "Authorization": api_key,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

        # ── 1. Recherche des attributs correspondants ─────
        payload = {
            "returnFormat": "json",
            "value":        indicator,
            "limit":        20,
            "includeEventTags": True,
        }
        data = await self._post(f"{base_url}/attributes/restSearch", headers, payload)
        if not data:
            return [self._f(indicator, "In MISP", "label-capsule", "Not found")]

        attributes = (data.get("response") or {}).get("Attribute") or []
        if not attributes:
            return [self._f(indicator, "In MISP", "label-capsule", "Not found")]

        results = [self._f(indicator, "In MISP", "label-capsule", "Yes")]

        # ── 2. Dédupliquer les events référencés ──────────
        events: Dict[str, Dict] = {}
        for attr in attributes:
            ev = attr.get("Event") or {}
            eid = ev.get("id") or attr.get("event_id")
            if eid and eid not in events:
                events[eid] = ev

        results.append(self._f(indicator, "Matching Events", "label-capsule", str(len(events))))

        # ── 3. Noms des événements ─────────────────────────
        event_names = [
            ev.get("info", f"Event {eid}")[:80]
            for eid, ev in list(events.items())[:5]
        ]
        if event_names:
            results.append(self._f(indicator, "Events", "list", event_names))

        # ── 4. Tags / Galaxies ────────────────────────────
        tag_set: set = set()
        for attr in attributes:
            for tag in attr.get("Tag") or []:
                name = (tag.get("name") or "").strip()
                if name:
                    tag_set.add(name)
            # tags portés par l'event
            for ev_tag in (attr.get("Event") or {}).get("Tag") or []:
                name = (ev_tag.get("name") or "").strip()
                if name:
                    tag_set.add(name)

        # Séparer les tags MITRE/Galaxy des tags libres
        mitre_tags  = sorted(t for t in tag_set if "mitre" in t.lower() or "galaxy" in t.lower())
        plain_tags  = sorted(t for t in tag_set if t not in mitre_tags)

        if plain_tags:
            results.append(self._f(indicator, "Tags", "list", plain_tags[:10]))
        if mitre_tags:
            results.append(self._f(indicator, "MITRE / Galaxies", "list", mitre_tags[:10]))

        # ── 5. Catégories d'attributs ─────────────────────
        categories = sorted({a.get("category", "") for a in attributes if a.get("category")})
        if categories:
            results.append(self._f(indicator, "Categories", "list", categories))

        # ── 6. Threat level moyen (si présent) ───────────
        threat_levels = [
            ev.get("threat_level_id") for ev in events.values()
            if ev.get("threat_level_id")
        ]
        if threat_levels:
            _map = {"1": "High", "2": "Medium", "3": "Low", "4": "Undefined"}
            labels = list({_map.get(str(tl), str(tl)) for tl in threat_levels})
            results.append(self._f(indicator, "Threat Levels", "list", labels))

        # ── 7. Lien direct vers la recherche MISP ─────────
        link = f"{base_url}/attributes/index/search:{indicator}"
        results.append({
            "indicator":      indicator,
            "indicator_type": "ioc",
            "field_name":     "MISP Link",
            "field_type":     "label-capsule",
            "value":          "View in MISP",
            "icon":           "external-link",
            "link":           link,
            "max":            None,
        })

        return results

    # ──────────────────────────────────────────────────────
    # get_correlation  — pivot sur les attributs co-événements
    # ──────────────────────────────────────────────────────
    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        api_key  = context.get("api_key")
        base_url = context.get("misp_url", "").rstrip("/")
        if not api_key or not base_url:
            return []

        headers = {
            "Authorization": api_key,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
        }

        # Trouver les events qui contiennent cet indicateur
        payload = {
            "returnFormat": "json",
            "value":        indicator,
            "limit":        5,
        }
        data = await self._post(f"{base_url}/attributes/restSearch", headers, payload)
        if not data:
            return []

        attributes = (data.get("response") or {}).get("Attribute") or []
        event_ids = list({
            a.get("event_id") for a in attributes if a.get("event_id")
        })[:3]

        if not event_ids:
            return []

        correlations: List[Dict[str, Any]] = []
        seen: set = {indicator}

        for eid in event_ids:
            # Récupérer tous les attributs de l'événement
            ev_payload = {
                "returnFormat": "json",
                "eventid":      eid,
                "limit":        50,
            }
            ev_data = await self._post(f"{base_url}/attributes/restSearch", headers, ev_payload)
            if not ev_data:
                continue

            ev_attrs = (ev_data.get("response") or {}).get("Attribute") or []
            for attr in ev_attrs:
                val  = (attr.get("value") or "").strip()
                typ  = attr.get("type", "")
                if not val or val in seen:
                    continue

                # Mapper le type MISP vers nos types internes
                target_type = _misp_type_to_ioc(typ)
                if not target_type:
                    continue

                seen.add(val)
                correlations.append({
                    "source_indicator": indicator,
                    "source_type":      context.get("ioc_type", "ioc"),
                    "target_indicator": val,
                    "target_type":      target_type,
                    "score":            1,
                    "pivot":            True,
                    "pivot_reason":     f"MISP co-event {eid}",
                })

        return correlations

    # ──────────────────────────────────────────────────────
    # get_quotas  — version MISP (pas de quota, on probe)
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key  = context.get("api_key")
        base_url = context.get("misp_url", "").rstrip("/")
        if not api_key or not base_url:
            return {}

        headers = {
            "Authorization": api_key,
            "Accept":        "application/json",
        }
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{base_url}/servers/getVersion",
                    headers=headers, ssl=False
                ) as resp:
                    if resp.status != 200:
                        return {}
                    body = await resp.json()
                    version = body.get("version", "unknown")
                    return {
                        "plan_type": "internal",
                        "version":   version,
                        "remaining": None,
                        "limit":     None,
                    }
        except Exception:
            return {"plan_type": "internal", "remaining": None, "limit": None}

    # ──────────────────────────────────────────────────────
    # get_fields
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"]             = "misp"
        base["settings_fields"] = self.settings_fields
        return base

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    async def _post(self, url: str, headers: Dict, payload: Dict) -> Dict | None:
        timeout = aiohttp.ClientTimeout(total=15)
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        url, json=payload, headers=headers, ssl=False
                    ) as resp:
                        if resp.status not in (200, 201):
                            return None
                        return await resp.json()
            except Exception:
                if attempt == 2:
                    return None
                await asyncio.sleep(1 * (attempt + 1))
        return None

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict[str, Any]:
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


# ──────────────────────────────────────────────────────────────
# Module MISP externe — une instance par entrée utilisateur
# ──────────────────────────────────────────────────────────────

class ExternalMISPModule(MISPModule):
    """
    Identique à MISPModule mais représente une instance MISP externe
    (fournie par l'utilisateur dans les settings).
    L'instance_id permet de distinguer plusieurs instances.
    """

    src_type = "external"

    def __init__(self, requester, instance_id: str, label: str):
        super().__init__(requester)
        self._instance_id = instance_id
        self._label       = label
        self.name         = f"MISP — {label}"
        self.description  = f"External MISP instance: {label}"

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"]  = f"misp_ext_{self._instance_id}"
        base["name"] = self.name
        # Les settings_fields sont préfixés par instance_id
        base["settings_fields"] = [
            {
                "key":         f"misp_ext_{self._instance_id}_url",
                "type":        "url",
                "label":       f"{self._label} — URL",
                "placeholder": "https://misp.partner.com",
            }
        ]
        return base

    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Récupère l'URL spécifique à cette instance depuis le context
        url_key = f"misp_ext_{self._instance_id}_url"
        instance_context = {
            **context,
            "misp_url": context.get(url_key, ""),
        }
        return await super().get_info(indicator, instance_context)

    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        url_key = f"misp_ext_{self._instance_id}_url"
        instance_context = {
            **context,
            "misp_url": context.get(url_key, ""),
        }
        return await super().get_correlation(indicator, instance_context)

    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        url_key = f"misp_ext_{self._instance_id}_url"
        instance_context = {
            **context,
            "misp_url": context.get(url_key, ""),
        }
        return await super().get_quotas(instance_context)


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _misp_type_to_ioc(misp_type: str) -> str | None:
    """Convertit un type d'attribut MISP en type IOC interne."""
    _MAP = {
        # IP
        "ip-src":          "ip",
        "ip-dst":          "ip",
        "ip-src|port":     "ip",
        "ip-dst|port":     "ip",
        # Domain
        "domain":          "domain",
        "hostname":        "domain",
        "domain|ip":       "domain",
        # URL
        "url":             "url",
        "uri":             "url",
        # Hash
        "md5":             "hash",
        "sha1":            "hash",
        "sha256":          "hash",
        "sha512":          "hash",
        "ssdeep":          "hash",
        "filename|md5":    "hash",
        "filename|sha1":   "hash",
        "filename|sha256": "hash",
    }
    return _MAP.get(misp_type)
