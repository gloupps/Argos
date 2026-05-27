import aiohttp
import asyncio
from typing import List, Dict, Any
from .module import Module


# ── GraphQL queries ────────────────────────────────────────────

_GET_INDICATOR = """
query getIndicator($value: Any!) {
  indicators(
    filters: {
      mode: and
      filters: [{ key: "name", values: [$value], operator: eq }]
      filterGroups: []
    }
    first: 5
  ) {
    edges {
      node {
        id
        name
        indicator_types
        x_opencti_main_observable_type
        x_opencti_detection
        objectLabel { value color }
        reports(first: 5) {
          edges { node { id name published } }
        }
      }
    }
  }
}
"""

_GET_OBSERVABLE = """
query getObservable($value: String!) {
  stixCyberObservables(
    filters: {
      mode: and
      filters: [{ key: "value", values: [$value], operator: eq }]
      filterGroups: []
    }
    first: 5
  ) {
    edges {
      node {
        id
        entity_type
        observable_value
        objectLabel { value color }
        indicators(first: 3) {
          edges { node { id name indicator_types } }
        }
      }
    }
  }
}
"""


class OpenCTIModule(Module):

    name             = "OpenCTI"
    description      = "Internal threat intelligence — indicators, observables, labels, reports"
    src_type         = "internal"
    supported_types  = ["ip", "domain", "url", "hash"]
    icon             = "database"
    url              = ""          # set at runtime from settings

    # Extra settings field — the OpenCTI instance URL (not an API key)
    settings_fields = [
        {"key": "opencti_url", "type": "url",
         "label": "OpenCTI URL", "placeholder": "https://opencti.yourdomain.com"}
    ]

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        api_key  = context.get("api_key")
        base_url = context.get("opencti_url", "").rstrip("/")
        if not api_key or not base_url:
            return []

        headers  = {"Authorization": f"Bearer {api_key}"}
        gql_url  = f"{base_url}/graphql"

        # Try indicator lookup first, then observable
        data = await self._graphql(gql_url, headers, _GET_INDICATOR, {"value": indicator})
        ind_edges = (data or {}).get("indicators", {}).get("edges", []) if data else []

        results = []

        if ind_edges:
            node = ind_edges[0]["node"]
            ind_id = node.get("id")

            results.append(self._f(indicator, "In OpenCTI",    "label-capsule", "Yes"))
            results.append(self._f(indicator, "Detection",     "label-capsule",
                                   "Active" if node.get("x_opencti_detection") else "Inactive"))

            types = node.get("indicator_types") or []
            if types:
                results.append(self._f(indicator, "Indicator Types", "list", types))

            labels = [l["value"] for l in (node.get("objectLabel") or []) if l]
            if labels:
                results.append(self._f(indicator, "Labels", "list", labels))

            reports = node.get("reports", {}).get("edges", [])
            report_names = [r["node"]["name"] for r in reports if r.get("node")]
            if report_names:
                results.append(self._f(indicator, "Reports", "list", report_names[:5]))
            results.append(self._f(indicator, "Report Count", "label-capsule", str(len(reports))))

            # Build direct OpenCTI link
            if ind_id:
                link = f"{base_url}/dashboard/observations/indicators/{ind_id}"
                results.append({
                    "indicator": indicator, "indicator_type": "ioc",
                    "field_name": "OpenCTI Link", "field_type": "label-capsule",
                    "value": link, "icon": "external-link", "link": link, "max": None,
                })
        else:
            # Not found as indicator — note it
            results.append(self._f(indicator, "In OpenCTI", "label-capsule", "Not found"))

        return results

    # ──────────────────────────────────────────────────────
    # get_correlation  — no cross-indicator pivot for OpenCTI
    # ──────────────────────────────────────────────────────
    async def get_correlation(self, indicator: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key  = context.get("api_key")
        base_url = context.get("opencti_url", "").rstrip("/")
        if not api_key or not base_url:
            return {}

        # OpenCTI doesn't expose a standard quota endpoint;
        # we do a lightweight health probe instead.
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            data = await self._graphql(
                f"{base_url}/graphql", headers,
                "query { about { version } }", {}
            )
            version = (data or {}).get("about", {}).get("version", "unknown")
            return {"plan_type": "internal", "version": version,
                    "remaining": None, "limit": None}
        except Exception:
            return {"plan_type": "internal", "remaining": None, "limit": None}

    # ──────────────────────────────────────────────────────
    # get_fields  — expose settings_fields to frontend
    # ──────────────────────────────────────────────────────
    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"]             = "opencti"
        base["settings_fields"] = self.settings_fields
        return base

    # ──────────────────────────────────────────────────────
    # Internal GraphQL helper  (own session — no shared state)
    # ──────────────────────────────────────────────────────
    async def _graphql(self, url: str, headers: Dict, query: str,
                       variables: Dict) -> Dict | None:
        payload = {"query": query.strip(), "variables": variables or {}}
        timeout = aiohttp.ClientTimeout(total=15)
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(
                        url, json=payload, headers=headers, ssl=False
                    ) as resp:
                        if resp.status != 200:
                            return None
                        result = await resp.json()
                        if "errors" in result:
                            return None
                        return result.get("data")
            except Exception:
                if attempt == 2:
                    return None
                await asyncio.sleep(1 * (attempt + 1))
        return None

    @staticmethod
    def _f(indicator, name, field_type, value, max_=None) -> Dict[str, Any]:
        return {
            "indicator": indicator, "indicator_type": "ioc",
            "field_name": name, "field_type": field_type,
            "value": value, "icon": None, "link": None, "max": max_,
        }
