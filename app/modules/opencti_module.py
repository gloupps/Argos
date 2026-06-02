# app/modules/opencti_module.py
import aiohttp
import asyncio
from typing import List, Dict, Any
from .module import Module

# ── GraphQL queries ────────────────────────────────────────────
_GQL_REPORT_OBSERVABLES = """
query getReportObjects($id: String!) {
  report(id: $id) {
    id name
    objects(first: 200) {
      edges { node {
        ... on StixCyberObservable { id entity_type observable_value }
        ... on Indicator { id name indicator_types pattern }
      }}
    }
  }
}
"""

_GQL_LIST_INDICATORS = """
query listIndicators($first: Int) {
  indicators(first: $first) {
    edges { node {
      id name indicator_types
      objectLabel { value }
    }}
  }
}
"""
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
        reports(first: 10) {
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

# Récupère les indicateurs d'un report via ses stixCyberObservables
_GET_REPORT_OBSERVABLES = """
query getReportObservables($id: String!) {
  report(id: $id) {
    id
    name
    objects(first: 100) {
      edges {
        node {
          ... on StixCyberObservable {
            id
            entity_type
            observable_value
          }
          ... on Indicator {
            id
            name
            pattern
            indicator_types
          }
        }
      }
    }
  }
}
"""

# Récupère les reports d'un indicateur (lookup par valeur)
_GET_INDICATOR_REPORTS = """
query getIndicatorReports($value: Any!) {
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
        reports(first: 20) {
          edges { node { id name published } }
        }
      }
    }
  }
}
"""


class OpenCTIModule(Module):

    name = "OpenCTI"
    description = (
        "Internal threat intelligence — indicators, observables, labels, reports"
    )
    src_type = "internal"
    supported_types = ["ip", "domain", "url", "hash"]
    icon = "database"
    url = ""  # set at runtime from settings

    # Extra settings field — the OpenCTI instance URL (not an API key)
    settings_fields = [
        {
            "key": "opencti_url",
            "type": "url",
            "label": "OpenCTI URL",
            "placeholder": "https://opencti.yourdomain.com",
        }
    ]

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_correlation_fields
    # ──────────────────────────────────────────────────────
    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "opencti_min_shared_roots",
                "type": "range",
                "label": "Min graph IOCs in same report to pivot",
                "min": 1,
                "max": 10,
                "default": 2,
            },
            {
                "key": "opencti_max_reports",
                "type": "range",
                "label": "Max reports per pivot",
                "min": 1,
                "max": 10,
                "default": 3,
            },
            {
                "key": "opencti_include_correlated",
                "type": "checkbox",
                "label": "Include correlated IOCs (not only roots)",
                "default": False,
            },
        ]

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        base_url = context.get("opencti_url", "").rstrip("/")
        if not api_key or not base_url:
            return []

        headers = {"Authorization": f"Bearer {api_key}"}
        gql_url = f"{base_url}/graphql"

        # Try indicator lookup first, then observable
        data = await self._graphql(
            gql_url, headers, _GET_INDICATOR, {"value": indicator}
        )
        ind_edges = (data or {}).get("indicators", {}).get("edges", []) if data else []

        results = []

        if ind_edges:
            node = ind_edges[0]["node"]
            ind_id = node.get("id")

            results.append(self._f(indicator, "In OpenCTI", "label-capsule", "Yes"))
            results.append(
                self._f(
                    indicator,
                    "Detection",
                    "label-capsule",
                    "Active" if node.get("x_opencti_detection") else "Inactive",
                )
            )

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
            results.append(
                self._f(indicator, "Report Count", "label-capsule", str(len(reports)))
            )

            # Build direct OpenCTI link
            if ind_id:
                link = f"{base_url}/dashboard/observations/indicators/{ind_id}"
                results.append(
                    {
                        "indicator": indicator,
                        "indicator_type": "ioc",
                        "field_name": "OpenCTI Link",
                        "field_type": "label-capsule",
                        "value": link,
                        "icon": "external-link",
                        "link": link,
                        "max": None,
                    }
                )
        else:
            # Not found as indicator — note it
            results.append(
                self._f(indicator, "In OpenCTI", "label-capsule", "Not found")
            )

        return results

    # ──────────────────────────────────────────────────────
    # get_correlation  — pivot cross-IOC via reports OpenCTI
    #
    # Logique :
    #   1. Pour l'indicateur courant, récupérer ses report_ids OpenCTI.
    #   2. Pour chaque autre IOC du graph (root + correlated), récupérer
    #      ses report_ids et compter combien d'IOCs partagent chaque report.
    #   3. Si un report est partagé par ≥ opencti_min_shared_roots IOCs,
    #      on le sélectionne comme pivot et on injecte tous ses objets
    #      (StixCyberObservable + Indicator) dans le graph.
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        base_url = context.get("opencti_url", "").rstrip("/")
        if not api_key or not base_url:
            return []

        min_shared_roots = int(context.get("opencti_min_shared_roots", 2))
        max_reports = int(context.get("opencti_max_reports", 3))
        include_correlated = bool(context.get("opencti_include_correlated", False))

        all_roots = context.get("all_root_indicators", [])
        all_correlated = context.get("all_correlated_indicators", [])

        headers = {"Authorization": f"Bearer {api_key}"}
        gql_url = f"{base_url}/graphql"

        # ── Pool de comparaison : roots seuls ou roots + correlated ──────
        pool_values: set = set()
        for r in all_roots:
            pool_values.add(r["value"])
        if include_correlated:
            for r in all_correlated:
                pool_values.add(r["value"])
        pool_values.add(indicator)

        # ── 1. Récupérer les report_ids de l'indicateur courant ───────────
        my_report_ids: Dict[str, str] = {}  # report_id → report_name
        data = await self._graphql(
            gql_url, headers, _GET_INDICATOR_REPORTS, {"value": indicator}
        )
        ind_edges = (data or {}).get("indicators", {}).get("edges", []) if data else []
        if ind_edges:
            reports_raw = ind_edges[0]["node"].get("reports", {}).get("edges", [])
            for r in reports_raw:
                node = r.get("node") or {}
                rid = node.get("id")
                rname = node.get("name", rid)
                if rid:
                    my_report_ids[rid] = rname

        if not my_report_ids:
            return []

        # ── 2. Pour chaque autre IOC du pool, récupérer ses report_ids ────
        other_pool = [v for v in pool_values if v != indicator]

        if not other_pool:
            return []

        tasks = [
            self._graphql(gql_url, headers, _GET_INDICATOR_REPORTS, {"value": v})
            for v in other_pool
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # ── 3. Compter les IOCs qui partagent chaque report ───────────────
        # report_id → set de IOC values qui le contiennent
        report_ioc_map: Dict[str, set] = {}
        for rid in my_report_ids:
            report_ioc_map.setdefault(rid, set()).add(indicator)

        for other_val, resp in zip(other_pool, responses):
            if not resp or isinstance(resp, Exception):
                continue
            edges = (resp or {}).get("indicators", {}).get("edges", [])
            if not edges:
                continue
            other_reports = edges[0]["node"].get("reports", {}).get("edges", [])
            for r in other_reports:
                rid = (r.get("node") or {}).get("id")
                if rid and rid in my_report_ids:
                    report_ioc_map.setdefault(rid, set()).add(other_val)

        # ── 4. Filtrer les reports qualifiants ────────────────────────────
        qualifying_reports = {
            rid: iocs
            for rid, iocs in report_ioc_map.items()
            if len(iocs) >= min_shared_roots
        }

        if not qualifying_reports:
            return []

        # Respecter max_reports
        selected_reports = dict(list(qualifying_reports.items())[:max_reports])

        # ── 5. Récupérer tous les objets des reports qualifiants ──────────
        report_tasks = [
            self._graphql(gql_url, headers, _GET_REPORT_OBSERVABLES, {"id": rid})
            for rid in selected_reports
        ]
        report_responses = await asyncio.gather(*report_tasks, return_exceptions=True)

        correlations: List[Dict[str, Any]] = []
        seen: set = set()

        for rid, resp in zip(selected_reports, report_responses):
            if not resp or isinstance(resp, Exception):
                continue

            report_node = (resp or {}).get("report") or {}
            report_name = report_node.get("name") or my_report_ids.get(rid, rid)
            shared_count = len(selected_reports[rid])
            pivot_reason = (
                f"OpenCTI report: {report_name} "
                f"(shared by {shared_count}/{len(pool_values)} graph IOC(s))"
            )

            objects_edges = report_node.get("objects", {}).get("edges", [])
            for edge in objects_edges:
                node = edge.get("node") or {}

                # StixCyberObservable
                obs_val = node.get("observable_value")
                entity_type = node.get("entity_type", "")
                if obs_val and obs_val not in seen and obs_val != indicator:
                    target_type = _opencti_entity_to_ioc(entity_type)
                    if target_type:
                        seen.add(obs_val)
                        correlations.append(
                            {
                                "source_indicator": indicator,
                                "source_type": context.get("ioc_type", "ioc"),
                                "target_indicator": obs_val,
                                "target_type": target_type,
                                "score": 1,
                                "pivot": True,
                                "pivot_reason": pivot_reason,
                            }
                        )

                # Indicator (pattern-based)
                ind_name = node.get("name")
                if ind_name and ind_name not in seen and ind_name != indicator:
                    # Tenter de déduire le type depuis indicator_types ou le pattern
                    ind_types = node.get("indicator_types") or []
                    target_type = _opencti_indicator_type_to_ioc(ind_types, ind_name)
                    if target_type:
                        seen.add(ind_name)
                        correlations.append(
                            {
                                "source_indicator": indicator,
                                "source_type": context.get("ioc_type", "ioc"),
                                "target_indicator": ind_name,
                                "target_type": target_type,
                                "score": 1,
                                "pivot": True,
                                "pivot_reason": pivot_reason,
                            }
                        )

        return correlations

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        base_url = context.get("opencti_url", "").rstrip("/")
        if not api_key or not base_url:
            return {}

        # OpenCTI doesn't expose a standard quota endpoint;
        # we do a lightweight health probe instead.
        headers = {"Authorization": f"Bearer {api_key}"}
        gql_url = f"{base_url}/graphql"

        probe = """
        query { about { version } }
        """
        data = await self._graphql(gql_url, headers, probe, {})
        if not data:
            return {"plan_type": "internal", "reachable": False}

        version = (data.get("about") or {}).get("version", "unknown")
        return {"plan_type": "internal", "reachable": True, "version": version}

    # ──────────────────────────────────────────────────────
    # _graphql  — helper POST GraphQL
    # ──────────────────────────────────────────────────────
    async def _graphql(
        self,
        url: str,
        headers: Dict[str, str],
        query: str,
        variables: Dict[str, Any],
    ) -> Dict | None:
        try:
            resp = await self.requester.post(
                url,
                headers={**headers, "Content-Type": "application/json"},
                json={"query": query, "variables": variables},
            )
            if not resp:
                return None
            return resp.get("data")
        except Exception:
            return None

        
    # ──────────────────────────────────────────────────────
    # _f  — helper construction d'un champ UI
    # ──────────────────────────────────────────────────────
    @staticmethod
    def _f(
        indicator: str,
        name: str,
        field_type: str,
        value: Any,
        max_: int | None = None,
    ) -> Dict[str, Any]:
        return {
            "indicator": indicator,
            "indicator_type": "ioc",
            "field_name": name,
            "field_type": field_type,
            "value": value,
            "icon": None,
            "link": None,
            "max": None if max_ is None else max_,
        }
    

# ──────────────────────────────────────────────────────────────
# Helpers — mapping types OpenCTI → types IOC internes
# ──────────────────────────────────────────────────────────────


def _opencti_entity_to_ioc(entity_type: str) -> str | None:
    """Mappe un entity_type OpenCTI (StixCyberObservable) vers un type IOC interne."""
    _MAP = {
        "IPv4-Addr": "ip",
        "IPv6-Addr": "ip",
        "Domain-Name": "domain",
        "Hostname": "domain",
        "Url": "url",
        "StixFile": "hash",
        "File": "hash",
        "Artifact": "hash",
        "Email-Addr": None,  # non supporté pour l'instant
        "Email-Message": None,
        "Network-Traffic": None,
    }
    return _MAP.get(entity_type)


def _opencti_indicator_type_to_ioc(indicator_types: List[str], name: str) -> str | None:
    """
    Tente de déduire le type IOC depuis les indicator_types OpenCTI
    ou en analysant la valeur du nom (heuristique).
    """
    import re

    for t in indicator_types:
        tl = t.lower()
        if "ip" in tl:
            return "ip"
        if "domain" in tl or "hostname" in tl:
            return "domain"
        if "url" in tl:
            return "url"
        if "hash" in tl or "file" in tl or "malware" in tl:
            return "hash"

    # Heuristique sur la valeur
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
        return "ip"
    if re.match(r"^[a-f0-9]{32,64}$", name, re.IGNORECASE):
        return "hash"
    if name.startswith("http://") or name.startswith("https://"):
        return "url"
    if re.match(r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$", name):
        return "domain"

    return None

def _opencti_entity_to_ioc_type(entity_type: str, value: str) -> str:
    mapping = {
        "IPv4-Addr": "ip", "IPv6-Addr": "ip",
        "Domain-Name": "domain", "Hostname": "domain",
        "Url": "url", "StixFile": "hash",
    }
    return mapping.get(entity_type) or _guess_type(value)
