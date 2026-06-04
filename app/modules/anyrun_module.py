# app/modules/anyrun_module.py
import re
from typing import List, Dict, Any
from .module import Module


class AnyRunModule(Module):
    """
    Module ANY.RUN — sandbox analysis platform.
    Auth : API key dans l'entête Authorization: API-Key <key>

    Endpoints utilisés :
      GET /v1/analysis/?q=<hash|url>     → liste des analyses
      GET /v1/analysis/<task_id>          → détail d'une tâche

    Supporte : hash, URL
    Ref : https://any.run/api-documentation/
    """

    name = "ANY.RUN"
    description = "Interactive sandbox — behavioral analysis for hashes and URLs"
    src_type = "external"
    supported_types = ["hash", "url"]
    icon = "flask-conical"
    url = "https://any.run"

    _BASE = "https://api.any.run/v1"

    def __init__(self, requester):
        self.requester = requester

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "anyrun"
        return base

    def get_correlation_fields(self) -> List[Dict[str, Any]]:
        return [
            {
                "key": "anyrun_max_tasks",
                "type": "range",
                "label": "Max sandbox tasks to pivot on",
                "min": 1,
                "max": 20,
                "default": 5,
            },
            {
                "key": "anyrun_pivot_dropped",
                "type": "checkbox",
                "label": "Pivot on dropped files (IOC extraction)",
                "default": True,
            },
            {
                "key": "anyrun_pivot_network",
                "type": "checkbox",
                "label": "Pivot on contacted IPs/domains",
                "default": True,
            },
        ]

    # ──────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────
    def _headers(self, api_key: str) -> Dict[str, str]:
        return {
            "Authorization": f"API-Key {api_key}",
            "Content-Type": "application/json",
        }

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
    # _search_tasks — recherche d'analyses par hash ou URL
    # ──────────────────────────────────────────────────────
    async def _search_tasks(
        self, indicator: str, ioc_type: str, api_key: str, limit: int = 5
    ) -> List[Dict]:
        params: Dict[str, Any] = {"limit": limit}

        if ioc_type == "hash":
            # Détecte SHA256 / MD5 / SHA1
            if len(indicator) == 64:
                params["hash"] = indicator
            else:
                params["hash"] = indicator
        elif ioc_type == "url":
            params["q"] = indicator

        data = await self.requester.get(
            f"{self._BASE}/analysis/",
            headers=self._headers(api_key),
            params=params,
        )

        if not data or not isinstance(data, dict):
            return []

        tasks = data.get("data", {}).get("tasks") or []
        return tasks if isinstance(tasks, list) else []

    # ──────────────────────────────────────────────────────
    # _get_task_detail — détail complet d'une analyse
    # ──────────────────────────────────────────────────────
    async def _get_task_detail(self, task_id: str, api_key: str) -> Dict | None:
        data = await self.requester.get(
            f"{self._BASE}/analysis/{task_id}",
            headers=self._headers(api_key),
        )
        if not data or not isinstance(data, dict):
            return None
        return data.get("data") or data

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key  = (context.get("api_key") or "").strip()
        ioc_type = context.get("ioc_type", "hash")
        res: List[Dict] = []

        if not api_key:
            return res

        tasks = await self._search_tasks(indicator, ioc_type, api_key, limit=5)
        if not tasks:
            return res

        # ── Nombre d'analyses ──
        res.append(self._f(indicator, "Total Analyses", "label-capsule", str(len(tasks))))

        # Verdicts agrégés
        verdicts = [t.get("verdict") or t.get("mainObject", {}).get("verdict") for t in tasks]
        verdicts = [v for v in verdicts if v]
        malicious_count = sum(1 for v in verdicts if "malicious" in str(v).lower())
        suspicious_count = sum(1 for v in verdicts if "suspicious" in str(v).lower())

        if verdicts:
            res.append(self._f(indicator, "Malicious Reports", "label-capsule", str(malicious_count)))
            res.append(self._f(indicator, "Suspicious Reports", "label-capsule", str(suspicious_count)))

        # ── Dernière analyse ──
        latest = tasks[0]
        task_id = latest.get("uuid") or latest.get("taskid") or latest.get("id")

        latest_date = latest.get("date") or latest.get("createdAt")
        if latest_date:
            res.append(self._f(indicator, "Latest Analysis", "label-capsule", str(latest_date)[:10],
                               link=f"https://app.any.run/tasks/{task_id}" if task_id else None))

        # ── Verdict de la dernière analyse ──
        latest_verdict = (
            latest.get("verdict")
            or (latest.get("mainObject") or {}).get("verdict")
        )
        if latest_verdict:
            res.append(self._f(indicator, "Latest Verdict", "label-capsule", str(latest_verdict).capitalize()))

        # ── OS / environnement ──
        os_env = (latest.get("environment") or {}).get("OS") or latest.get("os")
        if os_env:
            res.append(self._f(indicator, "Sandbox OS", "label-capsule", os_env))

        # ── Détail de la dernière tâche ──
        if task_id:
            detail = await self._get_task_detail(str(task_id), api_key)
            if detail:
                res.extend(self._extract_detail_fields(indicator, detail))

        return res

    # ──────────────────────────────────────────────────────
    # _extract_detail_fields — parsing du détail d'une tâche
    # ──────────────────────────────────────────────────────
    def _extract_detail_fields(
        self, indicator: str, detail: Dict
    ) -> List[Dict]:
        res: List[Dict] = []

        analysis = detail.get("analysis") or detail
        task_id  = detail.get("taskid") or detail.get("uuid") or ""

        # ── MITRE ATT&CK ──
        mitre = analysis.get("mitre") or []
        if mitre:
            techniques = []
            for item in mitre[:15]:
                tid  = item.get("id") or item.get("technique_id") or ""
                name = item.get("name") or item.get("technique") or ""
                if tid and name:
                    techniques.append(f"{tid} — {name}")
                elif name:
                    techniques.append(name)
            if techniques:
                res.append(self._f(indicator, "MITRE ATT&CK", "list", techniques, max_=15))

        # ── Famille de malware détectée ──
        malware_family = (
            analysis.get("family")
            or analysis.get("malwareFamily")
            or analysis.get("detected_family")
        )
        if malware_family:
            if isinstance(malware_family, list):
                malware_family = ", ".join(malware_family)
            res.append(self._f(indicator, "Malware Family", "label-capsule", str(malware_family)))

        # ── Tags ──
        tags = analysis.get("tags") or []
        if tags:
            tag_list = [str(t) if not isinstance(t, dict) else t.get("tag", "") for t in tags]
            tag_list = [t for t in tag_list if t]
            if tag_list:
                res.append(self._f(indicator, "Tags", "list", tag_list[:20], max_=20))

        # ── IOCs réseau : IPs contactées ──
        network = analysis.get("network") or {}
        ips_contacted = []
        for conn in (network.get("connections") or [])[:15]:
            ip = conn.get("ip") or conn.get("dst_ip")
            if ip:
                ips_contacted.append(ip)
        if ips_contacted:
            res.append(self._f(indicator, "Contacted IPs", "list", list(dict.fromkeys(ips_contacted))[:10], max_=10))

        # ── IOCs réseau : domaines ──
        domains_contacted = []
        for dns_entry in (network.get("dns") or [])[:15]:
            dom = dns_entry.get("domain") or dns_entry.get("name")
            if dom:
                domains_contacted.append(dom)
        if domains_contacted:
            res.append(self._f(indicator, "Contacted Domains", "list", list(dict.fromkeys(domains_contacted))[:10], max_=10))

        # ── Fichiers droppés ──
        files = analysis.get("files") or []
        dropped = []
        for f in files[:15]:
            sha256 = f.get("sha256") or f.get("hash")
            name   = f.get("name") or f.get("filename")
            if sha256:
                label = f"{name} ({sha256[:16]}…)" if name else sha256
                dropped.append(label)
        if dropped:
            res.append(self._f(indicator, "Dropped Files", "list", dropped[:10], max_=10))

        # ── Score de menace ──
        score = analysis.get("scores", {}).get("verdict", {}).get("score") or analysis.get("score")
        if score is not None:
            res.append(self._f(indicator, "Threat Score", "score", str(score)))

        # ── Lien rapport ──
        if task_id:
            res.append(self._f(
                indicator, "Full Report", "label-capsule", "View on ANY.RUN",
                link=f"https://app.any.run/tasks/{task_id}",
            ))

        return res

    # ──────────────────────────────────────────────────────
    # get_correlation
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key  = (context.get("api_key") or "").strip()
        ioc_type = context.get("ioc_type", "hash")
        cfg      = context.get("anyrun") or {}

        if not api_key:
            return []

        max_tasks    = int(cfg.get("anyrun_max_tasks", 5))
        pivot_dropped = cfg.get("anyrun_pivot_dropped", True)
        pivot_network = cfg.get("anyrun_pivot_network", True)

        tasks = await self._search_tasks(indicator, ioc_type, api_key, limit=max_tasks)
        if not tasks:
            return []

        correlations: List[Dict] = []
        seen: set = set()

        for task in tasks[:max_tasks]:
            task_id = task.get("uuid") or task.get("taskid") or task.get("id")
            if not task_id:
                continue
            detail = await self._get_task_detail(str(task_id), api_key)
            if not detail:
                continue
            analysis = detail.get("analysis") or detail
            network  = analysis.get("network") or {}

            # ── Fichiers droppés → hashes ──
            if pivot_dropped:
                for f in (analysis.get("files") or [])[:10]:
                    sha256 = f.get("sha256") or f.get("hash")
                    if sha256 and sha256 not in seen and sha256 != indicator:
                        seen.add(sha256)
                        correlations.append({
                            "indicator": sha256,
                            "type": "hash",
                            "pivot_reason": f"Dropped file in ANY.RUN task {task_id}",
                            "pivot": f"ANYRUN dropped {sha256[:12]}…",
                        })

            # ── IPs et domaines contactés ──
            if pivot_network:
                for conn in (network.get("connections") or [])[:10]:
                    ip = conn.get("ip") or conn.get("dst_ip")
                    if ip and ip not in seen:
                        seen.add(ip)
                        correlations.append({
                            "indicator": ip,
                            "type": "ip",
                            "pivot_reason": f"Contacted IP in ANY.RUN task {task_id}",
                            "pivot": f"ANYRUN network {ip}",
                        })
                for dns_entry in (network.get("dns") or [])[:10]:
                    dom = dns_entry.get("domain") or dns_entry.get("name")
                    if dom and dom not in seen:
                        seen.add(dom)
                        correlations.append({
                            "indicator": dom,
                            "type": "domain",
                            "pivot_reason": f"DNS lookup in ANY.RUN task {task_id}",
                            "pivot": f"ANYRUN dns {dom}",
                        })

        return correlations

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = (context.get("api_key") or "").strip()
        if not api_key:
            return {"plan_type": "external", "reachable": False}

        data = await self.requester.get(
            f"{self._BASE}/user/",
            headers=self._headers(api_key),
        )
        if not data or not isinstance(data, dict):
            return {"plan_type": "external", "reachable": False}

        user = data.get("data") or {}
        plan = user.get("subscription", {}).get("planType") or user.get("plan")
        limits = user.get("limits") or {}
        api_requests = limits.get("api", {})

        result: Dict[str, Any] = {
            "plan_type": str(plan).lower() if plan else "external",
            "reachable": True,
        }

        remaining = api_requests.get("remaining")
        limit     = api_requests.get("total") or api_requests.get("limit")
        if remaining is not None:
            result["remaining"] = int(remaining)
        if limit is not None:
            result["limit"] = int(limit)
        if remaining is not None and limit:
            result["exhausted"] = int(remaining) == 0
            result["low"]       = int(remaining) < max(1, int(limit) * 0.1)

        return result
