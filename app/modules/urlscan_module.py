import asyncio
from typing import List, Dict, Any
from .module import Module


class URLScanModule(Module):

    name = "URLScan"
    description = "Passive web scanning — page metadata, transactions, DOM, similar pivots"
    src_type = "external"
    supported_types = ["url", "domain"]
    icon = "scan-search"
    url = "https://urlscan.io/api/v1"

    def __init__(self, requester):
        self.requester = requester

    # ──────────────────────────────────────────────────────
    # get_info
    # ──────────────────────────────────────────────────────
    async def get_info(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        if not api_key:
            return []

        ioc_type = context.get("ioc_type", "domain")
        headers  = {"API-Key": api_key}

        # ── 1. Search : récupérer la liste des scans ──────
        if ioc_type == "url":
            search_data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f'page.url:"{indicator}"'},
                headers=headers,
            )
        else:
            search_data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f"domain:{indicator}"},
                headers=headers,
            )

        if not search_data or "results" not in search_data:
            return []

        results_raw = search_data.get("results", [])

        # Trouver l'UUID du scan le plus récent
        latest_uuid = None
        latest_time = None
        for item in results_raw:
            t = (item.get("task") or {}).get("time")
            if t and (latest_time is None or t > latest_time):
                latest_time = t
                latest_uuid = item.get("_id") or (item.get("task") or {}).get("uuid")

        # ── 2. Fetch détail du scan le plus récent ────────
        detail = None
        if latest_uuid:
            detail = await self.requester.get(
                f"{self.url}/result/{latest_uuid}/",
                headers=headers,
            )

        return self._extract_fields(indicator, ioc_type, search_data, detail, latest_uuid)

    # ──────────────────────────────────────────────────────
    # get_correlation  — pivot via similarité URLScan
    # ──────────────────────────────────────────────────────
    async def get_correlation(
        self, indicator: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        api_key = context.get("api_key")
        if not api_key:
            return []

        ioc_type  = context.get("ioc_type", "domain")
        headers   = {"API-Key": api_key}
        max_hits  = int(context.get("urlscan_max_hits", 2))

        # ── 1. Trouver l'UUID le plus récent ──────────────
        if ioc_type == "url":
            search_data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f'page.url:"{indicator}"', "size": "1"},
                headers=headers,
            )
        else:
            search_data = await self.requester.get(
                f"{self.url}/search/",
                params={"q": f"domain:{indicator}", "size": "1"},
                headers=headers,
            )

        if not search_data:
            return []

        results_raw = search_data.get("results", [])
        if not results_raw:
            return []

        latest = results_raw[0]
        uuid_  = latest.get("_id") or (latest.get("task") or {}).get("uuid")
        if not uuid_:
            return []

        # ── 2. Appel similar ──────────────────────────────
        similar_data = await self.requester.get(
            f"{self.url}/result/{uuid_}/similar/",
            headers=headers,
        )
        if not similar_data:
            return []

        results: List[Dict[str, Any]] = []
        seen: set = set()

        # Structure attendue : { "similar": [ { "domain": ..., "ip": ..., "hits": ... }, ... ] }
        # ou liste directe selon la version API
        similar_items = (
            similar_data.get("similar")
            or similar_data.get("results")
            or (similar_data if isinstance(similar_data, list) else [])
        )

        source_domain = (latest.get("page") or {}).get("domain", "")
        source_ip     = (latest.get("page") or {}).get("ip", "")

        for item in similar_items:
            if not isinstance(item, dict):
                continue

            item_domain = item.get("domain") or (item.get("page") or {}).get("domain", "")
            item_ip     = item.get("ip")     or (item.get("page") or {}).get("ip", "")
            hits        = int(item.get("hits") or item.get("score") or 1)

            if hits > max_hits:
                continue

            # Pivot 1 : même domaine → on skip (c'est l'IP qu'on veut)
            # Pivot 2 : même IP, domaine différent → pivot intéressant
            if item_ip and item_ip != source_ip and item_ip not in seen:
                seen.add(item_ip)
                results.append({
                    "source_indicator": indicator,
                    "source_type":      ioc_type,
                    "target_indicator": item_ip,
                    "target_type":      "ip",
                    "score":            1,
                    "pivot":            True,
                    "pivot_reason":     f"URLScan similar — shared IP ({hits} hits)",
                })

            if item_domain and item_domain != source_domain and item_domain != indicator and item_domain not in seen:
                seen.add(item_domain)
                results.append({
                    "source_indicator": indicator,
                    "source_type":      ioc_type,
                    "target_indicator": item_domain,
                    "target_type":      "domain",
                    "score":            1,
                    "pivot":            True,
                    "pivot_reason":     f"URLScan similar — same domain cluster ({hits} hits)",
                })

        return results

    # ──────────────────────────────────────────────────────
    # get_quotas
    # ──────────────────────────────────────────────────────
    async def get_quotas(self, context: Dict[str, Any]) -> Dict[str, Any]:
        api_key = context.get("api_key")
        if not api_key:
            return {}
        data = await self.requester.get(
            f"{self.url}/quotas", headers={"API-Key": api_key}
        )
        if not data:
            return {}
        return self._parse_quota(data)

    def get_fields(self) -> Dict[str, Any]:
        base = super().get_fields()
        base["key"] = "urlscan"
        return base

    def get_correlation_fields(self):
        return [
            {
                "key":     "urlscan_max_results",   # ← clé renommée
                "type":    "range",
                "label":   "Max similarity hits",
                "min":     1,
                "max":     20,
                "default": 5,
            },
        ]

    # ──────────────────────────────────────────────────────
    # _extract_fields
    # ──────────────────────────────────────────────────────
    def _extract_fields(
        self,
        indicator:    str,
        ioc_type:     str,
        search_data:  Dict,
        detail:       Dict,
        latest_uuid:  str,
    ) -> List[Dict[str, Any]]:

        results_raw = search_data.get("results", [])
        total       = len(results_raw)
        res         = []

        res.append(self._f(indicator, "Scan Count", "label-capsule", str(total)))

        # ── Champs agrégés sur tous les scans ─────────────
        ips      = set()
        servers  = set()
        subs     = set()
        last_time = None
        scan_link  = None
        screenshot = None

        for item in results_raw[:50]:
            page = item.get("page") or {}
            task = item.get("task") or {}
            t    = task.get("time")

            if page.get("ip"):
                ips.add(page["ip"])
            if page.get("server"):
                servers.add(page["server"])

            if t and (last_time is None or t > last_time):
                last_time = t
                if latest_uuid:
                    screenshot = f"https://urlscan.io/screenshots/{latest_uuid}.png"
                    scan_link  = f"https://urlscan.io/result/{latest_uuid}/"

            if ioc_type == "domain":
                domain_found = (page.get("domain") or "").lower()
                if (
                    domain_found
                    and domain_found != indicator
                    and domain_found.endswith(f".{indicator}")
                ):
                    subs.add(domain_found)

        if ips:
            res.append(self._f(indicator, "Associated IPs", "list", sorted(ips)[:10]))
        if servers:
            res.append(self._f(indicator, "Server Headers", "list", sorted(servers)[:5]))
        if subs:
            res.append(self._f(indicator, "Subdomains Seen", "list", sorted(subs)[:10]))
        if last_time:
            res.append(self._f(indicator, "Last Scan", "label-capsule", last_time[:10]))

        if scan_link:
            res.append({
                "indicator":      indicator,
                "indicator_type": "ioc",
                "field_name":     "Scan Report",
                "field_type":     "label-capsule",
                "value":          "View on URLScan",
                "icon":           "external-link",
                "link":           scan_link,
                "max":            None,
            })

        if screenshot:
            res.append({
                "indicator":      indicator,
                "indicator_type": "ioc",
                "field_name":     "Screenshot",
                "field_type":     "screenshot",
                "value":          screenshot,
                "icon":           None,
                "link":           scan_link,
                "max":            None,
            })

        # ── Champs issus du détail du scan ────────────────
        if detail:
            res += self._extract_detail_fields(indicator, detail)

        return res

    # ──────────────────────────────────────────────────────
    # _extract_detail_fields  — données du /result/{uuid}/
    # ──────────────────────────────────────────────────────
    def _extract_detail_fields(self, indicator: str, detail: Dict) -> List[Dict[str, Any]]:
        res  = []
        data = detail.get("data") or {}
        meta = detail.get("meta") or {}

        # ── HTTP Transactions ─────────────────────────────
        requests = data.get("requests") or []
        transactions = []
        for req in requests[:20]:
            rq  = (req.get("request")  or {}).get("request")  or {}
            rp  = (req.get("response") or {}).get("response") or {}
            url = rq.get("url") or ""
            if not url:
                continue
            status   = rp.get("status", "")
            mime     = rp.get("mimeType") or (rp.get("headers") or {}).get("content-type", "")
            mime_short = mime.split(";")[0].strip() if mime else ""
            label = f"{status} {url[:80]}"
            if mime_short:
                label += f"  [{mime_short}]"
            transactions.append(label)

        if transactions:
            res.append(self._f(indicator, "HTTP Transactions", "list", transactions, max_=15))

        # ── Redirects ─────────────────────────────────────
        redirects = []
        for req in requests:
            rp      = (req.get("response") or {}).get("response") or {}
            status  = int(rp.get("status") or 0)
            if 300 <= status < 400:
                url = (req.get("request") or {}).get("request", {}).get("url") or ""
                loc = (rp.get("headers") or {}).get("location") or ""
                if url:
                    entry = f"{status} {url[:60]}"
                    if loc:
                        entry += f" → {loc[:60]}"
                    redirects.append(entry)

        if redirects:
            res.append(self._f(indicator, "Redirects", "list", redirects, max_=10))

        # ── Links ─────────────────────────────────────────
        links_raw = data.get("links") or []
        link_hrefs = []
        for lk in links_raw[:30]:
            href = lk.get("href") or lk.get("url") or ""
            if href and href.startswith("http"):
                link_hrefs.append(href[:120])

        if link_hrefs:
            res.append(self._f(indicator, "Links", "list", link_hrefs, max_=15))

        # ── DOM ───────────────────────────────────────────
        dom_raw = data.get("dom") or ""
        if not dom_raw:
            # certaines versions le mettent dans meta
            dom_raw = (meta.get("processors") or {}).get("dom", {}).get("data") or ""
        if dom_raw and isinstance(dom_raw, str) and len(dom_raw) > 20:
            res.append({
                "indicator":      indicator,
                "indicator_type": "ioc",
                "field_name":     "DOM",
                "field_type":     "text_modal",
                "value":          dom_raw[:50000],
                "icon":           None,
                "link":           None,
                "max":            None,
            })

        # ── Text Content ──────────────────────────────────
        text_raw = ""
        # Chercher dans les différents emplacements possibles selon version API
        if data.get("text"):
            text_raw = data["text"]
        elif (meta.get("processors") or {}).get("text", {}).get("data"):
            text_raw = meta["processors"]["text"]["data"]
        elif data.get("globals"):
            # fallback : certains scans exposent le text dans globals
            for g in (data.get("globals") or []):
                if g.get("prop") == "document.body.innerText":
                    text_raw = g.get("val") or ""
                    break

        if text_raw and isinstance(text_raw, str) and len(text_raw.strip()) > 10:
            res.append({
                "indicator":      indicator,
                "indicator_type": "ioc",
                "field_name":     "Text Content",
                "field_type":     "text_modal",
                "value":          text_raw[:20000],
                "icon":           None,
                "link":           None,
                "max":            None,
            })

        # ── Certificates ──────────────────────────────────
        certs = (meta.get("processors") or {}).get("certstream") or {}
        cert_domains = []
        for entry in (certs.get("data") or [])[:10]:
            d = entry.get("domain") or ""
            if d:
                cert_domains.append(d)
        if cert_domains:
            res.append(self._f(indicator, "TLS Cert Domains", "list", cert_domains, max_=10))

        return res

    # ──────────────────────────────────────────────────────
    # _parse_quota
    # ──────────────────────────────────────────────────────
    def _parse_quota(self, data) -> Dict[str, Any]:
        limits   = data.get("limits", {})
        search_d = limits.get("search", {}).get("day", {})
        try:
            limit = int(search_d.get("limit", 0))
            used  = int(search_d.get("used",  0))
        except (ValueError, TypeError):
            limit, used = 0, 0
        plan = "pro" if limit > 1000 else "free"
        return {
            "used":      used,
            "limit":     limit,
            "remaining": max(0, limit - used),
            "plan_type": plan,
        }

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
