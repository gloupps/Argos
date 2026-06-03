import asyncio
import aiosqlite
import json
import uuid
import re


def _guess_type(value: str) -> str:
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", value):
        return "hash"
    if re.match(r"^https?://", value):
        return "url"
    if "." in value:
        return "domain"
    return "ioc"


class Services:

    def __init__(self, database, requester, job_manager, socketio):
        self.database = database
        self.requester = requester
        self.job_manager = job_manager
        self.socketio = socketio

        from app.modules.shodan_module import ShodanModule
        from app.modules.virustotal_module import VirusTotalModule
        from app.modules.viewdns_module import ViewDNSModule
        from app.modules.urlscan_module import URLScanModule
        from app.modules.opencti_module import OpenCTIModule
        from app.modules.misp_module import MISPModule
        from app.modules.threatfox_module import ThreatFoxModule
        from app.modules.elasticsearch_module import ElasticsearchModule
        from app.modules.censys_module import CensysModule
        from app.modules.qradar_module import QRadarModule
        from app.modules.splunk_module import SplunkModule

        self.modules = {
            "shodan": ShodanModule(self.requester),
            "virustotal": VirusTotalModule(self.requester),
            "viewdns": ViewDNSModule(self.requester),
            "urlscan": URLScanModule(self.requester),
            "opencti": OpenCTIModule(self.requester),
            "misp": MISPModule(self.requester),
            "threatfox": ThreatFoxModule(self.requester),
            "elasticsearch": ElasticsearchModule(self.requester),
            "censys": CensysModule(self.requester),
            "qradar": QRadarModule(self.requester),
            "splunk": SplunkModule(self.requester),
        }

    # ── Public ────────────────────────────────────────────

    def start_job(self, data: dict) -> str:
        job_id = self.job_manager.create_job()
        self.socketio.start_background_task(self._run_async_job, job_id, data)
        return job_id

    def _run_async_job(self, job_id, data):
        try:
            asyncio.run(self._run_job(job_id, data))
            self.job_manager.complete_job(job_id)
        except Exception as e:
            self.job_manager.fail_job(job_id, str(e))

    # ── Router ────────────────────────────────────────────

    async def _run_job(self, job_id, data):
        action = data.get("action")
        self.job_manager.add_log(job_id, f"▶ {action}")
        try:
            if action == "enrich":
                await self._run_enrichment(job_id, data)
            elif action == "correlate":
                await self._run_correlation(job_id, data)
            elif action == "enrich_and_correlate":
                await self._run_enrichment(job_id, data)
                await self._run_correlation(job_id, data)
            elif action == "check_quotas":
                await self._check_quotas(job_id, data)
            elif action == "fetch_internal_source":
                await self._handle_fetch_internal_source(job_id, data)
            elif action == "siem":
                await self._run_siem(job_id, data)
            else:
                self.job_manager.add_log(job_id, f"❌ Unknown action: {action}")
        except Exception as e:
            self.job_manager.add_log(job_id, f"❌ {e}")
            raise

    # ── Enrichment ────────────────────────────────────────

    async def _run_enrichment(self, job_id, data):
        case_id = data.get("case_id")
        api_keys = data.get("api_keys", {})
        cfg = data.get("correlation_config", {})
        extra_config = data.get("extra_config", {})  # e.g. {"opencti_url": "..."}
        indicator_filter = data.get("indicator_filter")

        if not case_id:
            self.job_manager.add_log(job_id, "❌ Missing case_id")
            return

        self.job_manager.add_log(job_id, f"🔑 Keys received: {list(api_keys.keys())}")

        async with aiosqlite.connect(self.database.db_path) as db:
            db.row_factory = aiosqlite.Row

            if indicator_filter:
                cur = await db.execute(
                    "SELECT DISTINCT value, type FROM indicators WHERE case_id=? AND value=?",
                    (case_id, indicator_filter),
                )
            else:
                cur = await db.execute(
                    "SELECT DISTINCT value, type FROM indicators WHERE case_id=? ORDER BY id DESC",
                    (case_id,),
                )
            indicators = [dict(r) for r in await cur.fetchall()]

            if not indicators:
                self.job_manager.add_log(job_id, "⚠ No indicators found")
                return

            job_db_id = str(uuid.uuid4())
            await db.execute(
                "INSERT INTO jobs (id, tasks) VALUES (?,?)", (job_db_id, "enrich")
            )
            await db.commit()

            for ind in indicators:
                ioc_type = ind["type"]
                job_modules = self._build_modules_for_job(extra_config)
                for mod_key, module in job_modules.items():
                    if ioc_type not in module.supported_types:
                        self.job_manager.add_log(
                            job_id,
                            f"– [{module.name}] skip {ind['value']} "
                            f"(type={ioc_type}, supported={module.supported_types})",
                        )
                        continue

                    api_key = api_keys.get(mod_key)
                    if not api_key:
                        self.job_manager.add_log(
                            job_id, f"⚠ [{module.name}] no key for '{mod_key}'"
                        )
                        continue

                    self.job_manager.add_log(
                        job_id, f"🔍 [{module.name}] {ind['value']}…"
                    )

                    # Collect all root indicators for cross-IOC correlation (VT etc.)
                    root_cur = await db.execute(
                        "SELECT DISTINCT value, type FROM indicators WHERE case_id=? AND node_type='root'",
                        (case_id,),
                    )
                    all_root_indicators = [dict(r) for r in await root_cur.fetchall()]

                    try:
                        # Build context — include ioc_type and any extra_config (e.g. opencti_url)
                        mod_cfg = cfg.get(mod_key, {}) if isinstance(cfg, dict) else {}
                        context = {
                            "api_key": api_key,
                            "ioc_type": ioc_type,
                            "all_root_indicators": all_root_indicators,
                            **mod_cfg,
                            **extra_config,
                        }
                        results = await module.get_info(ind["value"], context)
                        if not results:
                            self.job_manager.add_log(
                                job_id, f"– [{module.name}] {ind['value']}: no data"
                            )
                            continue

                        # Upsert indicator
                        c = await db.execute(
                            "SELECT id FROM indicators WHERE value=? AND type=? AND case_id=?",
                            (ind["value"], ioc_type, case_id),
                        )
                        row = await c.fetchone()
                        if row:
                            indicator_id = row["id"]
                        else:
                            c = await db.execute(
                                "INSERT INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                                (ind["value"], ioc_type, "root", case_id),
                            )
                            indicator_id = c.lastrowid

                        for item in results:
                            await db.execute(
                                """INSERT OR REPLACE INTO module_data
                                   (job_id, module, indicator_id, case_id,
                                    field_name, field_type, value, icon, link, max)
                                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                                (
                                    job_db_id,
                                    mod_key,
                                    indicator_id,
                                    case_id,
                                    item["field_name"],
                                    item["field_type"],
                                    json.dumps(item["value"]),
                                    item.get("icon"),
                                    item.get("link"),
                                    item.get("max"),
                                ),
                            )
                        await db.commit()
                        self.job_manager.add_log(
                            job_id,
                            f"✓ [{module.name}] {ind['value']} → {len(results)} fields",
                        )

                    except Exception as e:
                        self.job_manager.add_log(
                            job_id, f"❌ [{module.name}] {ind['value']}: {e}"
                        )

        await self._emit_graph(case_id)

    # ── Correlation ────────────────────────────────────────

    async def _run_correlation(self, job_id, data):
        case_id = data.get("case_id")
        api_keys = data.get("api_keys", {})
        cfg = data.get("correlation_config", {})
        extra_config = data.get("extra_config", {})
        indicator_filter = data.get("indicator_filter")

        if not case_id:
            self.job_manager.add_log(job_id, "❌ Missing case_id")
            return

        async with aiosqlite.connect(self.database.db_path) as db:
            db.row_factory = aiosqlite.Row

            if indicator_filter:
                cur = await db.execute(
                    "SELECT DISTINCT value, type FROM indicators WHERE case_id=? AND value=?",
                    (case_id, indicator_filter),
                )
            else:
                cur = await db.execute(
                    "SELECT DISTINCT value, type FROM indicators WHERE case_id=? ORDER BY id DESC",
                    (case_id,),
                )
            indicators = [dict(r) for r in await cur.fetchall()]

            if not indicators:
                self.job_manager.add_log(job_id, "⚠ No indicators found")
                return

            # ── Snapshot undo ────────────────────────────────────────────
            ind_snap = [
                dict(r)
                for r in await (
                    await db.execute(
                        "SELECT id, value, type, node_type FROM indicators WHERE case_id=?",
                        (case_id,),
                    )
                ).fetchall()
            ]
            piv_snap = [
                dict(r)
                for r in await (
                    await db.execute(
                        "SELECT id, label, module FROM pivots WHERE case_id=?",
                        (case_id,),
                    )
                ).fetchall()
            ]
            lnk_snap = [
                dict(r)
                for r in await (
                    await db.execute(
                        "SELECT pivot_id, indicator_id, direction FROM pivot_links WHERE case_id=?",
                        (case_id,),
                    )
                ).fetchall()
            ]
            cor_snap = [
                dict(r)
                for r in await (
                    await db.execute(
                        "SELECT job_id, src_indicator_id, tgt_indicator_id, module, pivot FROM correlation WHERE case_id=?",
                        (case_id,),
                    )
                ).fetchall()
            ]
            import json as _json

            await db.execute(
                "INSERT INTO correlation_history (case_id, snapshot) VALUES (?,?)",
                (
                    case_id,
                    _json.dumps(
                        {
                            "indicators": ind_snap,
                            "pivots": piv_snap,
                            "pivot_links": lnk_snap,
                            "correlation": cor_snap,
                        }
                    ),
                ),
            )
            await db.commit()
            # ── Fin snapshot ─────────────────────────────────────────────

            job_db_id = str(uuid.uuid4())
            await db.execute(
                "INSERT INTO jobs (id, tasks) VALUES (?,?)", (job_db_id, "correlate")
            )
            await db.commit()

            # Collect all root indicators for cross-IOC correlation (VT etc.)
            root_cur = await db.execute(
                "SELECT DISTINCT value, type FROM indicators WHERE case_id=? AND node_type='root'",
                (case_id,),
            )
            all_root_indicators = [dict(r) for r in await root_cur.fetchall()]

            corr_cur = await db.execute(
                "SELECT DISTINCT value, type FROM indicators WHERE case_id=? AND node_type='correlated'",
                (case_id,),
            )
            all_correlated_indicators = [dict(r) for r in await corr_cur.fetchall()]

            for ind in indicators:
                ioc_type = ind["type"]
                job_modules = self._build_modules_for_job(extra_config)
                for mod_key, module in job_modules.items():
                    if ioc_type not in module.supported_types:
                        continue
                    api_key = api_keys.get(mod_key)
                    if not api_key:
                        continue

                    self.job_manager.add_log(
                        job_id, f"🔗 [{module.name}] pivot {ind['value']}…"
                    )
                    try:
                        mod_cfg = cfg.get(mod_key, {}) if isinstance(cfg, dict) else {}
                        context = {
                            "api_key": api_key,
                            "ioc_type": ioc_type,
                            "all_root_indicators": all_root_indicators,
                            "all_correlated_indicators": all_correlated_indicators,
                            **mod_cfg,
                            **extra_config,
                        }
                        corrs = await module.get_correlation(ind["value"], context)
                        if not corrs:
                            self.job_manager.add_log(
                                job_id, f"– [{module.name}] {ind['value']}: no pivots"
                            )
                            continue

                        for item in corrs:
                            pivot_text = (
                                item.get("pivot_reason") or item.get("pivot") or mod_key
                            )

                            # Source — upsert
                            c = await db.execute(
                                "SELECT id FROM indicators WHERE value=? AND type=? AND case_id=?",
                                (
                                    item["source_indicator"],
                                    item["source_type"],
                                    case_id,
                                ),
                            )
                            r = await c.fetchone()
                            if r:
                                src_id = r["id"]
                            else:
                                c = await db.execute(
                                    "INSERT INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                                    (
                                        item["source_indicator"],
                                        item["source_type"],
                                        "root",
                                        case_id,
                                    ),
                                )
                                src_id = c.lastrowid

                            # Target — upsert
                            tgt_type = item["target_type"]
                            c = await db.execute(
                                "SELECT id FROM indicators WHERE value=? AND type=? AND case_id=?",
                                (item["target_indicator"], tgt_type, case_id),
                            )
                            r = await c.fetchone()
                            if r:
                                tgt_id = r["id"]
                            else:
                                c = await db.execute(
                                    "INSERT INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                                    (
                                        item["target_indicator"],
                                        tgt_type,
                                        "correlated",
                                        case_id,
                                    ),
                                )
                                tgt_id = c.lastrowid

                            # INSERT OR IGNORE — no duplicates on same (case, src, tgt, pivot)
                            await db.execute(
                                """INSERT OR IGNORE INTO correlation
                                   (job_id, case_id, src_indicator_id, tgt_indicator_id, module, pivot)
                                   VALUES (?,?,?,?,?,?)""",
                                (
                                    job_db_id,
                                    case_id,
                                    src_id,
                                    tgt_id,
                                    mod_key,
                                    pivot_text,
                                ),
                            )
                            # ── Alimenter pivots + pivot_links ──
                            if pivot_text and pivot_text not in ("True", "true", ""):
                                await db.execute(
                                    "INSERT OR IGNORE INTO pivots (case_id, label, module) VALUES (?,?,?)",
                                    (case_id, pivot_text, mod_key),
                                )
                                prow = await (
                                    await db.execute(
                                        "SELECT id FROM pivots WHERE case_id=? AND label=?",
                                        (case_id, pivot_text),
                                    )
                                ).fetchone()
                                if prow:
                                    pivot_id = prow["id"]
                                    await db.execute(
                                        "INSERT OR IGNORE INTO pivot_links (case_id, pivot_id, indicator_id, direction) VALUES (?,?,?,?)",
                                        (case_id, pivot_id, src_id, "out"),
                                    )
                                    if tgt_id != src_id:
                                        await db.execute(
                                            "INSERT OR IGNORE INTO pivot_links (case_id, pivot_id, indicator_id, direction) VALUES (?,?,?,?)",
                                            (case_id, pivot_id, tgt_id, "in"),
                                        )
                        await db.commit()
                        self.job_manager.add_log(
                            job_id,
                            f"✓ [{module.name}] {ind['value']} → {len(corrs)} pivots",
                        )

                    except Exception as e:
                        self.job_manager.add_log(
                            job_id, f"❌ [{module.name}] {ind['value']}: {e}"
                        )

        await self._emit_graph(case_id)

    # ── Quotas ────────────────────────────────────────────

    async def _check_quotas(self, job_id, data):
        api_keys = data.get("api_keys", {})
        extra_config = data.get("extra_config", {})
        result = {}
        job_modules = self._build_modules_for_job(extra_config)
        for mod_key, module in job_modules.items():
            api_key = api_keys.get(mod_key)
            if not api_key:
                continue
            try:
                ctx = {"api_key": api_key, **extra_config}
                result[mod_key] = await module.get_quotas(ctx)
            except Exception as e:
                result[mod_key] = {"error": str(e)}
        self.socketio.emit("quotas_update", result)

    # ── Emit graph ────────────────────────────────────────
    async def _emit_graph(self, case_id):
        try:
            async with aiosqlite.connect(self.database.db_path) as db:
                db.row_factory = aiosqlite.Row

                nodes_cur = await db.execute(
                    "SELECT id, value, type, node_type FROM indicators WHERE case_id=?",
                    (case_id,),
                )
                pivots_cur = await db.execute(
                    "SELECT id, label, module FROM pivots WHERE case_id=?",
                    (case_id,),
                )
                pivots = [dict(r) for r in await pivots_cur.fetchall()]

                edges = []
                for pivot in pivots:
                    links_cur = await db.execute(
                        """SELECT pl.indicator_id, pl.direction
                           FROM pivot_links pl
                           WHERE pl.case_id=? AND pl.pivot_id=?""",
                        (case_id, pivot["id"]),
                    )
                    for lk in await links_cur.fetchall():
                        edges.append(
                            {
                                "pivot_id": pivot["id"],
                                "pivot_label": pivot["label"],
                                "pivot_module": pivot["module"],
                                "indicator_id": lk["indicator_id"],
                                "direction": lk["direction"],  # ← NEW
                            }
                        )

                legacy_cur = await db.execute(
                    "SELECT src_indicator_id, tgt_indicator_id, module, pivot FROM correlation WHERE case_id=?",
                    (case_id,),
                )

                graph = {
                    "nodes": [dict(r) for r in await nodes_cur.fetchall()],
                    "pivots": pivots,
                    "edges": edges,
                    "legacy_edges": [dict(r) for r in await legacy_cur.fetchall()],
                }
            self.socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
        except Exception as e:
            print(f"[Services] emit_graph error: {e}")

    def _build_modules_for_job(self, extra_config: dict) -> dict:
        """
        Retourne self.modules complété par les instances MISP externes
        déclarées dans extra_config["misp_instances"].
        """
        from app.modules.misp_module import ExternalMISPModule

        modules = dict(self.modules)  # shallow copy — on n'altère pas self.modules

        raw_instances = extra_config.get("misp_instances") or []
        for inst in raw_instances:
            iid = str(inst.get("id", "")).strip()
            label = str(inst.get("label", "")).strip()
            if not iid or not label:
                continue
            key = f"misp_ext_{iid}"
            if key not in modules:  # ne pas écraser un module déjà présent
                modules[key] = ExternalMISPModule(self.requester, iid, label)

        return modules

    async def _handle_fetch_internal_source(self, job_id, data):
        case_id      = data.get("case_id")
        source_url   = (data.get("internal_source_url") or "").strip()
        source_type  = data.get("internal_source_type", "opencti")
        api_keys     = data.get("api_keys", {})
        extra_config = data.get("extra_config", {})

        self.job_manager.add_log(job_id, f"🌐 Fetching from {source_type}: {source_url}")

        if not source_url:
            self.job_manager.add_log(job_id, "❌ No source URL provided")
            return

        iocs = []
        try:
            if source_type == "opencti":
                iocs = await self._fetch_iocs_from_opencti(job_id, source_url, api_keys)
            elif source_type == "misp":
                iocs = await self._fetch_iocs_from_misp(job_id, source_url, api_keys, extra_config)
        except Exception as e:
            self.job_manager.add_log(job_id, f"❌ Fetch error: {e}")
            import traceback; traceback.print_exc()

        self.job_manager.add_log(job_id, f"✓ {len(iocs)} IOC(s) extracted")

        if not iocs:
            return

        async with aiosqlite.connect(self.database.db_path) as db:
            db.row_factory = aiosqlite.Row
            for value, ioc_type in iocs:
                await db.execute(
                    "INSERT OR IGNORE INTO indicators (value, type, node_type, case_id) VALUES (?,?,?,?)",
                    (value, ioc_type, "root", case_id),
                )
            await db.commit()

        # Émettre le graph mis à jour
        await self.database.connect()
        graph = await self.database.get_graph(case_id)
        self.socketio.emit("graph_update", {"case_id": case_id, "graph": graph})

        # Chaîner enrich / correlate si demandé
        if data.get("chain_enrich"):
            self.start_job({
                "action":      "enrich",
                "case_id":     case_id,
                "api_keys":    api_keys,
                "extra_config": extra_config,
            })
        if data.get("chain_correlate"):
            self.start_job({
                "action":             "correlate",
                "case_id":            case_id,
                "api_keys":           api_keys,
                "correlation_config": data.get("correlation_config", {}),
                "extra_config":       extra_config,
            })

    async def _fetch_iocs_from_opencti(self, job_id, source_url: str, api_keys: dict):
        import re as _re
        api_key  = api_keys.get("opencti", "")
        if not api_key:
            self.job_manager.add_log(job_id, "❌ No OpenCTI API key in settings")
            return []

        # Extraire l'URL de base (avant /dashboard ou /graphql)
        base_url = source_url.rstrip("/")
        for marker in ["/dashboard", "/graphql"]:
            idx = base_url.find(marker)
            if idx > 0:
                base_url = base_url[:idx]

        gql_url = f"{base_url}/graphql"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        self.job_manager.add_log(job_id, f"  → GraphQL endpoint: {gql_url}")

        # Détecter si c'est un report (UUID dans l'URL)
        report_id = None
        m = _re.search(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', source_url)
        if m:
            report_id = m.group(1)
            self.job_manager.add_log(job_id, f"  → Report ID detected: {report_id}")

        iocs = []
        seen = set()

        _ENTITY_TO_TYPE = {
            "IPv4-Addr": "ip", "IPv6-Addr": "ip",
            "Domain-Name": "domain", "Hostname": "domain",
            "Url": "url", "StixFile": "hash", "File": "hash",
        }

        async def _gql(query, variables):
            data = await self.requester.post(
                gql_url,
                json={"query": query, "variables": variables},
                headers=headers,
            )
            return data or {}

        if report_id:
            _Q = """
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
                }"""
            resp = await _gql(_Q, {"id": report_id})
            edges = (resp.get("data") or resp).get("report", {}).get("objects", {}).get("edges", [])
            self.job_manager.add_log(job_id, f"  → {len(edges)} objects in report")
            for edge in edges:
                node = edge.get("node") or {}
                # Observable
                val = node.get("observable_value")
                if val and val not in seen:
                    etype = node.get("entity_type", "")
                    ioc_type = _ENTITY_TO_TYPE.get(etype) or _guess_type(val)
                    seen.add(val); iocs.append((val, ioc_type))
                # Indicator (pattern)
                name = node.get("name")
                if name and name not in seen:
                    pat = node.get("pattern", "")
                    m2 = _re.search(r"=\s*['\"]([^'\"]+)['\"]", pat)
                    val2 = m2.group(1) if m2 else name
                    if val2 not in seen:
                        seen.add(val2); iocs.append((val2, _guess_type(val2)))
        else:
            # Liste globale des indicateurs
            _Q = """
                query listIndicators($first: Int) {
                  indicators(first: $first) {
                    edges { node { id name pattern indicator_types } }
                  }
                }"""
            resp = await _gql(_Q, {"first": 200})
            edges = (resp.get("data") or resp).get("indicators", {}).get("edges", [])
            self.job_manager.add_log(job_id, f"  → {len(edges)} indicators from instance")
            for edge in edges:
                node = edge.get("node") or {}
                pat  = node.get("pattern", "")
                m2   = _re.search(r"=\s*['\"]([^'\"]+)['\"]", pat)
                val  = m2.group(1) if m2 else (node.get("name") or "")
                if val and val not in seen:
                    seen.add(val); iocs.append((val, _guess_type(val)))

        return iocs

    async def _fetch_iocs_from_misp(self, job_id, source_url: str, api_keys: dict, extra_config: dict):
        import re as _re
        api_key = api_keys.get("misp", "")
        if not api_key:
            self.job_manager.add_log(job_id, "❌ No MISP API key in settings")
            return []

        base_url  = source_url.rstrip("/")
        event_id  = None
        m = _re.search(r'/events/(?:view/)?(\d+)', source_url)
        if m:
            event_id = m.group(1)
            base_url = source_url[:m.start()]
        else:
            # Retirer tout path après le domaine
            from urllib.parse import urlparse
            p = urlparse(source_url)
            base_url = f"{p.scheme}://{p.netloc}"

        self.job_manager.add_log(job_id, f"  → MISP base: {base_url}, event: {event_id}")

        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        _MISP_IOC_TYPES = {
            "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
            "domain": "domain", "hostname": "domain", "domain|ip": "domain",
            "url": "url", "uri": "url",
            "md5": "hash", "sha1": "hash", "sha256": "hash",
            "filename|md5": "hash", "filename|sha1": "hash", "filename|sha256": "hash",
        }

        iocs = []
        seen = set()

        if event_id:
            url  = f"{base_url}/events/{event_id}.json"
            data = await self.requester.get(url, headers=headers)
            if not data:
                self.job_manager.add_log(job_id, f"❌ MISP event {event_id} not found or empty")
                return []
            attributes = (data.get("Event") or data).get("Attribute", [])
            self.job_manager.add_log(job_id, f"  → {len(attributes)} attributes in event")
        else:
            # Recherche des attributs récents
            url  = f"{base_url}/attributes/restSearch"
            data = await self.requester.post(
                url,
                json={"limit": 200, "to_ids": True},
                headers=headers,
            )
            if not data:
                self.job_manager.add_log(job_id, "❌ MISP restSearch returned nothing")
                return []
            attributes = (data.get("response") or {}).get("Attribute", [])
            self.job_manager.add_log(job_id, f"  → {len(attributes)} attributes from search")

        for attr in attributes:
            atype = attr.get("type", "")
            val   = (attr.get("value") or "").strip()
            if not val or atype not in _MISP_IOC_TYPES:
                continue
            # Types composites : prendre la 2e partie (ex: filename|sha256 → sha256 value)
            if "|" in val:
                val = val.split("|")[-1].strip()
            if val not in seen:
                seen.add(val)
                iocs.append((val, _MISP_IOC_TYPES[atype]))

        return iocs
    
    async def _run_siem(self, job_id: str, data: dict):
        """
        SIEM investigation — IOCs lus depuis le graph du case.

        Payload :
          case_id              — case actif
          include_correlated   — bool : inclure correlated/pivoted (défaut False)
          ipv4-addr_checkbox, domain-name_checkbox,
          url_checkbox, stixfile_checkbox
          date_start, date_end — ISO datetime strings ("2026-05-01T00:00")
          extra_config         — { qradar, qradar_url,
                                   qradar_md5_sources, qradar_sha1_sources }
        """
        from app.modules.qradar_module import classify_indicators, clean_results

        case_id            = data.get("case_id")
        include_correlated = data.get("include_correlated", False)
        date_start         = data.get("date_start") or ""
        date_end           = data.get("date_end")   or ""
        extra              = data.get("extra_config", {})

        if not case_id:
            self.job_manager.add_log(job_id, "Missing case_id", "failed")
            return

        # ── 1. Lire le graph ───────────────────────────────
        await self.database.connect()
        graph = await self.database.get_graph(case_id)
        nodes = graph.get("nodes", [])

        if not nodes:
            self.job_manager.add_log(job_id, "No indicators in case graph", "failed")
            return

        if include_correlated:
            selected = [n["value"] for n in nodes if n.get("value")]
        else:
            selected = [n["value"] for n in nodes
                        if n.get("value") and n.get("node_type") == "root"]

        if not selected:
            self.job_manager.add_log(job_id, "No IOCs match the selected scope", "failed")
            return

        scope_label = "root + correlated" if include_correlated else "root only"
        self.job_manager.add_log(job_id, f"Loaded {len(selected)} IOCs ({scope_label})")

        # ── 2. Classifier ──────────────────────────────────
        dict_indicators = classify_indicators(selected)

        # ── 3. Filtres type ────────────────────────────────
        if not data.get("ipv4-addr_checkbox", True):
            dict_indicators.pop("IPv4-Addr", None)
        if not data.get("domain-name_checkbox", True):
            dict_indicators.pop("Domain-Name", None)
        if not data.get("url_checkbox", True):
            dict_indicators.pop("Url", None)
        if not data.get("stixfile_checkbox", True):
            dict_indicators.pop("StixFile", None)

        if not dict_indicators:
            self.job_manager.add_log(job_id, "No indicators left after filtering", "failed")
            return

        # ── 4. Dispatch selon siem_type ───────────────────
        siem_type = extra.get("siem_type", "qradar")

        if siem_type == "splunk":
            context = {
                "api_key":              extra.get("splunk", ""),
                "splunk_url":           extra.get("splunk_url", ""),
                # Index par défaut
                "splunk_index":         extra.get("splunk_index", "*"),
                # Index par type d'IOC (optionnels)
                "splunk_index_ip":      extra.get("splunk_index_ip", ""),
                "splunk_index_domain":  extra.get("splunk_index_domain", ""),
                "splunk_index_url":     extra.get("splunk_index_url", ""),
                "splunk_index_hash":    extra.get("splunk_index_hash", ""),
                # Nom de clé résultat
                "splunk_result_key":    extra.get("splunk_result_key", "splunk"),
                # Dates
                "date_start":           date_start,
                "date_end":             date_end,
            }
            mod = self.modules.get("splunk")
            if not mod:
                self.job_manager.add_log(job_id, "Splunk module not registered", "failed")
                return
            self.job_manager.add_log(job_id, f"Running SPL searches ({date_start} → {date_end})…")
            results = await mod.investigate(dict_indicators, context)
            
        else:  # qradar (défaut)
            context = {
                "api_key":                extra.get("qradar", ""),
                "qradar_url":             extra.get("qradar_url", ""),
                # LogSource IDs par type de hash
                "qradar_md5_sources":     extra.get("qradar_md5_sources", ""),
                "qradar_sha1_sources":    extra.get("qradar_sha1_sources", ""),
                "qradar_sha256_sources":  extra.get("qradar_sha256_sources", ""),
                # LogSource IDs pour les URLs (optionnel, coûteux)
                "qradar_url_sources":     extra.get("qradar_url_sources", ""),
                # Nom de clé résultat
                "qradar_result_key":      extra.get("qradar_result_key", "qradar"),
                # Anonymisation
                "qradar_anonymize":       extra.get("qradar_anonymize", "false"),
                # Dates
                "date_start":             date_start,
                "date_end":               date_end,
            }
            mod = self.modules.get("qradar")
            if not mod:
                self.job_manager.add_log(job_id, "QRadar module not registered", "failed")
                return
            self.job_manager.add_log(job_id, f"Running AQL queries ({date_start} → {date_end})…")
            results = await mod.investigate(dict_indicators, context)

        # ── 5. Emit ────────────────────────────────────────
        self.socketio.emit("siem_result", {
            "job_id":  job_id,
            "case_id": case_id,
            "results": results,
        })
        self.job_manager.add_log(job_id, "SIEM investigation done")
        return results

