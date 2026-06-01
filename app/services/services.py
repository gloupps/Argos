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

        self.modules = {
            "shodan": ShodanModule(self.requester),
            "virustotal": VirusTotalModule(self.requester),
            "viewdns": ViewDNSModule(self.requester),
            "urlscan": URLScanModule(self.requester),
            "opencti": OpenCTIModule(self.requester),
            "misp": MISPModule(self.requester),
            "threatfox": ThreatFoxModule(self.requester),
            "elasticsearch": ElasticsearchModule(self.requester),
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
