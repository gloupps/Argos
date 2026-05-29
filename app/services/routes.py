from flask import request, jsonify, render_template
from flask_socketio import emit
import sqlite3, uuid, re, json

# ── DB helpers ────────────────────────────────────────────


def _get_conn(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY, name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT, type TEXT, node_type TEXT, case_id TEXT,
            UNIQUE(value, type, case_id)
        );
    """)
    conn.commit()
    return conn


def _load_cases(db_path):
    conn = _get_conn(db_path)
    rows = conn.execute("SELECT id, name FROM cases ORDER BY timestamp DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _load_case(db_path, case_id):
    conn = _get_conn(db_path)
    row = conn.execute("SELECT id, name FROM cases WHERE id=?", (case_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _load_indicators(db_path, case_id):
    conn = _get_conn(db_path)
    rows = conn.execute(
        "SELECT value, type, node_type FROM indicators WHERE case_id=?", (case_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _guess_type(value):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", value):
        return "hash"
    if re.match(r"^https?://", value):
        return "url"
    if "." in value:
        return "domain"
    return "ioc"


def _handle_create_case(db_path, data):
    conn = _get_conn(db_path)
    source_mode = data.get("source_mode", "ioc")
    case_name = (data.get("case_name") or "New Case").strip()
    existing_id = (data.get("existing_case") or "").strip()
    ioc_raw = data.get("ioc_list", "")
    source_url = (data.get("source_url") or "").strip()
    try:
        if source_mode == "db" and existing_id:
            # FIX : SELECT id, name pour récupérer le vrai nom du case existant
            row = conn.execute(
                "SELECT id, name FROM cases WHERE id=?", (existing_id,)
            ).fetchone()
            if not row:
                return None, None, f"Case {existing_id} not found"
            return row["id"], row["name"], None
        case_id = str(uuid.uuid4())
        conn.execute("INSERT INTO cases (id, name) VALUES (?,?)", (case_id, case_name))
        if source_mode == "ioc" and ioc_raw:
            for ioc in [l.strip() for l in ioc_raw.splitlines() if l.strip()]:
                conn.execute(
                    "INSERT OR IGNORE INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                    (ioc, _guess_type(ioc), "root", case_id),
                )
        elif source_mode == "url" and source_url:
            conn.execute(
                "INSERT OR IGNORE INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                (source_url, "url", "root", case_id),
            )
        conn.commit()
        return case_id, case_name, None
    except Exception as e:
        conn.rollback()
        return None, None, str(e)
    finally:
        conn.close()


# ── Register ──────────────────────────────────────────────


def register_routes(app, services, job_manager):

    db_path = services.database.db_path
    socketio = app.socketio

    # ── Views ──────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/view/new-case")
    def view_new_case():
        return render_template("form_case.html", existing_cases=_load_cases(db_path))

    @app.route("/view/case/<case_id>")
    def view_case(case_id):
        case = _load_case(db_path, case_id)
        if not case:
            return "Case not found", 404
        indicators = _load_indicators(db_path, case_id)
        root = next((i for i in indicators if i["node_type"] == "root"), None)
        return render_template(
            "ongoing_case.html",
            case_name=case["name"],
            case_id=case_id,
            root_indicator=root["value"] if root else None,
        )

    # ── Module registry endpoints ──────────────────────────

    @app.route("/api/modules")
    def api_modules():
        """
        Returns modules grouped by src_type.
        { "external": [...], "internal": [...], "siem": [...] }
        Each entry: { key, name, description, icon, supported_types, settings_fields }
        """
        grouped = {}
        for key, module in services.modules.items():
            fields = module.get_fields()
            entry = {
                "key": fields["key"],
                "name": fields["name"],
                "description": fields.get("description", ""),
                "icon": fields.get("icon", "box"),
                "supported_types": fields.get("supported_types", []),
                "settings_fields": fields.get("settings_fields", []),
                "type": fields.get("type", "external"),
            }
            grp = fields.get("type", "external")
            grouped.setdefault(grp, []).append(entry)
        return jsonify(grouped)

    @app.route("/api/modules/correlation")
    def api_modules_correlation():
        """
        Returns correlation schema for modules that have correlation fields.
        { modKey: { name, icon, fields: [{key, type, label, min, max, default}] } }
        """
        result = {}
        for key, module in services.modules.items():
            fields = module.get_fields()
            corr = fields.get("correlation", [])
            if corr:
                result[key] = {
                    "name": fields["name"],
                    "icon": fields.get("icon", "box"),
                    "fields": corr,
                }
        return jsonify(result)

    # ── API data ───────────────────────────────────────────

    @app.route("/api/cases")
    def api_cases():
        return jsonify(_load_cases(db_path))

    @app.route("/api/cases/<case_id>/graph")
    def api_graph(case_id):
        import asyncio

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(services.database.connect())
            graph = loop.run_until_complete(services.database.get_graph(case_id))
        finally:
            loop.close()
        return jsonify(graph)

    @app.route("/api/cases/<case_id>/info")
    def api_case_info(case_id):
        import asyncio, aiosqlite, json as _json

        async def _fetch():
            result = {}
            async with aiosqlite.connect(db_path) as db:
                db.row_factory = aiosqlite.Row
                ind_cur = await db.execute(
                    "SELECT value, type, node_type FROM indicators WHERE case_id=?",
                    (case_id,),
                )
                indicators = [dict(r) for r in await ind_cur.fetchall()]
                for ind in indicators:
                    cur = await db.execute(
                        """SELECT md.module, md.field_name, md.field_type,
                                  md.value, md.icon, md.link, md.max
                           FROM module_data md
                           JOIN indicators i ON i.id = md.indicator_id
                           WHERE i.value=? AND md.case_id=?""",
                        (ind["value"], case_id),
                    )
                    rows = await cur.fetchall()
                    if not rows:
                        continue
                    modules = {}
                    for row in rows:
                        mod = row["module"]
                        if mod not in modules:
                            modules[mod] = []
                        modules[mod].append(
                            {
                                "name": row["field_name"],
                                "type": row["field_type"],
                                "value": _json.loads(row["value"]),
                                "icon": row["icon"],
                                "link": row["link"],
                                "max": row["max"],
                            }
                        )
                    result[ind["value"]] = {
                        "type": ind["type"],
                        "node_type": ind["node_type"],
                        "modules": modules,
                    }
            return result

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_fetch())
        finally:
            loop.close()
        return jsonify(result)

    @app.route("/api/cases/<case_id>/export/stix")
    def api_export_stix(case_id):
        import asyncio

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(services.database.connect())
            bundle = loop.run_until_complete(services.database.export_stix(case_id))
        finally:
            loop.close()
        from flask import Response

        return Response(
            json.dumps(bundle, indent=2),
            mimetype="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="case_{case_id[:8]}.stix.json"'
            },
        )

    @app.route("/api/job/<job_id>")
    def job_status(job_id):
        job = job_manager.get_job(job_id)
        if not job:
            return jsonify({"error": "not found"}), 404
        return jsonify(job)

    # ── /api/run ───────────────────────────────────────────

    @app.route("/api/run", methods=["POST"])
    def api_run():
        data = request.get_json(force=True) or {}
        action = data.get("action")
        if not action:
            return jsonify({"error": "missing action"}), 400

        # get_modules
        if action == "get_modules":
            return jsonify(
                {key: module.get_fields() for key, module in services.modules.items()}
            )

        # rename_case
        if action == "rename_case":
            case_id = data.get("case_id")
            new_name = (data.get("new_name") or "").strip()
            if not case_id or not new_name:
                return jsonify({"error": "missing case_id or new_name"}), 400
            try:
                conn = _get_conn(db_path)
                conn.execute("UPDATE cases SET name=? WHERE id=?", (new_name, case_id))
                conn.commit()
                conn.close()
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # delete_case
        if action == "delete_case":
            case_id = data.get("case_id")
            if not case_id:
                return jsonify({"error": "missing case_id"}), 400
            import asyncio

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(services.database.connect())
                loop.run_until_complete(services.database.delete_case(case_id))
            finally:
                loop.close()
            return jsonify({"ok": True})

        # undo_correlation
        if action == "undo_correlation":
            case_id = data.get("case_id")
            if not case_id:
                return jsonify({"error": "missing case_id"}), 400
            import asyncio

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(services.database.connect())
                ok = loop.run_until_complete(
                    services.database.undo_last_correlation(case_id)
                )
                graph = loop.run_until_complete(services.database.get_graph(case_id))
            finally:
                loop.close()
            if ok:
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
            return jsonify({"ok": ok})

        # add_ioc
        if action == "add_ioc":
            case_id = data.get("case_id")
            value = (data.get("value") or "").strip()
            if not case_id or not value:
                return jsonify({"error": "missing case_id or value"}), 400
            node_type = data.get("node_type", "root")
            if node_type not in ("root", "correlated", "pivot"):
                node_type = "root"
            try:
                conn = _get_conn(db_path)
                conn.execute(
                    "INSERT OR IGNORE INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                    (value, _guess_type(value), node_type, case_id),
                )
                conn.commit()
                conn.close()
                import asyncio

                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(
                        services.database.get_graph(case_id)
                    )
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True, "value": value})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # delete_indicator
        if action == "delete_indicator":
            case_id = data.get("case_id")
            value = (data.get("value") or "").strip()
            if not case_id or not value:
                return jsonify({"error": "missing case_id or value"}), 400
            try:
                conn = _get_conn(db_path)
                row = conn.execute(
                    "SELECT id FROM indicators WHERE value=? AND case_id=?",
                    (value, case_id),
                ).fetchone()
                if not row:
                    conn.close()
                    return jsonify({"error": "indicator not found"}), 404
                ind_id = row["id"]
                conn.execute(
                    "DELETE FROM module_data  WHERE indicator_id=? AND case_id=?",
                    (ind_id, case_id),
                )
                conn.execute(
                    "DELETE FROM correlation  WHERE case_id=? AND (src_indicator_id=? OR tgt_indicator_id=?)",
                    (case_id, ind_id, ind_id),
                )
                conn.execute("DELETE FROM indicators   WHERE id=?", (ind_id,))
                conn.commit()
                conn.close()
                import asyncio

                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(
                        services.database.get_graph(case_id)
                    )
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # ══════════════════════════════════════════════════
        # add_manual_edge
        # ══════════════════════════════════════════════════
        if action == "add_manual_edge":
            case_id     = data.get("case_id")
            src         = (data.get("src") or "").strip()
            tgt         = (data.get("tgt") or "").strip()
            pivot_label = (data.get("pivot_label") or "").strip()

            if not case_id or not pivot_label:
                return jsonify({"error": "missing case_id or pivot_label"}), 400

            try:
                conn = _get_conn(db_path)

                def _upsert_ioc(value):
                    if not value:
                        return None
                    conn.execute(
                        "INSERT OR IGNORE INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                        (value, _guess_type(value), "correlated", case_id),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT id FROM indicators WHERE value=? AND case_id=?",
                        (value, case_id),
                    ).fetchone()
                    return row["id"] if row else None

                def _get_or_create_pivot(label, module="manual", pivot_db_id=None):
                    # ← NEW: si l'id est fourni, on vérifie d'abord qu'il existe
                    if pivot_db_id is not None:
                        row = conn.execute(
                            "SELECT id FROM pivots WHERE id=? AND case_id=?",
                            (pivot_db_id, case_id),
                        ).fetchone()
                        if row:
                            return row["id"]
                    # fallback : chercher/créer par label
                    conn.execute(
                        "INSERT OR IGNORE INTO pivots (case_id, label, module) VALUES (?,?,?)",
                        (case_id, label, module),
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT id FROM pivots WHERE case_id=? AND label=?",
                        (case_id, label),
                    ).fetchone()
                    return row["id"] if row else None

                def _link(pivot_id, indicator_id, direction="out"):
                    if indicator_id is None:
                        return
                    conn.execute(
                        """INSERT OR IGNORE INTO pivot_links
                           (case_id, pivot_id, indicator_id, direction) VALUES (?,?,?,?)""",
                        (case_id, pivot_id, indicator_id, direction),
                    )

                # Récupérer l'éventuel id de pivot transmis par le frontend
                pivot_db_id_raw = data.get("pivot_db_id")
                pivot_db_id = int(pivot_db_id_raw) if pivot_db_id_raw is not None else None

                # ── Upsert le pivot ──
                pivot_id = _get_or_create_pivot(pivot_label, pivot_db_id=pivot_db_id)
                if not pivot_id:
                    conn.close()
                    return jsonify({"error": "could not create pivot"}), 500

                # direction transmise par le frontend
                # src_dir : sens du drag depuis src vers le pivot
                # tgt_dir : sens opposé
                link_type = data.get("link_type", "correlation")  # "correlation" ou "manual_directed"

                if link_type == "manual_directed":
                    # Lien manuel avec direction explicite (drag IOC→pivot ou pivot→IOC)
                    src_direction = data.get("src_direction", "out")
                    tgt_direction = "in" if src_direction == "out" else "out"
                else:
                    # Corrélation IOC↔IOC : les deux IOC pointent vers le pivot
                    src_direction = "out"
                    tgt_direction = "out"

                # ── Rattacher src ──
                if src:
                    src_id = _upsert_ioc(src)
                    _link(pivot_id, src_id, src_direction)

                # ── Rattacher tgt (si différent de src) ──
                if tgt and tgt != src:
                    tgt_id = _upsert_ioc(tgt)
                    _link(pivot_id, tgt_id, tgt_direction)

                conn.commit()
                conn.close()

                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(services.database.get_graph(case_id))
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500
            
        # ══════════════════════════════════════════════════════════
        # add_pivot  — crée un pivot standalone dans la table pivots
        # ══════════════════════════════════════════════════════════
        if action == "add_pivot":
            case_id     = data.get("case_id")
            label       = (data.get("label") or "").strip()
            if not case_id or not label:
                return jsonify({"error": "missing case_id or label"}), 400
            try:
                conn = _get_conn(db_path)
                conn.execute(
                    "INSERT OR IGNORE INTO pivots (case_id, label, module) VALUES (?,?,?)",
                    (case_id, label, "manual"),
                )
                conn.commit()
                conn.close()

                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(services.database.get_graph(case_id))
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # ══════════════════════════════════════════════════
        # delete_pivot
        # ══════════════════════════════════════════════════
        if action == "delete_pivot":
            case_id     = data.get("case_id")
            pivot_label = (data.get("pivot_label") or "").strip()
            if not case_id or not pivot_label:
                return jsonify({"error": "missing case_id or pivot_label"}), 400
            try:
                conn = _get_conn(db_path)
                # pivot_links supprimés par CASCADE
                conn.execute(
                    "DELETE FROM pivots WHERE case_id=? AND label=?",
                    (case_id, pivot_label),
                )
                # Nettoyer aussi la table legacy
                conn.execute(
                    "DELETE FROM correlation WHERE case_id=? AND pivot=?",
                    (case_id, pivot_label),
                )
                conn.commit()
                conn.close()

                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(services.database.get_graph(case_id))
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # ══════════════════════════════════════════════════
        # rename_pivot
        # ══════════════════════════════════════════════════
        if action == "rename_pivot":
            case_id   = data.get("case_id")
            old_label = (data.get("old_label") or "").strip()
            new_label = (data.get("new_label") or "").strip()
            if not case_id or not old_label or not new_label:
                return jsonify({"error": "missing case_id, old_label or new_label"}), 400
            try:
                conn = _get_conn(db_path)
                conn.execute(
                    "UPDATE pivots SET label=? WHERE case_id=? AND label=?",
                    (new_label, case_id, old_label),
                )
                # Sync table legacy
                conn.execute(
                    "UPDATE correlation SET pivot=? WHERE case_id=? AND pivot=?",
                    (new_label, case_id, old_label),
                )
                conn.commit()
                conn.close()

                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(services.database.get_graph(case_id))
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # create_case
        if action == "create_case":
            # FIX : déstructuration en 3 valeurs — case_id, resolved_name, err
            case_id, resolved_name, err = _handle_create_case(db_path, data)
            if err:
                return jsonify({"error": err}), 400
            api_keys = data.get("api_keys", {})
            extra_config = data.get("extra_config", {})
            cfg = data.get("correlation_config", {})
            source_mode = data.get("source_mode", "ioc")
            job_ids = {}
            if source_mode != "db":
                if data.get("auto_enrich") and api_keys:
                    job_ids["enrich"] = services.start_job({
                        "action": "enrich",
                        "case_id": case_id,
                        "api_keys": api_keys,
                        "extra_config": extra_config,
                    })
                if data.get("correlation") and api_keys:
                    job_ids["correlate"] = services.start_job({
                        "action": "correlate",
                        "case_id": case_id,
                        "api_keys": api_keys,
                        "correlation_config": cfg,
                        "extra_config": extra_config,
                    })
            # FIX : retourner case_name pour que le JS nomme correctement l'onglet
            return jsonify(
                {"case_id": case_id, "case_name": resolved_name, "job_ids": job_ids}
            )

        # check_quotas — synchronous
        if action == "check_quotas":
            import asyncio

            api_keys = data.get("api_keys", {})
            extra_config = data.get("extra_config", {})

            async def _run_quotas():
                result = {}
                for mod_key, module in services.modules.items():
                    api_key = api_keys.get(mod_key)
                    if not api_key:
                        continue
                    try:
                        ctx = {"api_key": api_key, **extra_config}
                        result[mod_key] = await module.get_quotas(ctx)
                    except Exception as ex:
                        result[mod_key] = {"error": str(ex)}
                return result

            loop = asyncio.new_event_loop()
            try:
                quotas = loop.run_until_complete(_run_quotas())
            finally:
                loop.close()
            socketio.emit("quotas_update", quotas)
            return jsonify(quotas)

        # background jobs — pass extra_config through
        try:
            payload = {**data}
            if "extra_config" not in payload:
                payload["extra_config"] = {}
            job_id = services.start_job(payload)
            return jsonify({"job_id": job_id, "status": "started"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ── WebSocket ──────────────────────────────────────────

    @app.socketio.on("connect")
    def on_connect():
        print("[WS] client connected")

    @app.socketio.on("subscribe_case")
    def on_subscribe(data):
        case_id = data.get("case_id") if isinstance(data, dict) else None
        if case_id:
            from flask_socketio import join_room

            join_room(case_id)
            emit("subscribed", {"case_id": case_id})
