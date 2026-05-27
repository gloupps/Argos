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
    row  = conn.execute("SELECT id, name FROM cases WHERE id=?", (case_id,)).fetchone()
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
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value): return "ip"
    if re.match(r"^[a-fA-F0-9]{32,64}$", value):     return "hash"
    if re.match(r"^https?://", value):                return "url"
    if "." in value:                                  return "domain"
    return "ioc"

def _handle_create_case(db_path, data):
    conn        = _get_conn(db_path)
    source_mode = data.get("source_mode", "ioc")
    case_name   = (data.get("case_name") or "New Case").strip()
    existing_id = (data.get("existing_case") or "").strip()
    ioc_raw     = data.get("ioc_list", "")
    source_url  = (data.get("source_url") or "").strip()
    try:
        if source_mode == "db" and existing_id:
            row = conn.execute("SELECT id FROM cases WHERE id=?", (existing_id,)).fetchone()
            if not row: return None, f"Case {existing_id} not found"
            return row["id"], None
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
        return case_id, None
    except Exception as e:
        conn.rollback(); return None, str(e)
    finally:
        conn.close()


# ── Register ──────────────────────────────────────────────

def register_routes(app, services, job_manager):

    db_path  = services.database.db_path
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
        if not case: return "Case not found", 404
        indicators = _load_indicators(db_path, case_id)
        root = next((i for i in indicators if i["node_type"] == "root"), None)
        return render_template("ongoing_case.html",
            case_name=case["name"], case_id=case_id,
            root_indicator=root["value"] if root else None)

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
                    "SELECT value, type, node_type FROM indicators WHERE case_id=?", (case_id,)
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
                    if not rows: continue
                    modules = {}
                    for row in rows:
                        mod = row["module"]
                        if mod not in modules: modules[mod] = []
                        modules[mod].append({
                            "name": row["field_name"], "type": row["field_type"],
                            "value": _json.loads(row["value"]),
                            "icon": row["icon"], "link": row["link"], "max": row["max"],
                        })
                    result[ind["value"]] = {
                        "type": ind["type"], "node_type": ind["node_type"], "modules": modules,
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
            headers={"Content-Disposition": f'attachment; filename="case_{case_id[:8]}.stix.json"'}
        )

    @app.route("/api/job/<job_id>")
    def job_status(job_id):
        job = job_manager.get_job(job_id)
        if not job: return jsonify({"error": "not found"}), 404
        return jsonify(job)

    # ── /api/run ───────────────────────────────────────────

    @app.route("/api/run", methods=["POST"])
    def api_run():
        data   = request.get_json(force=True) or {}
        action = data.get("action")
        if not action:
            return jsonify({"error": "missing action"}), 400

        # get_modules
        if action == "get_modules":
            return jsonify({
                key: module.get_fields()
                for key, module in services.modules.items()
            })

        # rename_case
        if action == "rename_case":
            case_id  = data.get("case_id")
            new_name = (data.get("new_name") or "").strip()
            if not case_id or not new_name:
                return jsonify({"error": "missing case_id or new_name"}), 400
            try:
                conn = _get_conn(db_path)
                conn.execute("UPDATE cases SET name=? WHERE id=?", (new_name, case_id))
                conn.commit(); conn.close()
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
                ok    = loop.run_until_complete(services.database.undo_last_correlation(case_id))
                graph = loop.run_until_complete(services.database.get_graph(case_id))
            finally:
                loop.close()
            if ok:
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
            return jsonify({"ok": ok})

        # add_ioc
        if action == "add_ioc":
            case_id = data.get("case_id")
            value   = (data.get("value") or "").strip()
            if not case_id or not value:
                return jsonify({"error": "missing case_id or value"}), 400
            try:
                conn = _get_conn(db_path)
                conn.execute(
                    "INSERT OR IGNORE INTO indicators (value,type,node_type,case_id) VALUES(?,?,?,?)",
                    (value, _guess_type(value), "root", case_id),
                )
                conn.commit(); conn.close()
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    loop.run_until_complete(services.database.connect())
                    graph = loop.run_until_complete(services.database.get_graph(case_id))
                finally:
                    loop.close()
                socketio.emit("graph_update", {"case_id": case_id, "graph": graph})
                api_keys = data.get("api_keys", {})
                if api_keys:
                    services.start_job({"action": "enrich", "case_id": case_id, "api_keys": api_keys})
                return jsonify({"ok": True, "value": value})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

        # create_case
        if action == "create_case":
            case_id, err = _handle_create_case(db_path, data)
            if err: return jsonify({"error": err}), 400
            api_keys = data.get("api_keys", {})
            cfg      = data.get("correlation_config", {})
            job_ids  = {}
            if data.get("auto_enrich") and api_keys:
                job_ids["enrich"] = services.start_job({
                    "action": "enrich", "case_id": case_id, "api_keys": api_keys,
                })
            if data.get("correlation") and api_keys:
                job_ids["correlate"] = services.start_job({
                    "action": "correlate", "case_id": case_id,
                    "api_keys": api_keys, "correlation_config": cfg,
                })
            return jsonify({"case_id": case_id, "job_ids": job_ids})

        # check_quotas — synchronous
        if action == "check_quotas":
            import asyncio
            api_keys = data.get("api_keys", {})
            async def _run_quotas():
                result = {}
                for mod_key, module in services.modules.items():
                    api_key = api_keys.get(mod_key)
                    if not api_key: continue
                    try:
                        result[mod_key] = await module.get_quotas({"api_key": api_key})
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

        # background jobs
        try:
            job_id = services.start_job(data)
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
