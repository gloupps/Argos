from flask import request, jsonify, render_template, send_file
from flask_socketio import emit
import json
import sqlite3
import uuid


def _initialize_database(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            value TEXT,
            type TEXT,
            node_type TEXT,
            case_id TEXT,
            UNIQUE(value, type, case_id)
        );
    """)
    conn.commit()
    return conn


def _load_cases(db_path):
    conn = _initialize_database(db_path)
    cursor = conn.execute("SELECT id, name FROM cases ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def register_routes(app, services, job_manager) -> None:

    @app.route("/test-ws")
    def test_ws():
        app.socketio.emit(
            "job_update",
            {"job_id": "test", "message": "TEST", "status": "running"},
        )
        return "ok"

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/run", methods=["POST"])
    def run():
        try:

            data = request.get_json()
            job_id = services.start_job(data)

            return jsonify({"job_id": job_id, "status": "started"})

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route("/api/job/<job_id>")
    def job_status(job_id):

        job = job_manager.get_job(job_id)

        if not job:
            return {"error": "job not found"}, 404

        return job

    @app.socketio.on("search_ioc")
    def handle_search_ioc(data):
        ioc = data.get("ioc") if isinstance(data, dict) else None

        if not ioc:
            emit(
                "job_update",
                {"job_id": "search", "message": "IOC manquant", "status": "failed"},
            )
            return

        emit(
            "job_update",
            {
                "job_id": "search",
                "message": f"Recherche {ioc} en cours",
                "status": "running",
            },
        )

        nodes = [
            {"id": ioc, "label": ioc, "type": "root"},
            {"id": f"{ioc}-pivot-1", "label": "Pivot 1", "type": "pivot"},
            {"id": f"{ioc}-pivot-2", "label": "Pivot 2", "type": "pivot"},
            {"id": f"{ioc}-correlated-1", "label": "Corrélé A", "type": "correlated"},
        ]

        edges = [
            {"source": ioc, "target": f"{ioc}-pivot-1"},
            {"source": ioc, "target": f"{ioc}-pivot-2"},
            {"source": f"{ioc}-pivot-1", "target": f"{ioc}-correlated-1"},
        ]

        emit("graph_update", {"nodes": nodes, "edges": edges})
        emit(
            "job_update",
            {"job_id": "search", "message": "Graph ready", "status": "done"},
        )

    @app.route("/settings")
    def settings():
        return render_template("settings.html")

    @app.route("/new_case_form")
    def new_case_form():
        cases = _load_cases(services.database.db_path)
        return render_template("form_case.html", existing_cases=cases)

    @app.route("/create_case", methods=["POST"])
    def create_case():
        case_name = request.form.get("case_name", "").strip() or "New Case"
        source_mode = request.form.get("source_mode", "ioc")
        existing_case_id = request.form.get("existing_case", "").strip()
        source_url = request.form.get("source_url", "").strip()
        ioc_list = request.form.get("ioc_list", "").strip()
        stix_file = request.files.get("stix_file")

        db_path = services.database.db_path
        conn = _initialize_database(db_path)
        cursor = conn.cursor()

        case_id = None
        root_indicator = None
        search_message = "Case créé avec succès."

        if source_mode == "db" and existing_case_id:
            cursor.execute(
                "SELECT id, name FROM cases WHERE id = ?", (existing_case_id,)
            )
            row = cursor.fetchone()
            if row:
                case_id = row["id"]
                case_name = row["name"]
                search_message = f"Case existant chargé : {case_name}"
            else:
                case_id = str(uuid.uuid4())
                cursor.execute(
                    "INSERT INTO cases (id, name) VALUES (?, ?)", (case_id, case_name)
                )
                search_message = (
                    "Case créé et aucune case existant valide n'a été sélectionné."
                )
        else:
            case_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO cases (id, name) VALUES (?, ?)", (case_id, case_name)
            )

            if source_mode == "ioc" and ioc_list:
                iocs = [line.strip() for line in ioc_list.splitlines() if line.strip()]
                for ioc in iocs:
                    cursor.execute(
                        "INSERT OR IGNORE INTO indicators (value, type, node_type, case_id) VALUES (?, ?, ?, ?)",
                        (ioc, "ioc", "root", case_id),
                    )
                if iocs:
                    root_indicator = iocs[0]
                    search_message = (
                        f"Recherche lancée sur l'indicateur racine : {root_indicator}"
                    )
                else:
                    search_message = "Case créé mais aucune IOC n'a été fournie."

            elif source_mode == "url" and source_url:
                cursor.execute(
                    "INSERT OR IGNORE INTO indicators (value, type, node_type, case_id) VALUES (?, ?, ?, ?)",
                    (source_url, "url", "root", case_id),
                )
                root_indicator = source_url
                search_message = (
                    f"Recherche lancée sur la source URL : {root_indicator}"
                )

            elif source_mode == "file" and stix_file:
                root_indicator = None
                search_message = "STIX file reçu, case enregistré. La recherche STIX doit être lancée séparément."
            else:
                search_message = "Case créé sans source sélectionnée."

        conn.commit()
        conn.close()

        return render_template(
            "ongoing_case.html",
            case_name=case_name,
            case_id=case_id,
            root_indicator=root_indicator,
            search_message=search_message,
            source_mode=source_mode,
        )
