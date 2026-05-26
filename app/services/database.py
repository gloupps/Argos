import aiosqlite
import json
import uuid


class Database:

    def __init__(self, db_path="pivotlens.db"):
        self.db_path = db_path
        self.db = None

    # -------------------------
    # INIT / CONNECTION
    # -------------------------
    async def connect(self):
        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        if self.db:
            await self.db.close()

    # -------------------------
    # TABLES
    # -------------------------
    async def _create_tables(self):

        await self.db.executescript("""
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

        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            tasks TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS module_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            job_id TEXT,
            module TEXT,

            indicator_id INTEGER,
            case_id TEXT,

            field_name TEXT,
            field_type TEXT,
            value TEXT,

            icon TEXT,
            link TEXT,
            max INTEGER,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS correlation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            job_id TEXT,
            case_id TEXT,

            src_indicator_id INTEGER,
            tgt_indicator_id INTEGER,

            module TEXT,
            pivot BOOLEAN,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS siem (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            job_id TEXT,
            case_id TEXT,
            indicator_id INTEGER,

            source TEXT,
            raw_data TEXT,

            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(value);
        CREATE INDEX IF NOT EXISTS idx_module_data_indicator ON module_data(indicator_id);
        CREATE INDEX IF NOT EXISTS idx_corr_case ON correlation(case_id);
        """)

        await self.db.commit()

    # -------------------------
    # CASE / JOB
    # -------------------------
    async def create_case(self, name):
        case_id = str(uuid.uuid4())

        await self.db.execute(
            "INSERT INTO cases (id, name) VALUES (?, ?)", (case_id, name)
        )
        await self.db.commit()

        return case_id

    async def create_job(self, task_type):
        job_id = str(uuid.uuid4())

        await self.db.execute(
            "INSERT INTO jobs (id, tasks) VALUES (?, ?)", (job_id, task_type)
        )
        await self.db.commit()

        return job_id

    # -------------------------
    # INDICATOR
    # -------------------------
    async def get_or_create_indicator(self, value, type_, case_id, node_type="default"):

        cursor = await self.db.execute(
            """
            SELECT id FROM indicators
            WHERE value=? AND type=? AND case_id=?
        """,
            (value, type_, case_id),
        )

        row = await cursor.fetchone()

        if row:
            return row["id"]

        cursor = await self.db.execute(
            """
            INSERT INTO indicators (value, type, node_type, case_id)
            VALUES (?, ?, ?, ?)
        """,
            (value, type_, node_type, case_id),
        )

        await self.db.commit()
        return cursor.lastrowid

    # -------------------------
    # INSERT MODULE DATA
    # -------------------------
    async def insert_module_data(self, job_id, case_id, module, data):

        for item in data:

            indicator_id = await self.get_or_create_indicator(
                item["indicator"], item["indicator_type"], case_id
            )

            await self.db.execute(
                """
                INSERT INTO module_data (
                    job_id, module, indicator_id, case_id,
                    field_name, field_type, value,
                    icon, link, max
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    job_id,
                    module,
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

        await self.db.commit()

    # -------------------------
    # INSERT CORRELATION
    # -------------------------
    async def insert_correlation(self, job_id, case_id, module, correlations):

        for item in correlations:

            src_id = await self.get_or_create_indicator(
                item["source_indicator"], item["source_type"], case_id, "pivot"
            )

            tgt_id = await self.get_or_create_indicator(
                item["target_indicator"], item["target_type"], case_id, "correlated"
            )

            await self.db.execute(
                """
                INSERT INTO correlation (
                    job_id, case_id,
                    src_indicator_id, tgt_indicator_id,
                    module, pivot
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (job_id, case_id, src_id, tgt_id, module, item.get("pivot", False)),
            )

        await self.db.commit()

    # -------------------------
    # SIEM
    # -------------------------
    async def insert_siem(self, job_id, case_id, indicator_id, source, raw_data):

        await self.db.execute(
            """
            INSERT INTO siem (job_id, case_id, indicator_id, source, raw_data)
            VALUES (?, ?, ?, ?, ?)
        """,
            (job_id, case_id, indicator_id, source, json.dumps(raw_data)),
        )

        await self.db.commit()

    # -------------------------
    # GET GRAPH
    # -------------------------
    async def get_graph(self, case_id):

        nodes_cursor = await self.db.execute(
            """
            SELECT id, value, type, node_type
            FROM indicators
            WHERE case_id=?
        """,
            (case_id,),
        )

        edges_cursor = await self.db.execute(
            """
            SELECT src_indicator_id, tgt_indicator_id, module, pivot
            FROM correlation
            WHERE case_id=?
        """,
            (case_id,),
        )

        return {
            "nodes": [dict(row) for row in await nodes_cursor.fetchall()],
            "edges": [dict(row) for row in await edges_cursor.fetchall()],
        }

    # -------------------------
    # GET INFO (CASE)
    # -------------------------
    async def get_info(self, case_id, indicator_value):

        cursor = await self.db.execute(
            """
            SELECT md.module, md.field_name, md.field_type,
                   md.value, md.icon, md.link, md.max
            FROM module_data md
            JOIN indicators i ON i.id = md.indicator_id
            WHERE i.value=? AND md.case_id=?
        """,
            (indicator_value, case_id),
        )

        rows = await cursor.fetchall()

        result = {}

        for row in rows:
            module = row["module"]

            if module not in result:
                result[module] = []

            result[module].append(
                {
                    "name": row["field_name"],
                    "type": row["field_type"],
                    "value": json.loads(row["value"]),
                    "icon": row["icon"],
                    "link": row["link"],
                    "max": row["max"],
                }
            )

        return result

    # -------------------------
    # 🔥 GET GLOBAL INDICATOR HISTORY
    # -------------------------
    async def get_indicator_history(self, indicator_value):

        cursor = await self.db.execute(
            """
            SELECT md.module, md.field_name, md.field_type,
                   md.value, md.icon, md.link, md.max,
                   md.timestamp, md.case_id
            FROM module_data md
            JOIN indicators i ON i.id = md.indicator_id
            WHERE i.value=?
            ORDER BY md.timestamp DESC
        """,
            (indicator_value,),
        )

        rows = await cursor.fetchall()

        result = []

        for row in rows:
            result.append(
                {
                    "module": row["module"],
                    "case_id": row["case_id"],
                    "name": row["field_name"],
                    "type": row["field_type"],
                    "value": json.loads(row["value"]),
                    "icon": row["icon"],
                    "link": row["link"],
                    "max": row["max"],
                    "timestamp": row["timestamp"],
                }
            )

        return result

    # -------------------------
    # HISTORY (CASE)
    # -------------------------
    async def get_history(self, case_id, limit=50):

        cursor = await self.db.execute(
            """
            SELECT DISTINCT value, type
            FROM indicators
            WHERE case_id=?
            ORDER BY id DESC
            LIMIT ?
        """,
            (case_id, limit),
        )

        return [dict(row) for row in await cursor.fetchall()]
