import aiosqlite
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional


class Database:

    def __init__(self, db_path: str = "pivotlens.db"):
        self.db_path = db_path
        self.conn: Optional[aiosqlite.Connection] = None

    # =========================
    # 🔌 CONNECTION
    # =========================
    async def connect(self):
        if not self.conn:
            self.conn = await aiosqlite.connect(self.db_path)
            await self.conn.execute("PRAGMA foreign_keys = ON")

    async def close(self):
        if self.conn:
            await self.conn.close()

    # =========================
    # 🏗️ INIT DATABASE
    # =========================
    async def create_database(self):
        await self.connect()

        # CASES
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            name TEXT,
            created_at TEXT
        )
        """)

        # CASE IOC (multi-root support)
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS case_iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            value TEXT,
            type TEXT,
            is_root INTEGER,
            created_at TEXT,
            UNIQUE(case_id, value),
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)

        # JOBS (historique pivot / recherche)
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            case_id TEXT,
            type TEXT,
            created_at TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
        """)

        # NODES (graph)
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT,
            job_id TEXT,
            label TEXT,
            type TEXT,
            created_at TEXT,
            PRIMARY KEY (id, job_id),
            FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
        )
        """)

        # EDGES (graph)
        await self.conn.execute("""
        CREATE TABLE IF NOT EXISTS edges (
            id TEXT,
            job_id TEXT,
            source TEXT,
            target TEXT,
            created_at TEXT,
            PRIMARY KEY (id, job_id),
            FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
        )
        """)

        # INDEXES (CRITICAL PERF)
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_case_id ON jobs(case_id)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_nodes_job_id ON nodes(job_id)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_edges_job_id ON edges(job_id)"
        )
        await self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_case_iocs_case_id ON case_iocs(case_id)"
        )

        await self.conn.commit()

    # =========================
    # 📁 CASE MANAGEMENT
    # =========================
    async def create_case(self, name: str, iocs: List[Dict[str, str]]) -> str:
        """
        iocs = [
            {"value": "1.1.1.1", "type": "ip"},
            {"value": "evil.com", "type": "domain"}
        ]
        """

        await self.connect()

        case_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        await self.conn.execute(
            """
        INSERT INTO cases (id, name, created_at)
        VALUES (?, ?, ?)
        """,
            (case_id, name, now),
        )

        await self.conn.executemany(
            """
        INSERT INTO case_iocs (case_id, value, type, is_root, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
            [(case_id, ioc["value"], ioc["type"], 1, now) for ioc in iocs],
        )

        await self.conn.commit()
        return case_id

    async def add_iocs(
        self, case_id: str, iocs: List[Dict[str, str]], is_root: bool = False
    ):
        await self.connect()

        now = datetime.utcnow().isoformat()

        await self.conn.executemany(
            """
        INSERT OR IGNORE INTO case_iocs (case_id, value, type, is_root, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
            [(case_id, ioc["value"], ioc["type"], int(is_root), now) for ioc in iocs],
        )

        await self.conn.commit()

    async def get_root_iocs(self, case_id: str):
        await self.connect()

        rows = await self.conn.execute_fetchall(
            """
        SELECT value, type
        FROM case_iocs
        WHERE case_id = ? AND is_root = 1
        """,
            (case_id,),
        )

        return [{"value": r[0], "type": r[1]} for r in rows]

    # =========================
    # 🧠 JOBS (HISTORIQUE)
    # =========================
    async def create_job(self, case_id: str, job_type: str) -> str:
        await self.connect()

        job_id = str(uuid.uuid4())

        await self.conn.execute(
            """
        INSERT INTO jobs (id, case_id, type, created_at)
        VALUES (?, ?, ?, ?)
        """,
            (job_id, case_id, job_type, datetime.utcnow().isoformat()),
        )

        await self.conn.commit()
        return job_id

    # =========================
    # 📊 GRAPH STORAGE
    # =========================
    async def insert_nodes(self, job_id: str, nodes: List[Dict[str, Any]]):
        await self.connect()

        now = datetime.utcnow().isoformat()

        await self.conn.executemany(
            """
        INSERT OR IGNORE INTO nodes (id, job_id, label, type, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
            [(n["id"], job_id, n["label"], n["type"], now) for n in nodes],
        )

        await self.conn.commit()

    async def insert_edges(self, job_id: str, edges: List[Dict[str, Any]]):
        await self.connect()

        now = datetime.utcnow().isoformat()

        await self.conn.executemany(
            """
        INSERT OR IGNORE INTO edges (id, job_id, source, target, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
            [
                (f"{e['source']}_{e['target']}", job_id, e["source"], e["target"], now)
                for e in edges
            ],
        )

        await self.conn.commit()

    # =========================
    # 📥 GRAPH RETRIEVAL
    # =========================
    async def get_case_graph(self, case_id: str):
        await self.connect()

        nodes = await self.conn.execute_fetchall(
            """
        SELECT n.id, n.label, n.type
        FROM nodes n
        JOIN jobs j ON n.job_id = j.id
        WHERE j.case_id = ?
        """,
            (case_id,),
        )

        edges = await self.conn.execute_fetchall(
            """
        SELECT e.source, e.target
        FROM edges e
        JOIN jobs j ON e.job_id = j.id
        WHERE j.case_id = ?
        """,
            (case_id,),
        )

        return {
            "nodes": [{"id": n[0], "label": n[1], "type": n[2]} for n in nodes],
            "edges": [{"source": e[0], "target": e[1]} for e in edges],
        }

    # =========================
    # ⚡ LATEST STATE (FAST LOAD FRONT)
    # =========================
    async def get_latest_graph(self, case_id: str):
        await self.connect()

        job = await self.conn.execute_fetchone(
            """
        SELECT id
        FROM jobs
        WHERE case_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
            (case_id,),
        )

        if not job:
            return {"nodes": [], "edges": []}

        job_id = job[0]

        nodes = await self.conn.execute_fetchall(
            """
        SELECT id, label, type FROM nodes WHERE job_id = ?
        """,
            (job_id,),
        )

        edges = await self.conn.execute_fetchall(
            """
        SELECT source, target FROM edges WHERE job_id = ?
        """,
            (job_id,),
        )

        return {
            "nodes": [{"id": n[0], "label": n[1], "type": n[2]} for n in nodes],
            "edges": [{"source": e[0], "target": e[1]} for e in edges],
        }
