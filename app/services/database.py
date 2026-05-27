import aiosqlite
import json
import uuid


class Database:

    def __init__(self, db_path="pivotlens.db"):
        self.db_path = db_path
        self.db = None

    async def connect(self):
        self.db = await aiosqlite.connect(self.db_path)
        self.db.row_factory = aiosqlite.Row
        await self._create_tables()

    async def close(self):
        if self.db:
            await self.db.close()

    async def _create_tables(self):
        await self.db.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id        TEXT PRIMARY KEY,
            name      TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS indicators (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            value     TEXT,
            type      TEXT,
            node_type TEXT,
            case_id   TEXT,
            UNIQUE(value, type, case_id)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id        TEXT PRIMARY KEY,
            tasks     TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS module_data (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id       TEXT,
            module       TEXT,
            indicator_id INTEGER,
            case_id      TEXT,
            field_name   TEXT,
            field_type   TEXT,
            value        TEXT,
            icon         TEXT,
            link         TEXT,
            max          INTEGER,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS correlation (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id            TEXT,
            case_id           TEXT,
            src_indicator_id  INTEGER,
            tgt_indicator_id  INTEGER,
            module            TEXT,
            pivot             TEXT,
            timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS correlation_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id   TEXT,
            snapshot  TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS siem (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id       TEXT,
            case_id      TEXT,
            indicator_id INTEGER,
            source       TEXT,
            raw_data     TEXT,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_indicators_value  ON indicators(value);
        CREATE INDEX IF NOT EXISTS idx_module_data_ind   ON module_data(indicator_id);
        CREATE INDEX IF NOT EXISTS idx_corr_case         ON correlation(case_id);
        CREATE INDEX IF NOT EXISTS idx_corr_hist_case    ON correlation_history(case_id);
        """)
        await self.db.commit()

    # ── Cases ─────────────────────────────────────────────

    async def create_case(self, name):
        case_id = str(uuid.uuid4())
        await self.db.execute("INSERT INTO cases (id, name) VALUES (?, ?)", (case_id, name))
        await self.db.commit()
        return case_id

    async def delete_case(self, case_id):
        """Delete case and all related data."""
        await self.db.executescript(f"""
            DELETE FROM module_data        WHERE case_id='{case_id}';
            DELETE FROM correlation        WHERE case_id='{case_id}';
            DELETE FROM correlation_history WHERE case_id='{case_id}';
            DELETE FROM siem               WHERE case_id='{case_id}';
            DELETE FROM indicators         WHERE case_id='{case_id}';
            DELETE FROM cases              WHERE id='{case_id}';
        """)
        await self.db.commit()

    # ── Jobs ──────────────────────────────────────────────

    async def create_job(self, task_type):
        job_id = str(uuid.uuid4())
        await self.db.execute("INSERT INTO jobs (id, tasks) VALUES (?, ?)", (job_id, task_type))
        await self.db.commit()
        return job_id

    # ── Indicators ────────────────────────────────────────

    async def get_or_create_indicator(self, value, type_, case_id, node_type="default"):
        cursor = await self.db.execute(
            "SELECT id FROM indicators WHERE value=? AND type=? AND case_id=?",
            (value, type_, case_id),
        )
        row = await cursor.fetchone()
        if row:
            return row["id"]
        cursor = await self.db.execute(
            "INSERT INTO indicators (value, type, node_type, case_id) VALUES (?, ?, ?, ?)",
            (value, type_, node_type, case_id),
        )
        await self.db.commit()
        return cursor.lastrowid

    # ── Module data ───────────────────────────────────────

    async def insert_module_data(self, job_id, case_id, module, data):
        for item in data:
            indicator_id = await self.get_or_create_indicator(
                item["indicator"], item["indicator_type"], case_id
            )
            await self.db.execute(
                """INSERT INTO module_data
                   (job_id, module, indicator_id, case_id,
                    field_name, field_type, value, icon, link, max)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (job_id, module, indicator_id, case_id,
                 item["field_name"], item["field_type"], json.dumps(item["value"]),
                 item.get("icon"), item.get("link"), item.get("max")),
            )
        await self.db.commit()

    # ── Correlation ───────────────────────────────────────

    async def save_correlation_snapshot(self, case_id):
        """Save current graph state before adding new correlations (undo support)."""
        cur = await self.db.execute(
            "SELECT id, src_indicator_id, tgt_indicator_id, module, pivot FROM correlation WHERE case_id=?",
            (case_id,)
        )
        rows = [dict(r) for r in await cur.fetchall()]
        await self.db.execute(
            "INSERT INTO correlation_history (case_id, snapshot) VALUES (?,?)",
            (case_id, json.dumps(rows))
        )
        await self.db.commit()

    async def undo_last_correlation(self, case_id):
        """Restore the previous correlation snapshot."""
        cur = await self.db.execute(
            "SELECT id, snapshot FROM correlation_history WHERE case_id=? ORDER BY timestamp DESC LIMIT 1",
            (case_id,)
        )
        row = await cur.fetchone()
        if not row:
            return False

        snapshot = json.loads(row["snapshot"])
        snap_id  = row["id"]

        # Delete current correlations
        await self.db.execute("DELETE FROM correlation WHERE case_id=?", (case_id,))

        # Restore snapshot
        for item in snapshot:
            await self.db.execute(
                """INSERT INTO correlation
                   (job_id, case_id, src_indicator_id, tgt_indicator_id, module, pivot)
                   VALUES (?,?,?,?,?,?)""",
                (item["job_id"] if "job_id" in item else "",
                 case_id,
                 item["src_indicator_id"],
                 item["tgt_indicator_id"],
                 item["module"],
                 item["pivot"])
            )

        # Remove the snapshot we just restored
        await self.db.execute("DELETE FROM correlation_history WHERE id=?", (snap_id,))
        await self.db.commit()
        return True

    # ── Graph ─────────────────────────────────────────────

    async def get_graph(self, case_id):
        nodes_cur = await self.db.execute(
            "SELECT id, value, type, node_type FROM indicators WHERE case_id=?", (case_id,)
        )
        # pivot column is now TEXT — contains the pivot reason/label
        edges_cur = await self.db.execute(
            "SELECT src_indicator_id, tgt_indicator_id, module, pivot FROM correlation WHERE case_id=?",
            (case_id,)
        )
        return {
            "nodes": [dict(r) for r in await nodes_cur.fetchall()],
            "edges": [dict(r) for r in await edges_cur.fetchall()],
        }

    # ── Info ──────────────────────────────────────────────

    async def get_info(self, case_id, indicator_value):
        cursor = await self.db.execute(
            """SELECT md.module, md.field_name, md.field_type,
                      md.value, md.icon, md.link, md.max
               FROM module_data md
               JOIN indicators i ON i.id = md.indicator_id
               WHERE i.value=? AND md.case_id=?""",
            (indicator_value, case_id),
        )
        rows   = await cursor.fetchall()
        result = {}
        for row in rows:
            mod = row["module"]
            if mod not in result:
                result[mod] = []
            result[mod].append({
                "name":  row["field_name"],
                "type":  row["field_type"],
                "value": json.loads(row["value"]),
                "icon":  row["icon"],
                "link":  row["link"],
                "max":   row["max"],
            })
        return result

    async def get_history(self, case_id, limit=200):
        cursor = await self.db.execute(
            "SELECT DISTINCT value, type FROM indicators WHERE case_id=? ORDER BY id DESC LIMIT ?",
            (case_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ── STIX export ───────────────────────────────────────

    async def export_stix(self, case_id):
        """Build a minimal STIX 2.1 bundle from the case graph."""
        import datetime

        nodes_cur = await self.db.execute(
            "SELECT id, value, type, node_type FROM indicators WHERE case_id=?", (case_id,)
        )
        nodes = [dict(r) for r in await nodes_cur.fetchall()]

        edges_cur = await self.db.execute(
            """SELECT c.src_indicator_id, c.tgt_indicator_id, c.module, c.pivot,
                      src.value AS src_value, src.type AS src_type,
                      tgt.value AS tgt_value, tgt.type AS tgt_type
               FROM correlation c
               JOIN indicators src ON src.id = c.src_indicator_id
               JOIN indicators tgt ON tgt.id = c.tgt_indicator_id
               WHERE c.case_id=?""",
            (case_id,)
        )
        edges = [dict(r) for r in await edges_cur.fetchall()]

        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        TYPE_MAP = {
            "ip":     "ipv4-addr",
            "domain": "domain-name",
            "url":    "url",
            "hash":   "file",
            "ioc":    "indicator",
        }

        objects = []
        id_map  = {}   # db_id → stix_id

        for n in nodes:
            stix_type = TYPE_MAP.get(n["type"], "indicator")
            stix_id   = f"{stix_type}--{str(uuid.uuid4())}"
            id_map[n["id"]] = stix_id

            if stix_type == "ipv4-addr":
                obj = {"type": stix_type, "id": stix_id, "value": n["value"]}
            elif stix_type == "domain-name":
                obj = {"type": stix_type, "id": stix_id, "value": n["value"]}
            elif stix_type == "url":
                obj = {"type": stix_type, "id": stix_id, "value": n["value"]}
            elif stix_type == "file":
                obj = {"type": stix_type, "id": stix_id,
                       "hashes": {"SHA-256": n["value"]}}
            else:
                obj = {
                    "type": "indicator", "id": stix_id,
                    "spec_version": "2.1",
                    "created": now, "modified": now,
                    "name": n["value"],
                    "indicator_types": ["malicious-activity"],
                    "pattern": f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{n['value']}']",
                    "pattern_type": "stix",
                    "valid_from": now,
                }
            if "spec_version" not in obj:
                obj["spec_version"] = "2.1"
            objects.append(obj)

        for e in edges:
            src_stix = id_map.get(e["src_indicator_id"])
            tgt_stix = id_map.get(e["tgt_indicator_id"])
            if not src_stix or not tgt_stix:
                continue
            rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{str(uuid.uuid4())}",
                "created": now, "modified": now,
                "relationship_type": "related-to",
                "source_ref": src_stix,
                "target_ref": tgt_stix,
                "description": e.get("pivot") or e.get("module") or "correlated",
            }
            objects.append(rel)

        return {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "spec_version": "2.1",
            "objects": objects,
        }
