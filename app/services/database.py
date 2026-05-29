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
        await self._migrate()

    async def close(self):
        if self.db:
            await self.db.close()

    # ─────────────────────────────────────────────────────
    # Schema
    # ─────────────────────────────────────────────────────

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
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, indicator_id, module, field_name)
        );
        CREATE TABLE IF NOT EXISTS correlation (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id            TEXT,
            case_id           TEXT,
            src_indicator_id  INTEGER,
            tgt_indicator_id  INTEGER,
            module            TEXT,
            pivot             TEXT,
            timestamp         DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, src_indicator_id, tgt_indicator_id, pivot)
        );
        CREATE TABLE IF NOT EXISTS pivots (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id   TEXT    NOT NULL,
            label     TEXT    NOT NULL,
            module    TEXT    NOT NULL DEFAULT 'manual',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, label)
        );
        CREATE TABLE IF NOT EXISTS pivot_links (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id      TEXT    NOT NULL,
            pivot_id     INTEGER NOT NULL REFERENCES pivots(id) ON DELETE CASCADE,
            indicator_id INTEGER NOT NULL REFERENCES indicators(id) ON DELETE CASCADE,
            direction    TEXT    NOT NULL DEFAULT 'out',
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(case_id, pivot_id, indicator_id)
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
        CREATE INDEX IF NOT EXISTS idx_indicators_value   ON indicators(value);
        CREATE INDEX IF NOT EXISTS idx_module_data_ind    ON module_data(indicator_id);
        CREATE INDEX IF NOT EXISTS idx_corr_case          ON correlation(case_id);
        CREATE INDEX IF NOT EXISTS idx_corr_hist_case     ON correlation_history(case_id);
        CREATE INDEX IF NOT EXISTS idx_pivots_case        ON pivots(case_id);
        CREATE INDEX IF NOT EXISTS idx_pivot_links_pivot  ON pivot_links(pivot_id);
        CREATE INDEX IF NOT EXISTS idx_pivot_links_ind    ON pivot_links(indicator_id);
        """)
        await self.db.commit()

    async def _migrate(self):
        """Migration automatique : alimente pivots + pivot_links depuis correlation.pivot."""
        # Vérifier si la migration a déjà été faite
        cur = await self.db.execute("SELECT COUNT(*) as n FROM pivots")
        row = await cur.fetchone()
        pivots_populated = row["n"] > 0

        # Récupérer toutes les corrélations avec un pivot non vide
        cur = await self.db.execute(
            """SELECT DISTINCT case_id, src_indicator_id, tgt_indicator_id, module, pivot
               FROM correlation
               WHERE pivot IS NOT NULL AND pivot != '' AND pivot != 'True' AND pivot != 'true'"""
        )
        rows = await cur.fetchall()

        if not rows:
            return

        migrated = 0
        for row in rows:
            case_id  = row["case_id"]
            pivot_lbl = row["pivot"]
            module   = row["module"] or "manual"
            src_id   = row["src_indicator_id"]
            tgt_id   = row["tgt_indicator_id"]

            # Upsert pivot
            await self.db.execute(
                "INSERT OR IGNORE INTO pivots (case_id, label, module) VALUES (?,?,?)",
                (case_id, pivot_lbl, module),
            )
            cur2 = await self.db.execute(
                "SELECT id FROM pivots WHERE case_id=? AND label=?",
                (case_id, pivot_lbl),
            )
            pivot_row = await cur2.fetchone()
            if not pivot_row:
                continue
            pivot_id = pivot_row["id"]

            # Upsert pivot_links pour src et tgt (skip si src==tgt = ancien single_ioc)
            await self.db.execute(
                "INSERT OR IGNORE INTO pivot_links (case_id, pivot_id, indicator_id, direction) VALUES (?,?,?,?)",
                (case_id, pivot_id, src_id, "out"),
            )
            if tgt_id != src_id:
                await self.db.execute(
                    "INSERT OR IGNORE INTO pivot_links (case_id, pivot_id, indicator_id, direction) VALUES (?,?,?,?)",
                    (case_id, pivot_id, tgt_id, "in"),
                )
            migrated += 1

        if migrated:
            await self.db.commit()

    # ─────────────────────────────────────────────────────
    # Cases
    # ─────────────────────────────────────────────────────

    async def create_case(self, name, case_id=None):
        case_id = case_id or str(uuid.uuid4())
        await self.db.execute(
            "INSERT OR IGNORE INTO cases (id, name) VALUES (?, ?)",
            (case_id, name),
        )
        await self.db.commit()
        return case_id

    async def get_cases(self):
        cursor = await self.db.execute(
            "SELECT id, name, timestamp FROM cases ORDER BY timestamp DESC"
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_case(self, case_id):
        cursor = await self.db.execute(
            "SELECT id, name, timestamp FROM cases WHERE id=?", (case_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def delete_case(self, case_id):
        for table in ["module_data", "correlation", "correlation_history",
                      "siem", "pivot_links", "pivots", "indicators"]:
            await self.db.execute(f"DELETE FROM {table} WHERE case_id=?", (case_id,))
        await self.db.execute("DELETE FROM cases WHERE id=?", (case_id,))
        await self.db.commit()

    # ─────────────────────────────────────────────────────
    # Indicators
    # ─────────────────────────────────────────────────────

    async def get_or_create_indicator(self, value, type_, case_id, node_type="correlated"):
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

    # ─────────────────────────────────────────────────────
    # Module data
    # ─────────────────────────────────────────────────────

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

    # ─────────────────────────────────────────────────────
    # Correlation (table legacy — lecture seule pour modules)
    # ─────────────────────────────────────────────────────

    async def save_correlation_snapshot(self, case_id):
        cur = await self.db.execute(
            "SELECT id, src_indicator_id, tgt_indicator_id, module, pivot FROM correlation WHERE case_id=?",
            (case_id,),
        )
        rows = [dict(r) for r in await cur.fetchall()]
        await self.db.execute(
            "INSERT INTO correlation_history (case_id, snapshot) VALUES (?,?)",
            (case_id, json.dumps(rows)),
        )
        await self.db.commit()

    async def undo_last_correlation(self, case_id):
        cur = await self.db.execute(
            "SELECT id, snapshot FROM correlation_history WHERE case_id=? ORDER BY timestamp DESC LIMIT 1",
            (case_id,),
        )
        row = await cur.fetchone()
        if not row:
            return False

        snapshot = json.loads(row["snapshot"])
        snap_id  = row["id"]

        await self.db.execute("DELETE FROM correlation WHERE case_id=?", (case_id,))
        for item in snapshot:
            await self.db.execute(
                """INSERT OR IGNORE INTO correlation
                   (job_id, case_id, src_indicator_id, tgt_indicator_id, module, pivot)
                   VALUES (?,?,?,?,?,?)""",
                (
                    item.get("job_id", ""),
                    case_id,
                    item["src_indicator_id"],
                    item["tgt_indicator_id"],
                    item["module"],
                    item["pivot"],
                ),
            )
        await self.db.execute("DELETE FROM correlation_history WHERE id=?", (snap_id,))
        await self.db.commit()
        return True

    # ─────────────────────────────────────────────────────
    # Pivots
    # ─────────────────────────────────────────────────────

    async def get_or_create_pivot(self, case_id, label, module="manual"):
        await self.db.execute(
            "INSERT OR IGNORE INTO pivots (case_id, label, module) VALUES (?,?,?)",
            (case_id, label, module),
        )
        cur = await self.db.execute(
            "SELECT id FROM pivots WHERE case_id=? AND label=?",
            (case_id, label),
        )
        row = await cur.fetchone()
        await self.db.commit()
        return row["id"]

    async def link_indicator_to_pivot(self, case_id, pivot_id, indicator_id, direction="out"):
        await self.db.execute(
            """INSERT OR IGNORE INTO pivot_links (case_id, pivot_id, indicator_id, direction)
               VALUES (?,?,?,?)""",
            (case_id, pivot_id, indicator_id, direction),
        )
        await self.db.commit()

    async def delete_pivot(self, case_id, label):
        """Supprime le pivot et tous ses liens (CASCADE)."""
        await self.db.execute(
            "DELETE FROM pivots WHERE case_id=? AND label=?",
            (case_id, label),
        )
        await self.db.commit()

    async def rename_pivot(self, case_id, old_label, new_label):
        await self.db.execute(
            "UPDATE pivots SET label=? WHERE case_id=? AND label=?",
            (new_label, case_id, old_label),
        )
        await self.db.commit()

    async def get_pivot_indicator_ids(self, case_id, pivot_id):
        cur = await self.db.execute(
            "SELECT indicator_id FROM pivot_links WHERE case_id=? AND pivot_id=?",
            (case_id, pivot_id),
        )
        return [r["indicator_id"] for r in await cur.fetchall()]

    # ─────────────────────────────────────────────────────
    # Correlation — insertion via modules
    # ─────────────────────────────────────────────────────

    async def insert_correlation(self, job_id, case_id, src_indicator_id,
                                  tgt_indicator_id, module, pivot_label):
        """
        Insère une corrélation dans la table legacy ET dans pivots+pivot_links.
        C'est le point d'entrée unique pour tous les modules.
        """
        # 1. Table legacy (rétrocompatibilité, lecture par undo/snapshot)
        await self.db.execute(
            """INSERT OR IGNORE INTO correlation
               (job_id, case_id, src_indicator_id, tgt_indicator_id, module, pivot)
               VALUES (?,?,?,?,?,?)""",
            (job_id, case_id, src_indicator_id, tgt_indicator_id, module, pivot_label),
        )

        # 2. Table pivots + pivot_links
        if pivot_label and pivot_label not in ("True", "true", ""):
            pivot_id = await self.get_or_create_pivot(case_id, pivot_label, module)
            # src → pivot (direction out), pivot → tgt (direction in)
            await self.link_indicator_to_pivot(case_id, pivot_id, src_indicator_id, "out")
            if tgt_indicator_id != src_indicator_id:
                await self.link_indicator_to_pivot(case_id, pivot_id, tgt_indicator_id, "in")

        await self.db.commit()

    # ─────────────────────────────────────────────────────
    # Graph
    # ─────────────────────────────────────────────────────

    async def get_graph(self, case_id):
        # Nœuds : IOC normaux
        nodes_cur = await self.db.execute(
            "SELECT id, value, type, node_type FROM indicators WHERE case_id=?",
            (case_id,),
        )
        nodes = [dict(r) for r in await nodes_cur.fetchall()]

        # Nœuds pivot + edges depuis pivot_links
        pivots_cur = await self.db.execute(
            "SELECT id, label, module FROM pivots WHERE case_id=?",
            (case_id,),
        )
        pivots = [dict(r) for r in await pivots_cur.fetchall()]

        edges = []
        for pivot in pivots:
            links_cur = await self.db.execute(
                """SELECT pl.indicator_id, pl.direction, i.value as indicator_value
                   FROM pivot_links pl
                   JOIN indicators i ON i.id = pl.indicator_id
                   WHERE pl.case_id=? AND pl.pivot_id=?""",
                (case_id, pivot["id"]),
            )
            links = await links_cur.fetchall()
            for lk in links:
                edges.append({
                    "pivot_id":     pivot["id"],
                    "pivot_label":  pivot["label"],
                    "pivot_module": pivot["module"],
                    "indicator_id": lk["indicator_id"],
                    "direction":    lk["direction"],    # ← NEW
                })

        # Edges legacy (modules auto-correlation non encore migrés)
        legacy_cur = await self.db.execute(
            """SELECT src_indicator_id, tgt_indicator_id, module, pivot
               FROM correlation WHERE case_id=?""",
            (case_id,),
        )
        legacy_edges = [dict(r) for r in await legacy_cur.fetchall()]

        return {
            "nodes":        nodes,
            "pivots":       pivots,
            "edges":        edges,         # pivot_links
            "legacy_edges": legacy_edges,  # correlation table (fallback)
        }

    # ─────────────────────────────────────────────────────
    # Info / History
    # ─────────────────────────────────────────────────────

    async def get_info(self, case_id, indicator_value):
        cursor = await self.db.execute(
            """SELECT md.module, md.field_name, md.field_type,
                      md.value, md.icon, md.link, md.max
               FROM module_data md
               JOIN indicators i ON i.id = md.indicator_id
               WHERE i.value=? AND md.case_id=?""",
            (indicator_value, case_id),
        )
        rows = await cursor.fetchall()
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
