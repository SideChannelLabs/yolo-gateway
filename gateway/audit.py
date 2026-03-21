import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass
class AuditEntry:
    project: str
    decision: str
    action: str
    request_method: str | None = None
    request_path: str | None = None
    request_body: dict | None = None
    response_status: int | None = None
    response_body: dict | None = None
    response_time_ms: int | None = None
    error_message: str | None = None


class AuditLog:
    def __init__(self, db_path: str = "data/audit.db"):
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self._db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                project TEXT NOT NULL,
                decision TEXT NOT NULL,
                action TEXT NOT NULL,
                request_method TEXT,
                request_path TEXT,
                request_body TEXT,
                response_status INTEGER,
                response_body TEXT,
                response_time_ms INTEGER,
                action_prefix TEXT,
                error_message TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_project ON audit(project)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit(decision)")
        conn.commit()

    def log(self, entry: AuditEntry):
        conn = self._get_conn()
        prefix = entry.action.split(":")[0] if ":" in entry.action else entry.action

        resp_str = None
        if entry.response_body is not None:
            resp_str = json.dumps(entry.response_body, default=str)
            if len(resp_str) > 10240:
                resp_str = resp_str[:10240] + "... [truncated]"

        req_str = json.dumps(entry.request_body, default=str) if entry.request_body else None

        conn.execute(
            """INSERT INTO audit
            (timestamp, project, decision, action, request_method, request_path,
             request_body, response_status, response_body, response_time_ms,
             action_prefix, error_message)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                entry.project,
                entry.decision,
                entry.action,
                entry.request_method,
                entry.request_path,
                req_str,
                entry.response_status,
                resp_str,
                entry.response_time_ms,
                prefix,
                entry.error_message,
            ),
        )
        conn.commit()

    def query(
        self,
        project: str | None = None,
        decision: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        conn = self._get_conn()
        sql = "SELECT * FROM audit WHERE 1=1"
        params: list = []
        if project:
            sql += " AND project = ?"
            params.append(project)
        if decision:
            sql += " AND decision = ?"
            params.append(decision)
        if search:
            sql += " AND (action LIKE ? OR request_body LIKE ? OR response_body LIKE ? OR error_message LIKE ?)"
            params.extend([f"%{search}%"] * 4)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def get_entry(self, entry_id: int) -> dict | None:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM audit WHERE id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        entry = dict(row)
        for field in ("request_body", "response_body"):
            if entry[field]:
                try:
                    entry[field] = json.loads(entry[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return entry

    def count(self, since_minutes: int | None = None, decision: str | None = None) -> int:
        conn = self._get_conn()
        sql = "SELECT COUNT(*) FROM audit WHERE 1=1"
        params: list = []
        if since_minutes:
            cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
            sql += " AND timestamp > ?"
            params.append(cutoff)
        if decision:
            sql += " AND decision = ?"
            params.append(decision)
        return conn.execute(sql, params).fetchone()[0]

    def count_by(self, field: str) -> dict:
        conn = self._get_conn()
        rows = conn.execute(
            f"SELECT {field}, COUNT(*) as count FROM audit GROUP BY {field} ORDER BY count DESC"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def avg_response_time(self, since_minutes: int = 60) -> int:
        conn = self._get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
        row = conn.execute(
            "SELECT AVG(response_time_ms) FROM audit WHERE timestamp > ? AND response_time_ms IS NOT NULL",
            (cutoff,),
        ).fetchone()
        return round(row[0] or 0)
