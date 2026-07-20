# Copyright 2026 Siddharth
# SPDX-License-Identifier: Apache-2.0

"""SQLite persistence and shared data models.

Three tables: sessions, actions, findings. Every action keeps the full raw
span JSON (`raw_attributes`) so the audit record survives normalization gaps.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pathlib import Path

from pydantic import BaseModel, Field


def anzen_home() -> Path:
    """Anzen's home directory (database and logs). Override with ANZEN_HOME."""
    import os

    home = Path(os.environ.get("ANZEN_HOME", Path.home() / ".anzen"))
    home.mkdir(parents=True, exist_ok=True)
    return home


def default_db() -> str:
    """Default database path: ~/.anzen/anzen.db (zero-config for every command)."""
    return str(anzen_home() / "anzen.db")


DEFAULT_DB = "anzen.db"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ActionType(str, Enum):
    tool_call = "tool_call"
    llm_call = "llm_call"
    agent_invoke = "agent_invoke"
    prompt = "prompt"
    response = "response"
    permission_decision = "permission_decision"
    system_event = "system_event"
    unknown = "unknown"


class Session(BaseModel):
    id: str
    agent_name: str = "unknown-agent"
    started_at: float | None = None
    ended_at: float | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    # identity & posture (from telemetry resource/event attributes)
    user_email: str = ""
    user_id: str = ""
    org_id: str = ""
    hostname: str = ""
    terminal_type: str = ""
    app_version: str = ""
    permission_mode: str = ""
    department: str = ""
    cost_usd: float = 0.0
    # populated by list queries, not stored columns
    action_count: int = 0
    finding_counts: dict[str, int] = Field(default_factory=dict)


class Action(BaseModel):
    id: int | None = None
    session_id: str
    span_id: str
    timestamp: float
    action_type: ActionType = ActionType.unknown
    name: str = ""
    input: str = ""
    output: str = ""
    status: str = "ok"
    # event linkage & permission forensics (Claude Code telemetry)
    prompt_id: str = ""
    tool_use_id: str = ""
    decision: str = ""
    decision_source: str = ""
    cost_usd: float = 0.0
    duration_ms: float = 0.0
    raw_attributes: dict[str, Any] = Field(default_factory=dict)


class Endpoint(BaseModel):
    """One (agent type, user, host) triple observed reporting telemetry."""

    id: int | None = None
    agent_type: str = "unknown-agent"
    user_email: str = ""
    hostname: str = ""
    app_version: str = ""
    terminal_type: str = ""
    first_seen: float | None = None
    last_seen: float | None = None
    permission_mode_latest: str = ""
    # populated by list queries, not a stored column
    session_count: int = 0


class InventoryItem(BaseModel):
    """A discovered MCP server, plugin, skill, or hook seen anywhere in the fleet."""

    id: int | None = None
    kind: Literal["mcp_server", "plugin", "skill", "hook"]
    name: str
    scope: str = ""
    transport: str = ""
    version: str = ""
    marketplace: str = ""
    status: str = ""
    first_seen: float | None = None
    last_seen: float | None = None
    user_emails: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    approved: bool | None = None  # None = unreviewed


class Finding(BaseModel):
    id: int | None = None
    session_id: str
    action_id: int | None = None
    rule_id: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    owasp_llm: str = ""
    title: str
    explanation: str
    remediation: str
    matched_excerpt: str = ""
    source: Literal["rule", "llm"] = "rule"
    created_at: float | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT PRIMARY KEY,
    agent_name    TEXT NOT NULL DEFAULT 'unknown-agent',
    started_at    REAL,
    ended_at      REAL,
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS actions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT NOT NULL REFERENCES sessions(id),
    span_id        TEXT NOT NULL,
    timestamp      REAL NOT NULL,
    action_type    TEXT NOT NULL,
    name           TEXT NOT NULL DEFAULT '',
    input          TEXT NOT NULL DEFAULT '',
    output         TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'ok',
    raw_attributes TEXT NOT NULL DEFAULT '{}',
    UNIQUE(session_id, span_id)
);
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(id),
    action_id       INTEGER REFERENCES actions(id),
    rule_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    owasp_llm       TEXT NOT NULL DEFAULT '',
    title           TEXT NOT NULL,
    explanation     TEXT NOT NULL,
    remediation     TEXT NOT NULL,
    matched_excerpt TEXT NOT NULL DEFAULT '',
    source          TEXT NOT NULL DEFAULT 'rule',
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_type             TEXT NOT NULL DEFAULT 'unknown-agent',
    user_email             TEXT NOT NULL DEFAULT '',
    hostname               TEXT NOT NULL DEFAULT '',
    app_version            TEXT NOT NULL DEFAULT '',
    terminal_type          TEXT NOT NULL DEFAULT '',
    first_seen             REAL,
    last_seen              REAL,
    permission_mode_latest TEXT NOT NULL DEFAULT '',
    UNIQUE(agent_type, user_email, hostname)
);
CREATE TABLE IF NOT EXISTS inventory (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,
    name           TEXT NOT NULL,
    scope          TEXT NOT NULL DEFAULT '',
    transport      TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL DEFAULT '',
    marketplace    TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT '',
    first_seen     REAL,
    last_seen      REAL,
    user_emails    TEXT NOT NULL DEFAULT '[]',
    endpoint_count INTEGER NOT NULL DEFAULT 0,
    approved       INTEGER,  -- NULL = unreviewed, 0/1 = reviewed
    UNIQUE(kind, name)
);
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
-- rule findings are deterministic per (rule, action): lets auto-scan on ingest
-- and manual re-scans coexist without duplicates (INSERT OR IGNORE)
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_rule_unique
    ON findings(session_id, rule_id, action_id) WHERE source = 'rule';
"""

# Columns added after the initial schema shipped. Applied idempotently on open
# so existing databases upgrade in place (SQLite ALTER TABLE ADD COLUMN only).
_MIGRATIONS: dict[str, dict[str, str]] = {
    "sessions": {
        "user_email": "TEXT NOT NULL DEFAULT ''",
        "user_id": "TEXT NOT NULL DEFAULT ''",
        "org_id": "TEXT NOT NULL DEFAULT ''",
        "hostname": "TEXT NOT NULL DEFAULT ''",
        "terminal_type": "TEXT NOT NULL DEFAULT ''",
        "app_version": "TEXT NOT NULL DEFAULT ''",
        "permission_mode": "TEXT NOT NULL DEFAULT ''",
        "department": "TEXT NOT NULL DEFAULT ''",
        "cost_usd": "REAL NOT NULL DEFAULT 0",
    },
    "actions": {
        "prompt_id": "TEXT NOT NULL DEFAULT ''",
        "tool_use_id": "TEXT NOT NULL DEFAULT ''",
        "decision": "TEXT NOT NULL DEFAULT ''",
        "decision_source": "TEXT NOT NULL DEFAULT ''",
        "cost_usd": "REAL NOT NULL DEFAULT 0",
        "duration_ms": "REAL NOT NULL DEFAULT 0",
    },
}


class Store:
    """Thread-safe wrapper around the anzen SQLite database."""

    def __init__(self, path: str = DEFAULT_DB):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Add any columns introduced after a database was created (idempotent)."""
        for table, columns in _MIGRATIONS.items():
            existing = {
                row["name"]
                for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for column, decl in columns.items():
                if column not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

    def close(self) -> None:
        self._conn.close()

    # -- sessions ----------------------------------------------------------

    def upsert_session(self, session: Session) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO sessions (id, agent_name, started_at, ended_at, input_tokens, output_tokens,
                                      user_email, user_id, org_id, hostname, terminal_type,
                                      app_version, permission_mode, department, cost_usd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    agent_name    = CASE WHEN excluded.agent_name != 'unknown-agent'
                                         THEN excluded.agent_name ELSE sessions.agent_name END,
                    started_at    = MIN(COALESCE(sessions.started_at, excluded.started_at), excluded.started_at),
                    ended_at      = MAX(COALESCE(sessions.ended_at, excluded.ended_at), excluded.ended_at),
                    input_tokens  = sessions.input_tokens + excluded.input_tokens,
                    output_tokens = sessions.output_tokens + excluded.output_tokens,
                    user_email      = CASE WHEN excluded.user_email != '' THEN excluded.user_email ELSE sessions.user_email END,
                    user_id         = CASE WHEN excluded.user_id != '' THEN excluded.user_id ELSE sessions.user_id END,
                    org_id          = CASE WHEN excluded.org_id != '' THEN excluded.org_id ELSE sessions.org_id END,
                    hostname        = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE sessions.hostname END,
                    terminal_type   = CASE WHEN excluded.terminal_type != '' THEN excluded.terminal_type ELSE sessions.terminal_type END,
                    app_version     = CASE WHEN excluded.app_version != '' THEN excluded.app_version ELSE sessions.app_version END,
                    permission_mode = CASE WHEN excluded.permission_mode != '' THEN excluded.permission_mode ELSE sessions.permission_mode END,
                    department      = CASE WHEN excluded.department != '' THEN excluded.department ELSE sessions.department END,
                    cost_usd        = sessions.cost_usd + excluded.cost_usd
                """,
                (
                    session.id,
                    session.agent_name,
                    session.started_at,
                    session.ended_at,
                    session.input_tokens,
                    session.output_tokens,
                    session.user_email,
                    session.user_id,
                    session.org_id,
                    session.hostname,
                    session.terminal_type,
                    session.app_version,
                    session.permission_mode,
                    session.department,
                    session.cost_usd,
                ),
            )

    def get_session(self, session_id: str) -> Session | None:
        row = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if row is None:
            # allow unambiguous prefix lookup (short IDs in the CLI)
            rows = self._conn.execute(
                "SELECT * FROM sessions WHERE id LIKE ?", (session_id + "%",)
            ).fetchall()
            if len(rows) != 1:
                return None
            row = rows[0]
        return self._session_from_row(row)

    def list_sessions(self) -> list[Session]:
        rows = self._conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC"
        ).fetchall()
        return [self._session_from_row(r) for r in rows]

    def _session_from_row(self, row: sqlite3.Row) -> Session:
        session = Session(**{k: row[k] for k in row.keys()})
        session.action_count = self._conn.execute(
            "SELECT COUNT(*) FROM actions WHERE session_id = ?", (session.id,)
        ).fetchone()[0]
        counts = self._conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE session_id = ? GROUP BY severity",
            (session.id,),
        ).fetchall()
        session.finding_counts = {sev: n for sev, n in counts}
        return session

    # -- actions -----------------------------------------------------------

    def insert_action(self, action: Action) -> int | None:
        """Insert an action; returns its row id, or None if the span was already stored."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                """
                INSERT OR IGNORE INTO actions
                    (session_id, span_id, timestamp, action_type, name, input, output, status,
                     prompt_id, tool_use_id, decision, decision_source, cost_usd, duration_ms,
                     raw_attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.session_id,
                    action.span_id,
                    action.timestamp,
                    action.action_type.value,
                    action.name,
                    action.input,
                    action.output,
                    action.status,
                    action.prompt_id,
                    action.tool_use_id,
                    action.decision,
                    action.decision_source,
                    action.cost_usd,
                    action.duration_ms,
                    json.dumps(action.raw_attributes, sort_keys=True, default=str),
                ),
            )
            return cur.lastrowid if cur.rowcount else None

    def apply_decision(
        self, session_id: str, tool_use_id: str, decision: str, source: str
    ) -> bool:
        """Merge a tool_decision event onto its tool action. Returns False if no match yet."""
        if not tool_use_id:
            return False
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE actions SET decision = ?, decision_source = ? "
                "WHERE session_id = ? AND tool_use_id = ?",
                (decision, source, session_id, tool_use_id),
            )
            return cur.rowcount > 0

    def get_actions(self, session_id: str) -> list[Action]:
        rows = self._conn.execute(
            "SELECT * FROM actions WHERE session_id = ? ORDER BY timestamp, id",
            (session_id,),
        ).fetchall()
        actions = []
        for row in rows:
            data = {k: row[k] for k in row.keys()}
            data["raw_attributes"] = json.loads(data["raw_attributes"])
            actions.append(Action(**data))
        return actions

    def list_agents(self) -> list[dict]:
        """Per-agent rollup for `anzen agents`: sessions, actions, last seen, findings."""
        agents = []
        rows = self._conn.execute(
            "SELECT agent_name, COUNT(*) AS sessions, MAX(ended_at) AS last_seen "
            "FROM sessions GROUP BY agent_name ORDER BY last_seen DESC"
        ).fetchall()
        for row in rows:
            actions = self._conn.execute(
                "SELECT COUNT(*) FROM actions JOIN sessions ON actions.session_id = sessions.id "
                "WHERE sessions.agent_name = ?",
                (row["agent_name"],),
            ).fetchone()[0]
            counts = self._conn.execute(
                "SELECT severity, COUNT(*) FROM findings JOIN sessions ON findings.session_id = sessions.id "
                "WHERE sessions.agent_name = ? GROUP BY severity",
                (row["agent_name"],),
            ).fetchall()
            agents.append(
                {
                    "agent_name": row["agent_name"],
                    "sessions": row["sessions"],
                    "actions": actions,
                    "last_seen": row["last_seen"],
                    "finding_counts": {sev: n for sev, n in counts},
                }
            )
        return agents

    def stats(self) -> dict:
        """Totals for `anzen status`: sessions, actions, findings by severity."""
        sessions = self._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        actions = self._conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
        last_action = self._conn.execute("SELECT MAX(timestamp) FROM actions").fetchone()[0]
        severities = dict(
            self._conn.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            ).fetchall()
        )
        return {
            "sessions": sessions,
            "actions": actions,
            "last_action_at": last_action,
            "findings": severities,
        }

    # -- endpoints ---------------------------------------------------------

    def upsert_endpoint(self, endpoint: Endpoint) -> None:
        """Record an (agent, user, host) sighting; widens first/last seen, keeps latest metadata."""
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO endpoints (agent_type, user_email, hostname, app_version, terminal_type,
                                       first_seen, last_seen, permission_mode_latest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_type, user_email, hostname) DO UPDATE SET
                    app_version   = CASE WHEN excluded.app_version != '' THEN excluded.app_version ELSE endpoints.app_version END,
                    terminal_type = CASE WHEN excluded.terminal_type != '' THEN excluded.terminal_type ELSE endpoints.terminal_type END,
                    first_seen    = MIN(COALESCE(endpoints.first_seen, excluded.first_seen), excluded.first_seen),
                    last_seen     = MAX(COALESCE(endpoints.last_seen, excluded.last_seen), excluded.last_seen),
                    permission_mode_latest = CASE WHEN excluded.permission_mode_latest != ''
                                                  THEN excluded.permission_mode_latest
                                                  ELSE endpoints.permission_mode_latest END
                """,
                (
                    endpoint.agent_type,
                    endpoint.user_email,
                    endpoint.hostname,
                    endpoint.app_version,
                    endpoint.terminal_type,
                    endpoint.first_seen,
                    endpoint.last_seen,
                    endpoint.permission_mode_latest,
                ),
            )

    def list_endpoints(self) -> list[Endpoint]:
        rows = self._conn.execute(
            """
            SELECT e.*, COUNT(s.id) AS session_count
            FROM endpoints e
            LEFT JOIN sessions s
                ON s.agent_name = e.agent_type
               AND s.user_email = e.user_email
               AND s.hostname = e.hostname
            GROUP BY e.id
            ORDER BY e.last_seen DESC
            """
        ).fetchall()
        return [Endpoint(**{k: r[k] for k in r.keys()}) for r in rows]

    # -- inventory ---------------------------------------------------------

    def upsert_inventory_item(self, item: InventoryItem) -> None:
        """Record a sighting of an MCP server/plugin/skill/hook; merges users, preserves review state."""
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM inventory WHERE kind = ? AND name = ?", (item.kind, item.name)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO inventory (kind, name, scope, transport, version, marketplace,
                                           status, first_seen, last_seen, user_emails, endpoint_count, approved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.kind, item.name, item.scope, item.transport, item.version,
                        item.marketplace, item.status, item.first_seen, item.last_seen,
                        json.dumps(sorted(set(item.user_emails))), len(set(item.user_emails)),
                        item.approved,
                    ),
                )
                return
            emails = sorted(set(json.loads(row["user_emails"])) | set(item.user_emails))
            seen = [t for t in (row["first_seen"], row["last_seen"], item.first_seen, item.last_seen) if t]
            self._conn.execute(
                """
                UPDATE inventory SET
                    scope = ?, transport = ?, version = ?, marketplace = ?, status = ?,
                    first_seen = ?, last_seen = ?, user_emails = ?, endpoint_count = ?
                WHERE id = ?
                """,
                (
                    item.scope or row["scope"],
                    item.transport or row["transport"],
                    item.version or row["version"],
                    item.marketplace or row["marketplace"],
                    item.status or row["status"],
                    min(seen) if seen else None,
                    max(seen) if seen else None,
                    json.dumps(emails),
                    len(emails),
                    row["id"],
                ),
            )

    def set_inventory_approval(self, item_id: int, approved: bool | None) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE inventory SET approved = ? WHERE id = ?", (approved, item_id)
            )

    def list_inventory(self, kind: str | None = None) -> list[InventoryItem]:
        query = "SELECT * FROM inventory"
        params: tuple = ()
        if kind:
            query += " WHERE kind = ?"
            params = (kind,)
        rows = self._conn.execute(query + " ORDER BY last_seen DESC", params).fetchall()
        items = []
        for row in rows:
            data = {k: row[k] for k in row.keys()}
            data["user_emails"] = json.loads(data["user_emails"])
            data["approved"] = None if data["approved"] is None else bool(data["approved"])
            items.append(InventoryItem(**data))
        return items

    # -- findings ----------------------------------------------------------

    def replace_findings(self, session_id: str, source: str, findings: list[Finding]) -> None:
        """Replace all findings of one source for a session (idempotent re-scans)."""
        now = datetime.now(timezone.utc).timestamp()
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM findings WHERE session_id = ? AND source = ?",
                (session_id, source),
            )
            self._conn.executemany(
                """
                INSERT INTO findings
                    (session_id, action_id, rule_id, severity, owasp_llm, title,
                     explanation, remediation, matched_excerpt, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        f.session_id, f.action_id, f.rule_id, f.severity, f.owasp_llm,
                        f.title, f.explanation, f.remediation, f.matched_excerpt,
                        f.source, now,
                    )
                    for f in findings
                ],
            )

    def add_findings(self, findings: list[Finding]) -> int:
        """Append findings, skipping any already recorded. Returns how many were new."""
        now = datetime.now(timezone.utc).timestamp()
        added = 0
        with self._lock, self._conn:
            for f in findings:
                cur = self._conn.execute(
                    """
                    INSERT OR IGNORE INTO findings
                        (session_id, action_id, rule_id, severity, owasp_llm, title,
                         explanation, remediation, matched_excerpt, source, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.session_id, f.action_id, f.rule_id, f.severity, f.owasp_llm,
                        f.title, f.explanation, f.remediation, f.matched_excerpt,
                        f.source, now,
                    ),
                )
                added += cur.rowcount
        return added

    def get_findings(self, session_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE session_id = ?", (session_id,)
        ).fetchall()
        findings = [Finding(**{k: r[k] for k in r.keys()}) for r in rows]
        findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
        return findings

    def list_findings(
        self, severity: str | None = None, since: float | None = None
    ) -> list[Finding]:
        """Cross-session findings feed, newest first, optionally filtered."""
        query = "SELECT * FROM findings"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        rows = self._conn.execute(query + " ORDER BY created_at DESC", params).fetchall()
        return [Finding(**{k: r[k] for k in r.keys()}) for r in rows]
