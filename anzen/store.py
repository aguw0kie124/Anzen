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
    unknown = "unknown"


class Session(BaseModel):
    id: str
    agent_name: str = "unknown-agent"
    started_at: float | None = None
    ended_at: float | None = None
    input_tokens: int = 0
    output_tokens: int = 0
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
    raw_attributes: dict[str, Any] = Field(default_factory=dict)


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
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
-- rule findings are deterministic per (rule, action): lets auto-scan on ingest
-- and manual re-scans coexist without duplicates (INSERT OR IGNORE)
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_rule_unique
    ON findings(session_id, rule_id, action_id) WHERE source = 'rule';
"""


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

    def close(self) -> None:
        self._conn.close()

    # -- sessions ----------------------------------------------------------

    def upsert_session(self, session: Session) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO sessions (id, agent_name, started_at, ended_at, input_tokens, output_tokens)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    agent_name    = CASE WHEN excluded.agent_name != 'unknown-agent'
                                         THEN excluded.agent_name ELSE sessions.agent_name END,
                    started_at    = MIN(COALESCE(sessions.started_at, excluded.started_at), excluded.started_at),
                    ended_at      = MAX(COALESCE(sessions.ended_at, excluded.ended_at), excluded.ended_at),
                    input_tokens  = sessions.input_tokens + excluded.input_tokens,
                    output_tokens = sessions.output_tokens + excluded.output_tokens
                """,
                (
                    session.id,
                    session.agent_name,
                    session.started_at,
                    session.ended_at,
                    session.input_tokens,
                    session.output_tokens,
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
                    (session_id, span_id, timestamp, action_type, name, input, output, status, raw_attributes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(action.raw_attributes, sort_keys=True, default=str),
                ),
            )
            return cur.lastrowid if cur.rowcount else None

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
        findings = [Finding(**{k: r[k] for k in r.keys() if k != "created_at"}) for r in rows]
        findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
        return findings
