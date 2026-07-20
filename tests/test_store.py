"""Store extensions: migrations, identity columns, endpoints, inventory, findings feed."""

import sqlite3

from anzen.store import Action, ActionType, Endpoint, Finding, InventoryItem, Session, Store


def test_migration_upgrades_old_database(tmp_path):
    """A pre-extension database gains the new columns on open, keeping its data."""
    path = str(tmp_path / "old.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            agent_name TEXT NOT NULL DEFAULT 'unknown-agent',
            started_at REAL, ended_at REAL,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES sessions(id),
            span_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            action_type TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            input TEXT NOT NULL DEFAULT '',
            output TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'ok',
            raw_attributes TEXT NOT NULL DEFAULT '{}',
            UNIQUE(session_id, span_id)
        );
        INSERT INTO sessions (id) VALUES ('legacy');
        """
    )
    conn.commit()
    conn.close()

    store = Store(path)  # opening migrates
    session = store.get_session("legacy")
    assert session is not None
    assert session.user_email == ""  # new column, defaulted

    # migration is idempotent
    store.close()
    Store(path).close()


def test_session_identity_merge(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    store.upsert_session(Session(id="s1", agent_name="claude-code", user_email="a@co.com", cost_usd=0.5))
    store.upsert_session(Session(id="s1", hostname="mbp.local", cost_usd=0.25))  # later delivery

    s = store.get_session("s1")
    assert s.user_email == "a@co.com"  # empty later value didn't clobber
    assert s.hostname == "mbp.local"
    assert s.cost_usd == 0.75  # accrues
    store.close()


def test_action_permission_fields_roundtrip(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    store.upsert_session(Session(id="s1"))
    store.insert_action(Action(
        session_id="s1", span_id="sp1", timestamp=1.0,
        action_type=ActionType.tool_call, name="Bash",
        prompt_id="p-1", tool_use_id="tu-1",
        decision="accept", decision_source="config",
        duration_ms=12.5,
    ))
    a = store.get_actions("s1")[0]
    assert (a.prompt_id, a.tool_use_id) == ("p-1", "tu-1")
    assert (a.decision, a.decision_source) == ("accept", "config")
    assert a.duration_ms == 12.5
    store.close()


def test_endpoint_upsert_and_session_count(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    ep = Endpoint(agent_type="claude-code", user_email="a@co.com", hostname="mbp.local",
                  first_seen=100.0, last_seen=100.0)
    store.upsert_endpoint(ep)
    store.upsert_endpoint(Endpoint(
        agent_type="claude-code", user_email="a@co.com", hostname="mbp.local",
        first_seen=200.0, last_seen=200.0, permission_mode_latest="bypassPermissions",
    ))
    store.upsert_session(Session(id="s1", agent_name="claude-code",
                                 user_email="a@co.com", hostname="mbp.local"))

    endpoints = store.list_endpoints()
    assert len(endpoints) == 1
    e = endpoints[0]
    assert e.first_seen == 100.0 and e.last_seen == 200.0
    assert e.permission_mode_latest == "bypassPermissions"
    assert e.session_count == 1
    store.close()


def test_inventory_merges_users_and_preserves_approval(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    store.upsert_inventory_item(InventoryItem(
        kind="mcp_server", name="github", transport="stdio",
        first_seen=10.0, last_seen=10.0, user_emails=["a@co.com"], status="connected",
    ))
    [item] = store.list_inventory()
    assert item.approved is None  # unreviewed by default
    store.set_inventory_approval(item.id, True)

    # a second sighting from another user must not reset the review
    store.upsert_inventory_item(InventoryItem(
        kind="mcp_server", name="github",
        first_seen=20.0, last_seen=20.0, user_emails=["b@co.com"],
    ))
    [item] = store.list_inventory(kind="mcp_server")
    assert item.approved is True
    assert item.user_emails == ["a@co.com", "b@co.com"]
    assert item.endpoint_count == 2
    assert item.first_seen == 10.0 and item.last_seen == 20.0
    assert item.transport == "stdio"  # empty later value didn't clobber
    store.close()


def test_list_findings_filters(tmp_path):
    store = Store(str(tmp_path / "a.db"))
    store.upsert_session(Session(id="s1"))
    store.upsert_session(Session(id="s2"))
    base = dict(rule_id="R", owasp_llm="", title="t", explanation="e" * 10, remediation="r" * 10)
    store.add_findings([
        Finding(session_id="s1", severity="high", **base),
        Finding(session_id="s2", severity="low", **{**base, "rule_id": "R2"}),
    ])

    assert len(store.list_findings()) == 2
    high = store.list_findings(severity="high")
    assert [f.session_id for f in high] == ["s1"]
    assert high[0].created_at is not None
    assert store.list_findings(since=high[0].created_at + 1) == []
    store.close()
