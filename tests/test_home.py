"""Home directory resolution and status stats."""

from anzen.store import Action, ActionType, Finding, Session, Store, anzen_home, default_db


def test_anzen_home_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ANZEN_HOME", str(tmp_path / "custom-home"))
    home = anzen_home()
    assert home == tmp_path / "custom-home"
    assert home.is_dir()  # created on demand
    assert default_db() == str(home / "anzen.db")


def test_stats_counts(tmp_path):
    store = Store(str(tmp_path / "s.db"))
    store.upsert_session(Session(id="s1", started_at=1.0, ended_at=2.0))
    store.insert_action(Action(session_id="s1", span_id="a", timestamp=1.0,
                               action_type=ActionType.tool_call, name="Bash"))
    store.insert_action(Action(session_id="s1", span_id="b", timestamp=2.0,
                               action_type=ActionType.tool_call, name="Read"))
    store.replace_findings("s1", "rule", [
        Finding(session_id="s1", rule_id="X-1", severity="critical",
                title="t", explanation="e" * 10, remediation="r" * 10),
        Finding(session_id="s1", rule_id="X-2", severity="medium",
                title="t", explanation="e" * 10, remediation="r" * 10),
    ])
    stats = store.stats()
    assert stats["sessions"] == 1
    assert stats["actions"] == 2
    assert stats["last_action_at"] == 2.0
    assert stats["findings"] == {"critical": 1, "medium": 1}
    store.close()
