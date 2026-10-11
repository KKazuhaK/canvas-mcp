"""Database defaults, atomic configuration saves and public name boundaries."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from dbbackend import IS_POSTGRES, pg_database
from sqlalchemy import bindparam, text

from canvas_mcp.core.selfhost.db.engine import Database
from canvas_mcp.core.selfhost.db.migrations import baseline_v1
from canvas_mcp.core.selfhost.db.migrations.connections import sqlite_migration
from canvas_mcp.core.selfhost.db.settings_repo import (
    SettingsAccessDenied,
    SettingsConflict,
    read_settings,
    save_setting,
)
from canvas_mcp.core.selfhost.db.types import JsonDoc, new_id
from canvas_mcp.core.selfhost.server_settings import (
    SETTINGS,
    provider_display_name,
    validate_provider_names,
    validate_setting,
)


@pytest.fixture
def db(tmp_path):
    db = (
        pg_database(tmp_path / "settings")
        if IS_POSTGRES
        else Database.sqlite(tmp_path / "settings.sqlite3")
    )
    db.prepare_storage()
    transaction = db.write if IS_POSTGRES else lambda: sqlite_migration(db)
    with transaction() as conn:
        baseline_v1.create(conn, now=100)
    try:
        yield db
    finally:
        db.dispose()


def test_defaults_do_not_create_rows_or_feature_any_school(db):
    with db.read() as conn:
        settings = read_settings(conn)
        assert dict(settings.values) == {
            key: spec.default for key, spec in SETTINGS.items()
        }
        assert settings["schools.directory_search"] is True
        assert conn.execute(text("SELECT count(*) FROM settings")).scalar_one() == 0
        assert (
            conn.execute(text("SELECT count(*) FROM canvas_schools")).scalar_one() == 0
        )
        with pytest.raises(TypeError):
            settings.values["schools.directory_search"] = False


@pytest.mark.parametrize(
    "key,value",
    [
        ("schools.directory_search", 1),
        ("schools.directory_search", "true"),
        ("retention.auth_events_days", True),
        ("retention.auth_events_days", 6),
        ("retention.auth_events_days", 3651),
        ("retention.audit_days", -1),
        ("retention.audit_days", 3651),
        ("unknown", False),
    ],
)
def test_invalid_types_and_ranges_are_refused(key, value):
    with pytest.raises(ValueError):
        validate_setting(key, value)


@pytest.mark.parametrize(
    "value",
    [
        "line\nbreak",
        "tab\tname",
        "zero\u200bwidth",
        "bidi\u202ename",
        "private\ue000",
        "surrogate\ud800",
        "line\u2028separator",
        "para\u2029separator",
        "<name>",
        "{name}",
        "!!!",
        " " * 4,
        "A" * 41,
        123,
        False,
    ],
)
def test_provider_name_rejects_hidden_characters_and_markup(value):
    with pytest.raises(ValueError):
        provider_display_name(value)


def test_provider_name_normalizes_and_checks_effective_names():
    assert provider_display_name('  Cafe\u0301\u00a0  & "B"  ') == 'Café & "B"'
    assert provider_display_name("") is None
    assert provider_display_name(None) is None
    defaults = {"entra": "Microsoft", "google": "Google"}
    assert validate_provider_names(defaults, {}, {"entra": "Staff"}) == {
        "entra": "Staff",
        "google": None,
    }
    with pytest.raises(ValueError, match="unique"):
        validate_provider_names(defaults, {}, {"entra": "GOOGLE"})
    with pytest.raises(ValueError, match="configured"):
        validate_provider_names(defaults, {}, {"github": "GitHub"})


def test_operator_save_reset_and_audit_are_atomic(db):
    with db.write() as conn:
        assert (
            save_setting(
                conn,
                "schools.directory_search",
                False,
                expected_revision=0,
                now=101,
                actor_id=None,
            )
            == 1
        )
    with db.read() as conn:
        assert read_settings(conn)["schools.directory_search"] is False
        audit = (
            conn.execute(
                text("SELECT actor_kind,actor_id,detail FROM audit_log").columns(
                    detail=JsonDoc()
                )
            )
            .mappings()
            .one()
        )
        assert dict(audit) == {
            "actor_kind": "operator",
            "actor_id": None,
            "detail": {"old": True, "new": False},
        }
    with db.write() as conn:
        assert (
            save_setting(
                conn,
                "schools.directory_search",
                None,
                reset=True,
                expected_revision=1,
                now=102,
                actor_id=None,
            )
            == 2
        )
    with db.read() as conn:
        assert read_settings(conn)["schools.directory_search"] is True
        assert conn.execute(text("SELECT count(*) FROM settings")).scalar_one() == 0
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 2
    with pytest.raises(RuntimeError):
        with db.write() as conn:
            save_setting(
                conn,
                "schools.directory_search",
                False,
                expected_revision=2,
                now=103,
                actor_id=None,
            )
            raise RuntimeError("abort whole save")
    with db.read() as conn:
        assert (
            conn.execute(
                text("SELECT settings_revision FROM server_state")
            ).scalar_one()
            == 2
        )
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 2


def test_owner_standing_is_rechecked_and_refusals_leave_no_audit(db):
    owner = new_id()
    with db.write() as conn:
        conn.execute(
            text(
                "INSERT INTO accounts (id,status,role,admitted_via,created_at,updated_at) VALUES (:id,'active','owner','operator',100,100)"
            ),
            {"id": owner},
        )
    with db.write() as conn:
        save_setting(
            conn,
            "schools.directory_search",
            False,
            expected_revision=0,
            now=101,
            actor_id=owner,
        )
    with pytest.raises(ValueError, match="operator-only"):
        with db.write() as conn:
            save_setting(
                conn,
                "retention.audit_days",
                7,
                expected_revision=1,
                now=102,
                actor_id=owner,
            )
    with db.write() as conn:
        conn.execute(
            text("UPDATE accounts SET status='disabled',disabled_at=102 WHERE id=:id"),
            {"id": owner},
        )
    with pytest.raises(SettingsAccessDenied):
        with db.write() as conn:
            save_setting(
                conn,
                "schools.directory_search",
                True,
                expected_revision=1,
                now=103,
                actor_id=owner,
            )
    with db.read() as conn:
        assert (
            conn.execute(
                text("SELECT settings_revision FROM server_state")
            ).scalar_one()
            == 1
        )
        assert conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 1


def test_global_cas_serializes_different_saves_from_two_instances(db, tmp_path):
    other = pg_database(tmp_path / "settings") if IS_POSTGRES else Database(db.target)
    barrier = Barrier(2)

    def save(database, key, value):
        barrier.wait(timeout=3)
        try:
            with database.write() as conn:
                save_setting(
                    conn, key, value, expected_revision=0, now=101, actor_id=None
                )
            return "saved"
        except SettingsConflict:
            return "conflict"

    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            a = workers.submit(save, db, "schools.directory_search", False)
            b = workers.submit(save, other, "retention.audit_days", 30)
            assert sorted([a.result(timeout=6), b.result(timeout=6)]) == [
                "conflict",
                "saved",
            ]
        with other.read() as conn:
            assert (
                conn.execute(
                    text("SELECT settings_revision FROM server_state")
                ).scalar_one()
                == 1
            )
            assert conn.execute(text("SELECT count(*) FROM settings")).scalar_one() == 1
            assert (
                conn.execute(text("SELECT count(*) FROM audit_log")).scalar_one() == 1
            )
    finally:
        other.dispose()


def test_invalid_known_setting_fails_closed_but_newer_unknown_key_is_ignored(
    db, caplog
):
    statement = text(
        "INSERT INTO settings(key,value,updated_at) VALUES(:key,:value,100)"
    ).bindparams(bindparam("value", type_=JsonDoc()))
    with db.write() as conn:
        conn.execute(statement, {"key": "future.secret", "value": "do-not-log-this"})
    with db.read() as conn:
        assert read_settings(conn)["schools.directory_search"] is True
    assert "unknown server setting" in caplog.text
    assert "future.secret" not in caplog.text and "do-not-log-this" not in caplog.text
    with db.write() as conn:
        conn.execute(statement, {"key": "schools.directory_search", "value": 1})
    with db.read() as conn, pytest.raises(ValueError):
        read_settings(conn)
