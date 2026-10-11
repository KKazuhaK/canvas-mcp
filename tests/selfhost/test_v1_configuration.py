"""Immutable revisions, atomic settings writes and neutral school selection."""

from dataclasses import FrozenInstanceError

import pytest
from sqlalchemy import event, insert, select, update

from canvas_mcp.core.selfhost.config_snapshot import (
    CURRENT_CONFIG,
    ConfigSnapshots,
    school_display_name,
)
from canvas_mcp.core.selfhost.config_store import ConfigStore, SchoolRemovalConfirmation
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.db.repos import SqlProviderRepo
from canvas_mcp.core.selfhost.db.settings_repo import (
    SettingsAccessDenied,
    SettingsConflict,
)
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.login.config import LoginProvidersConfig
from canvas_mcp.core.selfhost.schools import School

from .authz.stack import ALICE, CANVAS_HOST, OWNER, Browser, local_stack
from .test_server_settings import db  # noqa: F401


async def public(host):
    return ["8.8.8.8"]


@pytest.fixture
def stack(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch) as running:
        yield running


@pytest.fixture
def browser(stack):
    return Browser(stack)


@pytest.fixture
def config(db):  # noqa: F811 - imported shared pytest fixture
    with db.write() as conn:
        SqlProviderRepo(db.kind).reconcile(conn, ["entra", "google"], now=100)
    snapshots = ConfigSnapshots(
        db, LoginProvidersConfig(order=("entra", "google")), resolve_host=public
    )
    return snapshots, ConfigStore(snapshots)


def test_neutral_defaults_and_frozen_snapshot(config):
    snapshots, _ = config
    current = snapshots.current
    assert current.schools.featured == () and current.schools.search_enabled
    assert [(p.id, p.effective_name) for p in current.providers] == [
        ("entra", "Microsoft"),
        ("google", "Google"),
    ]
    assert current.schools.sole_school is None
    with pytest.raises(FrozenInstanceError):
        current.revision = 100


def test_warm_revision_reads_nothing_and_miss_rebuilds_three_queries(config):
    snapshots, store = config
    old = snapshots.current
    # Another process commits without calling this process's cache.
    other = ConfigSnapshots(
        snapshots.database, snapshots.providers, resolve_host=public
    )
    revision = ConfigStore(other).names(
        {"entra": "Campus SSO"}, revision=old.revision, actor=None, now=110
    )
    seen = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            seen.append(statement)

    event.listen(snapshots.database.engine, "before_cursor_execute", observe)
    try:
        assert snapshots.get(old.revision) is old and not seen
        fresh = snapshots.get(revision)
        assert len(seen) == 3 and fresh.name("entra") == "Campus SSO"
        seen.clear()
        assert snapshots.get(revision) is fresh and not seen
        assert old.name("entra") == "Microsoft"
    finally:
        event.remove(snapshots.database.engine, "before_cursor_execute", observe)


def test_snapshot_never_combines_settings_from_different_committed_revisions(config):
    snapshots, _ = config
    previous = snapshots.current.revision
    with snapshots.database.write() as conn:
        conn.execute(update(s.server_state).values(settings_revision=previous + 1))
        conn.execute(
            update(s.login_providers)
            .where(s.login_providers.c.id == "entra")
            .values(display_name="First revision")
        )
    changed = False

    def concurrent_commit(conn, cursor, statement, parameters, context, executemany):
        nonlocal changed
        if changed or "LEFT OUTER JOIN settings" not in statement:
            return
        changed = True
        with snapshots.database.write() as writer:
            writer.execute(
                update(s.server_state).values(settings_revision=previous + 2)
            )
            writer.execute(
                update(s.login_providers)
                .where(s.login_providers.c.id == "entra")
                .values(display_name="Second revision")
            )

    event.listen(snapshots.database.engine, "after_cursor_execute", concurrent_commit)
    try:
        fresh = snapshots.get(previous + 1)
        assert changed
        # SQLite's read transaction can retain the first snapshot; PostgreSQL's
        # READ COMMITTED sees the changed revision and must rebuild the bundle.
        assert (fresh.revision, fresh.name("entra")) in {
            (previous + 1, "First revision"),
            (previous + 2, "Second revision"),
        }
        newest = snapshots.get(previous + 2)
        assert newest.name("entra") == "Second revision"
    finally:
        event.remove(
            snapshots.database.engine, "after_cursor_execute", concurrent_commit
        )


def test_failed_refresh_never_serves_stale_and_next_request_retries(config):
    snapshots, _ = config
    old = snapshots.current
    with snapshots.database.write() as conn:
        conn.execute(update(s.server_state).values(settings_revision=old.revision + 1))
        conn.execute(
            insert(s.settings).values(
                key="schools.directory_search", value="true", updated_at=110
            )
        )
    for _ in range(2):
        with pytest.raises(StoreUnavailable):
            snapshots.get(old.revision + 1)
        assert snapshots.current is old
    with snapshots.database.write() as conn:
        conn.execute(update(s.settings).values(value=False))
    assert snapshots.get(old.revision + 1).warnings == ("no_schools_offered",)


def test_cas_conflict_rolls_back_names_and_audit(config):
    snapshots, store = config
    revision = snapshots.current.revision
    new = store.names({"entra": "Campus Login"}, revision=revision, actor=None, now=110)
    with pytest.raises(SettingsConflict):
        store.names({"entra": "Lost update"}, revision=revision, actor=None, now=120)
    with snapshots.database.read() as conn:
        assert conn.execute(select(s.audit_log.c.action)).scalars().all() == [
            "sign_in_method_renamed"
        ]
    assert snapshots.get(new).name("entra") == "Campus Login"


def test_effective_name_collision_aborts_every_change(config):
    snapshots, store = config
    revision = snapshots.current.revision
    with pytest.raises(ValueError):
        store.names({"entra": "google"}, revision=revision, actor=None, now=110)
    assert snapshots.revision() == revision
    with snapshots.database.read() as conn:
        assert conn.execute(select(s.audit_log.c.id)).first() is None


def test_owner_is_checked_inside_governance_transaction(config):
    snapshots, store = config
    account = new_id()
    with snapshots.database.write() as conn:
        conn.execute(
            insert(s.accounts).values(
                id=account,
                status="active",
                role="user",
                admitted_via="operator",
                created_at=100,
                updated_at=100,
            )
        )
    with pytest.raises(SettingsAccessDenied):
        store.names(
            {"entra": "Campus"},
            revision=snapshots.current.revision,
            actor=account,
            now=110,
        )
    assert snapshots.current.name("entra") == "Microsoft"


def test_provider_reconciliation_preserves_names_but_updates_order(config):
    snapshots, store = config
    store.names(
        {"entra": "Campus"}, revision=snapshots.current.revision, actor=None, now=110
    )
    with snapshots.database.write() as conn:
        SqlProviderRepo(snapshots.database.kind).reconcile(
            conn, ["google", "entra"], now=120
        )
    fresh = snapshots.get(snapshots.revision())
    assert [p.id for p in fresh.providers] == ["google", "entra"]
    assert fresh.name("entra") == "Campus"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addresses,reason",
    [
        (["127.0.0.1"], "school_address_blocked"),
        (["8.8.8.8", "10.0.0.1"], "school_address_blocked"),
        ([], "school_unresolvable"),
    ],
)
async def test_school_validation_refuses_every_nonpublic_answer(
    config, addresses, reason
):
    snapshots, store = config

    async def resolve(host):
        return addresses

    snapshots.resolve_host = resolve
    with pytest.raises(ValueError, match=reason):
        await store.validate_school("school.example.edu", "School")


def test_private_exception_is_operator_only_and_survives_unfeaturing(config):
    snapshots, store = config
    revision = store.allow_private(
        "canvas.internal", True, revision=snapshots.current.revision, now=110
    )
    revision = store.setting(
        "schools.directory_search", False, revision=revision, actor=None, now=120
    )
    assert (
        snapshots.get(revision).schools.resolve_stored("canvas.internal").allow_private
    )
    assert snapshots.get(revision).schools.resolve_stored("other.internal") is None
    revision, _ = store.schools([], revision=revision, actor=None, now=130)
    assert snapshots.get(revision).schools.resolve_stored("canvas.internal") is not None


def test_feature_removal_requires_affected_enrollment_confirmation(config):
    snapshots, store = config
    school = School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "Example")
    revision, _ = store.schools(
        [school], revision=snapshots.current.revision, actor=None, now=110
    )
    revision = store.setting(
        "schools.directory_search", False, revision=revision, actor=None, now=120
    )
    with snapshots.database.write() as conn:
        account = new_id()
        conn.execute(
            insert(s.accounts).values(
                id=account,
                status="active",
                admitted_via="operator",
                created_at=100,
                updated_at=100,
            )
        )
        conn.execute(
            insert(s.canvas_credentials).values(
                id=new_id(),
                account_id=account,
                canvas_host=CANVAS_HOST,
                kind="pat",
                is_primary=True,
                generation=0,
                key_id="test",
                nonce=bytes(12),
                ciphertext=bytes(17),
                canvas_user_id="1",
                canvas_user_name="Example",
                created_at=100,
                updated_at=100,
                custody_notice_version=1,
                custody_ack_at=100,
            )
        )
    with pytest.raises(SchoolRemovalConfirmation) as caught:
        store.schools([], revision=revision, actor=None, now=130)
    assert caught.value.affected == {CANVAS_HOST: 1}
    assert snapshots.revision() == revision
    new, affected = store.schools(
        [], revision=revision, actor=None, now=140, confirmed=[CANVAS_HOST]
    )
    assert (
        affected == {CANVAS_HOST: 1}
        and snapshots.get(new).schools.resolve_stored(CANVAS_HOST) is None
    )
    with snapshots.database.read() as conn:
        assert conn.execute(select(s.canvas_credentials.c.id)).first() is not None


def test_session_uses_one_authoritative_query_and_leaves_no_context(stack, browser):
    from .authz.test_mcp_hot_read import statements

    browser.sign_in(ALICE)
    with statements(stack) as seen:
        response = browser.api("GET", "/me/schools")
    assert response.status_code == 200
    assert response.json()["selected"] is None
    assert sum("FROM accounts a CROSS JOIN server_state" in sql for sql in seen) == 1
    assert len(seen) == 2  # session snapshot + primary credential display
    assert CURRENT_CONFIG.get() is None


def test_public_provider_changes_and_mcp_school_removal_are_immediate(stack, browser):
    stack.runtime.snapshots.resolve_host = public
    account = stack.enroll(ALICE)
    _, tokens = stack.tokens_for(ALICE)
    browser.sign_in(OWNER)
    csrf = browser.csrf_token()
    current = browser.api("GET", "/admin/settings").json()
    changed = browser.api(
        "PUT",
        "/admin/settings/sign-in-methods",
        body={"revision": current["revision"], "names": {"entra": "Campus Sign In"}},
        csrf=csrf,
    )
    assert changed.status_code == 200, changed.text
    assert (
        browser.api("GET", "/providers").json()["providers"][0]["name"]
        == "Campus Sign In"
    )
    # Fail before decryption; changing offered schools doesn't destroy credentials.
    changed = browser.api(
        "PUT",
        "/admin/settings/directory-search",
        body={"revision": changed.json()["revision"], "enabled": False},
        csrf=csrf,
    )
    assert changed.status_code == 200, changed.text
    response = stack.rpc(
        tokens["access_token"], "tools/call", {"name": "list_courses", "arguments": {}}
    )
    assert response.status_code == 200
    assert stack.store.info(account) is not None
    assert CANVAS_HOST not in response.text and account not in response.text


@pytest.mark.parametrize(
    "body",
    [
        {"revision": True, "names": {"entra": "Changed"}},
        {"revision": 1, "names": {"entra": "Changed"}, "extra": True},
    ],
)
def test_settings_api_rejects_bad_closed_body(stack, browser, body):
    browser.sign_in(OWNER)
    response = browser.api(
        "PUT", "/admin/settings/sign-in-methods", body=body, csrf=browser.csrf_token()
    )
    assert response.status_code == 422


def test_settings_api_owner_freshness_origin_csrf_and_conflict(stack, browser):
    browser.sign_in(ALICE)
    assert browser.api("GET", "/admin/settings").status_code == 403
    browser.sign_in(OWNER)
    csrf = browser.csrf_token()
    revision = browser.api("GET", "/admin/settings").json()["revision"]
    body = {"revision": revision, "enabled": False}
    assert (
        browser.api("PUT", "/admin/settings/directory-search", body=body).status_code
        == 403
    )
    assert (
        browser.api(
            "PUT",
            "/admin/settings/directory-search",
            body=body,
            csrf=csrf,
            **{"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        browser.api(
            "PUT", "/admin/settings/directory-search", body=body, csrf=csrf
        ).status_code
        == 200
    )
    assert (
        browser.api(
            "PUT", "/admin/settings/directory-search", body=body, csrf=csrf
        ).json()["error"]["code"]
        == "settings_conflict"
    )
    stack.clock.advance(601)
    assert (
        browser.api("GET", "/admin/settings").json()["error"]["code"]
        == "reauth_required"
    )


def test_cli_uses_governed_repositories_for_names_retention_and_private_schools(
    config, monkeypatch, capsys
):
    import base64

    from canvas_mcp.core.selfhost import config_cli, token_admin
    from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore

    snapshots, _ = config
    store = TokenStore(
        snapshots.database, Keyring.parse("k1:" + base64.b64encode(bytes(32)).decode())
    )
    monkeypatch.setattr(token_admin, "_open_store", lambda: store)
    monkeypatch.setattr(config_cli, "snapshots_for", lambda store: snapshots)
    assert token_admin.main(["providers", "rename", "entra", "Campus CLI"]) == 0
    assert token_admin.main(["providers", "list"]) == 0
    assert "Campus CLI" in capsys.readouterr().out
    assert token_admin.main(["providers", "reset-name", "entra"]) == 0
    assert snapshots.current.name("entra") == "Microsoft"
    assert (
        token_admin.main(["settings", "set", "retention.auth_events_days", "180"]) == 0
    )
    assert snapshots.current.settings["retention.auth_events_days"] == 180
    assert (
        token_admin.main(["settings", "set", "retention.auth_events_days", "true"])
        == token_admin.EXIT_CONFIG
    )
    assert snapshots.current.settings["retention.auth_events_days"] == 180
    assert token_admin.main(["settings", "reset", "retention.auth_events_days"]) == 0
    assert snapshots.current.settings["retention.auth_events_days"] == 90
    assert (
        token_admin.main(
            [
                "schools",
                "add",
                "canvas.internal",
                "--name",
                "Local School",
                "--allow-private",
            ]
        )
        == 0
    )
    assert (
        token_admin.main(["schools", "rename", "canvas.internal", "Renamed School"])
        == 0
    )
    assert token_admin.main(["schools", "list"]) == 0
    assert "Renamed School" in capsys.readouterr().out
    assert token_admin.main(["schools", "remove", "canvas.internal"]) == 0
    assert token_admin.main(["schools", "allow-private", "canvas.internal", "off"]) == 0
    assert snapshots.current.schools.resolve_stored("canvas.internal") is None
    with snapshots.database.read() as conn:
        assert set(conn.execute(select(s.audit_log.c.actor_kind)).scalars()) == {
            "operator"
        }
        assert {
            "setting_changed",
            "school_access_changed",
            "featured_schools_changed",
            "sign_in_method_renamed",
        } <= set(conn.execute(select(s.audit_log.c.action)).scalars())


def test_school_name_round_trip_preserves_empty_and_hostname_display_names(config):
    snapshots, store = config
    host = "school.example.edu"
    new, _ = store.schools(
        [School(host, f"https://{host}/api/v1", "")],
        revision=snapshots.current.revision,
        actor=None,
        now=110,
    )
    assert snapshots.get(new).schools.featured[0].name == ""
    new, _ = store.schools(
        [School(host, f"https://{host}/api/v1", host)],
        revision=new,
        actor=None,
        now=120,
    )
    assert snapshots.get(new).schools.featured[0].name == host


@pytest.mark.parametrize(
    "name", ["School\n", "\tSchool", "Zero\u200bwidth", "bidi\u202e", "A" * 121]
)
def test_school_names_refuse_controls_before_trimming(name):
    with pytest.raises(ValueError):
        school_display_name(name)


def test_school_api_rechecks_owner_after_dns_and_never_writes_on_refusal(
    stack, browser
):
    browser.sign_in(OWNER)
    owner = stack.account_of(OWNER)
    csrf = browser.csrf_token()
    revision = browser.api("GET", "/admin/settings").json()["revision"]

    async def owner_lost(host):
        with stack.store.database.write() as conn:
            conn.execute(
                update(s.accounts).where(s.accounts.c.id == owner).values(role="user")
            )
        return ["8.8.8.8"]

    stack.runtime.snapshots.resolve_host = owner_lost
    response = browser.api(
        "PUT",
        "/admin/settings/schools",
        body={
            "revision": revision,
            "featured": [{"host": CANVAS_HOST, "display_name": ""}],
            "confirm_affected": [],
        },
        csrf=csrf,
    )
    assert response.status_code == 403, response.text
    assert stack.runtime.snapshots.revision() == revision
    with stack.store.database.read() as conn:
        assert conn.execute(select(s.canvas_schools.c.host)).first() is None


def test_school_api_keeps_private_exceptions_readonly_and_settings_body_bounded(
    stack, browser
):
    browser.sign_in(OWNER)
    csrf = browser.csrf_token()
    revision = browser.api("GET", "/admin/settings").json()["revision"]
    response = browser.api(
        "PUT",
        "/admin/settings/schools",
        body={
            "revision": revision,
            "featured": [
                {
                    "host": "canvas.internal",
                    "display_name": "Private",
                    "allow_private": True,
                }
            ],
            "confirm_affected": [],
        },
        csrf=csrf,
    )
    assert response.status_code == 422
    response = browser.api(
        "PUT",
        "/admin/settings/sign-in-methods",
        body={"revision": revision, "names": {"entra": "A" * 9000}},
        csrf=csrf,
    )
    assert response.status_code == 413
    assert stack.runtime.snapshots.revision() == revision


def test_other_instance_school_policy_is_applied_before_decrypt_and_restores_access(
    stack, monkeypatch
):
    from canvas_mcp.core.selfhost.maintenance import MaintenanceScheduler

    from .authz.test_mcp_hot_read import payload, statements

    # This observer measures foreground SQL only; housekeeping has its own runner tests.
    monkeypatch.setattr(MaintenanceScheduler, "schedule", lambda *args, **kwargs: None)

    account = stack.enroll(ALICE)
    _, tokens = stack.tokens_for(ALICE)
    assert stack.mcp_status(tokens["access_token"]) == 200
    root = stack.runtime.snapshots
    other = ConfigSnapshots(
        stack.store.database, stack.settings.login_providers, resolve_host=public
    )
    config = ConfigStore(other)
    old = root.current.revision
    revision = config.setting(
        "schools.directory_search",
        False,
        revision=old,
        actor=None,
        now=int(stack.clock()),
    )
    assert root.current.revision == old  # no in-process invalidation hook
    decrypt = stack.store.decrypt_snapshot

    def forbidden(*args):
        pytest.fail("a school removed by another instance must fail before decryption")

    monkeypatch.setattr(stack.store, "decrypt_snapshot", forbidden)
    with statements(stack) as seen:
        result = payload(
            stack.rpc(
                tokens["access_token"],
                "tools/call",
                {"name": "list_courses", "arguments": {}},
            )
        )
    assert result["isError"] and "school is no longer offered" in str(result)
    assert CANVAS_HOST not in str(result) and account not in str(result)
    assert len(seen) == 4  # authoritative hot read, then three snapshot reads
    assert root.current.revision == revision
    school = School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "")
    revision, _ = config.schools(
        [school], revision=revision, actor=None, now=int(stack.clock())
    )
    root.resolve_host = public
    monkeypatch.setattr(stack.store, "decrypt_snapshot", decrypt)
    assert stack.mcp_status(tokens["access_token"]) == 200
    assert root.current.revision == revision
    with statements(stack) as seen:
        assert stack.mcp_status(tokens["access_token"]) == 200
    assert len(seen) == 1


def test_pilot_config_writes_are_atomic_and_out_of_process_changes_fail_closed(config):
    from canvas_mcp.core.selfhost.profile import PilotProfileViolation

    snapshots, store = config
    revision = snapshots.current.revision
    school = School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "")
    revision, _ = store.schools([school], revision=revision, actor=None, now=110)
    revision = store.setting(
        "schools.directory_search", False, revision=revision, actor=None, now=120
    )
    snapshots.enable_pilot()
    for reset in (False, True):
        with pytest.raises(PilotProfileViolation):
            store.setting(
                "schools.directory_search",
                True,
                revision=revision,
                actor=None,
                now=130,
                reset=reset,
            )
        assert snapshots.revision() == revision
    for schools in (
        [],
        [school, School("other.example.edu", "https://other.example.edu/api/v1", "")],
    ):
        with pytest.raises(PilotProfileViolation):
            store.schools(schools, revision=revision, actor=None, now=130)
        assert snapshots.revision() == revision
    other = ConfigSnapshots(
        snapshots.database, snapshots.providers, resolve_host=public
    )
    changed = ConfigStore(other).setting(
        "schools.directory_search", True, revision=revision, actor=None, now=140
    )
    with pytest.raises(StoreUnavailable):
        snapshots.get(changed)
    assert snapshots.current.revision == revision


def test_pilot_settings_api_returns_a_specific_refusal(stack, browser):
    browser.sign_in(OWNER)
    snapshots = stack.runtime.snapshots
    store = ConfigStore(snapshots)
    revision = snapshots.current.revision
    snapshots.resolve_host = public
    revision, _ = store.schools(
        [School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "")],
        revision=revision,
        actor=None,
        now=int(stack.clock()),
    )
    revision = store.setting(
        "schools.directory_search",
        False,
        revision=revision,
        actor=None,
        now=int(stack.clock()),
    )
    snapshots.enable_pilot()
    response = browser.api(
        "PUT",
        "/admin/settings/directory-search",
        body={"revision": revision, "enabled": True},
        csrf=browser.csrf_token(),
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "pilot_profile_restricted"
    assert snapshots.revision() == revision


def test_pilot_cli_refuses_enabling_search_reset_and_second_school(
    config, monkeypatch, capsys
):
    import base64

    from canvas_mcp.core.selfhost import config_cli, token_admin
    from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore

    snapshots, config_store = config
    revision, _ = config_store.schools(
        [School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "")],
        revision=snapshots.current.revision,
        actor=None,
        now=110,
    )
    revision = config_store.setting(
        "schools.directory_search", False, revision=revision, actor=None, now=120
    )
    store = TokenStore(
        snapshots.database, Keyring.parse("k1:" + base64.b64encode(bytes(32)).decode())
    )
    monkeypatch.setattr(token_admin, "_open_store", lambda: store)
    monkeypatch.setattr(config_cli, "snapshots_for", lambda store: snapshots)
    monkeypatch.setenv("SELFHOST_PROFILE", "pilot")
    for arguments in (
        ["settings", "set", "schools.directory_search", "true"],
        ["settings", "reset", "schools.directory_search"],
        ["schools", "add", "other.example.edu", "--name", "Other School"],
        ["schools", "remove", CANVAS_HOST],
    ):
        assert token_admin.main(arguments) == token_admin.EXIT_CONFIG
        assert snapshots.revision() == revision
        assert "SELFHOST_PROFILE" in capsys.readouterr().err
