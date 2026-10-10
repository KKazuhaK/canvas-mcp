"""Every action of the HTML pages has an API equivalent, and both do the same thing.

Two checks keep the surfaces from drifting:

* a route matrix: each (method, path) of the legacy page application maps to the API
  routes that replace it, and every API route is accounted for;
* a scenario table: the same sequence of actions is run once through the HTML forms
  and once through the JSON API on fresh, identical servers, and the stored state, the
  audit rows, the audit log lines and the rate-limit consumption must be identical.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.selfhost import account_api
from canvas_mcp.core.selfhost.account_web import (
    CanvasCheckError,
    CanvasIdentity,
    _AccountApp,
    build_account_app,
)
from canvas_mcp.core.selfhost.tool_prefs import ToolPrefsCache, WriteToolCatalog

from .conftest import acct_key
from .test_account_api import (
    APPROVAL,
    CEILING,
    NEW_TOKEN,
    OID_BLOCKED,
    OID_PENDING,
    REGISTERED,
    Api,
    _LazySource,
    make,
    seed_people,
    sign_in_owner,
)
from .test_account_web import (
    BASE,
    CANVAS_TOKEN,
    KEY,
    KEY_2,
    KEY_OWNER,
    OID,
    OID_2,
    Harness,
    _display_in_utc,  # noqa: F401 - autouse fixture: timestamps render in UTC
    build_harness,
    csrf_of,
    make_cfg,
    post_form,
    put_row,
    sign_in,
)

P = "/account/api"

#: Where each legacy (method, path) went. ``None`` marks the two server-side halves of
#: the sign-in, which are the same routes in both modes.
LEGACY_TO_API: dict[tuple[str, str], list[tuple[str, str]] | None] = {
    ("GET", "/account"): [("GET", f"{P}/providers"), ("GET", f"{P}/me")],
    ("GET", "/account/login"): None,
    ("GET", "/account/callback"): None,
    ("POST", "/account/token"): [("PUT", f"{P}/me/canvas-token")],
    ("POST", "/account/token/delete"): [("DELETE", f"{P}/me/canvas-token")],
    ("POST", "/account/token/recheck"): [("POST", f"{P}/me/canvas-token/recheck")],
    ("POST", "/account/logout"): [("POST", f"{P}/session/logout")],
    ("GET", "/account/admin"): [
        ("GET", f"{P}/admin/enrollments"),
        ("GET", f"{P}/admin/accounts"),
    ],
    ("POST", "/account/admin/remove"): [("DELETE", f"{P}/admin/enrollments/{{id}}")],
    ("POST", "/account/admin/disable"): [("POST", f"{P}/admin/accounts/{{id}}/disable")],
    ("POST", "/account/admin/enable"): [("POST", f"{P}/admin/accounts/{{id}}/enable")],
    ("POST", "/account/admin/invalidate"): [
        ("POST", f"{P}/admin/enrollments/{{id}}/mark-invalid")
    ],
    ("POST", "/account/admin/approve"): [("POST", f"{P}/admin/accounts/{{id}}/approve")],
    ("POST", "/account/admin/deny"): [("POST", f"{P}/admin/accounts/{{id}}/deny")],
    ("GET", "/account/admin/audit"): [("GET", f"{P}/admin/audit")],
    ("GET", "/account/schools"): [("GET", f"{P}/me/schools/search")],
    ("POST", "/account/write-tools"): [
        ("PUT", f"{P}/me/write-tools"),
        ("DELETE", f"{P}/me/write-tools"),
    ],
}

#: The routes of the local authorization server (``SELFHOST_AUTH_MODE=local``): the legacy
#: pages register them only then, and the API answers ``not_found`` for them otherwise.
#: ``tests/selfhost/authz/test_account_api_authz.py`` checks this table against a local-mode app.
LOCAL_LEGACY_TO_API: dict[tuple[str, str], list[tuple[str, str]]] = {
    ("GET", "/account/consent"): [("GET", f"{P}/consent/{{id}}")],
    ("POST", "/account/consent"): [("POST", f"{P}/consent/{{id}}")],
    ("POST", "/account/grants/revoke"): [("DELETE", f"{P}/me/grants/{{id}}")],
    ("POST", "/account/admin/grants/revoke"): [
        ("DELETE", f"{P}/admin/grants/{{id}}"),
    ],
}

#: API routes that read what the pages render inline (no legacy route of their own).
READ_MODELS = {
    ("GET", f"{P}/me/canvas-token"),
    ("GET", f"{P}/me/schools"),
    ("GET", f"{P}/me/write-tools"),
    ("GET", f"{P}/me/login-history"),
    ("PUT", f"{P}/me/ui-locale"),  # the ?lang= toggle of the pages
    ("GET", f"{P}/me/grants"),  # the "Connected apps" card of GET /account (local mode)
    ("GET", f"{P}/admin/accounts/{{id}}/grants"),  # the per-account block of the admin page
}


def legacy_app(tmp_path: pathlib.Path) -> _AccountApp:
    h = build_harness(tmp_path)
    return build_account_app(make_cfg(), h.store, h.identity)  # type: ignore[arg-type]


class TestRouteMatrix:
    def test_every_legacy_route_has_an_api_entry(self, tmp_path: pathlib.Path) -> None:
        app = legacy_app(tmp_path)
        legacy = {
            (method, path) for path, handlers in app.route_table() for method in handlers
        }
        assert legacy == set(LEGACY_TO_API), (
            "a legacy route has no entry in LEGACY_TO_API, or the table names a route that "
            f"is gone: {legacy ^ set(LEGACY_TO_API)}"
        )

    def test_every_entry_names_a_registered_api_route(self, tmp_path: pathlib.Path) -> None:
        app = legacy_app(tmp_path)
        registered = account_api.ApiApp(app).route_keys()
        # {id} placeholders are the same text in both tables.
        for legacy, targets in LEGACY_TO_API.items():
            for method, path in targets or []:
                assert (method, path) in registered, (legacy, method, path)

    def test_no_api_route_is_unaccounted_for(self, tmp_path: pathlib.Path) -> None:
        app = legacy_app(tmp_path)
        registered = account_api.ApiApp(app).route_keys()
        mapped = {t for targets in LEGACY_TO_API.values() for t in (targets or [])}
        mapped |= {t for targets in LOCAL_LEGACY_TO_API.values() for t in targets}
        extra = registered - mapped - READ_MODELS
        assert extra == set(), f"API routes with no legacy counterpart or read-model entry: {extra}"
        assert READ_MODELS <= registered

    def test_the_sign_in_halves_stay_in_the_react_mode(self, tmp_path: pathlib.Path) -> None:
        h = build_harness(tmp_path)
        app = build_account_app(make_cfg(), h.store, h.identity, ui="react")  # type: ignore[arg-type]
        paths = {route.path for route in app.routes()}
        assert paths == {"/account/login", "/account/callback"}
        full = build_account_app(make_cfg(), h.store, h.identity)  # type: ignore[arg-type]
        assert {r.path for r in full.routes()} >= paths | {"/account/token", "/account/admin"}

    def test_the_legacy_default_registers_no_api(self, tmp_path: pathlib.Path) -> None:
        from canvas_mcp.core.selfhost.account_web import build_account_routes

        h = build_harness(tmp_path)
        routes = build_account_routes(make_cfg(), h.store, h.identity)  # type: ignore[arg-type]
        assert not [r for r in routes if r.path.startswith("/account/api")]


# -- scenarios ----------------------------------------------------------------------------


@dataclass
class Rig:
    h: Harness
    api: Api
    cache: ToolPrefsCache | None = None

    def form(self, path: str, **fields: str) -> Any:
        return post_form(self.h, path, {"csrf": csrf_of(self.h), **fields})


def build_rig(tmp_path: pathlib.Path, name: str, **kwargs: Any) -> Rig:
    source = _LazySource()
    cache = ToolPrefsCache(source)

    async def listing() -> list[str]:
        return list(REGISTERED)

    h = make(
        tmp_path / name,
        write_tools=WriteToolCatalog(ceiling=CEILING, list_registered=listing),
        tool_prefs=cache,
        **kwargs,
    )
    source.store = h.store
    return Rig(h, Api(h), cache)


@dataclass
class Scenario:
    name: str
    legacy: Callable[[Rig], None]
    api: Callable[[Rig], None]
    setup: Callable[[Rig], None] = lambda rig: None
    policy: Any = None


def observe(rig: Rig, lines: list[str]) -> dict[str, Any]:
    store = rig.h.store
    keys = [KEY, KEY_2, KEY_OWNER, acct_key(OID_PENDING), acct_key(OID_BLOCKED)]
    infos = {}
    for key in keys:
        info = store.info(key)
        stored = store.get(key) if info is not None else None
        infos[key] = (
            dataclasses.asdict(info) if info is not None else None,
            stored.api_token if stored is not None else None,
        )
    prefs = {}
    for key in keys:
        value = store.get_tool_prefs(key)
        prefs[key] = (
            (sorted(value.enabled_write_tools), dict(sorted(value.enabled_at.items())))
            if value is not None
            else None
        )
    return {
        "enrollments": infos,
        "statuses": {
            key: dataclasses.asdict(store.get_principal_status(key)) for key in keys
        },
        "prefs": prefs,
        "audit_rows": [
            (e.actor, e.action, e.target, e.reason, e.detail) for e in store.list_audit(500)
        ],
        "status_events": [
            (e.principal_key, e.action, e.actor, e.reason, e.session_epoch)
            for e in store.list_status_events(limit=500)
        ],
        "log_lines": [
            {k: v for k, v in json.loads(line).items() if k != "timestamp"} for line in lines
        ],
        "cache": sorted(rig.cache.enabled(KEY)) if rig.cache is not None else None,
    }


def enroll_form(rig: Rig, token: str = CANVAS_TOKEN, **extra: str) -> Any:
    return rig.form("/account/token", canvas_token=token, **extra)


def enroll_api(rig: Rig, token: str = CANVAS_TOKEN, **extra: Any) -> Any:
    return rig.api.put("/me/canvas-token", {"canvas_token": token, **extra})


def confirmation_from_page(response: Any) -> str:
    match = re.search(r'name="confirm_identity_change" value="([^"]+)"', response.text)
    assert match, "the page did not ask for a confirmation"
    return match.group(1)


def _identity_change_legacy(rig: Rig) -> None:
    rig.h.whoami_result = CanvasIdentity("42", "Ada Canvas")
    assert enroll_form(rig).status_code == 303
    rig.h.whoami_result = CanvasIdentity("77", "Bob Canvas")
    refused = enroll_form(rig, NEW_TOKEN)
    assert refused.status_code == 409
    confirmation = confirmation_from_page(refused)
    assert enroll_form(rig, NEW_TOKEN, confirm_identity_change="wrong").status_code == 409
    assert enroll_form(rig, NEW_TOKEN, confirm_identity_change=confirmation).status_code == 303


def _identity_change_api(rig: Rig) -> None:
    rig.h.whoami_result = CanvasIdentity("42", "Ada Canvas")
    assert enroll_api(rig).status_code == 200
    rig.h.whoami_result = CanvasIdentity("77", "Bob Canvas")
    refused = enroll_api(rig, NEW_TOKEN)
    assert refused.status_code == 409
    confirmation = refused.json()["error"]["params"]["confirmation"]
    assert enroll_api(rig, NEW_TOKEN, confirm_identity_change="wrong").status_code == 409
    assert enroll_api(rig, NEW_TOKEN, confirm_identity_change=confirmation).status_code == 200


def _write_tools_legacy(rig: Rig) -> None:
    assert rig.form("/account/write-tools", **{"tool.send_message": "1"}).status_code == 200
    rig.h.now += 601
    refused = rig.form(
        "/account/write-tools", **{"tool.send_message": "1", "tool.create_assignment": "1"}
    )
    assert refused.status_code == 403
    assert rig.form("/account/write-tools", **{"tool.send_message": "1"}).status_code == 200
    assert rig.form("/account/write-tools", disable_all="1").status_code == 200


def _write_tools_api(rig: Rig) -> None:
    assert rig.api.put("/me/write-tools", {"enabled": ["send_message"]}).status_code == 200
    rig.h.now += 601
    refused = rig.api.put("/me/write-tools", {"enabled": ["send_message", "create_assignment"]})
    assert refused.status_code == 403
    assert rig.api.put("/me/write-tools", {"enabled": ["send_message"]}).status_code == 200
    assert rig.api.delete("/me/write-tools").status_code == 200


def _admin_setup(rig: Rig) -> None:
    from .conftest import make_account

    seed_people(rig.h)
    make_account(rig.h.store, OID_PENDING, status="pending", name="Newcomer")
    make_account(rig.h.store, OID_BLOCKED, status="disabled", name="Blocked")
    sign_in_owner(rig.h)


def _admin_legacy(rig: Rig) -> None:
    def act(path: str, key: str) -> None:
        assert rig.form(path, principal_key=key).status_code in (303, 400, 409, 403)

    act("/account/admin/invalidate", KEY)
    act("/account/admin/disable", KEY)
    act("/account/admin/enable", KEY)
    act("/account/admin/disable", KEY_OWNER)  # yourself
    act("/account/admin/approve", acct_key(OID_PENDING))
    act("/account/admin/deny", acct_key(OID_PENDING))  # no longer pending
    act("/account/admin/enable", acct_key(OID_BLOCKED))
    act("/account/admin/remove", KEY_2)
    act("/account/admin/remove", KEY_2)


def _admin_api(rig: Rig) -> None:
    def tail(key: str) -> str:
        return key.removeprefix("acct:")

    api = rig.api
    api.post(f"/admin/enrollments/{tail(KEY)}/mark-invalid")
    api.post(f"/admin/accounts/{tail(KEY)}/disable")
    api.post(f"/admin/accounts/{tail(KEY)}/enable")
    api.post(f"/admin/accounts/{tail(KEY_OWNER)}/disable")
    api.post(f"/admin/accounts/{tail(acct_key(OID_PENDING))}/approve")
    api.post(f"/admin/accounts/{tail(acct_key(OID_PENDING))}/deny")
    api.post(f"/admin/accounts/{tail(acct_key(OID_BLOCKED))}/enable")
    api.delete(f"/admin/enrollments/{tail(KEY_2)}")
    api.delete(f"/admin/enrollments/{tail(KEY_2)}")


def _stale_admin_legacy(rig: Rig) -> None:
    rig.h.now += 601
    # The stale owner is refused for every action.
    assert post_form(
        rig.h, "/account/admin/disable", {"csrf": _csrf_of_stale(rig), "principal_key": KEY}
    ).status_code == 403


def _csrf_of_stale(rig: Rig) -> str:
    # The account page still renders for a stale session; read its token.
    return csrf_of(rig.h)


def _stale_admin_api(rig: Rig) -> None:
    rig.api.csrf()
    rig.h.now += 601
    assert rig.api.post(f"/admin/accounts/{KEY.removeprefix('acct:')}/disable").status_code == 403


def _recheck_setup(rig: Rig) -> None:
    sign_in(rig.h)
    put_row(rig.h.store, OID, token=CANVAS_TOKEN, name="Ada Canvas", canvas_user_id="42",
            canvas_host="canvas.example.test")
    rig.h.store.mark_invalid(KEY, reason="canvas_token_rejected")


def _recheck_legacy(rig: Rig) -> None:
    rig.h.whoami_result = CanvasCheckError("invalid")
    assert rig.form("/account/token/recheck").status_code == 400
    assert rig.form("/account/token/recheck").status_code == 429  # once a minute
    rig.h.now += 61
    rig.h.whoami_result = CanvasIdentity("42", "Ada Canvas")
    assert rig.form("/account/token/recheck").status_code == 200


def _recheck_api(rig: Rig) -> None:
    rig.h.whoami_result = CanvasCheckError("invalid")
    assert rig.api.post("/me/canvas-token/recheck").status_code == 422
    assert rig.api.post("/me/canvas-token/recheck").status_code == 429
    rig.h.now += 61
    rig.h.whoami_result = CanvasIdentity("42", "Ada Canvas")
    assert rig.api.post("/me/canvas-token/recheck").status_code == 200


def _budget_legacy(rig: Rig) -> None:
    for _ in range(10):
        enroll_form(rig, "short")
    assert enroll_form(rig).status_code == 429


def _budget_mixed(rig: Rig) -> None:
    for _ in range(5):
        enroll_form(rig, "short")
    for _ in range(5):
        enroll_api(rig, "short")
    assert enroll_api(rig).status_code == 429


def _delete_legacy(rig: Rig) -> None:
    assert rig.form("/account/token/delete").status_code == 303
    assert rig.form("/account/token/delete").status_code == 303


def _delete_api(rig: Rig) -> None:
    assert rig.api.delete("/me/canvas-token").status_code == 204
    assert rig.api.delete("/me/canvas-token").status_code == 204


def _enroll_setup(rig: Rig) -> None:
    sign_in(rig.h)


SCENARIOS = [
    Scenario(
        "pending account is refused everywhere",
        legacy=lambda rig: (
            enroll_form(rig),
            rig.form("/account/token/recheck"),
            rig.form("/account/write-tools", **{"tool.send_message": "1"}),
        ),
        api=lambda rig: (
            enroll_api(rig),
            rig.api.post("/me/canvas-token/recheck"),
            rig.api.put("/me/write-tools", {"enabled": ["send_message"]}),
        ),
        setup=lambda rig: sign_in(rig.h, roles=()),
        policy=APPROVAL,
    ),
    Scenario(
        "enrolling with an expiry date",
        legacy=lambda rig: enroll_form(rig, expires_on="2027-03-01"),
        api=lambda rig: enroll_api(rig, expires_on="2027-03-01"),
        setup=_enroll_setup,
    ),
    Scenario(
        "a refused enrollment stores nothing",
        legacy=lambda rig: (
            enroll_form(rig, "short"),
            enroll_form(rig, expires_on="2020-01-01"),
            setattr(rig.h, "whoami_result", CanvasCheckError("invalid")),
            enroll_form(rig),
        ),
        api=lambda rig: (
            enroll_api(rig, "short"),
            enroll_api(rig, expires_on="2020-01-01"),
            setattr(rig.h, "whoami_result", CanvasCheckError("invalid")),
            enroll_api(rig),
        ),
        setup=_enroll_setup,
    ),
    Scenario("the same budget in both", legacy=_budget_legacy, api=_budget_mixed, setup=_enroll_setup),
    Scenario("identity change needs a confirmation", legacy=_identity_change_legacy,
             api=_identity_change_api, setup=_enroll_setup),
    Scenario("self-disconnect", legacy=_delete_legacy, api=_delete_api,
             setup=lambda rig: (sign_in(rig.h), put_row(rig.h.store, OID, token=CANVAS_TOKEN,
                                name="Ada", canvas_user_id="42"))),
    Scenario("check again", legacy=_recheck_legacy, api=_recheck_api, setup=_recheck_setup),
    Scenario("write tools and the fresh sign-in rule", legacy=_write_tools_legacy,
             api=_write_tools_api, setup=_enroll_setup),
    Scenario("owner actions", legacy=_admin_legacy, api=_admin_api, setup=_admin_setup),
    Scenario("a stale owner is refused", legacy=_stale_admin_legacy, api=_stale_admin_api,
             setup=lambda rig: (seed_people(rig.h), sign_in_owner(rig.h))),
]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.name for s in SCENARIOS])
def test_both_surfaces_do_the_same_thing(
    scenario: Scenario, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    results: dict[str, dict[str, Any]] = {}
    for surface in ("legacy", "api"):
        lines: list[str] = []

        class Recorder:
            def __init__(self, sink: list[str]) -> None:
                self.sink = sink

            def info(self, line: str) -> None:
                self.sink.append(line)

        monkeypatch.setattr(audit, "_audit_logger", Recorder(lines))
        monkeypatch.setattr(audit, "_access_events_enabled", True)
        kwargs = {"policy": scenario.policy} if scenario.policy is not None else {}
        rig = build_rig(tmp_path, surface, **kwargs)
        scenario.setup(rig)
        lines.clear()
        getattr(scenario, surface)(rig)
        results[surface] = observe(rig, lines)
    assert results["legacy"] == results["api"]
    assert results["legacy"]["audit_rows"] is not None


def test_the_scenarios_really_change_something(tmp_path: pathlib.Path) -> None:
    """A guard against comparing two empty worlds."""
    rig = build_rig(tmp_path, "check")
    _admin_setup(rig)
    before = observe(rig, [])
    _admin_api(rig)
    after = observe(rig, [])
    assert before != after
    assert BASE and OID_2
