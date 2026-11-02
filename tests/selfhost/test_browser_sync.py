"""Browser sync over HTTP: pairing, extension endpoints, uploads, account views, purge.

Runs on the real built-in authorization server, account API and database. The
extension is a second client without cookies, as in a browser.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
from typing import Any

import httpx
import pytest
from sqlalchemy import func, insert, select

from canvas_mcp.core.selfhost import browser_plan
from canvas_mcp.core.selfhost.browser_store import (
    BrowserSyncStore,
    hash_code,
    normalize_code,
)
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.sealed import SEALED
from canvas_mcp.core.selfhost.maintenance import MaintenanceRunner
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .account_fixture import (
    BASE,
    CANVAS_TOKEN,
    KEY,
    KEY_2,
    OID,
    OID_2,
    Harness,
    _display_in_utc,  # noqa: F401 - autouse fixture: timestamps render in UTC
    build_harness,
    put_row,
    sign_in,
)
from .authz.stack import CANVAS_HOST
from .test_account_api import Api, error_of

EXT = "chrome-extension://" + "a" * 32
FIREFOX = "moz-extension://12345678-1234-1234-1234-123456789abc"
P = "/api/v1"
X = P + "/extension"
BARE = {"include[]": sorted(browser_plan.RESOURCES[6].query["include[]"])}  # every enrollment
COURSES = {"enrollment_state": "active", **BARE}  # the active ones: the course source
ACTIVE_B = {**COURSES, "state[]": ["available"]}  # a second course-source list


def iso(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class Rig:
    def __init__(self, h: Harness) -> None:
        self.h = h
        self.api = Api(h)
        self.ext = h.stack.new_client()
        self.store = BrowserSyncStore(h.store.database, h.store.keyring, clock=h.clock)

    # -- the extension --------------------------------------------------------------

    def call(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: Any = None,
        origin: str | None = EXT,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        client: Any = None,
        content_type: str | None = "application/json",
    ) -> httpx.Response:
        sent = dict(headers or {})
        if origin is not None:
            sent["Origin"] = origin
        if token is not None:
            sent["Authorization"] = "Bearer " + token
        raw = content if content is not None else (None if body is None else json.dumps(body).encode())
        if raw is not None and content_type is not None:
            sent["Content-Type"] = content_type
        return (client or self.ext).request(method, X + path, content=raw, headers=sent)

    def pairing_code(self) -> str:
        response = self.api.post("/me/extension/pairing", None)
        assert response.status_code == 200, response.text
        return response.json()["code"]

    def pair(self) -> str:
        """A fresh upload token for the signed-in account."""
        response = self.call("POST", "/claim", body={"code": self.pairing_code()})
        assert response.status_code == 200, response.text
        return response.json()["uploadToken"]

    def upload(
        self,
        token: str,
        items: list[dict[str, Any]],
        *,
        captured_at: float | None = None,
        **fields: Any,
    ) -> httpx.Response:
        body: dict[str, Any] = {
            "schemaVersion": 1,
            "canvasOrigin": f"https://{CANVAS_HOST}",
            "canvasUserId": 77,
            "capturedAt": iso(self.h.now - 60 if captured_at is None else captured_at),
            "planVersion": 1,
            "resources": items,
        }
        body.update(fields)
        return self.call("POST", "/snapshots", token=token, body=body)

    def upload_no_origin(self, token: str) -> httpx.Response:
        body = {
            "schemaVersion": 1,
            "canvasOrigin": f"https://{CANVAS_HOST}",
            "canvasUserId": 77,
            "capturedAt": iso(self.h.now - 60),
            "planVersion": 1,
            "resources": [res("/users/self", {}, {"id": 77})],
        }
        return self.call("POST", "/snapshots", token=token, body=body, origin=None)

    def sync_courses(self, token: str, ids: tuple[int, ...] = (101, 102), **kw: Any) -> httpx.Response:
        return self.upload(
            token,
            [res("/courses", COURSES, [{"id": i, "name": f"Course {i}"} for i in ids])],
            **kw,
        )

    def binding_id(self, key: str = KEY) -> str | None:
        binding = self.store.active_binding(key)
        return None if binding is None else binding.id


def res(path: str, query: dict[str, Any] | None = None, body: Any = None, status: int = 200) -> dict[str, Any]:
    return {"path": path, "query": query or {}, "status": status, "body": body}


def window() -> dict[str, str]:
    return {"start_date": "2026-11-16T00:00:00Z", "end_date": "2027-05-15T00:00:00Z"}


@pytest.fixture
def rig(tmp_path: pathlib.Path) -> Rig:
    h = build_harness(tmp_path)
    assert sign_in(h).status_code == 303
    return Rig(h)


def refused(response: httpx.Response, status: int, error: str) -> None:
    assert response.status_code == status, (response.status_code, response.text)
    assert response.json() == {"error": error}


# -- pairing codes -----------------------------------------------------------------------------


def test_a_pairing_code_is_single_use(rig: Rig):
    code = rig.pairing_code()
    first = rig.call("POST", "/claim", body={"code": code})
    assert first.status_code == 200
    body = first.json()
    assert set(body) == {"uploadToken", "bindingId"} and len(body["uploadToken"]) == 43
    refused(rig.call("POST", "/claim", body={"code": code}), 400, "invalid_code")


def test_a_pairing_code_expires_after_five_minutes(rig: Rig):
    code = rig.pairing_code()
    rig.h.now += 299
    assert rig.store.claim(code) is not None
    code = rig.pairing_code()
    rig.h.now += 301
    refused(rig.call("POST", "/claim", body={"code": code}), 400, "invalid_code")


def test_the_pairing_response_names_its_expiry(rig: Rig):
    response = rig.api.post("/me/extension/pairing", None)
    body = response.json()
    assert set(body) == {"code", "expiresAt"}
    assert body["expiresAt"] == iso(rig.h.now + 300)
    assert len(body["code"]) == 14 and body["code"].count("-") == 2


def test_a_new_code_replaces_the_earlier_unclaimed_one(rig: Rig):
    old, new = rig.pairing_code(), rig.pairing_code()
    refused(rig.call("POST", "/claim", body={"code": old}), 400, "invalid_code")
    assert rig.call("POST", "/claim", body={"code": new}).status_code == 200


def test_a_code_may_be_typed_loosely(rig: Rig):
    code = rig.pairing_code()
    typed = "  " + code.lower().replace("-", " ") + " "
    assert rig.call("POST", "/claim", body={"code": typed}).status_code == 200


@pytest.mark.parametrize("code", ["", "short", "0" * 12, "ABCD-EFGH-JKLM-NPQR", 5, None, ["a"]])
def test_malformed_codes_are_refused_without_a_lookup(rig: Rig, code):
    refused(rig.call("POST", "/claim", body={"code": code}), 400, "invalid_code")


def test_the_claim_body_is_closed(rig: Rig):
    code = rig.pairing_code()
    refused(rig.call("POST", "/claim", body={"code": code, "extra": 1}), 400, "invalid_request")
    refused(rig.call("POST", "/claim", body={}), 400, "invalid_request")
    refused(rig.call("POST", "/claim", content=b'{"code": "a", "code": "b"}'), 400, "invalid_request")
    refused(rig.call("POST", "/claim", content=b"[]"), 400, "invalid_request")
    refused(rig.call("POST", "/claim", content=b'{"code": NaN}'), 400, "invalid_request")
    refused(rig.call("POST", "/claim", content=b"{}", content_type="text/plain"), 415, "unsupported_media_type")


def test_codes_and_tokens_are_stored_only_as_hashes(rig: Rig):
    code = rig.pairing_code()
    token = rig.call("POST", "/claim", body={"code": code}).json()["uploadToken"]
    with rig.h.store.database.read() as conn:
        codes = conn.execute(select(s.extension_pairing_codes)).mappings().all()
        bindings = conn.execute(select(s.extension_bindings)).mappings().all()
    assert [row["code_hash"] for row in codes] == [hash_code(normalize_code(code) or "")]
    assert [row["token_hash"] for row in bindings] == [hashlib.sha256(token.encode()).hexdigest()]
    dump = json.dumps([dict(r) for r in (*codes, *bindings)], default=str)
    assert token not in dump and (normalize_code(code) or "x") not in dump


def test_junk_claims_never_lock_out_a_real_pairing(rig: Rig):
    # Only failed claims count, in their own bucket: even a full bucket leaves a valid
    # unexpired code alone (its 60 bits and 5 minutes are the protection).
    statuses = [rig.call("POST", "/claim", body={"code": "ABCDEFGHJKLM"}).status_code for _ in range(602)]
    assert statuses[:600] == [400] * 600 and statuses[600:] == [429, 429]
    good = rig.call("POST", "/claim", body={"code": rig.pairing_code()})
    assert good.status_code == 200
    # ... and it did not use up the failure allowance either way.
    assert rig.call("POST", "/claim", body={"code": rig.pairing_code()}).status_code == 200


def test_a_disabled_account_cannot_spend_its_code(rig: Rig):
    code = rig.pairing_code()
    assert rig.h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
    refused(rig.call("POST", "/claim", body={"code": code}), 400, "invalid_code")


# -- authentication of the extension -------------------------------------------------------------


def test_plan_and_upload_need_a_live_token(rig: Rig):
    token = rig.pair()
    assert rig.call("GET", "/plan", token=token).status_code == 200
    for bad in (None, "x" * 43, token[:-1] + ("A" if token[-1] != "A" else "B"), "short"):
        refused(rig.call("GET", "/plan", token=bad), 401, "invalid_token")
        refused(rig.call("POST", "/snapshots", token=bad, body={}), 401, "invalid_token")
        refused(rig.call("DELETE", "/binding", token=bad), 401, "invalid_token")
    refused(
        rig.call("GET", "/plan", headers={"Authorization": "Basic " + token}), 401, "invalid_token"
    )


def test_pairing_again_revokes_the_old_token_and_deletes_its_snapshots(rig: Rig):
    old = rig.pair()
    assert rig.sync_courses(old).json()["accepted"] == 1
    old_binding = rig.binding_id()
    new = rig.pair()
    refused(rig.call("GET", "/plan", token=old), 401, "invalid_token")
    refused(rig.call("POST", "/snapshots", token=old, body={}), 401, "invalid_token")
    assert rig.call("GET", "/plan", token=new).status_code == 200
    with rig.h.store.database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.browser_snapshots)).scalar_one() == 0
        live = conn.execute(
            select(s.extension_bindings.c.id).where(s.extension_bindings.c.revoked_at.is_(None))
        ).scalars().all()
    assert len(live) == 1 and live[0] != old_binding
    # The new binding starts empty: nothing carries over, not even the pinned Canvas user.
    plan = rig.call("GET", "/plan", token=new).json()
    assert plan["canvasHost"] is None


def test_the_extension_can_delete_its_own_binding(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    response = rig.call("DELETE", "/binding", token=token)
    assert response.status_code == 204 and response.content == b""
    refused(rig.call("GET", "/plan", token=token), 401, "invalid_token")
    assert rig.store.active_binding(KEY) is None
    with rig.h.store.database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.browser_snapshots)).scalar_one() == 0


def test_a_disabled_account_token_stops_working(rig: Rig):
    token = rig.pair()
    assert rig.h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
    refused(rig.call("GET", "/plan", token=token), 401, "invalid_token")


def test_a_token_is_not_an_account_or_mcp_credential(rig: Rig):
    token = rig.pair()
    other = rig.h.stack.new_client()
    for path in ("/me", "/me/extension", "/providers"):
        response = other.get(P + path, headers={"Authorization": "Bearer " + token})
        assert response.status_code in (401, 200)
        assert "uploadToken" not in response.text
    assert other.get(P + "/me", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert other.post("/mcp", headers={"Authorization": "Bearer " + token}, json={}).status_code == 401


# -- origins, cookies, CORS ------------------------------------------------------------------------


def test_capabilities_answer_an_extension_origin_with_cors(rig: Rig):
    for origin in (EXT, FIREFOX):
        response = rig.call("GET", "/capabilities", origin=origin)
        assert response.status_code == 200
        assert response.json() == {"browserSync": 1, "maxBodyBytes": 4194304}
        assert response.headers["access-control-allow-origin"] == origin
        assert response.headers["vary"] == "Origin"
        assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        BASE,
        "null",
        "chrome-extension://" + "a" * 31,
        "chrome-extension://" + "a" * 33,
        "chrome-extension://" + "q" * 32,
        "chrome-extension://" + "A" * 32,
        "chrome-extension://" + "a" * 32 + "/",
        "moz-extension://not-a-uuid",
        "http://chrome-extension://" + "a" * 32,
    ],
)
def test_only_an_extension_origin_is_answered_and_nobody_else_gets_cors(rig: Rig, origin):
    for method, path in (("GET", "/capabilities"), ("POST", "/claim"), ("GET", "/plan")):
        response = rig.call(method, path, origin=origin, body={"code": "x"} if method == "POST" else None)
        # Either the server's origin guard or the endpoint itself says no; nobody gets CORS headers.
        assert response.status_code == 403, (origin, response.status_code)
        assert not [h for h in response.headers if h.lower().startswith("access-control-")]
    preflight = rig.call("OPTIONS", "/snapshots", origin=origin)
    assert preflight.status_code == 403
    assert "access-control-allow-origin" not in preflight.headers


def test_a_missing_origin_is_accepted_without_cors_headers(rig: Rig):
    # Chrome sends no Origin on GETs from an extension service worker.
    response = rig.call("GET", "/capabilities", origin=None)
    assert response.status_code == 200
    assert not [h for h in response.headers if h.lower().startswith("access-control-")]
    claim = rig.call("POST", "/claim", body={"code": rig.pairing_code()}, origin=None)
    assert claim.status_code == 200
    token = claim.json()["uploadToken"]
    assert rig.call("GET", "/plan", token=token, origin=None).status_code == 200
    assert rig.upload_no_origin(token).status_code == 200
    assert rig.call("DELETE", "/binding", token=token, origin=None).status_code == 204


def test_a_missing_origin_still_needs_credentials_and_no_cookie(rig: Rig):
    refused(rig.call("GET", "/plan", origin=None), 401, "invalid_token")
    refused(rig.call("POST", "/claim", body={"code": "ABCDEFGHJKLM"}, origin=None), 400, "invalid_code")
    refused(rig.call("GET", "/capabilities", origin=None, headers={"Cookie": "a=b"}), 400, "cookies_not_allowed")


def test_a_preflight_still_needs_an_extension_origin(rig: Rig):
    refused(rig.call("OPTIONS", "/snapshots", origin=None), 403, "origin_not_allowed")


def test_a_page_of_the_portal_itself_is_not_an_extension(rig: Rig):
    # The portal's own origin passes the host guard, so the endpoint must refuse it.
    refused(rig.call("GET", "/capabilities", origin=BASE), 403, "origin_not_allowed")


def test_a_request_with_a_cookie_is_refused(rig: Rig):
    token = rig.pair()
    for method, path in (("GET", "/capabilities"), ("GET", "/plan"), ("DELETE", "/binding")):
        response = rig.call(method, path, token=token, headers={"Cookie": "a=b"})
        refused(response, 400, "cookies_not_allowed")
        # The extension can still read the refusal.
        assert response.headers["access-control-allow-origin"] == EXT
    refused(rig.call("OPTIONS", "/plan", headers={"Cookie": "a=b"}), 400, "cookies_not_allowed")
    # A browser that holds the student's session cookie sends it: the signed-in client is refused too.
    refused(rig.call("GET", "/capabilities", client=rig.h.client), 400, "cookies_not_allowed")
    assert rig.store.active_binding(KEY) is not None


def test_the_preflight_names_exactly_the_methods_and_headers_the_extension_uses(rig: Rig):
    response = rig.call(
        "OPTIONS",
        "/snapshots",
        headers={
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization, content-type",
        },
    )
    assert response.status_code == 204 and response.content == b""
    assert response.headers["access-control-allow-origin"] == EXT
    assert response.headers["access-control-allow-methods"] == "GET, POST, DELETE"
    assert response.headers["access-control-allow-headers"] == "Authorization, Content-Type"
    assert response.headers["access-control-max-age"] == "600"
    assert "access-control-allow-credentials" not in response.headers
    assert response.headers["vary"] == "Origin"


def test_a_method_the_path_does_not_serve_is_refused_with_allow(rig: Rig):
    response = rig.call("PUT", "/plan", token="x" * 43)
    refused(response, 405, "method_not_allowed")
    assert response.headers["allow"] == "GET"


def test_the_account_api_stays_closed_to_cors(rig: Rig):
    response = rig.ext.options(P + "/me/extension", headers={"Origin": EXT, "Access-Control-Request-Method": "GET"})
    assert response.status_code == 405
    assert "access-control-allow-origin" not in response.headers
    response = rig.ext.get(P + "/me/extension", headers={"Origin": EXT})
    assert response.status_code == 401 and "access-control-allow-origin" not in response.headers


def test_capabilities_is_never_limited(rig: Rig):
    # Static and free: an anonymous loop must not lock real users out of it.
    assert {rig.call("GET", "/capabilities").status_code for _ in range(400)} == {200}


def test_bad_tokens_never_limit_a_real_binding(rig: Rig):
    token = rig.pair()
    statuses = [rig.call("GET", "/plan", token="x" * 43).status_code for _ in range(700)]
    # The failure bucket answers 429 to further failures only.
    assert statuses[:600] == [401] * 600 and statuses[600:] == [429] * 100
    assert rig.call("GET", "/plan", token=token).status_code == 200
    assert rig.call("POST", "/snapshots", token=token, body={"schemaVersion": 2}).status_code == 400
    assert rig.call("GET", "/capabilities").status_code == 200


def test_each_binding_has_its_own_allowance(tmp_path: pathlib.Path):
    h = build_harness(tmp_path)
    assert sign_in(h).status_code == 303
    alice = Rig(h)
    alice_token = alice.pair()
    h.client.cookies.clear()
    assert sign_in(h, oid=OID_2, name="Bea", upn="bea@example.test").status_code == 303
    bea = Rig(h)
    bea_token = bea.pair()
    statuses = [alice.call("GET", "/plan", token=alice_token) for _ in range(122)]
    assert statuses[0].status_code == 200 and statuses[-1].status_code == 429
    assert statuses[-1].headers["retry-after"] == "60"
    assert bea.call("GET", "/plan", token=bea_token).status_code == 200


def test_the_authenticated_ceiling_counts_valid_requests_only(tmp_path: pathlib.Path, monkeypatch):
    from canvas_mcp.core.selfhost import browser_extension_api

    monkeypatch.setattr(browser_extension_api, "AUTHENTICATED_REQUESTS_PER_MINUTE", 5)
    h = build_harness(tmp_path)
    assert sign_in(h).status_code == 303
    rig = Rig(h)
    token = rig.pair()
    for _ in range(50):  # failures do not use the authenticated allowance
        rig.call("GET", "/plan", token="x" * 43)
    codes = [rig.call("GET", "/plan", token=token).status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    assert rig.call("GET", "/capabilities").status_code == 200


# -- plan ----------------------------------------------------------------------------------------------


def test_the_plan_follows_the_contract_and_fits_the_extension_allowlist(rig: Rig):
    token = rig.pair()
    plan = rig.call("GET", "/plan", token=token).json()
    assert set(plan) == {"planVersion", "canvasHost", "maxPages", "coldIntervalHours", "resources"}
    assert plan["planVersion"] == 2 and plan["maxPages"] == 50 and plan["canvasHost"] is None
    assert plan["coldIntervalHours"] == 12
    paths = [r["path"] for r in plan["resources"]]
    assert paths[:2] == ["/users/self", "/users/self/profile"]
    for resource in plan["resources"]:
        assert set(resource) <= {"path", "query", "paginate", "tier", "expand", "chunk", "courseSource", "perCourse"}
        assert resource["tier"] in ("hot", "cold")
        assert isinstance(resource["query"], dict)
        concrete = resource["path"].replace("{course_id}", "123")
        assert browser_plan.ALLOWED_PATH.fullmatch(concrete), resource["path"]
        assert all("{start}" not in json.dumps(v) and "{end}" not in json.dumps(v) for v in resource["query"].values())
        for key, value in resource["query"].items():
            assert isinstance(value, list) if key.endswith("[]") else isinstance(value, str)
    # The first course list precedes every per-course resource, so ids are known before use.
    first_per_course = next(i for i, r in enumerate(plan["resources"]) if r.get("expand"))
    assert any(r["path"] == "/courses" for r in plan["resources"][:first_per_course])
    # Dates are concrete: about 60 days back and 120 ahead of the server's day.
    windowed = [r for r in plan["resources"] if "start_date" in r["query"]]
    assert windowed
    for resource in windowed:
        assert resource["query"]["start_date"] == iso(
            dt.datetime.fromtimestamp(rig.h.now, tz=dt.UTC)
            .replace(hour=0, minute=0, second=0, microsecond=0)
            .timestamp()
            - 60 * 86400
        )
        assert resource["query"]["end_date"].endswith("Z")


def test_the_personal_calendar_is_planned_once_the_student_is_known(rig: Rig):
    token = rig.pair()
    before = rig.call("GET", "/plan", token=token).json()
    assert not any("user_" in json.dumps(r["query"]) for r in before["resources"])
    assert rig.sync_courses(token).status_code == 200
    after = rig.call("GET", "/plan", token=token).json()
    assert after["canvasHost"] == CANVAS_HOST
    personal = [r for r in after["resources"] if r["query"].get("context_codes[]") == ["user_77"]]
    assert len(personal) == 2


# -- uploads ----------------------------------------------------------------------------------------------


def test_an_upload_is_stored_and_the_first_one_pins_host_and_user(rig: Rig):
    token = rig.pair()
    response = rig.sync_courses(token)
    assert response.status_code == 200 and response.json() == {"accepted": 1, "rejected": []}
    binding = rig.store.active_binding(KEY)
    assert binding is not None
    assert (binding.canvas_host, binding.canvas_user_id) == (CANVAS_HOST, "77")
    assert binding.last_upload_at == int(rig.h.now)
    [stored] = rig.store.load_path(binding.id, "/courses")
    assert stored.captured_at == int(rig.h.now) - 60 and stored.status == 200
    assert stored.body == [{"id": 101, "name": "Course 101"}, {"id": 102, "name": "Course 102"}]


def test_per_course_resources_are_checked_against_the_courses_of_the_same_upload(rig: Rig):
    token = rig.pair()
    body = [{"id": 101}]
    response = rig.upload(
        token,
        [
            res("/courses/101/quizzes", {}, [{"id": 1}]),  # listed before /courses: still fine
            res("/courses", COURSES, body),
            res("/courses/999/quizzes", {}, []),
        ],
    )
    assert response.json() == {
        "accepted": 2,
        "rejected": [{"path": "/courses/999/quizzes", "reason": "not_in_plan"}],
    }


def test_a_rejected_course_list_does_not_name_courses(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token,
        [
            res("/courses", {"enrollment_state": "completed"}, [{"id": 555}]),  # not a planned list
            res("/courses/555/quizzes", {}, []),
        ],
    )
    assert response.json()["accepted"] == 0
    assert [r["reason"] for r in response.json()["rejected"]] == ["not_in_plan", "not_in_plan"]


def test_course_ids_also_come_from_an_earlier_upload(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token, (101,))
    response = rig.upload(token, [res("/courses/101/quizzes", {}, [])])
    assert response.json()["accepted"] == 1
    response = rig.upload(token, [res("/courses/102/quizzes", {}, [])])
    assert response.json()["rejected"] == [{"path": "/courses/102/quizzes", "reason": "not_in_plan"}]


@pytest.mark.parametrize(
    "path,query,reason",
    [
        ("/courses/101/pages", {}, "invalid_resource"),  # outside the extension allowlist
        ("/users/123", {}, "invalid_resource"),
        ("/courses/101/quizzes/5", {}, "invalid_resource"),
        ("/courses/../users/self", {}, "invalid_resource"),
        ("/users/self?x=1", {}, "invalid_resource"),
        ("/users/self", {"x": "1"}, "not_in_plan"),
        ("/courses/101/quizzes", {"per_page": "100"}, "not_in_plan"),
        ("/courses/101/assignments", {"include[]": ["rubric"]}, "not_in_plan"),
        ("/courses/101/enrollments", {}, "invalid_resource"),  # a roster: outside the allowlist
        (7, {}, "invalid_resource"),
        ("/users/self", [], "invalid_resource"),
        ("/users/self", {"bad key": "1"}, "invalid_resource"),
        ("/users/self", {"a": {"nested": 1}}, "invalid_resource"),
    ],
)
def test_resources_outside_the_plan_are_rejected_one_by_one(rig: Rig, path, query, reason):
    token = rig.pair()
    rig.sync_courses(token)
    response = rig.upload(token, [res("/users/self", {}, {"id": 77}), {"path": path, "query": query, "status": 200, "body": []}])
    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 1
    assert [r["reason"] for r in body["rejected"]] == [reason]


def test_dated_resources_need_a_sane_window(rig: Rig):
    token = rig.pair()
    ok = res("/planner/items", window(), [])
    no_window = res("/planner/items", {}, [])
    reversed_window = res("/planner/items", {"start_date": "2027-05-15", "end_date": "2026-11-16"}, [])
    huge = res("/planner/items", {"start_date": "2020-01-01", "end_date": "2030-01-01"}, [])
    bad = res("/planner/items", {"start_date": "yesterday", "end_date": "tomorrow"}, [])
    response = rig.upload(token, [ok, no_window, reversed_window, huge, bad])
    body = response.json()
    assert body["accepted"] == 1
    assert [r["reason"] for r in body["rejected"]] == ["invalid_resource"] * 4
    # A window on a resource the plan does not date is refused too.
    stray = rig.upload(token, [res("/users/self", window(), {"id": 77})])
    assert stray.json()["rejected"] == [{"path": "/users/self", "reason": "invalid_resource"}]


def test_a_dated_resource_is_one_row_whatever_its_window(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/planner/items", window(), [{"id": 1}])], captured_at=rig.h.now - 100)
    rig.upload(
        token,
        [res("/planner/items", {"start_date": "2026-11-17T00:00:00Z", "end_date": "2027-05-16T00:00:00Z"}, [{"id": 2}])],
    )
    binding = rig.binding_id()
    [only] = rig.store.load_path(binding, "/planner/items")
    assert only.body == [{"id": 2}]
    assert only.query["start_date"] == ["2026-11-17T00:00:00Z"]
    assert [r.key for r in rig.store.resources(binding)] == ["/planner/items"]


def test_an_older_capture_never_replaces_a_newer_one(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self", {}, {"id": 77, "name": "new"})], captured_at=rig.h.now - 10)
    older = rig.upload(token, [res("/users/self", {}, {"id": 77, "name": "old"})], captured_at=rig.h.now - 500)
    assert older.json() == {"accepted": 0, "rejected": [{"path": "/users/self", "reason": "older_than_stored"}]}
    [stored] = rig.store.load_path(rig.binding_id(), "/users/self")
    assert stored.body["name"] == "new"
    same = rig.upload(token, [res("/users/self", {}, {"id": 77, "name": "same time"})], captured_at=rig.h.now - 10)
    assert same.json()["accepted"] == 1
    newer = rig.upload(token, [res("/users/self", {}, {"id": 77, "name": "newest"})], captured_at=rig.h.now - 1)
    assert newer.json()["accepted"] == 1
    [stored] = rig.store.load_path(rig.binding_id(), "/users/self")
    assert stored.body["name"] == "newest" and stored.captured_at == int(rig.h.now) - 1


def test_one_resource_twice_in_an_upload_keeps_the_first(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token, [res("/users/self", {}, {"id": 77, "n": 1}), res("/users/self", {}, {"id": 77, "n": 2})]
    )
    assert response.json() == {
        "accepted": 1,
        "rejected": [{"path": "/users/self", "reason": "duplicate_in_upload"}],
    }
    assert rig.store.load_path(rig.binding_id(), "/users/self")[0].body["n"] == 1


def test_a_failed_canvas_status_is_stored_without_a_body(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token,
        [
            res("/users/self", {}, None, status=401),
            res("/users/self/todo", {}, {"leaked": "text"}, status=403),
            res("/users/self/profile", {}, "not json structure"),
        ],
    )
    assert response.json()["accepted"] == 2
    assert [r["path"] for r in response.json()["rejected"]] == ["/users/self/profile"]
    [self_row] = rig.store.load_path(rig.binding_id(), "/users/self")
    [todo] = rig.store.load_path(rig.binding_id(), "/users/self/todo")
    assert (self_row.status, self_row.body, todo.status, todo.body) == (401, None, 403, None)


@pytest.mark.parametrize(
    "fields,status,error",
    [
        ({"canvasOrigin": "https://other.example.edu"}, 409, "canvas_mismatch"),
        ({"canvasOrigin": "http://" + CANVAS_HOST}, 409, "canvas_mismatch"),
        ({"canvasOrigin": f"https://{CANVAS_HOST}/api/v1"}, 409, "canvas_mismatch"),
        ({"canvasOrigin": f"https://{CANVAS_HOST}:8443"}, 409, "canvas_mismatch"),
        ({"canvasOrigin": f"https://user@{CANVAS_HOST}"}, 409, "canvas_mismatch"),
        ({"canvasOrigin": "https://127.0.0.1"}, 409, "canvas_mismatch"),
        ({"canvasOrigin": 5}, 409, "canvas_mismatch"),
        ({"schemaVersion": 2}, 400, "unsupported_schema"),
        ({"schemaVersion": True}, 400, "unsupported_schema"),
        ({"planVersion": 3}, 409, "plan_outdated"),
        ({"planVersion": 0}, 409, "plan_outdated"),
        ({"planVersion": "2"}, 409, "plan_outdated"),
        ({"canvasUserId": 0}, 400, "invalid_request"),
        ({"canvasUserId": "abc"}, 400, "invalid_request"),
        ({"canvasUserId": True}, 400, "invalid_request"),
        ({"capturedAt": "2999-01-01T00:00:00Z"}, 400, "invalid_request"),
        ({"capturedAt": "2019-12-31T00:00:00Z"}, 400, "invalid_request"),
        ({"capturedAt": "2027-01-01T00:00:00"}, 400, "invalid_request"),
        ({"capturedAt": "soon"}, 400, "invalid_request"),
        ({"resources": "all"}, 400, "invalid_request"),
        ({"resources": [1, "x", None]}, None, None),
    ],
)
def test_a_bad_upload_header_rejects_the_whole_upload(rig: Rig, fields, status, error):
    token = rig.pair()
    response = rig.upload(token, [res("/users/self", {}, {"id": 77})], **fields)
    if status is None:
        # Malformed entries are rejected one by one.
        assert response.status_code == 200 and response.json()["accepted"] == 0
        assert len(response.json()["rejected"]) == 3
        return
    refused(response, status, error)
    assert rig.store.resources(rig.binding_id()) == []


def test_missing_header_fields_are_a_bad_request(rig: Rig):
    token = rig.pair()
    for missing in ("schemaVersion", "canvasOrigin", "canvasUserId", "capturedAt", "planVersion", "resources"):
        body = {
            "schemaVersion": 1,
            "canvasOrigin": f"https://{CANVAS_HOST}",
            "canvasUserId": 77,
            "capturedAt": iso(rig.h.now),
            "planVersion": 1,
            "resources": [],
        }
        del body[missing]
        response = rig.call("POST", "/snapshots", token=token, body=body)
        assert response.status_code in (400, 409), missing


def test_the_canvas_host_and_user_are_pinned_for_the_life_of_the_binding(rig: Rig):
    token = rig.pair()
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})]).status_code == 200
    other_user = rig.upload(token, [res("/users/self", {}, {"id": 5, "x": "other"})], canvasUserId=78)
    refused(other_user, 409, "canvas_mismatch")
    assert rig.store.load_path(rig.binding_id(), "/users/self")[0].body == {"id": 77}
    # Another school is refused at the directory (only one is offered here), and never re-pins.
    refused(
        rig.upload(token, [res("/users/self", {}, {"id": 77})], canvasOrigin="https://elsewhere.example.edu"),
        409,
        "canvas_mismatch",
    )
    binding = rig.store.active_binding(KEY)
    assert binding is not None and binding.canvas_host == CANVAS_HOST


def test_a_second_school_in_the_directory_still_cannot_replace_the_pinned_one(tmp_path: pathlib.Path):
    from canvas_mcp.core.selfhost.schools import School, SchoolPolicy

    from .account_fixture import FixtureConfig

    other = "second.example.edu"
    schools = SchoolPolicy(
        (
            School(CANVAS_HOST, f"https://{CANVAS_HOST}/api/v1", "A"),
            School(other, f"https://{other}/api/v1", "B"),
        ),
        False,
    )
    h = build_harness(tmp_path, cfg=FixtureConfig(schools=schools))
    sign_in(h)
    rig = Rig(h)
    token = rig.pair()
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})]).status_code == 200
    refused(
        rig.upload(token, [res("/users/self", {}, {"id": 77})], canvasOrigin=f"https://{other}"),
        409,
        "canvas_mismatch",
    )


def test_a_revoked_binding_cannot_finish_an_upload(rig: Rig):
    token = rig.pair()
    binding = rig.store.authenticate(token)
    assert binding is not None
    rig.store.revoke_account(KEY)
    from canvas_mcp.core.selfhost.browser_store import BindingGone, SnapshotItem

    item = SnapshotItem("/users/self", "/users/self", {}, 1, 200, {"id": 1})
    with pytest.raises(BindingGone):
        rig.store.save(binding.id, canvas_host=CANVAS_HOST, canvas_user_id="77", items=[item])


def test_uploads_stop_at_four_mebibytes(rig: Rig):
    token = rig.pair()
    filler = "x" * (4 * 1024 * 1024)
    big = json.dumps({"schemaVersion": 1, "pad": filler}).encode()
    refused(rig.call("POST", "/snapshots", token=token, content=big), 413, "payload_too_large")
    # The limit also applies to a body that does not declare its length.
    def stream():
        yield b'{"pad": "'
        for _ in range(5):
            yield b"y" * (1024 * 1024)
        yield b'"}'

    refused(rig.call("POST", "/snapshots", token=token, content=stream()), 413, "payload_too_large")
    # Just under the limit is read (and then judged on its content).
    body = json.dumps({"schemaVersion": 1, "pad": "z" * (4 * 1024 * 1024 - 100)}).encode()
    assert len(body) < 4 * 1024 * 1024
    assert rig.call("POST", "/snapshots", token=token, content=body).status_code in (400, 409)


def test_an_upload_needs_json(rig: Rig):
    token = rig.pair()
    refused(rig.call("POST", "/snapshots", token=token, content=b"{}", content_type="text/plain"), 415, "unsupported_media_type")
    refused(rig.call("POST", "/snapshots", token=token, content=b"{", ), 400, "invalid_request")
    refused(rig.call("POST", "/snapshots", token=token, content=b"\xff\xfe"), 400, "invalid_request")
    refused(rig.call("POST", "/snapshots", token=token, content=b"[" * 5000), 400, "invalid_request")
    refused(rig.call("POST", "/snapshots", token=token, content=b"{}", headers={"Content-Length": "-1"}), 400, "invalid_request")


# -- storage ---------------------------------------------------------------------------------------------


def test_bodies_are_sealed_and_bound_to_their_binding_and_resource(rig: Rig):
    token = rig.pair()
    secret = "Dr. Hidden Name 12345"
    rig.upload(
        token,
        [res("/users/self", {}, {"id": 77, "name": secret}), res("/users/self/todo", {}, [{"id": 1}])],
    )
    entry = next(e for e in SEALED if e.table is s.browser_snapshots)
    with rig.h.store.database.read() as conn:
        rows = [dict(r) for r in conn.execute(select(s.browser_snapshots).order_by(s.browser_snapshots.c.resource_key)).mappings()]
    assert len(rows) == 2 and all(secret.encode() not in bytes(r["ciphertext"]) for r in rows)
    assert entry.aad(rows[0]).startswith(b"canvas-mcp/browser-snapshot/v1\x1f")
    ring = rig.h.store.keyring
    # A row copied under another resource key or another binding does not decrypt.
    swapped = dict(rows[0], resource_key=rows[1]["resource_key"])
    with pytest.raises(Exception, match="."):
        ring.decrypt(swapped["key_id"], bytes(swapped["nonce"]), bytes(swapped["ciphertext"]), entry.aad(swapped))
    moved = dict(rows[0], binding_id="00000000-0000-4000-8000-000000000000")
    with pytest.raises(Exception, match="."):
        ring.decrypt(moved["key_id"], bytes(moved["nonce"]), bytes(moved["ciphertext"]), entry.aad(moved))


# -- accounts never see each other's data ---------------------------------------------------------------------


def test_one_account_can_never_read_or_change_anothers_snapshots(tmp_path: pathlib.Path):
    h = build_harness(tmp_path)
    assert sign_in(h).status_code == 303
    alice = Rig(h)
    alice_token = alice.pair()
    alice.upload(alice_token, [res("/users/self", {}, {"id": 77, "name": "alice"})])
    alice_binding = alice.binding_id()

    h.client.cookies.clear()
    assert sign_in(h, oid=OID_2, name="Bea", upn="bea@example.test").status_code == 303
    bea = Rig(h)
    bea.api = Api(h)
    bea_token = bea.pair()
    bea_binding = bea.binding_id(KEY_2)
    assert bea_binding and bea_binding != alice_binding
    assert bea.upload(bea_token, [res("/users/self", {}, {"id": 88, "name": "bea"})], canvasUserId=88).status_code == 200

    # Each binding holds only its own rows, whatever path is asked for.
    assert [x.body["name"] for x in bea.store.load_path(bea_binding, "/users/self")] == ["bea"]
    assert [x.body["name"] for x in alice.store.load_path(alice_binding, "/users/self")] == ["alice"]
    # Bea's token cannot reach Alice's binding: she is pinned to her own user and her own rows.
    refused(
        bea.upload(bea_token, [res("/users/self", {}, {"id": 77})], canvasUserId=77),
        409,
        "canvas_mismatch",
    )
    # The account views show only the caller's resources.
    [shown] = bea.api.get("/me/extension").json()["binding"]["resources"]
    assert shown["path"] == "/users/self"
    assert alice.store.active_binding(KEY_2) is not None and alice.store.active_binding(KEY) is not None
    # Revoking one leaves the other.
    bea.api.delete("/me/extension")
    assert alice.store.load_path(alice_binding, "/users/self")
    assert not bea.store.load_path(bea_binding, "/users/self")
    assert alice.call("GET", "/plan", token=alice_token).status_code == 200
    refused(bea.call("GET", "/plan", token=bea_token), 401, "invalid_token")


# -- the account's own view --------------------------------------------------------------------------------


def test_pairing_is_a_protected_mutation(rig: Rig):
    error_of(rig.api.post("/me/extension/pairing", None, csrf=False), 403, "csrf_invalid")
    error_of(rig.api.post("/me/extension/pairing", None, fetch_site="cross-site"), 403, "origin_not_allowed")
    error_of(rig.api.post("/me/extension/pairing", {"x": 1}), 400, "malformed_request")
    signed_out = rig.h.stack.new_client().post(P + "/me/extension/pairing", headers={"Origin": BASE})
    assert signed_out.status_code == 401
    error_of(rig.api.get("/me/extension", headers={"Sec-Fetch-Site": "cross-site"}), 403, "origin_not_allowed")
    assert rig.api.delete("/me/extension", csrf=False).status_code == 403


def test_pairing_is_rate_limited_per_account(rig: Rig):
    results = [rig.api.post("/me/extension/pairing", None).status_code for _ in range(11)]
    assert results[:10] == [200] * 10 and results[10] == 429


def test_the_account_sees_no_binding_until_it_pairs(rig: Rig):
    assert rig.api.get("/me/extension").json() == {"binding": None}
    rig.pair()
    shown = rig.api.get("/me/extension").json()["binding"]
    assert shown == {
        "createdAt": iso(rig.h.now),
        "lastUploadAt": None,
        "canvasHost": None,
        "resources": [],
        "active": False,
        "reason": "school_unknown",
    }


def test_the_account_lists_what_was_synced_and_whether_it_is_used(rig: Rig):
    token = rig.pair()
    rig.upload(
        token,
        [
            res("/courses", BARE, [{"id": 101}]),
            res("/courses", COURSES, [{"id": 101}]),
            res("/courses/101/front_page", {}, None, status=404),
        ],
    )
    shown = rig.api.get("/me/extension").json()["binding"]
    assert shown["canvasHost"] == CANVAS_HOST and shown["active"] is True and shown["reason"] is None
    assert shown["lastUploadAt"] == iso(rig.h.now)
    assert sorted((r["path"], r["canvasStatus"]) for r in shown["resources"]) == [
        ("/courses", 200),
        ("/courses", 200),
        ("/courses/101/front_page", 404),
    ]
    assert all(r["capturedAt"] == iso(rig.h.now - 60) for r in shown["resources"])


def test_a_usable_token_wins_and_an_unusable_one_does_not(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self", {}, {"id": 77})])
    assert rig.api.get("/me/extension").json()["binding"]["active"] is True
    put_row(rig.h.store, OID, token=CANVAS_TOKEN, name="Ada")
    shown = rig.api.get("/me/extension").json()["binding"]
    assert (shown["active"], shown["reason"]) == (False, "token_preferred")
    # A token Canvas rejected is not usable: the synced data takes over for the same school.
    assert rig.h.store.mark_invalid(KEY, reason="canvas_token_rejected")
    shown = rig.api.get("/me/extension").json()["binding"]
    assert (shown["active"], shown["reason"]) == (True, None)


def test_deleting_the_binding_from_the_account_removes_the_data(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    assert rig.api.delete("/me/extension").status_code == 204
    assert rig.api.get("/me/extension").json() == {"binding": None}
    refused(rig.call("GET", "/plan", token=token), 401, "invalid_token")
    assert rig.api.delete("/me/extension").status_code == 204  # idempotent
    with rig.h.store.database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.browser_snapshots)).scalar_one() == 0
        assert conn.execute(select(func.count()).select_from(s.extension_pairing_codes)).scalar_one() == 0


# -- account deletion and housekeeping ------------------------------------------------------------------------


def test_deleting_the_account_removes_every_trace(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    rig.pairing_code()
    assert rig.h.store.delete_account(KEY) is True
    with rig.h.store.database.read() as conn:
        for table in (s.extension_bindings, s.extension_pairing_codes, s.browser_snapshots):
            assert conn.execute(select(func.count()).select_from(table)).scalar_one() == 0


async def test_maintenance_purges_old_snapshots_spent_codes_and_old_bindings(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 31 * 86400)
    rig.upload(token, [res("/users/self/todo", {}, [])], captured_at=rig.h.now - 29 * 86400)
    rig.pairing_code()
    rig.pair()  # revokes the first binding (and spends a code)
    with rig.h.store.database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.extension_bindings)).scalar_one() == 2
    runner = MaintenanceRunner(rig.h.store.database, cimd_stale_max=3600, now=lambda: rig.h.now)
    removed = await runner.run()
    assert removed["browser_snapshots"] == 0  # the revoke already deleted the first binding's rows
    rig.h.now += 40 * 86400
    removed = await runner.run()
    assert removed["browser_snapshots"] == 0 and removed["revoked_bindings"] == 1
    assert removed["extension_codes"] >= 1
    with rig.h.store.database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.extension_bindings)).scalar_one() == 1


async def test_maintenance_removes_only_snapshots_past_the_purge_age(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 31 * 86400)
    rig.upload(token, [res("/users/self/todo", {}, [])], captured_at=rig.h.now - 29 * 86400)
    runner = MaintenanceRunner(rig.h.store.database, cimd_stale_max=3600, now=lambda: rig.h.now)
    removed = await runner.run()
    assert removed["browser_snapshots"] == 1
    assert [r.key for r in rig.store.resources(rig.binding_id())] == ["/users/self/todo"]
    # The age is a setting.
    with rig.h.store.database.write() as conn:
        conn.execute(insert(s.settings).values(key="browser_sync.purge_days", value=10, updated_at=1))
    removed = await runner.run()
    assert removed["browser_snapshots"] == 1
    assert rig.store.resources(rig.binding_id()) == []


def test_the_thresholds_are_settings_with_the_documented_defaults(rig: Rig):
    from canvas_mcp.core.selfhost.db.settings_repo import read_settings

    with rig.h.store.database.read() as conn:
        values = read_settings(conn)
    assert (
        values["browser_sync.fresh_hours"],
        values["browser_sync.max_age_days"],
        values["browser_sync.purge_days"],
    ) == (24, 14, 30)


# -- limits on what one binding can hold ------------------------------------------------------------------


def course_list(ids: range | list[int]) -> dict[str, Any]:
    return res("/courses", COURSES, [{"id": i} for i in ids])


def test_a_binding_may_name_at_most_two_hundred_courses(rig: Rig):
    token = rig.pair()
    ok = rig.upload(token, [course_list(range(1, 201))])
    assert ok.json() == {"accepted": 1, "rejected": []}
    # The 201st distinct course is refused, and so is whatever depends on it.
    more = rig.upload(token, [course_list(range(1, 202)), res("/courses/201/quizzes", {}, [])])
    assert more.json() == {
        "accepted": 0,
        "rejected": [
            {"path": "/courses", "reason": "too_many_courses"},
            {"path": "/courses/201/quizzes", "reason": "not_in_plan"},
        ],
    }
    assert len(rig.store.course_ids(rig.binding_id())) == 200


def test_the_cap_counts_courses_across_uploads_and_list_variants(rig: Rig):
    token = rig.pair()
    rig.upload(token, [course_list(range(1, 151))])
    other = res("/courses", ACTIVE_B, [{"id": i} for i in range(1000, 1100)])
    response = rig.upload(token, [other])
    assert response.json()["rejected"] == [{"path": "/courses", "reason": "too_many_courses"}]
    # Ids already known do not count twice.
    same = res("/courses", ACTIVE_B, [{"id": i} for i in range(1, 151)])
    assert rig.upload(token, [same]).json()["accepted"] == 1


def test_a_huge_course_list_is_refused_without_expanding_the_plan(rig: Rig):
    import time

    token = rig.pair()
    started = time.monotonic()
    response = rig.upload(token, [course_list(range(1, 150_001))])
    assert response.status_code == 200, response.text[:200]
    assert response.json()["rejected"] == [{"path": "/courses", "reason": "too_many_courses"}]
    assert time.monotonic() - started < 5
    assert rig.store.course_ids(rig.binding_id()) == set()


def test_the_row_quota_refuses_the_whole_upload(rig: Rig, monkeypatch):
    from canvas_mcp.core.selfhost import browser_store

    monkeypatch.setattr(browser_store, "MAX_SNAPSHOT_ROWS", 3)
    token = rig.pair()
    first = [res("/users/self", {}, {"id": 77}), res("/users/self/todo", {}, []), res("/users/self/groups", {}, [])]
    assert rig.upload(token, first).json()["accepted"] == 3
    refused(rig.upload(token, [res("/users/self/profile", {}, {"id": 77})]), 413, "quota_exceeded")
    # Replacing rows already held is not growth.
    assert rig.upload(token, first, captured_at=rig.h.now - 10).json()["accepted"] == 3
    assert len(rig.store.resources(rig.binding_id())) == 3


def test_the_byte_quota_counts_sealed_bytes_and_leaves_stored_data_alone(rig: Rig, monkeypatch):
    from canvas_mcp.core.selfhost import browser_store

    token = rig.pair()
    assert rig.upload(token, [res("/users/self", {}, {"id": 77, "pad": "a" * 500})]).json()["accepted"] == 1
    monkeypatch.setattr(browser_store, "MAX_SEALED_BYTES", 2000)
    refused(rig.upload(token, [res("/users/self/todo", {}, [{"pad": "b" * 3000}])]), 413, "quota_exceeded")
    [kept] = rig.store.load_path(rig.binding_id(), "/users/self")
    assert kept.body["pad"] == "a" * 500
    assert rig.store.load_path(rig.binding_id(), "/users/self/todo") == []
    # A replacement that fits is allowed, and shrinking frees room.
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 5).json()["accepted"] == 1


def test_the_limits_are_documented():
    from canvas_mcp.core.selfhost import browser_plan, browser_store

    doc = (pathlib.Path(__file__).resolve().parents[2] / "deploy/selfhost/BROWSER-SYNC-DESIGN.md").read_text(encoding="utf-8")
    for value in (browser_plan.MAX_COURSES_PER_BINDING, browser_store.MAX_SNAPSHOT_ROWS):
        assert str(value) in doc
    assert "64 MiB" in doc and browser_store.MAX_SEALED_BYTES == 64 * 1024 * 1024


# -- a failed read does not erase good data ------------------------------------------------------------------


def test_a_transient_failure_never_replaces_a_stored_good_copy(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self/todo", {}, [{"id": 1}])], captured_at=rig.h.now - 100)
    for status in (408, 429, 500, 503, 599):
        failed = rig.upload(
            token, [res("/users/self/todo", {}, None, status=status)], captured_at=rig.h.now - 10
        )
        assert failed.json() == {
            "accepted": 0,
            "rejected": [{"path": "/users/self/todo", "reason": "kept_stored_data"}],
        }, status
    [todo] = rig.store.load_path(rig.binding_id(), "/users/self/todo")
    assert (todo.status, todo.body, todo.captured_at) == (200, [{"id": 1}], int(rig.h.now) - 100)


@pytest.mark.parametrize("status", [400, 401, 403, 404, 410, 422])
def test_an_answer_that_says_no_replaces_the_old_content(rig: Rig, status):
    # Access lost or content deleted: old content must not keep serving for two weeks.
    token = rig.pair()
    rig.upload(token, [res("/users/self/todo", {}, [{"id": 1}])], captured_at=rig.h.now - 100)
    answered = rig.upload(
        token, [res("/users/self/todo", {}, None, status=status)], captured_at=rig.h.now - 10
    )
    assert answered.json() == {"accepted": 1, "rejected": []}
    [todo] = rig.store.load_path(rig.binding_id(), "/users/self/todo")
    assert (todo.status, todo.body) == (status, None)


def test_failures_are_stored_when_nothing_better_is_held_and_later_data_replaces_them(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self", {}, None, status=503)], captured_at=rig.h.now - 20)
    assert rig.store.load_path(rig.binding_id(), "/users/self")[0].status == 503
    rig.upload(token, [res("/users/self", {}, None, status=401)], captured_at=rig.h.now - 10)
    assert rig.store.load_path(rig.binding_id(), "/users/self")[0].status == 401
    rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 1)
    assert rig.store.load_path(rig.binding_id(), "/users/self")[0].status == 200


def test_a_new_term_can_replace_the_course_list_without_hitting_the_cap(rig: Rig):
    token = rig.pair()
    assert rig.upload(token, [course_list(range(1, 151))]).json()["accepted"] == 1
    # Sixty new courses replace the old list: 60 count, not 150 + 60.
    rollover = rig.upload(token, [course_list(range(1000, 1060))], captured_at=rig.h.now - 5)
    assert rollover.json() == {"accepted": 1, "rejected": []}
    assert rig.store.course_ids(rig.binding_id()) == {str(i) for i in range(1000, 1060)}
    # The courses of the new term are plannable at once.
    assert rig.upload(token, [res("/courses/1000/quizzes", {}, [])], captured_at=rig.h.now - 4).json()["accepted"] == 1
    # The old ones are no longer.
    assert rig.upload(token, [res("/courses/5/quizzes", {}, [])], captured_at=rig.h.now - 3).json()["accepted"] == 0


# -- junk claims stay off the write path -----------------------------------------------------------------------


class WriteCounter:
    """Counts every entry to the write path: each takes the process write lock (and, on
    SQLite, BEGIN IMMEDIATE). Reads (`database.read`) are not counted."""

    def __init__(self, database: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        self.opened: list[str] = []
        for name in ("write", "row_write", "write_gate", "best_effort_write"):
            original = getattr(database, name)

            def counted(*a: Any, _name: str = name, _original: Any = original, **k: Any) -> Any:
                self.opened.append(_name)
                return _original(*a, **k)

            monkeypatch.setattr(database, name, counted)


def test_a_junk_claim_opens_no_write_transaction_and_takes_no_write_lock(rig: Rig, monkeypatch):
    counter = WriteCounter(rig.h.store.database, monkeypatch)
    for code in ("ABCDEFGHJKLM", "ZZZZ-ZZZZ-ZZZZ", "abcd efgh jklm"):
        refused(rig.call("POST", "/claim", body={"code": code}), 400, "invalid_code")
    assert counter.opened == []
    # Spent and expired codes are told apart by the same read, also without a write.
    spent = rig.pairing_code()
    assert rig.call("POST", "/claim", body={"code": spent}).status_code == 200
    assert counter.opened, "control: a real claim does write"
    expired = rig.pairing_code()
    rig.h.now += 301
    before = list(counter.opened)
    refused(rig.call("POST", "/claim", body={"code": spent}), 400, "invalid_code")
    refused(rig.call("POST", "/claim", body={"code": expired}), 400, "invalid_code")
    assert counter.opened == before


def test_two_claims_that_both_saw_a_live_code_have_one_winner(rig: Rig, monkeypatch):
    """Both reads see the code unclaimed; the conditional UPDATE inside the write decides."""
    import threading
    from contextlib import contextmanager

    code = rig.pairing_code()
    database = rig.h.store.database
    original = database.read
    barrier = threading.Barrier(2, timeout=10)

    @contextmanager
    def read_then_wait() -> Any:
        with original() as conn:
            yield conn
        barrier.wait()  # neither thread may write before both have read

    monkeypatch.setattr(database, "read", read_then_wait)
    results: list[Any] = []

    def claim() -> None:
        results.append(rig.store.claim(code))

    threads = [threading.Thread(target=claim) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    monkeypatch.undo()
    assert len(results) == 2 and sum(r is not None for r in results) == 1
    with database.read() as conn:
        assert conn.execute(select(func.count()).select_from(s.extension_bindings)).scalar_one() == 1
        assert conn.execute(select(s.extension_pairing_codes.c.claimed_at)).scalar_one() is not None


def test_a_real_claim_still_writes(rig: Rig):
    code = rig.pairing_code()
    assert rig.store.claim(code) is not None
    assert rig.store.claim(code) is None


def test_token_checks_are_reads_only(rig: Rig, monkeypatch):
    token = rig.pair()
    counter = WriteCounter(rig.h.store.database, monkeypatch)
    assert rig.call("GET", "/plan", token=token).status_code == 200
    refused(rig.call("GET", "/plan", token="x" * 43), 401, "invalid_token")
    assert counter.opened == []


# -- the course cap only forgives rows an upload really replaces ----------------------------------------------


def test_an_older_course_list_does_not_free_the_cap(rig: Rig):
    token = rig.pair()
    rig.upload(token, [course_list(range(1, 201))], captured_at=rig.h.now - 10)
    # Same key, older than stored: it replaces nothing, so the stored 200 still count.
    sneaky = rig.upload(token, [course_list(range(1000, 1200))], captured_at=rig.h.now - 500)
    assert sneaky.json()["rejected"] == [{"path": "/courses", "reason": "older_than_stored"}]
    assert rig.store.course_ids(rig.binding_id()) == {str(i) for i in range(1, 201)}
    # Next to it, a different list may not take the room the older one pretended to free.
    other = res("/courses", ACTIVE_B, [{"id": i} for i in range(1000, 1100)])
    both = rig.upload(token, [course_list(range(1000, 1200)), other], captured_at=rig.h.now - 500)
    assert sorted(r["reason"] for r in both.json()["rejected"]) == ["older_than_stored", "too_many_courses"]


def test_several_list_variants_cannot_each_hold_two_hundred_courses(rig: Rig):
    token = rig.pair()
    variants = [COURSES, ACTIVE_B]
    rig.upload(token, [res("/courses", variants[0], [{"id": i} for i in range(1, 201)])], captured_at=rig.h.now - 10)
    for n, query in enumerate(variants[1:], 1):
        ids = [{"id": i} for i in range(n * 1000, n * 1000 + 200)]
        response = rig.upload(token, [res("/courses", query, ids)], captured_at=rig.h.now - 20)
        assert response.json()["rejected"] == [{"path": "/courses", "reason": "too_many_courses"}]
    assert len(rig.store.course_ids(rig.binding_id())) == 200


@pytest.mark.parametrize("status", [429, 500, 503])
def test_a_transient_failure_on_the_course_list_keeps_the_per_course_resources(rig: Rig, status):
    token = rig.pair()
    rig.upload(token, [course_list([101, 102])], captured_at=rig.h.now - 100)
    response = rig.upload(
        token,
        [res("/courses", COURSES, None, status=status), res("/courses/101/quizzes", {}, [])],
        captured_at=rig.h.now - 10,
    )
    assert response.json() == {
        "accepted": 1,
        "rejected": [{"path": "/courses", "reason": "kept_stored_data"}],
    }
    assert rig.store.course_ids(rig.binding_id()) == {"101", "102"}


def test_a_newer_list_replaces_and_frees_the_cap_but_a_failure_does_not(rig: Rig):
    token = rig.pair()
    rig.upload(token, [course_list(range(1, 201))], captured_at=rig.h.now - 100)
    newer = rig.upload(token, [course_list(range(1000, 1200))], captured_at=rig.h.now - 50)
    assert newer.json() == {"accepted": 1, "rejected": []}
    for status in (401, 403, 404):
        failed = rig.upload(token, [res("/courses", COURSES, None, status=status)], captured_at=rig.h.now - 10)
        assert failed.json()["rejected"] == [{"path": "/courses", "reason": "kept_stored_data"}], status
    assert rig.store.course_ids(rig.binding_id()) == {str(i) for i in range(1000, 1200)}
    assert rig.upload(token, [course_list(range(2000, 2200))], captured_at=rig.h.now - 5).json()["accepted"] == 1


def test_a_refused_repeat_of_a_list_does_not_free_the_cap_for_another_variant(rig: Rig):
    token = rig.pair()
    variant_a = COURSES
    variant_b = ACTIVE_B
    rig.upload(token, [res("/courses", variant_a, [{"id": i} for i in range(1, 201)])], captured_at=rig.h.now - 10)
    # A again with 1001 ids (refused: too long) next to B with 200 new ids.
    response = rig.upload(
        token,
        [
            res("/courses", variant_a, [{"id": i} for i in range(5000, 6001)]),
            res("/courses", variant_b, [{"id": i} for i in range(2000, 2200)]),
        ],
        captured_at=rig.h.now - 5,
    )
    assert response.json() == {
        "accepted": 0,
        "rejected": [
            {"path": "/courses", "reason": "too_many_courses"},
            {"path": "/courses", "reason": "too_many_courses"},
        ],
    }
    assert rig.store.course_ids(rig.binding_id()) == {str(i) for i in range(1, 201)}


def test_a_repeat_of_a_refused_list_is_a_duplicate_not_a_second_chance(rig: Rig):
    token = rig.pair()
    big = res("/courses", COURSES, [{"id": i} for i in range(1, 1002)])
    small = course_list([1, 2])
    response = rig.upload(token, [big, small])
    assert [r["reason"] for r in response.json()["rejected"]] == ["too_many_courses", "duplicate_in_upload"]
    assert response.json()["accepted"] == 0


def test_an_invalid_first_copy_does_not_hide_a_valid_second_one(rig: Rig):
    token = rig.pair()
    bad = {"path": "/courses", "query": COURSES, "status": 200, "body": "not a list"}
    response = rig.upload(token, [bad, course_list([1, 2])])
    assert response.json() == {"accepted": 1, "rejected": [{"path": "/courses", "reason": "invalid_resource"}]}
    assert rig.store.course_ids(rig.binding_id()) == {"1", "2"}


# -- only the active enrollments expand the plan ----------------------------------------------------------------


def test_the_plan_marks_exactly_the_active_course_lists_as_the_source(rig: Rig):
    token = rig.pair()
    lists = [r for r in rig.call("GET", "/plan", token=token).json()["resources"] if r["path"] == "/courses"]
    assert len(lists) == 4
    flagged = [r for r in lists if r.get("courseSource")]
    # The active lists without `unpublished`: the unpublished variant never expands.
    assert len(flagged) == 2 and all(r["query"].get("enrollment_state") == "active" for r in flagged)
    assert all("unpublished" not in r["query"].get("state[]", []) for r in flagged)
    unflagged = [r for r in lists if not r.get("courseSource")]
    assert len(unflagged) == 2 and sorted("enrollment_state" in r["query"] for r in unflagged) == [False, True]
    assert not any(r.get("courseSource") for r in rig.call("GET", "/plan", token=token).json()["resources"] if r["path"] != "/courses")


def test_a_past_course_only_in_the_unfiltered_list_gets_no_per_course_resources(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token,
        [
            res("/courses", BARE, [{"id": 101}, {"id": 999}]),  # 999 is concluded
            res("/courses", COURSES, [{"id": 101}]),
            res("/courses/101/quizzes", {}, []),
            res("/courses/999/quizzes", {}, []),
            res("/announcements", {"context_codes[]": ["course_999"], "active_only": "true", **window()}, []),
        ],
    )
    assert response.json() == {
        "accepted": 3,
        "rejected": [
            {"path": "/courses/999/quizzes", "reason": "not_in_plan"},
            {"path": "/announcements", "reason": "not_in_plan"},
        ],
    }
    # The unfiltered list is still stored for the tools that read it.
    assert [c["id"] for c in rig.store.load_path(rig.binding_id(), "/courses")[0].body or []] in ([101, 999], [101])
    assert rig.store.course_ids(rig.binding_id()) == {"101"}


def test_an_unfiltered_list_alone_names_no_courses(rig: Rig):
    token = rig.pair()
    assert rig.upload(token, [res("/courses", BARE, [{"id": 101}])]).json()["accepted"] == 1
    response = rig.upload(token, [res("/courses/101/quizzes", {}, [])])
    assert response.json()["rejected"] == [{"path": "/courses/101/quizzes", "reason": "not_in_plan"}]


def test_the_cap_counts_only_active_ids(rig: Rig):
    token = rig.pair()
    # Hundreds of past courses in the unfiltered list do not use up the cap ...
    past = res("/courses", BARE, [{"id": i} for i in range(5000, 5900)])
    assert rig.upload(token, [past, course_list(range(1, 201))]).json() == {"accepted": 2, "rejected": []}
    assert rig.store.course_ids(rig.binding_id()) == {str(i) for i in range(1, 201)}
    # ... while a 201st active id is still refused.
    over = rig.upload(token, [res("/courses", ACTIVE_B, [{"id": i} for i in range(300, 301)])], captured_at=rig.h.now - 1)
    assert over.json()["rejected"] == [{"path": "/courses", "reason": "too_many_courses"}]


# -- plan v2: tiers, aggregated requests, deterministic chunks ----------------------------------------------------


def test_the_plan_resources_by_tier_and_expansion(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    plan = rig.call("GET", "/plan", token=token).json()
    table = [
        (r["path"], r["tier"], r.get("expand"), r.get("chunk")) for r in plan["resources"]
    ]
    hot = [row for row in table if row[1] == "hot"]
    cold = [row for row in table if row[1] == "cold"]
    assert {row[0] for row in cold} == {
        "/courses/{course_id}/assignments",
        "/courses/{course_id}/assignment_groups",
        "/courses/{course_id}/quizzes",
        "/courses/{course_id}/modules",
        "/courses/{course_id}/front_page",
        "/courses/{course_id}/discussion_topics",
    }
    assert len(cold) == 7 and all(row[2] == "eachCourse" and row[3] is None for row in cold)
    aggregated = [row for row in hot if row[2] is not None]
    assert sorted(aggregated) == [
        ("/announcements", "hot", "courseList", 10),
        ("/calendar_events", "hot", "courseList", 10),
        ("/calendar_events", "hot", "courseList", 10),
    ]
    assert len(hot) == 18  # incl. the two personal calendars, known after the first upload
    assert all(row[2] is None for row in hot if row not in aggregated)


def ids_unsorted(count: int) -> list[int]:
    # Numeric order differs from text order (9 < 10 < 100), and there are duplicates.
    ids = [100, 9, 10, 2, 1, 33, 8, 7, 6, 5, 4, 3, 11, 12]
    return (ids + ids[:3])[: count + 3]


def test_chunks_are_cut_from_sorted_distinct_ids_in_tens():
    ids = [str(i) for i in ids_unsorted(14)]
    keys = lambda order: sorted(  # noqa: E731
        k for k in browser_plan.expected_resources(order, "77") if k.startswith("/announcements?")
    )
    forward, backward = keys(ids), keys(list(reversed(ids)))
    assert forward == backward and len(forward) == 2
    sizes = sorted(len(browser_plan.sorted_course_ids(ids)[i : i + 10]) for i in (0, 10))
    assert sizes == [4, 10]
    assert browser_plan.sorted_course_ids(ids) == ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "33", "100"]


def test_an_upload_must_use_the_servers_chunks(rig: Rig):
    token = rig.pair()
    ids = list(range(1, 13))
    rig.upload(token, [course_list(ids)])

    def announcements(codes: list[int]) -> dict[str, Any]:
        query = {"context_codes[]": [f"course_{c}" for c in codes], "active_only": "true", **window()}
        return res("/announcements", query, [])

    ok = rig.upload(token, [announcements(ids[:10]), announcements(ids[10:])])
    assert ok.json() == {"accepted": 2, "rejected": []}
    odd = rig.upload(token, [announcements(ids[:5]), announcements(ids[5:]), announcements([3, 11, 12]), announcements(ids)])
    assert [r["reason"] for r in odd.json()["rejected"]] == ["not_in_plan"] * 4
    # Re-uploading the same chunk is a replacement, not a second row.
    again = rig.upload(token, [announcements(ids[:10])], captured_at=rig.h.now - 1)
    assert again.json()["accepted"] == 1
    assert sum(r.key.startswith("/announcements") for r in rig.store.resources(rig.binding_id())) == 2


def test_an_upload_of_hot_resources_only_keeps_the_cold_rows(rig: Rig):
    token = rig.pair()
    rig.upload(token, [course_list([101])], captured_at=rig.h.now - 5000)
    cold = rig.upload(
        token,
        [res("/courses/101/assignments", {"include[]": ["all_dates", "checkpoints", "submission"]}, [{"id": 1}]),
         res("/courses/101/quizzes", {}, [{"id": 2}])],
        captured_at=rig.h.now - 5000,
    )
    assert cold.json()["accepted"] == 2
    hot = rig.upload(token, [res("/users/self", {}, {"id": 77}), course_list([101])], captured_at=rig.h.now - 10)
    assert hot.json() == {"accepted": 2, "rejected": []}
    binding = rig.binding_id()
    [quiz] = rig.store.load_path(binding, "/courses/101/quizzes")
    assert quiz.body == [{"id": 2}] and quiz.captured_at == int(rig.h.now) - 5000
    assert len(rig.store.load_path(binding, "/courses/101/assignments")) == 1


def test_a_v1_upload_is_still_understood(rig: Rig):
    token = rig.pair()
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})], planVersion=1).json()["accepted"] == 1
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})], planVersion=2, captured_at=rig.h.now - 1).json()["accepted"] == 1


# -- unpublished courses never expand the plan --------------------------------------------------------------------


UNPUBLISHED = {"enrollment_state": "active", "include[]": ["term"], "state[]": ["available", "unpublished"]}


def calendar_chunk(codes: list[str], kind: str = "event") -> dict[str, Any]:
    query = {"type": kind, "context_codes[]": codes, "excludes[]": ["child_events"], **window()}
    return res("/calendar_events", query, [])


def test_an_unpublished_course_is_left_out_of_the_expansion(rig: Rig):
    token = rig.pair()
    courses = [
        {"id": 101, "workflow_state": "available"},
        {"id": 191436, "workflow_state": "unpublished"},
        {"id": 102},  # no state given: kept
    ]
    assert rig.upload(token, [res("/courses", COURSES, courses)]).json()["accepted"] == 1
    assert rig.store.course_ids(rig.binding_id()) == {"101", "102"}
    response = rig.upload(
        token,
        [
            res("/courses/101/quizzes", {}, []),
            res("/courses/191436/quizzes", {}, []),
            calendar_chunk(["course_101", "course_102"]),
            calendar_chunk(["course_101", "course_102", "course_191436"]),
        ],
    )
    assert response.json()["accepted"] == 2
    assert [r["reason"] for r in response.json()["rejected"]] == ["not_in_plan"] * 2


def test_the_unpublished_variant_is_stored_but_never_expands(rig: Rig):
    token = rig.pair()
    stored = rig.upload(token, [res("/courses", UNPUBLISHED, [{"id": 555, "workflow_state": "available"}])])
    assert stored.json()["accepted"] == 1
    assert rig.store.load_path(rig.binding_id(), "/courses")
    assert rig.store.course_ids(rig.binding_id()) == set()
    refused_ = rig.upload(token, [res("/courses/555/quizzes", {}, [])])
    assert refused_.json()["rejected"] == [{"path": "/courses/555/quizzes", "reason": "not_in_plan"}]


def test_unpublished_courses_do_not_count_toward_the_cap(rig: Rig):
    token = rig.pair()
    mixed = [{"id": i, "workflow_state": "unpublished" if i > 150 else "available"} for i in range(1, 400)]
    assert rig.upload(token, [res("/courses", COURSES, mixed)]).json() == {"accepted": 1, "rejected": []}
    assert len(rig.store.course_ids(rig.binding_id())) == 150


# -- group calendars are planned from the stored groups --------------------------------------------------------------


def group_body(ids: range | list[int]) -> list[dict[str, Any]]:
    return [{"id": i, "name": f"Group {i}"} for i in ids]


def plan_calendars(rig: Rig, token: str) -> list[list[str]]:
    plan = rig.call("GET", "/plan", token=token).json()
    return [
        r["query"]["context_codes[]"]
        for r in plan["resources"]
        if r["path"] == "/calendar_events" and not r.get("expand") and r["query"]["context_codes[]"][0].startswith("group_")
    ]


def test_groups_become_concrete_calendar_resources_after_they_are_synced(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    assert plan_calendars(rig, token) == []
    ids = [100, 9, 10, 2, 1, 33, 8, 7, 6, 5, 4, 3]  # twelve, unsorted
    assert rig.upload(token, [res("/users/self/groups", {}, group_body(ids))]).json()["accepted"] == 1
    calendars = plan_calendars(rig, token)
    first = [f"group_{i}" for i in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)]
    second = ["group_33", "group_100"]
    assert calendars == [first, first, second, second]  # event and assignment, chunks of ten, numeric order
    plan = rig.call("GET", "/plan", token=token).json()
    group_entries = [r for r in plan["resources"] if r["query"].get("context_codes[]", [""])[0].startswith("group_")]
    assert all(r["tier"] == "hot" and "expand" not in r and "{course_id}" not in json.dumps(r) and "{user_id}" not in json.dumps(r) for r in group_entries)


def test_an_upload_must_carry_exactly_the_planned_group_calendars(rig: Rig):
    token = rig.pair()
    rig.sync_courses(token)
    rig.upload(token, [res("/users/self/groups", {}, group_body(range(1, 13)))])
    first = [f"group_{i}" for i in range(1, 11)]
    second = ["group_11", "group_12"]
    ok = rig.upload(token, [calendar_chunk(first), calendar_chunk(second, "assignment")])
    assert ok.json() == {"accepted": 2, "rejected": []}
    odd = rig.upload(
        token,
        [calendar_chunk(["group_1", "group_2"]), calendar_chunk(first + second), calendar_chunk(["group_999"])],
    )
    assert [r["reason"] for r in odd.json()["rejected"]] == ["not_in_plan"] * 3


def test_groups_and_their_calendars_may_arrive_in_one_upload(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token,
        [res("/users/self/groups", {}, group_body([7, 8])), calendar_chunk(["group_7", "group_8"])],
    )
    assert response.json() == {"accepted": 2, "rejected": []}


def test_a_refused_group_list_plans_no_group_calendars(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/users/self/groups", {}, group_body([7]))], captured_at=rig.h.now - 10)
    assert len(plan_calendars(rig, token)) == 2
    failed = rig.upload(token, [res("/users/self/groups", {}, None, status=403)], captured_at=rig.h.now - 5)
    assert failed.json()["rejected"] == [{"path": "/users/self/groups", "reason": "kept_stored_data"}]
    assert len(plan_calendars(rig, token)) == 2  # a failed read does not unplan them
    too_many = rig.upload(token, [res("/users/self/groups", {}, group_body(range(1, 202)))], captured_at=rig.h.now - 1)
    assert too_many.json()["accepted"] == 1
    assert plan_calendars(rig, token) == []


# -- group calendars skip forbidden groups -----------------------------------------------------------------------------


def mixed_groups() -> list[dict[str, Any]]:
    return [
        {"id": 1, "context_type": "Course", "course_id": 101},
        {"id": 2, "context_type": "Course", "course_id": 555},  # a course that is not a source
        {"id": 3, "context_type": "Account", "course_id": None},
        {"id": 4, "context_type": "Course", "course_id": 191436},  # unpublished
    ]


def test_only_groups_of_expanding_courses_and_other_contexts_get_calendars(rig: Rig):
    token = rig.pair()
    courses = [{"id": 101}, {"id": 191436, "workflow_state": "unpublished"}]
    rig.upload(token, [res("/courses", COURSES, courses), res("/users/self/groups", {}, mixed_groups())])
    assert plan_calendars(rig, token) == [["group_1", "group_3"]] * 2
    ok = rig.upload(token, [calendar_chunk(["group_1", "group_3"])])
    assert ok.json()["accepted"] == 1
    bad = rig.upload(token, [calendar_chunk(["group_1", "group_2", "group_3"]), calendar_chunk(["group_4"])])
    assert [r["reason"] for r in bad.json()["rejected"]] == ["not_in_plan"] * 2


def test_groups_and_courses_in_one_upload_agree_with_the_plan(rig: Rig):
    token = rig.pair()
    response = rig.upload(
        token,
        [
            res("/users/self/groups", {}, mixed_groups()),
            res("/courses", COURSES, [{"id": 101}]),
            calendar_chunk(["group_1", "group_3"]),
        ],
    )
    assert response.json() == {"accepted": 3, "rejected": []}


# -- rows that left the plan are deleted, and never served ------------------------------------------------------------


def row_keys(rig: Rig) -> set[str]:
    return {r.key for r in rig.store.resources(rig.binding_id())}


def test_rows_that_left_the_plan_are_deleted_on_the_next_accepted_upload(rig: Rig):
    token = rig.pair()
    both = [{"id": 101}, {"id": 102}]
    rig.upload(
        token,
        [
            res("/courses", COURSES, both),
            res("/courses/101/quizzes", {}, []),
            res("/courses/102/quizzes", {}, []),
            calendar_chunk(["course_101", "course_102"]),
        ],
        captured_at=rig.h.now - 100,
    )
    assert any(k.startswith("/calendar_events") for k in row_keys(rig)) and "/courses/102/quizzes" in row_keys(rig)
    # Course 102 becomes unpublished: its rows and every chunk naming it go.
    rig.upload(
        token,
        [res("/courses", COURSES, [{"id": 101}, {"id": 102, "workflow_state": "unpublished"}])],
        captured_at=rig.h.now - 10,
    )
    keys = row_keys(rig)
    assert "/courses/102/quizzes" not in keys
    assert not any(k.startswith("/calendar_events") for k in keys)
    # Rows still in the plan stay although this upload did not mention them (cold, not due).
    assert "/courses/101/quizzes" in keys


def test_an_upload_never_deletes_rows_only_because_it_left_them_out(rig: Rig):
    token = rig.pair()
    rig.upload(
        token,
        [res("/courses", COURSES, [{"id": 101}]), res("/courses/101/quizzes", {}, [{"id": 1}]),
         res("/courses/101/modules", {"include[]": ["items"]}, []), res("/users/self/todo", {}, [])],
        captured_at=rig.h.now - 5000,
    )
    before = row_keys(rig)
    hot_only = rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 10)
    assert hot_only.json()["accepted"] == 1
    assert row_keys(rig) == before | {"/users/self"}


def test_a_group_of_a_course_that_stops_expanding_loses_its_calendar_rows(rig: Rig):
    token = rig.pair()
    rig.upload(
        token,
        [res("/courses", COURSES, [{"id": 101}]), res("/users/self/groups", {}, mixed_groups()),
         calendar_chunk(["group_1", "group_3"])],
        captured_at=rig.h.now - 100,
    )
    assert any(k.startswith("/calendar_events") for k in row_keys(rig))
    rig.upload(token, [res("/courses", COURSES, [{"id": 7}])], captured_at=rig.h.now - 10)
    assert not any(k.startswith("/calendar_events") for k in row_keys(rig))


def test_a_refused_upload_changes_nothing(rig: Rig):
    token = rig.pair()
    rig.upload(token, [res("/courses", COURSES, [{"id": 101}]), res("/courses/101/quizzes", {}, [])], captured_at=rig.h.now - 100)
    before = row_keys(rig)
    nothing = rig.upload(token, [res("/courses", COURSES, [{"id": 9}])], captured_at=rig.h.now - 500)  # older
    assert nothing.json()["accepted"] == 0
    assert row_keys(rig) == before


# -- a failed course or group list never empties the plan -----------------------------------------------------------


def seed_two_courses(rig: Rig, token: str) -> None:
    rig.upload(
        token,
        [
            res("/courses", COURSES, [{"id": 101}, {"id": 102}]),
            res("/courses/101/quizzes", {}, [{"id": 1}]),
            res("/courses/102/quizzes", {}, [{"id": 2}]),
            res("/courses/102/modules", {"include[]": ["items"]}, []),
            calendar_chunk(["course_101", "course_102"]),
        ],
        captured_at=rig.h.now - 5000,
    )


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_a_failed_course_list_keeps_the_old_list_and_every_per_course_row(rig: Rig, status):
    token = rig.pair()
    seed_two_courses(rig, token)
    before = row_keys(rig)
    for query in (COURSES, ACTIVE_B, BARE):
        res_ = rig.upload(token, [res("/courses", query, None, status=status), res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 10)
        assert res_.json()["accepted"] >= 1
    assert before <= row_keys(rig)
    assert {"/courses/101/quizzes", "/courses/102/quizzes", "/courses/102/modules?include%5B%5D=items"} <= row_keys(rig)
    assert any(k.startswith("/calendar_events") for k in row_keys(rig))
    assert rig.store.course_ids(rig.binding_id()) == {"101", "102"}


def test_a_later_good_list_that_drops_a_course_prunes_its_rows(rig: Rig):
    token = rig.pair()
    seed_two_courses(rig, token)
    rig.upload(token, [res("/courses", COURSES, None, status=403)], captured_at=rig.h.now - 100)
    assert "/courses/102/quizzes" in row_keys(rig)
    rig.upload(token, [res("/courses", COURSES, [{"id": 101}])], captured_at=rig.h.now - 10)
    keys = row_keys(rig)
    assert "/courses/101/quizzes" in keys
    assert not [k for k in keys if k.startswith("/courses/102")]
    assert not any(k.startswith("/calendar_events") for k in keys)  # the chunk named 102


def test_pruning_is_skipped_when_a_list_it_would_use_is_not_good(rig: Rig):
    """Defence in depth: even if a failed list row got stored, nothing is pruned from it."""
    from sqlalchemy import update

    token = rig.pair()
    seed_two_courses(rig, token)
    with rig.h.store.database.write() as conn:
        conn.execute(
            update(s.browser_snapshots)
            .where(s.browser_snapshots.c.resource_key.like("/courses?%"))
            .values(canvas_status=403)
        )
    before = row_keys(rig)
    assert rig.upload(token, [res("/users/self", {}, {"id": 77})], captured_at=rig.h.now - 10).json()["accepted"] == 1
    assert row_keys(rig) == before | {"/users/self"}


# -- a v1 extension after a portal upgrade ----------------------------------------------------------------------


def test_each_course_entries_still_carry_the_v1_flag_and_course_lists_do_not(rig: Rig):
    token = rig.pair()
    resources = rig.call("GET", "/plan", token=token).json()["resources"]
    each = [r for r in resources if r.get("expand") == "eachCourse"]
    lists = [r for r in resources if r.get("expand") == "courseList"]
    assert len(each) == 7 and all(r["perCourse"] is True for r in each)
    assert len(lists) == 3 and not any("perCourse" in r for r in lists)
    assert not any("perCourse" in r for r in resources if r.get("expand") is None)


def test_a_v1_extension_upload_is_accepted(rig: Rig):
    token = rig.pair()
    v1 = rig.upload(
        token,
        [
            res("/courses", COURSES, [{"id": 101}]),
            res("/courses/101/quizzes", {}, []),
            res("/courses/101/assignments", {"include[]": ["all_dates", "checkpoints", "submission"]}, []),
        ],
        planVersion=1,
    )
    assert v1.json() == {"accepted": 3, "rejected": []}
