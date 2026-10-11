"""Real sessions, HTTP API and mocked outbound HTTP; custody refusals have no effects."""

import base64
import hashlib
import hmac

import httpx
import pytest
from sqlalchemy import select, update

from canvas_mcp.core.selfhost import custody
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.schools import DirectoryEntry

from .stack import ALICE, CANVAS_HOST, SESSION_SECRET, Browser, local_stack

TOKEN = "7~" + "T" * 62


@pytest.fixture
def ceremony(tmp_path, monkeypatch):
    outbound, lookups = [], []

    def canvas(request):
        outbound.append(request)
        return httpx.Response(200, json={"id": "17", "name": "Student"})

    class Directory:
        async def confirm(self, host):
            lookups.append(host)
            return DirectoryEntry(host, "School")

    async def resolve(host):
        return ["8.8.8.8"]

    options = {
        "directory": Directory(),
        "resolve_host": resolve,
        "http_client_factory": lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(canvas)
        ),
    }
    with local_stack(tmp_path, monkeypatch, account_options=options) as stack:
        stack.store._clock = stack.clock
        browser = Browser(stack)
        assert browser.sign_in(ALICE).status_code == 303
        csrf = browser.csrf_token()
        signature = (
            base64.urlsafe_b64encode(
                hmac.new(
                    base64.b64decode(SESSION_SECRET),
                    b"school-pick|" + csrf.encode() + b"|" + CANVAS_HOST.encode(),
                    hashlib.sha256,
                ).digest()
            )
            .decode()
            .rstrip("=")
        )
        body = {
            "canvas_token": TOKEN,
            "school": CANVAS_HOST,
            "school_sig": signature,
            "custody": {"acknowledged": True, "notice_version": 1},
        }
        yield stack, browser, csrf, body, outbound, lookups


def error(response, status, code):
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code


@pytest.mark.parametrize(
    "value,status,code",
    [
        (None, 422, "custody_ack_required"),
        ({"acknowledged": False, "notice_version": 1}, 422, "custody_ack_required"),
        ({"acknowledged": 1, "notice_version": 1}, 422, "custody_ack_required"),
        ({"acknowledged": "true", "notice_version": 1}, 422, "custody_ack_required"),
        ({"acknowledged": True, "notice_version": 0}, 409, "custody_notice_outdated"),
        ({"acknowledged": True, "notice_version": 2}, 409, "custody_notice_outdated"),
        (
            {"acknowledged": True, "notice_version": True},
            409,
            "custody_notice_outdated",
        ),
        ({"acknowledged": True}, 409, "custody_notice_outdated"),
    ],
)
def test_refused_put_has_no_school_row_audit_or_outgoing_request(
    ceremony, value, status, code
):
    stack, browser, csrf, body, outbound, lookups = ceremony
    if value is None:
        del body["custody"]
    else:
        body["custody"] = value
    before = list(stack.store.iter_audit())
    response = browser.api("PUT", "/me/canvas-token", body=body, csrf=csrf)
    error(response, status, code)
    assert outbound == lookups == [] and list(stack.store.iter_audit()) == before
    with stack.store.database.read() as conn:
        assert conn.execute(select(s.canvas_credentials)).first() is None
        assert conn.execute(select(s.canvas_schools)).first() is None


def test_success_replacement_and_delete_require_a_new_acknowledgement(ceremony):
    stack, browser, csrf, body, outbound, _ = ceremony
    assert browser.api("GET", "/me/canvas-token").json()["custody"] == {
        "notice_version": 1,
        "acknowledged_version": None,
        "acknowledged_at": None,
        "current": False,
    }
    first = browser.api("PUT", "/me/canvas-token", body=body, csrf=csrf)
    assert first.status_code == 200, first.text
    assert first.json()["custody"]["current"]
    assert browser.api("GET", "/me").json()["custody_ack_required"] is False
    row = stack.store.info(stack.account_of(ALICE))
    assert (
        row.custody_notice_version == 1
        and abs(row.custody_ack_at - int(stack.clock())) <= 1
    )
    assert (
        browser.api("PUT", "/me/canvas-token", body=body, csrf=csrf).status_code == 200
    )
    entries = list(stack.store.iter_audit())
    assert (
        len(
            [
                entry
                for entry in entries
                if entry.action == "custody_notice_acknowledged"
            ]
        )
        == 2
    )
    assert all(
        entry.detail["custody_notice_version"] == 1
        for entry in entries
        if entry.action in ("token_enrolled", "token_replaced")
    )
    assert len(outbound) == 2
    assert browser.api("DELETE", "/me/canvas-token", csrf=csrf).status_code == 204
    del body["custody"]
    error(
        browser.api("PUT", "/me/canvas-token", body=body, csrf=csrf),
        422,
        "custody_ack_required",
    )
    assert len(outbound) == 2
    assert stack.store.info(stack.account_of(ALICE)) is None


def test_version_bump_can_be_acknowledged_without_decryption_or_generation_change(
    ceremony, monkeypatch
):
    stack, browser, csrf, body, outbound, _ = ceremony
    assert (
        browser.api("PUT", "/me/canvas-token", body=body, csrf=csrf).status_code == 200
    )
    key = stack.account_of(ALICE)
    old = stack.store.info(key)
    before = list(stack.store.iter_audit())
    monkeypatch.setattr(custody, "CUSTODY_NOTICE_VERSION", 2)
    assert browser.api("GET", "/me").json()["custody_ack_required"] is True
    shown = browser.api("GET", "/me/canvas-token").json()["custody"]
    assert shown["notice_version"] == 2 and not shown["current"]
    response = browser.api(
        "POST", "/me/canvas-token/acknowledge", body={"notice_version": 2}, csrf=csrf
    )
    assert response.status_code == 200, response.text
    assert response.json()["custody"]["current"]
    new = stack.store.info(key)
    assert (
        new.credential_generation == old.credential_generation
        and new.credential_id == old.credential_id
    )
    assert len(outbound) == 1
    entry = list(stack.store.iter_audit())[0]
    assert entry.action == "custody_notice_acknowledged" and entry.detail == {
        "old": 1,
        "new": 2,
    }
    assert len(list(stack.store.iter_audit())) == len(before) + 1
    assert (
        browser.api(
            "POST",
            "/me/canvas-token/acknowledge",
            body={"notice_version": 2},
            csrf=csrf,
        ).status_code
        == 200
    )
    assert len(list(stack.store.iter_audit())) == len(before) + 1
    error(
        browser.api(
            "POST",
            "/me/canvas-token/acknowledge",
            body={"notice_version": 1},
            csrf=csrf,
        ),
        409,
        "custody_notice_outdated",
    )


@pytest.mark.parametrize(
    "failure,status,code",
    [
        ("csrf", 403, "csrf_invalid"),
        ("origin", 403, "origin_not_allowed"),
        ("content", 415, "unsupported_media_type"),
        ("stale", 401, "not_authenticated"),
        ("pending", 403, "pending_approval"),
        ("disabled", 401, "not_authenticated"),
    ],
)
def test_acknowledge_access_pipeline(ceremony, failure, status, code):
    stack, browser, csrf, _, outbound, _ = ceremony
    headers = {}
    if failure == "csrf":
        csrf = "wrong"
    elif failure == "origin":
        headers["Origin"] = "https://other.example.com"
    elif failure == "content":
        headers["Content-Type"] = "text/plain"
    elif failure == "stale":
        stack.clock.advance(1000)
    else:
        key = stack.account_of(ALICE)
        with stack.store.database.write() as conn:
            conn.execute(
                update(s.accounts)
                .where(s.accounts.c.id == key)
                .values(
                    status=failure,
                    disabled_at=int(stack.clock()) if failure == "disabled" else None,
                )
            )
    before = list(stack.store.iter_audit())
    response = browser.api(
        "POST",
        "/me/canvas-token/acknowledge",
        body={"notice_version": 1},
        csrf=csrf,
        **headers,
    )
    if failure == "origin":
        # FastMCP's outer host/origin guard rejects before the JSON API runs.
        assert response.status_code == status and response.text == "Forbidden Origin"
    else:
        error(response, status, code)
    assert list(stack.store.iter_audit()) == before and not outbound


def test_acknowledge_requires_an_enrollment(ceremony):
    _, browser, csrf, _, outbound, _ = ceremony
    error(
        browser.api(
            "POST",
            "/me/canvas-token/acknowledge",
            body={"notice_version": 1},
            csrf=csrf,
        ),
        404,
        "not_enrolled",
    )
    assert not outbound
