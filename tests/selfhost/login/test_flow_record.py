"""The stored state of a ceremony and the cookie that belongs to it."""

from __future__ import annotations

import json
from typing import Any

import pytest

from canvas_mcp.core.selfhost.login.ceremony import (
    FLOW_COOKIE,
    FLOW_KIND,
    FLOW_TTL_S,
    LINK_KIND,
    FlowCookie,
    FlowRecord,
    binding_digest,
    new_cookie_payload,
)


def record(**kw: Any) -> FlowRecord:
    base: dict[str, Any] = {
        "p": "google",
        "cv": "v" * 64,
        "n": "n" * 43,
        "pp": "sign_in",
        "txn": None,
        "rt": None,
        "rz": False,
        "ru": "https://canvas.example.test/auth/callback/google",
        "la": None,
        "le": None,
        "li": None,
        "iat": 1_800_000_000,
    }
    base.update(kw)
    return FlowRecord(**base)


def test_the_constants() -> None:
    assert (FLOW_KIND, LINK_KIND, FLOW_TTL_S, FLOW_COOKIE) == (
        "login_flow",
        "account_link",
        600,
        "__Host-cmcp_flow",
    )


def test_a_record_round_trips() -> None:
    link = record(
        pp="link",
        la="acct:x",
        le=3,
        li=1_800_000_000,
        txn="t" * 43,
        rt="/account/",
        rz=True,
    )
    assert FlowRecord.from_json(link.to_json()) == link
    assert FlowRecord.from_json(record().to_json()) == record()


def test_a_record_is_small_json_under_the_limit() -> None:
    raw = record().to_json()
    assert len(raw) < 4096 and json.loads(raw)["v"] == 1


def test_even_a_record_with_every_field_at_its_limit_fits() -> None:
    biggest = record(
        p="p" * 64,
        ru="https://x/" + "a" * 2038,
        rt="a" * 512,
        txn="t" * 64,
        cv="c" * 128,
        n="n" * 128,
        pp="link",
        la="a" * 64,
        le=2**40,
        li=2**40,
    )
    assert len(biggest.to_json()) < 4096
    assert FlowRecord.from_json(biggest.to_json()) == biggest


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(v=2),
        lambda d: d.update(pp="other"),
        lambda d: d.update(rz="yes"),
        lambda d: d.update(iat=True),
        lambda d: d.update(iat="now"),
        lambda d: d.update(p=5),
        lambda d: d.update(cv="x" * 129),
        lambda d: d.update(ru="x" * 2049),
        lambda d: d.pop("ru"),
        lambda d: d.update(le="3"),
        lambda d: d.update(txn=5),
        lambda d: d.update(pp="link"),
        lambda d: d.update(pp="link", la="acct:x", le=1),
    ],
)
def test_a_stored_record_that_does_not_fit_is_refused(mutate: Any) -> None:
    data = json.loads(record().to_json())
    mutate(data)
    with pytest.raises(ValueError):
        FlowRecord.from_json(json.dumps(data))


@pytest.mark.parametrize("raw", [b"", b"nope", b"[]", b'"x"', b"\xff"])
def test_garbage_is_refused(raw: bytes) -> None:
    with pytest.raises(ValueError):
        FlowRecord.from_json(raw)


def test_the_binding_digest_is_a_sha256_hex() -> None:
    digest = binding_digest("secret")
    assert (
        len(digest) == 64
        and digest == binding_digest("secret")
        and digest != binding_digest("Secret")
    )


def test_the_cookie_payload_round_trips_and_rejects_the_rest() -> None:
    payload = new_cookie_payload("S" * 43, "B" * 43, "github", 100)
    cookie = FlowCookie.from_payload(payload)
    assert cookie == FlowCookie("S" * 43, "B" * 43, "github", 100, "sign_in")
    for bad in (
        None,
        {},
        {**payload, "v": 2},
        {**payload, "s": ""},
        {**payload, "b": 5},
        {**payload, "p": None},
        {**payload, "iat": True},
        {**payload, "iat": "1"},
    ):
        assert FlowCookie.from_payload(bad) is None
