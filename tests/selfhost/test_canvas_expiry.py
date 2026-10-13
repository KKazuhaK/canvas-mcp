"""Read-only metadata discovery: bind the response to this exact token and user."""

import httpx
import pytest

from canvas_mcp.core.selfhost.canvas_expiry import fetch_expiry

TOKEN = "123~abcDE" + "x" * 59


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expiry,expected", [("2030-02-03T04:05:06Z", 1896321906), (None, None)]
)
async def test_exact_token_lookup_preserves_real_timestamp_or_no_expiry(
    expiry, expected
):
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200, json={"token_hint": "abcDE", "user_id": 42, "expires_at": expiry}
        )

    result = await fetch_expiry(
        TOKEN,
        "https://canvas.example.edu/api/v1",
        "42",
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(respond)
        ),
    )
    assert result.known and result.expires_at == expected
    assert len(requests) == 1 and requests[0].method == "GET"
    assert (
        str(requests[0].url)
        == "https://canvas.example.edu/api/v1/users/self/tokens/abcDE"
    )
    assert requests[0].headers["Authorization"] == "Bearer " + TOKEN
    assert TOKEN not in str(requests[0].url)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,body",
    [
        (403, {}),
        (404, {}),
        (200, {"user_id": 99, "token_hint": "abcDE", "expires_at": None}),
        (200, {"user_id": 42, "token_hint": "other", "expires_at": None}),
        (200, {"user_id": 42, "token_hint": "abcDE"}),
        (200, {"user_id": 42, "token_hint": "abcDE", "expires_at": "2030-02-03"}),
        (200, {"user_id": 42, "token_hint": "abcDE", "expires_at": False}),
    ],
)
async def test_unsupported_or_unbound_metadata_is_unknown(status, body):
    result = await fetch_expiry(
        TOKEN,
        "https://canvas.example.edu/api/v1",
        "42",
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(status, json=body))
        ),
    )
    assert not result.known and result.expires_at is None


@pytest.mark.asyncio
async def test_redirect_is_not_followed_with_credentials():
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://other.example/tokens"})

    result = await fetch_expiry(
        TOKEN,
        "https://canvas.example.edu/api/v1",
        "42",
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(respond)
        ),
    )
    assert not result.known and len(requests) == 1


def test_binding_reads_real_expiry_without_a_manual_date(tmp_path):
    from .account_fixture import build_harness, sign_in
    from .test_account_api import ACKNOWLEDGED, Api

    h = build_harness(tmp_path)
    sign_in(h)
    h.core._canvas_whoami = h.core._default_whoami
    calls = []

    def respond(request):
        calls.append(request)
        if request.url.path.endswith("/users/self"):
            return httpx.Response(200, json={"id": 42, "name": "Canvas User"})
        return httpx.Response(
            200,
            json={
                "user_id": 42,
                "token_hint": "abcDE",
                "expires_at": "2030-02-03T04:05:06Z",
            },
        )

    h.core._client_factory = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(respond)
    )
    api = Api(h)
    response = api.call(
        "PUT",
        "/me/canvas-token",
        body={
            "canvas_token": TOKEN,
            "custody": ACKNOWLEDGED,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["expiry_source"] == "canvas"
    assert body["expires_on"] == "2030-02-03"
    assert body["expires_at"] == "2030-02-03T04:05:06Z"
    assert len(calls) == 2 and all(request.method == "GET" for request in calls)
    assert TOKEN not in response.text


def test_legacy_manual_date_is_preserved_but_never_displayed_or_used(tmp_path):
    from .account_fixture import CANVAS_TOKEN, KEY, OID, build_harness, put_row, sign_in
    from .test_account_api import Api

    h = build_harness(tmp_path)
    sign_in(h)
    hint = int(h.now) - 86400
    put_row(
        h.store,
        OID,
        token=CANVAS_TOKEN,
        name="Canvas User",
        canvas_user_id="42",
        expires_hint_at=hint,
    )
    response = Api(h).get("/me/canvas-token")
    assert response.status_code == 200
    body = response.json()
    assert body["expiry_source"] == "unknown"
    assert body["expires_on"] is None and body["expires_at"] is None
    assert body["expiry_notice"] == "none"
    assert h.store.info(KEY).expires_hint_at == hint


@pytest.mark.parametrize("known", [False, True])
def test_missing_metadata_and_explicit_no_expiry_are_distinct(tmp_path, known):
    from canvas_mcp.core.selfhost.account_core import CanvasIdentity

    from .account_fixture import CANVAS_TOKEN, build_harness, sign_in
    from .test_account_api import ACKNOWLEDGED, Api

    h = build_harness(tmp_path)
    sign_in(h)
    h.whoami_result = CanvasIdentity("42", "Canvas User", known, None)
    response = Api(h).put(
        "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["expiry_source"] == ("canvas" if known else "unknown")
    assert body["expires_on"] is None and body["expires_at"] is None
    assert body["expiry_notice"] == "none" and body["state"] == "active"


def test_existing_active_token_can_read_expiry_without_replacement_or_revocation(
    tmp_path,
):
    from canvas_mcp.core.selfhost.account_core import CanvasIdentity

    from .account_fixture import CANVAS_TOKEN, KEY, OID, build_harness, put_row, sign_in
    from .test_account_api import Api

    h = build_harness(tmp_path)
    sign_in(h)
    put_row(h.store, OID, token=CANVAS_TOKEN, name="Canvas User", canvas_user_id="42")
    before = h.store.info(KEY)
    standing = h.store.get_principal_status(KEY)
    h.whoami_result = CanvasIdentity("42", "Canvas User", True, 1896321906)
    response = Api(h).post("/me/canvas-token/recheck")
    assert response.status_code == 200, response.text
    canvas = response.json()["canvas"]
    assert (
        canvas["expiry_source"] == "canvas"
        and canvas["expires_at"] == "2030-02-03T04:05:06Z"
    )
    after = h.store.info(KEY)
    assert after.credential_generation == before.credential_generation
    assert after.credential_id == before.credential_id
    assert h.store.get(KEY).api_token == CANVAS_TOKEN
    assert h.store.get_principal_status(KEY).session_epoch == standing.session_epoch
    assert h.whoami_calls == [CANVAS_TOKEN]


def test_active_check_never_writes_metadata_for_a_replaced_token(tmp_path):
    from canvas_mcp.core.selfhost.account_core import CanvasIdentity

    from .account_fixture import CANVAS_TOKEN, KEY, OID, build_harness, put_row, sign_in
    from .test_account_api import NEW_TOKEN, Api

    h = build_harness(tmp_path)
    sign_in(h)
    put_row(h.store, OID, token=CANVAS_TOKEN, name="Canvas User", canvas_user_id="42")

    async def late(token, url):
        put_row(h.store, OID, token=NEW_TOKEN, name="Canvas User", canvas_user_id="42")
        return CanvasIdentity("42", "Canvas User", True, 1896321906)

    h.core._canvas_whoami = late
    response = Api(h).post("/me/canvas-token/recheck")
    assert response.status_code == 200
    assert h.store.get(KEY).api_token == NEW_TOKEN
    assert h.store.info(KEY).expiry_source == "manual"
    assert h.store.info(KEY).access_expires_at is None
