"""The Inbox recipient search must not be a real-name -> pseudonym oracle.

While ``ENABLE_DATA_ANONYMIZATION`` is on, people who are not course staff are
shown only as ``Student_<hash>`` (with their real numeric user ID). Canvas's
``GET /search/recipients`` matches ``search`` against REAL names server-side,
so anything that survives a name search reveals that the name matched.
Returning a classmate's pseudonym or user ID for a real-name search would map
that real name onto the pseudonym the rest of the server shows for them, which
is exactly what anonymization exists to prevent, and a prompt-injected model
could do it for a whole class one name at a time.

These tests drive the real tool through the real Canvas client over a mocked
transport whose address book filters by the search term the way Canvas does
(a case-insensitive match on the person's name).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastmcp import FastMCP

from canvas_mcp.core import client as client_module
from canvas_mcp.core.anonymization import generate_anonymous_id
from canvas_mcp.core.config import reset_config
from canvas_mcp.core.course_policy import reset_policy_cache
from canvas_mcp.tools import student_messaging
from canvas_mcp.tools.student_messaging import (
    register_student_messaging_tools,
    reset_pending_confirmations,
)

COURSE = "123"
API = "/api/v1"

PROF = {"id": 501, "name": "Ada", "full_name": "Ada Lovelace",
        "common_courses": {COURSE: ["TeacherEnrollment"]}}
TA = {"id": 502, "name": "Grace", "full_name": "Grace Hopper",
      "common_courses": {COURSE: ["TaEnrollment"]}}
DESIGNER = {"id": 507, "name": "Margaret", "full_name": "Margaret Hamilton",
            "common_courses": {COURSE: ["DesignerEnrollment"]}}
CLASSMATE = {"id": 503, "name": "Alan", "full_name": "Alan Turing",
             "common_courses": {COURSE: ["StudentEnrollment"]}}
# Shares a first name with the professor.
NAMESAKE = {"id": 504, "name": "Ada", "full_name": "Ada Turing",
            "common_courses": {COURSE: ["StudentEnrollment"]}}
OBSERVER = {"id": 506, "name": "Pat", "full_name": "Pat Observer",
            "common_courses": {COURSE: ["ObserverEnrollment"]}}
# Staff in another course, a student in this one.
STAFF_ELSEWHERE = {"id": 505, "name": "Barbara", "full_name": "Barbara Liskov",
                   "common_courses": {COURSE: ["StudentEnrollment"], "777": ["TeacherEnrollment"]}}

ADDRESS_BOOK = [PROF, TA, DESIGNER, CLASSMATE, NAMESAKE, OBSERVER, STAFF_ELSEWHERE]
NON_STAFF = [CLASSMATE, NAMESAKE, OBSERVER, STAFF_ELSEWHERE]


class AddressBook:
    """Canvas's course address book, with server-side real-name search."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix(API)
        params = request.url.params
        if request.method != "GET":
            return httpx.Response(500, json={"errors": [{"message": "no writes here"}]})
        if path == f"/courses/{COURSE}":
            return httpx.Response(200, json={"id": int(COURSE), "syllabus_body": ""})
        if path == "/search/recipients":
            if "user_id" in params:
                user = next(
                    (u for u in ADDRESS_BOOK if str(u["id"]) == params["user_id"]), None
                )
                return httpx.Response(200, json=[user] if user else [])
            term = params.get("search", "").lower()
            return httpx.Response(200, json=[
                u for u in ADDRESS_BOOK
                if term in u["full_name"].lower() or term in u["name"].lower()
            ])
        return httpx.Response(404, json={"errors": [{"message": f"unrouted {path}"}]})

    def lookups(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == f"{API}/search/recipients"]


@pytest.fixture
def address_book(monkeypatch):
    monkeypatch.setenv("CANVAS_API_URL", "https://canvas.example/api/v1")
    monkeypatch.setenv("CANVAS_API_TOKEN", "synthetic")
    monkeypatch.setenv("ENABLE_DATA_ANONYMIZATION", "true")
    monkeypatch.setenv("STUDENT_WRITE_TOOLS", "send_message")
    monkeypatch.setenv("COURSE_AGENT_POLICY_ENABLED", "false")
    reset_config()
    reset_policy_cache()
    reset_pending_confirmations()
    fake = AddressBook()
    client = httpx.AsyncClient(transport=httpx.MockTransport(fake))
    with patch.object(client_module, "_get_http_client", return_value=client), patch.object(
        student_messaging, "get_course_code", AsyncMock(return_value="ICS33")
    ):
        yield fake
    reset_policy_cache()
    reset_pending_confirmations()


async def _tools() -> dict:
    mcp = FastMCP("recipient-privacy")
    register_student_messaging_tools(mcp)
    return {tool.name: tool.fn for tool in await mcp.list_tools(run_middleware=False)}


async def _find(**kwargs) -> dict:
    tools = await _tools()
    return await tools["find_message_recipients"](COURSE, **kwargs)


def _assert_no_trace_of_non_staff(result: dict) -> None:
    dumped = json.dumps(result)
    returned = {r["user_id"] for r in result.get("recipients", [])}
    for person in NON_STAFF:
        user_id = str(person["id"])
        assert user_id not in returned
        assert generate_anonymous_id(user_id) not in dumped
        assert person["full_name"] not in dumped


@pytest.mark.asyncio
@pytest.mark.parametrize("term", ["Alan Turing", "turing", "ALAN", "Pat Observer", "liskov"])
@pytest.mark.parametrize("role", ["any", "student"])
async def test_real_name_search_returns_no_student_and_no_pseudonym(address_book, term, role):
    result = await _find(search=term, role=role)

    # Canvas really was asked, and its real-name match really hit someone.
    assert [r.url.params["search"] for r in address_book.lookups()] == [term]
    assert result["success"] is True
    assert result["recipients"] == []
    assert result["count"] == 0 and result["total_matches"] == 0
    _assert_no_trace_of_non_staff(result)
    assert "staff" in result["anonymization_note"]


@pytest.mark.asyncio
async def test_search_matching_staff_and_students_returns_only_staff(address_book):
    """"ada" matches the professor and a classmate; only the professor comes back."""
    result = await _find(search="ada")
    assert [r["user_id"] for r in result["recipients"]] == ["501"]
    assert "Ada Lovelace" in result["recipients"][0]["name"]
    assert result["recipients"][0]["roles"] == ["teacher"]
    _assert_no_trace_of_non_staff(result)
    assert "staff" in result["anonymization_note"]


@pytest.mark.asyncio
async def test_broad_search_cannot_enumerate_classmates(address_book):
    """A one-letter search matches nearly everyone; still staff only."""
    result = await _find(search="a")
    assert {r["user_id"] for r in result["recipients"]} == {"501", "502", "507"}
    _assert_no_trace_of_non_staff(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("term,role,expected", [
    ("lovelace", "staff", PROF),
    ("Grace", "any", TA),
    ("hopper", "ta", TA),
    ("hamilton", "staff", DESIGNER),
])
async def test_staff_search_still_works(address_book, term, role, expected):
    result = await _find(search=term, role=role)
    [match] = result["recipients"]
    assert match["user_id"] == str(expected["id"])
    assert match["name"].startswith("<<<UNTRUSTED CANVAS CONTENT")
    assert expected["full_name"] in match["name"]


@pytest.mark.asyncio
async def test_listing_without_search_keeps_pseudonyms(address_book):
    """No search term means no name was matched, so pseudonyms are safe to list."""
    result = await _find()
    names = {r["user_id"]: r["name"] for r in result["recipients"]}
    assert set(names) == {str(u["id"]) for u in ADDRESS_BOOK}
    for person in NON_STAFF:
        assert names[str(person["id"])] == generate_anonymous_id(str(person["id"]))
        assert person["full_name"] not in json.dumps(result)
    assert "search" not in address_book.lookups()[0].url.params


@pytest.mark.asyncio
async def test_search_is_unchanged_when_anonymization_is_off(address_book, monkeypatch):
    monkeypatch.setenv("ENABLE_DATA_ANONYMIZATION", "false")
    reset_config()
    result = await _find(search="turing")
    assert [r["user_id"] for r in result["recipients"]] == ["503", "504"]
    assert "Alan Turing" in result["recipients"][0]["name"]
    assert "Ada Turing" in result["recipients"][1]["name"]
    assert "anonymization_note" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("recipient", ["Alan Turing", "turing", "@turing", "user_503"])
async def test_send_preview_cannot_resolve_a_recipient_by_name(address_book, recipient):
    """send_message takes numeric user IDs only, so a name never reaches Canvas."""
    tools = await _tools()
    result = await tools["send_message"](COURSE, [recipient], "Hi", "Body")
    assert result["nothing_sent"] is True
    assert "not a Canvas user ID" in result["error"]
    assert "preview" not in result
    assert address_book.requests == []


@pytest.mark.asyncio
async def test_send_preview_looks_recipients_up_by_id_never_by_search(address_book):
    """The preview's own lookup is by user_id; it shows the pseudonym the
    caller already had for that ID and adds no name -> ID link."""
    tools = await _tools()
    preview = await tools["send_message"](COURSE, ["501", "503"], "Hi", "Body")
    assert preview["preview"] is True
    lookups = address_book.lookups()
    assert [r.url.params["user_id"] for r in lookups] == ["501", "503"]
    assert all("search" not in r.url.params for r in lookups)
    names = {r["user_id"]: r["name"] for r in preview["recipients"]}
    assert names["503"] == generate_anonymous_id("503")
    assert "Alan Turing" not in json.dumps(preview)
