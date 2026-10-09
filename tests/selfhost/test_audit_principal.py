"""Audit events name the identity only (no school suffix, no token)."""

import json

import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.credentials import RequestCredentials, set_request_credentials, set_request_principal

from .conftest import OID_A, make_principal


class _Recorder:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def info(self, line: str) -> None:
        self.lines.append(line)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(audit, "_audit_logger", rec)
    return rec


def test_principal_field_is_the_identity_without_the_school(recorder: _Recorder) -> None:
    principal = make_principal(OID_A)
    set_request_principal(principal)
    set_request_credentials(
        RequestCredentials(api_token="a-canvas-token-1234567890", api_url="https://canvas.school-a.edu/api/v1")
    )
    audit._emit({"event_type": "data_access"})
    event = json.loads(recorder.lines[0])
    assert event["principal"] == principal.key
    assert "|" not in event["principal"]
    assert "school-a" not in recorder.lines[0] and "canvas-token" not in recorder.lines[0]


def test_no_principal_field_without_a_verified_identity(recorder: _Recorder) -> None:
    set_request_credentials(
        RequestCredentials(api_token="a-canvas-token-1234567890", api_url="https://canvas.school-a.edu/api/v1")
    )
    audit._emit({"event_type": "data_access"})
    assert "principal" not in json.loads(recorder.lines[0])
