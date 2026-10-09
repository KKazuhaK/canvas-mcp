"""Credentials are scrubbed from log lines and audit events."""

from __future__ import annotations

import json
import logging

import pytest

import canvas_mcp.core.audit as audit
from canvas_mcp.core.redact import (
    REDACTED,
    SecretScrubFilter,
    scrub_event,
    scrub_secrets,
    strip_query,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
CANVAS_TOKEN = "7~" + "A1b2C3d4" * 8
ENTRA_REFRESH = "0.AXkA" + "x1Y2z3" * 12
FERNET = "gAAAAAB" + "q" * 40


@pytest.mark.parametrize(
    "text",
    [
        f"Authorization: Bearer {JWT}",
        f"request failed for token {JWT}",
        f"Canvas rejected {CANVAS_TOKEN} with 401",
        f"refresh {ENTRA_REFRESH} was refused",
        f"sealed {FERNET}",
        "GET /auth/callback?code=abcdef0123456789&state=zyxwvu9876543210 HTTP/1.1",
        "https://login.example/token?client_secret=hunter2hunter2&x=1",
        "redirect_uri=https://x/cb&access_token=abc123",
        "postgres://admin:s3cretpass@db.example/app",
        '{"refresh_token": "opaque-refresh-value"}',
    ],
)
def test_credentials_are_replaced(text):
    scrubbed = scrub_secrets(text)
    assert REDACTED in scrubbed
    for secret in (JWT, CANVAS_TOKEN, ENTRA_REFRESH, FERNET, "abcdef0123456789", "zyxwvu9876543210",
                   "hunter2hunter2", "abc123", "s3cretpass", "opaque-refresh-value"):
        assert secret not in scrubbed


@pytest.mark.parametrize(
    "text",
    [
        "HTTP 401 (token rejected)",
        "status_code=404",
        "state=open",
        "code=401",
        "principal entra:11111111-2222-3333-4444-555555555555:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "/courses/***/users/***",
        "ReadTimeout",
    ],
)
def test_ordinary_text_is_left_alone(text):
    assert scrub_secrets(text) == text


def test_emails_are_removed_only_when_asked():
    assert scrub_secrets("user a.b@uci.edu failed") == "user a.b@uci.edu failed"
    assert "uci.edu" not in scrub_secrets("user a.b@uci.edu failed", emails=True)


def test_strip_query_drops_query_and_fragment():
    assert strip_query("/auth/callback?code=x&state=y#frag") == "/auth/callback"


def test_scrub_event_walks_nested_values_and_keeps_other_types():
    event = {"a": f"Bearer {JWT}", "b": ["fine", f"x {CANVAS_TOKEN}"], "c": 3, "d": {"e": f"{JWT}"}}
    scrubbed = scrub_event(event)
    assert scrubbed["c"] == 3
    assert JWT not in json.dumps(scrubbed)
    assert CANVAS_TOKEN not in json.dumps(scrubbed)


class TestLoggingFilter:
    def _record(self, msg, *args, exc=None):
        return logging.LogRecord("canvas_mcp", logging.ERROR, __file__, 1, msg, args, exc)

    def test_message_and_arguments_are_scrubbed(self):
        record = self._record("callback %s failed", "/auth/callback?code=abcdef0123456789&state=zyxwvu9876543210")
        assert SecretScrubFilter().filter(record) is True
        assert "abcdef0123456789" not in record.getMessage()
        assert "zyxwvu9876543210" not in record.getMessage()

    def test_tracebacks_are_scrubbed(self):
        try:
            raise RuntimeError(f"upstream said Bearer {JWT}")
        except RuntimeError:
            import sys

            record = self._record("boom", exc=sys.exc_info())
        SecretScrubFilter().filter(record)
        text = logging.Formatter().format(record)
        assert JWT not in text
        assert "RuntimeError" in text

    def test_the_application_log_handler_carries_the_filter(self):
        from canvas_mcp.core import logging as app_logging

        assert any(isinstance(f, SecretScrubFilter) for f in app_logging.handler.filters)


class TestAuditEvents:
    @pytest.fixture(autouse=True)
    def _reset(self, monkeypatch):
        audit.reset_audit_state()
        monkeypatch.setattr(audit, "_access_events_enabled", True)
        yield
        audit.reset_audit_state()

    @pytest.fixture
    def lines(self, monkeypatch):
        captured: list[str] = []
        monkeypatch.setattr(audit._audit_logger, "info", captured.append)  # noqa: SLF001
        return captured

    def test_endpoint_query_strings_are_dropped(self):
        assert audit._sanitize_endpoint("/courses/12345/users?access_token=abc&x=1") == "/courses/***/users"  # noqa: SLF001
        assert audit._sanitize_endpoint(f"/x/{CANVAS_TOKEN}") == f"/x/{REDACTED}"  # noqa: SLF001

    def test_error_text_is_scrubbed_and_cut_short(self, lines):
        audit.log_data_access(
            "GET", "/courses/1", "error",
            f"HTTPStatusError for https://u:pw@canvas/api?access_token=zzzzzzzz {JWT} a.b@uci.edu " + "x" * 1000,
        )
        (line,) = lines
        event = json.loads(line)
        assert JWT not in line and "zzzzzzzz" not in line and "pw@" not in line and "uci.edu" not in line
        assert len(event["error"]) <= 300

    def test_closed_set_codes_pass_through_unchanged(self, lines):
        audit.log_principal_event("disabled", "entra:t:o", actor="operator", reason="admin_disabled")
        event = json.loads(lines[0])
        assert event["principal"] == "entra:t:o"
        assert event["actor"] == "operator"
        assert event["reason"] == "admin_disabled"

    def test_an_unexpected_field_is_scrubbed_too(self, lines):
        audit._emit({"event_type": "x", "note": f"Bearer {JWT}"})  # noqa: SLF001
        assert JWT not in lines[0]
