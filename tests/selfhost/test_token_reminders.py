"""Real SQL opt-in, durable duplicate control and sealed SMTP configuration."""

import pytest
from sqlalchemy import delete, select, update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.mail import (
    DEFAULTS,
    MailStore,
    email_address,
    validate_config,
)
from canvas_mcp.core.selfhost.token_reminders import ReminderRunner

from .authz.stack import ALICE, OWNER, Browser, local_stack


@pytest.fixture
def running(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch) as stack:
        yield stack


def configure(stack):
    mail = MailStore(stack.store.database, stack.runtime.provider_store.keys)
    config = {
        **DEFAULTS,
        "enabled": True,
        "host": "smtp.example.test",
        "username": "operator",
        "from_email": "canvas@example.test",
    }
    mail.save(
        config,
        password="mail-secret-not-a-token",
        revision=stack.runtime.snapshots.revision(),
        actor=None,
        now=int(stack.clock()),
    )
    return mail


def test_mail_config_is_sealed_redacted_and_preserved_without_password(running):
    mail = configure(running)
    public = mail.public()
    assert public["secret_present"] is True and "password" not in public
    assert "mail-secret-not-a-token" not in repr(public)
    assert "mail-secret-not-a-token" not in repr(mail.load())
    assert mail.load().password == "mail-secret-not-a-token"
    mail.save(
        public["config"],
        password=None,
        revision=public["revision"],
        actor=None,
        now=int(running.clock()),
    )
    assert mail.load().password == "mail-secret-not-a-token"
    assert mail.load().password == "mail-secret-not-a-token"


def test_sender_name_defaults_on_existing_rows_and_saves_without_rewriting_secret(
    running,
):
    mail = configure(running)
    with running.store.database.write() as conn:
        conn.execute(
            delete(s.settings).where(s.settings.c.key == "notifications.sender_name")
        )
        before = dict(conn.execute(select(s.mail_settings)).mappings().one())
    assert "from_name" not in before["config"]
    assert mail.public()["config"]["from_name"] == "Canvas MCP"
    assert mail.load().config["from_name"] == "Canvas MCP"
    public = mail.public()
    config = {**public["config"], "from_name": '  \u6821\u56ed, "Canvas"  '}
    mail.save(
        config,
        password=None,
        revision=public["revision"],
        actor=None,
        now=int(running.clock()),
    )
    fresh = MailStore(running.store.database, running.runtime.provider_store.keys)
    assert fresh.public()["config"]["from_name"] == '\u6821\u56ed, "Canvas"'
    assert fresh.load().config["from_name"] == '\u6821\u56ed, "Canvas"'
    with running.store.database.read() as conn:
        after = dict(conn.execute(select(s.mail_settings)).mappings().one())
        assert (
            conn.execute(
                select(s.settings.c.value).where(
                    s.settings.c.key == "notifications.sender_name"
                )
            ).scalar_one()
            == '\u6821\u56ed, "Canvas"'
        )
    for key in ("config", "key_id", "nonce", "ciphertext"):
        assert after[key] == before[key]


@pytest.mark.parametrize(
    "name", ["\r\nBcc: other@example.test", "A\x00B", "A\u202eB", "A" * 121, None]
)
def test_sender_name_refuses_injected_hidden_and_oversize_values(name):
    with pytest.raises(ValueError):
        validate_config({**DEFAULTS, "from_name": name})


def test_sender_name_blank_resets_to_default():
    assert (
        validate_config({**DEFAULTS, "from_name": "   "})["from_name"] == "Canvas MCP"
    )


def test_sender_name_is_saved_by_governed_owner_api(running):
    browser = Browser(running)
    browser.sign_in(OWNER)
    public = browser.api("GET", "/admin/settings/mail").json()
    assert public["config"]["from_name"] == "Canvas MCP"
    body = {
        "revision": public["revision"],
        "config": {**public["config"], "from_name": "Campus mail"},
        "password": None,
    }
    assert browser.api("PUT", "/admin/settings/mail", body=body).status_code == 403
    saved = browser.api(
        "PUT", "/admin/settings/mail", body=body, csrf=browser.csrf_token()
    )
    assert saved.status_code == 200
    assert saved.json()["config"]["from_name"] == "Campus mail"
    conflict = browser.api(
        "PUT", "/admin/settings/mail", body=body, csrf=browser.csrf_token()
    )
    assert conflict.status_code == 409
    assert (
        browser.api("GET", "/admin/settings/mail").json()["config"]["from_name"]
        == "Campus mail"
    )


@pytest.mark.asyncio
async def test_reminders_require_opt_in_and_only_send_once_per_stage(running):
    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(expiry_source="canvas", access_expires_at=now + 3 * 86400)
        )
    sent = []
    runner = ReminderRunner(
        mail,
        base_url="https://canvas.example.test",
        now=running.clock,
        sender=lambda *args, **kwargs: sent.append((args, kwargs)),
    )
    assert await runner.run() == 0
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="en", epoch=0, now=now
    )
    assert await runner.run() == 1
    assert await runner.run() == 0
    assert len(sent) == 1 and sent[0][0][1] == "alice@example.test"
    assert ALICE.canvas_token not in sent[0][1]["body"]
    assert "https://canvas.example.test/account/token" in sent[0][1]["body"]
    running.clock.advance(4 * 86400)
    assert await runner.run() == 1
    assert await runner.run() == 0
    assert sent[1][1]["subject"] == "Canvas API token expired"


@pytest.mark.asyncio
async def test_disabled_account_and_replaced_generation_are_not_sent(running):
    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="zh", epoch=0, now=now
    )
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(expiry_source="canvas", access_expires_at=now + 86400)
        )
    runner = ReminderRunner(
        mail,
        base_url="https://canvas.example.test",
        now=running.clock,
        sender=lambda *a, **k: pytest.fail("must not send"),
    )
    row = runner.candidates(7)[0]
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.id == row["id"])
            .values(generation=row["generation"] + 1)
        )
    assert runner.claim(row, stage="soon", expiry=row["expiry"]) is None
    with running.store.database.write() as conn:
        conn.execute(
            update(s.accounts)
            .where(s.accounts.c.id == account)
            .values(status="disabled", disabled_at=now)
        )
    assert await runner.run() == 0


@pytest.mark.parametrize(
    "address",
    [
        "a@example.test\r\nBcc:b@example.test",
        "a..b@example.test",
        "a@evil..test",
        "name <a@example.test>",
    ],
)
def test_recipient_refuses_headers_and_malformed_addresses(address):
    with pytest.raises(ValueError):
        email_address(address)


def test_real_api_requires_fresh_owner_for_smtp_and_csrf_for_user_opt_in(running):
    browser = Browser(running)
    browser.sign_in(ALICE)
    assert browser.api("GET", "/admin/settings/mail").status_code == 403
    assert (
        browser.api(
            "PUT",
            "/notifications",
            body={"enabled": True, "email": "a@example.test", "locale": "en"},
        ).status_code
        == 403
    )
    response = browser.api(
        "PUT",
        "/notifications",
        body={"enabled": True, "email": "a@example.test", "locale": "en"},
        csrf=browser.csrf_token(),
    )
    assert response.status_code == 200 and response.json()["enabled"]
    browser.sign_in(OWNER)
    public = browser.api("GET", "/admin/settings/mail").json()
    assert not public["config"]["enabled"]
    running.clock.advance(601)
    assert (
        browser.api("GET", "/admin/settings/mail").json()["error"]["code"]
        == "reauth_required"
    )


@pytest.mark.parametrize("sender_name", ["Canvas MCP", '\u6821\u56ed, "Canvas"', ""])
def test_smtp_uses_verified_starttls_and_auth_before_sending(monkeypatch, sender_name):
    from canvas_mcp.core.selfhost import mail as module
    from canvas_mcp.core.selfhost.mail import SmtpSettings, send_message

    calls = []

    class Smtp:
        def __init__(self, host, port, **options):
            calls.append(("connect", host, port, options["timeout"]))

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def ehlo(self):
            calls.append(("ehlo",))

        def starttls(self, *, context):
            import ssl

            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
            calls.append(("tls",))

        def login(self, user, password):
            assert password == "secret"
            calls.append(("login", user))

        def send_message(self, message):
            from email import policy
            from email.parser import BytesParser

            parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
            assert len(parsed["From"].addresses) == 1
            sender = parsed["From"].addresses[0]
            assert sender.display_name == (sender_name or "Canvas MCP")
            assert sender.addr_spec == "canvas@example.test"
            assert parsed["Bcc"] is None
            calls.append(
                ("message", message["To"], message["Message-ID"], message.get_content())
            )

    monkeypatch.setattr(module.smtplib, "SMTP", Smtp)
    settings = SmtpSettings(
        {
            **DEFAULTS,
            "enabled": True,
            "host": "smtp.example.test",
            "username": "user",
            "from_name": sender_name,
            "from_email": "canvas@example.test",
        },
        "secret",
    )
    send_message(
        settings,
        "recipient@example.test",
        subject="Expiry reminder",
        body="Update your token",
        message_id="fixed-id",
    )
    assert [call[0] for call in calls] == [
        "connect",
        "ehlo",
        "tls",
        "ehlo",
        "login",
        "message",
    ]
    assert calls[-1][1:3] == ("recipient@example.test", "<fixed-id@canvas-mcp.local>")


@pytest.mark.asyncio
async def test_failed_delivery_has_bounded_retries_and_does_not_log_smtp_secrets(
    running, caplog
):
    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="en", epoch=0, now=now
    )
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(expiry_source="canvas", access_expires_at=now + 3 * 86400)
        )
    attempts = []

    def failed(*args, **kwargs):
        attempts.append(1)
        raise RuntimeError("mail-secret-not-a-token alice@example.test")

    runner = ReminderRunner(
        mail, base_url="https://canvas.example.test", now=running.clock, sender=failed
    )
    for _ in range(4):
        assert await runner.run() == 0
        running.clock.advance(3601)
    assert len(attempts) == 3
    assert (
        "mail-secret-not-a-token" not in caplog.text
        and "alice@example.test" not in caplog.text
    )


@pytest.mark.asyncio
async def test_legacy_manual_date_cannot_send_or_claim_reminders(running):
    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="en", epoch=0, now=now
    )
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(
                expiry_source="manual",
                expires_hint_at=now - 3600,
                access_expires_at=now - 3600,
            )
        )
    subjects = []
    runner = ReminderRunner(
        mail,
        base_url="https://canvas.example.test",
        now=running.clock,
        sender=lambda *args, **kwargs: subjects.append(kwargs["subject"]),
    )
    assert runner.candidates(7) == []
    assert await runner.run() == 0
    assert subjects == []
    with running.store.database.read() as conn:
        row = dict(conn.execute(s.canvas_credentials.select()).mappings().first())
    row.update(email="alice@example.test", locale="en")
    assert runner.claim(row, stage="expired", expiry=now - 3600) is None
    running.clock.advance(86400)
    assert await runner.run() == 0
    assert subjects == []


@pytest.mark.asyncio
@pytest.mark.parametrize("source", ["manual", "canvas"])
async def test_unknown_or_explicitly_unlimited_expiry_never_sends(running, source):
    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="en", epoch=0, now=now
    )
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(
                expiry_source=source,
                access_expires_at=None,
                expires_hint_at=now + 86400,
            )
        )
    runner = ReminderRunner(
        mail,
        base_url="https://canvas.example.test",
        now=running.clock,
        sender=lambda *a, **k: pytest.fail("must not send"),
    )
    assert runner.candidates(7) == []
    assert await runner.run() == 0


def test_two_workers_share_one_delivery_claim_and_reject_stale_mail_settings(running):
    from concurrent.futures import ThreadPoolExecutor

    mail = configure(running)
    account = running.enroll(ALICE)
    now = int(running.clock())
    mail.save_preferences(
        account, enabled=True, email="alice@example.test", locale="en", epoch=0, now=now
    )
    with running.store.database.write() as conn:
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == account)
            .values(expiry_source="canvas", access_expires_at=now + 86400)
        )
    runner = ReminderRunner(
        mail, base_url="https://canvas.example.test", now=running.clock
    )
    row = runner.candidates(7)[0]
    settings = mail.load()
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(
            pool.map(
                lambda _: runner.claim(
                    row, stage="soon", expiry=row["expiry"], revision=settings.revision
                ),
                range(2),
            )
        )
    assert sum(claim is not None for claim in claims) == 1
    running.clock.advance(301)
    public = mail.public()
    mail.save(
        public["config"],
        password=None,
        revision=public["revision"],
        actor=None,
        now=int(running.clock()),
    )
    assert (
        runner.claim(
            row, stage="soon", expiry=row["expiry"], revision=settings.revision
        )
        is None
    )


def test_smtp_probe_errors_are_redacted_at_real_api_boundary(running, monkeypatch):
    from canvas_mcp.core.selfhost import mail as module

    configure(running)
    browser = Browser(running)
    browser.sign_in(OWNER)

    def fail(settings):
        raise RuntimeError("mail-secret-not-a-token private@example.test")

    monkeypatch.setattr(module, "probe_smtp", fail)
    result = browser.api("POST", "/admin/settings/mail/test", csrf=browser.csrf_token())
    assert result.status_code == 503
    assert result.json() == {"error": {"code": "mail_unavailable"}}
    assert "mail-secret-not-a-token" not in result.text
