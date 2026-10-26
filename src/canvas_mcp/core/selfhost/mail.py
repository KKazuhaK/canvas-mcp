"""Database-owned SMTP settings and account notification preferences.

No Canvas token is needed by this service. SMTP secrets use the registered
sealed-column registry, including backup verification and key rotation.
"""

from __future__ import annotations

import hashlib
import re
import smtplib
import ssl
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from email.headerregistry import Address
from email.message import EmailMessage
from typing import Any

from sqlalchemy import delete, insert, select, update

from .config_store import ConfigStore
from .db import schema as s
from .db.engine import Database
from .db.sealed import SEALED, SealKeys
from .db.settings_repo import SettingsAccessDenied, read_settings
from .server_settings import DEFAULT_MAIL_SENDER_NAME, validate_setting

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "host": "",
    "port": 587,
    "security": "starttls",
    "username": "",
    "from_name": DEFAULT_MAIL_SENDER_NAME,
    "from_email": "",
    "reminder_days": 7,
}
SEALED_MAIL = next(entry for entry in SEALED if entry.table is s.mail_settings)


def email_address(value: object, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if not isinstance(value, str) or not 3 <= len(value) <= 254 or not value.isascii():
        raise ValueError("invalid email address")
    if not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?",
        value,
    ):
        raise ValueError("invalid email address")
    local, host = value.rsplit("@", 1)
    if (
        local.startswith(".")
        or local.endswith(".")
        or ".." in value
        or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            for label in host.split(".")
        )
    ):
        raise ValueError("invalid email address")
    return local + "@" + host.lower()


def validate_config(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(DEFAULTS):
        raise ValueError("invalid mail settings")
    config = dict(value)
    config["from_name"] = validate_setting(
        "notifications.sender_name", config["from_name"]
    )
    if (
        type(config["enabled"]) is not bool
        or type(config["port"]) is not int
        or not 1 <= config["port"] <= 65535
    ):
        raise ValueError("invalid mail settings")
    if (
        type(config["reminder_days"]) is not int
        or not 1 <= config["reminder_days"] <= 90
        or not isinstance(config["security"], str)
        or config["security"] not in {"starttls", "tls"}
    ):
        raise ValueError("invalid mail settings")
    for name in ("host", "username", "from_email"):
        text = config[name]
        if (
            not isinstance(text, str)
            or len(text) > 254
            or any(ord(c) < 32 or ord(c) == 127 for c in text)
        ):
            raise ValueError("invalid mail settings")
    host = config["host"]
    if host and (
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host)
        or ".." in host
    ):
        raise ValueError("invalid SMTP host")
    config["from_email"] = email_address(
        config["from_email"], optional=not config["enabled"]
    )
    if config["enabled"] and not host:
        raise ValueError("SMTP host required")
    return config


@dataclass(frozen=True)
class SmtpSettings:
    config: Mapping[str, Any]
    password: str | None = field(default=None, repr=False)
    revision: int = 0


class MailStore:
    def __init__(self, database: Database, keys: SealKeys) -> None:
        self.database = database
        self.keys = keys

    def public(self) -> dict[str, Any]:
        with self.database.read() as conn:
            revision: int = conn.execute(
                select(s.server_state.c.settings_revision)
            ).scalar_one()
            row = conn.execute(select(s.mail_settings)).mappings().first()
            settings = read_settings(conn)
            config = (
                validate_config(
                    {
                        **dict(row["config"]),
                        "from_name": settings["notifications.sender_name"],
                        "reminder_days": settings["notifications.token_reminder_days"],
                    }
                )
                if row
                else {
                    **DEFAULTS,
                    "from_name": settings["notifications.sender_name"],
                    "reminder_days": settings["notifications.token_reminder_days"],
                }
            )
            return {
                "revision": int(revision),
                "config": config,
                "secret_present": bool(row and row["ciphertext"] is not None),
            }

    def load(self) -> SmtpSettings:
        with self.database.read() as conn:
            revision = int(
                conn.execute(select(s.server_state.c.settings_revision)).scalar_one()
            )
            row = conn.execute(select(s.mail_settings)).mappings().first()
            settings = read_settings(conn)
            days = settings["notifications.token_reminder_days"]
            name = settings["notifications.sender_name"]
        if row is None:
            return SmtpSettings(
                {**DEFAULTS, "from_name": name, "reminder_days": days},
                revision=revision,
            )
        password = None
        if row["ciphertext"] is not None:
            password = self.keys.decrypt(
                row["key_id"],
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
                SEALED_MAIL.aad(row),
            ).decode("utf-8")
        return SmtpSettings(
            validate_config(
                {**dict(row["config"]), "from_name": name, "reminder_days": days}
            ),
            password,
            revision,
        )

    def save(
        self,
        config: object,
        *,
        password: object,
        revision: int,
        actor: str | None,
        now: int,
    ) -> int:
        validated = validate_config(config)
        if password is not None and (
            not isinstance(password, str)
            or len(password) > 1024
            or any(ord(c) < 32 for c in password)
        ):
            raise ValueError("invalid SMTP secret")
        with self.database.write() as conn:
            fresh = ConfigStore._authorize(conn, actor, revision, now)
            old = conn.execute(select(s.mail_settings)).mappings().first()
            values: dict[str, Any] = {
                "id": "smtp",
                "config": {
                    key: value
                    for key, value in validated.items()
                    if key not in {"reminder_days", "from_name"}
                },
                "updated_at": now,
                "key_id": None,
                "nonce": None,
                "ciphertext": None,
            }
            if password is None and old:
                for key in ("key_id", "nonce", "ciphertext"):
                    values[key] = old[key]
            elif password:
                kid = self.keys.active_key_id
                kid, nonce, ciphertext = self.keys.encrypt(
                    password.encode("utf-8"),
                    SEALED_MAIL.aad({"id": "smtp", "key_id": kid}),
                )
                values.update(key_id=kid, nonce=nonce, ciphertext=ciphertext)
            if (
                validated["enabled"]
                and validated["username"]
                and values["ciphertext"] is None
            ):
                raise ValueError("SMTP password required")
            for key, value in (
                ("notifications.token_reminder_days", validated["reminder_days"]),
                ("notifications.sender_name", validated["from_name"]),
            ):
                conn.execute(delete(s.settings).where(s.settings.c.key == key))
                conn.execute(
                    insert(s.settings).values(
                        key=key,
                        value=value,
                        updated_at=now,
                        updated_by=actor,
                    )
                )
            if old:
                conn.execute(
                    update(s.mail_settings)
                    .where(s.mail_settings.c.id == "smtp")
                    .values(**values)
                )
            else:
                conn.execute(insert(s.mail_settings).values(**values))
            ConfigStore._audit(
                conn,
                actor,
                now,
                "mail_settings_saved",
                "settings",
                "smtp",
                {
                    "enabled": validated["enabled"],
                    "reminder_days": validated["reminder_days"],
                    "secret_changed": password is not None,
                },
            )
        return fresh

    def preferences(self, account: str) -> dict[str, Any]:
        with self.database.read() as conn:
            row = (
                conn.execute(
                    select(s.notification_preferences).where(
                        s.notification_preferences.c.account_id == account
                    )
                )
                .mappings()
                .first()
            )
        config = self.public()["config"]
        return {
            "enabled": bool(row and row["enabled"]),
            "email": row["email"] if row else "",
            "locale": row["locale"] if row else "en",
            "mail_available": config["enabled"],
            "reminder_days": config["reminder_days"],
        }

    def save_preferences(
        self,
        account: str,
        *,
        enabled: object,
        email: object,
        locale: object,
        epoch: int,
        now: int,
    ) -> None:
        if (
            type(enabled) is not bool
            or not isinstance(locale, str)
            or locale not in {"en", "zh"}
        ):
            raise ValueError("invalid notification preferences")
        address = email_address(email, optional=not enabled)
        with self.database.write() as conn:
            owner = conn.execute(
                select(s.accounts.c.status, s.accounts.c.session_epoch).where(
                    s.accounts.c.id == account
                )
            ).first()
            if not owner or owner.status != "active" or owner.session_epoch != epoch:
                raise SettingsAccessDenied
            conn.execute(
                delete(s.notification_preferences).where(
                    s.notification_preferences.c.account_id == account
                )
            )
            conn.execute(
                insert(s.notification_preferences).values(
                    account_id=account,
                    enabled=enabled,
                    email=address,
                    locale=locale,
                    updated_at=now,
                )
            )
            ConfigStore._audit(
                conn,
                account,
                now,
                "notification_preferences_saved",
                "account",
                account,
                {"enabled": enabled},
            )

    @staticmethod
    def delivery_id(row: Mapping[str, Any], stage: str, expires: int) -> str:
        material = (
            "|".join(str(row[key]) for key in ("id", "generation"))
            + f"|{stage}|{expires}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def send_message(
    settings: SmtpSettings, recipient: str, *, subject: str, body: str, message_id: str
) -> None:
    config = validate_config(dict(settings.config))
    if not config["enabled"]:
        raise ValueError("mail disabled")
    recipient = email_address(recipient)
    message = EmailMessage()
    message["From"] = Address(
        display_name=config["from_name"], addr_spec=config["from_email"]
    )
    message["To"] = recipient
    message["Subject"] = subject
    message["Message-ID"] = f"<{message_id}@canvas-mcp.local>"
    message.set_content(body)
    with authenticated_smtp(settings) as smtp:
        smtp.send_message(message)


@contextmanager
def authenticated_smtp(settings: SmtpSettings) -> Iterator[smtplib.SMTP]:
    config = validate_config(dict(settings.config))
    if not config["enabled"]:
        raise ValueError("mail disabled")
    context = ssl.create_default_context()
    connection = (
        smtplib.SMTP_SSL(config["host"], config["port"], timeout=10, context=context)
        if config["security"] == "tls"
        else smtplib.SMTP(config["host"], config["port"], timeout=10)
    )
    with connection as smtp:
        smtp.ehlo()
        if config["security"] == "starttls":
            smtp.starttls(context=context)
            smtp.ehlo()
        if config["username"]:
            smtp.login(config["username"], settings.password or "")
        yield smtp


def probe_smtp(settings: SmtpSettings) -> None:
    """Test connection, certificate and authentication without sending a message."""
    with authenticated_smtp(settings):
        pass
