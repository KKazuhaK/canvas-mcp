"""Operator configuration commands. Schema upgrades belong to db.migrations."""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import TYPE_CHECKING

import anyio

from .login.config import LoginProvidersConfig
from .schools import School, parse_hostname

if TYPE_CHECKING:
    from .config_snapshot import ConfigSnapshots
    from .token_store import TokenStore


def register(sub: argparse._SubParsersAction) -> None:
    providers = sub.add_parser(
        "providers", help="manage database-owned public sign-in names"
    ).add_subparsers(dest="operation", required=True)
    providers.add_parser("list")
    rename = providers.add_parser("rename")
    rename.add_argument("provider")
    rename.add_argument("name")
    providers.add_parser("reset-name").add_argument("provider")
    settings = sub.add_parser(
        "settings", help="manage typed database-owned settings"
    ).add_subparsers(dest="operation", required=True)
    settings.add_parser("get").add_argument("key", nargs="?")
    setter = settings.add_parser("set")
    setter.add_argument("key")
    setter.add_argument("value", help="JSON boolean or integer")
    settings.add_parser("reset").add_argument("key")
    schools = sub.add_parser(
        "schools", help="manage featured schools and private-address exceptions"
    ).add_subparsers(dest="operation", required=True)
    schools.add_parser("list")
    add = schools.add_parser("add")
    add.add_argument("host")
    add.add_argument("--name", default="")
    add.add_argument("--allow-private", action="store_true")
    remove = schools.add_parser("remove")
    remove.add_argument("host")
    remove.add_argument(
        "--confirm-affected",
        action="store_true",
        help="confirm that existing bindings may stop working",
    )
    move = schools.add_parser("move")
    move.add_argument("host")
    move.add_argument("rank", type=int, help="1-based position")
    rename = schools.add_parser("rename")
    rename.add_argument("host")
    rename.add_argument("name")
    private = schools.add_parser("allow-private")
    private.add_argument("host")
    private.add_argument("enabled", choices=("on", "off"))


def snapshots_for(store: TokenStore) -> ConfigSnapshots:
    from .config_snapshot import ConfigSnapshots

    # Headless commands need no IdP secrets. They operate on the provider set
    # last reconciled by a server, including an empty new database.
    return ConfigSnapshots(
        store.database,
        LoginProvidersConfig(order=tuple(sorted(store.recorded_login_providers()))),
    )


def summary(store: TokenStore) -> list[str]:
    snapshot = snapshots_for(store).current
    return [
        f"settings revision: {snapshot.revision}",
        "configured providers: "
        + (", ".join(p.id for p in snapshot.providers if p.configured) or "(none)"),
        f"featured schools: {len(snapshot.schools.featured)}",
        "directory search: " + ("on" if snapshot.schools.search_enabled else "off"),
        f"auth event retention: {snapshot.settings['retention.auth_events_days']} days",
        f"audit retention: {snapshot.settings['retention.audit_days']} days (0 means forever)",
    ]


def run(args: argparse.Namespace, store: TokenStore) -> int:
    from .config_snapshot import school_display_name
    from .config_store import ConfigStore

    snapshots = snapshots_for(store)
    from .profile import read_profile

    config = ConfigStore(snapshots, pilot=read_profile(os.environ) == "pilot")
    current = snapshots.current
    revision, now = current.revision, int(time.time())
    if args.command == "providers":
        if args.operation == "list":
            for provider in current.providers:
                print(
                    f"{provider.id}\t{provider.effective_name}\tconfigured={str(provider.configured).lower()}"
                )
            return 0
        config.names(
            {args.provider: None if args.operation == "reset-name" else args.name},
            revision=revision,
            actor=None,
            now=now,
        )
    elif args.command == "settings":
        if args.operation == "get":
            if args.key is not None and args.key not in current.settings.values:
                raise ValueError("unknown setting")
            for key in [args.key] if args.key else current.settings.values:
                print(f"{key}\t{json.dumps(current.settings[key])}")
            return 0
        value = None if args.operation == "reset" else json.loads(args.value)
        config.setting(
            args.key,
            value,
            revision=revision,
            actor=None,
            now=now,
            reset=args.operation == "reset",
        )
    else:
        if args.operation == "list":
            counts = config.counts([school.host for school in current.schools.featured])
            for rank, school in enumerate(current.schools.featured, 1):
                print(
                    f"{rank}\t{school.host}\t{school.name}\tenrollments={counts[school.host]}\tallow_private={str(school.allow_private).lower()}"
                )
            for school in current.schools.private:
                if current.schools.featured_school(school.host) is None:
                    print(f"-\t{school.host}\t{school.name}\tallow_private=true")
            return 0
        host = parse_hostname(args.host)
        if host is None:
            raise ValueError("invalid school host")
        if args.operation == "allow-private":
            config.allow_private(host, args.enabled == "on", revision=revision, now=now)
        else:
            schools = list(current.schools.featured)
            index = next(
                (i for i, school in enumerate(schools) if school.host == host), None
            )
            if args.operation == "add":
                if index is not None:
                    raise ValueError("school is already featured")
                if args.allow_private:
                    school = School(
                        host,
                        f"https://{host}/api/v1",
                        school_display_name(args.name),
                        True,
                    )
                else:
                    school = anyio.run(config.validate_school, host, args.name)
                schools.append(school)
            else:
                if index is None:
                    raise ValueError("school is not featured")
                school = schools.pop(index)
                if args.operation == "move":
                    if not 1 <= args.rank <= len(schools) + 1:
                        raise ValueError("invalid school rank")
                    schools.insert(args.rank - 1, school)
                elif args.operation == "rename":
                    schools.insert(
                        index,
                        School(
                            school.host,
                            school.api_url,
                            school_display_name(args.name),
                            school.allow_private,
                        ),
                    )
            confirmed = (
                [host] if args.operation == "remove" and args.confirm_affected else []
            )
            config.schools(
                schools,
                revision=revision,
                actor=None,
                now=now,
                confirmed=confirmed,
                grant_private=args.operation == "add" and args.allow_private,
            )
    print(f"settings revision: {snapshots.current.revision}")
    return 0


def refusal(exc: Exception) -> str:
    from .config_store import SchoolRemovalConfirmation
    from .db.settings_repo import SettingsConflict
    from .profile import PilotProfileViolation

    if isinstance(exc, PilotProfileViolation):
        return "SELFHOST_PROFILE=pilot requires one featured school and directory search off"

    if isinstance(exc, SettingsConflict):
        return (
            "configuration changed elsewhere; read the current configuration and retry"
        )
    if isinstance(exc, SchoolRemovalConfirmation):
        return f"removal affects {sum(exc.affected.values())} binding(s); repeat with --confirm-affected after reviewing schools list"
    return "invalid configuration; review the command, types and school address checks"
