"""Operator commands for trusted issuers: ``trusted-issuers`` and ``link-federated``/``unlink-federated``."""

from __future__ import annotations

import argparse
import re
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..token_store import TokenStore

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_CONFIG = 2
EXIT_REFUSED = 3

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
COMMANDS = frozenset({"trusted-issuers", "link-federated", "unlink-federated"})


def register(sub: argparse._SubParsersAction) -> None:
    issuers = sub.add_parser(
        "trusted-issuers",
        help="accept access tokens from an external OAuth issuer on /mcp (off until one is added)",
    ).add_subparsers(dest="operation", required=True)
    issuers.add_parser("list", help="the trusted issuers (tab-separated)")
    add = issuers.add_parser("add", help="trust an issuer")
    add.add_argument("issuer", help="the exact issuer string (iss) of its tokens")
    add.add_argument("--name", help="how the account page names it (default: its host)")
    add.add_argument(
        "--audience",
        help="the aud its tokens must carry (default: this server's /mcp URL)",
    )
    add.add_argument(
        "--jwks-url",
        help="where its signing keys are (default: found through its RFC 8414 metadata)",
    )
    add.add_argument(
        "--algorithms",
        help="comma-separated signature algorithms (default: ES256,RS256,PS256,EdDSA)",
    )
    add.add_argument(
        "--allow-typ-jwt",
        action="store_true",
        help="do not require typ at+jwt (Microsoft Entra and Keycloak set typ JWT)",
    )
    add.add_argument(
        "--subject-claim",
        help="the claim that identifies the person (default: sub); never replaced by another",
    )
    add.add_argument(
        "--read-scope",
        help="a scope the token must carry (only ever narrows)",
    )
    add.add_argument(
        "--write-scope",
        help="a scope that write tools need in the token (only ever narrows)",
    )
    remove = issuers.add_parser(
        "remove", help="stop trusting an issuer and end its connections"
    )
    remove.add_argument("issuer")
    links = issuers.add_parser("links", help="the accounts linked to issuers' subjects")
    links.add_argument("--account", help="only this account (UUID)")

    link = sub.add_parser(
        "link-federated",
        help="link an existing account to a subject of a trusted issuer",
    )
    link.add_argument("--account", required=True, help="account UUID")
    link.add_argument("--issuer", required=True)
    link.add_argument("--subject", required=True)
    unlink = sub.add_parser(
        "unlink-federated", help="remove the link of a subject of a trusted issuer"
    )
    unlink.add_argument("--issuer", required=True)
    unlink.add_argument("--subject", required=True)


def _err(message: str) -> int:
    print("error: " + message, file=sys.stderr)
    return EXIT_CONFIG


def run(args: argparse.Namespace, token_store: TokenStore) -> int:
    # Imported here: registering the commands must not need the database extra.
    from .config import IssuerConfigError, build_issuer
    from .store import FederationStore, IssuerExists, LinkRefused

    store = FederationStore(token_store.database)
    if args.command == "link-federated":
        if not _UUID_RE.fullmatch(args.account):
            return _err(
                "--account must be a canonical account UUID printed by 'accounts'"
            )
        try:
            created = store.link(args.account, args.issuer, args.subject)
        except LinkRefused as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        print("linked" if created else "already linked")
        return EXIT_OK
    if args.command == "unlink-federated":
        try:
            gone = store.unlink(args.issuer, args.subject)
        except LinkRefused as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        if not gone:
            print("not found: no such link", file=sys.stderr)
            return EXIT_NOT_FOUND
        print("unlinked")
        return EXIT_OK
    operation = args.operation
    if operation == "list":
        for item in store.list_issuers():
            print(
                "\t".join(
                    [
                        item.issuer,
                        item.label,
                        f"audience={item.audience or '(this server)'}",
                        f"jwks={item.jwks_url or '(metadata)'}",
                        f"algorithms={','.join(item.algorithms)}",
                        f"typ={'at+jwt' if item.require_typ_at_jwt else 'any'}",
                        f"subject={item.subject_claim}",
                        f"read_scope={item.read_scope or '-'}",
                        f"write_scope={item.write_scope or '-'}",
                    ]
                )
            )
        return EXIT_OK
    if operation == "add":
        try:
            issuer = build_issuer(
                args.issuer,
                audience=args.audience,
                jwks_url=args.jwks_url,
                algorithms=args.algorithms,
                require_typ_at_jwt=not args.allow_typ_jwt,
                subject_claim=args.subject_claim,
                read_scope=args.read_scope,
                write_scope=args.write_scope,
                name=args.name,
            )
            store.add_issuer(issuer)
        except IssuerConfigError as exc:
            return _err(str(exc))
        except IssuerExists:
            print("refused: this issuer is already trusted", file=sys.stderr)
            return EXIT_REFUSED
        print("trusted: " + issuer.issuer)
        return EXIT_OK
    if operation == "remove":
        if not store.remove_issuer(args.issuer):
            print("not found: no such trusted issuer", file=sys.stderr)
            return EXIT_NOT_FOUND
        print("removed: " + args.issuer)
        return EXIT_OK
    if args.account is not None and not _UUID_RE.fullmatch(args.account):
        return _err("--account must be a canonical account UUID")
    for account, issuer_name, subject, kind in store.links(args.account):
        print("\t".join([account, issuer_name, subject, kind]))
    return EXIT_OK
