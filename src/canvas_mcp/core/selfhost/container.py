"""Self-host image entrypoint: initialize private defaults, then exec the server."""

from __future__ import annotations

import os
import sys

from .build_info import build_info
from .db.errors import TokenStoreError
from .runtime_secrets import initialize_secrets
from .settings import SelfhostConfigError


def main() -> None:
    command = sys.argv[1:]
    if not command:
        print("No container command supplied", file=sys.stderr)
        raise SystemExit(2)
    environment = dict(os.environ)
    if (
        command[0] == "canvas-mcp-server"
        and environment.get("MCP_AUTH_MODE") == "selfhost"
    ):
        stamp = build_info()
        print(
            f"Canvas MCP {stamp['version']} commit={stamp['commit']} built={stamp['built_at']}",
            flush=True,
        )
        try:
            environment = initialize_secrets(environment)
        except (SelfhostConfigError, TokenStoreError) as exc:
            print(f"Selfhost startup refused: {exc}", file=sys.stderr)
            raise SystemExit(2) from None
    os.execvpe(command[0], command, environment)


if __name__ == "__main__":
    main()
