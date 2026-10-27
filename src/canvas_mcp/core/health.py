"""The unauthenticated liveness probe, shared by every HTTP mode.

``GET /healthz`` answers ``{"ok": true, "version": "<package version>"}`` and
nothing else: no configuration, no tool list, no Canvas URL. The version is
the one in ``pyproject.toml``.
"""

from __future__ import annotations

import json

from .. import __version__

HEALTH_PATH = "/healthz"


def health_body() -> bytes:
    """The JSON body of a healthy response."""
    return json.dumps({"ok": True, "version": __version__}).encode("utf-8")
