#!/usr/bin/env python3
"""Start the server in legacy HTTP mode and check what a platform depends on.

No Canvas account and no platform: the Canvas URL is a placeholder that is never
contacted, and the token is a dummy. Checks, in order:

* ``GET /healthz`` answers ``{"ok": true, "version": ...}`` without any header,
  although an access key is configured;
* ``/mcp`` refuses a request without ``X-Canvas-Token`` (401);
* ``initialize`` and ``tools/list`` succeed with a dummy token;
* the tool list is not empty and every tool declares ``readOnlyHint`` or both
  ``destructiveHint`` and ``idempotentHint``, plus ``openWorldHint``.

Standard library only; run it from an environment where the package is installed.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "X-Canvas-Token": "dummy-token-for-smoke-test",
    # The legacy HTTP mode refuses to start without an access key.
    "X-MCP-Access-Key": "smoke-test-access-key",
}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def rpc(base: str, method: str, params: dict | None = None, request_id: int = 1) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
    request = urllib.request.Request(f"{base}/mcp", data=body.encode(), headers=HEADERS, method="POST")
    with urllib.request.urlopen(request, timeout=20) as response:
        text = response.read().decode()
    # Streamable HTTP may answer as a single SSE event.
    for line in text.splitlines():
        if line.startswith("data:"):
            text = line[len("data:"):].strip()
            break
    message = json.loads(text)
    if "error" in message:
        raise SystemExit(f"{method} failed: {message['error']}")
    return message["result"]


def wait_for_health(base: str, server: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise SystemExit(f"server exited early with code {server.returncode}")
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=2) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise SystemExit("server did not become healthy within 60s")


def check_annotations(tools: list[dict]) -> list[str]:
    problems = []
    for tool in tools:
        annotations = tool.get("annotations") or {}
        name = tool.get("name")
        if "openWorldHint" not in annotations:
            problems.append(f"{name}: openWorldHint missing")
        if annotations.get("readOnlyHint") is True:
            continue
        for hint in ("destructiveHint", "idempotentHint"):
            if hint not in annotations:
                problems.append(f"{name}: write tool without {hint}")
    return problems


def main() -> int:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CANVAS_", "MCP_"))}
    env["CANVAS_API_URL"] = "https://canvas.invalid/api/v1"
    env["MCP_ACCESS_KEYS"] = HEADERS["X-MCP-Access-Key"]
    server = subprocess.Popen(
        ["canvas-mcp-server", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
    )
    try:
        health = wait_for_health(base, server)
        if set(health) != {"ok", "version"} or health["ok"] is not True or not health["version"]:
            raise SystemExit(f"unexpected /healthz body: {health}")

        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"{base}/mcp",
                    data=b"{}",
                    headers={k: v for k, v in HEADERS.items() if k != "X-Canvas-Token"},
                    method="POST",
                ),
                timeout=10,
            )
        except urllib.error.HTTPError as err:
            if err.code != 401:
                raise SystemExit(f"/mcp without a token answered {err.code}, expected 401") from err
        else:
            raise SystemExit("/mcp without a token was accepted")

        init = rpc(
            base,
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "ci-smoke", "version": "0"},
            },
        )
        print(f"initialize ok: {init.get('serverInfo')}")
        tools = rpc(base, "tools/list", request_id=2)["tools"]
        if not tools:
            raise SystemExit("tools/list returned no tools")
        problems = check_annotations(tools)
        if problems:
            raise SystemExit("annotation problems:\n  " + "\n  ".join(problems))
        print(f"healthz ok (version {health['version']}); {len(tools)} tools, all annotated")
        return 0
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
