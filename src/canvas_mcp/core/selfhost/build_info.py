"""Immutable image identity, stamped at build time rather than operator configuration."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

STAMP = Path(__file__).with_name("_build_info.json")


def validate(data: dict[str, str]) -> dict[str, str]:
    if set(data) != {"version", "commit", "built_at"}:
        raise ValueError("Invalid build metadata fields")
    if data == {"version": "dev", "commit": "none", "built_at": "unknown"}:
        return data
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,79}", data["version"]):
        raise ValueError("Invalid build version")
    if not re.fullmatch(r"[0-9a-f]{40}", data["commit"]):
        raise ValueError("Build commit must be a full Git SHA")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", data["built_at"]):
        raise ValueError("Build time must be UTC RFC3339")
    datetime.strptime(data["built_at"], "%Y-%m-%dT%H:%M:%SZ")
    return data


def build_info() -> dict[str, str]:
    # The root-owned package file travels with the installed wheel. Environment,
    # database settings and the mutable Docker tag cannot change this identity.
    data = json.loads(STAMP.read_text(encoding="utf-8"))
    return validate(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--built-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = validate(
            {"version": args.version, "commit": args.commit, "built_at": args.built_at}
        )
    except ValueError as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(data) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
