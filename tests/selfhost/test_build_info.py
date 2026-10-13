"""Released identity survives packaging and cannot be set by operator configuration."""

import json
import subprocess
import sys

import pytest

from canvas_mcp.core.selfhost import build_info as metadata


def test_source_build_is_honestly_dev(monkeypatch):
    monkeypatch.setenv("BUILD_VERSION", "fake-release")
    monkeypatch.setenv("BUILD_COMMIT", "f" * 40)
    assert metadata.build_info() == {
        "version": "dev",
        "commit": "none",
        "built_at": "unknown",
    }


def test_stamp_cli_and_runtime_read_the_same_identity(tmp_path, monkeypatch):
    output = tmp_path / "stamp.json"
    expected = {
        "version": "1.14.0-beta.11",
        "commit": "a" * 40,
        "built_at": "2026-10-13T08:00:00Z",
    }
    subprocess.run(
        [
            sys.executable,
            metadata.__file__,
            "--version",
            expected["version"],
            "--commit",
            expected["commit"],
            "--built-at",
            expected["built_at"],
            "--output",
            str(output),
        ],
        check=True,
    )
    assert json.loads(output.read_text(encoding="utf-8")) == expected
    monkeypatch.setattr(metadata, "STAMP", output)
    assert metadata.build_info() == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "v1\nmalicious"),
        ("version", ""),
        ("commit", "a" * 7),
        ("commit", "none"),
        ("built_at", "2026-10-13T08:00:00+08:00"),
        ("built_at", "2026-02-30T08:00:00Z"),
        ("built_at", "unknown"),
    ],
)
def test_release_requires_closed_provenance(field, value):
    data = {
        "version": "1.14.0-beta.11",
        "commit": "a" * 40,
        "built_at": "2026-10-13T08:00:00Z",
    }
    data[field] = value
    with pytest.raises(ValueError):
        metadata.validate(data)
