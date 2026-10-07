"""Policy for the fork-only image publishing workflow.

The workflow pushes an image that every self-hosted deployment pulls, so a
future edit that adds a pull-request trigger, widens a token, floats an action
tag or moves the registry login ahead of the smoke test must fail here instead
of shipping. These are policy assertions, not behavior tests.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "selfhost-image.yml"
REPO_GUARD = "github.repository == 'KKazuhaK/canvas-mcp'"

ALLOWED_ACTION_SHAS = {
    "3d3c42e5aac5ba805825da76410c181273ba90b1",  # actions/checkout
    "f87e5991a6d7451dcb8d9637bfbc97413f497069",  # docker/setup-buildx-action
    "dbcb813823bdd20940b903addbd779551569679f",  # docker/login-action
    "dc802804100637a589fabce1cb79ff13a1411302",  # docker/metadata-action
    "c3c9e263c25d99ce0380d002d59b67737d91b0dc",  # docker/build-push-action
    "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",  # actions/upload-artifact
    "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",  # actions/download-artifact
    "4d101475d8b20a2381f78447822ac1eab6504dd8",  # actions/attest-build-provenance
}


@pytest.fixture(scope="module")
def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    # PyYAML follows YAML 1.1, which parses the bare key `on` as boolean True.
    return workflow.get("on", workflow.get(True)) or {}


def _steps(job: dict) -> list[dict]:
    return job["steps"]


def _step_index(job: dict, predicate) -> int:
    for index, step in enumerate(_steps(job)):
        if predicate(step):
            return index
    raise AssertionError("step not found")


def test_triggers_are_the_uci_branch_the_uci_tags_and_manual_runs(workflow):
    triggers = _triggers(workflow)
    assert triggers["push"] == {"branches": ["uci-student"], "tags": ["v*-uci.*"]}
    assert "workflow_dispatch" in triggers
    assert set(triggers) == {"push", "workflow_dispatch"}, (
        "no pull_request or pull_request_target: nothing may run for fork code"
    )


def test_workflow_token_is_read_only(workflow):
    assert workflow["permissions"] == {"contents": "read"}


def test_every_job_is_guarded_to_the_fork(workflow):
    for name, job in workflow["jobs"].items():
        assert REPO_GUARD in str(job.get("if", "")), f"job {name!r} lacks the repository guard"


def test_every_action_is_pinned_to_an_allowlisted_commit(workflow):
    seen = 0
    for name, job in workflow["jobs"].items():
        for step in _steps(job):
            uses = step.get("uses")
            if uses is None:
                continue
            seen += 1
            match = re.fullmatch(r"[\w.-]+/[\w.-]+@([0-9a-f]{40})", uses)
            assert match, f"{name}: {uses!r} is not pinned to a full commit SHA"
            assert match.group(1) in ALLOWED_ACTION_SHAS, f"{name}: {uses!r} is not on the allowlist"
    assert seen >= 8


def test_smoke_test_runs_before_login_and_push(workflow):
    build = workflow["jobs"]["build"]
    smoke = _step_index(build, lambda s: "deploy/selfhost/smoke-test.sh" in str(s.get("run", "")))
    login = _step_index(build, lambda s: str(s.get("uses", "")).startswith("docker/login-action@"))
    push = _step_index(
        build,
        lambda s: str(s.get("uses", "")).startswith("docker/build-push-action@")
        and "push-by-digest=true" in str(s.get("with", {}).get("outputs", "")),
    )
    assert smoke < login < push


def test_the_image_that_is_smoke_tested_is_not_pushed(workflow):
    build = workflow["jobs"]["build"]
    smoke_build = next(
        s
        for s in _steps(build)
        if str(s.get("uses", "")).startswith("docker/build-push-action@") and s["with"].get("load")
    )
    assert smoke_build["with"]["push"] is False
    assert smoke_build["with"]["file"] == "Dockerfile.selfhost"


def test_platforms_are_amd64_and_arm64_on_native_runners(workflow):
    include = workflow["jobs"]["build"]["strategy"]["matrix"]["include"]
    assert {entry["platform"] for entry in include} == {"linux/amd64", "linux/arm64"}
    assert {entry["slug"] for entry in include} == {"amd64", "arm64"}
    arm = next(entry for entry in include if entry["platform"] == "linux/arm64")
    assert arm["runner"] == "ubuntu-24.04-arm"


def test_only_publish_holds_attestation_scopes(workflow):
    for name, job in workflow["jobs"].items():
        permissions = job.get("permissions", {})
        holds = {"id-token", "attestations"} & {k for k, v in permissions.items() if v == "write"}
        if name == "publish":
            assert holds == {"id-token", "attestations"}
        else:
            assert not holds, f"job {name!r} must not hold {sorted(holds)}"


def test_only_build_and_publish_can_write_packages(workflow):
    for name, job in workflow["jobs"].items():
        packages = job.get("permissions", {}).get("packages")
        assert (packages == "write") == (name in {"build", "publish"}), name


def test_no_secret_other_than_github_token_and_no_env_dump(workflow):
    text = WORKFLOW.read_text(encoding="utf-8")
    secrets = set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))
    assert secrets == {"GITHUB_TOKEN"}
    for line in text.splitlines():
        stripped = line.strip()
        assert not re.match(r"(printenv|env|set)\s*($|\|)", stripped), stripped
        assert "set -x" not in stripped


def test_stable_channels_are_only_moved_by_tags(workflow):
    publish = workflow["jobs"]["publish"]
    meta = next(
        s for s in _steps(publish) if str(s.get("uses", "")).startswith("docker/metadata-action@")
    )
    tags = meta["with"]["tags"]
    assert "value=edge,enable=${{ github.ref == 'refs/heads/uci-student' }}" in tags
    latest = next(line for line in tags.splitlines() if "value=latest" in line)
    assert "is_tag == 'true'" in latest and "stable == 'true'" in latest
    beta = next(line for line in tags.splitlines() if "value=beta" in line)
    assert "is_tag == 'true'" in beta
