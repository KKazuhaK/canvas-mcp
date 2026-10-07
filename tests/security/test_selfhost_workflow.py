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


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """GitHub path filter semantics: ``*`` stays inside a directory, ``**`` does not."""
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + "$")


def test_triggers_are_the_uci_branch_the_uci_tags_and_manual_runs(workflow):
    triggers = _triggers(workflow)
    push = dict(triggers["push"])
    ignored = push.pop("paths-ignore")
    assert push == {"branches": ["uci-student"], "tags": ["v*-uci.*"]}
    # Anything that ends up in the image, or gates it, must still trigger a build.
    for path in (
        "src/canvas_mcp/server.py",
        "pyproject.toml",
        "uv.lock",
        "Dockerfile.selfhost",
        ".dockerignore",
        ".github/workflows/selfhost-image.yml",
        "deploy/selfhost/smoke-test.sh",
    ):
        assert not any(_glob_to_regex(p).match(path) for p in ignored), f"{path} must trigger a build"
    # ...while a docs-only change does not need a multi-arch build.
    assert any(_glob_to_regex(p).match("deploy/selfhost/README.md") for p in ignored)
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


# ----------------------------------------------------------------------------
# Expression syntax. GitHub rejects a workflow that calls an unknown function
# (for example substr) before any job runs, so nothing would ever be built; a
# YAML parse cannot see that. These checks stand in for actionlint.
# ----------------------------------------------------------------------------

EXPRESSION_FUNCTIONS = {
    "contains", "startswith", "endswith", "format", "join", "tojson", "fromjson",
    "hashfiles", "success", "always", "cancelled", "failure",
}
EXPRESSION_CONTEXTS = {
    "github", "env", "vars", "job", "jobs", "steps", "runner", "secrets",
    "strategy", "matrix", "needs", "inputs",
}
EXPRESSION_LITERALS = {"true", "false", "null", "nan", "infinity"}


def _expressions(text: str) -> list[str]:
    found = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        found.extend(re.findall(r"\$\{\{(.*?)\}\}", line))
    return found


def _expression_problems(expression: str) -> list[str]:
    bare = re.sub(r"'(?:[^']|'')*'", "''", expression)  # string literals
    problems = []
    for name in re.findall(r"(?<![\w.-])([A-Za-z_][\w-]*)\s*\(", bare):
        if name.lower() not in EXPRESSION_FUNCTIONS:
            problems.append(f"unknown function {name}()")
    for name in re.findall(r"(?<![\w.\-])([A-Za-z_][\w-]*)(?![\w-])(?!\s*\()", bare):
        if name.lower() not in EXPRESSION_CONTEXTS | EXPRESSION_LITERALS:
            problems.append(f"unknown name {name}")
    return problems


def test_the_expression_checker_catches_what_github_rejects():
    assert _expression_problems("format('edge-{0}', substr(github.sha, 0, 7))") == [
        "unknown function substr()"
    ]
    assert _expression_problems("github.ref == 'refs/heads/x' && startsWith(github.ref, 'refs/tags/v')") == []
    assert _expression_problems("needs.meta.outputs.version != '' && needs.meta.outputs.version") == []
    assert _expression_problems("nope.thing") == ["unknown name nope"]


def test_every_expression_uses_only_functions_and_contexts_github_defines():
    text = WORKFLOW.read_text(encoding="utf-8")
    expressions = _expressions(text)
    assert len(expressions) >= 15, "the expression scan found almost nothing"
    problems = {e.strip(): _expression_problems(e) for e in expressions if _expression_problems(e)}
    assert problems == {}


def test_every_needs_output_that_is_read_is_declared(workflow):
    text = WORKFLOW.read_text(encoding="utf-8")
    for job, output in set(re.findall(r"needs\.([\w-]+)\.outputs\.([\w-]+)", text)):
        declared = workflow["jobs"][job].get("outputs", {})
        assert output in declared, f"needs.{job}.outputs.{output} is read but never declared"


def test_the_image_version_label_is_computed_in_the_meta_job(workflow):
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "label_version" in workflow["jobs"]["meta"]["outputs"]
    assert "needs.meta.outputs.label_version" in text
    assert "substr(" not in text


def test_every_job_only_runs_for_the_branch_or_release_tags_it_publishes(workflow):
    """A manual run from any other ref must not push untagged digests."""
    for name, job in workflow["jobs"].items():
        condition = str(job.get("if", ""))
        assert "refs/heads/uci-student" in condition, name
        assert "startsWith(github.ref, 'refs/tags/v')" in condition, name
