"""The smoke test's optional provider section (o), replayed in process, and its static contract.

``deploy/selfhost/smoke-test.sh`` needs Docker. With ``SMOKE_EXPECT_PROVIDERS`` it boots local mode
with made-up Google and GitHub credentials and checks, with curl, that ``/account/api/providers``
lists them and that each start link answers 302 to the provider's own https authorize host. This
file replays those requests against the same app (``Host: 127.0.0.1:18819`` as curl sends it) so an
expectation in the script that the code does not meet fails here, not only in the image build.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
from urllib.parse import urlsplit

import pytest

from ..test_account_spa import make_dist
from .stack_providers import ProviderStack, provider_stack, query_of

SMOKE = pathlib.Path(__file__).resolve().parents[3] / "deploy" / "selfhost" / "smoke-test.sh"
BASE = "http://127.0.0.1:18819"


def script() -> str:
    return SMOKE.read_text(encoding="utf-8")


def section() -> str:
    text = script()
    start = text.index("(o) optional: sign-in providers")
    return text[start : text.index('echo "SMOKE TEST PASSED"')]


class TestTheScript:
    def test_the_syntax_is_valid_bash(self) -> None:
        bash = shutil.which("bash")
        if bash is None:
            pytest.skip("no bash")
        result = subprocess.run([bash, "-n", str(SMOKE)], capture_output=True, text=True, check=False)
        assert result.returncode == 0, result.stderr

    def test_the_section_is_optional_and_comes_last(self) -> None:
        text = script()
        assert text.index("(n) an unknown SELFHOST_AUTH_MODE fails closed") < text.index("(o) optional: sign-in providers")
        assert text.index("(o) optional") < text.index('echo "SMOKE TEST PASSED"')
        assert 'if [ -n "${SMOKE_EXPECT_PROVIDERS:-}" ]; then' in section()
        # The header documents the variable and what it needs.
        header = text[: text.index("set -euo pipefail")]
        assert "SMOKE_EXPECT_PROVIDERS=google,github" in header and "outbound HTTPS" in header

    def test_it_boots_local_mode_with_the_react_app_and_cleans_up(self) -> None:
        body = section()
        for needle in (
            "-e SELFHOST_AUTH_MODE=local",
            "-e ACCOUNT_UI=react",
            '-e "SELFHOST_LOGIN_PROVIDERS=entra${PROVIDER_LIST}"',
            "/account/api/providers",
            "/account/login/${provider}",
            'docker rm -f "$PROVIDERS_C"',
        ):
            assert needle in body, needle
        text = script()
        assert text.count("$PROVIDERS_C") >= 5
        assert '"$LOCAL_REACT" "$PROVIDERS_C" >/dev/null 2>&1 || true' in text  # the cleanup trap
        assert '"$LOCAL_REACT" "$PROVIDERS_C"; do' in text  # the log dump on failure

    def test_it_never_logs_in_and_never_prints_the_secret(self) -> None:
        body = section()
        # Only the start links are requested: no callback, no code, no token.
        assert "/account/callback" not in body and "code_verifier" not in body
        printing = [line for line in body.splitlines() if re.match(r"\s*(echo|printf|ok|cat) ", line)]
        assert printing and not [line for line in printing if "PROVIDER_SECRET" in line]
        assert "smoke-not-real.apps.googleusercontent.com" in body

    def test_an_unsupported_provider_name_fails_the_script(self) -> None:
        assert "SMOKE_EXPECT_PROVIDERS: unsupported provider" in section()
        for name in ("google", "github"):
            assert f"{name})" in section()
        assert "host=\"accounts.google.com\"" in section() and "host=\"github.com\"" in section()


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
    with provider_stack(tmp_path / "app", monkeypatch, providers="entra,google,github", env=env) as stack:
        yield stack


class TestTheReplay:
    def test_the_providers_endpoint_lists_the_expected_providers(self, ps: ProviderStack) -> None:
        doc = ps.stack.client.get(f"{BASE}/account/api/providers").json()
        assert [p["id"] for p in doc["providers"]] == ["entra", "google", "github"]
        for entry in doc["providers"]:
            assert entry["start_url"].startswith("/account/login")
            assert set(entry) == {"id", "kind", "name", "icon", "start_url"}

    @pytest.mark.parametrize(
        ("provider", "host"), [("google", "accounts.google.com"), ("github", "github.com")]
    )
    def test_the_start_link_redirects_to_the_provider_with_pkce_and_a_state(
        self, ps: ProviderStack, provider: str, host: str
    ) -> None:
        response = ps.stack.client.get(f"{BASE}/account/login/{provider}")
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith(f"https://{host}/")
        query = query_of(location)
        for name in ("client_id", "state", "redirect_uri"):
            assert query[name], name
        assert query["code_challenge_method"] == "S256"
        secret = ps.google.client_secret if provider == "google" else ps.github.client_secret
        assert secret not in location
        assert urlsplit(location).scheme == "https"

    def test_the_script_lists_what_the_replay_checks(self) -> None:
        body = section()
        for needle in ('"client_id="', '"state="', '"code_challenge_method=S256"', '"redirect_uri="'):
            assert needle in body, needle
        assert re.search(r'\[ "\$code" = "302" \]', body)
