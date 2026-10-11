"""SELFHOST_LOGIN_PROVIDERS and the per-provider variables: every good and bad environment."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from canvas_mcp.core.selfhost.login.config import (
    LoginProvidersConfig,
    OidcConfig,
    blocked_host,
    env_prefix,
    parse_login_providers,
)
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    SelfhostSettings,
    load_selfhost_settings,
)

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
GOOGLE_ID = "1234567890-abcdefghij.apps.googleusercontent.com"
GOOGLE_SECRET = "GOCSPX-google-secret-value-0123"
GITHUB_ID = "Iv1.0123456789abcdef"
GITHUB_SECRET = "github-secret-value-0123456789abcdef"
OIDC_SECRET = "oidc-secret-value-0123456789abcdef"
ISSUER = "https://idp.example.edu/realms/school"
SESSION_SECRET = base64.b64encode(bytes(range(32))).decode()
TOKEN_KEYS = "k1:" + base64.b64encode(bytes(32)).decode()

SECRET_VALUES = (GOOGLE_SECRET, GITHUB_SECRET, OIDC_SECRET, "entra-secret-value-0123456789")


def env(**overrides: str | None) -> dict[str, str]:
    base = {
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "ENTRA_CLIENT_SECRET": "entra-secret-value-0123456789",
        "OAUTH_JWT_SIGNING_KEY": "k" * 48,
        "ACCOUNT_SESSION_SECRET": SESSION_SECRET,
        "CANVAS_TOKEN_KEYS": TOKEN_KEYS,
        "FASTMCP_HOME": "/data/fastmcp",
        "SELFHOST_AUTH_MODE": "local",
    }
    for key, value in overrides.items():
        if value is None:
            base.pop(key, None)
        else:
            base[key] = value
    return base


def google(**extra: str | None) -> dict[str, str | None]:
    return {"GOOGLE_CLIENT_ID": GOOGLE_ID, "GOOGLE_CLIENT_SECRET": GOOGLE_SECRET, **extra}


def github(**extra: str | None) -> dict[str, str | None]:
    return {"GITHUB_CLIENT_ID": GITHUB_ID, "GITHUB_CLIENT_SECRET": GITHUB_SECRET, **extra}


def oidc(slug: str = "school", **extra: str | None) -> dict[str, str | None]:
    prefix = env_prefix(slug)
    return {
        f"{prefix}ISSUER": ISSUER,
        f"{prefix}CLIENT_ID": "canvas-mcp",
        f"{prefix}CLIENT_SECRET": OIDC_SECRET,
        **{f"{prefix}{k}": v for k, v in extra.items()},
    }


def problems(**overrides: str | None) -> list[str]:
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(env(**overrides))
    return info.value.problems


def parse(**overrides: str | None) -> tuple[LoginProvidersConfig, list[str]]:
    found: list[str] = []
    cfg = parse_login_providers(env(**overrides), found, authz_mode="local")
    return cfg, found


def test_entra_only_environment_gives_todays_settings() -> None:
    plain = load_selfhost_settings(env(SELFHOST_AUTH_MODE=None))
    explicit = load_selfhost_settings(env(SELFHOST_AUTH_MODE=None, SELFHOST_LOGIN_PROVIDERS="entra"))
    assert plain.login_providers == LoginProvidersConfig()
    assert plain == explicit
    assert plain.entra_enabled
    assert plain.tenant_id == TENANT and plain.client_id == CLIENT
    # A settings object built by hand (the default factory) is the same Entra-only value.
    assert SelfhostSettings.__dataclass_fields__["login_providers"].default_factory() == LoginProvidersConfig()  # type: ignore[misc]


def test_unset_and_blank_mean_entra() -> None:
    for value in (None, "", "   "):
        cfg, found = parse(SELFHOST_LOGIN_PROVIDERS=value)
        assert found == [] and cfg.order == ("entra",) and cfg.single and not cfg.public


def test_all_providers_parse_in_button_order() -> None:
    cfg, found = parse(
        SELFHOST_LOGIN_PROVIDERS=" GitHub , entra,google,oidc:school ",
        **google(), **github(), **oidc(DISPLAY_NAME="School", SCOPES="openid profile", USERINFO="true",
                                      TOKEN_AUTH_METHOD="client_secret_post"),
    )
    assert found == []
    assert cfg.order == ("github", "entra", "google", "oidc:school")
    assert cfg.linking_enabled and cfg.public and not cfg.single
    assert cfg.non_entra == ("github", "google", "oidc:school")
    assert cfg.google is not None and cfg.google.client_id == GOOGLE_ID
    assert cfg.github is not None and cfg.github.client_id == GITHUB_ID
    assert cfg.oidc == (
        OidcConfig(
            slug="school", issuer=ISSUER, client_id="canvas-mcp", client_secret=OIDC_SECRET,
            display_name="School", scopes=("openid", "profile"),
            token_auth_method="client_secret_post", userinfo=True,
        ),
    )
    assert cfg.issuers() == {"oidc:school": ISSUER}


def test_oidc_defaults_and_trailing_slash_issuer_are_kept_verbatim() -> None:
    issuer = "https://authentik.example.edu/application/o/canvas/"
    cfg, found = parse(
        SELFHOST_LOGIN_PROVIDERS="oidc:my-idp",
        **oidc("my-idp", ISSUER=issuer),
        ENTRA_TENANT_ID=None, ENTRA_CLIENT_ID=None, ENTRA_CLIENT_SECRET=None,
    )
    assert found == []
    only = cfg.oidc[0]
    assert only.issuer == issuer
    assert only.scopes == ("openid", "email", "profile")
    assert only.display_name == "" and only.label == "my-idp"
    assert only.token_auth_method is None and only.userinfo is False
    assert not cfg.entra_enabled


@pytest.mark.parametrize(
    ("value", "fragment"),
    [
        ("facebook", "entry 1 is not entra, google, github or oidc:<slug>"),
        ("entra,entra", "lists a provider twice"),
        (",", "is set but lists no provider"),
        ("oidc:Bad_Slug", "entry 1 has an oidc slug outside a-z, 0-9 and '-'"),
        ("oidc:1abc", "oidc slug"),
        ("oidc:-a", "oidc slug"),
        ("oidc:", "oidc slug"),
        ("oidc:" + "a" * 33, "oidc slug"),
    ],
)
def test_bad_provider_lists_are_refused(value: str, fragment: str) -> None:
    _, found = parse(SELFHOST_LOGIN_PROVIDERS=value)
    assert any(fragment in p and "SELFHOST_LOGIN_PROVIDERS" in p or fragment in p for p in found), found


def test_more_than_eight_providers_is_refused() -> None:
    names = ",".join(f"oidc:p{i}" for i in range(9))
    _, found = parse(SELFHOST_LOGIN_PROVIDERS=names)
    assert any("more than 8 providers" in p for p in found)


def test_other_providers_need_local_mode_and_say_which() -> None:
    found = problems(
        SELFHOST_AUTH_MODE="entra_proxy", SELFHOST_LOGIN_PROVIDERS="entra,google,github,oidc:school",
        **google(), **github(), **oidc(),
    )
    message = next(p for p in found if "need SELFHOST_AUTH_MODE=local" in p)
    assert "google, github, oidc:school" in message and "entra_proxy" in message


def test_unrecognised_entries_are_never_echoed_in_the_local_mode_message() -> None:
    found = problems(
        SELFHOST_AUTH_MODE="entra_proxy", SELFHOST_LOGIN_PROVIDERS="google,hunter2-secret",
        **google(),
    )
    assert not any("hunter2" in p for p in found)


def test_entra_not_listed_refuses_each_entra_variable() -> None:
    found = problems(
        SELFHOST_LOGIN_PROVIDERS="google", **google(),
        ENTRA_REQUIRED_ROLE="Canvas.User", ENTRA_OWNER_ROLE="Canvas.Owner",
        ACCESS_RULES="google:domain:example.edu",
    )
    for name in (
        "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET", "ENTRA_REQUIRED_ROLE", "ENTRA_OWNER_ROLE",
    ):
        assert f"{name} is set but SELFHOST_LOGIN_PROVIDERS does not list entra" in found


def test_entra_not_listed_loads_with_empty_entra_fields() -> None:
    settings = load_selfhost_settings(
        env(
            SELFHOST_LOGIN_PROVIDERS="google,github", ACCESS_RULES="google:domain:example.edu,github:user:42",
            SELFHOST_BOOTSTRAP_OWNER="github:42", MCP_SCOPE="Canvas.Access",
            ENTRA_TENANT_ID=None, ENTRA_CLIENT_ID=None, ENTRA_CLIENT_SECRET=None,
            **google(), **github(),
        )
    )
    assert not settings.entra_enabled
    assert (settings.tenant_id, settings.client_id, settings.client_secret) == ("", "", "")
    assert settings.api_scope == "Canvas.Access"
    assert settings.access_policy.owner_rules == ()
    assert settings.access_policy.bootstrap_owner is not None


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"GOOGLE_CLIENT_ID": None}, "GOOGLE_CLIENT_ID is required"),
        ({"GOOGLE_CLIENT_ID": "12345.example.com"}, "ends with .apps.googleusercontent.com"),
        ({"GOOGLE_CLIENT_SECRET": None}, "GOOGLE_CLIENT_SECRET is required"),
        ({"GOOGLE_CLIENT_SECRET": "short"}, "GOOGLE_CLIENT_SECRET must be at least 16 characters"),
    ],
)
def test_google_variables(overrides: dict[str, Any], fragment: str) -> None:
    _, found = parse(SELFHOST_LOGIN_PROVIDERS="entra,google", **google(**overrides))
    assert any(fragment in p for p in found), found


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"GITHUB_CLIENT_ID": None}, "GITHUB_CLIENT_ID is required"),
        ({"GITHUB_CLIENT_ID": "x"}, "GITHUB_CLIENT_ID must be the client id of a GitHub OAuth App"),
        ({"GITHUB_CLIENT_ID": "has space in it"}, "GITHUB_CLIENT_ID must be"),
        ({"GITHUB_CLIENT_SECRET": None}, "GITHUB_CLIENT_SECRET is required"),
        ({"GITHUB_CLIENT_SECRET": "short"}, "at least 16 characters"),
    ],
)
def test_github_variables(overrides: dict[str, Any], fragment: str) -> None:
    _, found = parse(SELFHOST_LOGIN_PROVIDERS="entra,github", **github(**overrides))
    assert any(fragment in p for p in found), found


@pytest.mark.parametrize(
    ("extra", "fragment"),
    [
        ({"ISSUER": None}, "OIDC_SCHOOL_ISSUER is required"),
        ({"ISSUER": "http://idp.example.edu"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://user:pw@idp.example.edu"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://idp.example.edu/?a=b"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://idp.example.edu/#frag"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://localhost/realm"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://127.0.0.1/realm"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://127.1/realm"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://0x7f000001/realm"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://[::1]/realm"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://169.254.169.254/x"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"ISSUER": "https://" + "a" * 260 + ".test"}, "OIDC_SCHOOL_ISSUER must be the exact https issuer"),
        ({"CLIENT_ID": None}, "OIDC_SCHOOL_CLIENT_ID is required"),
        ({"CLIENT_ID": "has space"}, "OIDC_SCHOOL_CLIENT_ID must be 1 to 255 visible ASCII"),
        ({"CLIENT_SECRET": None}, "OIDC_SCHOOL_CLIENT_SECRET is required"),
        ({"CLIENT_SECRET": "tiny"}, "OIDC_SCHOOL_CLIENT_SECRET must be at least 16"),
        ({"DISPLAY_NAME": "x" * 41}, "OIDC_SCHOOL_DISPLAY_NAME must be"),
        ({"DISPLAY_NAME": "bad\nname"}, "OIDC_SCHOOL_DISPLAY_NAME must be"),
        ({"SCOPES": "profile email"}, "OIDC_SCHOOL_SCOPES must be"),
        ({"SCOPES": " ".join(["openid"] + [f"s{i}" for i in range(10)])}, "OIDC_SCHOOL_SCOPES must be"),
        ({"SCOPES": 'openid "quoted"'}, "OIDC_SCHOOL_SCOPES must be"),
        ({"TOKEN_AUTH_METHOD": "private_key_jwt"}, "OIDC_SCHOOL_TOKEN_AUTH_METHOD must be"),
        ({"USERINFO": "maybe"}, "OIDC_SCHOOL_USERINFO must be true or false"),
    ],
)
def test_oidc_variables(extra: dict[str, Any], fragment: str) -> None:
    _, found = parse(SELFHOST_LOGIN_PROVIDERS="entra,oidc:school", **oidc(**extra))
    assert any(fragment in p for p in found), found


def test_stray_provider_variables_are_refused_by_name() -> None:
    found = problems(
        SELFHOST_LOGIN_PROVIDERS="entra", **google(), **github(), **oidc("other"), ACCESS_RULES=None,
    )
    for name in (
        "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET",
    ):
        assert f"{name} is set but SELFHOST_LOGIN_PROVIDERS does not list" in " ".join(found)
    assert "OIDC_OTHER_ISSUER is set but SELFHOST_LOGIN_PROVIDERS does not list its provider" in found
    assert "OIDC_OTHER_CLIENT_SECRET is set but SELFHOST_LOGIN_PROVIDERS does not list its provider" in found


def test_an_entra_only_deployment_without_the_list_ignores_stray_provider_variables(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Every deployment from before SELFHOST_LOGIN_PROVIDERS existed keeps starting, whatever else a
    # shared environment file holds; the ignored variables are named in the log, never their values.
    stray = {**google(), **github(), **oidc("other")}
    with caplog.at_level("WARNING", logger="canvas_mcp.selfhost.account"):
        settings = load_selfhost_settings(env(**stray))
    assert settings.login_providers.order == ("entra",)
    text = caplog.text
    for name in ("GOOGLE_CLIENT_ID", "GITHUB_CLIENT_SECRET", "OIDC_OTHER_ISSUER"):
        assert f"{name} is set but SELFHOST_LOGIN_PROVIDERS is unset: it is ignored" in text
    for value in stray.values():
        assert value not in text


def test_a_variable_of_another_slug_is_not_mistaken_for_a_listed_one() -> None:
    _, found = parse(
        SELFHOST_LOGIN_PROVIDERS="entra,oidc:ab", **oidc("ab"), OIDC_AB_CD_ISSUER="https://x.example.test"
    )
    assert any(p.startswith("OIDC_AB_CD_ISSUER is set") for p in found)


def test_ci_style_github_variables_are_ignored() -> None:
    cfg, found = parse(
        GITHUB_TOKEN="ghs_ci_token_value_0123456789", GITHUB_ACTIONS="true", GITHUB_REPOSITORY="a/b",
        GITHUB_RUN_ID="1", GITHUB_SHA="deadbeef",
    )
    assert found == [] and cfg == LoginProvidersConfig()


def test_secrets_never_appear_in_problems_or_reprs() -> None:
    cfg, found = parse(
        SELFHOST_LOGIN_PROVIDERS="entra,google,github,oidc:school",
        **google(GOOGLE_CLIENT_ID="bad"), **github(), **oidc(ISSUER="http://insecure.example.edu"),
    )
    assert found
    blob = " ".join(found) + repr(cfg)
    settings = load_selfhost_settings(
        env(SELFHOST_LOGIN_PROVIDERS="entra,google,github,oidc:school", **google(), **github(), **oidc())
    )
    blob += repr(settings) + str(settings.login_providers)
    for secret in SECRET_VALUES:
        assert secret not in blob
    assert "client_secret" not in repr(settings.login_providers.google).replace("client_secret=", "")


def test_open_policy_with_a_public_provider_needs_the_acknowledgement() -> None:
    base = dict(SELFHOST_LOGIN_PROVIDERS="entra,google", ACCESS_POLICY="open", **google())
    found = problems(**base)
    assert any("admits anyone who has such an account" in p and "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC" in p for p in found)
    settings = load_selfhost_settings(env(**base, ACCESS_OPEN_ACKNOWLEDGE_PUBLIC="true"))
    assert settings.access_policy.mode == "open" and settings.access_policy.ack_public
    # Entra alone stays unenforced, as before.
    assert load_selfhost_settings(env(ACCESS_POLICY="open")).access_policy.mode == "open"


def test_rules_are_required_without_entra() -> None:
    found = problems(
        SELFHOST_LOGIN_PROVIDERS="google", **google(),
        ENTRA_TENANT_ID=None, ENTRA_CLIENT_ID=None, ENTRA_CLIENT_SECRET=None,
    )
    assert any(
        "ACCESS_RULES is required with ACCESS_POLICY=rules when SELFHOST_LOGIN_PROVIDERS does not list entra" in p
        for p in found
    )


def test_a_rule_of_a_provider_that_is_not_listed_is_refused() -> None:
    found = problems(ACCESS_RULES="github:org:acme")
    assert any("ACCESS_RULES entry 1 names the provider 'github', which is not enabled in this release" in p for p in found)
    found = problems(ACCESS_RULES="oidc:school:any")
    assert any("'oidc:school'" in p and "SELFHOST_LOGIN_PROVIDERS" in p for p in found)


def test_owner_rules_stay_entra_only() -> None:
    found = problems(
        SELFHOST_LOGIN_PROVIDERS="entra,google", OWNER_RULES="google:email:boss@example.edu", **google()
    )
    assert any(
        "OWNER_RULES entry 1 names google: owners come only from Entra app roles or groups" in p
        and "SELFHOST_BOOTSTRAP_OWNER or token_admin" in p
        for p in found
    )


@pytest.mark.parametrize(
    ("value", "providers", "ok"),
    [
        (f"entra:{TENANT}:aaaaaaaa-0000-4000-8000-00000000000a", "entra", True),
        ("google:1234567890", "entra,google", True),
        ("github:12345", "entra,github", True),
        ("oidc:school:user-1", "entra,oidc:school", True),
        ("token_admin", "entra,google", True),
        ("google:1234567890", "entra", False),
        ("github:0", "entra,github", False),
        ("github:octocat", "entra,github", False),
        ("google:", "entra,google", False),
        ("oidc:school:", "entra,oidc:school", False),
        ("oidc:school:a b", "entra,oidc:school", False),
        ("oidc:other:sub", "entra,oidc:school", False),
        ("nonsense", "entra,google", False),
    ],
)
def test_bootstrap_owner_grammar(value: str, providers: str, ok: bool) -> None:
    extra: dict[str, str | None] = {"SELFHOST_BOOTSTRAP_OWNER": value, "SELFHOST_LOGIN_PROVIDERS": providers}
    if "google" in providers:
        extra.update(google())
    if "github" in providers:
        extra.update(github())
    if "oidc" in providers:
        extra.update(oidc())
    if ok:
        settings = load_selfhost_settings(env(**extra))
        policy = settings.access_policy
        assert (policy.bootstrap_owner is not None) != policy.bootstrap_via_token_admin
    else:
        found = problems(**extra)
        assert any("SELFHOST_BOOTSTRAP_OWNER" in p for p in found), found
        assert not any("oidc:other:sub" == p or "nonsense" in p for p in found)


def test_bootstrap_issuers() -> None:
    settings = load_selfhost_settings(
        env(SELFHOST_LOGIN_PROVIDERS="entra,oidc:school", SELFHOST_BOOTSTRAP_OWNER="oidc:school:abc", **oidc())
    )
    boot = settings.access_policy.bootstrap_owner
    assert boot is not None and (boot.provider_id, boot.issuer, boot.subject) == ("oidc:school", ISSUER, "abc")
    settings = load_selfhost_settings(
        env(SELFHOST_LOGIN_PROVIDERS="entra,google", SELFHOST_BOOTSTRAP_OWNER="google:sub_1-x", **google())
    )
    boot = settings.access_policy.bootstrap_owner
    assert boot is not None and boot.issuer == "https://accounts.google.com" and boot.subject == "sub_1-x"
    settings = load_selfhost_settings(
        env(SELFHOST_LOGIN_PROVIDERS="entra,github", SELFHOST_BOOTSTRAP_OWNER="github:583231", **github())
    )
    boot = settings.access_policy.bootstrap_owner
    assert boot is not None and boot.issuer == "https://github.com"


def test_link_by_verified_email_is_reserved() -> None:
    for value in ("true", "1", "yes", "on"):
        found = problems(ACCOUNT_LINK_BY_VERIFIED_EMAIL=value)
        assert any(
            "ACCOUNT_LINK_BY_VERIFIED_EMAIL is reserved and not implemented; leave it unset" in p for p in found
        )
    # Saying "no" (or nothing) is what the server does anyway.
    for value in ("", "false", "False", "0", "no", "off"):
        load_selfhost_settings(env(ACCOUNT_LINK_BY_VERIFIED_EMAIL=value))


def test_more_than_ten_github_membership_rules_are_refused() -> None:
    rules = ",".join(f"github:org:org{i}" for i in range(11))
    found = problems(SELFHOST_LOGIN_PROVIDERS="entra,github", ACCESS_RULES=rules, **github())
    assert any("more than 10 github:org and github:team rules" in p for p in found)


@pytest.mark.parametrize(
    ("host", "blocked"),
    [
        ("localhost", True), ("app.localhost", True), ("127.0.0.1", True), ("[::1]", True),
        ("169.254.169.254", True), ("0.0.0.0", True), ("::ffff:127.0.0.1", True), ("224.0.0.1", True),
        ("fe80::1", True),
        ("127.1", True), ("2130706433", True), ("0x7f000001", True), ("0", True), ("2852039166", True),
        ("0177.0.0.1", True), ("127.000.000.001", True), ("0x7f.1", True), ("1.2.3.4.example.com", False),
        ("idp.example.edu", False), ("8.8.8.8", False), ("10.0.0.5", False),
    ],
)
def test_blocked_hosts(host: str, blocked: bool) -> None:
    assert blocked_host(host) is blocked
