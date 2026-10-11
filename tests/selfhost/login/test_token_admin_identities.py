"""token_admin: ``identities``, ``unlink-identity`` and ``login-providers``."""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import make_store, stack_env

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.accounts import ExternalClaims
from canvas_mcp.core.selfhost.login import registry as login_registry
from canvas_mcp.core.selfhost.login.http import SafeHttp
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore, token_db_path

from ..conftest import OID_A, OID_B, acct_key, make_account, sign_in
from .fake_idp import FakeNetwork, FakeOidcIdp, google_idp
from .test_provider_settings import (
    GITHUB_ID,
    GITHUB_SECRET,
    GOOGLE_ID,
    GOOGLE_SECRET,
    ISSUER,
    OIDC_SECRET,
    env,
)

KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
RING = "k1:" + base64.b64encode(b"\x01" * 32).decode()


@pytest.fixture
def cli_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", RING)
    for name, value in stack_env().items():
        monkeypatch.setenv(name, value)
    return tmp_path


@pytest.fixture
def store(cli_env: pathlib.Path) -> TokenStore:
    s = make_store(token_db_path(cli_env), Keyring.parse(RING), clock=lambda: 1_800_000_000, public=True)
    s.initialize()
    return s


def github(subject: str = "1001") -> ExternalClaims:
    return ExternalClaims(
        provider_id="github", issuer=acc.GITHUB_ISSUER, subject=subject, username="octo\tcat",
        email="o@example.test", email_verified=True,
    )


def link(store: TokenStore, key: str, ext: ExternalClaims) -> None:
    verdict = acc.evaluate_admission(ext, acc.AccessPolicy(mode="open"))
    result = store.link_identity(
        key, ext, verdict, acc.AccessPolicy(mode="open"),
        expected_epoch=store.get_principal_status(key).session_epoch,
    )
    assert result.ok


def lines(capsys: pytest.CaptureFixture[str]) -> list[list[str]]:
    return [line.split("\t") for line in capsys.readouterr().out.splitlines()]


class TestIdentities:
    def test_it_lists_every_sign_in_method_with_its_id_and_no_secret(self, store, capsys) -> None:
        make_account(store, OID_A, username="ada@example.test")
        link(store, KEY_A, github())
        make_account(store, OID_B)
        assert token_admin.main(["identities"]) == 0
        rows = lines(capsys)
        assert len(rows) == 3 and all(len(r) == 8 for r in rows)
        github_row = next(r for r in rows if r[2] == "github")
        assert github_row[0] == KEY_A and github_row[4] == "1001" and github_row[5] == "octo cat"
        # Never the e-mail address, verified or not.
        assert "o@example.test" not in capsys.readouterr().out
        assert "verified" not in "	".join(github_row)

    def test_the_output_has_no_email_at_all(self, store, capsys) -> None:
        make_account(store, OID_A, username="ada@example.test")
        link(store, KEY_A, github())
        assert token_admin.main(["identities"]) == 0
        assert "@example.test" not in capsys.readouterr().out.replace("ada@example.test", "")

    def test_one_account_only(self, store, capsys) -> None:
        make_account(store, OID_A)
        make_account(store, OID_B)
        link(store, KEY_A, github())
        assert token_admin.main(["identities", KEY_A]) == 0
        assert {r[0] for r in lines(capsys)} == {KEY_A}
        assert token_admin.main(["identities", "acct:11111111-2222-4333-8444-555555555555"]) == 1
        assert token_admin.main(["identities", "garbage"]) == 2


class TestProviderPrincipals:
    """google:<sub>, github:<id> and oidc:<slug>:<sub> name an account by one of its identities."""

    def test_github_and_google_and_oidc_with_a_configured_issuer(self, store, cli_env, monkeypatch, capsys) -> None:
        make_account(store, OID_A)
        make_account(store, OID_B)
        link(store, KEY_A, github("1001"))
        link(store, KEY_A, ExternalClaims("google", acc.GOOGLE_ISSUER, "Sub_1-x", "g"))
        link(store, KEY_B, ExternalClaims("oidc:school", "https://idp.example.edu/realms/s/", "Teacher.One", "t"))
        monkeypatch.setenv("OIDC_SCHOOL_ISSUER", "https://idp.example.edu/realms/s/")
        for principal in ("github:1001", "google:Sub_1-x"):
            assert token_admin.main(["identities", principal]) == 0
            assert {r[0] for r in lines(capsys)} == {KEY_A}
        # The subject keeps its case; a different case is another subject.
        assert token_admin.main(["identities", "oidc:school:Teacher.One"]) == 0
        assert {r[0] for r in lines(capsys)} == {KEY_B}
        assert token_admin.main(["identities", "oidc:school:teacher.one"]) == 1
        assert token_admin.main(["identities", "github:2002"]) == 1

    def test_every_command_takes_them(self, store, capsys) -> None:
        make_account(store, OID_A)
        link(store, KEY_A, github("1001"))
        assert token_admin.main(["promote-owner", "github:1001"]) == 0
        assert store.get_principal_status(KEY_A).is_owner
        assert token_admin.main(["history", "github:1001"]) == 0

    def test_an_oidc_subject_without_an_issuer_is_found_when_it_is_unique(self, store, monkeypatch, capsys) -> None:
        monkeypatch.delenv("OIDC_SCHOOL_ISSUER", raising=False)
        make_account(store, OID_A)
        link(store, KEY_A, ExternalClaims("oidc:school", "https://idp.example.edu/realms/s", "T1", "t"))
        assert token_admin.main(["identities", "oidc:school:T1"]) == 0
        assert {r[0] for r in lines(capsys)} == {KEY_A}

    def test_an_oidc_subject_that_two_issuers_share_asks_for_the_issuer(self, store, monkeypatch, capsys) -> None:
        monkeypatch.delenv("OIDC_SCHOOL_ISSUER", raising=False)
        make_account(store, OID_A)
        make_account(store, OID_B)
        link(store, KEY_A, ExternalClaims("oidc:school", "https://one.example.edu/", "T1", "t"))
        link(store, KEY_B, ExternalClaims("oidc:school", "https://two.example.edu/", "T1", "t"))
        capsys.readouterr()
        assert token_admin.main(["identities", "oidc:school:T1"]) == 2
        err = capsys.readouterr().err
        assert "OIDC_<SLUG>_ISSUER" in err and "T1" not in err
        # With the issuer in the environment the same name is exact.
        monkeypatch.setenv("OIDC_SCHOOL_ISSUER", "https://two.example.edu/")
        assert token_admin.main(["identities", "oidc:school:T1"]) == 0
        assert {r[0] for r in lines(capsys)} == {KEY_B}

    @pytest.mark.parametrize(
        "principal",
        ["github:abc", "github:0", "github:01", "github:", "google:", "google:a b", "oidc:School:x", "oidc:school:", "oidc::x", "oidc:school:a,b", "facebook:1"],
    )
    def test_a_malformed_principal_is_a_usage_error(self, store, capsys, principal: str) -> None:
        assert token_admin.main(["identities", principal]) == 2
        assert "google:<subject>" in capsys.readouterr().err


class TestUnlinkIdentity:
    def test_the_operator_removes_one_and_it_is_audited(self, store, capsys) -> None:
        make_account(store, OID_A)
        link(store, KEY_A, github())
        github_id = next(i.id for i in store.list_identities(KEY_A) if i.provider_id == "github")
        before = store.get_principal_status(KEY_A).session_epoch
        assert token_admin.main(["unlink-identity", KEY_A, str(github_id)]) == 0
        assert "unlinked 1 sign-in method (github)" in capsys.readouterr().out
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra"]
        assert store.get_principal_status(KEY_A).session_epoch == before + 1
        entry = next(e for e in store.list_audit(50) if e.action == "identity_unlinked")
        assert entry.actor == "operator" and entry.detail["by"] == "operator"

    def test_the_last_one_is_refused_and_unknown_ids_are_not_found(self, store, capsys) -> None:
        make_account(store, OID_A)
        only = store.list_identities(KEY_A)[0].id
        assert token_admin.main(["unlink-identity", KEY_A, str(only)]) == 3
        assert "keeps at least one sign-in method" in capsys.readouterr().err
        assert token_admin.main(["unlink-identity", KEY_A, "99999"]) == 1
        assert token_admin.main(["unlink-identity", "acct:11111111-2222-4333-8444-555555555555", "1"]) == 1


    def test_the_only_rules_owner_keeps_its_entra_identity(self, store, capsys) -> None:
        policy = acc.AccessPolicy(
            mode="rules",
            rules=(acc.AccessRule("entra", "role", "Canvas.User"), acc.AccessRule("github", "user", "1001")),
            owner_rules=(acc.AccessRule("entra", "role", "Canvas.Owner"),),
        )
        make_account(store, OID_A)
        sign_in(store, OID_A, owner=True, policy=policy)
        ext = github()
        assert store.link_identity(
            KEY_A, ext, acc.evaluate_admission(ext, policy), policy,
            expected_epoch=store.get_principal_status(KEY_A).session_epoch,
        ).ok
        entra = next(i.id for i in store.list_identities(KEY_A) if i.provider_id == "entra")
        assert token_admin.main(["unlink-identity", KEY_A, str(entra)]) == 3
        assert "without a usable owner" in capsys.readouterr().err
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra", "github"]

    def test_two_rules_owners_cannot_both_drop_entra(self, store, capsys) -> None:
        policy = acc.AccessPolicy(
            mode="rules",
            rules=(acc.AccessRule("entra", "role", "Canvas.User"),),
            owner_rules=(acc.AccessRule("entra", "role", "Canvas.Owner"),),
        )
        open_policy = acc.AccessPolicy(mode="open")
        for oid, key, subject in ((OID_A, KEY_A, "1001"), (OID_B, KEY_B, "1002")):
            make_account(store, oid)
            sign_in(store, oid, owner=True, policy=policy)
            ext = github(subject)
            assert store.link_identity(
                key, ext, acc.evaluate_admission(ext, open_policy), open_policy,
                expected_epoch=store.get_principal_status(key).session_epoch,
            ).ok
        first, second = (
            next(i.id for i in store.list_identities(key) if i.provider_id == "entra")
            for key in (KEY_A, KEY_B)
        )
        assert token_admin.main(["unlink-identity", KEY_A, str(first)]) == 0
        capsys.readouterr()
        assert token_admin.main(["unlink-identity", KEY_B, str(second)]) == 3
        assert "without a usable owner" in capsys.readouterr().err
        assert [i.provider_id for i in store.list_identities(KEY_B)] == ["entra", "github"]


    def test_an_explicit_provider_list_holds_when_the_other_settings_do_not_load(
        self, store, monkeypatch, capsys
    ) -> None:
        # SELFHOST_LOGIN_PROVIDERS=github without GITHUB_CLIENT_ID: the full settings fail, the list does not.
        for name in ("GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "github")
        assert token_admin._listed_providers(store) == frozenset({"github"})
        make_account(store, OID_A)
        assert store.promote_owner(KEY_A)
        link(store, KEY_A, github())
        github_id = next(i.id for i in store.list_identities(KEY_A) if i.provider_id == "github")
        # Entra is not listed: removing the GitHub identity would leave the one owner without a way in.
        assert token_admin.main(["unlink-identity", KEY_A, str(github_id)]) == 3
        assert "without a usable owner" in capsys.readouterr().err
        assert [i.provider_id for i in store.list_identities(KEY_A)] == ["entra", "github"]

    def test_an_unreadable_provider_list_assumes_every_provider_and_says_so(
        self, store, monkeypatch, capsys
    ) -> None:
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "not-a-provider")
        assert token_admin._listed_providers(store) is None
        assert "assumed to be listed" in capsys.readouterr().err


class TestRecordedLoginProviders:
    @pytest.mark.parametrize("command", ["disable", "unlink-identity"])
    def test_overlapping_provider_lists_cannot_erase_the_recorded_owner_path(
        self, store, monkeypatch, capsys, command: str,
    ) -> None:
        policy = acc.AccessPolicy(mode="open")
        keys = []
        for ext in (
            ExternalClaims(provider_id="google", issuer=acc.GOOGLE_ISSUER, subject="1234567890"),
            github("1001"),
        ):
            result = store.resolve_identity(
                ext, acc.evaluate_admission(ext, policy), policy, purpose="sign_in",
            )
            assert result.principal_key is not None
            keys.append(result.principal_key)
            assert store.promote_owner(result.principal_key)
        first, _ = keys
        # A delisted fallback keeps unlink from hitting the ordinary last-identity guard.
        fallback = ExternalClaims(
            provider_id="oidc:backup", issuer="https://backup.example.edu", subject="backup",
        )
        link(store, first, fallback)
        store.record_login_providers({"entra", "google"})
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "entra,github")
        before = store.get_principal_status(first).session_epoch
        args = [command, first]
        if command == "unlink-identity":
            identity = next(i for i in store.list_identities(first) if i.provider_id == "google")
            args.append(str(identity.id))
        assert token_admin.main(args) == token_admin.EXIT_REFUSED
        assert store.count_usable_owners({"entra", "google"}) == 1
        assert store.get_principal_status(first).status == "active"
        assert store.get_principal_status(first).session_epoch == before

    """The usable-owner checks use the providers the server recorded, not the shell's variables."""

    @pytest.fixture(autouse=True)
    def bare_shell(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("SELFHOST_LOGIN_PROVIDERS", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"):
            monkeypatch.delenv(name, raising=False)

    @staticmethod
    def google_only_world(store: TokenStore) -> str:
        """S: an Entra-rule owner (stranded once Entra is delisted); C: a Google-only operator owner."""
        sign_in(store, OID_A, owner=True)
        return store.create_operator_account(
            provider_id="google", issuer=acc.GOOGLE_ISSUER, subject="1234567890",
            status="active", role="owner",
        )

    def test_the_servers_record_decides_without_its_variables(self, store, capsys) -> None:
        c = self.google_only_world(store)
        store.record_login_providers({"google"})
        assert token_admin.main(["disable", c]) == 3
        err = capsys.readouterr().err
        assert "last usable owner" in err and "note:" not in err
        assert store.get_principal_status(c).status == "active"

    def test_a_variable_that_shares_no_provider_with_the_record_leaves_the_record_in_force(
        self, store, monkeypatch, capsys
    ) -> None:
        c = self.google_only_world(store)
        store.record_login_providers({"google"})
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "entra")
        assert token_admin.main(["disable", c]) == 3
        assert store.get_principal_status(c).status == "active"
        assert "differs from the list the server last recorded" in capsys.readouterr().err

    def test_a_different_variable_is_noted_and_an_owner_must_be_usable_under_both_lists(
        self, store, monkeypatch, capsys
    ) -> None:
        # The operator moves the server from entra,google to google. S (an Entra-rule owner) is
        # usable under the record, not under the new list; C (a Google-only operator owner) is
        # the only owner usable under both, so it must not be disabled.
        c = self.google_only_world(store)
        store.record_login_providers({"entra", "google"})
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "google")
        assert token_admin.main(["disable", c]) == 3
        err = capsys.readouterr().err
        assert "differs from the list the server last recorded" in err
        assert "entra, google" in err and "last usable owner" in err
        assert store.get_principal_status(c).status == "active"

    def test_the_same_list_in_the_shell_and_the_record_says_nothing(
        self, store, monkeypatch, capsys
    ) -> None:
        c = self.google_only_world(store)
        store.record_login_providers({"google"})
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "google")
        assert token_admin.main(["disable", c]) == 3
        err = capsys.readouterr().err
        assert "note:" not in err and "last usable owner" in err

    def test_promote_owner_follows_the_list_a_refused_start_was_refused_for(
        self, store, monkeypatch, capsys
    ) -> None:
        # The server last recorded entra,google; X holds an Entra-rule role and a Google identity.
        sign_in(store, OID_A, owner=True)
        link(store, KEY_A, ExternalClaims(
            provider_id="google", issuer=acc.GOOGLE_ISSUER, subject="1234567890",
            email="a@example.test", email_verified=True,
        ))
        store.record_login_providers({"entra", "google"})
        assert token_admin.main(["promote-owner", KEY_A]) == 1  # usable under that list
        capsys.readouterr()
        # The shell now names google alone: X is not usable under it, so it is promoted.
        monkeypatch.setenv("SELFHOST_LOGIN_PROVIDERS", "google")
        assert token_admin.main(["promote-owner", KEY_A]) == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == "promoted 1 account to owner"
        assert "differs from the list the server last recorded" in captured.err
        assert store.get_principal_status(KEY_A).role_source == "operator"

    def test_promote_owner_says_why_an_owner_cannot_be_made_usable(self, store, capsys) -> None:
        sign_in(store, OID_A, owner=True)  # an Entra identity only
        store.record_login_providers({"google"})
        assert token_admin.main(["promote-owner", KEY_A]) == 1
        out = capsys.readouterr().out
        assert "cannot be made usable" in out and "no sign-in method at a listed provider" in out
        assert store.get_principal_status(KEY_A).role_source == "rules"

    def test_nothing_recorded_and_nothing_set_assumes_entra_and_says_so(self, store, capsys) -> None:
        c = self.google_only_world(store)
        assert token_admin.main(["disable", c]) == 0  # the assumption, as before
        err = capsys.readouterr().err
        assert "has not recorded" in err and "google" in err

    def test_an_entra_only_database_gets_no_note(self, store, capsys) -> None:
        sign_in(store, OID_A, owner=True)
        sign_in(store, OID_B, owner=True)
        assert token_admin.main(["disable", KEY_B]) == 0
        captured = capsys.readouterr()
        assert captured.err == "" and captured.out.strip() == "disabled 1 user"

    def test_an_unlisted_provider_variable_is_not_logged_by_the_command(
        self, store, monkeypatch, capsys, caplog
    ) -> None:
        sign_in(store, OID_A, owner=True)
        sign_in(store, OID_B, owner=True)
        monkeypatch.setenv("GOOGLE_CLIENT_ID", GOOGLE_ID)
        with caplog.at_level("DEBUG"):
            assert token_admin.main(["disable", KEY_B]) == 0
        assert not [r for r in caplog.records if "is ignored" in r.getMessage()]
        captured = capsys.readouterr()
        assert captured.err == "" and "ignored" not in captured.out

    def test_promote_owner_re_sources_a_stranded_rules_owner(self, store, capsys) -> None:
        sign_in(store, OID_A, owner=True)
        link(store, KEY_A, ExternalClaims(
            provider_id="google", issuer=acc.GOOGLE_ISSUER, subject="1234567890",
            email="a@example.test", email_verified=True,
        ))
        # Entra alone: the rules owner is usable, so there is nothing to do.
        assert token_admin.main(["promote-owner", KEY_A]) == 1
        assert store.get_principal_status(KEY_A).role_source == "rules"
        capsys.readouterr()
        store.record_login_providers({"google"})
        assert token_admin.main(["promote-owner", KEY_A]) == 0
        assert capsys.readouterr().out.strip() == "promoted 1 account to owner"
        assert store.get_principal_status(KEY_A).role_source == "operator"
        assert store.count_usable_owners({"google"}) == 1
        assert token_admin.main(["promote-owner", KEY_A]) == 1


class TestLoginProviders:
    def settings_env(self, monkeypatch: pytest.MonkeyPatch, **extra: str) -> None:
        options = {
            "SELFHOST_LOGIN_PROVIDERS": "entra,google,github,oidc:school",
            "GOOGLE_CLIENT_ID": GOOGLE_ID, "GOOGLE_CLIENT_SECRET": GOOGLE_SECRET,
            "GITHUB_CLIENT_ID": GITHUB_ID, "GITHUB_CLIENT_SECRET": GITHUB_SECRET,
            "OIDC_SCHOOL_ISSUER": ISSUER, "OIDC_SCHOOL_CLIENT_ID": "canvas-mcp",
            "OIDC_SCHOOL_CLIENT_SECRET": OIDC_SECRET,
            "ACCESS_POLICY": "open", "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC": "true",
            **extra,
        }
        values = env(**options)
        for name, value in values.items():
            monkeypatch.setenv(name, value)

    def test_it_prints_the_redirect_uris_to_register_and_no_secret(
        self, cli_env, monkeypatch, capsys
    ) -> None:
        self.settings_env(monkeypatch)
        assert token_admin.main(["login-providers"]) == 0
        out = capsys.readouterr().out
        assert out.splitlines() == [
            "entra\tredirect_uri=https://canvas.example.test/account/callback",
            "google\tredirect_uri=https://canvas.example.test/account/callback/google",
            "github\tredirect_uri=https://canvas.example.test/account/callback/github",
            "oidc:school\tredirect_uri=https://canvas.example.test/account/callback/oidc/school",
        ]
        for secret in (GOOGLE_SECRET, GITHUB_SECRET, OIDC_SECRET):
            assert secret not in out

    def test_check_asks_each_openid_provider(self, cli_env, monkeypatch, capsys) -> None:
        self.settings_env(monkeypatch)
        net = FakeNetwork()
        google_idp(net)
        FakeOidcIdp(net, ISSUER)
        monkeypatch.setattr(login_registry, "SafeHttp", lambda transport=None: SafeHttp(transport=net.transport))
        assert token_admin.main(["login-providers", "--check"]) == 0
        rows = {r[0]: r for r in lines(capsys)}
        assert rows["google"][2] == "OK" and "iss_param=yes" in rows["google"] and "algs=RS256" in rows["google"]
        assert rows["oidc:school"][2] == "OK" and "jwks_keys=2" in rows["oidc:school"]
        assert rows["github"][2] == "OK" and rows["entra"][1].startswith("redirect_uri=")
        # Hosts only, never a path or a query; GitHub prints the scopes it would ask for.
        assert "hosts=accounts.google.com," in "	".join(rows["google"])
        assert not any("/o/oauth2" in cell for cell in rows["google"])
        assert "pkce=listed" in rows["google"] and "iss_param=yes" in rows["google"]
        assert "scopes=user:email" in rows["github"] and "read:org" not in "	".join(rows["github"])
        # Discovery and the key set only: every request is a GET, so no token was ever asked for.
        assert net.log and {method for method, _, _ in net.log} == {"GET"}

    def test_check_names_read_org_when_a_rule_needs_it(self, cli_env, monkeypatch, capsys) -> None:
        self.settings_env(monkeypatch, ACCESS_POLICY="rules", ACCESS_RULES="entra:role:Canvas.User,github:org:acme")
        net = FakeNetwork()
        google_idp(net)
        FakeOidcIdp(net, ISSUER)
        monkeypatch.setattr(login_registry, "SafeHttp", lambda transport=None: SafeHttp(transport=net.transport))
        assert token_admin.main(["login-providers", "--check"]) == 0
        rows = {r[0]: r for r in lines(capsys)}
        assert "scopes=user:email,read:org" in rows["github"]

    def test_check_exits_1_when_a_provider_is_down(self, cli_env, monkeypatch, capsys) -> None:
        self.settings_env(monkeypatch)
        net = FakeNetwork()
        google_idp(net)  # the school provider has no route
        monkeypatch.setattr(login_registry, "SafeHttp", lambda transport=None: SafeHttp(transport=net.transport))
        assert token_admin.main(["login-providers", "--check"]) == 1
        rows = {r[0]: r for r in lines(capsys)}
        assert rows["google"][2] == "OK" and rows["oidc:school"][2] == "FAILED"
        assert "idp.example.edu" not in rows["oidc:school"][3]

    def test_a_bad_environment_is_a_configuration_error(self, cli_env, monkeypatch, capsys) -> None:
        for name, value in env(SELFHOST_LOGIN_PROVIDERS="google").items():
            monkeypatch.setenv(name, value)
        assert token_admin.main(["login-providers"]) == 2
        assert "GOOGLE_CLIENT_ID is required" in capsys.readouterr().err
