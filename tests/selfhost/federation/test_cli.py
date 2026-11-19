"""``token_admin trusted-issuers``, ``link-federated`` and ``unlink-federated``."""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import make_store, stack_env

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore, token_db_path

from ..conftest import OID_A, OID_B, acct_key, make_account

RING = "k1:" + base64.b64encode(b"\x01" * 32).decode()
HUB = "https://hub.example.test"


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", RING)
    for name, value in stack_env().items():
        monkeypatch.setenv(name, value)
    return tmp_path


@pytest.fixture
def store(env: pathlib.Path) -> TokenStore:
    s = make_store(
        token_db_path(env),
        Keyring.parse(RING),
        clock=lambda: 1_800_000_000,
        public=True,
    )
    s.initialize()
    return s


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = token_admin.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


class TestTrustedIssuers:
    def test_nothing_is_trusted_by_default(self, store, capsys):
        assert run(capsys, "trusted-issuers", "list") == (0, "", "")

    def test_add_list_remove(self, store, capsys):
        code, out, _ = run(
            capsys, "trusted-issuers", "add", HUB, "--name", "MCPHub",
            "--subject-claim", "mcphub_uid", "--read-scope", "canvas:read",
            "--write-scope", "canvas:write",
        )  # fmt: skip
        assert code == 0 and "trusted: " + HUB in out
        code, out, _ = run(capsys, "trusted-issuers", "list")
        fields = out.strip().split("\t")
        assert fields[:2] == [HUB, "MCPHub"]
        assert "algorithms=ES256,RS256,PS256,EdDSA" in fields
        assert "typ=at+jwt" in fields and "subject=mcphub_uid" in fields
        assert (
            "read_scope=canvas:read" in fields and "write_scope=canvas:write" in fields
        )
        assert run(capsys, "trusted-issuers", "remove", HUB)[0] == 0
        assert run(capsys, "trusted-issuers", "list") == (0, "", "")
        assert run(capsys, "trusted-issuers", "remove", HUB)[0] == 1

    def test_a_second_add_and_bad_values_are_refused(self, store, capsys):
        assert run(capsys, "trusted-issuers", "add", HUB)[0] == 0
        code, _, err = run(capsys, "trusted-issuers", "add", HUB)
        assert code == 3 and "already trusted" in err
        code, _, err = run(capsys, "trusted-issuers", "add", "http://hub.example.test")
        assert code == 2 and "https" in err
        code, _, err = run(
            capsys,
            "trusted-issuers",
            "add",
            "https://b.example.test",
            "--algorithms",
            "HS256",
        )
        assert code == 2 and "asymmetric" in err  # fmt: skip

    def test_typ_can_be_relaxed(self, store, capsys):
        assert run(capsys, "trusted-issuers", "add", HUB, "--allow-typ-jwt")[0] == 0
        assert "typ=any" in run(capsys, "trusted-issuers", "list")[1]


class TestLinks:
    def test_link_and_unlink(self, store, capsys):
        account = make_account(store, OID_A)
        other = make_account(store, OID_B)
        assert account == acct_key(OID_A)
        run(capsys, "trusted-issuers", "add", HUB)
        args = ("--account", account, "--issuer", HUB, "--subject", "hub-1")
        assert run(capsys, "link-federated", *args) == (0, "linked\n", "")
        assert run(capsys, "link-federated", *args) == (0, "already linked\n", "")
        code, out, _ = run(capsys, "trusted-issuers", "links")
        assert out == f"{account}\t{HUB}\thub-1\tlinked\n"
        assert run(capsys, "trusted-issuers", "links", "--account", other)[1] == ""
        # Another account cannot take the same subject.
        code, _, err = run(
            capsys,
            "link-federated",
            "--account",
            other,
            "--issuer",
            HUB,
            "--subject",
            "hub-1",
        )
        assert code == 3 and "another account" in err
        assert run(
            capsys, "unlink-federated", "--issuer", HUB, "--subject", "hub-1"
        ) == (
            0,
            "unlinked\n",
            "",
        )
        code, _, err = run(
            capsys, "unlink-federated", "--issuer", HUB, "--subject", "hub-1"
        )
        assert code == 1 and "no such link" in err

    def test_refusals(self, store, capsys):
        account = make_account(store, OID_A)
        # An issuer that was never added.
        code, _, err = run(
            capsys,
            "link-federated",
            "--account",
            account,
            "--issuer",
            HUB,
            "--subject",
            "s",
        )
        assert code == 3 and "no such trusted issuer" in err
        run(capsys, "trusted-issuers", "add", HUB)
        code, _, err = run(
            capsys,
            "link-federated",
            "--account",
            "not-a-uuid",
            "--issuer",
            HUB,
            "--subject",
            "s",
        )
        assert code == 2 and "UUID" in err
        code, _, err = run(
            capsys, "link-federated", "--account", "11111111-1111-4111-8111-111111111111",
            "--issuer", HUB, "--subject", "s",
        )  # fmt: skip
        assert code == 3 and "no such account" in err

    def test_removing_the_issuer_keeps_the_links_for_when_it_returns(
        self, store, capsys
    ):
        account = make_account(store, OID_A)
        run(capsys, "trusted-issuers", "add", HUB)
        run(
            capsys,
            "link-federated",
            "--account",
            account,
            "--issuer",
            HUB,
            "--subject",
            "s",
        )
        run(capsys, "trusted-issuers", "remove", HUB)
        assert (
            run(capsys, "trusted-issuers", "links")[1] == ""
        )  # not shown without the issuer
        run(capsys, "trusted-issuers", "add", HUB)
        assert (
            run(capsys, "trusted-issuers", "links")[1]
            == f"{account}\t{HUB}\ts\tlinked\n"
        )
