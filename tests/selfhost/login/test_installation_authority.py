"""An unconfigured public endpoint cannot claim setup without operator authority."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import update

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.login.installation import InstallationAuthority
from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError

from .test_database_provider_config import (  # noqa: F401
    CONFIG,
    SECRET,
    db,
    providers,
    revision,
)


@pytest.fixture
def authority(providers, tmp_path):  # noqa: F811
    return InstallationAuthority(providers, tmp_path, clock=lambda: 100)


def test_code_is_private_expiring_and_reused_on_recreation(authority):
    assert not authority.verify("unknown")
    code = authority.issue()
    assert code is not None and authority.verify(code)
    assert authority.issue() == code
    recreated = InstallationAuthority(
        authority.providers, authority.path.parent, clock=lambda: 101
    )
    assert recreated.verify(code)
    if os.name == "posix":
        assert stat.S_IMODE(authority.path.stat().st_mode) == 0o600
    expired = InstallationAuthority(
        authority.providers, authority.path.parent, clock=lambda: 1900
    )
    assert not expired.verify(code)
    replacement = expired.issue()
    assert replacement != code and expired.verify(replacement)


def test_concurrent_issuers_share_one_persisted_code(authority):
    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(lambda _: authority.issue(), [0, 1]))
    assert codes[0] == codes[1]
    assert authority.verify(codes[0])


def test_initialization_is_once_only_and_disable_does_not_reopen(authority):
    store = authority.providers
    code = authority.issue()
    store.initialize(
        config=CONFIG, client_secret=SECRET, revision=revision(store.database), now=100
    )
    assert not authority.verify(code) and authority.issue() is None
    store.save(
        "entra",
        config=CONFIG,
        client_secret=None,
        enabled=False,
        rank=0,
        revision=revision(store.database),
        actor=None,
        now=110,
    )
    assert not store.setup_available()
    with pytest.raises(
        ProviderConfigurationError, match="installation_already_initialized"
    ):
        store.initialize(
            config=CONFIG,
            client_secret=SECRET,
            revision=revision(store.database),
            now=120,
        )


def test_code_is_bound_to_this_database(authority):
    code = authority.issue()
    with authority.providers.database.write() as conn:
        conn.execute(
            update(s.server_state).values(
                database_id="99999999-2222-3333-4444-555555555555"
            )
        )
    assert not authority.verify(code)


def test_damaged_authority_is_not_replaced_or_echoed(authority):
    authority.path.write_text("broken-private-file", encoding="utf-8")
    with pytest.raises(ProviderConfigurationError) as error:
        authority.issue()
    assert "broken-private-file" not in str(error.value)
    assert authority.path.read_text(encoding="utf-8") == "broken-private-file"
