"""A developer's .env must never change test outcomes."""

import os

import dotenv


def test_dotenv_loading_is_disabled_under_pytest(tmp_path, monkeypatch):
    """canvas_mcp.core.config calls load_dotenv() on import and python-dotenv
    walks up the tree, so a real .env in a parent checkout (a git worktree
    sits under one) would leak write-tool allowlists into the suite."""
    probe = "CANVAS_MCP_DOTENV_ISOLATION_PROBE"
    env_file = tmp_path / ".env"
    env_file.write_text(f"{probe}=leaked\n", encoding="utf-8")
    monkeypatch.delenv(probe, raising=False)

    dotenv.load_dotenv(env_file)
    dotenv.load_dotenv()

    assert probe not in os.environ
