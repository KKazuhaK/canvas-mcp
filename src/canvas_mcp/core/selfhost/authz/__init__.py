"""The server's own OAuth authorization server (``SELFHOST_AUTH_MODE=local``).

Importing this package costs nothing and imports nothing: every module is loaded on
first use, so ``entra_proxy`` mode (the default) never touches any of it. The only
module that imports FastMCP or SDK internals is :mod:`.fastmcp_compat`.
"""
