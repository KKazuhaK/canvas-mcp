"""Sign-in providers for the server's own sign-in (``/account`` and, in local mode, MCP).

Entra is the first provider and keeps its own ceremony in ``account_web``. Google, GitHub
and generic OpenID Connect providers live here; they exist only with
``SELFHOST_AUTH_MODE=local``. ``config`` is the only module imported at settings-parse time
(standard library only); everything else is loaded when a non-Entra provider is configured.
"""
