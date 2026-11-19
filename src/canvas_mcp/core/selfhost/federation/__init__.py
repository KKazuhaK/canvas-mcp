"""Tokens from trusted external OAuth issuers (a hub that signs the person in), valid on /mcp only.

Nothing here runs unless the operator has added a trusted issuer (``trusted-issuers add``):
without one, the server accepts exactly the access tokens it issued itself.
"""
