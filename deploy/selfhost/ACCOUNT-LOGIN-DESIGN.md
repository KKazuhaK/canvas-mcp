# Account identity and login policy

This revision implements the owner's October 12 account/login requirements on
the independent selfhost fork. It does not synchronize or publish hosting code
to upstream. The configuration, administrator UI, SQL state, migrations and
verification must land together; this document is the implementation contract,
not a claim that the features below have already shipped.

## Identity and names

`accounts.id` is permanent. UPN is one account-level, unique, case-insensitive
login name. Local password credentials contain only the account FK, salted hash
and timestamps; they do not contain another username. Local sign-in looks up the
account by UPN. Renaming UPN never changes the account id, Canvas credentials,
audit ownership or external identities.

Existing local names become the account UPN during the isolated upgrade so
previous local sign-in names continue working. A new SSO registration can use a
verified or explicitly trusted, unclaimed email as its default UPN. Missing
proof or a name collision gets a unique system-generated UPN, without another
registration step. Only
administrators can rename it; the personal UI is read-only. Rename uses recent
sign-in, Origin/CSRF, revision CAS and an in-transaction owner check, and ends
existing named-account sessions/codes/grants. Isolated revision 0004 completes
older provisional names without merging accounts or changing existing names.

External identity is canonical issuer plus immutable subject: Google and generic
OIDC use issuer/sub; Entra's adapter defaults to its verified tenant issuer and
object subject. The database has no tenant-specific or object-specific columns.
Each custom OIDC instance has its own registration id and database configuration.
The provider registration id identifies the offered login configuration, not the
person. Multiple registrations can recognize the same canonical identity only
within the existing account and its login policy. Changing reported email or UPN
updates provider metadata, never identity ownership.

Migration must not silently merge accounts. Historical canonical subjects that
are owned by different account ids require explicit operator resolution; refuse
and roll back the upgrade rather than taking over one account. Preserve same-
account provider aliases and identity/audit history.

## Governed policy

Use one closed database-owned policy object, not additional environment flags:

```json
{
  "allow_multiple": true,
  "lock_first_sso": false,
  "block_conflicting_registration": false
}
```

Unknown fields and malformed policy values are rejected. Each provider instance,
including every custom OIDC registration, independently stores `auto_link_email`,
default false. There is no global automatic-association switch or provider-pair
matrix. Existing provider enablement is still authoritative.

Account policy stores an optional multi-link override, an inherited or explicit
provider allowlist, the selected SSO lock and an exemption from automatically
reapplying that lock. The SSO lock concerns external methods; local password
access is independently controlled by the provider allowlist. Admin unlock
clears only the SSO lock, permits explicit additional linking and exempts that
account from immediate relocking. It retains the original external identity,
does not create another identity and emits an audit row.

All linked methods remain stored when restrictions change. Login and linking
must enforce the current allowlist and lock before admitting a method. Tightening
policy invalidates affected sessions, pending ceremonies and MCP grants; issuer
and request paths must observe the committed state. Every account/provider
policy write preserves at least one usable administrator path under the final
effective policy, not merely an identity at an enabled global provider.

## Email association and conflict handling

Stable subject lookup precedes any email lookup. An already known subject always
resolves to its existing account; it cannot be moved by a new email claim.

Automatic email association requires all of:

- Explicit opt-in on the incoming provider instance.
- A normalized matching email supplied by that configured, trusted provider.
- Exactly one eligible target account; ambiguity refuses association.
- Current target-account standing and method/lock restrictions permit the new
  method. Admission and owner evidence checks remain in force.
- No conflicting subject ownership or second identity for the same method.

Enabling this switch declares operator trust in that provider's matching claims.
Entra can match its supplied email or UPN; Google and custom OIDC can match their
configured email claim. Matching also recognizes saved provider mail-style login
names, so a Google sign-in can find an existing Entra account after its account
UPN was renamed. No additional mailbox challenge or user confirmation is
required for automatic association. This trust policy does not rewrite the
protocol's `email_verified` claim. Without the instance opt-in, email or UPN alone
never enters another account. Google-first, Entra-second sign-in with matching
email enters the original account when Entra's switch and account policy allow
it; subsequent sign-ins use the immutable identity binding.

With conflicting-registration blocking enabled, a matching existing UPN or
email refuses creation of a separate account and asks the person to sign in
through the existing method. It never enters that account on the strength of
the conflict. Without blocking, uniqueness still prevents reusing the UPN and
a unique system name is assigned. Explicit linking requires a fresh original
session and a session-bound verification ceremony for the new identity.

## Public origin assessment

The canonical address affects OAuth issuer, audience, client metadata, callback
URLs and Host/Origin protection. It cannot refresh as an ordinary display setting.
The existing environment value is adopted once into `site.public_base_url`; the
database wins on subsequent boots, including when the environment is removed.

An explicit owner-confirmed change atomically advances account and JWT epochs,
revokes grants, deletes pending codes/ceremonies and records old/new origins.
Configuration-dependent requests pause until restart, when all OAuth and edge
components use the new origin together. The operator must update the reverse
proxy and external app callbacks; clients reconnect. An unchanged canonical
origin does not revoke connections. Corrupt database values refuse startup and
do not fall back to the environment. DATABASE_URL remains infrastructure config.

## Upgrade and verification

At least one independent active owner with a local identity, password, assigned
UPN and permitted local login is retained once such an entry point exists. A
remaining SSO owner does not replace it. Provider disablement, account method
restrictions, identity unlink, disablement and deletion cannot remove the final
local administrator, including operator force-disable. Another local owner
allows intentional rotation. Entra rules owners are not silently converted to
independent local administrators. Older SSO-only installations show a warning
and let a fresh owner explicitly create an independent local administrator.

Sign-in registrations store optional bounded embedded PNG icons in SQL. Upload,
preservation and reset use the existing governed provider edit, without remote
image fetching or additional deployment files. Home labels distinguish the
Canvas MCP account from its Canvas LMS connection.

Every schema revision, compatibility gate, legacy name adoption, automatic backup
and data-transfer adjustment stays under `core/selfhost/db/migrations/`. The
previous frozen nineteen-table baseline and local-credential expand revision
remain unchanged. Removing a redundant legacy name column requires a contract
revision, an increased compatibility floor and an automatic SQLite backup.

Verification must cover SQLite and native PostgreSQL, populated upgrades and
transfer, case-insensitive UPN uniqueness/races, mutable external claims,
multiple OIDC registrations, explicit linking, trusted email association,
provider opt-in/off conflicts, lock/unlock without identity deletion, policy changes
and last-owner guards, session/code/access/refresh revocation, and actual Compose
boot/recreation with an unchanged data volume. English/Chinese administrator
and onboarding flows must match the server policy. Deployment remains Compose
and a complete env template; no host/system environment changes are required.
