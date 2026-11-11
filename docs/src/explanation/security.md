# Security model

This page explains what protects what, and why, for whoever reviews a deployment.

## Organization isolation

Every operation on organization data goes through one access check, in the domain layer that
both the interface and the API use, not in the pages. It resolves the user's role in the
organization (the higher of the role given in nanobom and the one from identity provider groups)
and compares it with the permission the operation needs (see
[Roles and permissions](../reference/accounts.md#organization-roles)). Organizations a user does
not belong to answer "not found", so their existence does not leak; the upload API answers `404`
for an organization that is not the token's for the same reason. Instance administrators act as
owners everywhere.

Shared data is limited to what is not organization-specific: cached OSV records and exploitation
data per CVE. The error message of a failed instance-wide run can name packages of any
organization, and its counts of new and fixed findings span all of them, so both are shown to
instance administrators only, and the failure webhook should
reach operators rather than an organization's channel.

## API tokens

- 256 bits of randomness, prefixed with `nanobom_` so secret scanners (and you) can recognize
  them in logs and repositories.
- Stored as a SHA-256 digest. A slow password hash is unnecessary for random values of that
  length, and would slow every upload down.
- Limited to an organization or one project; they reach the upload, VEX and read APIs only,
  never the interface. A project token limits a leak to one project, and cannot create
  projects. Every token reads the findings of the projects it reaches, as a viewer, through the
  same checks as the interface.
- An `upload` token can also replace components and ignore findings by importing VEX
  statements: a leaked upload token can hide vulnerabilities, so treat it like the SBOM pipeline
  it belongs to. A `read` token cannot change anything: every write path refuses it, in the
  server and again in the domain layer. Give tools that only read a read token
  ([Tokens and scopes](tokens.md)).
- Shown once; revocable; their last use is recorded, to the minute: a token used again within
  a minute does not write to the database, so reads stay reads.

The upload API is not exposed to cross-site request forgery: it is authenticated by the
`Authorization` header (`X-Api-Key` for the Dependency-Track API), which browsers never add on
their own. The read API also accepts the session cookie, so the interface's pages can use it;
it only answers `GET` requests and changes nothing, and since it sends no CORS headers, a page
of another site cannot read its answers. Its responses are `Cache-Control: private, no-cache`
and vary on the cookie and token headers, so a shared proxy cannot serve what one caller
obtained to another.

## Sessions and cookies

The session cookie, `nanobom_session`, holds only a random session identifier; sessions are
stored in the database, so they survive restarts and can be ended from the server. It is:

- `HttpOnly`, out of reach of scripts;
- `SameSite=Lax`, not sent with cross-site form submissions;
- `Secure` when `NANOBOM_PUBLIC_URL` is `https`, so it is only sent over TLS.

Sessions end after `NANOBOM_SESSION_INACTIVITY_DAYS` without activity, on sign-out, on a password
change and when the user is disabled.

The language cookie, `nanobom_locale`, only holds the chosen language.

## Cross-site request forgery

State-changing requests from the interface (form submissions, which all use `POST`) are refused
with `403` when:

- the browser reports them as cross-site (`Sec-Fetch-Site` other than `same-origin` or `none`), or
- their `Origin` header differs from the origin of `NANOBOM_PUBLIC_URL`.

Together with `SameSite=Lax` cookies, which browsers do not send with cross-site `POST` requests,
this covers current and older browsers without a token in every form. Requests carrying an
`Authorization` header are not checked, since they do not rely on cookies, and neither are
requests carrying neither `Sec-Fetch-Site` nor `Origin`: browsers send at least one of them on a
cross-site `POST`, so such requests come from other clients, which a cookie-based attack cannot
use. This is why `NANOBOM_PUBLIC_URL` must match the browser's address bar exactly.

## Passwords and sign-in

- Local passwords are hashed with Argon2id. The minimum length is configurable, with no
  composition rules: length is what makes a password strong, and a password manager is the way to
  get one.
- Password sign-in is rate limited per client address (a burst of 5, then one attempt every 4
  seconds). Behind a proxy, nanobom sees the proxy's address as the client of every request, so
  all users would share one budget; `NANOBOM_TRUST_FORWARDED_HEADERS` reads the address from the
  proxy's headers instead. It must stay off unless a proxy you control sets them: otherwise any
  client can send a made-up header and escape the limit.
- Redirects after sign-in only go to paths of the same site.

## Single sign-on

- OpenID Connect uses the authorization code flow with PKCE, a `state` and a nonce, and verifies
  the ID token's signature, issuer, audience and expiry, and the access token hash when present.
- Users are matched by issuer and subject, never by email address: an attacker who can set an
  arbitrary email address at a provider cannot take over an account. The price is that a local
  account and a single sign-on identity with the same address stay two users.
- The discovery and token requests do not follow redirects, so the issuer cannot be used to make
  nanobom request other addresses.
- The provider is the authority for its users: with an administrator claim configured, it grants
  and removes instance administration at each sign-in, and roles from groups follow the user's
  groups. A user who loses a group keeps its role until their next sign-in; disabling the user
  cuts access at once.

## HTTP headers

Every response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, which prevent
nanobom from being framed by another site. HSTS is left to the TLS-terminating proxy.

## Advisory text

Advisories come from OSV and their description is Markdown written by third parties. A finding's
page shows it formatted, and treats it as untrusted:

- HTML in the description is shown as text, never interpreted.
- A link is kept only when it leads to an `http`, `https` or `mailto` address, and carries
  `rel="noopener noreferrer nofollow"`. Any other link, relative ones included, is reduced to
  its text. So is an address made to mislead: a web address with user information before its
  host, a `mailto` address that fills in a subject or a body, an address holding characters
  that change the direction of text.
- An image is never shown, so opening a finding makes the browser request nothing from a third
  party: it is replaced by a link to its address when that address is allowed, by its
  alternative text otherwise.
- A description that is very long (over 256 KiB), or built to grow out of proportion once
  formatted, is shown as plain text.

The addresses listed under **References** follow the same rule: one that is not allowed is
shown without a link. The [read API](../reference/read-api.md) returns the description as
published.

## Outbound requests

nanobom makes requests to:

- OSV (`NANOBOM_OSV_URL`), during runs;
- CISA and FIRST (`NANOBOM_KEV_URL`, `NANOBOM_EPSS_URL`), after runs, unless exploitation data is
  off;
- the OpenID Connect provider, at sign-in;
- webhooks: organization webhooks set by organization admins, and the failure webhook;
- the SMTP server (`NANOBOM_SMTP_URL`), for emails to the recipients organization admins set.
  Recipients are not verified and any signed-in user can create an organization, so test emails
  are rate limited per organization, per user and for the instance, and name the organization
  by its slug rather than its free-text display name.

Organization admins can make nanobom `POST` to any `http` or `https` address they choose,
including addresses on its own network. If nanobom runs next to services that trust their
network, restrict its outbound traffic with a firewall or an egress proxy.

Webhook requests are not signed: receivers should treat them as a hint to look at nanobom, not as
an authority, and keep their URL secret.

## Unauthenticated endpoints

`/healthz`, `/metrics`, the sign-in page and static assets need no session; the upload API needs a
token. Metrics are instance-wide counts; restrict `/metrics` at the proxy if even those should
stay private.

Project [badges](../reference/badges.md) (`/badges/…`) need no session either: the random key in
their address is their authorization, and it unlocks only the open finding counts of one project.
They are off until an admin turns them on, and a new address or turning them off revokes the old
one at once. To serve badges to the internet while keeping the rest of nanobom private, expose
only `/badges/` at the proxy. nanobom keeps the key out of its own logs, but the proxy's access
log records it with each request.

## Data at rest

Everything, password hashes and token digests included, is in the database (SQLite or
PostgreSQL): treat it and its backups as sensitive. On PostgreSQL, the connection carries that
data too: use `sslmode=verify-full` when the database is on another host
([PostgreSQL URLs](../reference/configuration.md#postgresql-urls)).
