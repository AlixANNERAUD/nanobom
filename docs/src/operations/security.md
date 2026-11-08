# Security model

This page summarizes what protects what, for whoever reviews a deployment.

## Organization isolation

Every operation on organization data goes through one access check, in the domain layer that
both the interface and the API use, not in the pages. It resolves the user's role in the
organization (the higher of the role given in nanobom and the one from identity provider groups)
and compares it with the permission the operation needs (see
[Roles and permissions](../access/roles.md)). Organizations a user does not belong to answer
"not found", so their existence does not leak. Instance administrators act as owners everywhere.

Shared data is limited to what is not organization-specific: cached OSV records and exploitation
data per CVE. The error message of a failed instance-wide run can name packages of any
organization, so it is shown to instance administrators only.

## Upload tokens

- 256 bits of randomness, prefixed with `nanobom_` so secret scanners (and you) can recognize
  them in logs and repositories.
- Stored as a SHA-256 digest. A slow password hash is unnecessary for random values of that
  length, and would slow every upload down.
- Scoped to an organization or one project; they reach the upload API only, never the interface.
- Shown once; revocable; their last use is recorded.

The upload API is not exposed to cross-site request forgery: it is authenticated by the
`Authorization` header, which browsers never add on their own.

## Sessions and cookies

The session cookie, `nanobom_session`, holds only a random session identifier; sessions are
stored in the database. It is `HttpOnly`, `SameSite=Lax`, and `Secure` when `NANOBOM_PUBLIC_URL`
is `https`. Sessions end after `NANOBOM_SESSION_INACTIVITY_DAYS` without activity, on sign-out, on
a password change and when the user is disabled.

The language cookie, `nanobom_locale`, only holds the chosen language.

## Cross-site request forgery

State-changing requests from the interface (form submissions, which all use `POST`) are refused
with `403` when:

- the browser reports them as cross-site (`Sec-Fetch-Site` other than `same-origin` or `none`), or
- their `Origin` header differs from the origin of `NANOBOM_PUBLIC_URL`.

Together with `SameSite=Lax` cookies, which browsers do not send with cross-site `POST` requests,
this covers current and older browsers without a token in every form. Requests carrying an
`Authorization` header are not checked, since they do not rely on cookies.

## Passwords and sign-in

- Local passwords are hashed with Argon2id; the minimum length is configurable, with no
  composition rules.
- Password sign-in is rate limited per client address (a burst of 5, then one attempt every 4
  seconds). Behind a proxy, this depends on `NANOBOM_TRUST_FORWARDED_HEADERS`; see
  [Reverse proxy and TLS](reverse-proxy.md).
- Redirects after sign-in only go to paths of the same site.
- OpenID Connect uses the authorization code flow with PKCE, a `state` and a nonce, and verifies
  the ID token's signature, issuer, audience and expiry, and the access token hash when present.
  Users are matched by issuer and subject, never by email address. The discovery and token
  requests do not follow redirects, so the issuer cannot be used to make nanobom request other
  addresses.

## HTTP headers

Every response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`,
`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, which prevent
nanobom from being framed by another site. HSTS is left to the TLS-terminating proxy.

## Outbound requests

nanobom makes requests to:

- OSV (`NANOBOM_OSV_URL`), during runs;
- CISA and FIRST (`NANOBOM_KEV_URL`, `NANOBOM_EPSS_URL`), after runs, unless exploitation data is
  off;
- the OpenID Connect provider, at sign-in;
- webhooks: organization webhooks set by organization admins, and the failure webhook.

Organization admins can make nanobom `POST` to any `http` or `https` address they choose,
including addresses on its own network. If nanobom runs next to services that trust their
network, restrict its outbound traffic with a firewall or an egress proxy.

Webhook requests are not signed: receivers should treat them as a hint and keep their URL secret.

## Unauthenticated endpoints

`/healthz`, `/metrics`, the sign-in page and static assets need no session; the upload API needs a
token. Metrics are instance-wide counts; restrict `/metrics` at the proxy if even those should
stay private.
