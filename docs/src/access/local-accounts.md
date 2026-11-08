# Local accounts

Local accounts are on by default (`NANOBOM_LOCAL_ACCOUNTS=true`). Users sign in with their
username or their email address, and a password.

## Creating accounts

There is no self-registration. Accounts come from:

- `nanobom create-administrator`, for instance administrators, on the command line;
- **Administration → New local account**, where an instance administrator sets the username, an
  optional email address, the initial password, and whether the user is an instance
  administrator;
- OpenID Connect, for users who sign in with single sign-on (see
  [OpenID Connect](openid-connect.md)).

Usernames are 1 to 64 characters among lower-case letters, digits, `.`, `_` and `-`, starting
with a letter or a digit. Email addresses are not verified; they are only another way to sign in
and to add the user to an organization, and each address belongs to one account at most.

## Passwords

- Passwords must have at least `NANOBOM_PASSWORD_MINIMUM_LENGTH` characters (12 by default) and
  at most 1,024. There are no composition rules: length is what makes a password strong, and a
  password manager is the way to get one.
- They are hashed with Argon2id.
- Instance administrators set a new password for a user from the **Administration** page; there
  is no reset by email. Setting a new password ends all of the user's sessions.

## Rate limiting

Password sign-in attempts are limited per client address: a burst of 5, then one attempt every 4
seconds. Beyond that, the server answers `429 Too Many Requests`.

Behind a reverse proxy, nanobom sees the proxy's address as the client of every request, so all
users would share one budget. Set `NANOBOM_TRUST_FORWARDED_HEADERS=true` to read the client
address from the `X-Forwarded-For`, `X-Real-IP` or `Forwarded` headers instead, **only** when a
proxy you control sets them: otherwise any client can send a made-up header and escape the limit.
See [Reverse proxy and TLS](../operations/reverse-proxy.md).

## Sessions

A successful sign-in starts a session, stored in the database, so restarts and upgrades do not
sign anyone out. The session cookie, `nanobom_session`, is:

- `HttpOnly`, out of reach of scripts;
- `SameSite=Lax`, not sent with cross-site form submissions;
- `Secure` when `NANOBOM_PUBLIC_URL` starts with `https://`, so it is only sent over TLS.

A session ends after `NANOBOM_SESSION_INACTIVITY_DAYS` (7 by default) without a request, when
the user signs out, when their password changes, or when they are disabled. Expired sessions are
deleted every hour.

## Turning local accounts off

With single sign-on in place, `NANOBOM_LOCAL_ACCOUNTS=false` removes the password form and the
password sign-in route: every user, administrators included, signs in through the identity
provider. Local accounts stay in the database and work again if the setting is turned back on.
nanobom refuses to start with local accounts off and no OpenID Connect configured, since nobody
could sign in.

Keep in mind that a local account and a single sign-on identity are two different users, even
with the same email address: see [OpenID Connect](openid-connect.md#how-users-are-matched).
