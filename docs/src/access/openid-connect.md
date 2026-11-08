# OpenID Connect

nanobom signs users in with any OpenID Connect provider, using the authorization code flow with
PKCE and a nonce. Setting the issuer and the client identifier enables it; a **Sign in with
single sign-on** button then appears on the sign-in page, next to the password form if local
accounts stay on.

## Setting up the client

In your provider, create a client (also called application or relying party) for nanobom:

| Setting | Value |
| --- | --- |
| Type | Web application, authorization code flow |
| Redirect URI | `<public URL>/auth/oidc/callback`, e.g. `https://nanobom.example.org/auth/oidc/callback` |
| Client authentication | a client secret (confidential client), or none (public client, PKCE only) |
| Scopes | `openid profile email`, plus whatever your provider needs for groups |

Then configure nanobom:

```sh
NANOBOM_PUBLIC_URL=https://nanobom.example.org
NANOBOM_OIDC_ISSUER=https://id.example.org/realms/acme
NANOBOM_OIDC_CLIENT_ID=nanobom
NANOBOM_OIDC_CLIENT_SECRET=…        # omit for a public client
```

The redirect URI is built from `NANOBOM_PUBLIC_URL`, so the two must agree exactly, scheme and
port included: most "redirect URI mismatch" errors come from a public URL left at its default,
`http://localhost:8080`.

nanobom reads the provider's discovery document (`<issuer>/.well-known/openid-configuration`) at
the first sign-in, not at startup, so a provider that is down does not prevent nanobom from
starting. The discovery request does not follow redirects: give the issuer exactly as the
provider announces it.

> **Known limitation:** nanobom currently removes a trailing slash from `NANOBOM_OIDC_ISSUER`,
> while the issuer in the discovery document must match it character for character. Providers
> whose issuer ends with `/`, such as Authentik, fail at the first sign-in with
> `unexpected issuer URI` in the logs. Keycloak, Zitadel and most other providers announce their
> issuer without a trailing slash and are not affected.

## How users are matched

A user is identified by the provider's **issuer and subject** (`iss` and `sub`), never by email
address: an attacker who can set an arbitrary email address at a provider cannot take over an
account. At the first sign-in, with `NANOBOM_OIDC_CREATE_USERS=true` (the default), nanobom
creates the user:

- the **username** comes from `preferred_username`, else the part of `email` before `@`, folded
  to lower case with other characters than letters, digits, `.`, `_` and `-` replaced by `-`;
  `-2`, `-3`… is appended when it is taken;
- the **email address** is kept if no other account uses it;
- the **display name** comes from `name`.

These are taken at the first sign-in and not updated afterwards. Claims are read from the ID
token and from the provider's user information endpoint, the ID token winning when both have one.

Consequences worth knowing:

- A local account and a single sign-on identity are **two different users**, even with the same
  email address. There is no linking: if someone used a local account before single sign-on was
  set up, their memberships do not carry over; add the new user to the organizations, then
  disable the local account.
- A single sign-on user only exists after their first sign-in, so they can only be added to an
  organization by hand after that (group mapping, below, avoids the wait).
- With `NANOBOM_OIDC_CREATE_USERS=false`, only users who signed in before can sign in; others see
  "This account is not known here and new accounts are not created automatically". Turn it off once everyone who should have access has an
  account, if the provider serves more people than nanobom should.
- Personal organizations are created for new single sign-on users too, according to
  `NANOBOM_PERSONAL_ORGANIZATIONS`.

## Instance administrators

A claim can grant instance administration:

```sh
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```

The user is an instance administrator when the claim contains the value: as an element of a list
(`["nanobom-admins", "developers"]`), a key of an object (Zitadel's roles), or the whole string.
Without `NANOBOM_OIDC_ADMINISTRATOR_VALUE`, the claim must be the boolean `true`.

The claim is applied at **each sign-in, both ways**: it grants administration, and removes it
from a user who no longer has it, including rights given on the **Administration** page. The
provider is the authority for its users. Without `NANOBOM_OIDC_ADMINISTRATOR_CLAIM`, sign-in never
changes the flag.

## Mapping groups to organization roles

```sh
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member;auditors=acme:viewer;platform=infra:owner"
```

The mapping is a list of `group=organization:role` entries, separated by `;` or line breaks:

- `group` is a name as it appears in the groups claim; it may contain `:` but not `=`;
- `organization` is an organization slug;
- `role` is `viewer`, `member`, `admin` or `owner`.

Spaces around entries and parts are ignored. An invalid entry stops the server at startup with
`invalid NANOBOM_OIDC_GROUP_MAPPING`, naming the entry.

At each sign-in, nanobom reads the user's groups from the claim and replaces the user's
**synchronized** memberships with those the mapping gives:

- when several groups give a role in the same organization, the highest wins;
- an organization named by the mapping is created if it does not exist, with its slug as its
  name; if no group maps to `owner` in it, only instance administrators can manage its owners;
- a user who left a group loses its role at their **next sign-in**; until then, and as long as
  their session lasts, they keep it. Disable the user to cut access at once;
- groups that are not in the mapping are ignored.

Synchronized memberships are kept apart from the ones given in nanobom: a sign-in never changes
a role an admin gave by hand, and the effective role is the higher of the two (see
[Managing members](roles.md#managing-members)).

The groups claim can be a list of strings, an object whose keys are the names, or a single
string. Its name is looked up as a whole first (`urn:zitadel:iam:org:project:roles` is one claim),
then as a dot-separated path into nested objects (`realm_access.roles`).

## Provider examples

### Keycloak

1. In the realm, **Clients → Create client**: OpenID Connect, client ID `nanobom`; **Client
   authentication** on, **Standard flow** on; **Valid redirect URIs**
   `https://nanobom.example.org/auth/oidc/callback`. Copy the secret from **Credentials**.
2. For groups: **Clients → nanobom → Client scopes → nanobom-dedicated → Add mapper → By
   configuration → Group Membership**, with token claim name `groups`, **Full group path** off,
   **Add to ID token** and **Add to userinfo** on.

```sh
NANOBOM_OIDC_ISSUER=https://keycloak.example.org/realms/acme
NANOBOM_OIDC_CLIENT_ID=nanobom
NANOBOM_OIDC_CLIENT_SECRET=…
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member"
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```

To use realm roles instead of groups, set `NANOBOM_OIDC_GROUPS_CLAIM=realm_access.roles`, and turn
on **Add to ID token** (or **Add to userinfo**) in the **realm roles** mapper of the `roles` client
scope: by default Keycloak puts roles in the access token only, which nanobom does not read.

### Zitadel

1. In a project, **New application → Web**, authentication method **Code** (with a secret) or
   **PKCE** (public client); redirect URI `https://nanobom.example.org/auth/oidc/callback`.
   During tests over plain `http`, enable **Development Mode** on the application.
2. Create the project roles (`nanobom-admin`, `acme-developers`, …), grant them to users, and
   enable **Assert Roles on Authentication** in the project's settings, so the roles are part of
   the user information.

```sh
NANOBOM_OIDC_ISSUER=https://acme-abc123.zitadel.cloud
NANOBOM_OIDC_CLIENT_ID=289746…@nanobom
NANOBOM_OIDC_CLIENT_SECRET=…
NANOBOM_OIDC_GROUPS_CLAIM=urn:zitadel:iam:org:project:roles
NANOBOM_OIDC_GROUP_MAPPING="acme-developers=acme:member;acme-security=acme:admin"
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=urn:zitadel:iam:org:project:roles
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admin
```

Zitadel's roles claim is an object whose keys are the role names, which nanobom reads as the
list of groups.

### Authentik

1. **Applications → Providers → Create → OAuth2/OpenID Provider**: client type **Confidential**,
   redirect URI `https://nanobom.example.org/auth/oidc/callback` (strict).
2. **Applications → Create** with slug `nanobom`, using that provider.

Authentik's default `profile` scope includes a `groups` claim listing the user's group names.

```sh
NANOBOM_OIDC_ISSUER=https://authentik.example.org/application/o/nanobom/
NANOBOM_OIDC_CLIENT_ID=…
NANOBOM_OIDC_CLIENT_SECRET=…
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member"
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```

Authentik's issuer ends with a slash, so it is affected by the
[known limitation](#setting-up-the-client) above.

### Other providers

- Providers that only include groups when asked need the scope:
  `NANOBOM_OIDC_SCOPES="openid profile email groups"` (Authelia, Dex).
- Microsoft Entra ID puts group **object IDs** in `groups`, not names: use the IDs in the
  mapping, or emit application roles and map the `roles` claim.

## Signing in without local accounts

Once single sign-on works and an administrator signs in through it (with the administrator
claim, or after an existing administrator granted it), local accounts can be turned off with
`NANOBOM_LOCAL_ACCOUNTS=false`: see [Local accounts](local-accounts.md#turning-local-accounts-off).
Keep a way back: if the provider is down, nobody can sign in until local accounts are turned on
again.

## When sign-in fails

The sign-in page shows a short message and the logs say why:

| Message | Cause |
| --- | --- |
| The identity provider could not sign you in | Discovery failed, the provider refused the sign-in (wrong redirect URI or client secret), or its answer could not be verified; see the `OpenID Connect sign-in refused` or `starting the OpenID Connect sign-in failed` log line |
| The sign-in took too long; please try again | The session cookie set when leaving for the provider was not sent back: the sign-in took longer than the session, or the public URL's host or scheme differs from the address in the browser |
| This account is not known here and new accounts are not created automatically | `NANOBOM_OIDC_CREATE_USERS=false` and the user never signed in |
| This account is disabled | An instance administrator disabled the user |

See also [Troubleshooting](../troubleshooting.md#single-sign-on).
