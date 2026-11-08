# Set up single sign-on

nanobom signs users in with any OpenID Connect provider. Setting the issuer and the client
identifier enables it; a **Sign in with single sign-on** button then appears on the sign-in page,
next to the password form if local accounts stay on. How single sign-on users are created and
matched is described in the [accounts reference](../reference/accounts.md#single-sign-on-users),
and why in the [security model](../explanation/security.md#single-sign-on).

## 1. Create the client at the provider

Create a client (also called application or relying party) for nanobom:

| Setting | Value |
| --- | --- |
| Type | Web application, authorization code flow |
| Redirect URI | `<public URL>/auth/oidc/callback`, e.g. `https://nanobom.example.org/auth/oidc/callback` |
| Client authentication | a client secret (confidential client), or none (public client, PKCE only) |
| Scopes | `openid profile email`, plus whatever your provider needs for groups |

The steps for [Keycloak](#keycloak), [Zitadel](#zitadel) and [Authentik](#authentik) are below.

## 2. Configure nanobom

```sh
NANOBOM_PUBLIC_URL=https://nanobom.example.org
NANOBOM_OIDC_ISSUER=https://id.example.org/realms/acme
NANOBOM_OIDC_CLIENT_ID=nanobom
NANOBOM_OIDC_CLIENT_SECRET=…        # omit for a public client
```

Restart nanobom. All `NANOBOM_OIDC_*` options are in the
[configuration reference](../reference/configuration.md#openid-connect).

- The redirect URI is built from `NANOBOM_PUBLIC_URL`, so the two must agree exactly, scheme and
  port included: most "redirect URI mismatch" errors come from a public URL left at its default,
  `http://localhost:8080`.
- nanobom reads the provider's discovery document (`<issuer>/.well-known/openid-configuration`)
  at the first sign-in, not at startup, so a provider that is down does not prevent nanobom from
  starting. The discovery request does not follow redirects: give the issuer exactly as the
  provider announces it.

## 3. Grant instance administration from the provider (optional)

```sh
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```

A user whose claim contains the value is an instance administrator. The claim is applied at each
sign-in, both ways: it also removes administration given on the **Administration** page from
users who do not have it. See [administrator claim](../reference/accounts.md#administrator-claim).

To give organization roles from groups as well, see
[Map identity-provider groups to organizations](group-mapping.md).

## 4. Sign in

Sign out, then select **Sign in with single sign-on**. The first sign-in creates your user. If it
fails, the page shows a short message and the logs say why: see
[Single sign-on](troubleshoot.md#single-sign-on) in the troubleshooting guide.

Before inviting people, know that:

- A local account and a single sign-on identity are **two different users**, even with the same
  email address. There is no linking: if someone used a local account before single sign-on was
  set up, their memberships do not carry over; add the new user to the organizations, then
  disable the local account.
- A single sign-on user only exists after their first sign-in, so they can only be added to an
  organization by hand after that ([group mapping](group-mapping.md) avoids the wait).
- With `NANOBOM_OIDC_CREATE_USERS=false`, only users who signed in before can sign in. Turn it off
  once everyone who should have access has an account, if the provider serves more people than
  nanobom should.

## 5. Turn local accounts off (optional)

Once single sign-on works and an administrator signs in through it (with the administrator claim,
or after an existing administrator granted it), set `NANOBOM_LOCAL_ACCOUNTS=false`. This removes
the password form and the password sign-in route: every user, administrators included, signs in
through the identity provider. Local accounts stay in the database and work again if the setting
is turned back on. nanobom refuses to start with local accounts off and no OpenID Connect
configured, since nobody could sign in.

Keep a way back: if the provider is down, nobody can sign in until local accounts are turned on
again.

## Keycloak

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

## Zitadel

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

## Authentik

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

Authentik's issuer ends with a slash (`…/application/o/nanobom/`); keep it in
`NANOBOM_OIDC_ISSUER`.

## Other providers

- Providers that only include groups when asked need the scope:
  `NANOBOM_OIDC_SCOPES="openid profile email groups"` (Authelia, Dex).
- Microsoft Entra ID puts group **object IDs** in `groups`, not names: use the IDs in the
  mapping, or emit application roles and map the `roles` claim.
