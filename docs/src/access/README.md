# Accounts, organizations and access

Who can see and do what in nanobom depends on two things:

- **instance administration**, a flag on the user account: instance administrators manage users
  and act as owners of every organization;
- **organization roles**: viewer, member, admin or owner, per organization.

Users sign in with a **local account** (username or email address, and password), with **OpenID
Connect** single sign-on, or with both enabled side by side:

- [Roles and permissions](roles.md): what each role allows, personal organizations, managing
  members, instance administrators.
- [Local accounts](local-accounts.md): passwords, rate limiting, sessions.
- [OpenID Connect](openid-connect.md): provider setup with Authentik, Keycloak and Zitadel,
  administrator claim, group mapping.

Upload tokens are not user accounts: they authenticate CI on the upload API only, and are
described in [The upload API](../uploading/api.md#tokens).
