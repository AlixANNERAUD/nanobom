# Map identity-provider groups to organizations

With single sign-on in place ([Set up single sign-on](single-sign-on.md)), nanobom can give each
user their organization roles from the groups (or roles) their identity provider lists, at every
sign-in. Nobody then has to add members by hand, and a user who leaves a group loses its role.

## 1. Put the groups in a claim nanobom reads

nanobom reads claims from the ID token and from the provider's user information endpoint, not
from the access token. Configure the provider to send the user's groups in one of them: see the
steps for [Keycloak](single-sign-on.md#keycloak), [Zitadel](single-sign-on.md#zitadel) and
[Authentik](single-sign-on.md#authentik), and [other providers](single-sign-on.md#other-providers).

## 2. Name the claim and write the mapping

```sh
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member;auditors=acme:viewer;platform=infra:owner"
```

`NANOBOM_OIDC_GROUPS_CLAIM` is the claim's name, or a dotted path into nested claims
(`realm_access.roles`). The mapping is a list of `group=organization:role` entries separated by
`;` or line breaks; the roles are `viewer`, `member`, `admin` and `owner`
([what each allows](../reference/accounts.md#organization-roles)). The exact syntax, and how
memberships are synchronized, are in the
[accounts reference](../reference/accounts.md#roles-from-identity-provider-groups).

Organizations named by the mapping are created at the first sign-in that needs them. Map at least
one group to `owner` in each, or only instance administrators can manage its owners.

Restart nanobom: an invalid entry stops it at startup with `invalid NANOBOM_OIDC_GROUP_MAPPING`,
naming the entry.

## 3. Check

Sign out and in again: roles are applied at sign-in. In the organization's **Settings → Members**,
roles that come from groups are listed apart, under **From groups**; they cannot be changed in
nanobom.

If a role is missing, see
[Groups or administrator rights are not applied](troubleshoot.md#groups-or-administrator-rights-are-not-applied).

## Remove someone's access at once

A user who left a group keeps its role until their next sign-in, as long as their session lasts.
To cut access at once, disable the user ([Manage users](manage-access.md#disable-a-user)).
