# Accounts, roles and permissions

Who can see and do what depends on two things: **instance administration**, a flag on the user
account, and the user's **organization role**, per organization. API tokens are not user
accounts: they authenticate CI and scripts on the [upload API](upload-api.md#tokens), the
[VEX API](vex-api.md) and the [read API](read-api.md) only, where they read as viewers of their
organization.

## Organization roles

Each member of an organization has one of four roles, each including the ones before it:

| Permission | Viewer | Member | Admin | Owner |
| --- | :---: | :---: | :---: | :---: |
| See the organization, its projects, components, findings and runs; export VEX documents | ✓ | ✓ | ✓ | ✓ |
| Ignore and restore findings | | ✓ | ✓ | ✓ |
| Start a run (**Check now**) | | ✓ | ✓ | ✓ |
| Add, change and remove members other than owners | | | ✓ | ✓ |
| Delete projects | | | ✓ | ✓ |
| Create and revoke API tokens, upload or read | | | ✓ | ✓ |
| Configure the webhook | | | ✓ | ✓ |
| Rename the organization | | | ✓ | ✓ |
| Grant and remove the owner role | | | | ✓ |
| Delete the organization | | | | ✓ |

- Any signed-in user can create an organization and becomes its owner.
- Any member can leave an organization, unless they are its last owner. An organization always
  keeps at least one owner: removing or demoting the last one is refused.
- Projects are created by uploads, not in the interface, so creating one only needs an
  organization-wide upload token.
- A user who is not a member of an organization gets "not found" for its pages, projects and
  findings. Search results and a finding's **Also affected** list only cover organizations the
  user belongs to (every organization, for instance administrators).
- A member with both a role given in nanobom and a role from groups has the higher of the two.

## Instance administrators

Instance administrators:

- act as owners in every organization, including those they are not a member of;
- see every organization on the **Administration** page;
- create local accounts, reset passwords, disable and enable users, and grant or remove
  instance administration;
- see the error messages and the finding counts of instance-wide runs.

They cannot disable themselves or remove their own administration. The first one is created with
[`nanobom create-administrator`](command-line.md#nanobom-create-administrator); with OpenID
Connect, the [administrator claim](#administrator-claim) can grant it instead.

## Personal organizations

With `NANOBOM_PERSONAL_ORGANIZATIONS` on (the default), every new user, local or single sign-on,
gets an organization owned by them and named after their username (`alice`, or `alice-2` if that
slug is taken). It is marked "personal" in the list and otherwise behaves like any organization:
members can be added to it, and it can be deleted.

## Names

- **Organization and project slugs** are 1 to 64 characters among lower-case letters, digits,
  `.`, `_` and `-`, starting with a letter or a digit; upper-case letters are folded to lower
  case, so `Acme` and `acme` are the same organization. Organizations also have a display name.
- **Usernames** follow the same rules.
- **Email addresses** are not verified; they are only another way to sign in and to add the user
  to an organization, and each address belongs to one account at most.

## Local accounts

Local accounts are on by default (`NANOBOM_LOCAL_ACCOUNTS=true`). Users sign in with their
username or their email address, and a password. There is no self-registration and no password
reset by email.

- Passwords must have at least `NANOBOM_PASSWORD_MINIMUM_LENGTH` characters (12 by default) and
  at most 1,024. There are no composition rules.
- They are hashed with Argon2id.
- Setting a new password ends all of the user's sessions.
- Password sign-in attempts are limited per client address: a burst of 5, then one attempt every
  4 seconds. Beyond that, the server answers `429 Too Many Requests`. Behind a reverse proxy, the
  client address is read from `X-Forwarded-For`, `X-Real-IP` or `Forwarded` only with
  `NANOBOM_TRUST_FORWARDED_HEADERS=true`.

With `NANOBOM_LOCAL_ACCOUNTS=false`, the password form and the password sign-in route are
removed; local accounts stay in the database and work again if the setting is turned back on.

## Single sign-on users

A single sign-on user is identified by the provider's **issuer and subject** (`iss` and `sub`),
never by email address. At the first sign-in, with `NANOBOM_OIDC_CREATE_USERS=true` (the
default), nanobom creates the user:

- the **username** comes from `preferred_username`, else the part of `email` before `@`, folded
  to lower case with other characters than letters, digits, `.`, `_` and `-` replaced by `-`;
  `-2`, `-3`… is appended when it is taken;
- the **email address** is kept if no other account uses it;
- the **display name** comes from `name`.

These are taken at the first sign-in and not updated afterwards. Claims are read from the ID
token and from the provider's user information endpoint, the ID token winning when both have one;
the access token is not read.

A local account and a single sign-on identity are two different users, even with the same email
address; there is no linking. With `NANOBOM_OIDC_CREATE_USERS=false`, only users who signed in
before can sign in; others see "This account is not known here and new accounts are not created
automatically".

## Administrator claim

With `NANOBOM_OIDC_ADMINISTRATOR_CLAIM` set, a single sign-on user is an instance administrator
when the claim contains `NANOBOM_OIDC_ADMINISTRATOR_VALUE`: as an element of a list
(`["nanobom-admins", "developers"]`), a key of an object (Zitadel's roles), or the whole string.
Without `NANOBOM_OIDC_ADMINISTRATOR_VALUE`, the claim must be the boolean `true`. Dotted paths
reach nested claims.

The claim is applied at **each sign-in, both ways**: it grants administration, and removes it
from a user who no longer has it, including rights given on the **Administration** page. Without
`NANOBOM_OIDC_ADMINISTRATOR_CLAIM`, sign-in never changes the flag.

## Roles from identity-provider groups

```sh
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member;auditors=acme:viewer;platform=infra:owner"
```

`NANOBOM_OIDC_GROUP_MAPPING` is a list of `group=organization:role` entries, separated by `;` or
line breaks:

- `group` is a name as it appears in the groups claim; it may contain `:` but not `=`;
- `organization` is an organization slug;
- `role` is `viewer`, `member`, `admin` or `owner`.

Spaces around entries and parts are ignored. An invalid entry stops the server at startup with
`invalid NANOBOM_OIDC_GROUP_MAPPING`, naming the entry.

The groups claim, named by `NANOBOM_OIDC_GROUPS_CLAIM`, can be a list of strings, an object whose
keys are the names, or a single string. Its name is looked up as a whole first
(`urn:zitadel:iam:org:project:roles` is one claim), then as a dot-separated path into nested
objects (`realm_access.roles`).

At each sign-in, nanobom reads the user's groups from the claim and replaces the user's
**synchronized** memberships with those the mapping gives:

- when several groups give a role in the same organization, the highest wins;
- an organization named by the mapping is created if it does not exist, with its slug as its
  name; if no group maps to `owner` in it, only instance administrators can manage its owners;
- a user who left a group loses its role at their **next sign-in**; until then, and as long as
  their session lasts, they keep it;
- groups that are not in the mapping are ignored.

Synchronized memberships are kept apart from the ones given in nanobom, and shown under **From
groups** in **Settings → Members**, where they cannot be changed. A sign-in never changes a role
an admin gave by hand; the effective role is the higher of the two, and removing the one given in
nanobom leaves the other.

## Sessions

A successful sign-in starts a session, stored in the database, so restarts and upgrades do not
sign anyone out. The session cookie, `nanobom_session`, holds only a random session identifier,
and is `HttpOnly`, `SameSite=Lax`, and `Secure` when `NANOBOM_PUBLIC_URL` starts with `https://`.

A session ends after `NANOBOM_SESSION_INACTIVITY_DAYS` (7 by default) without a request, when
the user signs out, when their password changes, or when they are disabled. Expired sessions are
deleted every hour.

A **disabled** user cannot sign in, and their current sessions stop working at their next
request. Their memberships are kept, so enabling them again restores their access.
