# Manage users, administrators and organizations

What each role allows, and the rules for usernames and passwords, are in the
[accounts reference](../reference/accounts.md). Users and instance administration are managed by
instance administrators on the **Administration** page; organizations and their members by the
organization's admins and owners.

## Create a local account

There is no self-registration. An instance administrator opens **Administration → New local
account** and sets the username, an optional email address, the initial password, and whether
the user is an instance administrator. The user signs in with their username or email address.

The first administrator is created on the command line, with `nanobom create-administrator`
([Install nanobom](install.md#create-the-first-administrator)). Users who sign in with single
sign-on are created at their first sign-in ([Set up single sign-on](single-sign-on.md)).

## Reset a password

There is no reset by email. An instance administrator sets a new password for the user on the
**Administration** page. Setting a new password ends all of the user's sessions.

## Disable a user

On the **Administration** page, an instance administrator disables the user. A disabled user
cannot sign in, and their current sessions stop working at their next request. Their memberships
are kept, so enabling them again restores their access. Administrators cannot disable
themselves.

## Grant or remove instance administration

On the **Administration** page, an instance administrator grants or removes instance
administration. Administrators cannot remove their own, so an instance cannot lose its last
administrator by accident. With `NANOBOM_OIDC_ADMINISTRATOR_CLAIM` set, the identity provider
decides at each sign-in instead, and overrides changes made here
([administrator claim](../reference/accounts.md#administrator-claim)).

## Create an organization

Any signed-in user can create an organization from the **Organizations** page, under **New
organization** (a name and a slug), and becomes its owner. The slug appears in addresses and
upload URLs, so keep it short (`acme`).

With `NANOBOM_PERSONAL_ORGANIZATIONS` on (the default), every new user also gets a personal
organization. Turn the setting off when organizations mirror teams and personal spaces would only
clutter the list; it applies to users created afterwards.

With single sign-on, organizations can also be created by the
[group mapping](group-mapping.md).

## Add and manage members

An organization's admins manage members in **Settings → Members**:

- **Add member** takes the username or email address of an existing account. Users who sign in
  with single sign-on only exist after their first sign-in.
- Admins can give and take away the viewer, member and admin roles; granting, changing or
  removing an **owner** needs an owner.
- An organization always keeps at least one owner: removing or demoting the last one is refused.
- Any member can **Leave** an organization, unless they are its last owner.

Typical assignments: **viewer** for auditors and managers who read reports; **member** for the
developers who triage findings; **admin** for whoever maintains the CI integration; **owner** for
the people accountable for the organization.

Roles from the identity provider's groups are listed apart, under **From groups**, and cannot be
changed here; removing a role given in nanobom leaves the one from groups.

## Rename or delete an organization

In the organization's **Settings**, admins rename it; owners delete it, with its projects,
findings, tokens and memberships, for good.
