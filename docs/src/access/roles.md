# Roles and permissions

## Organization roles

Each member of an organization has one of four roles, each including the ones before it:

| Permission | Viewer | Member | Admin | Owner |
| --- | :---: | :---: | :---: | :---: |
| See the organization, its projects, components, findings and runs | ✓ | ✓ | ✓ | ✓ |
| Ignore and restore findings | | ✓ | ✓ | ✓ |
| Start a run (**Check now**) | | ✓ | ✓ | ✓ |
| Add, change and remove members other than owners | | | ✓ | ✓ |
| Delete projects | | | ✓ | ✓ |
| Create and revoke upload tokens | | | ✓ | ✓ |
| Configure the webhook | | | ✓ | ✓ |
| Rename the organization | | | ✓ | ✓ |
| Grant and remove the owner role | | | | ✓ |
| Delete the organization | | | | ✓ |

Typical assignments: **viewer** for auditors and managers who read reports; **member** for the
developers who triage findings; **admin** for whoever maintains the CI integration; **owner** for
the people accountable for the organization.

Projects are created by uploads, not in the interface, so creating one only needs an
organization-wide upload token.

Isolation is enforced below the interface, on every operation: a user who is not a member of an
organization gets "not found" for its pages, projects and findings, as if it did not exist. Search
results and a finding's **Also affected** list only cover organizations you belong to (every
organization, for instance administrators).

## Creating organizations

Any signed-in user can create an organization from the **Organizations** page and becomes its
owner. With `NANOBOM_PERSONAL_ORGANIZATIONS` on (the default), every new user also gets a
**personal organization**, owned by them and named after their username (`alice`, or `alice-2`
if that slug is taken). It is marked "personal" in the list and otherwise behaves like any
organization: you can add members to it, or delete it. Turn the setting off when organizations
mirror teams and personal spaces would only clutter the list; it applies to users created
afterwards.

With OpenID Connect, organizations can also be created by the
[group mapping](openid-connect.md#mapping-groups-to-organization-roles).

## Managing members

An organization's admins manage members in **Settings → Members**:

- **Add member** takes the username or email address of an existing account. Users who sign in
  with single sign-on only exist after their first sign-in.
- Admins can give and take away the viewer, member and admin roles; granting, changing or
  removing an **owner** needs an owner.
- An organization always keeps at least one owner: removing or demoting the last one is refused.
- Any member can **Leave** an organization, unless they are its last owner.

Roles that come from the identity provider's groups are shown apart, under **From groups**. They
cannot be changed in nanobom: they follow the user's groups at each sign-in. A member with both a
role given in nanobom and a role from groups has the higher of the two; removing the one given in
nanobom leaves the other.

## Instance administrators

Instance administrators:

- act as owners in every organization, including those they are not a member of;
- see every organization on the **Administration** page;
- create local accounts, reset passwords, disable and enable users, and grant or remove
  instance administration;
- see the error messages of failed instance-wide runs.

They cannot disable themselves or remove their own administration, so an instance cannot lose its
last administrator by accident. The first one is created on the command line
(`nanobom create-administrator`, see [Getting started](../getting-started.md#2-create-the-first-administrator));
with OpenID Connect, the [administrator claim](openid-connect.md#instance-administrators) can grant
it instead.

A **disabled** user cannot sign in, and their current sessions stop working at their next
request. Their memberships are kept, so enabling them again restores their access.
