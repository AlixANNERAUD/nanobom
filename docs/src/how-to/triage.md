# Triage findings

A project with a few hundred dependencies easily has dozens of findings. Why they are ordered as
they are is explained in [Prioritization](../explanation/prioritization.md); a reasonable
routine, from most to least urgent:

1. **Known exploited** findings: someone exploits them in the wild. CISA gives federal agencies a
   due date to fix each one; it is a fair deadline for anyone.
2. **Critical and high** findings with a high EPSS score.
3. The rest, by severity, during regular dependency updates.

Findings that do not apply (vulnerable code not reachable, feature not compiled in, accepted
risk) are ignored with a reason, ideally with an expiry date so the decision is revisited.
Ignoring and restoring need the member role or above ([roles](../reference/accounts.md#organization-roles)).

## Ignore a finding

On the finding's page, under **Triage**:

1. **Reason** (required, up to 2,000 characters): why it does not apply or is accepted. It is kept
   in the finding's history with your name, for whoever reads it next year.
2. **Ignore until** (optional): a date, `YYYY-MM-DD`, after which the finding opens again.
3. Select **Ignore finding**.

Good reasons are specific and checkable:

- "Only the `sqlite` feature of sqlx is compiled; the PostgreSQL driver is not linked."
- "Affects the CLI parsing of `foo`; we only use its library API. Revisit when upgrading to 3.x."

An expiry date turns a decision into a reminder: ignore until the date of the planned upgrade,
not forever. Only open findings can be ignored. What an ignored finding still does, and when it
opens again, is described in
[How findings are kept up to date](../explanation/findings.md#ignored-findings).

## Restore a finding

**Restore finding**, on the page of an ignored finding, returns it to open at once. Only ignored
findings can be restored; fixed findings need no action.

## Filter a project's findings

On the project page, filters narrow the findings by severity, status (open and ignored by
default, or one status, or all), ecosystem, or to **Only known exploited vulnerabilities**.

## Find which projects use a package

The search box at the top of every page finds components across all the organizations you can
see:

| Query | Finds |
| --- | --- |
| `openssl` | components whose name contains `openssl` (case-insensitive) |
| `openssl 3.` | the same, with a version starting with `3.` |
| `lodash@4.17` | the same as `lodash 4.17` |
| `babel/core` | `@babel/core`; leave out a leading `@`, which would start the version |

Names include the namespace of the package URL (`@scope/name` for npm, `group/name` for Maven).
At most 200 results are shown. Search is the quickest answer to "are we affected?" when an
advisory is in the news, before the nightly run has even picked it up.

From a finding's page, **Also affected** lists the other components affected by the same
vulnerability in the organizations you can see.

## Check a project now

**Check now**, on an organization or project page (members and above), starts a run of that
scope instead of waiting for the next upload or the nightly run.

## Retire a project

A project whose SBOM stopped coming is flagged **Stale** ([stale projects](../explanation/findings.md#stale-projects)).
If it was retired, delete it from its page (admins): its components, upload history and findings
are deleted. With an organization token, a later upload under the same slug creates it again.
