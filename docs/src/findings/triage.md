# Triage, stale projects and search

## Ignoring a finding

When a finding does not apply, or its risk is accepted, a member (or above) ignores it from the
finding's page, under **Triage**:

- **Reason** (required, up to 2,000 characters): why it does not apply or is accepted. It is kept
  in the finding's history with your name, for whoever reads it next year.
- **Ignore until** (optional): a date, `YYYY-MM-DD`, after which the finding opens again.

An ignored finding:

- is left out of the open counts, of the CI gate (`fail_on`) and of the metrics;
- does not trigger webhooks;
- is still tracked: if its component goes away it becomes **fixed**, and it still gets
  exploitation data, so you can see if an ignored vulnerability becomes known exploited.

The expiry is midnight UTC at the start of the given date. It takes effect at the next run
covering the project, which is the nightly run at the latest: the finding returns to open, with an
**Ignore expired** entry in its history, and is then counted again. It is not notified as new;
only as `exploited`, if it became known exploited while ignored.

**Restore finding** returns an ignored finding to open at once. Only open findings can be ignored
and only ignored ones restored; fixed findings need no action.

Good reasons are specific and checkable:

- "Only the `sqlite` feature of sqlx is compiled; the PostgreSQL driver is not linked."
- "Affects the CLI parsing of `foo`; we only use its library API. Revisit when upgrading to 3.x."

An expiry date turns a decision into a reminder: ignore until the date of the planned upgrade,
not forever.

## Stale projects

A project is **stale** when its last upload, or its creation if it never received an SBOM, is
older than `NANOBOM_STALE_AFTER_DAYS` (30 by default). It usually means its CI job broke or was
removed, and its inventory no longer describes what runs in production.

Stale projects are:

- flagged **Stale** on the organization page, with an alert on the project page;
- counted by the `nanobom_stale_projects` metric;
- sent to the organization's webhook as `projects.stale`, after a scheduled run, once per stale
  period: a project is notified again only after it receives an SBOM and later goes stale again
  (see [Notifications](../notifications.md#projectsstale)).

A stale project keeps being checked by the nightly run: its old inventory still gets new
advisories. If the project was retired, delete it from its page (admins), which removes its
components, history and findings. With an organization token, a later upload under the same slug
creates it again.

`NANOBOM_STALE_AFTER_DAYS=0` turns the feature off. Choose a value above the longest normal gap
between two builds: a library released twice a year would be stale most of the time with the
default, so either raise the threshold or upload its SBOM from a scheduled pipeline.

## Searching components

The search box at the top of every page finds which projects use a package, across all the
organizations you can see:

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
