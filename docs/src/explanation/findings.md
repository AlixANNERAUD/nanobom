# How findings are kept up to date

A project's findings change for two reasons: its SBOM changed, or what OSV knows changed. nanobom
notices both with runs.

## When runs happen

| Trigger | Scope | When |
| --- | --- | --- |
| `upload` | the project | right after each upload (unless `NANOBOM_RUN_AFTER_UPLOAD=false`), or when an upload waits for its evaluation |
| `scheduled` | every project of the instance | on `NANOBOM_SCHEDULE`, by default `0 3 * * *`: every day at 03:00 UTC |
| `manual` | an organization or a project | **Check now** on the organization or project page (members and above) |

The nightly run is what catches advisories published after a project's last build: new
advisories appear for old versions all the time. Turning it off (`NANOBOM_SCHEDULE=off`) means a
project that is not rebuilt is never re-checked, and stale projects are never notified. It is
also why a CI gate can fail without a code change.

### One run at a time

Runs execute one after the other, in the order requested. A request for a scope that is already
waiting in the queue is merged with it: twenty uploads to the same project during a long run
cause one more run, not twenty. Since runs share one queue, a manual check or a waiting upload
can sit behind the nightly run of a large instance; the run's duration is in the
`nanobom_run_duration_seconds` metric.

### Failed runs

A run fails when OSV cannot be reached (after three attempts per request, for network errors,
rate limiting and server errors) or answers something unexpected. Apart from returning expired
ignores to open, a failed run changes no finding: they stay as the last successful run left them,
so a failure never reads as "no vulnerabilities". It is listed as **Failed** under **Recent
runs**, counted by `nanobom_run_failures_total`, and sent to `NANOBOM_FAILURE_WEBHOOK_URL` if set.

**Recent runs** on an organization page lists the runs of that organization and its projects,
and the instance-wide scheduled runs. The error message of an instance-wide run can name other
organizations' packages, and its counts of new and fixed findings span every organization, so
only instance administrators see them; others read "the run could not complete" and no counts.

A run that stops before it can record its end is recorded as failed with the error "the run
stopped unexpectedly", counted and sent to the failure webhook like any failed run. That happens
right away when a bug makes the run panic (the queue goes on with the next run), and at the next
start when nanobom was stopped or crashed during the run. Such a run is not resumed; the next run
of the same scope does its work.

## Matching against OSV

A run:

1. returns findings whose ignore has expired to open;
2. collects the components of its scope that have a version, and queries
   [OSV's batch API](https://google.github.io/osv.dev/post-v1-querybatch/) once per distinct package
   URL (qualifiers and subpath removed), up to 1,000 per request;
3. downloads the details of each reported vulnerability it does not have yet, or that OSV
   modified since; details are cached in the database, so a nightly run of an unchanged instance
   downloads little more than the batch answers;
4. updates the findings of each project in one transaction.

After a successful run, exploitation data is refreshed for the run's scope
([Prioritization](prioritization.md#when-the-data-is-refreshed)), then webhooks are sent.

## How findings change

For each component and each group of reported vulnerabilities that are aliases of each other:

- if the project has no finding for it, a finding is **opened**;
- if it has a **fixed** one, it is **reopened**;
- if it has an **open** or **ignored** one, it stays as it is, and its severity is updated if the
  advisory changed.

Then every open or ignored finding of the project that was not reported is **fixed**: its
component left the SBOM, was upgraded to an unaffected version, or OSV withdrew or changed the
advisory.

A finding belongs to one component, identified by its full package URL: upgrading `lodash` from
`4.17.20` to `4.17.21` fixes the findings of `pkg:npm/lodash@4.17.20` and opens findings for the
new version, if it has any.

## Aliases

OSV records list the identifiers of the same vulnerability in other databases: a
`GHSA-35jh-r3h4-6jhm` record has `CVE-2021-23337` as alias. When OSV reports several identifiers
for one component, nanobom groups those that share an alias (directly or through others), and
makes one finding per group:

- a new finding is named after the smallest reported identifier of its group;
- later runs find it through any identifier of the group, so a CVE assigned after the GHSA was
  published, or a new RustSec advisory for the same issue, updates the existing finding instead of
  opening another;
- the finding page and webhooks list the other identifiers as aliases.

## Severity

The severity of each record comes from its CVSS vectors, scored by nanobom:

1. the vector of the most recent CVSS version the record has (4.0, then 3.1, 3.0, 2.0) gives a
   base score, rated **critical** from 9.0, **high** from 7.0, **medium** from 4.0, **low** below
   (0.0 included);
2. without a usable vector, the qualitative rating of the advisory database
   (`database_specific.severity`, as GitHub advisories give: `CRITICAL`, `HIGH`, `MODERATE`,
   `LOW`);
3. otherwise **unknown**.

A finding takes the highest severity among the records of its group, so a GitHub advisory and
the CVE it aliases that rate the same issue differently show the higher. Severity is recomputed
at every run, so a re-scored advisory moves the finding.

**Unknown** is not "harmless": it means no score was published yet, which is common for fresh
advisories of some ecosystems. Unknown findings are listed after low ones and never trip a
severity gate.

## Ignored findings

An ignored finding:

- is left out of the open counts, of the CI gate (`fail_on`) and of the metrics;
- does not trigger webhooks;
- is still tracked: if its component goes away it becomes **fixed**, and it still gets
  exploitation data, so you can see if an ignored vulnerability becomes known exploited.

Its expiry is midnight UTC at the start of the given date. It takes effect at the next run
covering the project, which is the nightly run at the latest: the finding returns to open, with an
**Ignore expired** entry in its history, and is then counted again. It is not notified as new;
only as `exploited`, if it became known exploited while ignored.

## Stale projects

A project is **stale** when its last upload, or its creation if it never received an SBOM, is
older than `NANOBOM_STALE_AFTER_DAYS` (30 by default). It usually means its CI job broke or was
removed, and its inventory no longer describes what runs in production.

Stale projects are:

- flagged **Stale** on the organization page, with an alert on the project page;
- counted by the `nanobom_stale_projects` metric;
- sent to the organization's webhook as
  [`projects.stale`](../reference/webhooks.md#projectsstale), after a scheduled run, once per
  stale period.

A stale project keeps being checked by the nightly run: its old inventory still gets new
advisories.
