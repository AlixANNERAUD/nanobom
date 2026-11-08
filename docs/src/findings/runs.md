# Runs and matching

## When runs happen

| Trigger | Scope | When |
| --- | --- | --- |
| `upload` | the project | right after each upload (unless `NANOBOM_RUN_AFTER_UPLOAD=false`), or when an upload waits for its evaluation |
| `scheduled` | every project of the instance | on `NANOBOM_SCHEDULE`, by default `0 3 * * *`: every day at 03:00 UTC |
| `manual` | an organization or a project | **Check now** on the organization or project page (members and above) |

The schedule is a cron expression in UTC with five fields (minute, hour, day of month, month, day
of week): `0 */6 * * *` runs every six hours, `30 2 * * 1-5` at 02:30 on weekdays. `off` turns
scheduled runs off; uploads and manual checks still run. An invalid expression stops the server
at startup with `invalid NANOBOM_SCHEDULE`.

The nightly run is what catches advisories published after a project's last build. Turning it
off means a project that is not rebuilt is never re-checked, and stale projects are never
notified.

### One run at a time

Runs execute one after the other, in the order requested. A request for a scope that is already
waiting in the queue is merged with it: twenty uploads to the same project during a long run
cause one more run, not twenty. Since runs share one queue, a manual check or a waiting upload
can sit behind the nightly run of a large instance; the run's duration is in the
`nanobom_run_duration_seconds` metric.

### Failed runs

A run fails when OSV cannot be reached (after three attempts per request, for network errors,
rate limiting and server errors) or answers something unexpected. Apart from returning expired
ignores to open, a failed run changes no finding: they stay as the last successful run left them, so a failure never reads as "no
vulnerabilities". It is listed as **Failed** under **Recent runs**, counted by
`nanobom_run_failures_total`, and sent to `NANOBOM_FAILURE_WEBHOOK_URL` if set.

**Recent runs** on an organization page lists the runs of that organization and its projects,
and the instance-wide scheduled runs. The error message of an instance-wide run can name other
organizations' packages, so only instance administrators see it; others read "the run could not
complete".

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

`NANOBOM_OSV_URL` points at another OSV-compatible API, such as a mirror; it must offer
`/v1/querybatch` and `/v1/vulns/{id}`.

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

### Aliases

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

A finding takes the highest severity among the records of its group. Severity is recomputed at every run, so a re-scored advisory moves the
finding.

**Unknown** is not "harmless": it means no score was published yet, which is common for fresh
advisories of some ecosystems. Unknown findings are listed after low ones and never trip a
severity gate.
