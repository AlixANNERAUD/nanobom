# Prioritization

Severity tells how bad a vulnerability could be. Most critical vulnerabilities are never
exploited, and some medium ones are exploited widely. A project with a few hundred dependencies
easily has dozens of findings, so severity alone does not say where to start. nanobom adds two
public signals of actual exploitation to each finding that has a CVE, and lists findings by them
first.

## The signals

**Known exploited (CISA KEV).** The US Cybersecurity and Infrastructure Security Agency keeps the
[Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
vulnerabilities with reliable evidence of exploitation in the wild. A finding with a CVE in it is
**known exploited**, and shows:

- the date CISA added it;
- its **due date**, the deadline CISA sets for US federal agencies to remediate it;
- whether it is known to be used in ransomware campaigns.

Someone exploits these in the wild, which makes them the most urgent; CISA's due date is a fair
deadline for anyone.

**EPSS.** FIRST's [Exploit Prediction Scoring System](https://www.first.org/epss/) estimates the
probability that a CVE is exploited in the next 30 days, from 0 to 1, and its percentile among
all scored CVEs. An EPSS of 0.0149 with a percentile of 0.78 means "1.5% chance, higher than 78%
of CVEs". It is a ranking aid, not a verdict.

Only CVE identifiers are looked up: those among the finding's identifier and its aliases. A
finding known only by a GHSA or RustSec identifier, with no CVE alias, has neither signal. When a
finding has several CVEs, it takes the most alarming value of each signal: known exploited if any
of them is, the earliest due date, the highest EPSS score.

## Ordering

On the project page, findings are listed:

1. known exploited first;
2. then by severity, critical first;
3. within a severity, by EPSS score, highest first; findings without a score last;
4. then by CVSS score.

The upload response's `evaluation.findings` is ordered by severity first (its 100 entries keep
the most severe), and within a severity in the order above.

The project page's filter **Only known exploited vulnerabilities** keeps the known exploited
ones; the organization page counts them per project, and the `nanobom_open_findings_known_exploited`
metric counts them across the instance. A CI gate with `fail_on=exploited` fails on them whatever
their severity.

## When the data is refreshed

After each successful run, nanobom refreshes the data of the CVEs of the run's scope (those of
open and ignored findings):

- the KEV catalog is downloaded and kept in memory for 12 hours, so most runs reuse it;
- EPSS scores are fetched, 100 CVEs per request, for the CVEs whose score is older than 24 hours.

Nothing is written unless every download succeeded: a failed download keeps the previous data
for every CVE. The run itself is not affected by a failed refresh. Failures are logged (`refreshing
exploitation data failed`) and counted by `nanobom_exploitation_refresh_failures_total`.

Two bounds keep an outage of those services from slowing nanobom down:

- a refresh taking more than 60 seconds is abandoned (and counted as failed), because uploads
  waiting for their evaluation are answered only after it;
- after a failed download of the KEV catalog, refreshes fail at once for 5 minutes instead of
  retrying it, so a series of uploads during an outage does not wait for the retries each time.

The refresh comes before waiting uploads are answered so that `fail_on=exploited` sees the CVEs
first reported by that very run.

A vulnerability added to the KEV catalog after it was first reported is noticed at the next
refresh of a run covering it, at the latest the nightly run, and is notified once with the
`exploited` reason (see [`findings.new`](../reference/webhooks.md#findingsnew)).

## Limits

- The signals only cover CVEs; ecosystems whose advisories rarely get a CVE get few signals.
- EPSS predicts, it does not observe; KEV lists only what CISA has evidence for. Neither says
  whether the vulnerable code is reachable in your project: that is what triage records.
- Instances that cannot reach CISA and FIRST can use mirrors or turn the data off
  ([Run without internet access](../how-to/offline.md)); with it off, no finding is known
  exploited.
