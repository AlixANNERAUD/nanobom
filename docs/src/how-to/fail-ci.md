# Fail CI on vulnerabilities

An upload with `fail_on` waits for the project's evaluation and answers `409` when its open
findings reach the threshold, so the CI job fails. The thresholds, the response and the status
codes are in the [upload API reference](../reference/upload-api.md#fail_on-thresholds).

## Turn the gate on

Add the threshold to the upload:

- with the GitHub Action or the [GitLab CI template](upload-from-ci.md#gitlab-ci), the input
  `fail-on: high`;
- with any other client, the query parameter `fail_on=high`, as in the
  [curl example](upload-from-ci.md#any-ci-with-curl).

`exploited` fails on known exploited findings whatever their severity; it needs exploitation data,
and is refused with a `422` on an instance with `NANOBOM_EXPLOITATION_DATA=false` rather than
always passing.

Thresholds combine, separated by commas: `fail_on=high,exploited` fails on either. `license`
fails on components whose license the organization forbids
([Enforce a license policy](license-policy.md#fail-ci-on-forbidden-licenses)).

The client must treat any status from 400 as a failure while printing the body, which lists the
findings that crossed the threshold in `evaluation.findings`: the action and the GitLab template
do it, and so do `curl --fail-with-body` and `wget --content-on-error`.

## Before turning it on

- **The gate looks at the whole project, not at what changed.** A pipeline that never touched
  `lodash` fails when a new advisory for it appears overnight. That is the point of a gate on the
  default branch; on pull requests, it can surprise contributors.
- **Ignoring is how a pipeline passes while the fix is planned.** Ignored findings do not count:
  ignore with a reason and an expiry date ([Triage findings](triage.md)).
- **No answer is not a pass.** When the evaluation fails (OSV unreachable) or times out, the
  upload answers `503`: the findings are not up to date, so the gate cannot say they are fine. If
  you would rather not block releases on OSV's availability, treat `503` as a warning in your
  script.
- **`unknown` severity never fails a severity gate.** Findings whose advisory has no score or
  rating are only caught by `exploited` (if they are), or by reading the project page.

## Let uploads wait through your proxies

A waiting upload holds its HTTP request open for up to `NANOBOM_UPLOAD_WAIT_SECONDS` (300 by
default). Every proxy between CI and nanobom must allow that, or CI gets a `504` from the proxy
while the run goes on:

- nginx: `proxy_read_timeout 330s;` on the API location (the default is 60 seconds);
- Traefik 3: the entry point's `transport.respondingTimeouts.readTimeout` defaults to 60 seconds;
  raise it above the wait as a precaution, and keep `forwardingTimeouts.responseHeaderTimeout`
  unset (no limit) or above it;
- Caddy does not limit how long a proxied response takes by default (unless
  `response_header_timeout` is set);
- cloud load balancers often have an idle timeout of 60 seconds that needs raising.

Alternatively, lower `NANOBOM_UPLOAD_WAIT_SECONDS` below your proxy's timeout. Complete proxy
configurations are in [Run behind a reverse proxy](reverse-proxy.md).

Keep `NANOBOM_UPLOAD_WAIT_SECONDS` above the usual duration of a project's run plus the time it
may wait behind the nightly run: runs execute one at a time.

## When the gate fails

- `409`: fix the findings listed in `evaluation.findings` by upgrading the components, or ignore
  the ones that do not apply, then run the job again.
- `503`: see [Upload answers 503](troubleshoot.md#upload-answers-503).

The SBOM is stored in both cases: the inventory is up to date even when the gate fails.

## Turn the gate off

Remove `fail_on` (or `fail-on`) from the upload; the SBOM is still recorded.
