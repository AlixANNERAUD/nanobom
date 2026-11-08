# Continuous integration

Every CI system can upload with `curl`. GitHub Actions also has a dedicated action that generates
the SBOM, uploads it and reports the findings in the job.

In each case, store the upload token as a **secret** of the CI system, and the instance's address
as a plain variable.

## GitHub Actions

[nanobom-action](https://github.com/AlixANNERAUD/nanobom-action) uploads an SBOM, writes the
evaluation to the job summary, annotates the job with the findings that fail the gate, and sets
outputs for later steps. Without an `sbom` input it generates one with Syft from the checkout.

```yaml
name: SBOM

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          fail-on: high
```

The project defaults to the repository's name. Useful inputs:

| Input | Default | |
| --- | --- | --- |
| `project` | repository name | Project slug |
| `sbom` | | An existing CycloneDX JSON file; without it, Syft generates one |
| `scan-path` | `.` | Directory Syft scans |
| `scan-image` | | Container image Syft scans instead |
| `fail-on` | | `critical`, `high`, `medium`, `low` or `exploited` |
| `wait` | `true` | Wait for the evaluation and report it |
| `source-commit`, `image-tag` | the commit; the Git tag, if any | Shown in the upload history |

Outputs include `http-status`, `project-url`, `evaluation-status`, the open findings per severity
(`critical`, `high`, `medium`, `low`) and `known-exploited`. The
[action's README](https://github.com/AlixANNERAUD/nanobom-action#readme) lists them all.

An SBOM from your own generator, for a Rust project:

```yaml
      - run: cargo install cargo-cyclonedx --locked
      - run: cargo cyclonedx --format json --override-filename sbom
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          sbom: sbom.json
          fail-on: exploited
```

[`examples/github-actions.yml`](https://github.com/AlixANNERAUD/nanobom/blob/main/examples/github-actions.yml)
is that workflow in full. Without the action, upload with `curl` as in
[Any CI, with curl](#any-ci-with-curl).

## GitLab CI

[`examples/gitlab-ci.yml`](https://github.com/AlixANNERAUD/nanobom/blob/main/examples/gitlab-ci.yml)
generates the SBOM of a container image with Syft on each tag and uploads it. The Syft image has
`wget` but not `curl`:

```yaml
sbom:
  stage: deploy
  image:
    name: anchore/syft:latest
    entrypoint: [""]
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - syft "$CI_REGISTRY_IMAGE:$CI_COMMIT_TAG" --output cyclonedx-json=sbom.json
    - >
      wget --quiet --output-document=- --content-on-error --method=PUT
      --header="Authorization: Bearer $NANOBOM_TOKEN"
      --header="Content-Type: application/json"
      --body-file=sbom.json
      "$NANOBOM_URL/api/organizations/acme/projects/$CI_PROJECT_NAME/sbom?source_commit=$CI_COMMIT_SHA&image_tag=$CI_COMMIT_TAG&fail_on=high"
```

Define `NANOBOM_URL` and `NANOBOM_TOKEN` (masked) under **Settings → CI/CD → Variables**.
`--content-on-error` prints the response body on a `409`, so the job log shows which findings
failed the gate. A registry that needs credentials needs them in the job too (Syft reads
`~/.docker/config.json`, or `SYFT_REGISTRY_AUTH_*` variables).

## Any CI, with curl

```sh
#!/bin/sh
set -eu
# NANOBOM_URL, NANOBOM_TOKEN, COMMIT and the SBOM come from the CI system.
curl --fail-with-body --silent --show-error \
  --request PUT \
  --header "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  --output response.json \
  "$NANOBOM_URL/api/organizations/acme/projects/web/sbom?source_commit=$COMMIT&fail_on=high" \
  || { cat response.json; exit 1; }
jq -r '.evaluation | "\(.status): \(.open.critical) critical, \(.open.high) high, \(.known_exploited) known exploited"' response.json
```

- `--data-binary` sends the file unchanged (`--data` would strip its line breaks); `-F` would
  wrap it in a multipart form, which nanobom does not read.
- `--fail-with-body` makes `curl` exit with an error on any status from 400, so the job fails on
  `409` and `503` as well as on configuration mistakes, while keeping the body for the log.

## Gating with `fail_on`

`fail_on` turns the upload into a check: the request waits for the evaluation and fails when the
project's open findings reach the threshold.

| `fail_on` | Fails (`409`) when an open finding is |
| --- | --- |
| `critical` | critical |
| `high` | high or critical |
| `medium` | medium, high or critical |
| `low` | low, medium, high or critical (anything but unknown) |
| `exploited` | known exploited, whatever its severity |

Things to know before turning it on:

- **The gate looks at the whole project, not at what changed.** A pipeline that never touched
  `lodash` fails when a new advisory for it appears overnight. That is the point of a gate on the
  default branch; on pull requests, it can surprise contributors. Ignoring a finding (with a reason
  and an expiry date) is how you let a pipeline pass while the fix is planned: ignored findings do
  not count.
- **No answer is not a pass.** When the evaluation fails (OSV unreachable) or times out, the
  upload answers `503`: the findings are not up to date, so the gate cannot say they are fine. If
  you would rather not block releases on OSV's availability, treat `503` as a warning in your
  script.
- **`unknown` severity never fails a severity gate.** Findings whose advisory has no score or
  rating are only caught by `exploited` (if they are), or by reading the project page.
- **`exploited` needs exploitation data.** On an instance with `NANOBOM_EXPLOITATION_DATA=false`, the
  upload is refused with a `422` rather than always passing.

To stop gating, remove `fail_on` from the URL; the SBOM is still recorded.

## Reverse proxy timeouts

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

Alternatively, lower `NANOBOM_UPLOAD_WAIT_SECONDS` below your proxy's timeout. See
[Reverse proxy and TLS](../operations/reverse-proxy.md) for complete configurations.
