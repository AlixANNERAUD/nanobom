# Upload from CI

Each build that produces something you ship generates an SBOM ([Generate an
SBOM](generate-sbom.md)) and sends it with one `PUT` request, authenticated with an upload token.
The request and its answer are described in the [upload API reference](../reference/upload-api.md).
Pipelines written for Dependency-Track keep their client: see [Upload with Dependency-Track
clients](dependency-track-clients.md).

## Choose which builds upload

Upload from the builds that produce what you ship (the default branch, release tags), not from
every pull request: each upload replaces the project's components, so an SBOM of a feature
branch would hide the state of production until the next upload from `main`. To check a pull
request without replacing anything, use a separate project (`web-pr`), or none at all.
Maintenance branches that ship next to the default one upload to their own version of the
project: see [Track several versions of a product](track-versions.md).

## Create an upload token

An organization's admins create tokens in **Settings → API tokens**: a name, a project, either
**Whole organization** or one project, and the scope **Upload and read** (a **Read only** token
cannot upload). Copy the token when it is shown: it is shown once.

- Use an **organization token** for the first upload of a project: it creates the project.
- Then prefer a **project token** when a repository builds one project: a leaked token reaches
  one project only, and a typo in the URL fails instead of creating a new project. It can only be
  created once the project exists.

With access to the database, the command line does the same and prints the token alone, so a
script can capture it (see the [command-line reference](../reference/command-line.md#nanobom-token)):

```sh
TOKEN=$(nanobom token create --organization acme --name "web CI" --project web)
```

Store the token as a **secret** of the CI system, and the instance's address as a plain variable.
To replace a token, create a new one, update the secret, then revoke the old one; the settings
page shows when each token was last used.

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
| `sbom` | | An existing CycloneDX or SPDX JSON file; without it, Syft generates one |
| `scan-path` | `.` | Directory Syft scans |
| `scan-image` | | Container image Syft scans instead |
| `fail-on` | | `critical`, `high`, `medium`, `low`, `exploited` or `license`, or several separated by commas (`high,license`); see [Fail CI](fail-ci.md) |
| `wait` | `true` | Wait for the evaluation and report it |
| `source-commit`, `image-tag` | the commit; the Git tag, if any | Shown in the upload history |
| `summary` | `true` | Write the evaluation to the job summary |

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

The [GitLab CI template](../reference/gitlab-template.md) adds a `nanobom` job that does what
the GitHub action does: it generates the SBOM with Syft unless you give one, uploads it, writes
the evaluation to the job log, and fails the job on your threshold. Include it in
`.gitlab-ci.yml`, pinned to a release tag:

```yaml
include:
  - remote: https://raw.githubusercontent.com/AlixANNERAUD/nanobom/vX.Y.Z/ci/gitlab/nanobom.yml
    inputs:
      organization: acme
      fail-on: high
```

Replace `vX.Y.Z` with a [release](https://github.com/AlixANNERAUD/nanobom/releases). `main`
works too, but changes under you. Define `NANOBOM_URL` and `NANOBOM_TOKEN` (masked) under
**Settings → CI/CD → Variables**. The project defaults to the GitLab project's name, the scanned
directory to the checkout. Every input is in the [reference](../reference/gitlab-template.md#inputs).

The template sets no `rules`: the job runs in every pipeline. Add them, and anything else, in a
job of the same name:

```yaml
nanobom:
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

To scan the image a tag pipeline built, in the project's registry (the job logs in with the
job's credentials):

```yaml
include:
  - remote: https://raw.githubusercontent.com/AlixANNERAUD/nanobom/vX.Y.Z/ci/gitlab/nanobom.yml
    inputs:
      organization: acme
      scan-image: $CI_REGISTRY_IMAGE:$CI_COMMIT_TAG
      stage: deploy
      fail-on: high,exploited

nanobom:
  needs: [build-image]
  rules:
    - if: $CI_COMMIT_TAG
```

To upload an SBOM from your own generator, give its path in `sbom` and take it from the job that
writes it:

```yaml
include:
  - remote: https://raw.githubusercontent.com/AlixANNERAUD/nanobom/vX.Y.Z/ci/gitlab/nanobom.yml
    inputs:
      organization: acme
      sbom: sbom.json

nanobom:
  needs: [cargo-sbom]
```

Later jobs that need the `nanobom` job read the counts from its dotenv report, such as
`$NANOBOM_HIGH` and `$NANOBOM_PROJECT_URL` ([outputs](../reference/gitlab-template.md#outputs)).
To upload several SBOMs, include the template once per SBOM with a different `job-name` and
`project` or `version`.

The job runs in `alpine:3.24` and installs `curl` and `jq` at each run. To run it elsewhere,
such as in a mirror of the image or in an image that already has `curl`, `jq` and `syft`, set
the `image` input ([requirements](../reference/gitlab-template.md#the-job)).

The template is not in the GitLab CI/CD Catalog: `include: component` does not work, and the
remote include is fetched from GitHub when the pipeline is created.
[`examples/gitlab-ci.yml`](https://github.com/AlixANNERAUD/nanobom/blob/main/examples/gitlab-ci.yml)
is a complete pipeline. Without the template, upload with `curl` as below.

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
- When many jobs wait at once, the instance may refuse one with a `503` and a `Retry-After`
  header, before storing anything ([limit](../reference/upload-api.md#waiting-for-the-evaluation)).
  `--retry 3` sends it again after that delay, but also after a `503` for an evaluation that did
  not complete, which uploads the SBOM again.

Without `fail_on` (and `wait`), the request returns as soon as the SBOM is stored. To fail the
job on vulnerabilities, see [Fail CI on vulnerabilities](fail-ci.md).

Pick a project slug that is valid as is: `${GITHUB_REPOSITORY#*/}` and `$CI_PROJECT_NAME` are
usually fine, but a repository name with spaces, slashes, a leading dot or upper-case letters is
folded or refused (see the [slug rules](../reference/upload-api.md#request)).
