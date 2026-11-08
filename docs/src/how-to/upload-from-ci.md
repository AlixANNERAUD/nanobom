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

## Create an upload token

An organization's admins create tokens in **Settings → Upload tokens**: a name, and a scope,
either **Whole organization** or one project. Copy the token when it is shown: it is shown once.

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
| `fail-on` | | `critical`, `high`, `medium`, `low` or `exploited` |
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

Without `fail_on` (and `wait`), the request returns as soon as the SBOM is stored. To fail the
job on vulnerabilities, see [Fail CI on vulnerabilities](fail-ci.md).

Pick a project slug that is valid as is: `${GITHUB_REPOSITORY#*/}` and `$CI_PROJECT_NAME` are
usually fine, but a repository name with spaces, slashes, a leading dot or upper-case letters is
folded or refused (see the [slug rules](../reference/upload-api.md#request)).
