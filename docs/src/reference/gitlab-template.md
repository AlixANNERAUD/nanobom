# GitLab CI template

[`ci/gitlab/nanobom.yml`](https://github.com/AlixANNERAUD/nanobom/blob/main/ci/gitlab/nanobom.yml)
adds one job to a GitLab pipeline: it generates an SBOM with Syft unless one is given, uploads
it with the [upload API](upload-api.md), writes the project's evaluation to the job log and
fails the job when it crosses a threshold. It is included from this repository, not from the
GitLab CI/CD Catalog:

```yaml
include:
  - remote: https://raw.githubusercontent.com/AlixANNERAUD/nanobom/vX.Y.Z/ci/gitlab/nanobom.yml
    inputs:
      organization: acme
```

The template is in releases from v0.1.0 on: an older tag answers 404.

How to use it is in [Upload from CI](../how-to/upload-from-ci.md#gitlab-ci).

## Inputs

Only `organization` is required. Inputs are text: quote `true` and `false` (`wait: "false"`).
A value may refer to CI/CD variables (`version: $CI_COMMIT_REF_NAME`), which are expanded when
the job runs.

| Input | Default | |
| --- | --- | --- |
| `url` | `$NANOBOM_URL` | Address of the nanobom instance, such as `https://nanobom.example.org` |
| `organization` | | Slug of the organization |
| `project` | `$CI_PROJECT_NAME` | Slug of the project; created by the first upload when the token covers the organization |
| `sbom` | | Path of an existing CycloneDX or SPDX JSON SBOM; empty, Syft generates one |
| `scan-path` | `.` | Directory Syft scans when `sbom` is empty |
| `scan-image` | | Container image Syft scans instead of `scan-path` when `sbom` is empty |
| `fail-on` | | `critical`, `high`, `medium`, `low`, `exploited` or `license`, or several separated by commas (`high,license`): the upload's [`fail_on`](upload-api.md#fail_on-thresholds). Implies `wait` |
| `wait` | `"true"` | `"true"` or `"false"`: wait for the evaluation and report it |
| `version` | | The [project version](upload-api.md#versions) the SBOM describes; empty, the unnamed version |
| `latest` | | `"true"`, `"false"` or empty: the upload's `latest` parameter |
| `source-commit` | `$CI_COMMIT_SHA` | Commit the SBOM was built from, shown in the upload history |
| `image-tag` | `$CI_COMMIT_TAG` | Container image tag the SBOM describes, shown in the upload history; empty outside tag pipelines |
| `stage` | `test` | Stage of the job |
| `job-name` | `nanobom` | Name of the job |
| `image` | `alpine:3.24` | Image of the job |

`fail-on` is trimmed and folded to lower case before it is sent. `wait` and `latest` are checked
before anything is uploaded.

## Variables

| Variable | |
| --- | --- |
| `NANOBOM_TOKEN` | Required. An [upload token](upload-api.md#tokens); define it under **Settings → CI/CD → Variables**, masked. It is never an input, since inputs are visible in the pipeline configuration |
| `NANOBOM_URL` | Read through the default of `url` only |
| `CI_REGISTRY`, `CI_REGISTRY_USER`, `CI_REGISTRY_PASSWORD` | Set by GitLab. When `scan-image` is in the project's registry (it starts with `$CI_REGISTRY/`) and `SYFT_REGISTRY_AUTH_AUTHORITY` is not set, Syft logs in with them |
| `SYFT_*` | Read by Syft, such as `SYFT_REGISTRY_AUTH_AUTHORITY`, `SYFT_REGISTRY_AUTH_USERNAME` and `SYFT_REGISTRY_AUTH_PASSWORD` for another registry |

The job passes its inputs to its script as variables named `NANOBOM_INPUT_*`; a project or
group variable with one of these names would override the input.

## The job

| | |
| --- | --- |
| Name | The `job-name` input |
| Stage | The `stage` input |
| Image | The `image` input, with an empty entrypoint |
| Rules, needs | None: the job runs in every pipeline, after the jobs of earlier stages |
| Artifacts | The dotenv report `nanobom.env`, kept even when the job fails |

Override or add keys in a job of the same name, or in a job that `extends` it. The template
does not set `rules`, `needs`, `dependencies`, `tags` or `interruptible`.

The image needs a POSIX shell, and `curl` and `jq` or `apk` to install them; the default
Alpine image installs them at each run. When `sbom` is empty and `syft` is not on the `PATH`,
the job downloads Syft 1.57.0 for `x86_64` or `aarch64` from its GitHub release and checks it
against a SHA-256 digest written in the template; another architecture needs an image with
`syft`.

## Outputs

The dotenv report gives these variables to the jobs of later stages, as GitLab does with every
artifact unless `needs` or `dependencies` limit which jobs a job downloads from. A value nanobom
did not return is left out: without `wait`, there is no evaluation, and without a
[license policy](license-policy.md), no license counts. Every copy of the template writes the same
names, so a job that downloads the reports of two copies gets the values of only one: limit it
with `needs` or `dependencies` to the job it reads. Values are checked before they are written
(numbers, a known status, a URL on one line), so a server cannot add other variables.

| Variable | |
| --- | --- |
| `NANOBOM_HTTP_STATUS` | HTTP status of the upload |
| `NANOBOM_PROJECT_URL` | The project's page in nanobom |
| `NANOBOM_EVALUATION_STATUS` | `succeeded`, `failed` or `timed_out` |
| `NANOBOM_CRITICAL`, `NANOBOM_HIGH`, `NANOBOM_MEDIUM`, `NANOBOM_LOW` | Open findings of the version uploaded, by severity |
| `NANOBOM_KNOWN_EXPLOITED` | Open findings known to be exploited |
| `NANOBOM_FORBIDDEN_LICENSES`, `NANOBOM_WARNED_LICENSES` | Components whose license the policy forbids, or warns about |

## Job log

- The Syft run, in a collapsed section.
- The upload: components stored, HTTP status, project page, and a warning for components
  without a package URL.
- With an evaluation, a section with its status, the open findings per severity and known
  exploited, the first 25 findings (severity, vulnerability, component, known exploited, page)
  and, with a license policy, the counts and the first 25 components it forbids or warns about.
- When the gate fails, the findings and forbidden licenses over the threshold, at most 25 of
  each, then the server's `error`.

## Exit status

| Upload answer | Job |
| --- | --- |
| `200`, `201` | Succeeds |
| `409`: a `fail-on` threshold is crossed | Fails |
| `503`: with a severity or `exploited` threshold, the evaluation failed or timed out; or too many uploads are waiting | Fails |
| `401`, `403`, `404`, `413`, `422`, any other status, or no answer | Fails, with the reason |

The job also fails before uploading on an empty `url`, `organization` or `project`, a missing
`NANOBOM_TOKEN`, an invalid `wait` or `latest`, a missing SBOM file, or when Syft cannot
generate the SBOM. Like [nanobom-action](https://github.com/AlixANNERAUD/nanobom-action),
`curl` sends the upload again up to twice after a `503` or a connection error, which uploads the
SBOM again.
