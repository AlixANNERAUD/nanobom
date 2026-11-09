# Track several versions of a product

When a product has maintenance branches next to its main one (`main` ships 3.x while `release/2.4`
still gets security fixes), upload each branch to its own **version** of the same project. Each
version keeps its own components, findings and triage, so a dependency fixed on `main` still
shows as vulnerable on the branch that ships the old one. How versions work is explained in
[Concepts](../explanation/concepts.md#versions); the parameters are in the
[upload API reference](../reference/upload-api.md#versions).

## Name the version in the upload

Add `version` to the upload URL. The first upload naming a version creates it, with the open and
ignored findings of the latest version, so a release branch starts with the triage already done
on `main`.

```sh
curl --fail-with-body --silent --show-error \
  --request PUT \
  --header "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "$NANOBOM_URL/api/organizations/acme/projects/web/sbom?version=$BRANCH&fail_on=high"
```

- A version name is 1 to 64 letters, digits, `.`, `_`, `+`, `/` or `-`, and is case-sensitive:
  `release/2.4` and `2.4.x` are fine; a name with a space is refused with a `422`. Encode `/` as
  `%2F` and `+` as `%2B` in the URL.
- Name a version after something that lasts: a release branch or a release line. A build number
  or a commit hash creates a new version at every build, and a project keeps at most 50 active
  versions.
- Projects that never name a version keep their single, unnamed version: nothing changes for
  them. Uploads without `version` keep going to the unnamed version.

## Keep the latest version on the main branch

The **latest** version is the one the project page, the read API and the VEX export show when
they are not asked for another. A version an upload creates becomes the latest, which is right
for the branch that will ship next, and wrong for a maintenance branch. Upload maintenance
branches with `latest=false`:

```yaml
name: SBOM

on:
  push:
    branches: [main, "release/**"]

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7.0.1
      # Writes sbom.json: see Generate an SBOM.
      - run: cargo install cargo-cyclonedx --locked && cargo cyclonedx --format json --override-filename sbom
      - name: Upload the SBOM
        env:
          NANOBOM_URL: ${{ vars.NANOBOM_URL }}
          NANOBOM_TOKEN: ${{ secrets.NANOBOM_TOKEN }}
          VERSION: ${{ github.ref_name }}
          LATEST: ${{ github.ref_name == 'main' }}
        run: |
          VERSION=$(printf %s "$VERSION" | sed 's|/|%2F|g; s|+|%2B|g')
          curl --fail-with-body --silent --show-error \
            --request PUT \
            --header "Authorization: Bearer $NANOBOM_TOKEN" \
            --data-binary @sbom.json \
            "$NANOBOM_URL/api/organizations/acme/projects/web/sbom?version=$VERSION&latest=$LATEST&fail_on=high"
```

Uploads from `main` keep the `main` version latest (`latest=true`), and uploads from
`release/2.4` go to the `release/2.4` version without taking the flag (`latest=false`). The
workflow runs on the main and release branches only: on pull request branches, `ref_name` would
create a version per branch.

To version by release line rather than by branch, send the line instead: `version=2.4` from
every `v2.4.*` tag.

## Read one version

- **On the project page**, the **Version** selector shows the latest version by default; choose
  another and select **Show**. The findings, the license violations, the component count and the
  **Export VEX** button follow the version shown. The upload history lists every upload of the
  project, with its version.
- **With the read API**, add `version` to the findings, components and license violations
  endpoints, and list the versions with `/versions`
  ([reference](../reference/read-api.md#versions)):

  ```sh
  curl --silent --header "Authorization: Bearer $NANOBOM_TOKEN" \
    "$NANOBOM_URL/api/organizations/acme/projects/web/findings?version=release%2F2.4"
  ```

- **VEX documents** are exported from and imported into one version with the same parameter
  ([VEX API](../reference/vex-api.md)).

## What to expect

- **The gate judges the version uploaded.** `fail_on` counts the findings of the version the
  upload went to, not those of the other versions: a release branch fails on its own
  vulnerabilities only.
- **Triage is per version.** Ignoring a finding in `release/2.4` does not ignore it in `main`.
  Versions created later inherit the ignores of the latest version at the time.
- **Notifications are per vulnerability.** A new advisory against a dependency several versions
  share is announced once, with the list of the versions it affects; findings a new version
  inherits are never announced ([payloads](../reference/webhooks.md#findingsnew)).
- **Counts are per issue.** The organization page counts a vulnerability of a package once per
  project, at its highest severity, however many versions have it.
- **Dependency-Track clients** already send a version: `projectVersion` is the version, and
  `isLatest` the latest flag ([Upload with Dependency-Track clients](dependency-track-clients.md)).
