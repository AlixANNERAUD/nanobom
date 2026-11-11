# Upload with Dependency-Track clients

nanobom accepts the upload requests of Dependency-Track's API, so a pipeline that uploads SBOMs
to Dependency-Track can upload to nanobom by changing two settings: the server's address, and the
API key, which becomes a nanobom upload token. The requests and answers are described in the
[upload API reference](../reference/upload-api.md#dependency-track-api); what the mapping implies
is explained in [Dependency-Track compatibility](../explanation/dependency-track.md).

## Before you start

- **Generate the SBOM in JSON.** Many Dependency-Track setups upload `bom.xml`; nanobom reads
  CycloneDX JSON and SPDX JSON only, so switch the generator's output format (see [Generate an
  SBOM](generate-sbom.md)).
- **Get an upload token** as in [Upload from CI](upload-from-ci.md#get-an-upload-token). A
  client that uploads to one project uses that project's upload token; `autoCreate` is accepted
  with it but never creates the project, which must exist. Use an organization token for clients
  that create projects (`autoCreate`).
- **Name projects with a slug.** The project name becomes the project's slug, folded to lower
  case: `Web-App` uploads to `web-app`, but `Web App` is refused, since a slug cannot contain a
  space.
- **Identify projects by name, not by UUID.** nanobom has no project UUIDs: a client configured
  with a project UUID only gets a `400`.

- **Send a version that names a release, not a build.** `projectVersion` is the
  [project version](../explanation/concepts.md#versions) the SBOM goes to. A build number or a
  commit hash, new at every build, creates a version per build: it works, but past 50 active
  versions each build makes the oldest one inactive ([the cap](../reference/versions.md#the-cap)),
  and the project page lists every build. Use a release or branch name, or leave
  `projectVersion` out to keep one version per project. Version names are 1 to 64 letters, digits, `.`, `_`, `+`, `/` or `-`.

Earlier nanobom releases recorded `projectVersion` as the upload's image tag and kept one
inventory per project. Since project versions, each `projectVersion` is a version of its own
([what changed](../explanation/dependency-track.md#what-maps-and-how)).

## GitHub Actions, with gh-upload-sbom

```yaml
- uses: DependencyTrack/gh-upload-sbom@v4.3.0
  with:
    server-hostname: nanobom.example.org
    api-key: ${{ secrets.NANOBOM_TOKEN }}
    project-name: web
    project-version: ${{ github.ref_name }}
    auto-create: true
    bom-filename: bom.json
```

Run it on the default and release branches only: on every pull request branch, `ref_name` would
create a version per branch.

`auto-create: true` is required even when the project exists: without it, the action sends the
project's UUID instead of its name. For an instance on another port or over plain HTTP, set
`port` and `protocol`.

The action does not wait for the evaluation. To fail the job on vulnerabilities, use
[nanobom-action](upload-from-ci.md#github-actions) instead.

## Jenkins

In **Manage Jenkins → System → Dependency-Track**, set **Dependency-Track Backend URL** to the
nanobom address and **API key** to a credential holding the upload token. Then publish from the
pipeline:

```groovy
dependencyTrackPublisher artifact: 'target/bom.json', projectName: 'web',
    projectVersion: env.BRANCH_NAME, synchronous: false
```

`env.BRANCH_NAME` is set in multibranch pipelines; avoid `env.BUILD_NUMBER`, which would create
a version per build.

Keep **synchronous publishing** off: in synchronous mode the plugin fetches findings and policy
violations through Dependency-Track endpoints that nanobom does not have, and fails the build. For
the same reason, leave project properties (tags, group, description, SWID tag ID) unset. Thresholds
need synchronous mode; to fail a build on vulnerabilities, call the native upload with `fail_on`
([Fail CI on vulnerabilities](fail-ci.md)).

## Maven

Generate the SBOM in JSON with the CycloneDX Maven plugin, then upload it with the
Dependency-Track Maven plugin:

```sh
mvn org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json \
  io.github.pmckeown:dependency-track-maven-plugin:0.8.8:upload-bom \
  -Ddependency-track.dependencyTrackBaseUrl=https://nanobom.example.org \
  -Ddependency-track.apiKey="$NANOBOM_TOKEN" \
  -Ddependency-track.bomLocation=target/bom.json
```

The project name defaults to the artifact ID and the version to the Maven version; set
`dependency-track.projectName` when the artifact ID is not a valid slug. The plugin creates
missing projects. With a `-SNAPSHOT` version, every snapshot of a release uploads to the same
version, as wanted; set `dependency-track.projectVersion` to override it.

After the upload, the `upload-bom` goal looks the project up and refreshes its metrics through
Dependency-Track endpoints that nanobom does not have, and logs an error. The SBOM is stored all
the same, and with `failOnError` at its default, `false`, the build passes. Keep it so.

## Gradle

There is no widely used Gradle plugin for Dependency-Track uploads. Generate the SBOM in JSON
with the CycloneDX Gradle plugin, then upload the file with `curl`, as below.

## Scripts and curl

As a multipart form, which is what most clients send:

```sh
curl --fail-with-body --silent --show-error \
  -H "X-Api-Key: $NANOBOM_TOKEN" \
  -F projectName=web -F projectVersion=1.4.0 -F autoCreate=true \
  -F bom=@bom.json \
  https://nanobom.example.org/api/v1/bom
```

Or as JSON, with the SBOM base64-encoded:

```sh
base64 < bom.json | tr -d '\n' |
jq -Rs '{projectName: "web", projectVersion: "1.4.0", autoCreate: true, bom: .}' |
curl --fail-with-body --silent --show-error -X PUT \
  -H "X-Api-Key: $NANOBOM_TOKEN" -H "Content-Type: application/json" \
  --data-binary @- \
  https://nanobom.example.org/api/v1/bom
```

The SBOM travels through pipes: passing it as a command-line argument (`jq --arg bom "$(base64
…)"`) fails for SBOMs of about 100 KiB or more, since the system limits the size of an
argument. `tr` removes the line breaks that GNU `base64` adds; nanobom ignores them, but
Dependency-Track does not, so the same command works against both.

Both answer `{"token": "…"}`. A script that must wait for the project's evaluation polls
`GET /api/v1/event/token/{token}` with the same header until it answers
`{"processing": false}`.
