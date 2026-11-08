# Dependency-Track compatibility

Many build tools and pipelines already upload SBOMs to OWASP Dependency-Track. nanobom answers
the part of Dependency-Track's API they use to upload, so those pipelines work against nanobom
without being rewritten, and a team moving from Dependency-Track changes a URL and a key rather
than every pipeline. The requests are listed in the [upload API
reference](../reference/upload-api.md#dependency-track-api); this page explains how
Dependency-Track's model maps onto nanobom's, and where it stops.

## What maps, and how

Dependency-Track identifies a project by a UUID, or by a name and a version, and keeps one
project per version. nanobom identifies a project by its slug within an organization, and keeps
one inventory per project: each upload replaces the previous one ([Concepts](concepts.md)).

- **The organization comes from the token.** Dependency-Track has no organizations; a nanobom
  upload token belongs to one, so the token alone tells where the SBOM goes.
- **The project name is the slug.** It is normalized as in the native API, trimmed and folded to
  lower case, but not rewritten further: a name with a space or an accent is refused rather than
  silently mapped to a slug nobody chose, which could merge two projects into one.
- **The version is a label.** nanobom has no project versions yet, so `projectVersion` is stored
  as the upload's image tag. Uploads of `1.4.0` and `1.5.0` of the same project replace each
  other, as uploads of one project always do.
- **UUIDs cannot be resolved.** A client configured with a project UUID refers to a project that
  only exists in Dependency-Track; nanobom refuses it with a message asking for the name, rather
  than guessing.
- **`autoCreate` keeps its meaning.** Without it, a missing project is a `404`, as in
  Dependency-Track. With it, an organization token creates the project; a project token never
  does, whatever the request says ([Security model](security.md#upload-tokens)).
- **The rest is ignored.** Tags, parent projects, the latest-version flag and the active flag have
  no equivalent; they are accepted so that clients sending them still work.

## Processing status

Dependency-Track processes an upload in the background and returns a token; clients that wait
poll the token until it is no longer processing, then usually fetch results. nanobom's work after
an upload is the project's run, so a token is processing until that run has finished, exploitation
data included. That is what a client polling before reading results needs: once `processing` is
`false` after a run that completed, the project's findings are those of this SBOM. It is not a
guarantee when the wait ended at `NANOBOM_UPLOAD_WAIT_SECONDS` before the run finished, when the
run failed, or when runs after uploads are off: the token then reads as not processing although
the findings may still be those of the previous SBOM.

The tokens are kept in memory only. Persisting them would add a table for state that matters for
a few minutes, and a restart already abandons the run they wait for. Like Dependency-Track, an
unknown token reads as not processing, so a client polling across a restart, or polling an
upload made when runs after uploads are off, stops waiting instead of hanging. The wait is
bounded by `NANOBOM_UPLOAD_WAIT_SECONDS`, the same bound as native uploads that wait.

## Where compatibility stops

Only uploading and its processing status are implemented. Clients that go further after the
upload call endpoints nanobom does not have:

- reading findings, metrics or policy violations (the Jenkins plugin in synchronous mode, the
  Maven plugin's `upload-bom` goal after the upload);
- looking projects up or changing their properties (project tags or description in the Jenkins
  plugin);
- uploading VEX documents.

Those answer `404`. [Upload with Dependency-Track clients](../how-to/dependency-track-clients.md)
says how to configure each client to stay within uploads. Failing a build on vulnerabilities is
done with the native API's `fail_on` ([Fail CI on vulnerabilities](../how-to/fail-ci.md)),
which answers in the same request.

The answers follow Dependency-Track's shapes where clients read them: `200` with a token,
plain-text error messages that clients print to the build log, and an RFC 9457 problem for an
invalid document. Messages are nanobom's, in English, as for the native API.
