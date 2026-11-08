# Uploading SBOMs

Everything nanobom knows about a project comes from the SBOMs your CI sends. The flow is the
same for every ecosystem:

1. **Generate** a CycloneDX JSON SBOM in the build, with the generator of your ecosystem:
   [Generating an SBOM](generators.md).
2. **Upload** it with one `PUT` request per project and build, authenticated with an upload
   token: [The upload API](api.md).
3. Optionally **gate** the pipeline on the result, in the same request:
   [Continuous integration](ci.md).

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "https://nanobom.example.org/api/organizations/acme/projects/web/sbom?source_commit=$COMMIT"
```

Upload from the builds that produce what you ship (the default branch, release tags), not from
every pull request: each upload replaces the project's components, so an SBOM of a feature
branch would hide the state of production until the next upload from `main`. To check a pull
request without replacing anything, use a separate project (`web-pr`), or none at all.
