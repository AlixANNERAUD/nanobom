# Enforce a license policy

Tell nanobom which licenses your organization accepts, see the components that break the rule,
and fail CI when one is forbidden. Every setting and how licenses are judged are in the
[license policy reference](../reference/license-policy.md). You need the admin role in the
organization.

## Check that your SBOMs carry licenses

nanobom reads licenses from the SBOM; it does not look at the packages themselves. Search for a
license you know you use, such as `MIT`, in the **License** field of the search page: if your
projects' components show up, the generator writes licenses. If they do not, or many show
*Unknown*, check the generator's options first, then upload again: licenses are read at each
upload. Some generators write free-text names (`Apache Software License`) rather than SPDX
identifiers; nanobom treats those as unknown.

## Forbid a few licenses

1. Open the organization, then **Settings**, then **License policy**.
2. Write the licenses to forbid in **Forbidden licenses**, one per line or separated by commas,
   as [SPDX identifiers](https://spdx.org/licenses):

   ```text
   AGPL-3.0-only
   AGPL-3.0-or-later
   SSPL-1.0
   ```

3. Optionally, write licenses to review in **Licenses to warn about** (`GPL-3.0-only`,
   `MPL-2.0`), and set **Unknown licenses** to *Warn* to see the components whose license the
   SBOM does not give.
4. Keep **Licenses not listed** at *Allow*, and save.

## Allow only some licenses

An allowlist forbids everything you did not approve:

1. In **Allowed licenses**, list what you accept:

   ```text
   MIT
   Apache-2.0
   BSD-2-Clause
   BSD-3-Clause
   ISC
   ```

2. Set **Licenses not listed** to *Forbid*.
3. Set **Unknown licenses** to *Warn* while you clean up, then to *Forbid* to require a license
   on every component.
4. Save.

A component licensed `MIT OR GPL-3.0-only` passes, since you can choose MIT; one licensed
`MIT AND GPL-3.0-only` does not, since both apply ([why](../explanation/licenses.md)).

## See the violations

Each project page gets a **Licenses** section listing the components the policy forbids or
warns about, forbidden first, and the organization page shows a badge on each project with
violations. The policy applies at once to every project, without waiting for an upload.

Scripts read the same list from the [read API](../reference/read-api.md#license-policy-and-violations):

```sh
curl --fail-with-body -H "Authorization: Bearer $NANOBOM_READ_TOKEN" \
  "$NANOBOM_URL/api/organizations/acme/projects/web/license-violations"
```

## Fail CI on forbidden licenses

Add `license` to `fail_on` in the upload URL. Alone, it gates on licenses only; with a severity
it gates on both:

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @sbom.json \
  "$NANOBOM_URL/api/organizations/acme/projects/web/sbom?fail_on=high,license"
```

The upload answers `409` when a component is forbidden, and lists the first violations in
`evaluation.licenses` ([response](../reference/upload-api.md#the-evaluation-object)). Warnings
never fail it. The SBOM is stored either way.

## Deal with a violation

- **Replace the component**, or upgrade it to a version under a license you accept.
- **Accept the license**: move it to **Allowed licenses**, or to **Licenses to warn about** to
  keep seeing it.
- **Name a license outside the SPDX list**: when your SBOM gives `LicenseRef-Acme-Commercial`
  for a component you bought, list that identifier in **Allowed licenses**.
- **Unknown license**: fix the generator's settings, or the component's metadata, so the SBOM
  gives an SPDX expression; a free-text name such as `Apache License 2.0` is unknown.

## Turn the policy off

Empty the three lists, set both defaults to *Allow* and save. Remove `license` from `fail_on`:
without a policy it always passes anyway.
