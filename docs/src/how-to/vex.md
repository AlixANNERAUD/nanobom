# Exchange VEX statements

A VEX document tells someone which vulnerabilities of your product matter and which do not
([VEX](../explanation/vex.md)). nanobom writes one from a project's findings and reads others'
to ignore findings. The exact formats and rules are in the [VEX API reference](../reference/vex-api.md).

## Record why a finding does not apply

Exports only say a vulnerability does not affect the product when a member said why, in
machine-readable form. When you ignore a finding ([Triage findings](triage.md#ignore-a-finding)),
choose a **Justification** as well as the reason:

- **Vulnerable code not reachable**, **Vulnerable code not present**, **Requires a configuration
  not in use** and the other justifications state that the product is not affected;
- **False positive** says the vulnerability was wrongly associated with the component;
- **None** fits an accepted risk: the finding is ignored in nanobom, but exported as still being
  analysed (`in_triage`), with your reason.

## Export a VEX for a customer or an auditor

From the interface: on the project page, select **Export VEX**. Any member, viewers included,
can download it.

From a script or CI, with an upload token of the project or its organization:

```sh
curl -fsS -H "Authorization: Bearer $NANOBOM_TOKEN" \
  -o web.vex.cdx.json \
  https://nanobom.example.org/api/organizations/acme/projects/web/vex
```

Send it with the SBOM of the same release: the VEX names components by package URL, so it reads
on its own, but the SBOM tells what else the product contains. Before sending, check that the
project's latest upload is the release you describe, since the export reflects the current
findings.

## Import a vendor's VEX

When a supplier ships a VEX for a component you use, import it into each project that uses the
component:

```sh
curl -fsS -X PUT -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @vendor.vex.cdx.json \
  https://nanobom.example.org/api/organizations/acme/projects/web/vex
```

Statements saying `not_affected` or `false_positive` ignore the open findings they cover; the
response lists what was ignored and what was skipped, and why. Read the `results` with
`no_matching_finding` or `unresolved_reference`: the vendor may name the component in a way
nanobom cannot match, such as a package URL without a version.

The ignores show **by upload token** and the token's name in each finding's history. Give the
token used for imports a name that says where the statements come from, such as `vendor VEX`.

## Keep your own statements in the repository

To keep triage decisions next to the code and review them in pull requests, write them as a
CycloneDX VEX file in the repository and import it in CI after each upload:

```yaml
- name: Upload the SBOM
  run: |
    curl -fsS -X PUT -H "Authorization: Bearer $NANOBOM_TOKEN" --data-binary @sbom.json \
      "https://nanobom.example.org/api/organizations/acme/projects/web/sbom?wait=true"
- name: Import our VEX statements
  run: |
    curl -fsS -X PUT -H "Authorization: Bearer $NANOBOM_TOKEN" --data-binary @vex.cdx.json \
      https://nanobom.example.org/api/organizations/acme/projects/web/vex
```

A minimal file, for one finding:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2021-23337",
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "We never call lodash.template."
      },
      "affects": [{ "ref": "pkg:npm/lodash@4.17.20" }]
    }
  ]
}
```

The package URL includes the version: when the component is upgraded and still vulnerable, the
new finding is not covered until you review the statement and update it.

An export, edited, is a good starting point: change `analysis` where it applies and drop the
other entries.

## Put the statements in the SBOM

Generators and tools that write statements into the SBOM's own `vulnerabilities` need no second
call: the upload imports them. Upload with `wait=true` or `fail_on` so they also cover findings
opened by this upload, and so the gate ignores them
([statements inside an SBOM](../reference/vex-api.md#statements-inside-an-sbom)).
