# VEX

An SBOM lists what a product contains; matched against vulnerability databases, it yields every
vulnerability of every component. Most do not affect the product: the vulnerable function is
never called, the feature is not compiled in, the attack needs a configuration nobody uses. A
customer or an auditor who receives the SBOM finds the same long list and cannot tell.

VEX (Vulnerability Exploitability eXchange) is the answer to that list: a statement, per
vulnerability and component, of whether the product is affected, and why not when it is not. In
CycloneDX, it is the `analysis` of each entry of `vulnerabilities`: a state (`not_affected`,
`exploitable`, `in_triage`, `resolved`…), a justification for `not_affected`, and free text.

## Why it matters now

Customers increasingly ask for one, and regulation is following. The EU Cyber Resilience Act
requires manufacturers of products with digital elements to identify and document the
components and vulnerabilities of their products, with an SBOM, and to handle vulnerabilities
without delay. A VEX document is the usual way to show that handling for each vulnerability the
SBOM reveals, in a form tools can read.

## What nanobom says, and what it does not

nanobom's triage already holds the information: an ignored finding has a reason. What a reason
lacks is a form a machine can read, and a distinction between "does not affect us" and "we
accept the risk". Hence the **justification** of an ignore, from the CycloneDX vocabulary, and
these choices in exports:

- **Only a justification makes a `not_affected`.** An ignore with just a reason is often an
  accepted risk or a postponed fix. Telling a customer it does not affect the product would be a
  claim nobody made, so it is exported as `in_triage`, with the reason as detail.
- **Open is `in_triage`, never `exploitable`.** nanobom knows when a vulnerability is exploited
  in the wild (CISA KEV), not whether this product exposes it. Being exploited somewhere does not
  make it exploitable here, and stating `exploitable` would be as unfounded as stating
  `not_affected`.
- **Fixed is `resolved`.** A fixed finding's component is often gone or upgraded, so the
  statement is about a version the product no longer contains. It stays in the document as the
  record of what was handled.
- **False positive is kept apart.** CycloneDX has a `false_positive` state for a vulnerability
  wrongly associated with a component. nanobom offers it alongside the justifications so an
  ignore can say it, and an import of `false_positive` round-trips.

## Importing statements

Imports turn others' statements, or your own kept in a repository, into ignores, so the same
decision is not made twice and the CI gate stops failing on what was already analysed. Only
`not_affected` and `false_positive` act; the other states inform and change nothing, since
reopening or prioritizing a finding on someone else's word is a decision for a member.

Matching is deliberately strict. A statement must name the vulnerability (by any alias) and the
component's exact version: a statement written for `lodash 4.17.20` says nothing about
`4.17.21`, which may contain other code. Version ranges (`affects[].versions`) are not read for
the same reason.

An import is attributed to the upload token that sent it, not to a person: tokens are how CI
acts, and whoever reads the history sees where the decision came from. Restoring an imported
ignore works as for any other; a later import of the same statement ignores the finding again,
so fix the statement rather than the finding.

## Limits

- **CycloneDX only.** OpenVEX, CSAF VEX and SPDX security information are not read or written.
  OpenVEX describes the same idea with other justifications
  (`vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`…) that map only
  partly onto CycloneDX's; nanobom is CycloneDX-native throughout, so it stays with one
  vocabulary rather than translate lossily. Converters exist between the formats.
- **The export describes the current state** of the project, with the findings of its latest
  SBOM; nanobom keeps no history of exports or per-release VEX documents.
- **References to elements of another document** (BOM-Links whose fragment is a `bom-ref` rather
  than a package URL) cannot be resolved, since nanobom does not keep the `bom-ref`s of uploaded
  SBOMs.
- **Responses** (`can_not_fix`, `update`…) and `affects[].versions` are neither read nor
  written.
