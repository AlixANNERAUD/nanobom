# License policies

A component's license is rarely one identifier. npm packages declare `(MIT OR Apache-2.0)`,
Rust crates `MIT OR Apache-2.0`, firmware bundles `GPL-2.0-only AND BSD-3-Clause`. A policy
written as a list of identifiers (allowed, warned, forbidden) has to say what such an
expression means. This page explains the choices nanobom makes; the rules themselves are in the
[license policy reference](../reference/license-policy.md#evaluation).

## OR is a choice, AND is an obligation

SPDX gives the two operators precise meanings. `A OR B` means the licensor offers both, and
whoever redistributes the component picks one: a dual-licensed `MIT OR GPL-3.0-only` library
can be shipped under MIT, and the GPL never applies. `A AND B` means both apply at once,
usually because parts of the component come under different licenses: shipping
`MIT AND GPL-3.0-only` means complying with the GPL.

So nanobom keeps the **least severe** side of `OR`, the choice you would make, and the **most
severe** side of `AND`, the obligation you cannot avoid. Nested expressions follow the same
rule from the inside out, with SPDX's precedence (`AND` binds tighter than `OR`). The verdict
also names the licenses that decided it: on `MIT AND (GPL-3.0-only OR LGPL-2.1-only)` with
GPL forbidden and LGPL warned, the verdict is a warning because of `LGPL-2.1-only`, which is
what to look at.

Choosing the least severe side assumes you do choose it. Shipping a dual-licensed component
under MIT is a decision your notices and attributions must reflect; nanobom records the
licenses, not the decision.

## Several license entries are combined with AND

A CycloneDX component may list several license entries without saying whether they are
alternatives. nanobom joins them with `AND` when it reads the SBOM
([how](../reference/upload-api.md#the-document)): reading two licenses as two obligations can
only produce a warning you then review, while reading them as a choice could hide a forbidden
license. Generators that mean a choice can write one `expression` with `OR`.

## Unknown is judged as a whole

An expression that is not valid SPDX (a free-text name such as `Apache License 2.0`, an
identifier outside the SPDX list, broken parentheses) gets the action for unknown licenses,
whatever valid licenses it also contains. Judging the valid part alone would be guessing: in
`MIT AND Some-Custom-License`, the unrecognized part might be the one that matters. nanobom
does not guess identifiers either (`Apache` is not taken for `Apache-2.0`), for the same
reason. Identifiers and operators are compared without case, since SPDX says case does not
matter, and SBOMs in the wild write `mit` and `Apache-2.0 or MIT`.

## Computed when read, not stored

Violations are not a table that runs fill in, unlike findings. They depend only on the
project's latest SBOM and the current policy, so they are computed each time a page, the API or
an upload asks. Changing the policy applies to every project at once, without a run, and the
policy cannot drift from what was evaluated. The cost is small: each distinct license of a
project is evaluated once, and the database counts the components.

The trade-off is history: nanobom keeps no record of past verdicts, and no webhook reports a new
violation. The upload gate is where a new forbidden license is caught, at the moment it enters
the project.

## Only forbid fails the gate

`warn` exists for licenses that need a look but not a block: weak copyleft such as `MPL-2.0`,
or unknown licenses while generators are being fixed. `fail_on=license` fails only on `forbid`,
so warnings can be added without breaking pipelines. Licenses are read from the uploaded SBOM,
not found by the run, so a failed or slow run does not stop the license gate from answering.

## What this is not

A license policy here is a list of SPDX identifiers with three actions. nanobom does not detect
licenses from source files, does not track obligations such as attribution or source
distribution, and does not produce notices. It answers one question at the point where code
ships: does this project contain a license we decided not to accept?
