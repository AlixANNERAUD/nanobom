# License policy

An organization's license policy says which licenses of its components it allows, warns about
or forbids. Admins change it in the organization's **Settings** (how-to:
[Enforce a license policy](../how-to/license-policy.md)); why it evaluates licenses the way it
does is in [License policies](../explanation/licenses.md).

## Settings

| Setting | Values | Default | |
| --- | --- | --- | --- |
| Allowed licenses | identifiers | none | Rules with the action `allow` |
| Licenses to warn about | identifiers | none | Rules with the action `warn` |
| Forbidden licenses | identifiers | none | Rules with the action `forbid` |
| Licenses not listed | `allow`, `warn`, `forbid` | `allow` | The action for a license no rule lists; `forbid` turns the allowed list into an allowlist |
| Unknown licenses | `allow`, `warn`, `forbid` | `allow` | The action for a component whose license is unknown (see [Evaluation](#evaluation)) |

The actions, from the least to the most severe: `allow`, `warn`, `forbid`. Saving replaces the
whole policy, the three lists and both defaults.

A policy is **active** when a rule or a default is not `allow`. Without an active policy,
nothing is a violation and the interface does not mention licenses: every organization starts
that way.

## Identifiers

Each list holds identifiers separated by spaces, commas or new lines:

- an identifier of the [SPDX license list](https://spdx.org/licenses) that nanobom is built
  with, in any case (`mit` is stored as `MIT`); the deprecated GNU identifiers without a suffix
  (`GPL-2.0`, `LGPL-2.1`, `AGPL-3.0`) are stored as their `-only` variant, which they mean, and
  the deprecated ones with an exception as the license they carry: the GNU ones
  (`GPL-2.0-with-classpath-exception`) as the `-only` variant of their license, `eCos-2.0` as
  `GPL-2.0-or-later` and `wxWindows` as `LGPL-2.0-or-later`; no other deprecated identifier is
  replaced;
- or `LicenseRef-` followed by letters, digits, `.` and `-` (`LicenseRef-Proprietary`), for
  licenses outside the SPDX list.

An identifier with `+` (`GPL-2.0+`) is refused: name the `-or-later` variant, or the license
itself. Exception identifiers (`Classpath-exception-2.0`) and `NOASSERTION` are refused too: a
rule judges a license whatever exception follows it, and `NOASSERTION` is an unknown license.

The `-only` and `-or-later` variants of a GNU license are two licenses: a rule on
`GPL-3.0-only` does not cover `GPL-3.0-or-later`, and a typed `GPL-3.0` is stored as
`GPL-3.0-only`. To judge both, list both.

The same identifier, ignoring case, may appear once; in two lists it is refused. A policy holds
at most 1000 rules, and an identifier is at most 200 characters. Refused input changes nothing,
and the settings page says why:

| Message |
| --- |
| `"…" is not an SPDX license identifier (see https://spdx.org/licenses) nor LicenseRef- followed by letters, digits, '.' or '-'` |
| `"…" is listed with two different actions` |
| `a license policy holds at most 1000 rules` |

## Evaluation

Each component has one license, an SPDX license expression as read from its latest SBOM
([how licenses are read](upload-api.md#the-document)). Its verdict:

1. A component without a license is **unknown**: it gets the action for unknown licenses, and
   the verdict names no identifier.
2. The expression is parsed, ignoring the case of identifiers and operators. Deprecated
   identifiers, `/` for `OR` and `+` after an identifier are accepted.
3. Each license of the expression gets its rule, or the action for licenses not listed.
   `WITH` exceptions are ignored: `GPL-2.0-only WITH Classpath-exception-2.0` is judged as
   `GPL-2.0-only`. `GPL-2.0` matches a rule on `GPL-2.0-only`, `GPL-2.0+` one on
   `GPL-2.0-or-later`, `GPL-2.0-with-classpath-exception` one on `GPL-2.0-only`, `eCos-2.0`
   one on `GPL-2.0-or-later` and `wxWindows` one on `LGPL-2.0-or-later`; `+` after another
   license is ignored (`Apache-1.0+` is judged as `Apache-1.0`).
   `DocumentRef-…:LicenseRef-…` names a license of another document, which a rule on the
   `LicenseRef-…` alone does not match. `NOASSERTION` gets the action for unknown licenses.
4. `OR` keeps the least severe side, `AND` the most severe. `AND` binds tighter than `OR`
   (`A OR B AND C` is `A OR (B AND C)`); parentheses group as written.
5. The verdict is the resulting action, with the identifiers that lead to it; when both sides
   of an operator give the same action, both are named.
6. An expression that does not parse is **unknown**: a free-text name (`Apache License 2.0`),
   an identifier outside the SPDX list (`Apache`, which is not guessed), an exception outside
   the list, unbalanced parentheses. Its words are still read (see
   [Identifiers in invalid text](#identifiers-in-invalid-text)): each SPDX identifier or
   `LicenseRef-…` among them gets its action as in step 3, and the verdict is the most severe
   of these actions and the action for unknown licenses, as if everything were joined with
   `AND`. It names the identifiers that give it, none when only the action for unknown
   licenses does. A forbidden identifier is therefore never allowed because the rest of the
   text is not SPDX.

With a policy that forbids `GPL-3.0-only`, warns about `LGPL-2.1-only`, allows the licenses
not listed and warns about unknown ones:

| License | Verdict | Because of |
| --- | --- | --- |
| `MIT` | allow | |
| `GPL-3.0-only` | forbid | `GPL-3.0-only` |
| `MIT OR GPL-3.0-only` | allow | |
| `MIT AND GPL-3.0-only` | forbid | `GPL-3.0-only` |
| `GPL-3.0-only OR LGPL-2.1-only` | warn | `LGPL-2.1-only` |
| `(MIT OR GPL-3.0-only) AND LGPL-2.1-only` | warn | `LGPL-2.1-only` |
| `gpl-3.0-only with classpath-exception-2.0` | forbid | `GPL-3.0-only` |
| none | warn | |
| `Apache License 2.0` | warn | |
| `(GNU Affero General Public License v3) AND GPL-3.0-only` | forbid | `GPL-3.0-only` |
| `GPL-3.0-only WITH Some-Custom-exception` | forbid | `GPL-3.0-only` |
| `MIT AND Some-Custom-License` | warn | |
| `Licensed under GPL-3.0-only.` | forbid | `GPL-3.0-only` |
| `Intel Simplified Software License` | warn | |

### Identifiers in invalid text

Words are runs of letters, digits, `.`, `:` and `-`; case does not matter. A word is matched,
in order:

1. as it is;
2. without the `.`, `:` and `-` at its start and end (`GPL-3.0-only.` and `GPL-3.0-only:` are
   `GPL-3.0-only`);
3. when it holds a `:` and is not a `DocumentRef-…:LicenseRef-…`, part by part, each without
   `.` and `-` at its ends (`License:GPL-3.0-only` names `GPL-3.0-only`).

`+` right after a word that ends with a GNU identifier means its `-or-later` variant, as in an
expression.

Which matches count depends on the identifier:

- An identifier **shaped like one**, holding a digit, `-`, `.` or `+`, and every
  `LicenseRef-…`, counts wherever it appears: `Licensed under AGPL-3.0-only` names
  `AGPL-3.0-only`.
- An identifier that is a **plain word**, letters only (`MIT`, `Intel`, `Ruby`, `DOC`, `JSON`,
  `Unlicense`, close to 200 of the SPDX list), counts only when it is the whole of a part of the
  text, found as it is or by step 2, alone or followed by `+`. Parts are separated by
  parentheses, the operators `AND`, `OR` and `WITH` in any case, `,`, `;` and `/`. Such words
  are common in prose: `Intel Simplified Software License`, `SEE LICENSE IN doc/LICENSE` and
  `Lizenz mit Ausnahmen` name no license, while `MIT, Some proprietary thing` and
  `(Ruby) AND Foo bar` name `MIT` and `Ruby`.

A component whose verdict is `warn` or `forbid` is a **violation**. Violations are computed
when read, from the current policy and each project's latest SBOM: a policy change applies to
every project at once, without a run, and nothing about past verdicts is kept.

## Where violations show

| Where | What |
| --- | --- |
| The project page | A **Licenses** section, while the policy is active: the violations, forbidden first, then by name, with their license and the identifiers behind the verdict; at most 200, the read API lists every one |
| The organization page | A badge on each project with violations: the number of forbidden licenses, or of warnings when nothing is forbidden |
| [Read API](read-api.md#license-policy-and-violations) | `GET /api/organizations/{organization}/license-policy` and `GET /api/organizations/{organization}/projects/{project}/license-violations` |
| [Upload API](upload-api.md#the-evaluation-object) | `evaluation.licenses` in the response of an upload that waited: the counts and the first 20 violations |
| The upload gate | `fail_on=license` fails the upload with `409` when a component is forbidden ([thresholds](upload-api.md#fail_on-thresholds)) |

Webhooks and metrics do not report license violations, and the
[Dependency-Track API](upload-api.md#dependency-track-api) does not gate on them.

## Permissions

| | Viewer | Member | Admin | Owner |
| --- | :---: | :---: | :---: | :---: |
| See the violations on project pages | ✓ | ✓ | ✓ | ✓ |
| Read the policy and the violations through the read API | ✓ | ✓ | ✓ | ✓ |
| See and change the policy in **Settings** | | | ✓ | ✓ |

Tokens of either scope read the policy of their organization, and a project token the
violations of its project only ([Accounts, roles and permissions](accounts.md)).
