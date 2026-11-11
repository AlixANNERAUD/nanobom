# Tokens and scopes

CI pipelines, scripts and dashboards talk to nanobom without a person behind them, so they
authenticate with tokens rather than user accounts. This page explains how a token's reach and
scope combine, and which token to give to what. The facts (headers, endpoints, commands) are in
the [upload API](../reference/upload-api.md#tokens) and [read API](../reference/read-api.md)
references.

## Two independent choices

A token is created with two answers:

- **Reach**: the whole organization, or one project of it. It bounds what the token sees and
  touches.
- **Scope**: what the token may do within its reach.

| Scope | Uploads SBOMs | Imports VEX documents | Creates projects | Reads (read API, VEX export) |
| --- | :---: | :---: | :---: | :---: |
| `upload` | ✓ | ✓ | organization tokens only | ✓ |
| `read` | | | | ✓ |

Whatever its scope, a token reads like a **viewer** of what it reaches: the same checks as the
interface decide, in the same place, so a token never sees more than a viewer of its
organization would, and a project token sees one project. Anything out of reach looks missing
(`404`), so a token cannot learn which other organizations or projects exist.

## Why upload tokens also read

An upload token already receives the project's open findings when CI waits for the evaluation,
and its VEX export lists every finding. Refusing it the read API would protect nothing while
forcing CI to hold two secrets. The scope that matters is the reverse one: a token that can
**only** read.

## Why read tokens exist

An upload token can change what nanobom reports. It replaces a project's components, so an
SBOM that leaves out a vulnerable package fixes its findings; it imports VEX statements, which
ignore findings. A leaked upload token can therefore hide vulnerabilities.

A dashboard, a spreadsheet export or an issue-tracker integration needs none of that. Giving it
a read token means a leak exposes the findings, which is serious, but cannot change them: the
upload, VEX import and Dependency-Track routes refuse read tokens with `403`, and the check is
made again in the domain layer, so a future route cannot forget it.

## Every project comes with a token

A project created in the interface could not receive anything until someone created a token for
it, and a token shown once must be copied at once, or created again. So every project comes
with an upload token of its own, shown on its page to admins and owners for as long as it is in
use, next to a workflow step ready to paste: create the project, copy two lines into CI, done.
This is how CI services such as Codecov enroll a repository.

The price is that nanobom keeps that token's value, where other tokens keep only a digest
([security model](security.md#api-tokens)). The token is renewed rather than revoked, so a
project never lacks one; named tokens stay for everything else: a second pipeline that should
be revoked on its own, a read-only integration, CI that creates projects.

## Choosing a token

| Tool | Token |
| --- | --- |
| CI of one repository | the project's upload token, or another `upload` token reaching that project |
| CI that creates projects on the fly (a monorepo, a fleet of images) | `upload`, reaching the organization |
| A dashboard or report over the organization | `read`, reaching the organization |
| An integration about one project (its own issue tracker) | `read`, reaching that project |

Prefer the narrowest reach that works: a project token limits a leak to one project.

## Tokens and people

Tokens are not user accounts. They do not sign in to the interface, belong to no user, and keep
working when the admin who created them leaves; revoke them in **Settings → API tokens** or with
`nanobom token revoke`, and renew a project's upload token on its page or with
`nanobom project token --renew`. A person who wants to call the API from a browser does not need a token:
pages of the instance can call the read API with the session, and then read what that person
sees, with their role.
