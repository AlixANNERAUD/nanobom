# Troubleshoot

Each entry gives the symptom, its cause, and the fix. Status codes and messages of the upload API
are listed in the [upload API reference](../reference/upload-api.md#status-codes); log messages in
the [logs reference](../reference/metrics.md#log-messages).

## Uploads

### Upload answers 401

`a valid upload token is required in the Authorization header (Bearer)`: the request has no
`Authorization: Bearer …` header, or the token is unknown or revoked.

- Check that the CI secret is set and reaches the job. On GitHub, workflows triggered by pull
  requests from forks get no secrets, so the header is `Bearer ` with nothing after it.
- Check the token in **Settings → Upload tokens**: its first characters, whether it is revoked,
  and when it was last used. A token that was never used never reached nanobom.
- Tokens are shown once. If in doubt, create a new one and revoke the old one.

### Upload answers 403

`this token does not allow uploads to this project`: a project token was used for another project
of the organization. Fix the project slug in the URL, or use the token of that project.

### Upload answers 404

`not found`, for one of these reasons:

- the organization slug in the URL is wrong, or the token belongs to another organization (nanobom
  does not say which, so as not to reveal which organizations exist);
- the token is a project token and the project does not exist yet. Project tokens never create
  projects: make the first upload with an organization token, or create the project that way
  first.

### Upload answers 413

The SBOM is larger than the limit. The limit may be:

- nanobom's, `NANOBOM_MAXIMUM_SBOM_SIZE` (16 MiB by default); the answer is then plain text, not
  JSON. Raise the limit, or split the SBOM;
- the reverse proxy's: nginx accepts 1 MiB by default and answers with an HTML page. Set
  `client_max_body_size` (see [Run behind a reverse proxy](reverse-proxy.md)).

Very large SBOMs often list each file of an image; generators can usually list packages only.

### Upload answers 422

The `error` field says what is wrong; the
[upload API reference](../reference/upload-api.md#status-codes) lists the messages. The usual
ones:

- `the SBOM must be a CycloneDX JSON document` — an SPDX document, an XML CycloneDX document, or
  the generator's default format: ask for CycloneDX JSON explicitly (Syft:
  `-o cyclonedx-json=sbom.json`);
- `unsupported CycloneDX version` — the generator writes a version older than 1.3, or newer
  than 1.7;
- `the project slug must be …` — the project name in the URL contains spaces, slashes or other
  characters. `${GITHUB_REPOSITORY#*/}` and `$CI_PROJECT_NAME` are usually fine; a repository
  name with a dot at the start or with upper-case letters is folded or refused;
- `fail_on=exploited needs exploitation data (NANOBOM_EXPLOITATION_DATA)` — exploitation data is
  off on this instance: gate on a severity instead.

### Upload answers 409

That is the gate doing its job: open findings reach `fail_on`. The response lists them in
`evaluation.findings`. Fix them by upgrading the components, or ignore the ones that do not
apply, with a reason (see [Triage findings](triage.md)); ignored findings do not count.

### Upload answers 503

`the evaluation did not complete`, with `fail_on`: the run failed (`evaluation.status` is
`failed`) or did not finish in time (`timed_out`). The SBOM is stored; only the gate could not
decide.

- `failed`: nanobom could not reach OSV. Look for `run failed` in the logs, and check that the
  instance can reach `https://api.osv.dev/`.
- `timed_out`: the run took longer than `NANOBOM_UPLOAD_WAIT_SECONDS`, often because it waited
  behind another run, such as the nightly run of a large instance. Retry, raise the setting, or
  move the schedule away from your busiest CI hours.

### Upload answers 502 or 504 after a minute

A reverse proxy between CI and nanobom gave up on a waiting upload (most default to 60 seconds).
nanobom still finishes the run. Raise the proxy's read timeout above
`NANOBOM_UPLOAD_WAIT_SECONDS`, or lower the setting: see
[Let uploads wait through your proxies](fail-ci.md#let-uploads-wait-through-your-proxies).

### Components without package URL

The response's `components_without_purl` is not zero, and the project page says some components
cannot be checked. OSV matches components by package URL, so those are invisible to it. The
`skipped` list in the response names them with the reason (`no package URL`, or an invalid one).

Usually the generator could not identify them: vendored code, binaries copied into an image,
packages installed outside a package manager. Use the generator of the ecosystem instead of a
generic scanner where you can (see [Generate an SBOM](generate-sbom.md)). Components that are
genuinely your own code have no package URL, and need none.

### A project appeared twice, or with an unexpected name

Organization tokens create a project for each new slug, so a typo or a renamed repository
creates a new project. Delete the unwanted one from its page (admins), and switch the pipeline to
a project token, which cannot create projects.

## Findings

### No findings at all

Check, in order:

1. **Did a run happen?** The organization page lists **Recent runs**. With
   `NANOBOM_RUN_AFTER_UPLOAD=false`, a project waits for the nightly run or a **Check now**.
2. **Did it succeed?** A failed run leaves findings as they were, so a new project stays empty.
3. **Are the components checkable?** The project page shows the component count and warns about
   components without package URL. Components whose package URL has no version cannot be matched.
4. **Does OSV cover them?** OSV covers language ecosystems and several Linux distributions; it
   does not cover everything (some distributions, firmware, proprietary software).

An SBOM of up-to-date dependencies may simply have no known vulnerabilities.

### Findings were fixed, but nothing was upgraded

Each upload replaces the project's components: a component missing from the new SBOM fixes its
findings. Typical causes are an SBOM generated from a different directory, a partial build, a
per-crate SBOM of a workspace instead of the binary's, or development dependencies left out where
they used to be included. Compare `component_count` across uploads in the project's
**Upload history**.

### A finding has an unexpected severity

Severity comes from the highest-rated record among the finding's aliases, using the most recent
CVSS version available. A GitHub advisory and the CVE it aliases can rate the same issue
differently; nanobom shows the higher. See [Severity](../explanation/findings.md#severity).

### No finding is known exploited

- Only CVEs are looked up: findings without a CVE among their identifiers have no exploitation
  data.
- Exploitation data is refreshed after successful runs; check
  `nanobom_exploitation_refresh_failures_total` and look for `refreshing exploitation data
  failed` in the logs. The instance must reach `www.cisa.gov` and `api.first.org`.
- `NANOBOM_EXPLOITATION_DATA=false` turns it off.

### A webhook does not arrive

- **Settings → Webhook** shows the last delivery and its outcome: an HTTP status from your
  receiver, or a network error.
- The webhook must be **Enabled**, and findings must reach the minimum severity (or be known
  exploited). With **Only known exploited vulnerabilities**, nothing else is sent.
- `findings.new` is only sent for new, reopened or newly exploited findings: a finding that was
  already open is not sent again.
- `projects.stale` is only sent after **scheduled** runs.
- Deliveries are not retried, and must be answered within 15 seconds.

### A run stays "Running"

nanobom was stopped during that run. It is not resumed; the next run of the same scope does the
work. The entry stays in the list as it was.

## Interface

### Forms answer "cross-site request refused"

The browser's address does not match `NANOBOM_PUBLIC_URL`: another host name, `http` instead of
`https`, or another port. Set `NANOBOM_PUBLIC_URL` to the address you use, or use the address it
names.

### Signing in returns to the sign-in page

The session cookie is not kept. Most often `NANOBOM_PUBLIC_URL` is `https://…` while you browse
over plain `http`: the cookie is then marked `Secure`, and the browser does not send it back.

### Pages have no styles

nanobom cannot find its assets: `NANOBOM_SITE_ROOT` must point at the `site` directory of the
release. In the image, it is set to `/app/site`.

### Sign-in answers 429

Too many failed attempts from the same address: wait a few seconds. If every user is limited at
once, nanobom sees all requests coming from the reverse proxy: set
`NANOBOM_TRUST_FORWARDED_HEADERS=true`, only behind a proxy that replaces `X-Forwarded-For` (see
[Run behind a reverse proxy](reverse-proxy.md)).

## Single sign-on

The sign-in page shows a short message, and the logs say why:

| Message | Cause |
| --- | --- |
| The identity provider could not sign you in | Discovery failed, the provider refused the sign-in (wrong redirect URI or client secret), or its answer could not be verified; see the `OpenID Connect sign-in refused` or `starting the OpenID Connect sign-in failed` log line, and [below](#the-identity-provider-could-not-sign-you-in) |
| The sign-in took too long; please try again | The session cookie set when leaving for the provider was not sent back: the sign-in took longer than the session, or the public URL's host or scheme differs from the address in the browser |
| This account is not known here and new accounts are not created automatically | `NANOBOM_OIDC_CREATE_USERS=false` and the user never signed in |
| This account is disabled | An instance administrator disabled the user |

### The provider reports a redirect URI mismatch

The redirect URI nanobom sends is `NANOBOM_PUBLIC_URL` followed by `auth/oidc/callback`. Register
exactly that at the provider, scheme, host and port included: if `NANOBOM_PUBLIC_URL` was left at
its default, nanobom sends `http://localhost:8080/auth/oidc/callback`.

### "The identity provider could not sign you in"

The logs say why (`OpenID Connect sign-in refused` or `starting the OpenID Connect sign-in
failed`):

- `the identity provider could not be reached` — nanobom cannot fetch
  `<issuer>/.well-known/openid-configuration`: wrong issuer, provider unreachable from nanobom's
  network, or a redirect (an `http` issuer redirected to `https`, for example), which nanobom does
  not follow;
- `unexpected issuer URI` — the issuer in the discovery document differs from
  `NANOBOM_OIDC_ISSUER`. Copy it exactly from the discovery document, including a trailing `/`
  if there is one;
- `the identity provider refused the sign-in` — usually a wrong client secret, or a client not
  allowed to use the authorization code flow.

### Groups or administrator rights are not applied

- Roles from groups and the administrator claim are applied **at sign-in**: sign out and in again
  after changing them at the provider.
- The claim must be in the ID token or in the user information. Many providers put groups and
  roles in the access token only by default, which nanobom does not read; see the
  [provider examples](single-sign-on.md#keycloak).
- `NANOBOM_OIDC_GROUPS_CLAIM` must name the claim exactly, as a top-level name or a dotted path
  (`realm_access.roles`).
- Group names in `NANOBOM_OIDC_GROUP_MAPPING` must match the claim's values exactly; Keycloak
  sends `/developers` with **Full group path** on.

### An administrator lost their rights after signing in

With `NANOBOM_OIDC_ADMINISTRATOR_CLAIM` set, the claim decides at each sign-in, and removes rights
given in the interface from users who do not have it. Grant the claim at the provider instead.

## Startup errors

| Message | Fix |
| --- | --- |
| `no sign-in method` | Enable local accounts or configure OpenID Connect |
| `OpenID Connect needs both NANOBOM_OIDC_ISSUER and NANOBOM_OIDC_CLIENT_ID` | Set both, or neither |
| `invalid NANOBOM_SCHEDULE` | Use a five-field cron expression, or `off` |
| `invalid NANOBOM_OIDC_GROUP_MAPPING` | Fix the entry named in the message: `group=organization:role` |
| `invalid value '' for '--failure-webhook-url …'` (or another option) | An empty variable: remove it instead |
| `unable to open database file` | The database's directory does not exist or is not writable by nanobom's user (65532 in the image) |
