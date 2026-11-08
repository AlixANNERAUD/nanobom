# Configuration

Every option is an environment variable and a command-line flag of the same name
(`NANOBOM_PUBLIC_URL` is `--public-url`); a flag wins over the variable. `nanobom <command>
--help` lists them with their defaults. This page lists the options of the server,
`nanobom serve`, and those every command reads; the options of the other commands are in the
[command-line reference](command-line.md).

Boolean options take `true` or `false`, as variables and as flags (`--run-after-upload false`).
Leave an option unset rather than empty: an empty variable is a value, and an empty URL is an
invalid one, which stops nanobom at startup.

## Every command

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_DATABASE_URL` | `--database-url` | `sqlite:///data/nanobom.db` | The database. SQLite: `sqlite:///absolute/path.db` (three slashes before an absolute path) or `sqlite://relative/path.db`, created if missing. PostgreSQL: `postgres://user:password@host:port/database`, an existing database (see below). |
| `NANOBOM_LOG_FORMAT` | `--log-format` | `json` | `json` (one object per line, for collectors) or `text`. |
| `NANOBOM_LOG_LEVEL` | `--log-level` | `info` | A [`tracing` filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html), such as `info,nanobom=debug`. |

### PostgreSQL URLs

`postgres://user:password@host:port/database?parameter=value&…` (`postgresql://` works too). The
port defaults to 5432. Characters of the user or password outside letters, digits and `-._~` are
percent-encoded (`@` is `%40`). The database must exist; nanobom creates its tables at startup,
so the role needs to own the database or to be allowed to create tables in its `public` schema.
nanobom opens at most 8 connections.

| Parameter | |
| --- | --- |
| `sslmode` | `disable`, `prefer` (the default: TLS when the server offers it, without checking the certificate), `require` (TLS, certificate not checked), `verify-ca` (certificate checked against the trusted authorities) or `verify-full` (also checks that it names the host). Without `sslrootcert`, the trusted authorities are the public ones of [webpki-roots](https://github.com/rustls/webpki-roots). |
| `sslrootcert` | A PEM file of the authorities to trust instead, such as a managed database's CA bundle. |
| `sslcert`, `sslkey` | A client certificate and its key, for servers that require one. |
| `application_name` | The name shown in `pg_stat_activity`. |

See [Run on PostgreSQL](../how-to/postgresql.md).

## Addresses and files

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_PUBLIC_URL` | `--public-url` | `http://localhost:8080` | The address users reach nanobom at. Used for links in webhooks and API responses, the OpenID Connect redirect URI, the `Secure` flag of cookies (set when it is `https`) and the cross-site request check (the `Origin` of form submissions must match it). Set it to the address in the browser's address bar, scheme and port included. |
| `NANOBOM_LISTEN_ADDRESS` | `--listen-address` | `0.0.0.0:8080` | Address and port to listen on. `127.0.0.1:8080` keeps nanobom reachable only through a local reverse proxy. |
| `NANOBOM_SITE_ROOT` | `--site-root` | `site` | The directory of the web interface's assets (the `site` directory of a release archive; `/app/site` in the image). Relative paths are relative to the working directory. |

## Runs

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_SCHEDULE` | `--schedule` | `0 3 * * *` | When every project is re-evaluated: a cron expression in UTC with five fields (minute, hour, day of month, month, day of week), or `off`. `0 */6 * * *` runs every six hours, `30 2 * * 1-5` at 02:30 on weekdays. `off` turns scheduled runs off; uploads and manual checks still run. An invalid expression stops the server at startup. |
| `NANOBOM_RUN_AFTER_UPLOAD` | `--run-after-upload` | `true` | Evaluate a project right after each upload. With `false`, projects are evaluated by the schedule, manual checks and uploads that wait. |
| `NANOBOM_UPLOAD_WAIT_SECONDS` | `--upload-wait-seconds` | `300` | Longest time an upload with `wait` or `fail_on` waits for its evaluation. Keep it below your reverse proxy's read timeout. |
| `NANOBOM_OSV_URL` | `--osv-url` | `https://api.osv.dev/` | The OSV API, or a compatible mirror offering `/v1/querybatch` and `/v1/vulns/{id}`. |
| `NANOBOM_MAXIMUM_SBOM_SIZE` | `--maximum-sbom-size` | `16` | Largest accepted SBOM, in MiB. Parsing takes a few times this much memory. |
| `NANOBOM_STALE_AFTER_DAYS` | `--stale-after-days` | `30` | Days without an SBOM after which a project is stale; `0` turns the feature off. |
| `NANOBOM_FAILURE_WEBHOOK_URL` | `--failure-webhook-url` | | Receives a [`run.failed`](webhooks.md#runfailed) document when a run fails. |

## Exploitation data

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_EXPLOITATION_DATA` | `--exploitation-data` | `true` | Download exploitation data (CISA KEV, FIRST EPSS) after each run. `false` for instances that cannot reach them; `fail_on=exploited` is then refused. |
| `NANOBOM_KEV_URL` | `--kev-url` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA's Known Exploited Vulnerabilities catalog (JSON). A mirror must serve the catalog's JSON as is. |
| `NANOBOM_EPSS_URL` | `--epss-url` | `https://api.first.org/data/v1/epss` | FIRST's EPSS API. A mirror must answer `GET <url>?cve=CVE-…,CVE-…` like FIRST's API. |

## Accounts and sessions

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_LOCAL_ACCOUNTS` | `--local-accounts` | `true` | Sign-in with a username or email address and a password. |
| `NANOBOM_PASSWORD_MINIMUM_LENGTH` | `--password-minimum-length` | `12` | Minimum length of local passwords. |
| `NANOBOM_PERSONAL_ORGANIZATIONS` | `--personal-organizations` | `true` | Give each new user an organization of their own; applies to users created afterwards. |
| `NANOBOM_SESSION_INACTIVITY_DAYS` | `--session-inactivity-days` | `7` | Sign users out after this many days without a request (at least 1). |
| `NANOBOM_TRUST_FORWARDED_HEADERS` | `--trust-forwarded-headers` | `false` | Read client addresses from `X-Forwarded-For`, `X-Real-IP` and `Forwarded`, for sign-in rate limiting. Only behind a reverse proxy that sets them. |

nanobom refuses to start when local accounts are off and OpenID Connect is not configured.

## OpenID Connect

Enabled by setting both `NANOBOM_OIDC_ISSUER` and `NANOBOM_OIDC_CLIENT_ID`; setting only one stops
nanobom at startup. See [Set up single sign-on](../how-to/single-sign-on.md).

| Variable | Flag | Default | |
| --- | --- | --- | --- |
| `NANOBOM_OIDC_ISSUER` | `--oidc-issuer` | | Issuer URL of the provider; its discovery document is read from it. |
| `NANOBOM_OIDC_CLIENT_ID` | `--oidc-client-id` | | Client identifier. |
| `NANOBOM_OIDC_CLIENT_SECRET` | `--oidc-client-secret` | | Client secret, for confidential clients; public clients rely on PKCE alone. |
| `NANOBOM_OIDC_SCOPES` | `--oidc-scopes` | `openid profile email` | Scopes to request, separated by spaces. |
| `NANOBOM_OIDC_CREATE_USERS` | `--oidc-create-users` | `true` | Create users at their first sign-in. |
| `NANOBOM_OIDC_ADMINISTRATOR_CLAIM` | `--oidc-administrator-claim` | | Claim granting instance administration, applied at each sign-in ([administrator claim](accounts.md#administrator-claim)). Dotted paths reach nested claims. |
| `NANOBOM_OIDC_ADMINISTRATOR_VALUE` | `--oidc-administrator-value` | | Value the administrator claim must contain; without it, the claim must be `true`. |
| `NANOBOM_OIDC_GROUPS_CLAIM` | `--oidc-groups-claim` | | Claim listing the user's groups or roles, for the group mapping. |
| `NANOBOM_OIDC_GROUP_MAPPING` | `--oidc-group-mapping` | | `group=organization:role` entries separated by `;` or line breaks ([syntax](accounts.md#roles-from-identity-provider-groups)). |
| `NANOBOM_OIDC_BUTTON_LABEL` | `--oidc-button-label` | `Sign in with single sign-on` | Label of the sign-in button. |
