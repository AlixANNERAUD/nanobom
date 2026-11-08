# Configuration reference

Every option is an environment variable and a command-line flag of the same name
(`NANOBOM_PUBLIC_URL` is `--public-url`); a flag wins over the variable. `nanobom <command>
--help` lists them with their defaults.

Boolean options take `true` or `false`, as variables and as flags (`--run-after-upload false`).
Leave an option unset rather than empty: an empty variable is a value, and an empty URL is an
invalid one, which stops nanobom at startup.

## Server (`nanobom serve`)

### Addresses and files

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_PUBLIC_URL` | `http://localhost:8080` | The address users reach nanobom at. Used for links in webhooks and API responses, the OpenID Connect redirect URI, the `Secure` flag of cookies (set when it is `https`) and the cross-site request check (the `Origin` of form submissions must match it). Set it to the address in the browser's address bar, scheme and port included. |
| `NANOBOM_LISTEN_ADDRESS` | `0.0.0.0:8080` | Address and port to listen on. `127.0.0.1:8080` keeps nanobom reachable only through a local reverse proxy. |
| `NANOBOM_DATABASE_URL` | `sqlite:///data/nanobom.db` | The SQLite database, created if missing. `sqlite:///absolute/path.db` (three slashes before an absolute path) or `sqlite://relative/path.db`. Every command reads it. |
| `NANOBOM_SITE_ROOT` | `site` | The directory of the web interface's assets (the `site` directory of a release archive; `/app/site` in the image). Relative paths are relative to the working directory. |

### Runs

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_SCHEDULE` | `0 3 * * *` | When every project is re-evaluated: a cron expression in UTC (minute, hour, day of month, month, day of week), or `off`. |
| `NANOBOM_RUN_AFTER_UPLOAD` | `true` | Evaluate a project right after each upload. With `false`, projects are evaluated by the schedule, manual checks and uploads that wait. |
| `NANOBOM_UPLOAD_WAIT_SECONDS` | `300` | Longest time an upload with `wait` or `fail_on` waits for its evaluation. Keep it below your reverse proxy's read timeout. |
| `NANOBOM_OSV_URL` | `https://api.osv.dev/` | The OSV API, or a compatible mirror. |
| `NANOBOM_MAXIMUM_SBOM_SIZE` | `16` | Largest accepted SBOM, in MiB. Parsing takes a few times this much memory. |
| `NANOBOM_STALE_AFTER_DAYS` | `30` | Days without an SBOM after which a project is stale; `0` turns the feature off. |
| `NANOBOM_FAILURE_WEBHOOK_URL` | | Receives a `run.failed` document when a run fails. |

### Exploitation data

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_EXPLOITATION_DATA` | `true` | Download exploitation data (CISA KEV, FIRST EPSS) after each run. `false` for instances that cannot reach them; `fail_on=exploited` is then refused. |
| `NANOBOM_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | CISA's Known Exploited Vulnerabilities catalog (JSON). |
| `NANOBOM_EPSS_URL` | `https://api.first.org/data/v1/epss` | FIRST's EPSS API. |

### Accounts and sessions

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_LOCAL_ACCOUNTS` | `true` | Sign-in with a username or email address and a password. |
| `NANOBOM_PASSWORD_MINIMUM_LENGTH` | `12` | Minimum length of local passwords. |
| `NANOBOM_PERSONAL_ORGANIZATIONS` | `true` | Give each new user an organization of their own. |
| `NANOBOM_SESSION_INACTIVITY_DAYS` | `7` | Sign users out after this many days without a request (at least 1). |
| `NANOBOM_TRUST_FORWARDED_HEADERS` | `false` | Read client addresses from `X-Forwarded-For`, `X-Real-IP` and `Forwarded`, for sign-in rate limiting. Only behind a reverse proxy that sets them. |

nanobom refuses to start when local accounts are off and OpenID Connect is not configured.

### OpenID Connect

Enabled by setting both `NANOBOM_OIDC_ISSUER` and `NANOBOM_OIDC_CLIENT_ID`; setting only one stops
nanobom at startup. See [OpenID Connect](access/openid-connect.md).

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_OIDC_ISSUER` | | Issuer URL of the provider; its discovery document is read from it. |
| `NANOBOM_OIDC_CLIENT_ID` | | Client identifier. |
| `NANOBOM_OIDC_CLIENT_SECRET` | | Client secret, for confidential clients; public clients rely on PKCE alone. |
| `NANOBOM_OIDC_SCOPES` | `openid profile email` | Scopes to request, separated by spaces. |
| `NANOBOM_OIDC_CREATE_USERS` | `true` | Create users at their first sign-in. |
| `NANOBOM_OIDC_ADMINISTRATOR_CLAIM` | | Claim granting instance administration, applied at each sign-in. Dotted paths reach nested claims. |
| `NANOBOM_OIDC_ADMINISTRATOR_VALUE` | | Value the administrator claim must contain; without it, the claim must be `true`. |
| `NANOBOM_OIDC_GROUPS_CLAIM` | | Claim listing the user's groups or roles, for the group mapping. |
| `NANOBOM_OIDC_GROUP_MAPPING` | | `group=organization:role` entries separated by `;` or line breaks. |
| `NANOBOM_OIDC_BUTTON_LABEL` | `Sign in with single sign-on` | Label of the sign-in button. |

### Logs

These apply to every command.

| Variable | Default | |
| --- | --- | --- |
| `NANOBOM_LOG_FORMAT` | `json` | `json` (one object per line, for collectors) or `text`. |
| `NANOBOM_LOG_LEVEL` | `info` | A [`tracing` filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html), such as `info,nanobom=debug`. |

## Other commands

| Command | Options | |
| --- | --- | --- |
| `nanobom migrate` | | Apply pending database migrations and exit. |
| `nanobom backup <destination>` | `NANOBOM_BACKUP_DESTINATION` | Write a consistent copy of the live database to a new file; it never overwrites one. |
| `nanobom create-administrator` | `--username` (`NANOBOM_ADMINISTRATOR_USERNAME`), `--email` (`NANOBOM_ADMINISTRATOR_EMAIL`), `--password` (`NANOBOM_ADMINISTRATOR_PASSWORD`, read from standard input when unset), and the account options `NANOBOM_PERSONAL_ORGANIZATIONS`, `NANOBOM_PASSWORD_MINIMUM_LENGTH` | Create a local instance administrator. |
| `nanobom token create` | `--organization` (`NANOBOM_TOKEN_ORGANIZATION`), `--name` (`NANOBOM_TOKEN_NAME`), `--project` (`NANOBOM_TOKEN_PROJECT`, optional) | Create an upload token and print it. |
| `nanobom token list` | `--organization` (`NANOBOM_TOKEN_ORGANIZATION`) | List an organization's upload tokens. |
| `nanobom token revoke` | `--id` | Revoke an upload token. |
| `nanobom healthcheck` | `--listen-address` (`NANOBOM_LISTEN_ADDRESS`), `--url` (`NANOBOM_HEALTHCHECK_URL`), `--timeout-seconds` (5) | Exit successfully when the running server answers its health endpoint; for container health checks. Does not open the database. |

`create-administrator` and `token` apply pending migrations first, so they work on a new
database; `backup` copies the database as it is. Run them with the same `NANOBOM_DATABASE_URL`
as the server: in a container, `docker exec <container> /app/nanobom …` inherits it.

## Example

A production configuration behind a reverse proxy, with single sign-on and an alarm for failed
runs:

```sh
NANOBOM_PUBLIC_URL=https://nanobom.example.org
NANOBOM_LISTEN_ADDRESS=127.0.0.1:8080
NANOBOM_TRUST_FORWARDED_HEADERS=true
NANOBOM_FAILURE_WEBHOOK_URL=https://hooks.example.org/nanobom-ops/7f3c9a
NANOBOM_OIDC_ISSUER=https://keycloak.example.org/realms/acme
NANOBOM_OIDC_CLIENT_ID=nanobom
NANOBOM_OIDC_CLIENT_SECRET=…
NANOBOM_OIDC_GROUPS_CLAIM=groups
NANOBOM_OIDC_GROUP_MAPPING="security=acme:admin;developers=acme:member"
NANOBOM_OIDC_ADMINISTRATOR_CLAIM=groups
NANOBOM_OIDC_ADMINISTRATOR_VALUE=nanobom-admins
```
