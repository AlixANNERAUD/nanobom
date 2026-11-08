# Command line

```text
nanobom [--database-url …] [--log-format …] [--log-level …] <command> [options]
```

Every option is also an environment variable; the options every command reads, and those of
`serve`, are in the [configuration reference](configuration.md). `nanobom --version` prints the
version, and `nanobom <command> --help` lists a command's options with their defaults.

In the container image, run commands with `docker exec <container> /app/nanobom …` (or
`docker compose exec nanobom /app/nanobom …`), which inherits the server's
`NANOBOM_DATABASE_URL`. Elsewhere, run them with the same `NANOBOM_DATABASE_URL` as the server.

| Command | |
| --- | --- |
| `nanobom serve` | Apply pending migrations, then serve the web interface and the API. |
| `nanobom migrate` | Apply pending database migrations and exit. |
| `nanobom backup <destination>` | Write a consistent copy of the live database to a new file. |
| `nanobom create-administrator` | Create a local instance administrator. |
| `nanobom token create`, `list`, `revoke` | Manage upload tokens. |
| `nanobom healthcheck` | Check that the running server is healthy. |

`create-administrator` and `token` apply pending migrations first, so they work on a new
database; `backup` copies the database as it is.

## `nanobom serve`

Serves the web interface, the upload API, `/healthz` and `/metrics`, and runs the schedule.
Database migrations run at startup, before it accepts requests. On `SIGTERM`, requests in
progress finish; a run in progress is not resumed and stays listed as running. Options: see
[Configuration](configuration.md).

## `nanobom migrate`

Applies pending database migrations and exits, for a deployment that wants them as a separate
step. Migrations only go forward.

## `nanobom backup`

| Argument | Variable | |
| --- | --- | --- |
| `<destination>` | `NANOBOM_BACKUP_DESTINATION` | The file to write; it must not exist yet. |

Writes a consistent copy of the live SQLite database with SQLite's `VACUUM INTO`, without
stopping the server or blocking it. It never overwrites a file; the directory must exist and be
writable by the user nanobom runs as.

On PostgreSQL it writes nothing and fails with `nanobom backup copies SQLite databases only; back
up this Postgres database with its own tools, pg_dump for PostgreSQL`: see
[Back up and restore PostgreSQL](../how-to/maintenance.md#back-up-and-restore-postgresql).

## `nanobom create-administrator`

| Flag | Variable | |
| --- | --- | --- |
| `--username` | `NANOBOM_ADMINISTRATOR_USERNAME` | Required. |
| `--email` | `NANOBOM_ADMINISTRATOR_EMAIL` | Optional; can then be used to sign in instead of the username. |
| `--password` | `NANOBOM_ADMINISTRATOR_PASSWORD` | Read from standard input when unset, as a plain line, shown as it is typed. |
| `--personal-organizations` | `NANOBOM_PERSONAL_ORGANIZATIONS` | Give the user a personal organization (default `true`). |
| `--password-minimum-length` | `NANOBOM_PASSWORD_MINIMUM_LENGTH` | Minimum password length (default `12`). |

Creates a local account that is an instance administrator, typically the first one.

## `nanobom token`

Manages upload tokens with direct access to the database, like **Settings → Upload tokens**.

| Command | Flags | |
| --- | --- | --- |
| `nanobom token create` | `--organization` (`NANOBOM_TOKEN_ORGANIZATION`), `--name` (`NANOBOM_TOKEN_NAME`), `--project` (`NANOBOM_TOKEN_PROJECT`, optional) | Create a token and print it. Without `--project`, the token covers the organization and may create projects. |
| `nanobom token list` | `--organization` (`NANOBOM_TOKEN_ORGANIZATION`) | List an organization's tokens. |
| `nanobom token revoke` | `--id` | Revoke a token, by the identifier `token list` prints. |

```sh
nanobom token create --organization acme --name "web CI" --project web
nanobom token list --organization acme
# 7	nanobom_3f9a1c	web CI	web	2026-11-08T03:12:44+00:00	active
nanobom token revoke --id 7
```

`token create` prints the token alone on standard output, so a script can capture it:
`TOKEN=$(nanobom token create --organization acme --name CI)`. It cannot be shown again.

`token list` prints one tab-separated line per token, revoked ones included: identifier, first
characters, name, project (or `(organization)`), last use, state.

## `nanobom healthcheck`

| Flag | Variable | Default | |
| --- | --- | --- | --- |
| `--listen-address` | `NANOBOM_LISTEN_ADDRESS` | `0.0.0.0:8080` | The server's listen address; its health endpoint is reached over loopback when it listens on every interface. |
| `--url` | `NANOBOM_HEALTHCHECK_URL` | | Health endpoint to check instead of the one derived from the listen address. |
| `--timeout-seconds` | | `5` | Seconds to wait for an answer. |

Exits successfully when the running server answers its health endpoint, `/healthz`, with `200`.
It is the container image's health check, which has no shell or `curl`. It does not open the
database.
