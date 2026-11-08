# Install nanobom

nanobom listens on port 8080 and keeps everything in one SQLite file. Install it with Docker
Compose, `docker run`, or from a release archive, then create the first administrator. Every
setting is listed in the [configuration reference](../reference/configuration.md).

## With Docker Compose

The repository contains a ready
[`compose.yaml`](https://github.com/AlixANNERAUD/nanobom/blob/main/compose.yaml):

```sh
git clone https://github.com/AlixANNERAUD/nanobom.git
cd nanobom
docker compose up -d --wait
```

`--wait` returns once the container reports itself healthy. The file uses the published image
(`ghcr.io/alixanneraud/nanobom:latest`, for amd64 and arm64) and builds it from the checkout
when it is not available. Settings come from the environment or a `.env` file next to
`compose.yaml`, for example:

```sh
# .env
NANOBOM_PUBLIC_URL=http://localhost:8080
NANOBOM_PORT=8080
```

`compose.yaml` only passes a few variables to the container. To set others, add them under
`environment:` in the file. Leave optional settings out rather than empty: an empty
`NANOBOM_FAILURE_WEBHOOK_URL` is an invalid URL, not "no webhook".

## With `docker run`

```sh
docker run -d --name nanobom -p 8080:8080 -v nanobom-data:/data \
  -e NANOBOM_PUBLIC_URL=http://localhost:8080 \
  ghcr.io/alixanneraud/nanobom:latest
```

The database lives in the `/data` volume. The image is distroless: it has no shell, so run
nanobom's own commands with `docker exec nanobom /app/nanobom …`. It runs as the unprivileged
user 65532; a bind mount instead of a volume must be writable by that user.

## Without containers

Each [release](https://github.com/AlixANNERAUD/nanobom/releases) has an archive per
architecture, `nanobom-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` and
`nanobom-vX.Y.Z-aarch64-unknown-linux-gnu.tar.gz`, with a `.sha256` checksum and build
provenance. It holds the `nanobom` binary and the `site` directory of the web interface. The
binary is built on Debian 12 and needs its glibc or a newer one.

```sh
tar -xzf nanobom-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
cd nanobom-vX.Y.Z-x86_64-unknown-linux-gnu
export NANOBOM_SITE_ROOT="$PWD/site"
export NANOBOM_DATABASE_URL="sqlite://$HOME/nanobom/nanobom.db"
mkdir -p "$HOME/nanobom"
./nanobom serve
```

`NANOBOM_SITE_ROOT` defaults to `site`, relative to the working directory, which only works when
nanobom starts from the extracted directory; otherwise pages load without their styles and
scripts. The default database path, `/data/nanobom.db`, suits the image; elsewhere, set
`NANOBOM_DATABASE_URL` to a file in a directory the service can write to.

As a systemd service:

```ini
# /etc/systemd/system/nanobom.service
[Unit]
Description=nanobom
After=network-online.target
Wants=network-online.target

[Service]
User=nanobom
ExecStart=/opt/nanobom/nanobom serve
Environment=NANOBOM_SITE_ROOT=/opt/nanobom/site
Environment=NANOBOM_DATABASE_URL=sqlite:///var/lib/nanobom/nanobom.db
Environment=NANOBOM_PUBLIC_URL=https://nanobom.example.org
Environment=NANOBOM_LOG_FORMAT=text
StateDirectory=nanobom
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Create the first administrator

Nobody can sign in to a new instance. Create an instance administrator from the command line;
the password is read from standard input:

```sh
# Docker Compose
docker compose exec nanobom /app/nanobom create-administrator --username admin
# docker run
docker exec -it nanobom /app/nanobom create-administrator --username admin
# Without containers (same environment as the server, for NANOBOM_DATABASE_URL)
./nanobom create-administrator --username admin
```

The password is read as a plain line and shown as you type it; it must have at least
`NANOBOM_PASSWORD_MINIMUM_LENGTH` characters (12 by default). In scripts, pass it in
`NANOBOM_ADMINISTRATOR_PASSWORD` instead. `--email` sets an email address, which can then be used
to sign in instead of the username. All options are in the
[command-line reference](../reference/command-line.md#nanobom-create-administrator).

If you only use single sign-on, you can skip this step and grant administration through a claim
of your identity provider instead: see [Set up single sign-on](single-sign-on.md).

## Before opening the instance to your users

- [ ] TLS is terminated by a reverse proxy, and `NANOBOM_PUBLIC_URL` is its `https` address:
  [Run behind a reverse proxy](reverse-proxy.md).
- [ ] The proxy accepts SBOMs as large as `NANOBOM_MAXIMUM_SBOM_SIZE` and lets uploads wait
  `NANOBOM_UPLOAD_WAIT_SECONDS`.
- [ ] `NANOBOM_TRUST_FORWARDED_HEADERS=true`, so sign-in rate limiting sees client addresses.
- [ ] `/metrics` is scraped, and reachable only by your monitoring:
  [Monitor with Prometheus](monitoring.md).
- [ ] An alert fires when the last successful run is too old, and `NANOBOM_FAILURE_WEBHOOK_URL`
  reaches the operators: [Get notified](notifications.md#report-failed-runs-to-the-operators).
- [ ] The database is backed up daily, and a restore was tried once:
  [Back up, restore and upgrade](maintenance.md).
- [ ] The instance can reach `api.osv.dev`, `www.cisa.gov` and `api.first.org`, or uses mirrors,
  or has exploitation data turned off: [Run without internet access](offline.md).
- [ ] Only one nanobom process uses the database
  ([why](../explanation/architecture.md#one-process-per-database)).

A production configuration, behind a reverse proxy, with single sign-on and an alarm for failed
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
