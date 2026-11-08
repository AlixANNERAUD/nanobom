# Getting started

This page takes you from nothing to a first SBOM with its findings, on your own machine. For a
real deployment, read [Operating nanobom](operations/README.md) next: it adds TLS, a reverse
proxy, monitoring and backups.

## 1. Start nanobom

Pick one of the three ways below. All of them listen on port 8080 and keep their data in one
SQLite file.

### Docker Compose

From a clone of the repository, which contains a ready
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

### `docker run`

```sh
docker run -d --name nanobom -p 8080:8080 -v nanobom-data:/data \
  -e NANOBOM_PUBLIC_URL=http://localhost:8080 \
  ghcr.io/alixanneraud/nanobom:latest
```

The database lives in the `/data` volume. The image is distroless: it has no shell, so run
nanobom's own commands with `docker exec nanobom /app/nanobom …`. It runs as the unprivileged
user 65532; a bind mount instead of a volume must be writable by that user.

### Without containers

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
scripts. The default database path, `/data/nanobom.db`, suits the image; elsewhere,
set `NANOBOM_DATABASE_URL` to a file in a directory the service can write to. A systemd unit is a few
lines:

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

## 2. Create the first administrator

Nobody can sign in yet. Create an instance administrator from the command line; the password is
read from standard input:

```sh
# Docker Compose
docker compose exec nanobom /app/nanobom create-administrator --username admin
# docker run
docker exec -it nanobom /app/nanobom create-administrator --username admin
# Without containers (same environment as the server, for NANOBOM_DATABASE_URL)
./nanobom create-administrator --username admin
```

The password is read as a plain line and shown as you type it; it must have at least 12
characters (`NANOBOM_PASSWORD_MINIMUM_LENGTH`). In scripts, pass it with
`NANOBOM_ADMINISTRATOR_PASSWORD` instead. `--email` sets an email address, which can then be used
to sign in instead of the username.

If you only use single sign-on, you can skip this step and grant administration through a claim
of your identity provider instead: see [OpenID Connect](access/openid-connect.md).

## 3. Create an organization and an upload token

1. Open <http://localhost:8080> and sign in.
2. You land on **Organizations**. You already have a personal organization named after your
   username; for a team, create another one under **New organization** (its slug appears in
   upload URLs, so keep it short: `acme`).
3. Open the organization, then **Settings**. Under **Upload tokens**, give the token a name
   (`CI`) and leave the scope on **Whole organization**, then **Create token**.
4. Copy the token, which starts with `nanobom_`. It is shown once; only a digest is stored.

The same token can be created from the command line, which prints it on standard output:

```sh
docker compose exec nanobom /app/nanobom token create --organization acme --name CI
```

## 4. Upload an SBOM

Any CycloneDX JSON SBOM will do. If you have none at hand, generate one of the nanobom checkout
with [Syft](https://github.com/anchore/syft):

```sh
syft dir:. -o cyclonedx-json=sbom.json
```

Then send it, naming the project in the URL (`demo` here; it is created by this first upload):

```sh
export NANOBOM_TOKEN=nanobom_…
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "http://localhost:8080/api/organizations/acme/projects/demo/sbom?wait=true"
```

`wait=true` holds the request until the project has been checked against OSV, and adds the
result to the response:

```json
{
  "organization": "acme",
  "project": "demo",
  "project_id": 1,
  "project_created": true,
  "upload_id": 1,
  "component_count": 412,
  "components_without_purl": 0,
  "skipped": [],
  "evaluation": {
    "status": "succeeded",
    "run_id": 1,
    "open": { "critical": 0, "high": 1, "medium": 3, "low": 0, "unknown": 0 },
    "known_exploited": 0,
    "findings": [ … ]
  }
}
```

The response format and every status code are described in [The upload API](uploading/api.md).

## 5. Read the results

Open the organization page. Each project shows its open findings by severity, how many are
ignored or known exploited, and when its last SBOM arrived. **Recent runs** lists the runs that
covered the organization, with their outcome.

Open the project: its findings are listed known exploited first, then by severity and by EPSS
score. Filters narrow them by severity, status, ecosystem, or to known exploited ones. A
warning appears when the last SBOM had components without a package URL.

Open a finding to see the vulnerability's description, the fixed versions OSV knows, its
aliases and references, its exploitation signals, the other components affected by it in the
organizations you can see, and its history. Members can **ignore** it there, with a reason.

From here:

- wire your pipelines: [Continuous integration](uploading/ci.md);
- get notified of new findings: [Notifications](notifications.md);
- invite your team: [Accounts, organizations and access](access/README.md).
