# Backups and upgrades

## What to back up

Everything lives in the SQLite database (`/data/nanobom.db` in the image): users and password
hashes, organizations, upload token digests, inventories, findings and their history, sessions,
and the cached OSV and exploitation data. Back up that file and nothing else; treat the backups
as sensitive.

Do not copy the database file of a running instance with `cp`: nanobom uses SQLite's
write-ahead log, so recent changes may still be in `nanobom.db-wal` and the copy can be
inconsistent. Use `nanobom backup`.

## Taking a backup

`nanobom backup <file>` writes a consistent copy of the live database with SQLite's
`VACUUM INTO`, without stopping nanobom or blocking it. It refuses to overwrite an existing file,
and the directory must exist and be writable by the user nanobom runs as.

The image has no shell to manage files, so give it a backup directory. With Compose, add a bind
mount owned by the container's user (65532):

```yaml
services:
  nanobom:
    volumes:
      - nanobom-data:/data
      - ./backups:/backups
```

```sh
mkdir -p backups && sudo chown 65532:65532 backups
# Daily, from cron on the host; $(date) is expanded by the host's shell.
docker compose exec -T nanobom /app/nanobom backup "/backups/nanobom-$(date +%F).db"
```

Then rotate and copy `backups/` off the host with your usual tools. Without containers:

```sh
nanobom backup "/var/backups/nanobom/nanobom-$(date +%F).db"
```

A backup is an ordinary SQLite database, so it can be checked with
`sqlite3 nanobom-2026-11-08.db 'PRAGMA integrity_check'`.

## Restoring

1. Stop nanobom.
2. Replace the database with the backup, and delete the `-wal` and `-shm` files next to it, which
   belong to the old database.
3. Start nanobom. If the backup comes from an older version, its migrations run at startup.

With a Docker volume, a throwaway container does the copy (the volume of a Compose project is
named after the project, here `nanobom_nanobom-data`):

```sh
docker compose stop nanobom
docker run --rm -v nanobom_nanobom-data:/data -v "$PWD/backups:/backups" alpine sh -c '
  cp /backups/nanobom-2026-11-08.db /data/nanobom.db &&
  rm -f /data/nanobom.db-wal /data/nanobom.db-shm &&
  chown 65532:65532 /data/nanobom.db'
docker compose start nanobom
```

Sessions are in the database too, so users signed in after the backup was taken have to sign in
again; uploads and runs since then are lost and come back with the next uploads and the next
nightly run.

## Upgrading

```sh
docker compose pull && docker compose up -d --wait
```

Database migrations run when the server starts, before it accepts requests. `nanobom migrate`
runs them alone, for a deployment that wants them as a separate step. Migrations only go forward:
take a backup before upgrading, since going back to an older version means restoring it.

Images are tagged `X.Y.Z`, `X.Y`, `X` and `latest`. Pin a tag that matches how you want to
upgrade: `X.Y` follows fixes only. While nanobom's version is below 1.0, a breaking change raises
the minor version (`0.3` to `0.4`): read the
[changelog](https://github.com/AlixANNERAUD/nanobom/blob/main/CHANGELOG.md) before changing it.

On shutdown (`SIGTERM`), requests in progress finish; a run in progress is not resumed and stays
listed as running. The next scheduled run covers its scope again.

## Sizing

nanobom does its work in short bursts, after uploads and at night, and is idle the rest of the
time. What makes it grow:

- **Memory** peaks during uploads: each request body is held in memory, and parsing an SBOM takes
  a few times its size, with two SBOMs parsed at a time at most. Raise
  `NANOBOM_MAXIMUM_SBOM_SIZE` with that in mind.
- **Disk** holds the components of each project's latest SBOM, the findings and their history,
  and the cached vulnerability records. Old uploads only keep their metadata (date, commit, tag,
  counts), not their components, so the database grows with the number of projects and findings,
  not with the number of uploads.
- **Run duration** depends on the number of distinct package URLs (one OSV request per 1,000) and
  on how many vulnerability records are new or modified (fetched 8 at a time). The first run of a
  large instance takes the longest; later ones reuse the cache. Watch
  `nanobom_run_duration_seconds`, and keep `NANOBOM_UPLOAD_WAIT_SECONDS` above the usual duration
  of a project's run plus the time it may wait behind the nightly run.

One instance runs one process: do not start two servers on the same database. Runs are
serialized inside the process, and two processes would each run the schedule and send every
webhook twice.
