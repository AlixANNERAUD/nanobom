# Back up, restore and upgrade

Everything lives in the database, the SQLite file (`/data/nanobom.db` in the image) or the
PostgreSQL database: users and password hashes, organizations, upload token digests,
inventories, findings and their history, sessions, and the cached OSV and exploitation data.
Back up the database and nothing else; treat the backups as sensitive.

## Take a backup of SQLite

Do not copy the database file of a running instance with `cp`: nanobom uses SQLite's
write-ahead log, so recent changes may still be in `nanobom.db-wal` and the copy can be
inconsistent. Use `nanobom backup <file>`, which writes a consistent copy of the live database
without stopping nanobom or blocking it. It refuses to overwrite an existing file, and the
directory must exist and be writable by the user nanobom runs as.

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

## Restore a SQLite backup

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

## Back up and restore PostgreSQL

`nanobom backup` copies SQLite databases only; on PostgreSQL it stops with a message pointing to
`pg_dump`. `pg_dump` writes a consistent snapshot of the live database without stopping nanobom;
the custom format (`--format=custom`) is compressed and restored with `pg_restore`. Use a
`pg_dump` at least as recent as the server. With
[`examples/compose-postgres.yaml`](postgresql.md#with-docker-compose), from cron on the host:

```sh
docker compose -f examples/compose-postgres.yaml exec -T postgres \
  pg_dump --username nanobom --format=custom nanobom > "backups/nanobom-$(date +%F).dump"
```

Against another server, `pg_dump --format=custom --file nanobom.dump "$NANOBOM_DATABASE_URL"`
does the same (`pg_dump` reads the URL, `sslmode` included). A managed database's own snapshots
work too.

To restore:

1. Stop nanobom.
2. Restore the dump over the database, replacing its objects:

   ```sh
   docker compose -f examples/compose-postgres.yaml exec -T postgres \
     pg_restore --username nanobom --dbname nanobom --clean --if-exists --no-owner \
     < backups/nanobom-2026-11-08.dump
   ```

3. Start nanobom. If the dump comes from an older version, its migrations run at startup.

As with SQLite, sessions, uploads and runs since the dump are lost.

## Upgrade

Take a backup first (`nanobom backup` or `pg_dump`): migrations only go forward, so going back
to an older version means restoring it. Then:

```sh
docker compose pull && docker compose up -d --wait
```

Database migrations run when the server starts, before it accepts requests. `nanobom migrate`
runs them alone, for a deployment that wants them as a separate step.

Images are tagged `X.Y.Z`, `X.Y`, `X` and `latest`. Pin a tag that matches how you want to
upgrade: `X.Y` follows fixes only. While nanobom's version is below 1.0, a breaking change raises
the minor version (`0.3` to `0.4`): read the
[changelog](https://github.com/AlixANNERAUD/nanobom/blob/main/CHANGELOG.md) before changing it.

On shutdown (`SIGTERM`), requests in progress finish; a run in progress is not resumed and stays
listed as running. The next scheduled run covers its scope again.

After an upgrade from a version without exploitation signals, the first run delivers every open
known exploited finding of its scope once to the organizations' webhooks, with the `exploited`
reason, since none had been notified as such.
