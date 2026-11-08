# Run on PostgreSQL

nanobom keeps its data in SQLite by default. It can use a PostgreSQL database instead, for
example a managed one or a server you already back up: see
[SQLite or PostgreSQL](../explanation/architecture.md#sqlite-or-postgresql) to decide. Decide
before the first start: nanobom has no tool to move its data from one database to the other.

nanobom is tested on PostgreSQL 17 and needs nothing beyond a database and a role that owns it.

## With Docker Compose

[`examples/compose-postgres.yaml`](https://github.com/AlixANNERAUD/nanobom/blob/main/examples/compose-postgres.yaml)
runs nanobom next to a `postgres:17-alpine` container. Set the database password first, in the
environment or a `.env` file next to the Compose file:

```sh
# examples/.env
NANOBOM_POSTGRES_PASSWORD=a-long-random-password
NANOBOM_PUBLIC_URL=http://localhost:8080
```

```sh
docker compose -f examples/compose-postgres.yaml up -d --wait
docker compose -f examples/compose-postgres.yaml exec nanobom /app/nanobom create-administrator --username admin
```

The PostgreSQL container has a health check (`pg_isready`), and nanobom starts once it passes
(`depends_on` with `condition: service_healthy`), since it applies its migrations at startup.
The data lives in the `postgres-data` volume; nanobom itself needs no volume.

The password is part of a URL in `NANOBOM_DATABASE_URL`: keep it to letters, digits and `-._~`,
or percent-encode the other characters (`@` is `%40`).

## With an existing PostgreSQL server

1. Create a role and a database it owns, so that nanobom can create its tables:

   ```sql
   CREATE ROLE nanobom LOGIN PASSWORD 'a-long-random-password';
   CREATE DATABASE nanobom OWNER nanobom;
   ```

2. Point nanobom at it, with the [URL form](../reference/configuration.md#every-command):

   ```sh
   NANOBOM_DATABASE_URL=postgres://nanobom:a-long-random-password@db.example.org:5432/nanobom?sslmode=verify-full
   ```

   `sslmode=verify-full` encrypts the connection and checks the server's certificate against the
   public certificate authorities; add `sslrootcert=/path/to/ca.pem` when the server's certificate
   comes from a private one, as with most managed databases.

3. Start nanobom (`nanobom serve`): it creates the schema on the first start, and applies new
   migrations on later ones. Then
   [create the first administrator](install.md#create-the-first-administrator), with the same
   `NANOBOM_DATABASE_URL`.

nanobom opens at most 8 connections. Run a single nanobom process per database
([why](../explanation/architecture.md#one-process-per-database)).

## Back up

`nanobom backup` copies SQLite databases only. Use PostgreSQL's tools: see
[Back up and restore PostgreSQL](maintenance.md#back-up-and-restore-postgresql).
