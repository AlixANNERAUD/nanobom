# Operating nanobom

nanobom is one process and one SQLite file. There is no worker to scale, no cache to warm and no
queue to drain: running it well comes down to a reverse proxy in front, a backup of the file,
and a few alerts.

Before opening an instance to your users:

- [ ] TLS is terminated by a reverse proxy, and `NANOBOM_PUBLIC_URL` is its `https` address:
  [Reverse proxy and TLS](reverse-proxy.md).
- [ ] The proxy accepts SBOMs as large as `NANOBOM_MAXIMUM_SBOM_SIZE` and lets uploads wait
  `NANOBOM_UPLOAD_WAIT_SECONDS`.
- [ ] `NANOBOM_TRUST_FORWARDED_HEADERS=true`, so sign-in rate limiting sees client addresses.
- [ ] `/metrics` is scraped, and reachable only by your monitoring:
  [Monitoring](monitoring.md).
- [ ] An alert fires when the last successful run is too old, and `NANOBOM_FAILURE_WEBHOOK_URL`
  reaches the operators.
- [ ] The database is backed up daily, and a restore was tried once:
  [Backups and upgrades](maintenance.md).
- [ ] The instance can reach `api.osv.dev`, `www.cisa.gov` and `api.first.org`, or uses mirrors,
  or has exploitation data turned off.

[Security model](security.md) describes what protects what, for a review.
