# Run without internet access

nanobom makes outbound requests to three services: OSV during runs, and CISA and FIRST for
exploitation data after runs. On an instance behind a firewall or an outbound proxy, allow them,
point nanobom at mirrors, or turn exploitation data off. The settings are in the
[configuration reference](../reference/configuration.md#runs).

| Service | Setting | Default |
| --- | --- | --- |
| OSV | `NANOBOM_OSV_URL` | `https://api.osv.dev/` |
| CISA KEV | `NANOBOM_KEV_URL` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| FIRST EPSS | `NANOBOM_EPSS_URL` | `https://api.first.org/data/v1/epss` |

## Use an OSV mirror

OSV is needed for runs: an instance that cannot reach `api.osv.dev` needs an OSV-compatible
mirror. Point `NANOBOM_OSV_URL` at it; it must offer `/v1/querybatch` and `/v1/vulns/{id}`.

```sh
NANOBOM_OSV_URL=https://osv-mirror.internal/
```

## Use exploitation data mirrors

Point `NANOBOM_KEV_URL` and `NANOBOM_EPSS_URL` at them: the KEV mirror must serve the catalog's
JSON as is, and the EPSS mirror must answer `GET <url>?cve=CVE-…,CVE-…` like FIRST's API.

## Turn exploitation data off

Without access to either service, set:

```sh
NANOBOM_EXPLOITATION_DATA=false
```

Nothing is downloaded, no finding becomes known exploited, and uploads with `fail_on=exploited`
are refused with a `422`, since that gate could never fail. Data downloaded before the setting was
changed stays in the database as it was, without updates.

## Check

After the next run, **Recent runs** on an organization page shows it as succeeded. A run that
cannot reach OSV fails and changes no finding; failed exploitation downloads are logged as
`refreshing exploitation data failed` and counted by
`nanobom_exploitation_refresh_failures_total`.
