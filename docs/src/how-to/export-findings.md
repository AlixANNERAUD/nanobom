# Export findings to a spreadsheet

This guide writes the open findings of every project of an organization to a CSV file, which
any spreadsheet opens, with the [read API](../reference/read-api.md), `curl` and `jq`.

## Create a read token

A read token reads everything its organization holds and changes nothing, so it is the token to
give a script ([Tokens and scopes](../explanation/tokens.md)).

1. In the organization's **Settings → API tokens**, name the token (`spreadsheet export`), keep
   **Whole organization** as project, choose **Read only** as scope, and select
   **Create token**.
2. Copy the token: it is shown once.

From the command line, on the server:

```sh
nanobom token create --organization acme --name "spreadsheet export" --scope read
```

Store it in an environment variable for the steps below:

```sh
export NANOBOM_URL=https://nanobom.example.com
export NANOBOM_TOKEN=nanobom_…
```

## Check the token

```sh
curl -fsS -H "Authorization: Bearer $NANOBOM_TOKEN" "$NANOBOM_URL/api/organizations" | jq
```

The answer lists the token's organization, with the role `viewer`. A `401` means the token is
wrong or revoked.

## Write the CSV file

Save this script as `export-findings.sh`:

```sh
#!/bin/sh
# Writes the open findings of every project of an organization as CSV.
set -eu
organization=$1
api() {
  curl -fsS -H "Authorization: Bearer $NANOBOM_TOKEN" "$NANOBOM_URL/api/$1"
}

echo 'project,vulnerability,aliases,severity,known exploited,EPSS,component,version,introduced via,first seen,link'
for project in $(api "organizations/$organization/projects" | jq -r '.items[].slug'); do
  offset=0
  while :; do
    page=$(api "organizations/$organization/projects/$project/findings?status=open&limit=500&offset=$offset")
    echo "$page" | jq -r '.items[] | [
        .project,
        .vulnerability_id,
        (.aliases | join(" ")),
        .severity,
        .exploitation.known_exploited,
        (.exploitation.epss_score // ""),
        .component.name,
        (.component.version // ""),
        ([.introduced_via[].name] | join(" ")),
        .first_seen_at,
        .url
      ] | @csv'
    offset=$((offset + 500))
    [ "$offset" -lt "$(echo "$page" | jq .total)" ] || break
  done
done
```

Run it:

```sh
sh export-findings.sh acme > findings.csv
```

Each project's findings come in the project page's order: known exploited first, then by
severity and EPSS score.

## Adjust the selection

Change the query of the findings request:

| To export | Query |
| --- | --- |
| Open and ignored findings, as the project page shows them | remove `status=open` |
| Critical and high findings only | add `&severity=critical,high` |
| Known exploited findings only | add `&exploited=true` |
| Every finding, fixed ones included | `status=all` |

The [reference](../reference/read-api.md#findings) lists every field of a finding, such as the
ignore reason and justification, to add as columns.

## Run it on a schedule

The script only reads, so it can run as often as needed, for example nightly after the scheduled
run, from cron or a CI schedule. Keep the token in the scheduler's secrets, and revoke it in
**Settings → API tokens** when the export is no longer needed.
