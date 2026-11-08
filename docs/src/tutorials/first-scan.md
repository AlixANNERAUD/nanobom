# Your first scan

In this tutorial you run nanobom on your own machine, send it the SBOM of a small project, read
the vulnerabilities it finds, and set one of them aside with a reason. It takes about fifteen
minutes.

You need Docker with Compose, git, and curl. Port 8080 must be free.

## 1. Start nanobom

Clone the repository, which contains a ready `compose.yaml`, and start it:

```sh
git clone https://github.com/AlixANNERAUD/nanobom.git
cd nanobom
docker compose up -d --wait
```

The command returns once the container reports itself healthy. Check that nanobom answers:

```sh
curl http://localhost:8080/healthz
```

```json
{"status":"ok"}
```

## 2. Create the administrator

Nobody can sign in yet. Create an instance administrator named `admin`:

```sh
docker compose exec nanobom /app/nanobom create-administrator --username admin
```

Type a password of at least 12 characters and press Enter. It is shown as you type it.

Open <http://localhost:8080> and sign in as `admin` with that password. You land on
**Organizations**, which already lists one organization, `admin`: every new user gets a personal
one.

## 3. Create an organization and an upload token

Your CI will send SBOMs to an organization, with an upload token of that organization.

1. Under **New organization**, enter `Acme` as the name and `acme` as the slug, then **Create**.
2. Open **Acme**, then **Settings**.
3. Under **API tokens**, enter `tutorial` as the token name, leave the project on **Whole
   organization** and the scope on **Upload and read**, and **Create token**.
4. Copy the token: it starts with `nanobom_`, and it will not be shown again.

In the terminal, keep it in a variable for the next steps:

```sh
export NANOBOM_TOKEN=nanobom_…
```

## 4. Upload an SBOM

Real SBOMs come from your build. For this tutorial, write a small one by hand: a project that
depends on two old npm packages, `lodash` 4.17.20 and `minimist` 1.2.5.

```sh
cat > sbom.json <<'EOF'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20"
    },
    {
      "type": "library",
      "name": "minimist",
      "version": "1.2.5",
      "purl": "pkg:npm/minimist@1.2.5"
    }
  ]
}
EOF
```

The `purl` of each component, its package URL, is what nanobom looks up in OSV.

Send the file to a project named `demo`; the project does not exist yet, and this upload creates
it:

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "http://localhost:8080/api/organizations/acme/projects/demo/sbom?wait=true"
```

`wait=true` holds the request until nanobom has checked the project against OSV, which takes a
few seconds. The answer looks like this, shortened:

```json
{
  "organization": "acme",
  "project": "demo",
  "project_created": true,
  "component_count": 2,
  "components_without_purl": 0,
  "evaluation": {
    "status": "succeeded",
    "open": { "critical": 1, "high": 2, "medium": 2, "low": 0, "unknown": 0 },
    "known_exploited": 0,
    "findings": [ … ]
  }
}
```

Check three things: `project_created` is `true`, `component_count` is `2`, and
`evaluation.status` is `succeeded`. The counts in `open` depend on what OSV knows today; expect
at least a critical finding (minimist) and a high one (lodash). Each entry of `findings` names a
vulnerability, the component it affects, and the address of its page.

## 5. Read the findings

Open <http://localhost:8080/organizations/acme>. The project `demo` is listed with its open
findings by severity, how many are ignored or known exploited, and the time of its last
SBOM. Under **Recent runs**, the run your upload
started is listed as succeeded.

Open `demo`. Its findings are listed most urgent first: known exploited ones, then by severity.
Open the high finding of `lodash`. Its page shows:

- the vulnerability's description, and the version that fixes it under **Fixed in**;
- its **Aliases**: the same vulnerability under other identifiers, such as a CVE;
- its **References**: the advisories and fixes OSV links to;
- **Exploitation**: whether it is known to be exploited, and its EPSS score;
- **Also affected**: other components with the same vulnerability, here none;
- **History**: an **Opened** entry, from the run of your upload.

## 6. Ignore a finding

Suppose your team checked that the vulnerable `lodash` function is never called. Record that
decision on the finding's page, under **Triage**:

1. In **Reason**, write `Tutorial: the vulnerable function is not used.`
2. In **Ignore until**, pick a date a month from now.
3. Select **Ignore finding**.

The page says **Finding ignored.**, and **History** gains an **Ignored** entry with your name
and the reason. Back on the project page, the finding's status is now **Ignored**; the default
filter, **Open and ignored**, still lists it, and setting **Status** to **Open** hides it.

Upload the same SBOM again:

```sh
curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $NANOBOM_TOKEN" \
  --data-binary @sbom.json \
  "http://localhost:8080/api/organizations/acme/projects/demo/sbom?wait=true"
```

This time `project_created` is `false`, and `evaluation.open.high` is one lower than before:
ignored findings do not count. On the date you picked, the finding opens again by itself.

## 7. Clean up

To delete the instance and its data:

```sh
docker compose down --volumes
```

## What you learned

You started nanobom, created an organization and a token, uploaded an SBOM that created a
project, read its findings, and ignored one with a reason and an expiry date.

Next:

- [Gate a repository's CI](gate-ci.md): the same loop, driven by a GitHub repository.
- [Concepts](../explanation/concepts.md): what organizations, projects, runs and findings are.
- [Install nanobom](../how-to/install.md): a real deployment.
