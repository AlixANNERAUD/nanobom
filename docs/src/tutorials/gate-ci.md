# Gate a repository's CI

In this tutorial you connect a GitHub repository to nanobom: every push uploads its SBOM, the job
shows the project's vulnerabilities, and the job fails when one of them is high or critical. You
then make it pass again, once by upgrading the dependency and once by triaging the finding.

You need:

- a nanobom instance that GitHub's runners can reach over the internet (an instance on
  `localhost`, as in [Your first scan](first-scan.md), is not reachable from them);
- an organization on it, here `acme`, where you are an admin or an owner (see step 3 of
  [Your first scan](first-scan.md#3-create-an-organization-and-a-project));
- a GitHub account, git, and npm.

## 1. Create a small project

The project depends on an old version of `lodash` with a known high-severity vulnerability:

```sh
mkdir nanobom-gate && cd nanobom-gate
git init -b main
npm init -y
npm install --save-exact lodash@4.17.20
echo node_modules > .gitignore
git add . && git commit -m "Depend on lodash"
```

Create an empty repository named `nanobom-gate` on GitHub, then push to it:

```sh
git remote add origin https://github.com/<you>/nanobom-gate.git
git push -u origin main
```

## 2. Give the repository the token and the address

In nanobom, open `acme`, and under **New project** enter `nanobom-gate`, the repository's name,
as the slug, then **Create project**. The project page that opens shows its **Upload token**.

In the repository on GitHub, open **Settings → Secrets and variables → Actions**:

1. On the **Secrets** tab, add a repository secret `NANOBOM_TOKEN` with the project's upload
   token.
2. On the **Variables** tab, add a repository variable `NANOBOM_URL` with the instance's address,
   such as `https://nanobom.example.org`.

## 3. Upload on every push

Add `.github/workflows/sbom.yml`:

```yaml
name: SBOM

on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7.0.1
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
```

Commit and push it:

```sh
git add .github && git commit -m "Upload the SBOM to nanobom" && git push
```

Open the repository's **Actions** tab and the run of this commit. The job succeeds. The action
generated an SBOM of the checkout with Syft (it reads `package-lock.json`), uploaded it, and
waited for nanobom to check it. The run's summary page shows the result: a link to the project,
the number of components uploaded, the evaluation's status, the open findings by severity, and a
table of those findings, each linked to its page.

In nanobom, the project `nanobom-gate`, which the action names after the repository, now has the
findings of `lodash` 4.17.20.

## 4. Make the job fail

Ask the action to fail when an open finding is high or critical, with `fail-on`:

```yaml
      - uses: AlixANNERAUD/nanobom-action@v1
        with:
          url: ${{ vars.NANOBOM_URL }}
          token: ${{ secrets.NANOBOM_TOKEN }}
          organization: acme
          fail-on: high
```

```sh
git commit -am "Fail on high vulnerabilities" && git push
```

This run fails. The job is annotated with each finding that crosses the threshold, among them
the high finding of `pkg:npm/lodash@4.17.20`, with a link to its page in nanobom. The upload
itself was recorded: nanobom answered `409`, the status of a gate that failed, after storing
the SBOM.

## 5. Fix it by upgrading

Upgrade `lodash` to its latest version, which fixes the vulnerability:

```sh
npm install --save-exact lodash@latest
git commit -am "Upgrade lodash" && git push
```

The run passes. In nanobom, the findings of `lodash` 4.17.20 are now **Fixed**, since that
component left the SBOM.

## 6. Or triage it

Upgrading is not always possible right away. Go back to the vulnerable version to see the other
way out:

```sh
npm install --save-exact lodash@4.17.20
git commit -am "Back to lodash 4.17.20" && git push
```

The run fails again, and the finding is reopened. Open it in nanobom from the job's annotation,
and under **Triage**, ignore it with a reason (`Tutorial: the template function is not used.`)
and an **Ignore until** date a month from now.

On GitHub, open the failed run and select **Re-run jobs**. The run passes: ignored findings do not
count. When the date passes, the finding opens again and the next push fails, unless the
dependency was upgraded by then.

## What you learned

You added the nanobom action to a repository, read its result in the job summary, turned it into
a gate with `fail-on`, and made the gate pass both by fixing the dependency and by triaging the
finding.

Next:

- [Upload from CI](../how-to/upload-from-ci.md): the action's options, GitLab CI, and any other
  CI with curl.
- [Fail CI on vulnerabilities](../how-to/fail-ci.md): what to know before gating real
  pipelines.
- [How findings are kept up to date](../explanation/findings.md): why a gate can fail without a
  code change.
