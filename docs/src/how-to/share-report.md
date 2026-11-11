# Share a vulnerability report

This guide gives a customer, an auditor or a regulator a document describing the
vulnerabilities of a release: what nanobom checked, what is open, and what was assessed as not
affecting the product. What the report contains is in the
[reference](../reference/report.md).

## Print it from the interface

1. Open the project and, if the project has versions, choose the version in the filters.
2. Select **Report**. The report opens for the version shown.
3. Print the page from the browser (`Ctrl+P`, or `Cmd+P` on macOS), and choose **Save as PDF**
   as the printer to get a file.

The printout leaves out the interface around the report and always uses light colors. Before
sharing it, check the **Scope and provenance** section: a warning says when the project stopped
receiving SBOMs or when the version is no longer checked.

Ignored findings appear with their reason and justification. Write reasons for this audience:
the [triage guide](triage.md) explains how to ignore a finding with a justification.

## Archive it from CI

The same report is served as an HTML document under the API, so a release workflow can store
it next to the release's artifacts.

1. Create a token: in the organization's **Settings → API tokens**, choose the project and the
   **Read only** scope. An upload token of the project works too.
2. Store it as a secret of the repository (`NANOBOM_TOKEN`), and the address of nanobom as a
   variable (`NANOBOM_URL`).
3. After the upload of the release's SBOM, download the report of the release's version:

```yaml
      - name: Archive the vulnerability report
        env:
          NANOBOM_URL: ${{ vars.NANOBOM_URL }}
          NANOBOM_TOKEN: ${{ secrets.NANOBOM_TOKEN }}
          VERSION: ${{ github.ref_name }}
        run: |
          curl --fail-with-body --silent --show-error \
            --get --data-urlencode "version=$VERSION" \
            -H "Authorization: Bearer $NANOBOM_TOKEN" \
            -o vulnerability-report.html \
            "$NANOBOM_URL/api/organizations/acme/projects/web/report"
      - uses: actions/upload-artifact@v7.0.2
        with:
          name: vulnerability-report
          path: vulnerability-report.html
```

Replace `acme` and `web` with the organization and project slugs. Without `version`, the report
is about the latest version. Add `-H "Accept-Language: fr"` for a report in French. The file
opens in any browser, without access to nanobom, and prints like the page.

A `404` means the version has no SBOM in nanobom yet, or the token does not reach the project;
the [reference](../reference/report.md#endpoint) lists the statuses.

## Give the machine-readable form too

The report is the readable form of the project's VEX statements. Tools that read VEX get the
same assessments from the [VEX export](vex.md), whose address the report gives.
