# /// script
# requires-python = ">=3.10"
# dependencies = ["pyyaml>=6"]
# ///
"""Tests of the GitLab CI template ci/gitlab/nanobom.yml, without GitLab and without network.

The template is rendered as GitLab would: its inputs interpolated with their defaults or the
given values, then the job's variables expanded against a fake CI environment. The job's
script then runs against a mock nanobom (mock_nanobom.py), and the checks read its exit code,
its log, its dotenv report and the requests the mock received.

    uv run ci/gitlab/tests/test_template.py                   # run the tests
    uv run ci/gitlab/tests/test_template.py --extract out.sh  # write the script, for shellcheck

NANOBOM_TEST_SHELL picks the shell that runs the script (`sh` by default, `busybox sh` for the
shell of the template's Alpine image).
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import HTTPServer
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "nanobom.yml"
sys.path.insert(0, str(HERE))
import mock_nanobom  # noqa: E402

INPUT = re.compile(r"\$\[\[\s*inputs\.([A-Za-z0-9_-]+)\s*\]\]")
VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def load():
    """The template's spec and its body, as parsed YAML."""
    spec, body = yaml.safe_load_all(TEMPLATE.read_text(encoding="utf-8"))
    return spec, body


def interpolate(node, values):
    if isinstance(node, dict):
        return {interpolate(key, values): interpolate(value, values) for key, value in node.items()}
    if isinstance(node, list):
        return [interpolate(item, values) for item in node]
    if isinstance(node, str):
        return INPUT.sub(lambda match: str(values[match.group(1)]), node)
    return node


def render(inputs):
    """The job's name and definition once GitLab has interpolated `inputs`."""
    spec, body = load()
    values = {}
    for name, definition in spec["spec"]["inputs"].items():
        if name in inputs:
            values[name] = inputs[name]
        elif "default" in definition:
            values[name] = definition["default"]
        else:
            raise ValueError(f"the input {name} is required")
    unknown = set(inputs) - set(values)
    if unknown:
        raise ValueError(f"unknown inputs: {sorted(unknown)}")
    ((name, job),) = interpolate(body, values).items()
    return name, job


def expand(value, environment):
    """Expands $VAR and ${VAR} like the runner; an undefined variable stays as written, the
    least favorable case for the script."""

    def replace(match):
        variable = match.group(1) or match.group(2)
        return environment.get(variable, match.group(0))

    return VARIABLE.sub(replace, str(value))


def script(job):
    return "\n".join(job["script"])


class Mock:
    def __enter__(self):
        self.directory = Path(tempfile.mkdtemp())
        self.server = HTTPServer(("127.0.0.1", 0), mock_nanobom.Handler)
        self.server.log = str(self.directory / "requests.jsonl")
        Path(self.server.log).touch()
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        return self

    def __exit__(self, *arguments):
        self.server.shutdown()
        shutil.rmtree(self.directory)

    def requests(self):
        return [json.loads(line) for line in Path(self.server.log).read_text().splitlines()]


class Run:
    """One run of the job: `code`, `log`, `dotenv` (dict), `request` (the last one, or None)."""

    def __init__(self, mock, inputs=None, environment=None, syft=False):
        self.inputs = {"organization": "acme", "url": mock.url, **(inputs or {})}
        directory = Path(tempfile.mkdtemp())
        try:
            (directory / "sbom.json").write_text('{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}')
            if "sbom" not in self.inputs and not syft:
                self.inputs["sbom"] = "sbom.json"
            path = os.environ["PATH"]
            if syft:
                path = f"{self.stub_syft(directory)}:{path}"
            ci = {
                "PATH": path,
                "HOME": str(directory),
                "CI_PROJECT_NAME": "passing",
                "CI_COMMIT_SHA": "abc123",
                "NANOBOM_TOKEN": "nanobom_secret",
                **(environment or {}),
            }
            _, job = render(self.inputs)
            variables = {key: expand(value, ci) for key, value in job.get("variables", {}).items()}
            requests_before = len(mock.requests())
            shell = shlex.split(os.environ.get("NANOBOM_TEST_SHELL", "sh"))
            result = subprocess.run(
                [*shell, "-c", script(job)],
                cwd=directory,
                env={**ci, **variables},
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.code = result.returncode
            self.log = result.stdout + result.stderr
            dotenv = directory / "nanobom.env"
            self.dotenv = dict(line.split("=", 1) for line in dotenv.read_text().splitlines()) if dotenv.exists() else None
            requests = mock.requests()[requests_before:]
            self.request = requests[-1] if requests else None
            calls = directory / "syft-calls"
            self.syft_calls = calls.read_text().splitlines() if calls.exists() else []
        finally:
            shutil.rmtree(directory)

    @staticmethod
    def stub_syft(directory):
        """A syft on the PATH that records its arguments and registry credentials, and writes
        an empty SBOM where it is asked to."""
        bin_directory = directory / "bin"
        bin_directory.mkdir()
        stub = bin_directory / "syft"
        stub.write_text(
            "#!/bin/sh\n"
            f'echo "$* auth=${{SYFT_REGISTRY_AUTH_AUTHORITY:-}}:${{SYFT_REGISTRY_AUTH_USERNAME:-}}" >> "{directory}/syft-calls"\n'
            'for argument; do case "$argument" in cyclonedx-json=*) output="${argument#cyclonedx-json=}" ;; esac; done\n'
            'printf \'{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}\' > "$output"\n'
        )
        stub.chmod(0o755)
        return bin_directory

    def query(self, key):
        return self.request["query"].get(key) if self.request else None

    def after(self, marker):
        """The part of the log after `marker`, empty without it."""
        return self.log.split(marker, 1)[1] if marker in self.log else ""


failures = 0


def check(description, condition, run=None):
    global failures
    if condition:
        print(f"ok   {description}")
    else:
        failures += 1
        print(f"FAIL {description}")
        if run is not None:
            print("     log:\n" + "\n".join("       " + line for line in run.log.splitlines()))


def test_definition():
    spec, body = load()
    inputs = spec["spec"]["inputs"]
    text = TEMPLATE.read_text(encoding="utf-8").split("\n---\n", 1)[1]
    used = set(INPUT.findall(text))
    check("the template has a spec and one job", isinstance(body, dict) and len(body) == 1)
    check("every input used is declared", used <= set(inputs), None)
    check("every input declared is used", set(inputs) <= used)
    check("every input has a description", all(definition.get("description") for definition in inputs.values()))
    check("only the organization is required", [name for name, definition in inputs.items() if "default" not in definition] == ["organization"])
    name, job = render({"organization": "acme", "job-name": "sbom-web", "stage": "deploy"})
    check("the job name is an input", name == "sbom-web")
    check("the stage is an input", job["stage"] == "deploy")
    check("the dotenv report is kept even when the job fails", job["artifacts"] == {"when": "always", "reports": {"dotenv": "nanobom.env"}})
    check("the token is not an input", "token" not in inputs and "NANOBOM_TOKEN" in script(job))


def test_runs(mock):
    run = Run(mock)
    check("a passing upload succeeds", run.code == 0, run)
    check("it sends the token", run.request["authorization"] == "Bearer nanobom_secret")
    check("it sends JSON", run.request["content_type"] == "application/json")
    check("the project defaults to CI_PROJECT_NAME", run.request["path"] == "/api/organizations/acme/projects/passing/sbom")
    check("it asks to wait", run.query("wait") == "true")
    check("the commit defaults to CI_COMMIT_SHA", run.query("source_commit") == "abc123")
    check(
        "it sends no empty parameter, nor an undefined CI_COMMIT_TAG",
        not set(run.request["query"]) & {"image_tag", "fail_on", "version", "latest"},
        run,
    )
    check("reports the status", run.dotenv.get("NANOBOM_HTTP_STATUS") == "201", run)
    check("reports the evaluation", run.dotenv.get("NANOBOM_EVALUATION_STATUS") == "succeeded")
    check("reports the counts", run.dotenv.get("NANOBOM_MEDIUM") == "1" and run.dotenv.get("NANOBOM_CRITICAL") == "0")
    check("reports the project URL", run.dotenv.get("NANOBOM_PROJECT_URL") == f"{mock.url}organizations/acme/projects/passing")
    check("no license counts without a policy", "NANOBOM_FORBIDDEN_LICENSES" not in run.dotenv)
    check("logs the counts", "Open findings: 0 critical, 0 high, 1 medium, 0 low, 0 unknown; 0 known exploited" in run.log, run)
    check("logs the findings", re.search(r"medium +GHSA-medium +pkg:npm/left-pad@1\.0\.0 +http", run.log) is not None, run)
    check("logs in a collapsible section", "section_start:" in run.log and "nanobom_evaluation" in run.log)
    check("never logs the token", "nanobom_secret" not in run.log)

    run = Run(mock, environment={"NANOBOM_URL": mock.url}, inputs={"url": "$NANOBOM_URL"})
    check("the url defaults to the NANOBOM_URL variable", run.code == 0, run)
    run = Run(mock, inputs={"url": "$NANOBOM_URL"})
    check("an unset NANOBOM_URL fails clearly", run.code != 0 and "set the url input, or the NANOBOM_URL variable" in run.log, run)
    run = Run(mock, environment={"NANOBOM_TOKEN": ""})
    check("a missing token fails before uploading", run.code != 0 and run.request is None and "NANOBOM_TOKEN" in run.log, run)

    run = Run(mock, environment={"CI_COMMIT_TAG": "v1.2.0"})
    check("the image tag defaults to CI_COMMIT_TAG", run.query("image_tag") == "v1.2.0", run)
    run = Run(mock, inputs={"version": "2.4/rc+1", "latest": "false", "source-commit": "$CI_COMMIT_SHORT_SHA"}, environment={"CI_COMMIT_SHORT_SHA": "abc"})
    check("it sends the version", run.query("version") == "2.4/rc+1", run)
    check("it sends latest", run.query("latest") == "false")
    check("inputs may refer to variables", run.query("source_commit") == "abc")
    check("it logs the version", "version 2.4/rc+1" in run.log)
    run = Run(mock, inputs={"latest": "yes"})
    check("an invalid latest fails before uploading", run.code != 0 and run.request is None, run)

    run = Run(mock, {"project": "gated", "fail-on": " High "})
    over = run.after("Over the threshold")
    check("a gated upload fails", run.code != 0, run)
    check("it sends fail_on normalized", run.query("fail_on") == "high")
    check("it does not send wait with fail_on", "wait" not in run.request["query"])
    check("it reports the server's error", "ERROR: 2 open findings at or above high" in run.log, run)
    check("it lists the critical finding", re.search(r"critical +CVE-2021-44228 +pkg:maven/\S+ +known exploited", over) is not None, run)
    check("it lists the high finding", "GHSA-high" in over, run)
    check("it does not list the medium finding", "GHSA-medium" not in over, run)
    check("reports known exploited", run.dotenv.get("NANOBOM_KNOWN_EXPLOITED") == "1")
    check("reports the counts of a failed gate", run.dotenv.get("NANOBOM_HTTP_STATUS") == "409" and run.dotenv.get("NANOBOM_HIGH") == "1")

    run = Run(mock, {"project": "gated", "fail-on": "exploited"})
    over = run.after("Over the threshold")
    check("exploited lists the exploited finding", "CVE-2021-44228" in over, run)
    check("exploited does not list the others", "GHSA-high" not in over, run)

    run = Run(mock, {"project": "licensed", "fail-on": "High, License"})
    over = run.after("Over the threshold")
    check("a license gate fails", run.code != 0, run)
    check("it sends the list normalized", run.query("fail_on") == "high,license")
    check("the list lists the high finding", "GHSA-high" in over, run)
    check("the list does not list the medium finding", "GHSA-medium" not in over, run)
    check(
        "it lists the forbidden license",
        re.search(r"forbidden license +pkg:npm/copyleft@2\.0\.0 +MIT AND AGPL-3\.0-only +AGPL-3\.0-only", over) is not None,
        run,
    )
    check("it does not list a warned license", "mystery" not in over, run)
    check("reports the license counts", run.dotenv.get("NANOBOM_FORBIDDEN_LICENSES") == "1" and run.dotenv.get("NANOBOM_WARNED_LICENSES") == "1")
    check("logs the license policy", "License policy: 1 forbidden, 1 warned" in run.log, run)
    check("logs an unknown license", re.search(r"warn +pkg:npm/mystery@1\.0\.0 +unknown", run.log) is not None, run)

    run = Run(mock, {"project": "licensed", "fail-on": "license"})
    over = run.after("Over the threshold")
    check("license alone lists the license", "pkg:npm/copyleft" in over, run)
    check("license alone lists no finding", "GHSA-high" not in over, run)

    run = Run(mock, {"project": "gated", "fail-on": "critical,exploited"})
    over = run.after("Over the threshold")
    check("a severity and exploited list the exploited finding", "CVE-2021-44228" in over, run)
    check("they do not list below the threshold", "GHSA-high" not in over, run)

    run = Run(mock, {"project": "incomplete", "fail-on": "critical"})
    check("an incomplete evaluation fails", run.code != 0, run)
    check("it says why", "the evaluation did not complete" in run.log, run)
    check("reports timed_out", run.dotenv.get("NANOBOM_EVALUATION_STATUS") == "timed_out")

    run = Run(mock, {"project": "plain", "wait": "false"})
    check("an upload without wait succeeds", run.code == 0, run)
    check("it does not ask to wait", "wait" not in run.request["query"])
    check("it warns about components without package URL", "3 components have no package URL" in run.log, run)
    check("no evaluation in the report", "NANOBOM_EVALUATION_STATUS" not in run.dotenv and run.dotenv.get("NANOBOM_HTTP_STATUS") == "200")

    run = Run(mock, {"project": "refused"})
    check("a refused token fails", run.code != 0, run)
    check("it explains the refusal", "the upload token was refused (401)" in run.log, run)

    run = Run(mock, {"project": "missing"})
    check("an unknown project fails", run.code != 0, run)
    check("it names the project", "acme/missing (404)" in run.log, run)

    run = Run(mock, {"wait": "maybe"})
    check("an invalid wait fails before uploading", run.code != 0 and run.request is None, run)

    run = Run(mock, {"project": "My.Project"})
    check("the project URL is lower-cased", run.dotenv.get("NANOBOM_PROJECT_URL", "").endswith("/projects/my.project"), run)

    run = Run(mock, {"sbom": "absent.json"})
    check("a missing SBOM fails", run.code != 0 and "SBOM not found" in run.log, run)

    run = Run(mock, {"scan-path": "src"}, syft=True)
    check("without an sbom, Syft scans the directory", run.code == 0 and run.syft_calls and run.syft_calls[0].startswith("scan dir:src --quiet --output cyclonedx-json="), run)
    check("the generated SBOM is uploaded", run.request is not None and run.request["body_size"] > 0, run)

    run = Run(
        mock,
        {"scan-image": "registry.example.com/acme/web:1.0"},
        environment={"CI_REGISTRY": "registry.example.com", "CI_REGISTRY_USER": "gitlab-ci-token", "CI_REGISTRY_PASSWORD": "secret"},
        syft=True,
    )
    check("Syft scans the image", run.code == 0 and run.syft_calls and run.syft_calls[0].startswith("scan registry.example.com/acme/web:1.0 "), run)
    check("with the job's registry credentials", run.syft_calls and run.syft_calls[0].endswith("auth=registry.example.com:gitlab-ci-token"), run)

    run = Run(mock, {"scan-image": "docker.io/library/alpine:3.24"}, environment={"CI_REGISTRY": "registry.example.com"}, syft=True)
    check("but not for another registry", run.syft_calls and run.syft_calls[0].endswith("auth=:"), run)


def main():
    if sys.argv[1:2] == ["--extract"]:
        _, job = render({"organization": "acme"})
        Path(sys.argv[2]).write_text("#!/bin/sh\n" + script(job) + "\n")
        return
    test_definition()
    with Mock() as mock:
        test_runs(mock)
    if failures:
        print(f"{failures} check(s) failed")
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
