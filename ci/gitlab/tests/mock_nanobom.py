"""A stand-in for nanobom's upload endpoint, answering by project name, for the template's tests.

Adapted from the tests of nanobom-action (https://github.com/AlixANNERAUD/nanobom-action).

Usage: python3 mock_nanobom.py PORT REQUESTS_LOG
Each request is appended to REQUESTS_LOG as a JSON line (path, query, headers, body size).
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

BASE = "http://localhost:{port}"


def finding(vulnerability, component, severity, exploited=False):
    return {
        "vulnerability": vulnerability,
        "component": component,
        "severity": severity,
        "known_exploited": exploited,
        "url": f"{BASE}/findings/{vulnerability}",
    }


def evaluation(status, open_counts, known_exploited, findings):
    keys = ("critical", "high", "medium", "low", "unknown")
    return {
        "status": status,
        "run_id": 7 if status != "timed_out" else None,
        "open": dict(zip(keys, open_counts)),
        "known_exploited": known_exploited,
        "findings": findings,
    }


def upload(project, created=False, without_purl=0):
    return {
        "organization": "acme",
        "project": project,
        "project_id": 1,
        "project_created": created,
        "version": "",
        "version_created": created,
        "upload_id": 3,
        "component_count": 42,
        "components_without_purl": without_purl,
        "skipped": [],
    }


RESPONSES = {
    "passing": (
        201,
        {
            **upload("passing", created=True),
            "evaluation": evaluation(
                "succeeded",
                (0, 0, 1, 0, 0),
                0,
                [finding("GHSA-medium", "pkg:npm/left-pad@1.0.0", "medium")],
            ),
        },
    ),
    # A server trying to add variables to the dotenv report, which later jobs load.
    "hostile": (
        201,
        {
            **upload("hostile"),
            "evaluation": {
                **evaluation("succeeded\nCI_REGISTRY=evil.example", (0, 0, 0, 0, 0), 0, []),
                "known_exploited": "1\nCI_JOB_TOKEN=stolen",
            },
        },
    ),
    "gated": (
        409,
        {
            **upload("gated"),
            "error": "2 open findings at or above high",
            "evaluation": evaluation(
                "succeeded",
                (1, 1, 1, 0, 0),
                1,
                [
                    finding("CVE-2021-44228", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "critical", True),
                    finding("GHSA-high", "pkg:npm/lodash@4.17.20", "high"),
                    finding("GHSA-medium", "pkg:npm/left-pad@1.0.0", "medium"),
                ],
            ),
        },
    ),
    "licensed": (
        409,
        {
            **upload("licensed"),
            "error": "1 component with a forbidden license",
            "evaluation": {
                **evaluation(
                    "succeeded",
                    (0, 1, 1, 0, 0),
                    0,
                    [
                        finding("GHSA-high", "pkg:npm/lodash@4.17.20", "high"),
                        finding("GHSA-medium", "pkg:npm/left-pad@1.0.0", "medium"),
                    ],
                ),
                "licenses": {
                    "forbidden": 1,
                    "warned": 1,
                    "violations": [
                        {
                            "component": "pkg:npm/copyleft@2.0.0",
                            "name": "copyleft",
                            "version": "2.0.0",
                            "license": "MIT AND AGPL-3.0-only",
                            "verdict": "forbid",
                            "licenses": ["AGPL-3.0-only"],
                        },
                        {
                            "component": "pkg:npm/mystery@1.0.0",
                            "name": "mystery",
                            "version": "1.0.0",
                            "license": None,
                            "verdict": "warn",
                            "licenses": [],
                        },
                    ],
                },
            },
        },
    ),
    "incomplete": (
        503,
        {
            **upload("incomplete"),
            "error": "the evaluation did not complete",
            "evaluation": evaluation("timed_out", (0, 0, 0, 0, 0), 0, []),
        },
    ),
    "plain": (200, upload("plain", without_purl=3)),
    "refused": (401, {"error": "a valid upload token is required in the Authorization header (Bearer)"}),
}


class Handler(BaseHTTPRequestHandler):
    def do_PUT(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        with open(self.server.log, "a", encoding="utf-8") as log:
            log.write(
                json.dumps(
                    {
                        "path": parts.path,
                        "query": {key: values[0] for key, values in parse_qs(parts.query).items()},
                        "authorization": self.headers.get("Authorization"),
                        "content_type": self.headers.get("Content-Type"),
                        "body_size": length,
                    }
                )
                + "\n"
            )
        segments = parts.path.strip("/").split("/")
        project = segments[4] if len(segments) == 6 else ""
        status, body = RESPONSES.get(project, (404, {"error": "not found"}))
        payload = json.dumps(body).replace("{port}", str(self.server.server_port)).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *arguments):
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
    server.log = sys.argv[2]
    server.serve_forever()
