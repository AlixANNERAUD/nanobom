//! The MCP endpoint: the handshake, the tools and their answers, the reach of each token and
//! the requests that are refused. It shares the read API's setup: `acme` (`web`, `api`) and
//! `globex` (`web`), each project with a lodash (high, known exploited) and a minimist
//! (critical) finding.

use std::collections::BTreeSet;

use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use chrono::Utc;
use nanobom_domain::{findings, projects, testing};
use nanobom_entity::{findings as findings_entity, vulnerabilities};
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::{Value, json};

use crate::{
    common::{TestServer, body_json, body_text},
    read_api::{Setup, setup},
};

const PROTOCOL: &str = "2025-06-18";

/// The credentials a request carries.
#[derive(Clone, Copy)]
enum Credentials<'a> {
    None,
    Bearer(&'a str),
    ApiKey(&'a str),
    Cookie(&'a str),
}

fn request(credentials: Credentials<'_>) -> axum::http::request::Builder {
    let builder = Request::post("/mcp")
        .header(header::HOST, "localhost:8080")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", PROTOCOL);
    match credentials {
        Credentials::None => builder,
        Credentials::Bearer(token) => {
            builder.header(header::AUTHORIZATION, format!("Bearer {token}"))
        }
        Credentials::ApiKey(token) => builder.header("X-Api-Key", token),
        Credentials::Cookie(cookie) => builder.header(header::COOKIE, cookie),
    }
}

async fn post(server: &TestServer, credentials: Credentials<'_>, body: Value) -> Response<Body> {
    server
        .send(
            request(credentials)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
}

/// A JSON-RPC request, expecting `200` and returning its `result`.
async fn rpc(server: &TestServer, token: &str, method: &str, params: Value) -> Value {
    let response = post(
        server,
        Credentials::Bearer(token),
        json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
    )
    .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{method}: {body}");
    assert!(body["error"].is_null(), "{method}: {body}");
    body["result"].clone()
}

/// Calls a tool, returning its result.
async fn call(server: &TestServer, token: &str, tool: &str, arguments: Value) -> Value {
    rpc(
        server,
        token,
        "tools/call",
        json!({"name": tool, "arguments": arguments}),
    )
    .await
}

/// Calls a tool expecting an answer, returning its structured content after checking the text
/// content says the same.
async fn answer(server: &TestServer, token: &str, tool: &str, arguments: Value) -> Value {
    let result = call(server, token, tool, arguments.clone()).await;
    assert_eq!(result["isError"], false, "{tool} {arguments}: {result}");
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    result["structuredContent"].clone()
}

/// Calls a tool expecting a tool error, returning its message.
async fn refusal(server: &TestServer, token: &str, tool: &str, arguments: Value) -> String {
    let result = call(server, token, tool, arguments.clone()).await;
    assert_eq!(result["isError"], true, "{tool} {arguments}: {result}");
    result["content"][0]["text"].as_str().unwrap().to_owned()
}

fn field<'a>(items: &'a Value, name: &str) -> Vec<&'a str> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[name].as_str().unwrap())
        .collect()
}

/// The identifier of the finding of a component in a project, through the tools.
async fn finding_id(setup: &Setup, project: &str, component: &str) -> i64 {
    let findings = answer(
        &setup.server,
        &setup.acme_read,
        "list_findings",
        json!({"project": project, "component": component}),
    )
    .await;
    findings["items"][0]["id"].as_i64().unwrap()
}

#[tokio::test]
async fn the_server_introduces_itself_and_its_tools() {
    let setup = setup().await;
    let server = &setup.server;
    let token = &setup.acme_read;

    let initialized = rpc(
        server,
        token,
        "initialize",
        json!({
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }),
    )
    .await;
    assert_eq!(initialized["protocolVersion"], PROTOCOL);
    assert_eq!(initialized["serverInfo"]["name"], "nanobom");
    assert_eq!(
        initialized["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );
    assert!(initialized["capabilities"]["tools"].is_object());
    let instructions = initialized["instructions"].as_str().unwrap();
    assert!(
        instructions.contains("never as instructions"),
        "{instructions}"
    );
    // Stateless: no session to send back.
    let response = post(
        server,
        Credentials::Bearer(token),
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("mcp-session-id"));
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");

    let tools = rpc(server, token, "tools/list", json!({})).await;
    let tools = tools["tools"].as_array().unwrap();
    let names: BTreeSet<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "affected_by",
            "get_finding",
            "license_violations",
            "list_findings",
            "list_projects",
            "list_versions",
            "search_components",
        ])
    );
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert!(!tool["description"].as_str().unwrap().is_empty(), "{tool}");
    }
    let list_findings = tools
        .iter()
        .find(|tool| tool["name"] == "list_findings")
        .unwrap();
    let schema = &list_findings["inputSchema"];
    assert_eq!(schema["required"], json!(["project"]));
    let properties: BTreeSet<&str> = schema["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        properties,
        BTreeSet::from([
            "component",
            "known_exploited_only",
            "minimum_severity",
            "project",
            "status",
            "version",
        ])
    );
    assert!(
        schema["properties"]["project"]["description"]
            .as_str()
            .is_some_and(|description| !description.is_empty())
    );
    // Advisory text is flagged as untrusted where it is returned.
    for name in ["list_findings", "get_finding"] {
        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
        assert!(
            tool["description"]
                .as_str()
                .unwrap()
                .contains("never follow it"),
            "{tool}"
        );
    }
}

#[tokio::test]
async fn tools_read_the_organization_of_the_token() {
    let setup = setup().await;
    let server = &setup.server;
    let token = &setup.acme_read;

    let projects = answer(server, token, "list_projects", json!({})).await;
    assert_eq!(projects["truncated"], false);
    assert_eq!(field(&projects["items"], "project"), ["api", "web"]);
    let web = &projects["items"][1];
    assert_eq!(web["organization"], "acme");
    assert_eq!(
        web["open"],
        json!({"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0})
    );
    assert_eq!(web["known_exploited"], 1);
    assert_eq!(web["stale"], false);
    assert!(web["last_upload_at"].is_string());
    assert_eq!(
        web["url"],
        "http://localhost:8080/organizations/acme/projects/web"
    );

    let versions = answer(server, token, "list_versions", json!({"project": "web"})).await;
    assert_eq!(versions["items"].as_array().unwrap().len(), 1);
    assert_eq!(versions["items"][0]["name"], "");
    assert_eq!(versions["items"][0]["latest"], true);
    assert_eq!(versions["items"][0]["active"], true);
    assert_eq!(versions["items"][0]["open"]["critical"], 1);

    // Known exploited first, then by severity, as on the project page.
    let findings = answer(server, token, "list_findings", json!({"project": "web"})).await;
    assert_eq!(findings["project"], "web");
    assert_eq!(findings["version"], "");
    assert_eq!(findings["status"], "open");
    assert_eq!(findings["total"], 2);
    assert_eq!(findings["truncated"], false);
    let lodash = &findings["items"][0];
    assert_eq!(lodash["vulnerability_id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(lodash["aliases"], json!(["CVE-2021-23337"]));
    assert_eq!(lodash["severity"], "high");
    assert_eq!(lodash["known_exploited"], true);
    assert_eq!(lodash["component"]["name"], "lodash");
    assert_eq!(lodash["component"]["version"], "4.17.20");
    assert_eq!(lodash["advisory_summary"], "Command Injection in lodash");
    assert!(lodash["ignore"].is_null());
    assert_eq!(
        field(&findings["items"], "vulnerability_id")[1],
        "GHSA-xvch-5gv4-984h"
    );
    for (arguments, expected) in [
        (
            json!({"minimum_severity": "critical"}),
            vec!["GHSA-xvch-5gv4-984h"],
        ),
        (
            json!({"minimum_severity": "high"}),
            vec!["GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"],
        ),
        (
            json!({"known_exploited_only": true}),
            vec!["GHSA-35jh-r3h4-6jhm"],
        ),
        (json!({"component": "MINI"}), vec!["GHSA-xvch-5gv4-984h"]),
        (json!({"status": "fixed"}), vec![]),
        (
            json!({"version": ""}),
            vec!["GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"],
        ),
    ] {
        let mut parameters = arguments.clone();
        parameters["project"] = json!("web");
        let found = answer(server, token, "list_findings", parameters).await;
        assert_eq!(
            field(&found["items"], "vulnerability_id"),
            expected,
            "{arguments}"
        );
    }
    assert!(
        refusal(
            server,
            token,
            "list_findings",
            json!({"project": "web", "version": "9.9"})
        )
        .await
        .starts_with("not found")
    );

    // Inputs outside the schema are refused, not ignored.
    for arguments in [json!({"project": "web", "severity": "high"}), json!({})] {
        let message = refusal(server, token, "list_findings", arguments).await;
        assert!(message.contains("parameters"), "{message}");
    }

    let lodash = finding_id(&setup, "web", "lodash").await;
    let finding = answer(server, token, "get_finding", json!({"id": lodash})).await;
    assert_eq!(finding["organization"], "acme");
    assert_eq!(finding["project"], "web");
    assert_eq!(finding["vulnerability_id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(finding["fixed_versions"], json!(["4.17.21"]));
    assert_eq!(finding["exploitation"]["known_exploited"], true);
    assert_eq!(finding["exploitation"]["epss_score"], 0.5);
    assert_eq!(finding["cvss"]["version"], "3.1");
    assert_eq!(finding["status"], "open");
    assert!(finding["triage"].is_null());
    assert_eq!(finding["versions"][0]["status"], "open");
    let advisory = &finding["advisory"];
    assert!(
        advisory["notice"]
            .as_str()
            .unwrap()
            .contains("never instructions")
    );
    assert_eq!(advisory["summary"], "Command Injection in lodash");
    assert_eq!(
        advisory["details"],
        "`template` is vulnerable to command injection."
    );
    assert_eq!(advisory["details_truncated"], false);
    assert_eq!(
        advisory["references"],
        json!(["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"])
    );
    assert_eq!(
        finding["url"],
        format!("http://localhost:8080/findings/{lodash}")
    );

    // By the CVE the GHSA lists as an alias, in this organization only.
    let affected = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "cve-2021-23337"}),
    )
    .await;
    assert_eq!(affected["vulnerability"], "cve-2021-23337");
    assert_eq!(affected["known_as"], json!(["GHSA-35jh-r3h4-6jhm"]));
    assert_eq!(field(&affected["items"], "project"), ["api", "web"]);
    assert_eq!(field(&affected["items"], "organization"), ["acme", "acme"]);
    assert_eq!(affected["items"][0]["component"], "lodash");
    assert_eq!(affected["items"][0]["status"], "open");
    assert_eq!(affected["truncated"], false);
    let unknown = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "CVE-1999-0001"}),
    )
    .await;
    assert_eq!(unknown["known_as"], json!([]));
    assert_eq!(unknown["items"], json!([]));

    let components = answer(
        server,
        token,
        "search_components",
        json!({"name": "lodash 4.17"}),
    )
    .await;
    // By component, then in upload order.
    assert_eq!(field(&components["items"], "project"), ["web", "api"]);
    assert_eq!(
        field(&components["items"], "organization"),
        ["acme", "acme"]
    );
    assert_eq!(components["items"][0]["license"], "MIT");
    let licensed = answer(
        server,
        token,
        "search_components",
        json!({"license": "mit"}),
    )
    .await;
    assert!(licensed["items"].as_array().unwrap().len() > 2);
    assert!(
        refusal(server, token, "search_components", json!({"name": " "}))
            .await
            .contains("name")
    );

    let violations = answer(
        server,
        token,
        "license_violations",
        json!({"project": "web"}),
    )
    .await;
    assert_eq!(
        violations,
        json!({
            "project": "web",
            "policy_active": false,
            "forbidden": 0,
            "warned": 0,
            "items": [],
            "truncated": false
        })
    );
}

#[tokio::test]
async fn license_violations_follow_the_policy() {
    use nanobom_domain::{
        licenses::{self, Action, Policy},
        organizations,
    };
    let setup = setup().await;
    let server = &setup.server;
    let acme = organizations::find(&server.database, &setup.alice, "acme")
        .await
        .unwrap();
    // Every component of the npm fixture is MIT, which this policy does not list.
    licenses::set_policy(
        &server.database,
        &setup.alice,
        acme.id,
        &Policy {
            unlisted: Action::Forbid,
            unknown: Action::Warn,
            rules: Vec::new(),
        },
    )
    .await
    .unwrap();
    let violations = answer(
        server,
        &setup.acme_read,
        "license_violations",
        json!({"project": "web"}),
    )
    .await;
    assert_eq!(violations["policy_active"], true);
    let forbidden = violations["forbidden"].as_u64().unwrap();
    assert!(forbidden > 0);
    assert_eq!(
        violations["items"].as_array().unwrap().len() as u64,
        forbidden
    );
    assert_eq!(violations["items"][0]["verdict"], "forbid");
    assert_eq!(violations["items"][0]["licenses"], json!(["MIT"]));
}

#[tokio::test]
async fn ignored_findings_are_not_listed_as_open() {
    let setup = setup().await;
    let server = &setup.server;
    let token = &setup.acme_read;
    let minimist = finding_id(&setup, "web", "minimist").await;
    findings::ignore(
        &server.database,
        &setup.alice,
        minimist,
        "only used by the build",
        Some(findings::Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();

    let open = answer(server, token, "list_findings", json!({"project": "web"})).await;
    assert_eq!(
        field(&open["items"], "vulnerability_id"),
        ["GHSA-35jh-r3h4-6jhm"]
    );
    let ignored = answer(
        server,
        token,
        "list_findings",
        json!({"project": "web", "status": "ignored"}),
    )
    .await;
    assert_eq!(
        field(&ignored["items"], "vulnerability_id"),
        ["GHSA-xvch-5gv4-984h"]
    );
    assert_eq!(
        ignored["items"][0]["ignore"],
        json!({
            "reason": "only used by the build",
            "justification": "code_not_reachable",
            "expires_at": null
        })
    );
    let finding = answer(server, token, "get_finding", json!({"id": minimist})).await;
    assert_eq!(finding["status"], "ignored");
    assert_eq!(finding["triage"]["reason"], "only used by the build");
    assert_eq!(finding["triage"]["ignored_by"], "alice");

    let projects = answer(server, token, "list_projects", json!({})).await;
    assert_eq!(projects["items"][1]["open"]["critical"], 0);
    assert_eq!(projects["items"][1]["ignored"], 1);

    let open = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "CVE-2021-44906"}),
    )
    .await;
    assert_eq!(field(&open["items"], "project"), ["api"]);
    let any = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "CVE-2021-44906", "any_status": true}),
    )
    .await;
    assert_eq!(field(&any["items"], "project"), ["api", "web"]);
    assert_eq!(field(&any["items"], "status"), ["open", "ignored"]);
}

#[tokio::test]
async fn tokens_read_only_what_they_reach() {
    let setup = setup().await;
    let server = &setup.server;
    let api_lodash = finding_id(&setup, "api", "lodash").await;
    let web_lodash = finding_id(&setup, "web", "lodash").await;

    // A project token: its project only, the others are not found.
    let token = &setup.acme_web_read;
    let projects = answer(server, token, "list_projects", json!({})).await;
    assert_eq!(field(&projects["items"], "project"), ["web"]);
    answer(server, token, "list_findings", json!({"project": "web"})).await;
    for (tool, arguments) in [
        ("list_findings", json!({"project": "api"})),
        ("list_versions", json!({"project": "api"})),
        ("license_violations", json!({"project": "api"})),
        ("get_finding", json!({"id": api_lodash})),
    ] {
        let message = refusal(server, token, tool, arguments.clone()).await;
        assert!(
            message.starts_with("not found"),
            "{tool} {arguments}: {message}"
        );
    }
    let affected = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "CVE-2021-23337"}),
    )
    .await;
    assert_eq!(field(&affected["items"], "project"), ["web"]);
    let components = answer(
        server,
        token,
        "search_components",
        json!({"name": "lodash"}),
    )
    .await;
    assert_eq!(field(&components["items"], "project"), ["web"]);

    // Upload tokens read too, as on the read API.
    let projects = answer(server, &setup.acme_upload, "list_projects", json!({})).await;
    assert_eq!(field(&projects["items"], "project"), ["api", "web"]);
    let projects = answer(server, &setup.acme_web_upload, "list_projects", json!({})).await;
    assert_eq!(field(&projects["items"], "project"), ["web"]);

    // Another organization's token: its own `web`, never acme's data.
    let token = &setup.globex_read;
    let projects = answer(server, token, "list_projects", json!({})).await;
    assert_eq!(field(&projects["items"], "organization"), ["globex"]);
    let message = refusal(server, token, "get_finding", json!({"id": web_lodash})).await;
    assert!(message.starts_with("not found"), "{message}");
    let message = refusal(server, token, "list_findings", json!({"project": "api"})).await;
    assert!(message.starts_with("not found"), "{message}");
    let affected = answer(
        server,
        token,
        "affected_by",
        json!({"vulnerability": "CVE-2021-23337"}),
    )
    .await;
    assert_eq!(field(&affected["items"], "organization"), ["globex"]);
    let components = answer(
        server,
        token,
        "search_components",
        json!({"name": "lodash"}),
    )
    .await;
    assert_eq!(field(&components["items"], "organization"), ["globex"]);
    // A finding of globex's own `web` reads fine.
    let own = answer(server, token, "list_findings", json!({"project": "web"})).await;
    let own_id = own["items"][0]["id"].as_i64().unwrap();
    assert_ne!(own_id, web_lodash);
    answer(server, token, "get_finding", json!({"id": own_id})).await;
}

#[tokio::test]
async fn requests_without_a_valid_token_are_refused() {
    let setup = setup().await;
    let server = &setup.server;
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    for credentials in [
        Credentials::None,
        Credentials::Bearer("nanobom_invalid"),
        Credentials::ApiKey("nanobom_invalid"),
        // The session of a signed-in user authenticates nothing here.
        Credentials::Cookie(&setup.cookie),
    ] {
        let response = post(server, credentials, list.clone()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        let body = body_json(response).await;
        assert!(body["error"].is_string(), "{body}");
    }
    // `X-Api-Key` works as on the read API.
    let response = post(server, Credentials::ApiKey(&setup.acme_read), list.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);

    // A browser's request, even with a token, and the transport's stream are refused.
    let response = server
        .send(
            request(Credentials::Bearer(&setup.acme_read))
                .header(header::ORIGIN, "https://attacker.example")
                .body(Body::from(list.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
    );
    let response = server
        .send(
            Request::get("/mcp")
                .header(header::HOST, "localhost:8080")
                .header(header::ACCEPT, "text/event-stream")
                .header(header::AUTHORIZATION, format!("Bearer {}", setup.acme_read))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    // Notifications get no answer; clients must accept both JSON and event streams.
    let response = post(
        server,
        Credentials::Bearer(&setup.acme_read),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let response = server
        .send(
            Request::post("/mcp")
                .header(header::HOST, "localhost:8080")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", setup.acme_read))
                .body(Body::from(list.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);

    // Bodies beyond the limit are refused before anything runs.
    let large = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "search_components", "arguments": {"name": "x".repeat(100_000)}}
    });
    let response = post(server, Credentials::Bearer(&setup.acme_read), large).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let _ = body_text(response).await;
}

/// Open findings on many components of a project's latest version.
async fn many_findings(setup: &Setup, project: &str, count: usize) {
    let database = &setup.server.database;
    let acme = nanobom_domain::organizations::find(database, &setup.alice, "acme")
        .await
        .unwrap();
    let project = projects::find(database, &setup.alice, acme.id, project)
        .await
        .unwrap();
    let version = testing::latest_version(database, project.id).await;
    for index in 0..count {
        let id = format!("GHSA-test-{index:04}");
        vulnerabilities::ActiveModel {
            id: Set(id.clone()),
            modified: Set(Utc::now().fixed_offset()),
            aliases: Set("[]".to_owned()),
            severity: Set("low".to_owned()),
            record: Set("{}".to_owned()),
            fetched_at: Set(Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(database)
        .await
        .unwrap();
        findings_entity::ActiveModel {
            project_id: Set(project.id),
            version_id: Set(Some(version)),
            purl: Set(format!("pkg:npm/package-{index:04}@1.0.0")),
            ecosystem: Set("npm".to_owned()),
            vulnerability_id: Set(id),
            status: Set("open".to_owned()),
            severity: Set("low".to_owned()),
            first_seen_at: Set(Utc::now().fixed_offset()),
            last_seen_at: Set(Utc::now().fixed_offset()),
            ..Default::default()
        }
        .insert(database)
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn long_lists_are_cut_and_say_so() {
    let setup = setup().await;
    let server = &setup.server;
    many_findings(&setup, "web", 120).await;

    let findings = answer(
        server,
        &setup.acme_read,
        "list_findings",
        json!({"project": "web"}),
    )
    .await;
    assert_eq!(findings["total"], 122);
    assert_eq!(findings["items"].as_array().unwrap().len(), 100);
    assert_eq!(findings["truncated"], true);
    // The most urgent come first.
    assert_eq!(
        findings["items"][0]["vulnerability_id"],
        "GHSA-35jh-r3h4-6jhm"
    );

    let filtered = answer(
        server,
        &setup.acme_read,
        "list_findings",
        json!({"project": "web", "minimum_severity": "medium"}),
    )
    .await;
    assert_eq!(filtered["total"], 2);
    assert_eq!(filtered["truncated"], false);
}

#[tokio::test]
async fn arguments_outside_a_tool_schema_are_tool_errors() {
    let setup = setup().await;
    let server = &setup.server;
    for arguments in [
        json!({"project": "web", "unknown": true}),
        json!({}),
        json!({"project": "web", "status": "maybe"}),
    ] {
        let response = post(
            server,
            Credentials::Bearer(&setup.acme_read),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_findings", "arguments": arguments},
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        // A result the assistant can read and correct, not a protocol error.
        assert_eq!(body["result"]["isError"], true, "{arguments}: {body}");
        let message = body["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            message.starts_with("failed to deserialize parameters"),
            "{arguments}: {message}"
        );
    }
}
