//! The read API: shapes against the OpenAPI description, filters, pagination, isolation
//! between organizations and projects, token scopes and session access.

use std::collections::BTreeSet;

use crate::common::{TestServer, body_json, local_user, sbom_document, server};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use base64::Engine;
use nanobom::read_api::{OPENAPI, PATHS};
use nanobom_domain::{
    access::Actor,
    findings::{self, Justification},
    organizations,
    tokens::{self, Scope},
};
use nanobom_entity::{exploitation, projects};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, EntityTrait, PaginatorTrait};
use serde_json::{Value, json};

const PASSWORD: &str = "correct horse battery staple";
const ORIGIN: &str = "http://localhost:8080";
const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";

/// How a request authenticates.
#[derive(Clone, Copy)]
enum Caller<'a> {
    Anonymous,
    Bearer(&'a str),
    ApiKey(&'a str),
    Session(&'a str),
}

fn request(method: &str, path: &str, caller: Caller<'_>, body: Body) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(path);
    request = match caller {
        Caller::Anonymous => request,
        Caller::Bearer(token) => request.header(header::AUTHORIZATION, format!("Bearer {token}")),
        Caller::ApiKey(token) => request.header("X-Api-Key", token),
        Caller::Session(cookie) => request.header(header::COOKIE, cookie),
    };
    request.body(body).unwrap()
}

async fn get(server: &TestServer, path: &str, caller: Caller<'_>) -> Response<Body> {
    server
        .send(request("GET", path, caller, Body::empty()))
        .await
}

/// `GET` expecting `200`, returning the JSON body.
async fn read(server: &TestServer, path: &str, caller: Caller<'_>) -> Value {
    let response = get(server, path, caller).await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

/// `GET` expecting an error status with a JSON `{"error": …}` body.
async fn refused(server: &TestServer, path: &str, caller: Caller<'_>, expected: StatusCode) {
    let response = get(server, path, caller).await;
    assert_eq!(response.status(), expected, "GET {path}");
    let body = body_json(response).await;
    assert!(body["error"].is_string(), "GET {path}: {body}");
}

fn lodash_advisory() -> Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "published": "2021-02-15T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "details": "`template` is vulnerable to command injection.",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
        }],
        "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
    })
}

fn minimist_advisory() -> Value {
    json!({
        "id": "GHSA-xvch-5gv4-984h",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-44906"],
        "summary": "Prototype Pollution in minimist",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

/// Two organizations: `acme` (owned by alice, who signs in) with projects `web` and `api`,
/// and `globex` (owned by bob) with `web`. Every project has the npm fixture, so lodash
/// (high, known exploited) and minimist (critical) findings. Tokens of each kind are created.
struct Setup {
    server: TestServer,
    alice: Actor,
    cookie: String,
    acme_upload: String,
    acme_read: String,
    acme_web_read: String,
    acme_web_upload: String,
    globex_read: String,
}

async fn upload(server: &TestServer, token: &str, organization: &str, project: &str) {
    let response = server
        .send(request(
            "PUT",
            &format!("/api/organizations/{organization}/projects/{project}/sbom?wait=true"),
            Caller::Bearer(token),
            Body::from(sbom_document("cyclonedx-npm.json")),
        ))
        .await;
    // 201 when the upload creates the project, 200 afterwards.
    assert!(response.status().is_success(), "{}", response.status());
}

async fn sign_in(server: &TestServer, username: &str) -> String {
    let response = server
        .send(
            Request::post("/auth/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ORIGIN)
                .body(Body::from(format!(
                    "login={username}&password={}",
                    PASSWORD.replace(' ', "+")
                )))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("nanobom_session="))
        .expect("a session cookie")
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn token(
    server: &TestServer,
    owner: &Actor,
    organization: i64,
    project: Option<&str>,
    scope: Scope,
) -> String {
    tokens::create_with_scope(
        &server.database,
        owner,
        organization,
        project,
        "token",
        scope,
    )
    .await
    .unwrap()
    .secret
}

async fn setup() -> Setup {
    let server = server(&[]).await;
    server.source.publish(lodash_advisory(), &[LODASH]);
    server.source.publish(minimist_advisory(), &[MINIMIST]);
    exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_date_added: Set(Some("2021-11-03".to_owned())),
        kev_due_date: Set(None),
        kev_ransomware: Set(false),
        epss_score: Set(Some(0.5)),
        epss_percentile: Set(Some(0.9)),
        epss_date: Set(Some("2024-01-01".to_owned())),
        kev_checked_at: Set(None),
        epss_checked_at: Set(None),
    }
    .insert(&server.database)
    .await
    .unwrap();

    let alice = local_user(&server.database, "alice", PASSWORD).await;
    let bob = local_user(&server.database, "bob", PASSWORD).await;
    let acme = organizations::create(&server.database, &alice, "acme", "Acme")
        .await
        .unwrap();
    let globex = organizations::create(&server.database, &bob, "globex", "Globex")
        .await
        .unwrap();
    let acme_upload = token(&server, &alice, acme.id, None, Scope::Upload).await;
    let globex_upload = token(&server, &bob, globex.id, None, Scope::Upload).await;
    upload(&server, &acme_upload, "acme", "web").await;
    upload(&server, &acme_upload, "acme", "api").await;
    upload(&server, &globex_upload, "globex", "web").await;
    let acme_read = token(&server, &alice, acme.id, None, Scope::Read).await;
    let acme_web_read = token(&server, &alice, acme.id, Some("web"), Scope::Read).await;
    let acme_web_upload = token(&server, &alice, acme.id, Some("web"), Scope::Upload).await;
    let globex_read = token(&server, &bob, globex.id, None, Scope::Read).await;
    let cookie = sign_in(&server, "alice").await;
    Setup {
        server,
        alice,
        cookie,
        acme_upload,
        acme_read,
        acme_web_read,
        acme_web_upload,
        globex_read,
    }
}

/// The identifier of the finding of `purl` in a project, through the API.
async fn finding_id(setup: &Setup, organization: &str, project: &str, purl: &str) -> i64 {
    let token = if organization == "acme" {
        &setup.acme_read
    } else {
        &setup.globex_read
    };
    let page = read(
        &setup.server,
        &format!("/api/organizations/{organization}/projects/{project}/findings"),
        Caller::Bearer(token),
    )
    .await;
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["component"]["purl"] == purl)
        .and_then(|finding| finding["id"].as_i64())
        .expect("the finding is listed")
}

// The OpenAPI description, and a check of responses against it.

fn openapi() -> Value {
    serde_json::from_str(OPENAPI).expect("the OpenAPI description is JSON")
}

fn resolve<'a>(document: &'a Value, schema: &'a Value) -> &'a Value {
    match schema["$ref"].as_str() {
        Some(reference) => {
            let pointer = reference.strip_prefix('#').expect("a local reference");
            let target = document
                .pointer(pointer)
                .unwrap_or_else(|| panic!("{reference} resolves"));
            resolve(document, target)
        }
        None => schema,
    }
}

fn type_matches(value: &Value, kind: &str) -> bool {
    match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        other => panic!("unexpected type {other}"),
    }
}

/// Checks a value against the subset of JSON Schema the description uses. Objects must have
/// every required property and no undocumented one, so the description cannot drift from the
/// responses either way.
fn conforms(document: &Value, schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let schema = resolve(document, schema);
    if let Some(options) = schema["oneOf"].as_array() {
        let matching = options
            .iter()
            .filter(|option| conforms(document, option, value, path).is_ok())
            .count();
        return if matching == 1 {
            Ok(())
        } else {
            Err(format!(
                "{path}: {value} matches {matching} options of oneOf"
            ))
        };
    }
    let kinds: Vec<&str> = match &schema["type"] {
        Value::String(kind) => vec![kind.as_str()],
        Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !kinds.is_empty() && !kinds.iter().any(|kind| type_matches(value, kind)) {
        return Err(format!("{path}: {value} is not one of {kinds:?}"));
    }
    if let Some(allowed) = schema["enum"].as_array()
        && !allowed.contains(value)
    {
        return Err(format!("{path}: {value} is not one of {allowed:?}"));
    }
    if let Value::Object(fields) = value
        && let Some(properties) = schema["properties"].as_object()
    {
        for required in schema["required"].as_array().into_iter().flatten() {
            let name = required.as_str().unwrap_or_default();
            if !fields.contains_key(name) {
                return Err(format!("{path}: {name} is missing"));
            }
        }
        for (name, field) in fields {
            let property = properties
                .get(name)
                .ok_or_else(|| format!("{path}.{name} is not documented"))?;
            conforms(document, property, field, &format!("{path}.{name}"))?;
        }
    }
    if let Value::Array(items) = value
        && schema.get("items").is_some()
    {
        for (index, item) in items.iter().enumerate() {
            conforms(
                document,
                &schema["items"],
                item,
                &format!("{path}[{index}]"),
            )?;
        }
    }
    Ok(())
}

/// Checks a `200` response of a documented path against its schema.
fn assert_documented(path: &str, body: &Value) {
    let document = openapi();
    let schema = &document["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    assert!(!schema.is_null(), "{path} documents its response");
    if let Err(error) = conforms(&document, schema, body, path) {
        panic!("{error}");
    }
}

#[tokio::test]
async fn the_description_covers_exactly_the_routes() {
    let server = server(&[]).await;
    // Public: it describes the API, not data.
    let response = get(&server, "/api/openapi.json", Caller::Anonymous).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let served = body_json(response).await;
    assert_eq!(served, openapi());
    assert_eq!(served["openapi"], "3.1.0");
    let documented: BTreeSet<&str> = served["paths"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let routed: BTreeSet<&str> = PATHS.into_iter().collect();
    assert_eq!(documented, routed);
    // Every reference resolves.
    fn references(value: &Value, found: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(reference)) = map.get("$ref") {
                    found.push(reference.clone());
                }
                map.values().for_each(|value| references(value, found));
            }
            Value::Array(items) => items.iter().for_each(|value| references(value, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    references(&served, &mut found);
    for reference in found {
        assert!(
            served.pointer(reference.trim_start_matches('#')).is_some(),
            "{reference} resolves"
        );
    }
}

#[tokio::test]
async fn every_endpoint_answers_as_described() {
    let setup = setup().await;
    let server = &setup.server;
    let token = Caller::Bearer(&setup.acme_read);
    let lodash = finding_id(&setup, "acme", "web", LODASH).await;
    findings::ignore(
        &server.database,
        &setup.alice,
        finding_id(&setup, "acme", "web", MINIMIST).await,
        "only used by the build",
        Some(Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();

    let organizations = read(server, "/api/organizations", token).await;
    assert_documented("/api/organizations", &organizations);
    assert_eq!(
        organizations,
        json!({"items": [{"slug": "acme", "name": "Acme", "role": "viewer"}]})
    );

    let projects = read(server, "/api/organizations/acme/projects", token).await;
    assert_documented("/api/organizations/{organization}/projects", &projects);
    let slugs: Vec<&str> = projects["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|project| project["slug"].as_str().unwrap())
        .collect();
    assert_eq!(slugs, ["api", "web"]);
    let web = &projects["items"][1];
    assert_eq!(web["open"]["high"], 1);
    assert_eq!(web["open"]["critical"], 0);
    assert_eq!(web["ignored"], 1);
    assert_eq!(web["known_exploited"], 1);
    assert_eq!(web["stale"], false);
    assert!(web["last_upload_at"].is_string());

    let findings = read(
        server,
        "/api/organizations/acme/projects/web/findings",
        token,
    )
    .await;
    assert_documented(
        "/api/organizations/{organization}/projects/{project}/findings",
        &findings,
    );
    let first = &findings["items"][0];
    assert_eq!(first["vulnerability_id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(first["aliases"], json!(["CVE-2021-23337"]));
    assert_eq!(first["component"]["name"], "lodash");
    assert_eq!(first["component"]["version"], "4.17.20");
    assert_eq!(first["component"]["ecosystem"], "npm");
    assert_eq!(first["severity"], "high");
    assert_eq!(first["status"], "open");
    assert_eq!(first["exploitation"]["known_exploited"], true);
    assert_eq!(first["exploitation"]["epss_score"], 0.5);
    assert_eq!(first["ignore"], Value::Null);
    assert_eq!(
        first["url"],
        format!("http://localhost:8080/findings/{lodash}")
    );
    let ignored = &findings["items"][1];
    assert_eq!(ignored["status"], "ignored");
    assert_eq!(ignored["ignore"]["reason"], "only used by the build");
    assert_eq!(ignored["ignore"]["justification"], "code_not_reachable");

    let detail = read(server, &format!("/api/findings/{lodash}"), token).await;
    assert_documented("/api/findings/{finding}", &detail);
    assert_eq!(detail["organization"], "acme");
    assert_eq!(detail["fixed_versions"], json!(["4.17.21"]));
    assert_eq!(
        detail["references"][0]["url"],
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
    );
    assert_eq!(detail["events"][0]["kind"], "opened");
    assert!(detail["events"][0]["run_id"].is_i64());
    assert_eq!(
        detail["details"],
        "`template` is vulnerable to command injection."
    );
    // The other project of the organization; never the other organization's.
    assert_eq!(
        detail["affected_components"],
        json!([{
            "finding_id": finding_id(&setup, "acme", "api", LODASH).await,
            "organization": "acme",
            "project": "api",
            "purl": LODASH,
            "status": "open"
        }])
    );

    let components = read(
        server,
        "/api/organizations/acme/projects/web/components",
        token,
    )
    .await;
    assert_documented(
        "/api/organizations/{organization}/projects/{project}/components",
        &components,
    );
    assert!(components["total"].as_u64().unwrap() >= 3, "{components}");
    assert!(
        components["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component["purl"] == LODASH)
    );

    let matches = read(server, "/api/components?q=lodash", token).await;
    assert_documented("/api/components", &matches);
    let found: Vec<(&str, &str)> = matches["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| {
            (
                component["organization"].as_str().unwrap(),
                component["project"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(found.len(), 2);
    assert!(
        found
            .iter()
            .all(|(organization, _)| *organization == "acme")
    );

    let runs = read(server, "/api/organizations/acme/runs", token).await;
    assert_documented("/api/organizations/{organization}/runs", &runs);
    assert_eq!(runs["items"].as_array().unwrap().len(), 2, "{runs}");
    assert_eq!(runs["items"][0]["trigger"], "upload");
    assert_eq!(runs["items"][0]["status"], "succeeded");

    // The detail of an ignored finding says who ignored it.
    let minimist = finding_id(&setup, "acme", "web", MINIMIST).await;
    let detail = read(server, &format!("/api/findings/{minimist}"), token).await;
    assert_documented("/api/findings/{finding}", &detail);
    assert_eq!(detail["ignored_by"], "alice");
    let last = detail["events"].as_array().unwrap().last().unwrap().clone();
    assert_eq!(last["kind"], "ignored");
    assert_eq!(last["user"], "alice");
}

#[tokio::test]
async fn findings_take_the_project_page_filters_and_order() {
    let setup = setup().await;
    let server = &setup.server;
    let token = Caller::Bearer(&setup.acme_read);
    let base = "/api/organizations/acme/projects/web/findings";
    let vulnerabilities = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["vulnerability_id"].as_str().unwrap().to_owned())
            .collect()
    };

    // Known exploited first, even before a more severe finding.
    let all = read(server, base, token).await;
    assert_eq!(
        vulnerabilities(&all),
        ["GHSA-35jh-r3h4-6jhm", "GHSA-xvch-5gv4-984h"]
    );
    let critical = read(server, &format!("{base}?severity=critical"), token).await;
    assert_eq!(vulnerabilities(&critical), ["GHSA-xvch-5gv4-984h"]);
    let several = read(server, &format!("{base}?severity=critical,high"), token).await;
    assert_eq!(several["total"], 2);
    let exploited = read(server, &format!("{base}?exploited=true"), token).await;
    assert_eq!(vulnerabilities(&exploited), ["GHSA-35jh-r3h4-6jhm"]);
    let npm = read(server, &format!("{base}?ecosystem=npm"), token).await;
    assert_eq!(npm["total"], 2);
    let cargo = read(server, &format!("{base}?ecosystem=cargo"), token).await;
    assert_eq!(cargo["total"], 0);

    // Without `status`, open and ignored findings, as on the project page.
    findings::ignore(
        &server.database,
        &setup.alice,
        finding_id(&setup, "acme", "web", MINIMIST).await,
        "not reachable",
        None,
        None,
    )
    .await
    .unwrap();
    let default = read(server, base, token).await;
    assert_eq!(default["total"], 2);
    let open = read(server, &format!("{base}?status=open"), token).await;
    assert_eq!(vulnerabilities(&open), ["GHSA-35jh-r3h4-6jhm"]);
    let ignored = read(server, &format!("{base}?status=ignored"), token).await;
    assert_eq!(vulnerabilities(&ignored), ["GHSA-xvch-5gv4-984h"]);
    let fixed = read(server, &format!("{base}?status=fixed"), token).await;
    assert_eq!(fixed["total"], 0);
    let everything = read(server, &format!("{base}?status=all"), token).await;
    assert_eq!(everything["total"], 2);

    for invalid in [
        "status=closed",
        "severity=severe",
        "exploited=yes",
        "limit=0",
        "limit=501",
        "limit=ten",
        "offset=-1",
    ] {
        refused(
            server,
            &format!("{base}?{invalid}"),
            token,
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
}

#[tokio::test]
async fn lists_are_paginated() {
    let setup = setup().await;
    let server = &setup.server;
    let token = Caller::Bearer(&setup.acme_read);
    let base = "/api/organizations/acme/projects/web/findings";

    let first = read(server, &format!("{base}?limit=1"), token).await;
    assert_eq!(first["total"], 2);
    assert_eq!(first["limit"], 1);
    assert_eq!(first["offset"], 0);
    assert_eq!(first["items"][0]["vulnerability_id"], "GHSA-35jh-r3h4-6jhm");
    let second = read(server, &format!("{base}?limit=1&offset=1"), token).await;
    assert_eq!(
        second["items"][0]["vulnerability_id"],
        "GHSA-xvch-5gv4-984h"
    );
    let beyond = read(server, &format!("{base}?offset=5"), token).await;
    assert_eq!(beyond["items"], json!([]));
    assert_eq!(beyond["total"], 2);
    let defaults = read(server, base, token).await;
    assert_eq!(defaults["limit"], 100);

    let components = "/api/organizations/acme/projects/web/components";
    let all = read(server, components, token).await;
    let page = read(server, &format!("{components}?limit=2&offset=1"), token).await;
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert_eq!(page["items"][0], all["items"][1]);
    assert_eq!(page["items"][1], all["items"][2]);
    refused(
        server,
        &format!("{components}?limit=1000"),
        token,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;

    let runs = read(server, "/api/organizations/acme/runs?limit=1", token).await;
    assert_eq!(runs["items"].as_array().unwrap().len(), 1);
    refused(
        server,
        "/api/organizations/acme/runs?limit=101",
        token,
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
}

/// Every endpoint of the other organization is `404`, whoever asks.
#[tokio::test]
async fn organizations_are_isolated_on_every_endpoint() {
    let setup = setup().await;
    let server = &setup.server;
    let acme_finding = finding_id(&setup, "acme", "web", LODASH).await;
    let globex_finding = finding_id(&setup, "globex", "web", LODASH).await;
    let outside_acme = [
        "/api/organizations/acme/projects".to_owned(),
        "/api/organizations/acme/projects/web/findings".to_owned(),
        "/api/organizations/acme/projects/web/components".to_owned(),
        "/api/organizations/acme/runs".to_owned(),
        "/api/organizations/acme/projects/web/vex".to_owned(),
        format!("/api/findings/{acme_finding}"),
    ];
    for path in &outside_acme {
        refused(
            server,
            path,
            Caller::Bearer(&setup.globex_read),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    // Alice, signed in, is not a member of globex.
    let outside_globex = [
        "/api/organizations/globex/projects".to_owned(),
        "/api/organizations/globex/projects/web/findings".to_owned(),
        "/api/organizations/globex/projects/web/components".to_owned(),
        "/api/organizations/globex/runs".to_owned(),
        format!("/api/findings/{globex_finding}"),
    ];
    for path in &outside_globex {
        refused(
            server,
            path,
            Caller::Session(&setup.cookie),
            StatusCode::NOT_FOUND,
        )
        .await;
        refused(
            server,
            path,
            Caller::Bearer(&setup.acme_read),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
    // Lists and searches leave the other organization out.
    let organizations = read(
        server,
        "/api/organizations",
        Caller::Bearer(&setup.globex_read),
    )
    .await;
    assert_eq!(organizations["items"].as_array().unwrap().len(), 1);
    assert_eq!(organizations["items"][0]["slug"], "globex");
    let matches = read(
        server,
        "/api/components?q=lodash",
        Caller::Bearer(&setup.globex_read),
    )
    .await;
    assert_eq!(
        matches["items"],
        json!([{
            "organization": "globex",
            "project": "web",
            "purl": LODASH,
            "name": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm"
        }])
    );
    let detail = read(
        server,
        &format!("/api/findings/{globex_finding}"),
        Caller::Bearer(&setup.globex_read),
    )
    .await;
    assert_eq!(detail["affected_components"], json!([]));
    // Missing things look the same.
    for path in [
        "/api/organizations/initech/projects",
        "/api/organizations/acme/projects/missing/findings",
        "/api/findings/999999",
        "/api/findings/not-a-number",
    ] {
        refused(
            server,
            path,
            Caller::Bearer(&setup.acme_read),
            StatusCode::NOT_FOUND,
        )
        .await;
    }
}

/// A project token, of either scope, reads its project and nothing else of its organization.
#[tokio::test]
async fn project_tokens_read_their_project_only() {
    let setup = setup().await;
    let server = &setup.server;
    let api_finding = finding_id(&setup, "acme", "api", LODASH).await;
    let web_finding = finding_id(&setup, "acme", "web", LODASH).await;
    for token in [&setup.acme_web_read, &setup.acme_web_upload] {
        let caller = Caller::Bearer(token);
        let organizations = read(server, "/api/organizations", caller).await;
        assert_eq!(organizations["items"][0]["slug"], "acme");
        let projects = read(server, "/api/organizations/acme/projects", caller).await;
        assert_eq!(projects["items"].as_array().unwrap().len(), 1);
        assert_eq!(projects["items"][0]["slug"], "web");
        read(
            server,
            "/api/organizations/acme/projects/web/findings",
            caller,
        )
        .await;
        read(
            server,
            "/api/organizations/acme/projects/web/components",
            caller,
        )
        .await;
        for path in [
            "/api/organizations/acme/projects/api/findings".to_owned(),
            "/api/organizations/acme/projects/api/components".to_owned(),
            "/api/organizations/acme/projects/api/vex".to_owned(),
            format!("/api/findings/{api_finding}"),
        ] {
            refused(server, &path, caller, StatusCode::NOT_FOUND).await;
        }
        let detail = read(server, &format!("/api/findings/{web_finding}"), caller).await;
        assert_eq!(detail["affected_components"], json!([]));
        let matches = read(server, "/api/components?q=lodash", caller).await;
        assert_eq!(matches["items"].as_array().unwrap().len(), 1);
        assert_eq!(matches["items"][0]["project"], "web");
        // The upload run of `web`, not that of `api`.
        let runs = read(server, "/api/organizations/acme/runs", caller).await;
        assert_eq!(runs["items"].as_array().unwrap().len(), 1, "{runs}");
    }
}

async fn project_count(server: &TestServer) -> u64 {
    projects::Entity::find()
        .count(&server.database)
        .await
        .unwrap()
}

/// Read tokens upload nothing, import nothing and create no project, on any route.
#[tokio::test]
async fn read_tokens_never_write() {
    let setup = setup().await;
    let server = &setup.server;
    let projects_before = project_count(server).await;
    for token in [&setup.acme_read, &setup.acme_web_read] {
        for path in [
            "/api/organizations/acme/projects/web/sbom",
            "/api/organizations/acme/projects/new/sbom",
        ] {
            let response = server
                .send(request(
                    "PUT",
                    path,
                    Caller::Bearer(token),
                    Body::from(sbom_document("cyclonedx-npm.json")),
                ))
                .await;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "PUT {path}");
            let body = body_json(response).await;
            assert!(
                body["error"].as_str().unwrap().contains("read-only"),
                "{body}"
            );
        }

        let vex = serde_json::to_vec(&json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "vulnerabilities": [{
                "id": "CVE-2021-23337",
                "analysis": {"state": "not_affected", "justification": "code_not_reachable"},
                "affects": [{"ref": LODASH}]
            }]
        }))
        .unwrap();
        let response = server
            .send(request(
                "PUT",
                "/api/organizations/acme/projects/web/vex",
                Caller::Bearer(token),
                Body::from(vex),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The Dependency-Track routes, with the token in X-Api-Key.
        let bom =
            base64::engine::general_purpose::STANDARD.encode(sbom_document("cyclonedx-npm.json"));
        let response = server
            .send(
                Request::put("/api/v1/bom")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("X-Api-Key", token.as_str())
                    .body(Body::from(
                        json!({"projectName": "created", "autoCreate": true, "bom": bom})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(project_count(server).await, projects_before);
    let open = read(
        server,
        "/api/organizations/acme/projects/web/findings?status=open",
        Caller::Bearer(&setup.acme_read),
    )
    .await;
    assert_eq!(open["total"], 2, "the VEX document ignored nothing");

    // Reading is what they are for, VEX export included.
    let response = get(
        server,
        "/api/organizations/acme/projects/web/vex",
        Caller::Bearer(&setup.acme_web_read),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Upload tokens read what they reach, like read tokens; uploading still works.
#[tokio::test]
async fn upload_tokens_also_read() {
    let setup = setup().await;
    let server = &setup.server;
    let caller = Caller::Bearer(&setup.acme_upload);
    let organizations = read(server, "/api/organizations", caller).await;
    assert_eq!(organizations["items"][0]["role"], "viewer");
    let projects = read(server, "/api/organizations/acme/projects", caller).await;
    assert_eq!(projects["items"].as_array().unwrap().len(), 2);
    upload(server, &setup.acme_upload, "acme", "web").await;
}

#[tokio::test]
async fn callers_authenticate_with_a_token_or_the_session() {
    let setup = setup().await;
    let server = &setup.server;
    let path = "/api/organizations/acme/projects";

    let session = read(server, "/api/organizations", Caller::Session(&setup.cookie)).await;
    // Alice's personal organization comes along; globex does not.
    let items = session["items"].as_array().unwrap();
    assert!(items.contains(&json!({"slug": "acme", "name": "Acme", "role": "owner"})));
    assert!(
        items
            .iter()
            .all(|organization| organization["slug"] != "globex")
    );
    read(server, path, Caller::Session(&setup.cookie)).await;
    read(server, path, Caller::ApiKey(&setup.acme_read)).await;

    let response = get(server, path, Caller::Anonymous).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    assert!(body_json(response).await["error"].is_string());
    for caller in [
        Caller::Bearer("nanobom_0000"),
        Caller::ApiKey("nanobom_0000"),
        Caller::Bearer(""),
    ] {
        refused(server, path, caller, StatusCode::UNAUTHORIZED).await;
    }
    // A wrong token does not fall back to the session.
    let response = server
        .send(
            Request::get(path)
                .header(header::COOKIE, &setup.cookie)
                .header(header::AUTHORIZATION, "Bearer nanobom_0000")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // A revoked token stops working.
    let listed = tokens::list(
        &server.database,
        &setup.alice,
        organizations::find(&server.database, &setup.alice, "acme")
            .await
            .unwrap()
            .id,
    )
    .await
    .unwrap();
    let read_token = listed
        .iter()
        .find(|token| setup.acme_read.starts_with(&token.prefix))
        .unwrap();
    tokens::revoke(&server.database, &setup.alice, read_token.id)
        .await
        .unwrap();
    refused(
        server,
        path,
        Caller::Bearer(&setup.acme_read),
        StatusCode::UNAUTHORIZED,
    )
    .await;

    refused(
        server,
        "/api/components",
        Caller::Session(&setup.cookie),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await;
}

#[tokio::test]
async fn unchanged_responses_are_not_sent_again() {
    let setup = setup().await;
    let server = &setup.server;
    let path = "/api/organizations/acme/projects/web/findings";
    let caller = Caller::Bearer(&setup.acme_read);
    let response = get(server, path, caller).await;
    let etag = response.headers()[header::ETAG]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(etag.starts_with("W/\""), "{etag}");

    let conditional = |etag: String| {
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", setup.acme_read))
            .header(header::IF_NONE_MATCH, etag)
            .body(Body::empty())
            .unwrap()
    };
    let response = server.send(conditional(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(response.headers()[header::ETAG], etag.as_str());

    findings::ignore(
        &server.database,
        &setup.alice,
        finding_id(&setup, "acme", "web", LODASH).await,
        "accepted",
        None,
        None,
    )
    .await
    .unwrap();
    let response = server.send(conditional(etag.clone())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_ne!(response.headers()[header::ETAG], etag.as_str());
}
