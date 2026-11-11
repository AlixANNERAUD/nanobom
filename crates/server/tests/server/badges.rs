//! Public badges: served to anonymous clients by key, with caching headers, and gone as soon as
//! the badge is turned off or its address replaced.

use crate::common::{TestServer, body_json, body_text, sbom_document, server, user};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode, header},
};
use nanobom_domain::{
    access::Actor,
    badges,
    findings::{self, Filter},
    organizations, projects,
    tokens::{self, Scope},
};
use nanobom_entity::exploitation;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use serde_json::{Value, json};

const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";

fn lodash_advisory() -> Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}]
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

/// `acme/web` with the npm fixture uploaded: a high, known exploited lodash finding and a
/// critical minimist finding. Its badge is on.
struct Setup {
    server: TestServer,
    owner: Actor,
    project: i64,
    key: String,
}

async fn setup() -> Setup {
    let server = server(&[]).await;
    server.source.publish(lodash_advisory(), &[LODASH]);
    server.source.publish(minimist_advisory(), &[MINIMIST]);
    exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_ransomware: Set(false),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();
    let owner = user(&server.database, "owner").await;
    let acme = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token =
        tokens::create_with_scope(&server.database, &owner, acme.id, None, "ci", Scope::Upload)
            .await
            .unwrap()
            .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom?version=1.0&wait=true")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert!(response.status().is_success(), "{}", response.status());
    let project = projects::find(&server.database, &owner, acme.id, "web")
        .await
        .unwrap()
        .id;
    let key = badges::enable(&server.database, &owner, project)
        .await
        .unwrap();
    Setup {
        server,
        owner,
        project,
        key,
    }
}

/// An anonymous `GET`, with an optional `If-None-Match`.
async fn get(server: &TestServer, path: &str, if_none_match: Option<&str>) -> Response<Body> {
    let mut request = Request::get(path);
    if let Some(tag) = if_none_match {
        request = request.header(header::IF_NONE_MATCH, tag);
    }
    server.send(request.body(Body::empty()).unwrap()).await
}

fn header_value(response: &Response<Body>, name: header::HeaderName) -> &str {
    response
        .headers()
        .get(&name)
        .unwrap_or_else(|| panic!("a {name} header"))
        .to_str()
        .unwrap()
}

/// `GET` expecting an empty `404`.
async fn missing(server: &TestServer, path: &str) {
    let response = get(server, path, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "GET {path}");
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "no-store",
        "GET {path}"
    );
    assert_eq!(body_text(response).await, "", "GET {path}");
}

#[tokio::test]
async fn anonymous_clients_get_the_svg_and_json_badges_with_caching_headers() {
    let setup = setup().await;
    let server = &setup.server;
    let message = "1 exploited, 1 critical, 1 high";

    let response = get(server, &format!("/badges/{}.svg", setup.key), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&response, header::CONTENT_TYPE),
        "image/svg+xml; charset=utf-8"
    );
    assert_eq!(
        header_value(&response, header::CACHE_CONTROL),
        "public, max-age=300"
    );
    assert_eq!(
        header_value(&response, header::X_CONTENT_TYPE_OPTIONS),
        "nosniff"
    );
    assert_eq!(
        header_value(&response, header::CONTENT_SECURITY_POLICY),
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    );
    let etag = header_value(&response, header::ETAG).to_owned();
    assert!(etag.starts_with('"'), "a strong tag: {etag}");
    assert!(response.headers().get(header::SET_COOKIE).is_none());
    let svg = body_text(response).await;
    assert!(
        svg.contains(&format!(r#"aria-label="vulnerabilities: {message}""#)),
        "{svg}"
    );
    assert!(svg.contains(&format!(">{message}</text>")), "{svg}");

    // Even when the client accepts compression, the strong tag names the bytes sent.
    let response = server
        .send(
            Request::get(format!("/badges/{}.svg", setup.key))
                .header(header::ACCEPT_ENCODING, "gzip, br")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(response.headers().get(header::CONTENT_ENCODING).is_none());
    assert_eq!(header_value(&response, header::ETAG), etag);

    let response = get(server, &format!("/badges/{}.json", setup.key), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_value(&response, header::CONTENT_TYPE),
        "application/json"
    );
    assert_eq!(
        header_value(&response, header::CACHE_CONTROL),
        "public, max-age=300"
    );
    assert!(response.headers().get(header::ETAG).is_some());
    assert_eq!(
        body_json(response).await,
        json!({
            "schemaVersion": 1,
            "label": "vulnerabilities",
            "message": message,
            "color": "cf222e",
        })
    );

    // The latest version by its name reads the same.
    let response = get(
        server,
        &format!("/badges/{}.json?version=1.0", setup.key),
        None,
    )
    .await;
    assert_eq!(body_json(response).await["message"], message);
}

#[tokio::test]
async fn a_matching_if_none_match_is_answered_not_modified() {
    let setup = setup().await;
    let server = &setup.server;
    let path = format!("/badges/{}.svg", setup.key);
    let response = get(server, &path, None).await;
    let etag = header_value(&response, header::ETAG).to_owned();

    for candidate in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"other\", {etag}"),
        "*".to_owned(),
    ] {
        let response = get(server, &path, Some(&candidate)).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "{candidate}");
        assert_eq!(header_value(&response, header::ETAG), etag);
        assert_eq!(
            header_value(&response, header::CACHE_CONTROL),
            "public, max-age=300"
        );
        assert_eq!(body_text(response).await, "");
    }
    let response = get(server, &path, Some("\"other\"")).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn triage_changes_the_badge() {
    let setup = setup().await;
    let server = &setup.server;
    let path = format!("/badges/{}.json", setup.key);
    let before = get(server, &path, None).await;
    let etag = header_value(&before, header::ETAG).to_owned();

    let open = findings::list(
        &server.database,
        &setup.owner,
        setup.project,
        &Filter::default(),
    )
    .await
    .unwrap();
    let lodash = open
        .iter()
        .find(|finding| finding.purl == LODASH)
        .expect("the lodash finding");
    findings::ignore(
        &server.database,
        &setup.owner,
        lodash.id,
        "not reachable",
        None,
        None,
    )
    .await
    .unwrap();

    // The old tag no longer matches, and the ignored finding is gone from the message.
    let response = get(server, &path, Some(&etag)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let badge = body_json(response).await;
    assert_eq!(badge["message"], "1 critical");
    assert_eq!(badge["color"], "cf222e");
}

#[tokio::test]
async fn anything_that_does_not_resolve_is_an_empty_not_found() {
    let setup = setup().await;
    let server = &setup.server;
    let key = &setup.key;

    missing(server, &format!("/badges/{key}.png")).await;
    missing(server, &format!("/badges/{key}")).await;
    missing(server, &format!("/badges/{key}.svg?version=9.9")).await;
    missing(
        server,
        &format!("/badges/{key}.svg?version=1.0&version=2.0"),
    )
    .await;
    missing(server, "/badges/0123456789abcdef0123456789abcdef.svg").await;
    missing(server, "/badges/.svg").await;
    missing(server, &format!("/badges/{}.svg", key.to_uppercase())).await;

    // A new address: the old one stops working at once.
    let replaced = badges::regenerate(&server.database, &setup.owner, setup.project)
        .await
        .unwrap();
    missing(server, &format!("/badges/{key}.svg")).await;
    missing(server, &format!("/badges/{key}.json")).await;
    let response = get(server, &format!("/badges/{replaced}.svg"), None).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Turned off: nothing is served.
    badges::disable(&server.database, &setup.owner, setup.project)
        .await
        .unwrap();
    missing(server, &format!("/badges/{replaced}.svg")).await;
    missing(server, &format!("/badges/{replaced}.json")).await;
}

#[tokio::test]
async fn a_project_without_an_sbom_shows_no_sbom() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let acme = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let project = projects::create(&server.database, &owner, acme.id, "web", "Web")
        .await
        .unwrap();
    let key = badges::enable(&server.database, &owner, project.id)
        .await
        .unwrap();
    let response = get(&server, &format!("/badges/{key}.json"), None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await,
        json!({
            "schemaVersion": 1,
            "label": "vulnerabilities",
            "message": "no SBOM",
            "color": "6e7781",
        })
    );
}
