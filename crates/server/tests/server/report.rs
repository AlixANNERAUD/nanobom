//! The vulnerability report of a project version, as an HTML document for tokens.

use crate::common::{TestServer, body_json, body_text, sbom_document, server, user};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use nanobom_domain::{
    access::Actor,
    findings::{self, Filter, Justification},
    organizations, projects, tokens,
};
use serde_json::json;

const REPORT: &str = "/api/organizations/acme/projects/web/report";
const LODASH: &str = "pkg:npm/lodash@4.17.20";
const MINIMIST: &str = "pkg:npm/minimist@1.2.5";

fn get(path: &str, token: Option<&str>, language: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path);
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if let Some(language) = language {
        request = request.header(header::ACCEPT_LANGUAGE, language);
    }
    request.body(Body::empty()).unwrap()
}

/// `acme/web` evaluated from the npm fixture: lodash open and known exploited, minimist ignored
/// as not reachable. Returns an organization-wide token, the owner and the organization.
async fn evaluated_project(server: &TestServer) -> (String, Actor, i64) {
    server.source.publish(
        json!({
            "id": "GHSA-35jh-r3h4-6jhm",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection in lodash",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
        }),
        &[LODASH],
    );
    server.source.publish(
        json!({
            "id": "GHSA-xvch-5gv4-984h",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": ["CVE-2021-44906"],
            "summary": "Prototype Pollution in minimist",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        }),
        &[MINIMIST],
    );
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(
            Request::put("/api/organizations/acme/projects/web/sbom?wait=true")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document("cyclonedx-npm.json")))
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    let minimist = findings::list(&server.database, &owner, project.id, &Filter::default())
        .await
        .unwrap()
        .into_iter()
        .find(|finding| finding.purl == MINIMIST)
        .expect("the minimist finding")
        .id;
    findings::ignore(
        &server.database,
        &owner,
        minimist,
        "Only used by the build",
        Some(Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();
    use sea_orm::{ActiveModelTrait, ActiveValue::Set};
    nanobom_entity::exploitation::ActiveModel {
        cve_id: Set("CVE-2021-23337".to_owned()),
        known_exploited: Set(true),
        kev_ransomware: Set(false),
        epss_score: Set(Some(0.5)),
        epss_percentile: Set(Some(0.97)),
        ..Default::default()
    }
    .insert(&server.database)
    .await
    .unwrap();
    (token, owner, organization.id)
}

#[tokio::test]
async fn tokens_get_the_report_as_html() {
    let server = server(&[]).await;
    let (token, ..) = evaluated_project(&server).await;

    let response = server.send(get(REPORT, Some(&token), None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "private, no-cache"
    );
    assert_eq!(
        response.headers()[header::VARY],
        "Cookie, Authorization, X-Api-Key, Accept-Language"
    );
    let html = body_text(response).await;
    assert!(html.starts_with("<!DOCTYPE html><html lang=\"en\" class=\"light\">"));
    for section in [
        "Vulnerability report",
        "Scope and provenance",
        "Summary",
        "Open vulnerabilities",
        "Assessed as not affecting the product",
        "Licenses",
        "Method",
    ] {
        assert!(html.contains(section), "{section}");
    }
    assert!(html.contains("GHSA-35jh-r3h4-6jhm"));
    assert!(html.contains("CVE-2021-23337"));
    assert!(html.contains("4.17.21"), "the fixed version");
    assert!(html.contains("97%"), "the EPSS percentile");
    assert!(html.contains("1 open vulnerability of high or critical severity."));
    assert!(html.contains("Only used by the build"));
    assert!(html.contains("Vulnerable code not reachable"));
    assert!(html.contains("by owner"));
    assert!(html.contains("http://localhost:8080/api/organizations/acme/projects/web/vex"));
    // Nothing of the interface around it.
    assert!(!html.contains("Sign out"));

    let html = body_text(
        server
            .send(get(REPORT, Some(&token), Some("fr-FR,fr;q=0.9")))
            .await,
    )
    .await;
    assert!(html.contains("<html lang=\"fr\""));
    assert!(html.contains("Rapport de vulnérabilités"));
    assert!(html.contains("Évaluées comme n’affectant pas le produit"));
}

#[tokio::test]
async fn the_report_needs_a_reader_and_a_known_version() {
    let server = server(&[]).await;
    let (token, owner, organization) = evaluated_project(&server).await;

    let response = server.send(get(REPORT, None, None)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(body_json(response).await["error"].is_string());

    let response = server
        .send(get(&format!("{REPORT}?version=9.9"), Some(&token), None))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Named, the latest version is the unnamed one the upload went to.
    let response = server
        .send(get(&format!("{REPORT}?version="), Some(&token), None))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response).await.contains("Unnamed version"));

    let response = server
        .send(get(
            "/api/organizations/other/projects/web/report",
            Some(&token),
            None,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // A read token of another project does not reach this one.
    projects::create(&server.database, &owner, organization, "api", "API")
        .await
        .unwrap();
    let other = tokens::create_with_scope(
        &server.database,
        &owner,
        organization,
        Some("api"),
        "Reports",
        tokens::Scope::Read,
    )
    .await
    .unwrap()
    .secret;
    let response = server.send(get(REPORT, Some(&other), None)).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server
        .send(get(
            "/api/organizations/acme/projects/api/report",
            Some(&other),
            None,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
}
