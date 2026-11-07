//! The SBOM upload endpoint.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{body_json, sbom_document, server, user};
use nanobom_domain::{organizations, projects, tokens};

fn upload(path: &str, token: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::put(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body)).unwrap()
}

#[tokio::test]
async fn organization_tokens_upload_and_create_projects() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;

    let response = server
        .send(upload(
            "/api/organizations/acme/projects/web/sbom?source_commit=abc123&image_tag=web:1.2",
            Some(&token),
            sbom_document("cyclonedx-npm.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let outcome = body_json(response).await;
    assert_eq!(outcome["project"], "web");
    assert_eq!(outcome["project_created"], true);
    assert_eq!(outcome["component_count"], 3);
    assert_eq!(outcome["components_without_purl"], 0);

    let response = server
        .send(upload(
            "/api/organizations/acme/projects/web/sbom",
            Some(&token),
            sbom_document("syft.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let project = projects::find(&server.database, &owner, organization.id, "web")
        .await
        .unwrap();
    assert!(project.last_upload_at.is_some());
}

#[tokio::test]
async fn uploads_without_a_valid_token_are_refused() {
    let server = server(&[]).await;
    for token in [None, Some("nanobom_unknown"), Some("garbage")] {
        let response = server
            .send(upload(
                "/api/organizations/acme/projects/web/sbom",
                token,
                sbom_document("cyclonedx-py.json"),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
    }
}

#[tokio::test]
async fn project_tokens_cannot_reach_other_projects_or_organizations() {
    let server = server(&[]).await;
    let owner = user(&server.database, "owner").await;
    let acme = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    for slug in ["api", "web"] {
        projects::create(&server.database, &owner, acme.id, slug, slug)
            .await
            .unwrap();
    }
    organizations::create(&server.database, &owner, "other", "Other")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, acme.id, Some("api"), "API")
        .await
        .unwrap()
        .secret;
    let attempt = |path: &str| upload(path, Some(&token), sbom_document("cargo-cyclonedx.json"));

    let response = server
        .send(attempt("/api/organizations/acme/projects/api/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = server
        .send(attempt("/api/organizations/acme/projects/web/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = server
        .send(attempt("/api/organizations/acme/projects/new/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = server
        .send(attempt("/api/organizations/other/projects/api/sbom"))
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_and_oversized_documents_are_rejected() {
    let server = server(&["--maximum-sbom-size", "1"]).await;
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let path = "/api/organizations/acme/projects/web/sbom";

    let response = server
        .send(upload(
            path,
            Some(&token),
            b"{\"spdxVersion\": \"SPDX-2.3\"}".to_vec(),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(response).await;
    assert!(body["error"].as_str().unwrap().contains("CycloneDX"));

    let response = server
        .send(upload(path, Some(&token), vec![b' '; 1024 * 1024 + 1]))
        .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
