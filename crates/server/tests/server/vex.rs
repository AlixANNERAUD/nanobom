//! The VEX endpoints and the VEX statements of uploaded SBOMs.

use crate::common::{TestServer, body_json, sbom_document, server, user};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use nanobom_domain::{organizations, tokens};
use sea_orm::EntityTrait;
use serde_json::{Value, json};

const VEX: &str = "/api/organizations/acme/projects/web/vex";
const LODASH: &str = "pkg:npm/lodash@4.17.20";

fn request(method: &str, path: &str, token: Option<&str>, body: Vec<u8>) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request.body(Body::from(body)).unwrap()
}

/// A high severity advisory affecting the lodash of `cyclonedx-npm.json`.
fn lodash_advisory() -> Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}]
    })
}

/// An organization `acme` with an organization-wide token (returned) and the lodash SBOM
/// uploaded and evaluated in `acme/web`, which then has one open high finding.
async fn evaluated_project(server: &TestServer) -> String {
    server.source.publish(lodash_advisory(), &[LODASH]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    let response = server
        .send(request(
            "PUT",
            "/api/organizations/acme/projects/web/sbom?wait=true",
            Some(&token),
            sbom_document("cyclonedx-npm.json"),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    token
}

/// A VEX document saying the lodash of the fixture is not affected by its CVE.
fn not_affected() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "vulnerabilities": [{
            "id": "CVE-2021-23337",
            "analysis": {
                "state": "not_affected",
                "justification": "code_not_reachable",
                "detail": "template() is never called"
            },
            "affects": [{ "ref": LODASH }]
        }]
    }))
    .unwrap()
}

async fn finding_status(server: &TestServer) -> String {
    nanobom_entity::findings::Entity::find()
        .one(&server.database)
        .await
        .unwrap()
        .unwrap()
        .status
}

#[tokio::test]
async fn upload_tokens_export_and_import_vex_documents() {
    let server = server(&[]).await;
    let token = evaluated_project(&server).await;

    let response = server
        .send(request("GET", VEX, Some(&token), Vec::new()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/vnd.cyclonedx+json"
    );
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"acme-web.vex.cdx.json\""
    );
    let document = body_json(response).await;
    assert_eq!(document["specVersion"], "1.6");
    assert_eq!(document["vulnerabilities"][0]["id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(
        document["vulnerabilities"][0]["analysis"]["state"],
        "in_triage"
    );
    assert_eq!(document["vulnerabilities"][0]["affects"][0]["ref"], LODASH);

    let response = server
        .send(request("PUT", VEX, Some(&token), not_affected()))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let outcome = body_json(response).await;
    assert_eq!(outcome["ignored"], 1, "{outcome}");
    assert_eq!(outcome["results"][0]["result"], "ignored");
    assert_eq!(finding_status(&server).await, "ignored");

    // Again: nothing to do.
    let response = server
        .send(request("PUT", VEX, Some(&token), not_affected()))
        .await;
    let outcome = body_json(response).await;
    assert_eq!(outcome["ignored"], 0);
    assert_eq!(outcome["already_ignored"], 1);

    let document = body_json(
        server
            .send(request("GET", VEX, Some(&token), Vec::new()))
            .await,
    )
    .await;
    let analysis = &document["vulnerabilities"][0]["analysis"];
    assert_eq!(analysis["state"], "not_affected");
    assert_eq!(analysis["justification"], "code_not_reachable");
    assert_eq!(analysis["detail"], "template() is never called");
}

#[tokio::test]
async fn vex_endpoints_refuse_missing_tokens_and_invalid_documents() {
    let server = server(&[]).await;
    let token = evaluated_project(&server).await;

    for method in ["GET", "PUT"] {
        let response = server
            .send(request(method, VEX, None, not_affected()))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method}");
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        let response = server
            .send(request(
                method,
                VEX,
                Some("nanobom_unknown"),
                not_affected(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method}");
        let response = server
            .send(request(
                method,
                "/api/organizations/acme/projects/missing/vex",
                Some(&token),
                not_affected(),
            ))
            .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method}");
    }

    let response = server
        .send(request("PUT", VEX, Some(&token), b"{}".to_vec()))
        .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = body_json(response).await;
    assert!(body["error"].as_str().unwrap().contains("VEX"), "{body}");
    assert_eq!(finding_status(&server).await, "open");
}

#[tokio::test]
async fn statements_inside_an_sbom_apply_before_the_gate() {
    let server = server(&[]).await;
    let token = evaluated_project(&server).await;
    let mut sbom: Value = serde_json::from_slice(&sbom_document("cyclonedx-npm.json")).unwrap();
    sbom["vulnerabilities"] = json!([{
        "id": "GHSA-35jh-r3h4-6jhm",
        "analysis": { "state": "not_affected", "justification": "code_not_present" },
        "affects": [{ "ref": "fixture-npm@1.0.0|lodash@4.17.20" }]
    }]);

    let response = server
        .send(request(
            "PUT",
            "/api/organizations/acme/projects/web/sbom?fail_on=high",
            Some(&token),
            serde_json::to_vec(&sbom).unwrap(),
        ))
        .await;
    let status = response.status();
    let body = body_json(response).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["vex"]["ignored"], 1, "{body}");
    assert_eq!(body["evaluation"]["open"]["high"], 0);
    assert_eq!(finding_status(&server).await, "ignored");
}
