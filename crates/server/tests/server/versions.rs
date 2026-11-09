//! Project versions over HTTP: the upload parameters, the gate per version, and the reads and
//! VEX documents of one version.

use crate::common::{TestServer, body_json, sbom_document, server, user};
use crate::read_api::assert_documented;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use nanobom_domain::{organizations, tokens};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde_json::{Value, json};

const LODASH: &str = "pkg:npm/lodash@4.17.20";

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

/// A server with an `acme` organization and its organization-wide token, and the lodash
/// advisory published.
async fn setup() -> (TestServer, String) {
    let server = server(&[]).await;
    server.source.publish(lodash_advisory(), &[LODASH]);
    let owner = user(&server.database, "owner").await;
    let organization = organizations::create(&server.database, &owner, "acme", "Acme")
        .await
        .unwrap();
    let token = tokens::create(&server.database, &owner, organization.id, None, "CI")
        .await
        .unwrap()
        .secret;
    (server, token)
}

/// Uploads a fixture SBOM to `acme/web` with a query string.
async fn upload(
    server: &TestServer,
    token: &str,
    document: &str,
    query: &str,
) -> (StatusCode, Value) {
    let response = server
        .send(
            Request::put(format!("/api/organizations/acme/projects/web/sbom{query}"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(sbom_document(document)))
                .unwrap(),
        )
        .await;
    let status = response.status();
    (status, body_json(response).await)
}

async fn send(
    server: &TestServer,
    method: &str,
    path: &str,
    token: &str,
    body: Body,
) -> (StatusCode, Value) {
    let response = server
        .send(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(body)
                .unwrap(),
        )
        .await;
    let status = response.status();
    (status, body_json(response).await)
}

async fn read(server: &TestServer, path: &str, token: &str) -> Value {
    let (status, body) = send(server, "GET", path, token, Body::empty()).await;
    assert_eq!(status, StatusCode::OK, "GET {path}: {body}");
    body
}

#[tokio::test]
async fn uploads_name_their_version() {
    let (server, token) = setup().await;
    let (status, body) = upload(&server, &token, "cyclonedx-npm.json", "?version=2.4").await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["project_created"], true);
    assert_eq!(body["version"], "2.4");
    assert_eq!(body["version_created"], true);
    assert!(body.get("version_id").is_none(), "{body}");

    let (status, body) = upload(&server, &token, "cyclonedx-npm.json", "?version=%202.4%20").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], "2.4", "trimmed");
    assert_eq!(body["version_created"], false);
    let (status, body) = upload(
        &server,
        &token,
        "cyclonedx-npm.json",
        "?version=release%2F2.3%2B1&latest=false",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], "release/2.3+1");
    assert_eq!(body["version_created"], true);
    // Without `version`, the unnamed version, as before versions existed.
    let (_, body) = upload(&server, &token, "cyclonedx-npm.json", "").await;
    assert_eq!(body["version"], "");
    assert_eq!(body["version_created"], true);

    // Invalid parameters store nothing.
    let uploads = nanobom_entity::sbom_uploads::Entity::find()
        .count(&server.database)
        .await
        .unwrap();
    let (status, body) = upload(&server, &token, "cyclonedx-npm.json", "?version=1.0%20beta").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        json!({"error": "the version must be 1 to 64 characters: letters, digits, '.', '_', '+', '/' or '-'"})
    );
    let (status, body) = upload(&server, &token, "cyclonedx-npm.json", "?version=").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (status, body) = upload(&server, &token, "cyclonedx-npm.json", "?latest=yes").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "latest must be true or false"}));
    assert_eq!(
        nanobom_entity::sbom_uploads::Entity::find()
            .count(&server.database)
            .await
            .unwrap(),
        uploads
    );

    // The versions, newest first, with the latest flagged.
    let versions = read(
        &server,
        "/api/organizations/acme/projects/web/versions",
        &token,
    )
    .await;
    assert_documented(
        "/api/organizations/{organization}/projects/{project}/versions",
        &versions,
    );
    let listed: Vec<(&str, bool)> = versions["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|version| {
            (
                version["name"].as_str().unwrap(),
                version["latest"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [("", true), ("release/2.3+1", false), ("2.4", false)]
    );
}

#[tokio::test]
async fn the_gate_judges_the_uploaded_version() {
    let (server, token) = setup().await;
    let (status, body) = upload(
        &server,
        &token,
        "cyclonedx-npm.json",
        "?version=1.0&fail_on=high",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "1 open finding at or above high");

    // 2.0 inherits the lodash finding of 1.0, then its run fixes it: lodash is not in 2.0.
    let (status, body) = upload(
        &server,
        &token,
        "cyclonedx-py.json",
        "?version=2.0&fail_on=high",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.get("error").is_none(), "{body}");
    assert_eq!(body["evaluation"]["findings"], json!([]));
    assert_eq!(body["version"], "2.0");

    // 1.0 still fails on its own findings, whichever version is latest.
    let (status, body) = upload(
        &server,
        &token,
        "cyclonedx-npm.json",
        "?version=1.0&fail_on=high",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["evaluation"]["findings"][0]["component"], LODASH);

    // Reads take the latest version unless they name one; an unknown one is 404.
    let base = "/api/organizations/acme/projects/web";
    let latest = read(&server, &format!("{base}/findings"), &token).await;
    assert_eq!(latest["total"], 0, "{latest}");
    let fixed = read(&server, &format!("{base}/findings?status=fixed"), &token).await;
    assert_eq!(fixed["items"][0]["version"], "2.0");
    assert_eq!(fixed["items"][0]["component"]["purl"], LODASH);
    let old = read(&server, &format!("{base}/findings?version=1.0"), &token).await;
    assert_documented(
        "/api/organizations/{organization}/projects/{project}/findings",
        &old,
    );
    assert_eq!(old["total"], 1);
    assert_eq!(old["items"][0]["version"], "1.0");
    let id = old["items"][0]["id"].as_i64().unwrap();
    let detail = read(&server, &format!("/api/findings/{id}"), &token).await;
    assert_eq!(detail["version"], "1.0");
    let components = read(
        &server,
        &format!("{base}/components?version=1.0&limit=10"),
        &token,
    )
    .await;
    assert!(
        components["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|component| component["purl"] == LODASH)
    );
    let components = read(&server, &format!("{base}/components"), &token).await;
    assert!(
        components["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|component| component["purl"] != LODASH)
    );
    let violations = read(
        &server,
        &format!("{base}/license-violations?version=1.0"),
        &token,
    )
    .await;
    assert_eq!(violations["active"], false);
    for path in ["findings", "components", "license-violations", "vex"] {
        let (status, body) = send(
            &server,
            "GET",
            &format!("{base}/{path}?version=9.9"),
            &token,
            Body::empty(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
    }
}

#[tokio::test]
async fn vex_documents_are_per_version() {
    let (server, token) = setup().await;
    upload(
        &server,
        &token,
        "cyclonedx-npm.json",
        "?version=1.0&wait=true",
    )
    .await;
    upload(
        &server,
        &token,
        "cyclonedx-npm.json",
        "?version=2.0&wait=true",
    )
    .await;
    let base = "/api/organizations/acme/projects/web";

    let response = server
        .send(
            Request::get(format!("{base}/vex?version=1.0"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"acme-web-1.0.vex.cdx.json\""
    );
    let mut document = body_json(response).await;
    assert_eq!(document["metadata"]["component"]["version"], "1.0");
    assert_eq!(document["vulnerabilities"].as_array().unwrap().len(), 1);
    let latest = read(&server, &format!("{base}/vex"), &token).await;
    assert_eq!(latest["metadata"]["component"]["version"], "2.0");

    // Importing into 1.0 ignores its finding only.
    document["vulnerabilities"][0]["analysis"] = json!({
        "state": "not_affected",
        "justification": "code_not_reachable",
    });
    let (status, outcome) = send(
        &server,
        "PUT",
        &format!("{base}/vex?version=1.0"),
        &token,
        Body::from(document.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{outcome}");
    assert_eq!(outcome["ignored"], 1);
    let status_of = |page: &Value| page["items"][0]["status"].clone();
    let old = read(&server, &format!("{base}/findings?version=1.0"), &token).await;
    assert_eq!(status_of(&old), "ignored");
    let new = read(&server, &format!("{base}/findings"), &token).await;
    assert_eq!(status_of(&new), "open");
    let (status, _) = send(
        &server,
        "PUT",
        &format!("{base}/vex?version=9.9"),
        &token,
        Body::from(document.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reads_compare_versions_and_leave_inactive_ones_out_of_search() {
    let (server, token) = setup().await;
    let owner = nanobom_entity::users::Entity::find()
        .filter(nanobom_entity::users::Column::Username.eq("owner"))
        .one(&server.database)
        .await
        .unwrap()
        .unwrap();
    let owner = nanobom_domain::access::Actor::from_user(&owner);
    upload(&server, &token, "cyclonedx-npm.json", "?version=1.0").await;
    server.runner.wait_until_idle().await;
    upload(&server, &token, "cyclonedx-npm.json", "?version=2.0").await;
    server.runner.wait_until_idle().await;
    let names = |body: &Value| -> Vec<(String, bool)> {
        body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["project_version"].as_str().unwrap().to_owned(),
                    item["project_version_active"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let found = read(&server, "/api/components?q=lodash", &token).await;
    assert_documented("/api/components", &found);
    assert_eq!(
        names(&found),
        [("1.0".to_owned(), true), ("2.0".to_owned(), true)]
    );

    let project = nanobom_entity::projects::Entity::find()
        .one(&server.database)
        .await
        .unwrap()
        .unwrap();
    nanobom_domain::versions::set_active(&server.database, &owner, project.id, "1.0", false)
        .await
        .unwrap();
    let found = read(&server, "/api/components?q=lodash", &token).await;
    assert_eq!(names(&found), [("2.0".to_owned(), true)]);
    let found = read(&server, "/api/components?q=lodash&inactive=true", &token).await;
    assert_documented("/api/components", &found);
    assert_eq!(
        names(&found),
        [("1.0".to_owned(), false), ("2.0".to_owned(), true)]
    );
    let (status, body) = send(
        &server,
        "GET",
        "/api/components?q=lodash&inactive=yes",
        &token,
        Body::empty(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "inactive must be true or false"}));

    // Inactive versions stay listed, flagged, and readable.
    let versions = read(
        &server,
        "/api/organizations/acme/projects/web/versions",
        &token,
    )
    .await;
    let flags: Vec<(&str, bool, bool)> = versions["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|version| {
            (
                version["name"].as_str().unwrap(),
                version["latest"].as_bool().unwrap(),
                version["active"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(flags, [("2.0", true, true), ("1.0", false, false)]);
    let old = read(
        &server,
        "/api/organizations/acme/projects/web/findings?version=1.0",
        &token,
    )
    .await;
    assert_eq!(old["items"].as_array().unwrap().len(), 1);

    // A finding lists every version of its project.
    let current = read(
        &server,
        "/api/organizations/acme/projects/web/findings",
        &token,
    )
    .await;
    let id = current["items"][0]["id"].as_i64().unwrap();
    let detail = read(&server, &format!("/api/findings/{id}"), &token).await;
    assert_documented("/api/findings/{finding}", &detail);
    assert_eq!(
        detail["versions"],
        json!([
            {"name": "2.0", "latest": true, "active": true, "current": true, "status": "open", "finding_id": id},
            {"name": "1.0", "latest": false, "active": false, "current": false, "status": "open",
             "finding_id": old["items"][0]["id"]}
        ])
    );
    // Its copy in 1.0, an inactive version, is left out of the affected components.
    assert_eq!(detail["affected_components"], json!([]));
}
