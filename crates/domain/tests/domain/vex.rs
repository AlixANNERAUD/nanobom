//! VEX: exporting a project's findings as CycloneDX and importing statements from one.

use std::str::FromStr;

use chrono::Utc;
use cyclonedx_bom::{
    models::bom::SpecVersion,
    prelude::{Bom, Validate},
};
use nanobom_domain::{
    Error,
    access::Actor,
    findings::{self, Justification, Status},
    inventory, memberships, organizations, projects, testing, tokens,
    users::{self, NewUser},
    vex::{self, StatementResult},
};
use nanobom_entity::{findings as findings_entity, upload_tokens, vulnerabilities};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait};
use serde_json::{Value, json};

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    organization: i64,
    project: i64,
}

async fn user(database: &DatabaseConnection, username: &str) -> Actor {
    let user = users::create(
        database,
        NewUser {
            username: username.to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    Actor::from_user(&user)
}

async fn fixture() -> Fixture {
    let database = testing::database().await;
    let owner = user(&database, "owner").await;
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    let project = projects::create(&database, &owner, organization, "web", "Web shop")
        .await
        .unwrap()
        .id;
    Fixture {
        database,
        owner,
        organization,
        project,
    }
}

/// Stores a vulnerability with aliases and a CVSS vector, if not stored yet.
async fn vulnerability(database: &DatabaseConnection, id: &str, aliases: &[&str]) {
    if vulnerabilities::Entity::find_by_id(id.to_owned())
        .one(database)
        .await
        .unwrap()
        .is_some()
    {
        return;
    }
    vulnerabilities::ActiveModel {
        id: Set(id.to_owned()),
        modified: Set(Utc::now().fixed_offset()),
        published: Set(Some(Utc::now().fixed_offset())),
        summary: Set(Some(format!("Summary of {id}"))),
        aliases: Set(serde_json::to_string(aliases).unwrap()),
        severity: Set("high".to_owned()),
        cvss_score: Set(Some(7.5)),
        cvss_version: Set(Some("3.1".to_owned())),
        cvss_vector: Set(Some(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_owned(),
        )),
        record: Set("{}".to_owned()),
        fetched_at: Set(Utc::now().fixed_offset()),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap();
}

/// A finding of `id` on `purl`, with this status.
async fn finding(
    database: &DatabaseConnection,
    project: i64,
    purl: &str,
    id: &str,
    aliases: &[&str],
    status: Status,
) -> i64 {
    vulnerability(database, id, aliases).await;
    findings_entity::ActiveModel {
        project_id: Set(project),
        purl: Set(purl.to_owned()),
        ecosystem: Set(purl[4..].split('/').next().unwrap().to_owned()),
        vulnerability_id: Set(id.to_owned()),
        status: Set(status.as_str().to_owned()),
        severity: Set("high".to_owned()),
        first_seen_at: Set(Utc::now().fixed_offset()),
        last_seen_at: Set(Utc::now().fixed_offset()),
        fixed_at: Set((status == Status::Fixed).then(|| Utc::now().fixed_offset())),
        ..Default::default()
    }
    .insert(database)
    .await
    .unwrap()
    .id
}

async fn token(
    database: &DatabaseConnection,
    owner: &Actor,
    organization: i64,
    project: Option<&str>,
) -> upload_tokens::Model {
    let created = tokens::create(database, owner, organization, project, "CI")
        .await
        .unwrap();
    tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap()
}

async fn status(database: &DatabaseConnection, finding: i64) -> findings_entity::Model {
    findings_entity::Entity::find_by_id(finding)
        .one(database)
        .await
        .unwrap()
        .unwrap()
}

/// The exported vulnerability about `id`.
fn exported<'a>(document: &'a Value, id: &str) -> &'a Value {
    document["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vulnerability| vulnerability["id"] == id)
        .unwrap_or_else(|| panic!("{id} is exported"))
}

/// A statement: `(id, references, state, justification, detail, affects refs)`.
type Statement<'a> = (
    &'a str,
    &'a [&'a str],
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    &'a [&'a str],
);

/// A VEX document with these statements.
fn vex_document(statements: &[Statement]) -> Vec<u8> {
    let vulnerabilities: Vec<Value> = statements
        .iter()
        .map(|(id, references, state, justification, detail, refs)| {
            let mut analysis = json!({ "state": state });
            if let Some(justification) = justification {
                analysis["justification"] = json!(justification);
            }
            if let Some(detail) = detail {
                analysis["detail"] = json!(detail);
            }
            json!({
                "id": id,
                "references": references
                    .iter()
                    .map(|reference| json!({ "id": reference, "source": { "name": "NVD" } }))
                    .collect::<Vec<_>>(),
                "analysis": analysis,
                "affects": refs.iter().map(|reference| json!({ "ref": reference })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::to_vec(&json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            { "type": "library", "bom-ref": "lodash", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20" }
        ],
        "vulnerabilities": vulnerabilities,
    }))
    .unwrap()
}

#[tokio::test]
async fn exports_each_status_with_its_impact_analysis() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let lodash = "pkg:npm/lodash@4.17.20";
    finding(
        database,
        fixture.project,
        lodash,
        "GHSA-aaaa-aaaa-aaaa",
        &["CVE-2021-23337"],
        Status::Open,
    )
    .await;
    let justified = finding(
        database,
        fixture.project,
        "pkg:npm/minimist@1.2.0",
        "GHSA-bbbb-bbbb-bbbb",
        &[],
        Status::Open,
    )
    .await;
    let accepted = finding(
        database,
        fixture.project,
        "pkg:npm/qs@6.0.0",
        "GHSA-cccc-cccc-cccc",
        &[],
        Status::Open,
    )
    .await;
    let false_positive = finding(
        database,
        fixture.project,
        "pkg:npm/ms@2.0.0",
        "GHSA-dddd-dddd-dddd",
        &[],
        Status::Open,
    )
    .await;
    finding(
        database,
        fixture.project,
        "pkg:npm/debug@2.0.0",
        "GHSA-eeee-eeee-eeee",
        &[],
        Status::Fixed,
    )
    .await;
    findings::ignore(
        database,
        &fixture.owner,
        justified,
        "only used at build time",
        Some(Justification::CodeNotReachable),
        None,
    )
    .await
    .unwrap();
    findings::ignore(
        database,
        &fixture.owner,
        accepted,
        "accepted until the next release",
        None,
        None,
    )
    .await
    .unwrap();
    findings::ignore(
        database,
        &fixture.owner,
        false_positive,
        "wrong package",
        Some(Justification::FalsePositive),
        None,
    )
    .await
    .unwrap();

    let document = vex::export(database, &fixture.owner, "acme", "web")
        .await
        .unwrap();
    let document = serde_json::to_value(&document).unwrap();
    assert_eq!(document["bomFormat"], "CycloneDX");
    assert_eq!(document["specVersion"], "1.6");
    assert_eq!(document["metadata"]["component"]["name"], "Web shop");
    assert_eq!(
        document["metadata"]["tools"]["components"][0]["name"],
        "nanobom"
    );

    let open = exported(&document, "GHSA-aaaa-aaaa-aaaa");
    assert_eq!(open["analysis"]["state"], "in_triage");
    assert!(open["analysis"].get("justification").is_none());
    assert_eq!(open["affects"], json!([{ "ref": lodash }]));
    assert_eq!(open["source"]["name"], "GitHub Advisories");
    assert_eq!(
        open["references"],
        json!([{
            "id": "CVE-2021-23337",
            "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" }
        }])
    );
    assert_eq!(open["ratings"][0]["severity"], "high");
    assert_eq!(open["ratings"][0]["method"], "CVSSv31");
    assert_eq!(open["description"], "Summary of GHSA-aaaa-aaaa-aaaa");

    let justified = exported(&document, "GHSA-bbbb-bbbb-bbbb");
    assert_eq!(justified["analysis"]["state"], "not_affected");
    assert_eq!(justified["analysis"]["justification"], "code_not_reachable");
    assert_eq!(justified["analysis"]["detail"], "only used at build time");

    // Without a justification, an ignore is not a claim that the product is unaffected.
    let accepted = exported(&document, "GHSA-cccc-cccc-cccc");
    assert_eq!(accepted["analysis"]["state"], "in_triage");
    assert_eq!(
        accepted["analysis"]["detail"],
        "accepted until the next release"
    );

    let false_positive = exported(&document, "GHSA-dddd-dddd-dddd");
    assert_eq!(false_positive["analysis"]["state"], "false_positive");
    assert!(false_positive["analysis"].get("justification").is_none());

    assert_eq!(
        exported(&document, "GHSA-eeee-eeee-eeee")["analysis"]["state"],
        "resolved"
    );

    // Every reference resolves to a component listed in the document.
    let references: Vec<&str> = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|component| component["bom-ref"].as_str().unwrap())
        .collect();
    assert!(references.contains(&lodash));
    assert_eq!(references.len(), 5);

    // The document follows CycloneDX 1.6, as the reference library reads it.
    let bytes = serde_json::to_vec(&document).unwrap();
    let parsed =
        Bom::parse_from_json_with_version(&bytes[..], SpecVersion::from_str("1.6").unwrap())
            .expect("a CycloneDX 1.6 document");
    assert!(parsed.validate_version(SpecVersion::V1_6).passed());
}

#[tokio::test]
async fn an_export_imports_back_after_its_analysis_changes() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let finding_id = finding(
        database,
        fixture.project,
        "pkg:npm/lodash@4.17.20",
        "GHSA-aaaa-aaaa-aaaa",
        &["CVE-2021-23337"],
        Status::Open,
    )
    .await;
    let token = token(database, &fixture.owner, fixture.organization, None).await;

    let document = vex::export_for_upload_token(database, &token, "acme", "web")
        .await
        .unwrap();
    let mut document = serde_json::to_value(&document).unwrap();
    document["vulnerabilities"][0]["analysis"] = json!({
        "state": "not_affected",
        "justification": "requires_configuration",
        "detail": "template compilation is disabled",
    });
    let statements = vex::parse(&serde_json::to_vec(&document).unwrap()).unwrap();
    let outcome = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(outcome.ignored, 1);
    assert_eq!(outcome.results[0].result, StatementResult::Ignored);
    assert_eq!(outcome.results[0].findings, [finding_id]);

    let stored = status(database, finding_id).await;
    assert_eq!(stored.status, "ignored");
    assert_eq!(
        stored.ignore_reason.as_deref(),
        Some("template compilation is disabled")
    );
    assert_eq!(
        stored.ignore_justification.as_deref(),
        Some("requires_configuration")
    );
    assert_eq!(stored.ignored_by_user_id, None);
    assert_eq!(stored.ignored_by_upload_token_id, Some(token.id));

    let detail = findings::detail(database, &fixture.owner, finding_id)
        .await
        .unwrap();
    assert_eq!(detail.ignored_by_token.as_deref(), Some("CI"));
    let event = detail.events.last().unwrap();
    assert_eq!(event.token.as_deref(), Some("CI"));
    assert_eq!(
        event.justification,
        Some(Justification::RequiresConfiguration)
    );

    let exported = vex::export(database, &fixture.owner, "acme", "web")
        .await
        .unwrap();
    let exported = serde_json::to_value(&exported).unwrap();
    assert_eq!(
        exported["vulnerabilities"][0]["analysis"]["state"],
        "not_affected"
    );
    assert_eq!(
        exported["vulnerabilities"][0]["analysis"]["justification"],
        "requires_configuration"
    );
}

#[tokio::test]
async fn statements_match_aliases_and_package_urls_without_qualifiers() {
    let fixture = fixture().await;
    let database = &fixture.database;
    // The finding is filed under the GHSA identifier, with qualifiers in its package URL.
    let finding_id = finding(
        database,
        fixture.project,
        "pkg:npm/lodash@4.17.20?arch=x64",
        "GHSA-aaaa-aaaa-aaaa",
        &["CVE-2021-23337"],
        Status::Open,
    )
    .await;
    let other_version = finding(
        database,
        fixture.project,
        "pkg:npm/lodash@4.17.19",
        "GHSA-aaaa-aaaa-aaaa",
        &["CVE-2021-23337"],
        Status::Open,
    )
    .await;
    let token = token(database, &fixture.owner, fixture.organization, Some("web")).await;

    // The statement names the CVE (in lower case) and the component by its `bom-ref`.
    let statements = vex::parse(&vex_document(&[(
        "cve-2021-23337",
        &[],
        "false_positive",
        None,
        None,
        &["lodash"],
    )]))
    .unwrap();
    let outcome = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(outcome.ignored, 1);
    let stored = status(database, finding_id).await;
    assert_eq!(stored.status, "ignored");
    assert_eq!(
        stored.ignore_justification.as_deref(),
        Some("false_positive")
    );
    assert_eq!(
        stored.ignore_reason.as_deref(),
        Some("VEX statement: false_positive")
    );
    assert_eq!(status(database, other_version).await.status, "open");

    // An identifier among the references, and a package URL as the reference.
    let statements = vex::parse(&vex_document(&[(
        "SNYK-JS-LODASH-1040724",
        &["GHSA-aaaa-aaaa-aaaa"],
        "not_affected",
        Some("code_not_present"),
        Some("tree-shaken"),
        &["pkg:npm/lodash@4.17.19"],
    )]))
    .unwrap();
    let outcome = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(outcome.ignored, 1);
    assert_eq!(status(database, other_version).await.status, "ignored");
}

#[tokio::test]
async fn bom_links_resolve_through_their_fragment() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let finding_id = finding(
        database,
        fixture.project,
        "pkg:npm/%40angular/core@1.0.0",
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        Status::Open,
    )
    .await;
    let token = token(database, &fixture.owner, fixture.organization, None).await;
    let statements = vex::parse(&vex_document(&[(
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        "not_affected",
        Some("code_not_reachable"),
        None,
        &["urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg%3Anpm%2F%2540angular%2Fcore%401.0.0"],
    )]))
    .unwrap();
    let outcome = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(outcome.ignored, 1, "{outcome:?}");
    assert_eq!(
        status(database, finding_id).await.ignore_reason.as_deref(),
        Some("VEX statement: not_affected (code_not_reachable)")
    );
}

#[tokio::test]
async fn imports_are_idempotent_and_report_what_they_skip() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let lodash = finding(
        database,
        fixture.project,
        "pkg:npm/lodash@4.17.20",
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        Status::Open,
    )
    .await;
    let fixed = finding(
        database,
        fixture.project,
        "pkg:npm/qs@6.0.0",
        "GHSA-bbbb-bbbb-bbbb",
        &[],
        Status::Fixed,
    )
    .await;
    let token = token(database, &fixture.owner, fixture.organization, None).await;
    let document = vex_document(&[
        (
            "GHSA-aaaa-aaaa-aaaa",
            &[],
            "not_affected",
            Some("code_not_reachable"),
            Some("unused"),
            &["lodash"],
        ),
        // Informational states change nothing.
        (
            "GHSA-aaaa-aaaa-aaaa",
            &[],
            "exploitable",
            None,
            None,
            &["lodash"],
        ),
        (
            "GHSA-bbbb-bbbb-bbbb",
            &[],
            "resolved",
            None,
            None,
            &["pkg:npm/qs@6.0.0"],
        ),
        // Fixed findings are not ignored.
        (
            "GHSA-bbbb-bbbb-bbbb",
            &[],
            "not_affected",
            Some("code_not_present"),
            None,
            &["pkg:npm/qs@6.0.0"],
        ),
        // References that cannot be matched.
        (
            "GHSA-cccc-cccc-cccc",
            &[],
            "not_affected",
            Some("code_not_present"),
            None,
            &["unknown-ref"],
        ),
        (
            "GHSA-cccc-cccc-cccc",
            &[],
            "not_affected",
            Some("code_not_present"),
            None,
            &["pkg:npm/lodash"],
        ),
        (
            "GHSA-cccc-cccc-cccc",
            &[],
            "not_affected",
            Some("code_not_present"),
            None,
            &[],
        ),
    ]);
    let statements = vex::parse(&document).unwrap();
    let first = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(first.statements, 7);
    assert_eq!(first.ignored, 1);
    assert_eq!(first.already_ignored, 0);
    assert_eq!(first.skipped, 6);
    let results: Vec<StatementResult> = first.results.iter().map(|result| result.result).collect();
    assert_eq!(
        results,
        [
            StatementResult::Ignored,
            StatementResult::Informational,
            StatementResult::Informational,
            StatementResult::NoMatchingFinding,
            StatementResult::UnresolvedReference,
            StatementResult::NoVersion,
            StatementResult::NoTarget,
        ]
    );
    assert_eq!(status(database, fixed).await.status, "fixed");

    let second = vex::import(database, &token, "acme", "web", &statements)
        .await
        .unwrap();
    assert_eq!(second.ignored, 0);
    assert_eq!(second.already_ignored, 1);
    assert_eq!(second.results[0].result, StatementResult::AlreadyIgnored);
    let events = findings::detail(database, &fixture.owner, lodash)
        .await
        .unwrap()
        .events;
    assert_eq!(events.len(), 1, "one ignore, recorded once");
}

#[tokio::test]
async fn tokens_and_members_reach_only_their_projects() {
    let fixture = fixture().await;
    let database = &fixture.database;
    let finding_id = finding(
        database,
        fixture.project,
        "pkg:npm/lodash@4.17.20",
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        Status::Open,
    )
    .await;
    projects::create(database, &fixture.owner, fixture.organization, "api", "API")
        .await
        .unwrap();
    let globex = organizations::create(database, &fixture.owner, "globex", "Globex")
        .await
        .unwrap()
        .id;
    let globex_token = token(database, &fixture.owner, globex, None).await;
    let api_token = token(database, &fixture.owner, fixture.organization, Some("api")).await;
    let statements = vex::parse(&vex_document(&[(
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        "not_affected",
        Some("code_not_present"),
        None,
        &["lodash"],
    )]))
    .unwrap();

    for (token, organization) in [
        (&globex_token, "acme"),
        (&globex_token, "globex"),
        (&api_token, "acme"),
    ] {
        assert!(matches!(
            vex::import(database, token, organization, "web", &statements).await,
            Err(Error::NotFound)
        ));
        assert!(matches!(
            vex::export_for_upload_token(database, token, organization, "web").await,
            Err(Error::NotFound)
        ));
    }
    assert_eq!(status(database, finding_id).await.status, "open");

    // Viewers export; people outside the organization do not see it.
    let viewer = user(database, "viewer").await;
    let outsider = user(database, "outsider").await;
    memberships::add(
        database,
        &fixture.owner,
        fixture.organization,
        "viewer",
        nanobom_domain::access::Role::Viewer,
    )
    .await
    .unwrap();
    assert!(vex::export(database, &viewer, "acme", "web").await.is_ok());
    assert!(matches!(
        vex::export(database, &outsider, "acme", "web").await,
        Err(Error::NotFound)
    ));
    assert!(matches!(
        vex::export(database, &viewer, "acme", "missing").await,
        Err(Error::NotFound)
    ));
}

#[test]
fn vex_documents_are_checked_like_sboms() {
    assert!(matches!(vex::parse(b"not json"), Err(Error::Invalid(_))));
    assert!(matches!(
        vex::parse(br#"{"bomFormat": "SPDX", "specVersion": "1.6"}"#),
        Err(Error::Invalid(_))
    ));
    // CycloneDX 1.3 has no vulnerabilities.
    let error = vex::parse(br#"{"bomFormat": "CycloneDX", "specVersion": "1.3", "version": 1}"#)
        .unwrap_err();
    assert!(error.to_string().contains("1.4, 1.5, 1.6, 1.7"), "{error}");
}

#[test]
fn sboms_carry_their_analysed_vulnerabilities() {
    let mut document: Value = serde_json::from_slice(&vex_document(&[(
        "GHSA-aaaa-aaaa-aaaa",
        &[],
        "not_affected",
        Some("code_not_reachable"),
        None,
        &["lodash"],
    )]))
    .unwrap();
    // A scanner's finding without analysis is not a statement.
    document["vulnerabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": "GHSA-bbbb-bbbb-bbbb", "affects": [{ "ref": "lodash" }] }));
    let sbom = inventory::parse(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert_eq!(sbom.components.len(), 1);
    assert_eq!(sbom.vex.len(), 1);
    assert_eq!(
        sbom.vex[0].justification,
        Some(Justification::CodeNotReachable)
    );
    assert_eq!(
        sbom.vex[0].targets[0].purl.as_deref(),
        Some("pkg:npm/lodash@4.17.20")
    );
}
