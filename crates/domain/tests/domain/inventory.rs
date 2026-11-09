//! SBOM parsing with a document from each supported generator, upload tokens and intake.

use std::collections::BTreeSet;

use nanobom_domain::{
    Error,
    access::{Actor, Role},
    inventory::{self, ParsedSbom, UploadSource},
    memberships, organizations,
    problem::Problem,
    projects, testing, tokens,
    users::{self, NewUser},
};
use sea_orm::DatabaseConnection;
use serde_json::json;

fn sbom_document(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/sboms/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn purls(sbom: &ParsedSbom) -> Vec<&str> {
    sbom.components
        .iter()
        .map(|component| component.purl.as_str())
        .collect()
}

#[test]
fn parses_cargo_cyclonedx() {
    let sbom = inventory::parse(&sbom_document("cargo-cyclonedx.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.5");
    assert_eq!(
        purls(&sbom),
        ["pkg:cargo/itoa@1.0.18", "pkg:cargo/smallvec@1.6.0"]
    );
    assert_eq!(sbom.skipped_count, 0);
    let smallvec = &sbom.components[1];
    assert_eq!(smallvec.ecosystem, "cargo");
    assert_eq!(smallvec.name, "smallvec");
    assert_eq!(smallvec.version.as_deref(), Some("1.6.0"));
}

#[test]
fn parses_cyclonedx_npm() {
    let sbom = inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(
        purls(&sbom),
        [
            "pkg:npm/%40babel/helper-string-parser@7.25.9",
            "pkg:npm/lodash@4.17.20",
            "pkg:npm/minimist@1.2.5",
        ]
    );
    assert_eq!(sbom.components[0].name, "@babel/helper-string-parser");
}

#[test]
fn parses_cyclonedx_py() {
    let sbom = inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(
        purls(&sbom),
        ["pkg:pypi/idna@3.6", "pkg:pypi/urllib3@1.26.4"]
    );
}

#[test]
fn parses_syft_and_strips_qualifiers_for_queries() {
    let sbom = inventory::parse(&sbom_document("syft.json")).unwrap();
    assert_eq!(sbom.specification_version, "1.6");
    assert_eq!(sbom.components.len(), 15);
    assert_eq!(sbom.skipped_count, 0, "files and the OS are not packages");
    let busybox = sbom
        .components
        .iter()
        .find(|component| component.purl.starts_with("pkg:apk/alpine/busybox@"))
        .unwrap();
    assert_eq!(busybox.ecosystem, "apk");
    assert_eq!(busybox.name, "alpine/busybox");
    assert!(busybox.purl.contains("distro=alpine-3.19.0"));
    assert_eq!(busybox.query_purl, "pkg:apk/alpine/busybox@1.36.1-r15");
}

#[test]
fn reports_components_without_a_usable_purl() {
    let document = br#"{
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {"type": "library", "name": "vendored", "version": "1.0"},
            {"type": "library", "name": "broken", "purl": "not a purl"},
            {"type": "library", "name": "parent", "version": "2.0", "purl": "pkg:npm/parent@2.0",
             "components": [{"type": "library", "name": "child", "version": "3.0", "purl": "pkg:npm/child@3.0"}]},
            {"type": "library", "name": "parent", "version": "2.0", "purl": "pkg:npm/parent@2.0"}
        ]
    }"#;
    let sbom = inventory::parse(document).unwrap();
    assert_eq!(purls(&sbom), ["pkg:npm/child@3.0", "pkg:npm/parent@2.0"]);
    assert_eq!(sbom.skipped_count, 2);
    assert_eq!(sbom.skipped[0].name, "vendored");
    assert_eq!(sbom.skipped[0].reason, "no package URL");
    assert_eq!(sbom.skipped[1].name, "broken");
}

#[test]
fn rejects_documents_that_are_not_supported_cyclonedx() {
    for document in [
        &b"not json"[..],
        br#"{"bomFormat": "SPDX"}"#,
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.2", "version": 1}"#,
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": 3}"#,
    ] {
        assert!(matches!(inventory::parse(document), Err(Error::Invalid(_))));
    }
}

fn problem(document: &[u8]) -> Problem {
    match inventory::parse(document) {
        Err(Error::Invalid(problem)) => problem,
        other => panic!("expected a problem, got {other:?}"),
    }
}

fn query_purls(sbom: &ParsedSbom) -> BTreeSet<&str> {
    sbom.components
        .iter()
        .map(|component| component.query_purl.as_str())
        .collect()
}

#[test]
fn parses_syft_spdx_like_its_cyclonedx() {
    let sbom = inventory::parse(&sbom_document("syft-spdx.json")).unwrap();
    assert_eq!(sbom.specification_version, "SPDX-2.3");
    assert!(
        sbom.serial_number
            .as_deref()
            .unwrap()
            .starts_with("https://anchore.com/syft/image/alpine-"),
        "the document namespace identifies the document"
    );
    assert_eq!(sbom.components.len(), 15);
    assert_eq!(
        sbom.skipped_count, 0,
        "the image it describes and its files are not packages"
    );
    let busybox = sbom
        .components
        .iter()
        .find(|component| component.purl.starts_with("pkg:apk/alpine/busybox@"))
        .unwrap();
    assert_eq!(busybox.ecosystem, "apk");
    assert_eq!(busybox.name, "alpine/busybox");
    assert_eq!(busybox.version.as_deref(), Some("1.36.1-r15"));
    assert!(busybox.purl.contains("distro=alpine-3.19.0"));
    assert_eq!(busybox.query_purl, "pkg:apk/alpine/busybox@1.36.1-r15");

    // The same image in CycloneDX, scanned on another architecture: the package URLs differ
    // by their `arch` qualifier only, and OSV is queried with the same ones.
    let cyclonedx = inventory::parse(&sbom_document("syft.json")).unwrap();
    assert_ne!(purls(&sbom), purls(&cyclonedx));
    assert_eq!(query_purls(&sbom), query_purls(&cyclonedx));
}

#[test]
fn parses_spdx_2_2() {
    let sbom = inventory::parse(&sbom_document("syft-cargo-spdx-2.2.json")).unwrap();
    assert_eq!(sbom.specification_version, "SPDX-2.2");
    assert_eq!(
        purls(&sbom),
        [
            "pkg:cargo/aho-corasick@0.7.20",
            "pkg:cargo/fixture-cargo@0.1.0",
            "pkg:cargo/memchr@2.8.3",
            "pkg:cargo/regex-syntax@0.6.29",
            "pkg:cargo/regex@1.5.4",
            "pkg:cargo/smallvec@1.6.0",
        ]
    );
    assert_eq!(sbom.skipped_count, 0);
}

#[test]
fn parses_trivy_spdx() {
    let sbom = inventory::parse(&sbom_document("trivy-npm-spdx.json")).unwrap();
    assert_eq!(sbom.specification_version, "SPDX-2.3");
    assert_eq!(
        purls(&sbom),
        [
            "pkg:npm/%40babel/helper-string-parser@7.25.9",
            "pkg:npm/debug@2.6.8",
            "pkg:npm/lodash@4.17.20",
            "pkg:npm/minimist@1.2.5",
            "pkg:npm/ms@2.0.0",
        ]
    );
    assert_eq!(sbom.components[0].name, "@babel/helper-string-parser");
    // Trivy's entry for the lock file has no package URL, like in its CycloneDX output.
    assert_eq!(sbom.skipped_count, 1);
    assert_eq!(sbom.skipped[0].name, "package-lock.json");
    assert_eq!(sbom.skipped[0].reason, "no package URL");
}

#[test]
fn parses_github_dependency_graph_exports() {
    let sbom = inventory::parse(&sbom_document("github-dependency-graph.json")).unwrap();
    assert_eq!(sbom.specification_version, "SPDX-2.3");
    assert!(
        sbom.components
            .iter()
            .all(|component| component.ecosystem != "github"),
        "the repository is the project"
    );
    assert_eq!(
        sbom.components
            .iter()
            .filter(|component| component.ecosystem == "cargo")
            .count(),
        67
    );
    // Workflow actions pinned to a version requirement cannot be matched.
    assert_eq!(sbom.components.len(), 70);
    assert_eq!(sbom.skipped_count, 4);
    let checkout = sbom
        .skipped
        .iter()
        .find(|skipped| skipped.name == "actions/checkout")
        .unwrap();
    assert_eq!(checkout.version.as_deref(), Some("3.*.*"));
    assert_eq!(
        checkout.reason,
        "version requirement \"3.*.*\" instead of a resolved version"
    );
}

/// An SPDX document with the given packages and relationships, describing `root`.
fn spdx(packages: serde_json::Value, relationships: serde_json::Value) -> Vec<u8> {
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "sample",
        "documentNamespace": "https://example.org/spdx/sample",
        "packages": packages,
        "relationships": relationships,
    })
    .to_string()
    .into_bytes()
}

fn spdx_package(id: &str, name: &str, purl: Option<&str>) -> serde_json::Value {
    let mut package = json!({"SPDXID": id, "name": name, "versionInfo": "1.0"});
    if let Some(purl) = purl {
        package["externalRefs"] = json!([
            {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
             "referenceLocator": "cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*"},
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
             "referenceLocator": purl}
        ]);
    }
    package
}

#[test]
fn spdx_packages_map_like_cyclonedx_components() {
    let purls_in = [
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar#META-INF",
        "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12",
        "pkg:pypi/Django@4.2",
    ];
    let mut packages: Vec<serde_json::Value> = purls_in
        .iter()
        .enumerate()
        .map(|(index, purl)| spdx_package(&format!("SPDXRef-{index}"), "package", Some(purl)))
        .collect();
    packages.push(spdx_package(
        "SPDXRef-duplicate",
        "package",
        Some(purls_in[2]),
    ));
    packages.push(spdx_package("SPDXRef-vendored", "vendored", None));
    packages.push(spdx_package("SPDXRef-broken", "broken", Some("not a purl")));
    let mut os = spdx_package("SPDXRef-os", "debian", Some("pkg:generic/debian@12"));
    os["primaryPackagePurpose"] = json!("OPERATING-SYSTEM");
    packages.push(os);
    let mut legacy = spdx_package("SPDXRef-legacy", "legacy", None);
    legacy["externalRefs"] = json!([{"referenceCategory": "PACKAGE_MANAGER",
        "referenceType": "purl", "referenceLocator": "pkg:npm/legacy@0.1.0"}]);
    packages.push(legacy);
    let spdx = inventory::parse(&spdx(json!(packages), json!([]))).unwrap();

    let components: Vec<serde_json::Value> = purls_in
        .iter()
        .chain(&["pkg:npm/legacy@0.1.0"])
        .map(|purl| json!({"type": "library", "name": "package", "purl": purl}))
        .collect();
    let cyclonedx = inventory::parse(
        json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "components": components})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(spdx.components, cyclonedx.components);
    let log4j = spdx
        .components
        .iter()
        .find(|component| component.ecosystem == "maven")
        .unwrap();
    assert_eq!(
        log4j.query_purl,
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    );
    assert_eq!(log4j.name, "org.apache.logging.log4j/log4j-core");
    assert_eq!(
        spdx.serial_number.as_deref(),
        Some("https://example.org/spdx/sample")
    );
    assert_eq!(
        spdx.skipped_count, 2,
        "the operating system is not a package"
    );
    assert_eq!(spdx.skipped[0].name, "vendored");
    assert_eq!(spdx.skipped[0].reason, "no package URL");
    assert_eq!(spdx.skipped[1].name, "broken");
}

#[test]
fn version_requirements_are_skipped_in_every_format() {
    for version in [
        "%5E6.1.2",
        "~1.2",
        ">=1.0",
        "1.%2A",
        "1.x",
        "1.2.X",
        "x",
        "=",
        "=%3E1.0",
        "%5B1.0,2.0)",
    ] {
        let purl = format!("pkg:npm/ava@{version}");
        let document = json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [{"type": "library", "name": "ava", "purl": purl}]});
        let sbom = inventory::parse(document.to_string().as_bytes()).unwrap();
        assert!(sbom.components.is_empty(), "{purl}");
        assert!(sbom.skipped[0].reason.starts_with("version requirement"));
        let sbom = inventory::parse(&spdx(
            json!([spdx_package("SPDXRef-ava", "ava", Some(&purl))]),
            json!([]),
        ))
        .unwrap();
        assert!(sbom.components.is_empty(), "{purl}");
    }
}

#[test]
fn versions_are_not_mistaken_for_requirements() {
    for (purl, version) in [
        // Debian versions contain a tilde, and epochs a colon.
        (
            "pkg:deb/debian/openssl@3.0.11-1~deb12u2",
            "3.0.11-1~deb12u2",
        ),
        ("pkg:deb/debian/curl@1.2.3~rc1-1", "1.2.3~rc1-1"),
        ("pkg:deb/debian/perl@1:2.3", "1:2.3"),
        ("pkg:npm/ava@1.0.0-rc.1", "1.0.0-rc.1"),
        // A Go pseudo-version, and an incompatible major version.
        (
            "pkg:golang/golang.org/x/net@v0.0.0-20191109021931-daa7c04131f5",
            "v0.0.0-20191109021931-daa7c04131f5",
        ),
        (
            "pkg:golang/github.com/docker/docker@v1.2.3%2Bincompatible",
            "v1.2.3+incompatible",
        ),
        // A Python epoch.
        ("pkg:pypi/foo@1%212.0", "1!2.0"),
        // An exact requirement allows one version, which is kept.
        ("pkg:cargo/smallvec@=1.6.0", "1.6.0"),
        ("pkg:pypi/urllib3@%3D%3D1.26.4", "1.26.4"),
    ] {
        let sbom = inventory::parse(&spdx(
            json!([spdx_package("SPDXRef-package", "package", Some(purl))]),
            json!([]),
        ))
        .unwrap();
        assert!(sbom.skipped.is_empty(), "{purl}: {:?}", sbom.skipped);
        assert_eq!(
            sbom.components[0].version.as_deref(),
            Some(version),
            "{purl}"
        );
    }
    let sbom = inventory::parse(&spdx(
        json!([spdx_package(
            "SPDXRef-smallvec",
            "smallvec",
            Some("pkg:cargo/smallvec@=1.6.0?arch=x86_64")
        )]),
        json!([]),
    ))
    .unwrap();
    assert_eq!(
        sbom.components[0].purl,
        "pkg:cargo/smallvec@1.6.0?arch=x86_64"
    );
    assert_eq!(sbom.components[0].query_purl, "pkg:cargo/smallvec@1.6.0");
}

#[test]
fn spdx_nulls_are_absent_fields() {
    let mut nameless = spdx_package("SPDXRef-nameless", "nameless", Some("pkg:npm/a@1.0.0"));
    nameless["name"] = json!(null);
    let mut without_references = spdx_package("SPDXRef-bare", "bare", None);
    without_references["externalRefs"] = json!(null);
    let mut uncategorized = spdx_package("SPDXRef-uncategorized", "uncategorized", None);
    uncategorized["externalRefs"] =
        json!([{"referenceType": "purl", "referenceLocator": "pkg:npm/b@1.0.0"}]);
    let sbom = inventory::parse(&spdx(
        json!([nameless, without_references, uncategorized]),
        json!([
            {"spdxElementId": "SPDXRef-nameless", "relationshipType": "DEPENDS_ON"},
            {"spdxElementId": "SPDXRef-nameless", "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-uncategorized"},
            {"spdxElementId": null, "relationshipType": "DEPENDS_ON",
             "relatedSpdxElement": "SPDXRef-bare"}
        ]),
    ))
    .unwrap();
    assert_eq!(purls(&sbom), ["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"]);
    assert_eq!(sbom.skipped_count, 1);
    assert_eq!(sbom.skipped[0].name, "bare");
    assert_eq!(sbom.dependencies.len(), 1);

    let sbom = inventory::parse(
        br#"{"spdxVersion": "SPDX-2.3", "packages": null, "relationships": null,
             "documentDescribes": null}"#,
    )
    .unwrap();
    assert!(sbom.components.is_empty());
}

#[test]
fn unsupported_formats_are_named() {
    let tag_value = b"SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n";
    assert_eq!(problem(tag_value), Problem::SpdxTagValue);
    let rdf = br#"<?xml version="1.0"?>
        <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
                 xmlns:spdx="http://spdx.org/rdf/terms#"><spdx:SpdxDocument/></rdf:RDF>"#;
    assert_eq!(problem(rdf), Problem::SpdxRdf);
    let turtle = b"@prefix spdx: <http://spdx.org/rdf/terms#> .\n";
    assert_eq!(problem(turtle), Problem::SpdxRdf);
    let turtle = b"# An SBOM\n\nPREFIX spdx: <http://spdx.org/rdf/terms#>\n";
    assert_eq!(problem(turtle), Problem::SpdxRdf);
    // JSON-LD with the SPDX 2 vocabulary is RDF too.
    let json_ld = br#"{"@context": {"spdx": "http://spdx.org/rdf/terms#"}, "@graph": []}"#;
    assert_eq!(problem(json_ld), Problem::SpdxRdf);
    let xml = br#"<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>"#;
    assert_eq!(problem(xml), Problem::SbomXml);
    assert!(matches!(problem(b"not json"), Problem::SbomNotJson { .. }));
    // Broken JSON naming the SPDX vocabulary is not RDF.
    assert!(matches!(
        problem(br#"{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld","#),
        Problem::SbomNotJson { .. }
    ));
    // Valid JSON of another shape is not a format nanobom knows, rather than invalid JSON.
    for document in [&b"[1, 2]"[..], b"3", br#""SPDX-2.3""#, b"null"] {
        assert_eq!(problem(document), Problem::UnknownSbomFormat);
    }

    let spdx_3 = json!({
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [{"type": "SpdxDocument", "spdxId": "https://example.org/document"}]
    });
    let spdx_3 = problem(spdx_3.to_string().as_bytes());
    assert_eq!(
        spdx_3,
        Problem::UnsupportedSpdxVersion {
            version: "SPDX-3.0.1".to_owned()
        }
    );
    assert_eq!(
        spdx_3.to_string(),
        "unsupported SPDX version \"SPDX-3.0.1\"; supported versions are SPDX-2.2, SPDX-2.3, \
         in JSON"
    );
    // An inline context.
    let spdx_3 = json!({
        "@context": {"spdx": "https://spdx.org/rdf/3.0.1/terms/",
                     "name": {"@id": "https://spdx.org/rdf/3.0.1/terms/Core/name"}},
        "@graph": []
    });
    assert_eq!(
        problem(spdx_3.to_string().as_bytes()),
        Problem::UnsupportedSpdxVersion {
            version: "SPDX-3.0.1".to_owned()
        }
    );
    assert_eq!(
        problem(br#"{"spdxVersion": "SPDX-2.1", "packages": []}"#),
        Problem::UnsupportedSpdxVersion {
            version: "SPDX-2.1".to_owned()
        }
    );
    assert!(matches!(
        problem(br#"{"spdxVersion": "SPDX-2.3", "packages": 3}"#),
        Problem::InvalidSpdx { .. }
    ));
    // Type errors in a recognized document are about that document, not about JSON.
    assert!(matches!(
        problem(br#"{"spdxVersion": 2, "packages": []}"#),
        Problem::InvalidSpdx { .. }
    ));
    assert!(matches!(
        problem(br#"{"bomFormat": "CycloneDX", "specVersion": 1.5}"#),
        Problem::InvalidCycloneDx { .. }
    ));
    assert_eq!(problem(br#"{"name": "sbom"}"#), Problem::UnknownSbomFormat);
    assert!(
        Problem::UnknownSbomFormat
            .to_string()
            .contains("SPDX JSON document")
    );
}

#[test]
fn echoed_values_are_cut() {
    let long = "9".repeat(10_000);
    let cut = format!("{}\u{2026}", &long[..200]);
    let document = json!({"spdxVersion": format!("SPDX-{long}")});
    assert_eq!(
        problem(document.to_string().as_bytes()),
        Problem::UnsupportedSpdxVersion {
            version: format!("SPDX-{}\u{2026}", &long[..195])
        }
    );
    let document = json!({"bomFormat": "CycloneDX", "specVersion": long});
    assert_eq!(
        problem(document.to_string().as_bytes()),
        Problem::UnsupportedSpecificationVersion {
            version: cut.clone()
        }
    );
    let document = json!({"@context": format!("https://spdx.org/rdf/{long}/context")});
    assert_eq!(
        problem(document.to_string().as_bytes()),
        Problem::SpdxRdf,
        "a segment too long for a version"
    );

    for document in [
        json!({"spdxVersion": "SPDX-2.3", "packages": long}),
        json!({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": long}),
    ] {
        let detail = match problem(document.to_string().as_bytes()) {
            Problem::InvalidSpdx { detail } | Problem::InvalidCycloneDx { detail } => detail,
            other => panic!("{other:?}"),
        };
        assert_eq!(detail.chars().count(), 201, "{detail}");
        assert!(detail.ends_with('\u{2026}'));
    }
}

#[test]
fn documents_that_claim_both_formats_are_cyclonedx() {
    let sbom = inventory::parse(
        br#"{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
             "spdxVersion": "SPDX-2.3", "components": []}"#,
    )
    .unwrap();
    assert_eq!(sbom.specification_version, "1.6");
}

#[test]
fn large_contexts_are_read_without_building_them() {
    let mut document = br#"{"name": "sbom", "@context": ["#.to_vec();
    document.extend(b"0,".repeat(4 * 1024 * 1024));
    document.extend(br#"{"spdx": "https://spdx.org/rdf/3.0.1/terms/"}]}"#);
    assert_eq!(
        problem(&document),
        Problem::UnsupportedSpdxVersion {
            version: "SPDX-3.0.1".to_owned()
        }
    );
}

struct Fixture {
    database: DatabaseConnection,
    owner: Actor,
    viewer: Actor,
    organization: i64,
}

async fn setup() -> Fixture {
    let database = testing::database().await;
    let owner = users::create(
        &database,
        NewUser {
            username: "owner".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let owner = Actor::from_user(&owner);
    let viewer = users::create(
        &database,
        NewUser {
            username: "viewer".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    let viewer = Actor::from_user(&viewer);
    let organization = organizations::create(&database, &owner, "acme", "Acme")
        .await
        .unwrap()
        .id;
    memberships::add(&database, &owner, organization, "viewer", Role::Viewer)
        .await
        .unwrap();
    Fixture {
        database,
        owner,
        viewer,
        organization,
    }
}

#[tokio::test]
async fn tokens_are_shown_once_and_stored_hashed() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    assert!(created.secret.starts_with("nanobom_"));
    assert_eq!(created.secret.len(), "nanobom_".len() + 64);
    assert!(created.secret.starts_with(&created.token.prefix));

    let listed = tokens::list(database, &fixture.owner, fixture.organization)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].last_used_at.is_none());
    assert!(matches!(
        tokens::list(database, &fixture.viewer, fixture.organization).await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        tokens::create(database, &fixture.viewer, fixture.organization, None, "x").await,
        Err(Error::Forbidden)
    ));

    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    assert!(token.last_used_at.is_some());
    assert_ne!(token.token_hash, created.secret);
    assert!(
        tokens::authenticate(database, "nanobom_wrong")
            .await
            .unwrap()
            .is_none()
    );

    tokens::revoke(database, &fixture.owner, created.token.id)
        .await
        .unwrap();
    assert!(
        tokens::authenticate(database, &created.secret)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn organization_tokens_create_projects_and_uploads_replace_components() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();

    let outcome = inventory::ingest(
        database,
        &token,
        "acme",
        "Web",
        inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap(),
        UploadSource {
            source_commit: Some("0123abcd".to_owned()),
            image_tag: None,
        },
    )
    .await
    .unwrap();
    assert!(outcome.project_created);
    assert_eq!(outcome.project, "web");
    assert_eq!(outcome.component_count, 3);

    let second = inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    assert!(!second.project_created);
    assert_eq!(second.project_id, outcome.project_id);

    let components = inventory::components(database, &fixture.viewer, outcome.project_id)
        .await
        .unwrap();
    let current: Vec<_> = components
        .iter()
        .map(|component| component.purl.as_str())
        .collect();
    assert_eq!(current, ["pkg:pypi/idna@3.6", "pkg:pypi/urllib3@1.26.4"]);

    let history = inventory::uploads(database, &fixture.viewer, outcome.project_id)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].source_commit.as_deref(), Some("0123abcd"));
    assert_eq!(history[1].component_count, 3);
    let project = projects::find(database, &fixture.viewer, fixture.organization, "web")
        .await
        .unwrap();
    assert!(project.last_upload_at.is_some());
}

#[tokio::test]
async fn project_tokens_only_reach_their_project() {
    let fixture = setup().await;
    let database = &fixture.database;
    projects::create(database, &fixture.owner, fixture.organization, "api", "API")
        .await
        .unwrap();
    projects::create(database, &fixture.owner, fixture.organization, "web", "Web")
        .await
        .unwrap();
    let created = tokens::create(
        database,
        &fixture.owner,
        fixture.organization,
        Some("api"),
        "API CI",
    )
    .await
    .unwrap();
    assert_eq!(created.token.project_slug.as_deref(), Some("api"));
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    let sbom = || inventory::parse(&sbom_document("cargo-cyclonedx.json")).unwrap();

    inventory::ingest(
        database,
        &token,
        "acme",
        "api",
        sbom(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "acme",
            "web",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::Forbidden)
    ));
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "acme",
            "new",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
    let other = organizations::create(database, &fixture.owner, "other", "Other")
        .await
        .unwrap();
    projects::create(database, &fixture.owner, other.id, "api", "API")
        .await
        .unwrap();
    assert!(matches!(
        inventory::ingest(
            database,
            &token,
            "other",
            "api",
            sbom(),
            UploadSource::default()
        )
        .await,
        Err(Error::NotFound)
    ));
}

/// A search says whether the cap cut it: exactly the cap is complete, one more is not.
#[tokio::test]
async fn search_says_when_results_were_cut() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    let upload = |count: usize| {
        let components: Vec<_> = (0..count)
            .map(|index| {
                serde_json::json!({
                    "type": "library",
                    "name": format!("widget-{index:03}"),
                    "version": "1.0.0",
                    "purl": format!("pkg:npm/widget-{index:03}@1.0.0")
                })
            })
            .collect();
        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": components
        })
        .to_string()
    };
    let maximum = inventory::MAXIMUM_SEARCH_RESULTS;
    for (count, truncated) in [(maximum, false), (maximum + 1, true)] {
        inventory::ingest(
            database,
            &token,
            "acme",
            "web",
            inventory::parse(upload(count).as_bytes()).unwrap(),
            UploadSource::default(),
        )
        .await
        .unwrap();
        let found = inventory::search_results(database, &fixture.viewer, "widget")
            .await
            .unwrap();
        assert_eq!(found.matches.len(), maximum, "{count} components");
        assert_eq!(found.truncated, truncated, "{count} components");
        assert_eq!(found.matches[0].name, "widget-000");
        let plain = inventory::search(database, &fixture.viewer, "widget")
            .await
            .unwrap();
        assert_eq!(plain, found.matches);
    }
    let none = inventory::search_results(database, &fixture.viewer, "  ")
        .await
        .unwrap();
    assert!(none.matches.is_empty() && !none.truncated);
}

#[tokio::test]
async fn search_ignores_the_case_of_versions_too() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    let document = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [{
            "type": "library",
            "name": "Widget",
            "version": "1.0.0-RC1",
            "purl": "pkg:npm/Widget@1.0.0-RC1"
        }]
    });
    inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(document.to_string().as_bytes()).unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    for query in ["widget 1.0.0-rc", "WIDGET@1.0.0-RC1", "widget 1.0.0-rc2"] {
        let found = inventory::search(database, &fixture.viewer, query)
            .await
            .unwrap();
        assert_eq!(
            found.len(),
            usize::from(query != "widget 1.0.0-rc2"),
            "{query}"
        );
    }
}

#[tokio::test]
async fn search_finds_components_by_name_and_version_in_visible_organizations() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();

    let found = inventory::search(database, &fixture.viewer, "Lodash")
        .await
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].organization_slug, "acme");
    assert_eq!(found[0].project_slug, "web");
    assert_eq!(found[0].version.as_deref(), Some("4.17.20"));
    assert_eq!(
        inventory::search(database, &fixture.viewer, "lodash 4.17")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        inventory::search(database, &fixture.viewer, "lodash@4.17.2")
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        inventory::search(database, &fixture.viewer, "lodash 5")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        inventory::search(database, &fixture.viewer, "  ")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        inventory::search(database, &fixture.viewer, "lod_sh")
            .await
            .unwrap()
            .is_empty(),
        "wildcards in the query match themselves"
    );

    let outsider = users::create(
        database,
        NewUser {
            username: "outsider".to_owned(),
            ..NewUser::default()
        },
        true,
    )
    .await
    .unwrap();
    let outsider = Actor::from_user(&outsider);
    assert!(
        inventory::search(database, &outsider, "lodash")
            .await
            .unwrap()
            .is_empty()
    );
}

// Licenses.

/// The license of each component of a parsed SBOM, by package URL.
fn licenses(sbom: &ParsedSbom) -> Vec<(&str, Option<&str>)> {
    sbom.components
        .iter()
        .map(|component| (component.purl.as_str(), component.license.as_deref()))
        .collect()
}

/// A CycloneDX 1.7 document with one npm component per `licenses` value, named `a`, `b`…
fn cyclonedx_with_licenses(licenses: &[serde_json::Value]) -> Vec<u8> {
    let components: Vec<_> = licenses
        .iter()
        .zip('a'..)
        .map(|(licenses, name)| {
            let mut component = json!({
                "type": "library",
                "name": name.to_string(),
                "version": "1.0.0",
                "purl": format!("pkg:npm/{name}@1.0.0"),
            });
            if !licenses.is_null() {
                component["licenses"] = licenses.clone();
            }
            component
        })
        .collect();
    json!({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1, "components": components})
        .to_string()
        .into_bytes()
}

#[test]
fn cyclonedx_licenses_become_one_expression() {
    let long_name = "x".repeat(inventory::MAXIMUM_LICENSE_LENGTH + 1);
    let sbom = inventory::parse(&cyclonedx_with_licenses(&[
        json!([{"expression": " MIT OR Apache-2.0 "}]),
        json!([{"license": {"id": "MIT"}}]),
        json!([{"license": {"name": "Acme Commercial License"}}]),
        // Sorted and without duplicates, whatever the order of the document.
        json!([
            {"license": {"id": "MIT"}},
            {"license": {"id": "Apache-2.0"}},
            {"license": {"id": "MIT"}}
        ]),
        // CycloneDX 1.7 allows expressions next to licenses.
        json!([{"license": {"id": "BSD-3-Clause"}}, {"expression": "MIT OR Apache-2.0"}]),
        json!([]),
        serde_json::Value::Null,
        json!([{"license": {"name": long_name}}]),
    ]))
    .unwrap();
    assert_eq!(
        licenses(&sbom),
        [
            ("pkg:npm/a@1.0.0", Some("MIT OR Apache-2.0")),
            ("pkg:npm/b@1.0.0", Some("MIT")),
            ("pkg:npm/c@1.0.0", Some("Acme Commercial License")),
            ("pkg:npm/d@1.0.0", Some("Apache-2.0 AND MIT")),
            (
                "pkg:npm/e@1.0.0",
                Some("BSD-3-Clause AND (MIT OR Apache-2.0)")
            ),
            ("pkg:npm/f@1.0.0", None),
            ("pkg:npm/g@1.0.0", None),
            ("pkg:npm/h@1.0.0", None),
        ]
    );
}

#[test]
fn generators_licenses_are_read() {
    let npm = inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap();
    assert!(
        npm.components
            .iter()
            .all(|component| component.license.as_deref() == Some("MIT"))
    );
    let python = inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap();
    assert_eq!(
        licenses(&python),
        [
            (
                "pkg:pypi/idna@3.6",
                Some("License :: OSI Approved :: BSD License")
            ),
            ("pkg:pypi/urllib3@1.26.4", Some("MIT")),
        ]
    );
    let github = inventory::parse(&sbom_document("github-dependency-graph.json")).unwrap();
    assert!(
        licenses(&github).contains(&("pkg:cargo/clap_derive@4.5.18", Some("MIT OR Apache-2.0"))),
        "{:?}",
        licenses(&github)
    );
    let syft = inventory::parse(&sbom_document("syft-cargo-spdx-2.2.json")).unwrap();
    assert!(
        syft.components
            .iter()
            .all(|component| component.license.is_none())
    );
}

#[test]
fn spdx_licenses_prefer_the_concluded_one() {
    let package = |name: &str, concluded: serde_json::Value, declared: serde_json::Value| {
        let mut package = spdx_package(
            &format!("SPDXRef-{name}"),
            name,
            Some(&format!("pkg:npm/{name}@1.0")),
        );
        if !concluded.is_null() {
            package["licenseConcluded"] = concluded;
        }
        if !declared.is_null() {
            package["licenseDeclared"] = declared;
        }
        package
    };
    let null = serde_json::Value::Null;
    let document = spdx(
        json!([
            package("a", json!("MIT"), json!("Apache-2.0")),
            package("b", json!("NOASSERTION"), json!("Apache-2.0")),
            package("c", json!("NONE"), json!("GPL-2.0-only OR MIT")),
            package("d", null.clone(), json!("BSD-2-Clause")),
            package("e", json!("NOASSERTION"), json!("NOASSERTION")),
            package("f", json!("NONE"), json!("NONE")),
            package("g", json!(" LicenseRef-Acme "), null.clone()),
            // Not a string: ignored rather than refusing the document.
            package("h", json!({"id": "MIT"}), json!("ISC")),
            package("i", null.clone(), null),
        ]),
        json!([]),
    );
    let sbom = inventory::parse(&document).unwrap();
    assert_eq!(
        licenses(&sbom),
        [
            ("pkg:npm/a@1.0", Some("MIT")),
            ("pkg:npm/b@1.0", Some("Apache-2.0")),
            ("pkg:npm/c@1.0", Some("GPL-2.0-only OR MIT")),
            ("pkg:npm/d@1.0", Some("BSD-2-Clause")),
            ("pkg:npm/e@1.0", None),
            ("pkg:npm/f@1.0", None),
            ("pkg:npm/g@1.0", Some("LicenseRef-Acme")),
            ("pkg:npm/h@1.0", Some("ISC")),
            ("pkg:npm/i@1.0", None),
        ]
    );
}

/// How many components a search by name and license finds.
async fn found(fixture: &Fixture, query: &str, license: &str) -> usize {
    inventory::search_by_license(&fixture.database, &fixture.viewer, query, license)
        .await
        .unwrap()
        .matches
        .len()
}

#[tokio::test]
async fn licenses_are_replaced_with_each_upload_and_searchable() {
    let fixture = setup().await;
    let database = &fixture.database;
    let created = tokens::create(database, &fixture.owner, fixture.organization, None, "CI")
        .await
        .unwrap();
    let token = tokens::authenticate(database, &created.secret)
        .await
        .unwrap()
        .unwrap();
    for (licenses, expected) in [
        (json!([{"license": {"id": "MIT"}}]), Some("MIT")),
        (
            json!([{"expression": "GPL-3.0-only"}]),
            Some("GPL-3.0-only"),
        ),
        (serde_json::Value::Null, None),
    ] {
        let outcome = inventory::ingest(
            database,
            &token,
            "acme",
            "web",
            inventory::parse(&cyclonedx_with_licenses(&[licenses])).unwrap(),
            UploadSource::default(),
        )
        .await
        .unwrap();
        let components = inventory::components(database, &fixture.viewer, outcome.project_id)
            .await
            .unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].license.as_deref(), expected);
        assert_eq!(
            found(&fixture, "", "gpl").await,
            usize::from(expected == Some("GPL-3.0-only")),
            "{expected:?}"
        );
    }

    inventory::ingest(
        database,
        &token,
        "acme",
        "web",
        inventory::parse(&cyclonedx_with_licenses(&[
            json!([{"expression": "GPL-3.0-only"}]),
        ]))
        .unwrap(),
        UploadSource::default(),
    )
    .await
    .unwrap();
    let matches = inventory::search_by_license(database, &fixture.viewer, "", "GPL")
        .await
        .unwrap()
        .matches;
    assert_eq!(matches[0].license.as_deref(), Some("GPL-3.0-only"));
    // Name and license together.
    assert_eq!(found(&fixture, "a", "gpl-3").await, 1);
    assert_eq!(found(&fixture, "b", "gpl").await, 0);
    assert_eq!(found(&fixture, "", "MIT").await, 0);
    assert_eq!(
        found(&fixture, "", "gp_").await,
        0,
        "wildcards match themselves"
    );
    assert_eq!(found(&fixture, " ", " ").await, 0);
}
