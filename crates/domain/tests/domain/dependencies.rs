//! The dependency graph of an SBOM: what each generator gives, how it is stored with the
//! components, and the paths shown on findings, in webhooks and to CI.

use std::sync::Arc;

use nanobom_domain::{
    Error,
    access::Actor,
    dependencies::{self, ComponentRef, DependencyPaths},
    evaluation::{Evaluator, Scope, Trigger},
    findings::{self, Filter},
    inventory::{self, DependencyEdge, ParsedSbom, UploadSource},
    notifications, organizations, testing,
    testing::FakeSource,
    tokens,
    users::{self, NewUser},
};
use nanobom_entity::{component_dependencies, projects};
use nanobom_osv::Severity;
use sea_orm::{DatabaseConnection, EntityTrait, PaginatorTrait};
use serde_json::json;

const LODASH: &str = "pkg:npm/lodash@4.17.20";
const FRAMEWORK: &str = "pkg:npm/web-framework@2.1.0";
const ENGINE: &str = "pkg:npm/template-engine@0.9.0";
const LEFT_PAD: &str = "pkg:npm/left-pad@1.0.0";

fn sbom_document(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/sboms/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {path}: {error}"))
}

fn edge(parent: Option<&str>, child: &str) -> DependencyEdge {
    DependencyEdge {
        parent: parent.map(str::to_owned),
        child: child.to_owned(),
    }
}

/// `shop` depends on `web-framework` -> `template-engine` -> `lodash`, on `left-pad`, and on a
/// vendored package without a package URL that also depends on `lodash`.
fn shop_document() -> serde_json::Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "shop"}},
        "components": [
            {"type": "library", "name": "web-framework", "version": "2.1.0", "bom-ref": "framework", "purl": FRAMEWORK},
            {"type": "library", "name": "template-engine", "version": "0.9.0", "bom-ref": "engine", "purl": ENGINE},
            {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash", "purl": LODASH},
            {"type": "library", "name": "vendored", "bom-ref": "vendored"},
            {"type": "library", "name": "left-pad", "version": "1.0.0", "bom-ref": "left-pad", "purl": LEFT_PAD}
        ],
        "dependencies": [
            {"ref": "shop", "dependsOn": ["framework", "vendored", "left-pad"]},
            {"ref": "framework", "dependsOn": ["engine", "shop"]},
            {"ref": "engine", "dependsOn": ["lodash", "engine", "missing"]},
            {"ref": "vendored", "dependsOn": ["lodash"]},
            {"ref": "left-pad"}
        ]
    })
}

fn parse(document: &serde_json::Value) -> ParsedSbom {
    inventory::parse(document.to_string().as_bytes()).unwrap()
}

#[test]
fn cargo_cyclonedx_and_cyclonedx_npm_describe_the_project() {
    let sbom = inventory::parse(&sbom_document("cargo-cyclonedx.json")).unwrap();
    assert_eq!(
        sbom.dependencies,
        [
            edge(None, "pkg:cargo/itoa@1.0.18"),
            edge(None, "pkg:cargo/smallvec@1.6.0"),
        ]
    );
    let sbom = inventory::parse(&sbom_document("cyclonedx-npm.json")).unwrap();
    assert_eq!(
        sbom.dependencies,
        [
            edge(None, "pkg:npm/%40babel/helper-string-parser@7.25.9"),
            edge(None, "pkg:npm/lodash@4.17.20"),
            edge(None, "pkg:npm/minimist@1.2.5"),
        ]
    );
}

#[test]
fn cyclonedx_py_and_syft_leave_the_project_out() {
    // An environment has no project: the graph links packages only.
    let sbom = inventory::parse(&sbom_document("cyclonedx-py.json")).unwrap();
    assert_eq!(
        sbom.dependencies,
        [edge(Some("pkg:pypi/urllib3@1.26.4"), "pkg:pypi/idna@3.6")]
    );
    // An image names itself in the metadata, but no package depends on it.
    let sbom = inventory::parse(&sbom_document("syft.json")).unwrap();
    assert!(!sbom.dependencies.is_empty());
    assert!(sbom.dependencies.iter().all(|edge| edge.parent.is_some()));
}

#[test]
fn edges_through_components_that_are_not_kept_are_dropped() {
    let sbom = parse(&shop_document());
    assert_eq!(
        sbom.dependencies,
        [
            edge(None, LEFT_PAD),
            edge(None, FRAMEWORK),
            edge(Some(ENGINE), LODASH),
            edge(Some(FRAMEWORK), ENGINE),
        ],
        "no edge to the project, to itself, to an unknown reference or through `vendored`"
    );

    let mut document = shop_document();
    document.as_object_mut().unwrap().remove("dependencies");
    assert!(parse(&document).dependencies.is_empty());
}

#[test]
fn links_lost_through_dropped_components_are_flagged() {
    assert!(parse(&shop_document()).dependencies_partial);

    // `vendored` has no package URL. A path breaks only if the graph enters and leaves it.
    let mut document = shop_document();
    document["dependencies"] = json!([
        {"ref": "shop", "dependsOn": ["framework"]},
        {"ref": "framework", "dependsOn": ["engine", "vendored"]},
        {"ref": "vendored"}
    ]);
    assert!(!parse(&document).dependencies_partial, "left by nothing");
    document["dependencies"] = json!([
        {"ref": "shop", "dependsOn": ["framework"]},
        {"ref": "vendored", "dependsOn": ["lodash"]}
    ]);
    assert!(!parse(&document).dependencies_partial, "entered by nothing");
    document.as_object_mut().unwrap().remove("dependencies");
    assert!(!parse(&document).dependencies_partial);
}

#[test]
fn a_reference_shared_by_two_packages_is_dropped() {
    // `dup` names two packages: `shop -> dup -> lodash` would attach the edges to whichever
    // came last and make up a path.
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "shop"}},
        "components": [
            {"type": "library", "name": "web-framework", "version": "2.1.0", "bom-ref": "dup", "purl": FRAMEWORK},
            {"type": "library", "name": "template-engine", "version": "0.9.0", "bom-ref": "dup", "purl": ENGINE},
            {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash", "purl": LODASH},
            {"type": "library", "name": "left-pad", "version": "1.0.0", "bom-ref": "left-pad", "purl": LEFT_PAD}
        ],
        "dependencies": [
            {"ref": "shop", "dependsOn": ["dup", "left-pad"]},
            {"ref": "dup", "dependsOn": ["lodash"]}
        ]
    });
    let sbom = parse(&document);
    assert_eq!(sbom.components.len(), 4, "the components are kept");
    assert_eq!(sbom.dependencies, [edge(None, LEFT_PAD)]);
    assert!(sbom.dependencies_partial);

    // The same reference on copies of one package is not ambiguous.
    let document = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "shop", "bom-ref": "shop"}},
        "components": [
            {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash", "purl": LODASH,
                "components": [
                    {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash", "purl": LODASH}
                ]}
        ],
        "dependencies": [{"ref": "shop", "dependsOn": ["lodash"]}]
    });
    let sbom = parse(&document);
    assert_eq!(sbom.dependencies, [edge(None, LODASH)]);
    assert!(!sbom.dependencies_partial);
}

/// [`shop_document`] in SPDX, as relationships: `shop` is the package the document
/// describes. The project also contains `lodash`, as a scanned directory contains every
/// package, which is not a dependency.
fn shop_spdx() -> serde_json::Value {
    let package = |id: &str, name: &str, version: &str, purl: Option<&str>| {
        let mut package = json!({"SPDXID": id, "name": name, "versionInfo": version});
        if let Some(purl) = purl {
            package["externalRefs"] = json!([{"referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl", "referenceLocator": purl}]);
        }
        package
    };
    let relationship = |from: &str, kind: &str, to: &str| json!({"spdxElementId": from, "relationshipType": kind, "relatedSpdxElement": to});
    json!({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "shop",
        "packages": [
            package("SPDXRef-shop", "shop", "1.0.0", Some("pkg:npm/shop@1.0.0")),
            package("SPDXRef-framework", "web-framework", "2.1.0", Some(FRAMEWORK)),
            package("SPDXRef-engine", "template-engine", "0.9.0", Some(ENGINE)),
            package("SPDXRef-lodash", "lodash", "4.17.20", Some(LODASH)),
            package("SPDXRef-vendored", "vendored", "1.0", None),
            package("SPDXRef-left-pad", "left-pad", "1.0.0", Some(LEFT_PAD)),
        ],
        "relationships": [
            relationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-shop"),
            relationship("SPDXRef-shop", "DEPENDS_ON", "SPDXRef-framework"),
            relationship("SPDXRef-shop", "DEPENDS_ON", "SPDXRef-vendored"),
            relationship("SPDXRef-left-pad", "DEPENDENCY_OF", "SPDXRef-shop"),
            relationship("SPDXRef-shop", "CONTAINS", "SPDXRef-lodash"),
            relationship("SPDXRef-framework", "DEPENDS_ON", "SPDXRef-shop"),
            relationship("SPDXRef-engine", "RUNTIME_DEPENDENCY_OF", "SPDXRef-framework"),
            relationship("SPDXRef-engine", "CONTAINS", "SPDXRef-lodash"),
            relationship("SPDXRef-engine", "DEPENDS_ON", "SPDXRef-engine"),
            relationship("SPDXRef-engine", "DEPENDS_ON", "SPDXRef-missing"),
            relationship("SPDXRef-vendored", "DEPENDS_ON", "SPDXRef-lodash"),
            relationship("SPDXRef-lodash", "OTHER", "SPDXRef-framework"),
        ]
    })
}

#[test]
fn spdx_relationships_follow_the_same_rules() {
    let spdx = parse(&shop_spdx());
    // The same edges, except the project's to `left-pad`, which nothing links to another
    // package: a flat list of a lock file's packages looks the same (see below).
    let mut expected = parse(&shop_document()).dependencies;
    expected.retain(|kept| *kept != edge(None, LEFT_PAD));
    assert_eq!(spdx.dependencies, expected);
    assert_eq!(
        spdx.components.len(),
        4,
        "the described package is the project"
    );
    assert!(
        spdx.dependencies_partial,
        "the graph goes through the vendored package, which has no package URL"
    );

    // SPDX 2.2 names the project in `documentDescribes`.
    let mut document = shop_spdx();
    document["spdxVersion"] = json!("SPDX-2.2");
    document["documentDescribes"] = json!(["SPDXRef-shop"]);
    document["relationships"].as_array_mut().unwrap().remove(0);
    assert_eq!(parse(&document).dependencies, spdx.dependencies);
}

#[test]
fn spdx_generators_give_what_their_relationships_allow() {
    // Syft: the dependencies between crates, but the scanned directory only contains them.
    let sbom = inventory::parse(&sbom_document("syft-cargo-spdx-2.2.json")).unwrap();
    assert_eq!(
        sbom.dependencies,
        [
            edge(
                Some("pkg:cargo/aho-corasick@0.7.20"),
                "pkg:cargo/memchr@2.8.3"
            ),
            edge(
                Some("pkg:cargo/fixture-cargo@0.1.0"),
                "pkg:cargo/regex@1.5.4"
            ),
            edge(
                Some("pkg:cargo/fixture-cargo@0.1.0"),
                "pkg:cargo/smallvec@1.6.0"
            ),
            edge(
                Some("pkg:cargo/regex@1.5.4"),
                "pkg:cargo/aho-corasick@0.7.20"
            ),
            edge(Some("pkg:cargo/regex@1.5.4"), "pkg:cargo/memchr@2.8.3"),
            edge(
                Some("pkg:cargo/regex@1.5.4"),
                "pkg:cargo/regex-syntax@0.6.29"
            ),
        ]
    );
    assert!(!sbom.dependencies_partial);
    let sbom = inventory::parse(&sbom_document("syft-spdx.json")).unwrap();
    assert!(!sbom.dependencies.is_empty());
    assert!(sbom.dependencies.iter().all(|edge| edge.parent.is_some()));
    assert!(!sbom.dependencies_partial);

    // Trivy: the direct dependencies hang from the lock file's entry, which has no package
    // URL, so only the edge between packages is left.
    let sbom = inventory::parse(&sbom_document("trivy-npm-spdx.json")).unwrap();
    assert_eq!(
        sbom.dependencies,
        [edge(Some("pkg:npm/debug@2.6.8"), "pkg:npm/ms@2.0.0")]
    );
    assert!(sbom.dependencies_partial);

    // GitHub, Cargo: the repository depends on every crate of the lock file, transitive ones
    // included, with no edge between crates: no direct dependency can be told apart.
    let sbom = inventory::parse(&sbom_document("github-dependency-graph.json")).unwrap();
    assert!(sbom.dependencies.is_empty());

    // GitHub, npm: the repository depends on its direct dependencies (development ones
    // included), with the graph below them. Those that depend on nothing and that nothing
    // else depends on look like a flat list, and are left out.
    let sbom = inventory::parse(&sbom_document("github-npm-dependency-graph.json")).unwrap();
    let direct: Vec<&str> = sbom
        .dependencies
        .iter()
        .filter(|edge| edge.parent.is_none())
        .map(|edge| edge.child.as_str())
        .collect();
    assert_eq!(
        direct,
        [
            "pkg:npm/asynct@1.1.0",
            "pkg:npm/duplexer@0.1.1",
            "pkg:npm/it-is@1.0.3",
            "pkg:npm/pause-stream@0.0.11",
            "pkg:npm/split@1.0.1",
            "pkg:npm/stream-combiner@0.2.2",
            "pkg:npm/stream-spec@0.3.6",
            "pkg:npm/tape@4.9.1",
            "pkg:npm/through@2.3.8",
        ]
    );
    assert_eq!(sbom.dependencies.len() - direct.len(), 87);
    assert!(!sbom.dependencies_partial);
}

/// A package of `shop_spdx` the project depends on, in another ecosystem or not.
fn flat_package(document: &mut serde_json::Value, name: &str, purl: &str) {
    let id = format!("SPDXRef-{name}");
    document["packages"].as_array_mut().unwrap().push(
        json!({"SPDXID": id, "name": name, "versionInfo": "1.0.0",
        "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
            "referenceLocator": purl}]}),
    );
    document["relationships"].as_array_mut().unwrap().push(
        json!({"spdxElementId": "SPDXRef-shop", "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": id}),
    );
}

#[test]
fn spdx_project_edges_need_a_linked_package() {
    // A repository with a graphed npm lock file, a flat one, and a flat `Cargo.lock`: the
    // flat lists are not direct dependencies, whatever their ecosystem.
    let mut document = shop_spdx();
    flat_package(&mut document, "itoa", "pkg:cargo/itoa@1.0.0");
    flat_package(&mut document, "flat-a", "pkg:npm/flat-a@1.0.0");
    flat_package(&mut document, "flat-b", "pkg:npm/flat-b@1.0.0");
    let sbom = parse(&document);
    assert_eq!(sbom.components.len(), 7);
    assert_eq!(sbom.dependencies, parse(&shop_spdx()).dependencies);

    // A flat-listed package that is also linked to another one keeps its edge.
    document["relationships"].as_array_mut().unwrap().push(
        json!({"spdxElementId": "SPDXRef-flat-a", "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-lodash"}),
    );
    let dependencies = parse(&document).dependencies;
    assert!(dependencies.contains(&edge(None, "pkg:npm/flat-a@1.0.0")));
    assert!(!dependencies.contains(&edge(None, "pkg:npm/flat-b@1.0.0")));
}

#[test]
fn spdx_identifiers_given_to_several_packages_are_ambiguous() {
    let package = |id: &str, purl: Option<&str>| {
        let mut package = json!({"SPDXID": id, "name": id, "versionInfo": "1.0.0"});
        if let Some(purl) = purl {
            package["externalRefs"] = json!([{"referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl", "referenceLocator": purl}]);
        }
        package
    };
    let depends = |from: &str, to: &str| json!({"spdxElementId": from, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": to});
    let document = |packages: Vec<serde_json::Value>| {
        json!({
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": packages,
            "relationships": [
                depends("SPDXRef-framework", "SPDXRef-same"),
                depends("SPDXRef-same", "SPDXRef-lodash"),
            ]
        })
    };
    let framework = || package("SPDXRef-framework", Some(FRAMEWORK));
    let lodash = || package("SPDXRef-lodash", Some(LODASH));

    // Two copies of one package: the identifier is not ambiguous.
    let sbom = parse(&document(vec![
        framework(),
        lodash(),
        package("SPDXRef-same", Some(ENGINE)),
        package("SPDXRef-same", Some(ENGINE)),
    ]));
    assert_eq!(sbom.dependencies.len(), 2);
    assert!(!sbom.dependencies_partial);

    // Two packages, or a package and one without a package URL, whichever comes first.
    for duplicates in [
        [
            package("SPDXRef-same", Some(ENGINE)),
            package("SPDXRef-same", Some(LEFT_PAD)),
        ],
        [
            package("SPDXRef-same", Some(ENGINE)),
            package("SPDXRef-same", None),
        ],
        [
            package("SPDXRef-same", None),
            package("SPDXRef-same", Some(ENGINE)),
        ],
    ] {
        let mut packages = vec![framework(), lodash()];
        packages.extend(duplicates);
        let sbom = parse(&document(packages));
        assert!(sbom.dependencies.is_empty(), "{:?}", sbom.dependencies);
        assert!(sbom.dependencies_partial);
    }
}

struct Fixture {
    database: DatabaseConnection,
    source: Arc<FakeSource>,
    evaluator: Evaluator<FakeSource>,
    owner: Actor,
    organization: i64,
    secret: String,
}

impl Fixture {
    async fn new() -> Self {
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
        let organization = organizations::create(&database, &owner, "acme", "Acme")
            .await
            .unwrap()
            .id;
        let secret = tokens::create(&database, &owner, organization, None, "CI")
            .await
            .unwrap()
            .secret;
        let source = Arc::new(FakeSource::default());
        let evaluator = Evaluator::new(database.clone(), Arc::clone(&source));
        Self {
            database,
            source,
            evaluator,
            owner,
            organization,
            secret,
        }
    }

    async fn upload(&self, sbom: ParsedSbom) -> i64 {
        let token = tokens::authenticate(&self.database, &self.secret)
            .await
            .unwrap()
            .unwrap();
        inventory::ingest(
            &self.database,
            &token,
            "acme",
            "shop",
            sbom,
            UploadSource::default(),
        )
        .await
        .unwrap()
        .project_id
    }

    async fn paths(&self, project: i64, purl: &str) -> Option<DependencyPaths> {
        dependencies::paths(&self.database, &self.owner, project, purl)
            .await
            .unwrap()
    }

    /// The flag stored on the project by its latest upload.
    async fn partial(&self, project: i64) -> bool {
        projects::Entity::find_by_id(project)
            .one(&self.database)
            .await
            .unwrap()
            .unwrap()
            .dependencies_partial
    }

    async fn edge_count(&self) -> u64 {
        component_dependencies::Entity::find()
            .count(&self.database)
            .await
            .unwrap()
    }
}

fn component(purl: &str, name: &str, version: &str) -> ComponentRef {
    ComponentRef {
        purl: purl.to_owned(),
        name: name.to_owned(),
        version: Some(version.to_owned()),
    }
}

fn lodash_advisory() -> serde_json::Value {
    json!({
        "id": "GHSA-35jh-r3h4-6jhm",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command Injection in lodash",
        "database_specific": {"severity": "HIGH"}
    })
}

#[tokio::test]
async fn uploads_replace_the_graph_with_the_components() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(parse(&shop_document())).await;
    assert_eq!(fixture.edge_count().await, 4);
    assert_eq!(
        fixture.paths(project, LODASH).await,
        Some(DependencyPaths {
            paths: vec![vec![
                component(FRAMEWORK, "web-framework", "2.1.0"),
                component(ENGINE, "template-engine", "0.9.0"),
                component(LODASH, "lodash", "4.17.20"),
            ]],
            more: 0,
            // `vendored` has no package URL, and the graph goes through it.
            partial: true,
        })
    );
    assert_eq!(
        fixture.paths(project, LEFT_PAD).await.unwrap().paths,
        [vec![component(LEFT_PAD, "left-pad", "1.0.0")]]
    );

    // lodash becomes a direct dependency: the old path goes with the old upload.
    let mut document = shop_document();
    document["dependencies"] = json!([
        {"ref": "shop", "dependsOn": ["lodash", "left-pad"]},
        {"ref": "framework", "dependsOn": ["engine"]}
    ]);
    fixture.upload(parse(&document)).await;
    assert_eq!(fixture.edge_count().await, 3);
    let paths = fixture.paths(project, LODASH).await.unwrap();
    assert_eq!(paths.paths, [vec![component(LODASH, "lodash", "4.17.20")]]);
    assert!(!paths.partial, "the flag is replaced with the graph");
    assert_eq!(
        fixture.paths(project, ENGINE).await,
        Some(DependencyPaths::default()),
        "linked to nothing the project depends on"
    );

    // Without a graph, nothing is known any more.
    document.as_object_mut().unwrap().remove("dependencies");
    fixture.upload(parse(&document)).await;
    assert_eq!(fixture.edge_count().await, 0);
    assert_eq!(fixture.paths(project, LODASH).await, None);
}

#[tokio::test]
async fn spdx_uploads_store_the_graph_and_their_version() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(parse(&shop_spdx())).await;
    assert_eq!(fixture.edge_count().await, 3);
    assert_eq!(
        fixture.paths(project, LODASH).await.unwrap().paths,
        [vec![
            component(FRAMEWORK, "web-framework", "2.1.0"),
            component(ENGINE, "template-engine", "0.9.0"),
            component(LODASH, "lodash", "4.17.20"),
        ]]
    );
    let uploads = inventory::uploads(&fixture.database, &fixture.owner, project)
        .await
        .unwrap();
    assert_eq!(uploads[0].specification_version, "SPDX-2.3");
    assert_eq!(uploads[0].component_count, 4);
    assert_eq!(uploads[0].components_without_purl, 1);
}

#[tokio::test]
async fn spdx_uploads_store_whether_links_were_lost() {
    let fixture = Fixture::new().await;

    // The graph goes through `vendored`, which has no package URL.
    let project = fixture.upload(parse(&shop_spdx())).await;
    assert!(fixture.partial(project).await);
    assert!(
        fixture.paths(project, LODASH).await.unwrap().partial,
        "the paths carry the stored flag"
    );

    // Syft: every package has a package URL, nothing is lost. The flag is replaced, not kept.
    let sbom = inventory::parse(&sbom_document("syft-cargo-spdx-2.2.json")).unwrap();
    fixture.upload(sbom).await;
    assert!(!fixture.partial(project).await);

    // Trivy: the lock file's entry has no package URL and the graph goes through it.
    let sbom = inventory::parse(&sbom_document("trivy-npm-spdx.json")).unwrap();
    fixture.upload(sbom).await;
    assert!(fixture.partial(project).await);

    // An identifier given to two packages: no edge goes through it.
    let package = |id: &str, purl: &str| {
        json!({"SPDXID": id, "name": id, "versionInfo": "1.0.0",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl", "referenceLocator": purl}]})
    };
    let depends = |from: &str, to: &str| json!({"spdxElementId": from, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": to});
    let document = json!({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "packages": [
            package("SPDXRef-framework", FRAMEWORK),
            package("SPDXRef-same", ENGINE),
            package("SPDXRef-same", LEFT_PAD),
            package("SPDXRef-lodash", LODASH),
        ],
        "relationships": [
            depends("SPDXRef-framework", "SPDXRef-same"),
            depends("SPDXRef-same", "SPDXRef-lodash"),
        ]
    });
    fixture.upload(parse(&document)).await;
    assert!(fixture.partial(project).await);

    // Once the identifiers are distinct, the flag goes.
    let mut document = document;
    document["packages"][2]["SPDXID"] = json!("SPDXRef-other");
    fixture.upload(parse(&document)).await;
    assert!(!fixture.partial(project).await);
}

#[tokio::test]
async fn paths_are_limited_to_the_organization() {
    let fixture = Fixture::new().await;
    let project = fixture.upload(parse(&shop_document())).await;
    let stranger = users::create(
        &fixture.database,
        NewUser {
            username: "stranger".to_owned(),
            ..NewUser::default()
        },
        false,
    )
    .await
    .unwrap();
    assert!(matches!(
        dependencies::paths(
            &fixture.database,
            &Actor::from_user(&stranger),
            project,
            LODASH
        )
        .await,
        Err(Error::NotFound)
    ));
}

#[tokio::test]
async fn findings_webhooks_and_ci_name_the_direct_dependency() {
    let fixture = Fixture::new().await;
    fixture.source.publish(lodash_advisory(), &[LODASH]);
    let project = fixture.upload(parse(&shop_document())).await;
    notifications::set(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        "https://hooks.example.org/nanobom",
        Severity::Unknown,
        true,
        false,
    )
    .await
    .unwrap();
    let outcome = fixture
        .evaluator
        .run(Trigger::Scheduled, Scope::All, None)
        .await
        .unwrap();
    assert!(outcome.succeeded());

    let listed = findings::list(
        &fixture.database,
        &fixture.owner,
        project,
        &Filter::default(),
    )
    .await
    .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0].introduced_via,
        [component(FRAMEWORK, "web-framework", "2.1.0")]
    );

    let detail = findings::detail(&fixture.database, &fixture.owner, listed[0].id)
        .await
        .unwrap();
    assert_eq!(detail.finding.introduced_via, listed[0].introduced_via);
    let paths = detail.dependency_paths.unwrap();
    assert_eq!(paths.paths.len(), 1);
    assert_eq!(paths.paths[0].len(), 3);

    let deliveries = notifications::new_findings_deliveries(
        &fixture.database,
        &outcome,
        &"https://nanobom.example.org/".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(
        deliveries[0].payload.findings[0].introduced_via,
        ["web-framework"]
    );

    // An SBOM without a graph: the finding stays, its path is unknown.
    let mut document = shop_document();
    document.as_object_mut().unwrap().remove("dependencies");
    fixture.upload(parse(&document)).await;
    let detail = findings::detail(&fixture.database, &fixture.owner, listed[0].id)
        .await
        .unwrap();
    assert_eq!(detail.dependency_paths, None);
    assert!(detail.finding.introduced_via.is_empty());
}
