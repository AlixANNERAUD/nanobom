use std::sync::Arc;

use nanobom_domain::{
    access::Actor,
    database,
    evaluation::{Evaluator, Scope, Trigger},
    findings::{self, Filter},
    inventory::{self, UploadSource},
    organizations, projects, testing,
    testing::FakeSource,
    tokens,
    users::{self, NewUser},
    versions, vex,
};
use nanobom_entity::{project_versions, projects as projects_entity};
use nanobom_migration::{Migrator, MigratorTrait, SchemaManager};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder,
    Statement,
};
use serde_json::json;

const LODASH: &str = "pkg:npm/lodash@4.17.20";

/// The tables whose rows belong to a project version.
const VERSIONED: [&str; 4] = [
    "components",
    "component_dependencies",
    "sbom_uploads",
    "findings",
];

struct Fixture {
    database: DatabaseConnection,
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
        source.publish(
            json!({
                "id": "GHSA-35jh-r3h4-6jhm",
                "modified": "2024-01-01T00:00:00Z",
                "aliases": ["CVE-2021-23337"],
                "summary": "Command Injection in lodash",
                "database_specific": {"severity": "HIGH"}
            }),
            &[LODASH],
        );
        let evaluator = Evaluator::new(database.clone(), Arc::clone(&source));
        Self {
            database,
            evaluator,
            owner,
            organization,
            secret,
        }
    }

    /// Uploads an SBOM of lodash and a framework depending on it to `project`, created by the
    /// organization-wide token when missing; the graph goes through a component without a
    /// package URL, so it is partial.
    async fn upload(&self, project: &str) -> i64 {
        let token = tokens::authenticate(&self.database, &self.secret)
            .await
            .unwrap()
            .unwrap();
        let document = json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": project, "bom-ref": "root"}},
            "components": [
                {"type": "library", "name": "web-framework", "version": "2.1.0", "bom-ref": "framework", "purl": "pkg:npm/web-framework@2.1.0"},
                {"type": "library", "name": "lodash", "version": "4.17.20", "bom-ref": "lodash", "purl": LODASH},
                {"type": "library", "name": "vendored", "bom-ref": "vendored"}
            ],
            "dependencies": [
                {"ref": "root", "dependsOn": ["framework", "vendored"]},
                {"ref": "framework", "dependsOn": ["lodash"]},
                {"ref": "vendored", "dependsOn": ["lodash"]}
            ]
        });
        inventory::ingest(
            &self.database,
            &token,
            "acme",
            project,
            inventory::parse(document.to_string().as_bytes()).unwrap(),
            UploadSource::default(),
        )
        .await
        .unwrap()
        .project_id
    }

    async fn run(&self) {
        self.evaluator
            .run(Trigger::Scheduled, Scope::All, None)
            .await
            .unwrap();
    }

    async fn count(&self, sql: &str) -> i64 {
        self.database
            .query_one_raw(Statement::from_string(
                self.database.get_database_backend(),
                sql.to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "count")
            .unwrap()
    }

    /// Rows of the versioned tables without a version, or whose version belongs to another
    /// project or no longer exists.
    async fn misplaced_rows(&self) -> Vec<(&'static str, i64)> {
        let mut misplaced = Vec::new();
        for table in VERSIONED {
            let count = self
                .count(&format!(
                    "SELECT COUNT(*) AS count FROM {table} WHERE version_id IS NULL OR NOT EXISTS \
                     (SELECT 1 FROM project_versions WHERE project_versions.id = {table}.version_id \
                     AND project_versions.project_id = {table}.project_id)"
                ))
                .await;
            if count > 0 {
                misplaced.push((table, count));
            }
        }
        misplaced
    }

    async fn rows(&self) -> Vec<i64> {
        let mut counts = Vec::new();
        for table in VERSIONED {
            counts.push(
                self.count(&format!("SELECT COUNT(*) AS count FROM {table}"))
                    .await,
            );
        }
        counts
    }

    async fn versions(&self) -> Vec<project_versions::Model> {
        project_versions::Entity::find()
            .order_by_asc(project_versions::Column::Id)
            .all(&self.database)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn a_new_project_has_one_unnamed_latest_version() {
    let fixture = Fixture::new().await;
    let project = projects::create(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        "web",
        "Web",
    )
    .await
    .unwrap();
    let version = versions::find(&fixture.database, &fixture.owner, project.id, None)
        .await
        .unwrap();
    assert_eq!(version.name, versions::UNNAMED);
    assert!(version.latest);
    assert!(version.active);
    assert_eq!(version.last_upload_at, None);
    assert_eq!(
        versions::find(&fixture.database, &fixture.owner, project.id, Some(""))
            .await
            .unwrap(),
        version
    );
    assert!(matches!(
        versions::find(&fixture.database, &fixture.owner, project.id, Some("2.4")).await,
        Err(nanobom_domain::Error::NotFound)
    ));

    // Another organization's version is not found, as its project is not.
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
        versions::find(
            &fixture.database,
            &Actor::from_user(&stranger),
            project.id,
            None
        )
        .await,
        Err(nanobom_domain::Error::NotFound)
    ));
}

#[tokio::test]
async fn every_row_names_a_version_of_its_project() {
    let fixture = Fixture::new().await;
    projects::create(
        &fixture.database,
        &fixture.owner,
        fixture.organization,
        "empty",
        "Empty",
    )
    .await
    .unwrap();
    let shop = fixture.upload("shop").await;
    fixture.run().await;

    let token = tokens::authenticate(&fixture.database, &fixture.secret)
        .await
        .unwrap()
        .unwrap();
    let document = vex::export(&fixture.database, &token, "acme", "shop")
        .await
        .unwrap();
    let mut document = serde_json::to_value(&document).unwrap();
    document["vulnerabilities"][0]["analysis"] = json!({
        "state": "not_affected",
        "justification": "code_not_reachable",
    });
    let statements = vex::parse(&serde_json::to_vec(&document).unwrap()).unwrap();
    let outcome = vex::import(&fixture.database, &token, "acme", "shop", &statements)
        .await
        .unwrap();
    assert_eq!(outcome.ignored, 1);

    // A second upload replaces the components; the run keeps the ignored finding.
    fixture.upload("shop").await;
    fixture.upload("other").await;
    fixture.run().await;
    assert_eq!(fixture.misplaced_rows().await, []);
    let versions = fixture.versions().await;
    assert_eq!(versions.len(), 3, "one version per project");
    for version in &versions {
        assert_eq!(version.name, versions::UNNAMED);
        assert!(version.latest && version.active);
    }
    let shop_version = versions
        .iter()
        .find(|version| version.project_id == shop)
        .unwrap();
    let shop_project = projects_entity::Entity::find_by_id(shop)
        .one(&fixture.database)
        .await
        .unwrap()
        .unwrap();
    assert!(shop_version.dependencies_partial);
    assert_eq!(shop_version.last_upload_at, shop_project.last_upload_at);
    let findings = findings::list(&fixture.database, &fixture.owner, shop, &Filter::default())
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, findings::Status::Ignored);

    projects::delete(&fixture.database, &fixture.owner, shop)
        .await
        .unwrap();
    assert_eq!(fixture.misplaced_rows().await, []);
    assert_eq!(fixture.versions().await.len(), 2);
}

#[tokio::test]
async fn the_migration_attaches_existing_rows_to_an_unnamed_version() {
    let fixture = Fixture::new().await;
    let database = &fixture.database;
    let shop = fixture.upload("shop").await;
    fixture.run().await;
    projects::create(
        database,
        &fixture.owner,
        fixture.organization,
        "empty",
        "Empty",
    )
    .await
    .unwrap();
    let rows = fixture.rows().await;
    assert!(rows.iter().all(|count| *count > 0), "{rows:?}");
    let shop_before = projects_entity::Entity::find_by_id(shop)
        .one(database)
        .await
        .unwrap()
        .unwrap();

    // Back to the schema before versions, with a project created there.
    Migrator::down(database, Some(1)).await.unwrap();
    let manager = SchemaManager::new(database);
    assert!(!manager.has_table("project_versions").await.unwrap());
    for table in VERSIONED {
        assert!(!manager.has_column(table, "version_id").await.unwrap());
    }
    assert!(
        manager
            .has_column("projects", "dependencies_partial")
            .await
            .unwrap()
    );
    assert_eq!(
        fixture
            .count(
                "SELECT COUNT(*) AS count FROM projects WHERE slug = 'shop' \
                 AND dependencies_partial"
            )
            .await,
        1,
        "the flag returns to the project"
    );
    database
        .execute_unprepared(
            "INSERT INTO projects (organization_id, slug, name, created_at, last_upload_at, \
             dependencies_partial) SELECT organization_id, 'old', 'Old', created_at, \
             last_upload_at, FALSE FROM projects WHERE slug = 'shop'",
        )
        .await
        .unwrap();

    database::migrate(database).await.unwrap();
    assert_eq!(fixture.rows().await, rows, "no row is lost");
    assert_eq!(fixture.misplaced_rows().await, []);
    let projects = projects_entity::Entity::find()
        .order_by_asc(projects_entity::Column::Id)
        .all(database)
        .await
        .unwrap();
    let versions = fixture.versions().await;
    assert_eq!(versions.len(), projects.len());
    for project in &projects {
        let version = versions
            .iter()
            .find(|version| version.project_id == project.id)
            .unwrap();
        assert_eq!(version.name, versions::UNNAMED);
        assert!(version.latest && version.active);
        assert_eq!(version.created_at, project.created_at);
        assert_eq!(version.last_upload_at, project.last_upload_at);
        assert_eq!(version.dependencies_partial, project.slug == "shop");
    }
    assert_eq!(
        projects
            .iter()
            .find(|project| project.id == shop)
            .unwrap()
            .last_upload_at,
        shop_before.last_upload_at
    );

    // Everything reads and runs as before.
    let findings = findings::list(database, &fixture.owner, shop, &Filter::default())
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    fixture.upload("shop").await;
    fixture.run().await;
    assert_eq!(fixture.misplaced_rows().await, []);
    assert_eq!(
        project_versions::Entity::find()
            .filter(project_versions::Column::ProjectId.eq(shop))
            .all(database)
            .await
            .unwrap()
            .len(),
        1
    );
}
