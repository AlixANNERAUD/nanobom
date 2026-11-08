use std::time::Duration;

use nanobom_domain::{database, testing};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};

#[tokio::test]
async fn migrations_create_the_schema() {
    let connection = testing::database().await;
    let result = connection
        .query_one_raw(Statement::from_string(
            connection.get_database_backend(),
            "SELECT COUNT(*) AS count FROM findings",
        ))
        .await
        .expect("query the findings table")
        .expect("one row");
    let count: i64 = result.try_get("", "count").expect("count column");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn backup_writes_a_usable_copy() {
    let directory = std::env::temp_dir().join(format!("nanobom-backup-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create the temporary directory");
    let source_path = directory.join("source.db");
    let backup_path = directory.join("backup.db");
    let _ = std::fs::remove_file(&source_path);
    let _ = std::fs::remove_file(&backup_path);

    let source = database::connect(&format!("sqlite://{}", source_path.display()))
        .await
        .expect("open the source database");
    database::migrate(&source).await.expect("migrate");
    database::backup(&source, &backup_path)
        .await
        .expect("back up");

    let copy = database::connect(&format!("sqlite://{}", backup_path.display()))
        .await
        .expect("open the backup");
    assert_eq!(copy.get_database_backend(), DatabaseBackend::Sqlite);
    copy.query_one_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        "SELECT COUNT(*) FROM users",
    ))
    .await
    .expect("the backup holds the schema");

    let second = database::backup(&source, &backup_path).await;
    assert!(matches!(
        second,
        Err(database::BackupError::DestinationExists(_))
    ));
    std::fs::remove_dir_all(&directory).ok();
}

#[tokio::test]
async fn migrations_create_the_exploitation_table() {
    use nanobom_entity::exploitation;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};

    let connection = testing::database().await;
    exploitation::ActiveModel {
        cve_id: Set("CVE-2024-0001".to_owned()),
        known_exploited: Set(true),
        kev_date_added: Set(Some("2024-01-02".to_owned())),
        epss_score: Set(Some(0.5)),
        ..Default::default()
    }
    .insert(&connection)
    .await
    .expect("insert an exploitation row");

    let row = exploitation::Entity::find_by_id("CVE-2024-0001")
        .one(&connection)
        .await
        .expect("read the row")
        .expect("the row exists");
    assert!(row.known_exploited);
    assert!(!row.kev_ransomware);
    assert_eq!(row.kev_date_added.as_deref(), Some("2024-01-02"));
    assert_eq!(row.epss_score, Some(0.5));
    assert_eq!(row.kev_due_date, None);
}

#[tokio::test]
async fn backup_refuses_databases_other_than_sqlite() {
    let connection = testing::database().await;
    // Only meaningful when the suite runs on another database (NANOBOM_TEST_DATABASE_URL).
    if connection.get_database_backend() == DatabaseBackend::Sqlite {
        return;
    }
    let destination = std::env::temp_dir().join(format!("nanobom-refused-{}", std::process::id()));
    let error = database::backup(&connection, &destination)
        .await
        .expect_err("only SQLite is copied");
    assert!(matches!(
        error,
        database::BackupError::UnsupportedBackend(_)
    ));
    assert!(error.to_string().contains("pg_dump"));
    assert!(!destination.exists());
}

async fn count_writes(connection: &impl ConnectionTrait) -> i64 {
    connection
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "SELECT COUNT(*) AS count FROM writes",
        ))
        .await
        .expect("count the rows")
        .expect("one row")
        .try_get("", "count")
        .expect("count column")
}

const WRITE: &str = "INSERT INTO writes DEFAULT VALUES";

/// Under write-ahead logging, a transaction begun with a plain (deferred) `BEGIN` that read
/// before another connection committed a write cannot write any more: SQLite fails at once with
/// `SQLITE_BUSY_SNAPSHOT` (code 517), whatever the busy timeout. [`database::begin_write`] takes
/// the write lock up front, so the other writer waits for it instead. Write-ahead logging needs a
/// file, hence a database of its own whatever `NANOBOM_TEST_DATABASE_URL` says.
#[tokio::test]
async fn write_transactions_make_concurrent_writers_wait_on_sqlite() {
    let directory = std::env::temp_dir().join(format!("nanobom-write-lock-{}", std::process::id()));
    std::fs::remove_dir_all(&directory).ok();
    std::fs::create_dir_all(&directory).expect("create the temporary directory");
    let database = database::connect(&format!(
        "sqlite://{}",
        directory.join("nanobom.db").display()
    ))
    .await
    .expect("open the database");
    database
        .execute_unprepared("CREATE TABLE writes (id INTEGER PRIMARY KEY)")
        .await
        .expect("create the table");

    // The failure this guards against: read, another connection writes, then write.
    let deferred = database.begin().await.expect("begin");
    assert_eq!(count_writes(&deferred).await, 0);
    database
        .execute_unprepared(WRITE)
        .await
        .expect("another connection writes");
    let error = deferred
        .execute_unprepared(WRITE)
        .await
        .expect_err("a stale snapshot cannot be upgraded to a write");
    assert!(error.to_string().contains("(code: 517)"), "{error}");
    deferred.rollback().await.expect("roll back");

    let transaction = database::begin_write(&database).await.expect("begin");
    assert_eq!(count_writes(&transaction).await, 1);
    let other = tokio::spawn({
        let database = database.clone();
        async move { database.execute_unprepared(WRITE).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!other.is_finished(), "the other writer waits for the lock");
    transaction
        .execute_unprepared(WRITE)
        .await
        .expect("the transaction holds the write lock");
    transaction.commit().await.expect("commit");
    other
        .await
        .expect("the other writer's task")
        .expect("the other writer gets the lock once released");
    assert_eq!(count_writes(&database).await, 3);

    database.close().await.ok();
    std::fs::remove_dir_all(&directory).ok();
}

/// Every migration can be reverted and applied again: `down` steps are otherwise never run.
#[tokio::test]
async fn migrations_can_be_reverted_and_applied_again() {
    use nanobom_migration::{Migrator, MigratorTrait, SchemaManager};

    let connection = testing::database().await;
    let applied = Migrator::get_applied_migrations(&connection)
        .await
        .expect("list the applied migrations")
        .len();
    assert_eq!(applied, Migrator::migrations().len());

    Migrator::down(&connection, None)
        .await
        .expect("revert every migration");
    let manager = SchemaManager::new(&connection);
    for table in ["users", "findings", "exploitation", "webhook_deliveries"] {
        assert!(
            !manager.has_table(table).await.expect("look the table up"),
            "{table} is dropped"
        );
    }

    database::migrate(&connection)
        .await
        .expect("apply every migration again");
    let applied = Migrator::get_applied_migrations(&connection)
        .await
        .expect("list the applied migrations")
        .len();
    assert_eq!(applied, Migrator::migrations().len());
    connection
        .query_one_raw(Statement::from_string(
            connection.get_database_backend(),
            "SELECT COUNT(*) FROM exploitation",
        ))
        .await
        .expect("the schema is back");
}
