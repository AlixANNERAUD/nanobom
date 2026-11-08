use nanobom_domain::{database, testing};
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

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
