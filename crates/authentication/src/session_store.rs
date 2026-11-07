//! A tower-sessions store on top of SeaORM, so sessions live in the application's database and
//! share its connection pool, whatever the database.

use chrono::{DateTime, Utc};
use nanobom_entity::sessions;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    sea_query::OnConflict,
};
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::{self, ExpiredDeletion, SessionStore};

#[derive(Debug, Clone)]
pub struct DatabaseSessionStore {
    database: DatabaseConnection,
}

impl DatabaseSessionStore {
    pub fn new(database: DatabaseConnection) -> Self {
        Self { database }
    }
}

fn backend(error: impl std::fmt::Display) -> session_store::Error {
    session_store::Error::Backend(error.to_string())
}

fn expiry(record: &Record) -> session_store::Result<DateTime<Utc>> {
    DateTime::from_timestamp(record.expiry_date.unix_timestamp(), 0)
        .ok_or_else(|| session_store::Error::Encode("expiry date out of range".to_owned()))
}

impl DatabaseSessionStore {
    async fn upsert(&self, record: &Record, overwrite: bool) -> session_store::Result<bool> {
        let data = serde_json::to_string(record)
            .map_err(|error| session_store::Error::Encode(error.to_string()))?;
        let model = sessions::ActiveModel {
            id: Set(record.id.to_string()),
            data: Set(data),
            expiry_date: Set(expiry(record)?.fixed_offset()),
        };
        let mut conflict = OnConflict::column(sessions::Column::Id);
        if overwrite {
            conflict.update_columns([sessions::Column::Data, sessions::Column::ExpiryDate]);
        } else {
            conflict.do_nothing();
        }
        let inserted = sessions::Entity::insert(model)
            .on_conflict(conflict)
            .exec_without_returning(&self.database)
            .await
            .map_err(backend)?;
        Ok(inserted > 0)
    }
}

#[async_trait::async_trait]
impl SessionStore for DatabaseSessionStore {
    async fn create(&self, record: &mut Record) -> session_store::Result<()> {
        // Identifiers are random; on the unlikely collision, draw a new one.
        while !self.upsert(record, false).await? {
            record.id = Id::default();
        }
        Ok(())
    }

    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.upsert(record, true).await.map(drop)
    }

    async fn load(&self, id: &Id) -> session_store::Result<Option<Record>> {
        let Some(model) = sessions::Entity::find_by_id(id.to_string())
            .one(&self.database)
            .await
            .map_err(backend)?
        else {
            return Ok(None);
        };
        if model.expiry_date <= Utc::now() {
            return Ok(None);
        }
        serde_json::from_str(&model.data)
            .map(Some)
            .map_err(|error| session_store::Error::Decode(error.to_string()))
    }

    async fn delete(&self, id: &Id) -> session_store::Result<()> {
        sessions::Entity::delete_by_id(id.to_string())
            .exec(&self.database)
            .await
            .map_err(backend)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ExpiredDeletion for DatabaseSessionStore {
    async fn delete_expired(&self) -> session_store::Result<()> {
        sessions::Entity::delete_many()
            .filter(sessions::Column::ExpiryDate.lte(Utc::now().fixed_offset()))
            .exec(&self.database)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
