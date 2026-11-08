//! Roles, permissions and the actor on whose behalf an operation runs.
//!
//! Every function of the domain crate that reads or changes organization data takes an [`Actor`]
//! and checks it here, so isolation between organizations does not depend on the interface.
//!
//! Roles are ordered ([`Role::Viewer`] < [`Role::Member`] < [`Role::Admin`] < [`Role::Owner`]) and
//! each [`Permission`] names the lowest role that holds it, so a role holds every permission of
//! the roles below it. Instance administrators are not members anywhere; they act as owners of
//! every organization.
//!
//! [`Actor::authorize`] is the check to use. It answers [`Error::NotFound`] when the actor has no
//! role in the organization and [`Error::Forbidden`] when the role is too low, so an outsider
//! cannot tell an existing organization from a missing one.
//!
//! ```ignore
//! // Inside a domain function: refuse early, before reading anything.
//! actor
//!     .authorize(database, organization_id, Permission::ManageProjects)
//!     .await?;
//! ```

use std::fmt;

use nanobom_entity::{memberships, users};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    problem::Problem,
};

/// A role within one organization, from the least to the most privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads everything in the organization.
    Viewer,
    /// Also ignores and restores findings and triggers runs.
    Member,
    /// Also manages members, projects, upload tokens and the webhook.
    Admin,
    /// Also manages owners and deletes the organization.
    Owner,
}

impl Role {
    /// Every role, from the least to the most privileged.
    pub const ALL: [Role; 4] = [Role::Viewer, Role::Member, Role::Admin, Role::Owner];

    /// The name stored in the `memberships.role` column and used in group mappings.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Member => "member",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    /// Parses a name produced by [`Role::as_str`]; anything else is
    /// [`Problem::UnknownRole`].
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "viewer" => Ok(Role::Viewer),
            "member" => Ok(Role::Member),
            "admin" => Ok(Role::Admin),
            "owner" => Ok(Role::Owner),
            other => Err(Error::invalid(Problem::UnknownRole {
                role: other.to_owned(),
            })),
        }
    }

    /// Whether this role holds `permission`, that is, ranks at least as high as its
    /// [`Permission::minimum_role`].
    pub fn allows(self, permission: Permission) -> bool {
        self >= permission.minimum_role()
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What an actor may do within an organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// See the organization, its projects, components and findings.
    View,
    /// Ignore and restore findings.
    TriageFindings,
    /// Start a run for the organization or one of its projects.
    TriggerRuns,
    /// Add, change and remove members other than owners.
    ManageMembers,
    /// Create, rename and delete projects.
    ManageProjects,
    /// Create and revoke upload tokens.
    ManageUploadTokens,
    /// Configure the organization's webhook.
    ManageWebhook,
    /// Rename the organization.
    ManageOrganization,
    /// Grant and remove the owner role.
    ManageOwners,
    /// Delete the organization.
    DeleteOrganization,
}

impl Permission {
    /// Every permission, for tables and tests that go through all of them.
    pub const ALL: [Permission; 10] = [
        Permission::View,
        Permission::TriageFindings,
        Permission::TriggerRuns,
        Permission::ManageMembers,
        Permission::ManageProjects,
        Permission::ManageUploadTokens,
        Permission::ManageWebhook,
        Permission::ManageOrganization,
        Permission::ManageOwners,
        Permission::DeleteOrganization,
    ];

    /// The lowest role that holds the permission. This match is the whole permission table.
    pub fn minimum_role(self) -> Role {
        match self {
            Permission::View => Role::Viewer,
            Permission::TriageFindings | Permission::TriggerRuns => Role::Member,
            Permission::ManageMembers
            | Permission::ManageProjects
            | Permission::ManageUploadTokens
            | Permission::ManageWebhook
            | Permission::ManageOrganization => Role::Admin,
            Permission::ManageOwners | Permission::DeleteOrganization => Role::Owner,
        }
    }
}

/// The signed-in user on whose behalf an operation runs.
///
/// An actor is a snapshot taken when the request starts ([`Actor::load`]); roles are looked up
/// in the database at each check, so a membership change applies to the next operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub user_id: i64,
    /// Instance administrators manage users and act as owners of every organization.
    pub is_instance_administrator: bool,
}

impl Actor {
    /// Loads the actor for a user, refusing disabled and deleted users with [`Error::NotFound`].
    /// This is what makes disabling a user end their sessions.
    pub async fn load(database: &impl ConnectionTrait, user_id: i64) -> Result<Self> {
        let user = users::Entity::find_by_id(user_id)
            .one(database)
            .await?
            .filter(|user| !user.is_disabled)
            .ok_or(Error::NotFound)?;
        Ok(Self::from_user(&user))
    }

    /// Builds an actor from a user already loaded. Unlike [`Actor::load`], it does not check
    /// that the user is enabled.
    pub fn from_user(user: &users::Model) -> Self {
        Self {
            user_id: user.id,
            is_instance_administrator: user.is_instance_administrator,
        }
    }

    /// Fails with [`Error::Forbidden`] unless the actor is an instance administrator.
    pub fn require_instance_administrator(&self) -> Result<()> {
        if self.is_instance_administrator {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }

    /// The actor's role in an organization: the highest of its memberships, whatever their
    /// source, or `None` when it has none. Instance administrators act as owners everywhere,
    /// including in organizations that do not exist: callers check existence separately.
    pub async fn role_in(
        &self,
        database: &impl ConnectionTrait,
        organization_id: i64,
    ) -> Result<Option<Role>> {
        if self.is_instance_administrator {
            return Ok(Some(Role::Owner));
        }
        membership_role(database, organization_id, self.user_id).await
    }

    /// Checks a permission in an organization and returns the actor's role there.
    /// Organizations the actor does not belong to are reported as [`Error::NotFound`] rather
    /// than [`Error::Forbidden`].
    pub async fn authorize(
        &self,
        database: &impl ConnectionTrait,
        organization_id: i64,
        permission: Permission,
    ) -> Result<Role> {
        let role = self
            .role_in(database, organization_id)
            .await?
            .ok_or(Error::NotFound)?;
        if role.allows(permission) {
            Ok(role)
        } else {
            Err(Error::Forbidden)
        }
    }
}

/// The highest role a user holds in an organization, across manual and synchronized memberships.
pub(crate) async fn membership_role(
    database: &impl ConnectionTrait,
    organization_id: i64,
    user_id: i64,
) -> Result<Option<Role>> {
    let memberships = memberships::Entity::find()
        .filter(memberships::Column::OrganizationId.eq(organization_id))
        .filter(memberships::Column::UserId.eq(user_id))
        .all(database)
        .await?;
    let mut highest = None;
    for membership in memberships {
        let role = Role::parse(&membership.role)?;
        highest = highest.max(Some(role));
    }
    Ok(highest)
}
