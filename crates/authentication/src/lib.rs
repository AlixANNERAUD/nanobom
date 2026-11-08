//! Authentication for nanobom: sessions stored in the application database, local accounts and
//! OpenID Connect behind one axum-login backend, and cross-site request checks.
//!
//! This crate answers "who is this browser?" and stops there: what the signed-in user may do is
//! decided by `nanobom-domain` from the [`Actor`](nanobom_domain::access::Actor) that
//! [`SessionUser::actor`] builds. CI does not go through it either; upload tokens are checked
//! by the domain's `tokens` module.
//!
//! The pieces, as the server wires them:
//!
//! - [`DatabaseSessionStore`] keeps tower-sessions records in the `sessions` table;
//! - [`Backend`] is the axum-login backend. It turns [`Credentials`] into a [`SessionUser`] and
//!   reloads the user on every request, so disabling a user or changing their password ends
//!   their sessions;
//! - [`OpenId`] runs the authorization code flow and creates or updates users from the
//!   provider's claims ([`claims`] reads groups and administrator rights);
//! - [`csrf::protect`] refuses cross-site state-changing requests;
//! - [`redirect::local_path`] keeps a redirect target on this site.
//!
//! Start with [`backend`], then [`openid`] if single sign-on is in play.

pub mod backend;
pub mod claims;
pub mod csrf;
pub mod openid;
pub mod redirect;
pub mod session_store;

pub use backend::{AuthenticationSession, Backend, Credentials, SessionUser};
pub use openid::{OpenId, OpenIdError, OpenIdSettings, PendingSignIn};
pub use session_store::DatabaseSessionStore;
