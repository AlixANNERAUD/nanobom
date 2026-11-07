//! Authentication for nanobom: sessions stored in the application database, local accounts and
//! OpenID Connect behind one axum-login backend, and cross-site request checks.

pub mod backend;
pub mod claims;
pub mod csrf;
pub mod openid;
pub mod session_store;

pub use backend::{AuthenticationSession, Backend, Credentials, SessionUser};
pub use openid::{OpenId, OpenIdError, OpenIdSettings, PendingSignIn};
pub use session_store::DatabaseSessionStore;
