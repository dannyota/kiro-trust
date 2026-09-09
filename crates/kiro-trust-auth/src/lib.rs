//! Read-only Kiro CLI credential access and AWS IAM Identity Center refresh
//! (spec 3.3, 6.1).

mod db;
mod error;
mod locate;
mod refresh;
mod source;

pub use db::{Credentials, KiroDb};
pub use error::AuthError;
pub use locate::default_db_path;
pub use source::{Identity, TokenSource};
