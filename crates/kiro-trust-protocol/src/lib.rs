//! Pure protocol types and translation for kiro-trust. No I/O, no network,
//! no SQLite, no async runtime (spec 3.1).

pub mod anthropic;
pub mod catalog;
pub mod estimate;
pub mod eventstream;
pub mod kiro;
pub mod sanitize;
pub mod sse;
pub mod translate;
