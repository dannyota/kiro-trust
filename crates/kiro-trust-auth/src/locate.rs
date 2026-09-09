//! Default Kiro CLI database path per OS (spec 7.1): Linux
//! ~/.local/share/kiro-cli/data.sqlite3, macOS ~/Library/Application
//! Support/kiro-cli/data.sqlite3, Windows %LOCALAPPDATA%\kiro-cli\data.sqlite3.
//! `directories::BaseDirs::data_local_dir` is exactly those three.

use std::path::PathBuf;

pub fn default_db_path() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.data_local_dir().join("kiro-cli").join("data.sqlite3"))
}
