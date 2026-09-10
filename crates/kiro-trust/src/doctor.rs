//! Offline diagnostics with one explicit, fixed loopback health probe.

use crate::config::{DoctorArgs, parse_listen, read_extra_ca, resolve_db_path, resolve_token_file};
use crate::output::{abbreviate_home_path, escape_text_controls};
use kiro_trust_auth::KiroDb;
use kiro_trust_net::{RuntimeRegion, probe_loopback_health};
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorCheckName {
    Configuration,
    Database,
    CredentialExpiry,
    LocalToken,
    Listener,
}

#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Ok,
    Warning,
    Error,
    Skipped,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorDetail {
    Valid,
    InvalidConfiguration,
    ReadOnly,
    DatabaseUnavailable,
    CredentialInvalid,
    RefreshRequired,
    Expired,
    CredentialUnavailable,
    ExplicitTokenConfigured,
    PrivateFile,
    TokenFileMissing,
    TokenMetadataUnreadable,
    UnsafeTokenFile,
    AclNotVerified,
    NetworkDisabled,
    Healthy,
    HealthProbeFailed,
}

#[derive(Serialize)]
pub struct DoctorPaths {
    pub database: Option<String>,
    pub token_file: Option<String>,
    pub extra_ca: Option<String>,
}

#[derive(Serialize)]
pub struct DoctorCheck {
    pub name: DoctorCheckName,
    pub status: DoctorStatus,
    pub detail: DoctorDetail,
}

#[derive(Serialize)]
pub struct DoctorReport {
    pub version: String,
    pub paths: DoctorPaths,
    pub checks: Vec<DoctorCheck>,
}

fn check(name: DoctorCheckName, status: DoctorStatus, detail: DoctorDetail) -> DoctorCheck {
    DoctorCheck {
        name,
        status,
        detail,
    }
}

fn path_string(path: Option<&std::path::PathBuf>) -> Option<String> {
    path.map(|path| abbreviate_home_path(&path.display().to_string()))
}

fn token_file_check(path: &Path) -> DoctorCheck {
    if std::env::var_os("KIRO_TRUST_TOKEN").is_some() {
        return check(
            DoctorCheckName::LocalToken,
            DoctorStatus::Ok,
            DoctorDetail::ExplicitTokenConfigured,
        );
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_file() => {
            check(
                DoctorCheckName::LocalToken,
                DoctorStatus::Error,
                DoctorDetail::UnsafeTokenFile,
            )
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return check(
                        DoctorCheckName::LocalToken,
                        DoctorStatus::Error,
                        DoctorDetail::UnsafeTokenFile,
                    );
                }
                check(
                    DoctorCheckName::LocalToken,
                    DoctorStatus::Ok,
                    DoctorDetail::PrivateFile,
                )
            }
            #[cfg(windows)]
            {
                let _ = metadata;
                check(
                    DoctorCheckName::LocalToken,
                    DoctorStatus::Warning,
                    DoctorDetail::AclNotVerified,
                )
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = metadata;
                check(
                    DoctorCheckName::LocalToken,
                    DoctorStatus::Warning,
                    DoctorDetail::AclNotVerified,
                )
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => check(
            DoctorCheckName::LocalToken,
            DoctorStatus::Warning,
            DoctorDetail::TokenFileMissing,
        ),
        Err(_) => check(
            DoctorCheckName::LocalToken,
            DoctorStatus::Error,
            DoctorDetail::TokenMetadataUnreadable,
        ),
    }
}

pub fn report(args: &DoctorArgs) -> DoctorReport {
    let listen = parse_listen(&args.listen);
    let runtime_region = args
        .runtime_region
        .as_deref()
        .map(RuntimeRegion::parse)
        .transpose();
    let database = resolve_db_path(args.kiro_db.clone());
    let token_file = resolve_token_file(args.token_file.clone());
    let extra_ca = read_extra_ca(args.extra_ca.as_ref());
    let configuration_ok = listen.is_ok()
        && runtime_region.is_ok()
        && database.is_ok()
        && token_file.is_ok()
        && extra_ca.is_ok();

    let configuration = check(
        DoctorCheckName::Configuration,
        if configuration_ok {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Error
        },
        if configuration_ok {
            DoctorDetail::Valid
        } else {
            DoctorDetail::InvalidConfiguration
        },
    );

    let (database_check, expiry_check) = match database.as_ref() {
        Err(_) => (
            check(
                DoctorCheckName::Database,
                DoctorStatus::Skipped,
                DoctorDetail::InvalidConfiguration,
            ),
            check(
                DoctorCheckName::CredentialExpiry,
                DoctorStatus::Skipped,
                DoctorDetail::InvalidConfiguration,
            ),
        ),
        Ok(path) => match KiroDb::open_read_only(path) {
            Err(_) => (
                check(
                    DoctorCheckName::Database,
                    DoctorStatus::Error,
                    DoctorDetail::DatabaseUnavailable,
                ),
                check(
                    DoctorCheckName::CredentialExpiry,
                    DoctorStatus::Skipped,
                    DoctorDetail::CredentialUnavailable,
                ),
            ),
            Ok(db) if !db.is_read_only() => (
                check(
                    DoctorCheckName::Database,
                    DoctorStatus::Error,
                    DoctorDetail::CredentialInvalid,
                ),
                check(
                    DoctorCheckName::CredentialExpiry,
                    DoctorStatus::Skipped,
                    DoctorDetail::CredentialUnavailable,
                ),
            ),
            Ok(db) => match db.read_identity_center() {
                Err(_) => (
                    check(
                        DoctorCheckName::Database,
                        DoctorStatus::Error,
                        DoctorDetail::CredentialInvalid,
                    ),
                    check(
                        DoctorCheckName::CredentialExpiry,
                        DoctorStatus::Skipped,
                        DoctorDetail::CredentialUnavailable,
                    ),
                ),
                Ok(credentials) => {
                    let now = SystemTime::now();
                    let expiry = match credentials.expires_at.duration_since(now) {
                        Ok(remaining) if remaining > Duration::from_secs(300) => check(
                            DoctorCheckName::CredentialExpiry,
                            DoctorStatus::Ok,
                            DoctorDetail::Valid,
                        ),
                        Ok(_) => check(
                            DoctorCheckName::CredentialExpiry,
                            DoctorStatus::Warning,
                            DoctorDetail::RefreshRequired,
                        ),
                        Err(_) => check(
                            DoctorCheckName::CredentialExpiry,
                            DoctorStatus::Warning,
                            DoctorDetail::Expired,
                        ),
                    };
                    (
                        check(
                            DoctorCheckName::Database,
                            DoctorStatus::Ok,
                            DoctorDetail::ReadOnly,
                        ),
                        expiry,
                    )
                }
            },
        },
    };

    let local_token = match token_file.as_ref() {
        Ok(path) => token_file_check(path),
        Err(_) => check(
            DoctorCheckName::LocalToken,
            DoctorStatus::Skipped,
            DoctorDetail::InvalidConfiguration,
        ),
    };
    let listener = match listen {
        Err(_) => check(
            DoctorCheckName::Listener,
            DoctorStatus::Skipped,
            DoctorDetail::InvalidConfiguration,
        ),
        Ok(_) if !args.network => check(
            DoctorCheckName::Listener,
            DoctorStatus::Skipped,
            DoctorDetail::NetworkDisabled,
        ),
        Ok(addr) => match tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .and_then(|runtime| {
                runtime
                    .block_on(probe_loopback_health(addr))
                    .map_err(std::io::Error::other)
            }) {
            Ok(()) => check(
                DoctorCheckName::Listener,
                DoctorStatus::Ok,
                DoctorDetail::Healthy,
            ),
            Err(_) => check(
                DoctorCheckName::Listener,
                DoctorStatus::Error,
                DoctorDetail::HealthProbeFailed,
            ),
        },
    };

    DoctorReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        paths: DoctorPaths {
            database: database
                .ok()
                .as_ref()
                .and_then(|path| path_string(Some(path))),
            token_file: token_file
                .ok()
                .as_ref()
                .and_then(|path| path_string(Some(path))),
            extra_ca: path_string(args.extra_ca.as_ref()),
        },
        checks: vec![
            configuration,
            database_check,
            expiry_check,
            local_token,
            listener,
        ],
    }
}

pub fn render_text(report: &DoctorReport) -> String {
    let mut text = format!(
        "DATABASE\t{}\nTOKEN FILE\t{}\nEXTRA CA\t{}\n\nNAME\tSTATUS\tDETAIL\n",
        escape_text_controls(report.paths.database.as_deref().unwrap_or("none")),
        escape_text_controls(report.paths.token_file.as_deref().unwrap_or("none")),
        escape_text_controls(report.paths.extra_ca.as_deref().unwrap_or("none")),
    );
    for check in &report.checks {
        let name = enum_text(check.name);
        let status = enum_text(check.status);
        let detail = enum_text(check.detail);
        text.push_str(&format!("{}\t{}\t{}\n", name, status, detail,));
    }
    text
}

fn enum_text<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("fixed doctor enum serializes")
        .as_str()
        .expect("fixed doctor enum is a JSON string")
        .to_string()
}

pub fn exit_code(report: &DoctorReport) -> i32 {
    if report
        .checks
        .iter()
        .any(|check| check.status == DoctorStatus::Error)
    {
        1
    } else {
        0
    }
}

pub fn run(args: DoctorArgs) -> i32 {
    let json = args.json;
    let report = report(&args);
    if json {
        println!("{}", serde_json::to_string(&report).unwrap());
    } else {
        print!("{}", render_text(&report));
    }
    exit_code(&report)
}
