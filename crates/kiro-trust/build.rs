//! Record the commit for `kiro-trust audit`. Falls back to "unknown" when
//! git is unavailable (crates.io builds).

use std::process::Command;

fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=KIRO_TRUST_COMMIT={commit}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
