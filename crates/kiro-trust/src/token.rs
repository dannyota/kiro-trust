//! The local token Claude Code presents (spec 6.3): 32 CSPRNG bytes,
//! base64url without padding, in a 0600 file inside a 0700 directory.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use std::io;
use std::path::Path;

pub fn generate() -> SecretString {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("operating system randomness");
    SecretString::from(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn write_token_file(path: &Path, token: &SecretString) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("token file has no parent directory"))?;
    // Create the directory at 0700 only when it is missing. An existing
    // directory keeps whatever mode it already has: the 0600 file is the
    // protection, and `--token-file $HOME/tok` must not narrow `$HOME`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = dir.join(format!(".token.{}.tmp", std::process::id()));
    if let Err(e) = write_temp_file(&tmp, token) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

fn write_temp_file(tmp: &Path, token: &SecretString) -> io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(tmp)?;
    io::Write::write_all(&mut f, token.expose_secret().as_bytes())?;
    f.sync_all()
}

pub fn read_token_file(path: &Path) -> io::Result<SecretString> {
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token file is empty",
        ));
    }
    Ok(SecretString::from(trimmed.to_string()))
}

pub fn remove_token_file(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn generates_43_char_urlsafe_tokens_that_differ() {
        let a = generate();
        let b = generate();
        assert_eq!(a.expose_secret().len(), 43);
        assert!(
            a.expose_secret()
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn writes_0600_reads_back_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("token");
        let t = generate();
        write_token_file(&path, &t).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            read_token_file(&path).unwrap().expose_secret(),
            t.expose_secret()
        );
        assert!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count() == 1,
            "no temp file left behind"
        );
        remove_token_file(&path).unwrap();
        assert!(!path.exists());
        assert!(remove_token_file(&path).is_ok(), "idempotent");
    }

    #[test]
    #[cfg(unix)]
    fn existing_directory_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.path().join("token");
        let t = generate();
        write_token_file(&path, &t).unwrap();
        assert_eq!(
            std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing directory's mode must not be narrowed"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn read_token_file_rejects_whitespace_only_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "   \n\t  \n").unwrap();
        let err = read_token_file(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
