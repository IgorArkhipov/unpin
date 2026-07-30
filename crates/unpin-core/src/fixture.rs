use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureCredentialPurpose {
    Approval,
    BackupAuthentication,
    SessionAuthority,
}

impl FixtureCredentialPurpose {
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::Approval => b"approval",
            Self::BackupAuthentication => b"backup-authentication",
            Self::SessionAuthority => b"session-authority",
        }
    }
}

/// Derives deterministic, domain-separated fixture authority for one Unpin
/// state root. The physical path binding keeps independent fixture runs from
/// authenticating each other's evidence while remaining stable across the
/// separate CLI processes used by end-to-end tests.
pub fn fixture_credential_key(
    app_state_root: &Path,
    purpose: FixtureCredentialPurpose,
) -> Result<[u8; 32], String> {
    let scope = canonical_fixture_scope_path(app_state_root)?;
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-fixture-credential-v1");
    hasher.update([0]);
    hasher.update(purpose.domain());
    hasher.update([0]);
    update_hasher_with_path(&mut hasher, &scope);
    Ok(hasher.finalize().into())
}

/// Confines deterministic fixture authority to a private child of the OS
/// temporary directory. Live authority keeps normal provider-path behavior.
pub fn require_fixture_write_sandbox<'a>(
    fixture_mode: bool,
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), String> {
    if !fixture_mode {
        return Ok(());
    }
    let temporary_root = std::fs::canonicalize(std::env::temp_dir())
        .map_err(|error| format!("fixture temporary root could not be resolved: {error}"))?;
    for path in paths {
        if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return Err(
                "fixture apply is confined to absolute paths without parent traversal".to_string(),
            );
        }
        let resolved = canonical_existing_path_prefix(path)?;
        if resolved == temporary_root || !resolved.starts_with(&temporary_root) {
            return Err(
                "fixture apply is confined to private temporary paths; refusing requested write"
                    .to_string(),
            );
        }
    }
    Ok(())
}

/// Resolves a fixture state root through its nearest existing ancestor.
///
/// Fixture callers may need a stable physical root before the state directory
/// itself exists. This keeps credential and nonce paths consistent across
/// aliases such as macOS `/var` and `/private/var`.
pub fn canonical_fixture_scope_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
        return Err(
            "fixture credential scope must be an absolute path without parent traversal"
                .to_string(),
        );
    }
    let existing = path
        .ancestors()
        .find(|candidate| candidate.exists())
        .ok_or_else(|| "fixture credential scope has no existing ancestor".to_string())?;
    let canonical = std::fs::canonicalize(existing)
        .map_err(|error| format!("fixture credential scope could not be resolved: {error}"))?;
    let suffix = path.strip_prefix(existing).map_err(|_| {
        "fixture credential scope could not be bound to its physical path".to_string()
    })?;
    if suffix.as_os_str().is_empty() {
        Ok(canonical)
    } else {
        Ok(canonical.join(suffix))
    }
}

fn canonical_existing_path_prefix(path: &Path) -> Result<PathBuf, String> {
    path.ancestors()
        .find(|candidate| candidate.exists())
        .ok_or_else(|| "fixture write path has no existing ancestor".to_string())
        .and_then(|candidate| {
            std::fs::canonicalize(candidate)
                .map_err(|error| format!("fixture write path could not be resolved: {error}"))
        })
}

#[cfg(unix)]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    use std::os::unix::ffi::OsStrExt;

    hasher.update(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    use std::os::windows::ffi::OsStrExt;

    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn update_hasher_with_path(hasher: &mut Sha256, path: &Path) {
    hasher.update(path.to_string_lossy().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_authority_is_confined_to_private_temporary_paths() {
        let temp = tempfile::TempDir::new().expect("temporary fixture sandbox");
        let future_path = temp.path().join("state/provider/config.json");
        require_fixture_write_sandbox(true, [future_path.as_path()])
            .expect("temporary child path is allowed");

        let repository_path = std::env::current_dir().expect("current repository path");
        let error = require_fixture_write_sandbox(true, [repository_path.as_path()])
            .expect_err("non-temporary path must be rejected");
        assert!(error.contains("fixture apply is confined"));

        let temporary_root = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let error = require_fixture_write_sandbox(true, [temporary_root.as_path()])
            .expect_err("shared temporary root must be rejected");
        assert!(error.contains("fixture apply is confined"));

        let sibling = tempfile::TempDir::new().expect("temporary sibling");
        let sibling_name = sibling.path().file_name().expect("sibling name");
        let lexical_escape = temp
            .path()
            .join("..")
            .join(sibling_name)
            .join("config.json");
        let error = require_fixture_write_sandbox(true, [lexical_escape.as_path()])
            .expect_err("parent traversal must be rejected even within the temporary root");
        assert!(error.contains("without parent traversal"));

        let relative = Path::new("relative-fixture-write");
        let error = require_fixture_write_sandbox(true, [relative])
            .expect_err("relative fixture write must be rejected");
        assert!(error.contains("absolute paths"));
    }

    #[test]
    fn live_authority_does_not_apply_fixture_path_restrictions() {
        let repository_path = std::env::current_dir().expect("current repository path");
        require_fixture_write_sandbox(false, [repository_path.as_path()])
            .expect("live authority uses normal safety controls");
    }

    #[test]
    fn fixture_credentials_are_stable_and_scoped_by_root_and_purpose() {
        let first = tempfile::TempDir::new().expect("first fixture root");
        let second = tempfile::TempDir::new().expect("second fixture root");
        let first_state = first.path().join("state");
        let second_state = second.path().join("state");

        let approval =
            fixture_credential_key(&first_state, FixtureCredentialPurpose::Approval).unwrap();
        std::fs::create_dir(&first_state).expect("materialize first state root");
        assert_eq!(
            approval,
            fixture_credential_key(&first_state, FixtureCredentialPurpose::Approval).unwrap()
        );
        assert_ne!(
            approval,
            fixture_credential_key(&second_state, FixtureCredentialPurpose::Approval).unwrap()
        );
        assert_ne!(
            approval,
            fixture_credential_key(&first_state, FixtureCredentialPurpose::BackupAuthentication)
                .unwrap()
        );
        assert_ne!(
            approval,
            fixture_credential_key(&first_state, FixtureCredentialPurpose::SessionAuthority)
                .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn fixture_authority_rejects_temporary_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::TempDir::new().expect("temporary fixture sandbox");
        let repository_path = std::env::current_dir().expect("current repository path");
        let escape = temp.path().join("escape");
        symlink(&repository_path, &escape).expect("fixture escape symlink");

        let error = require_fixture_write_sandbox(true, [escape.join("config.json").as_path()])
            .expect_err("temporary symlink escape must be rejected");
        assert!(error.contains("fixture apply is confined"));
    }
}
