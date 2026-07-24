use std::path::{Component, Path, PathBuf};

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

fn canonical_existing_path_prefix(path: &Path) -> Result<PathBuf, String> {
    path.ancestors()
        .find(|candidate| candidate.exists())
        .ok_or_else(|| "fixture write path has no existing ancestor".to_string())
        .and_then(|candidate| {
            std::fs::canonicalize(candidate)
                .map_err(|error| format!("fixture write path could not be resolved: {error}"))
        })
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
