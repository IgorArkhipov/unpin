use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Barrier, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};

use serde::{Serialize, Serializer};
use serde_json::json;
use tempfile::TempDir as RawTempDir;
use unpin_core::state::{
    atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
    workspace::{
        WorkspaceDiagnosticSource, WorkspaceDiagnosticWarning, WorkspaceDiagnosticWarningKind,
        resolve_workspace_identity,
    },
};

struct TempDir {
    _inner: RawTempDir,
    physical_path: PathBuf,
}

impl TempDir {
    fn new() -> std::io::Result<Self> {
        let inner = RawTempDir::new()?;
        let physical_path = fs::canonicalize(inner.path())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&physical_path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            _inner: inner,
            physical_path,
        })
    }

    fn path(&self) -> &Path {
        &self.physical_path
    }
}

fn run_git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_repository(path: &Path) {
    fs::create_dir_all(path).expect("create repository");
    run_git(path, &["init", "--initial-branch=main"]);
    run_git(path, &["config", "user.name", "Unpin Test"]);
    run_git(path, &["config", "user.email", "unpin@example.invalid"]);
    fs::write(path.join("README.md"), "initial\n").expect("write repository file");
    run_git(path, &["add", "README.md"]);
    run_git(path, &["commit", "-m", "initial"]);
}

fn owner(id: &str, generation: u64) -> OwnerGeneration {
    OwnerGeneration::new(id, generation).expect("valid owner generation")
}

fn lock_path(store: &AtomicJsonStore) -> PathBuf {
    let resource_id = store.physical_resource_id().expect("physical resource id");
    store
        .path()
        .with_file_name(format!(".unpin-resource-{}.lock", resource_id.as_str()))
}

const CHILD_MODE: &str = "UNPIN_STATE_TEST_CHILD_MODE";
const CHILD_STATE_PATH: &str = "UNPIN_STATE_TEST_PATH";
const CHILD_RESULT_PATH: &str = "UNPIN_STATE_TEST_RESULT";
const CHILD_START_PATH: &str = "UNPIN_STATE_TEST_START";
const CHILD_READY_PATH: &str = "UNPIN_STATE_TEST_READY";
const CHILD_RELEASE_PATH: &str = "UNPIN_STATE_TEST_RELEASE";
const CHILD_REVISION_SEQUENCE: &str = "UNPIN_STATE_TEST_REVISION_SEQUENCE";
const CHILD_REVISION_FINGERPRINT: &str = "UNPIN_STATE_TEST_REVISION_FINGERPRINT";

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(10));
    }
    path.exists()
}

fn child_command(mode: &str, state_path: &Path, result_path: &Path) -> Command {
    let mut command = Command::new(env::current_exe().expect("current state test executable"));
    command
        .arg("--exact")
        .arg("atomic_json_subprocess_worker")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(CHILD_STATE_PATH, state_path)
        .env(CHILD_RESULT_PATH, result_path);
    command
}

fn assert_child_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "child failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct ProcessBlockingValue {
    entered_path: PathBuf,
    release_path: PathBuf,
}

impl Serialize for ProcessBlockingValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        fs::write(&self.entered_path, b"ready\n").expect("signal blocking serializer");
        assert!(
            wait_for_path(&self.release_path, Duration::from_secs(10)),
            "blocking serializer was not released"
        );
        serializer.serialize_str("released")
    }
}

#[test]
fn atomic_json_subprocess_worker() {
    let Ok(mode) = env::var(CHILD_MODE) else {
        return;
    };
    let state_path = PathBuf::from(env::var_os(CHILD_STATE_PATH).expect("child state path"));
    let result_path = PathBuf::from(env::var_os(CHILD_RESULT_PATH).expect("child result path"));
    let store = AtomicJsonStore::new(&state_path, 1);

    let result = match mode.as_str() {
        "cas-existing" => {
            let ready_path = PathBuf::from(env::var_os(CHILD_READY_PATH).expect("ready path"));
            let start_path = PathBuf::from(env::var_os(CHILD_START_PATH).expect("start path"));
            fs::write(&ready_path, b"ready\n").expect("announce ready");
            assert!(
                wait_for_path(&start_path, Duration::from_secs(10)),
                "child start barrier timed out"
            );
            let expected = StateRevision {
                sequence: env::var(CHILD_REVISION_SEQUENCE)
                    .expect("revision sequence")
                    .parse()
                    .expect("numeric revision sequence"),
                fingerprint: env::var(CHILD_REVISION_FINGERPRINT).expect("revision fingerprint"),
            };
            store.compare_and_swap(
                Some(&expected),
                owner("subprocess-owner", 1),
                &json!({ "pid": std::process::id() }),
            )
        }
        "cas-create" => {
            let ready_path = PathBuf::from(env::var_os(CHILD_READY_PATH).expect("ready path"));
            let start_path = PathBuf::from(env::var_os(CHILD_START_PATH).expect("start path"));
            fs::write(&ready_path, b"ready\n").expect("announce ready");
            assert!(
                wait_for_path(&start_path, Duration::from_secs(10)),
                "child start barrier timed out"
            );
            store.compare_and_swap(
                None,
                owner("subprocess-owner", 1),
                &json!({ "pid": std::process::id() }),
            )
        }
        "blocking-create" => {
            let entered_path = PathBuf::from(env::var_os(CHILD_READY_PATH).expect("entered path"));
            let release_path =
                PathBuf::from(env::var_os(CHILD_RELEASE_PATH).expect("release path"));
            store.compare_and_swap(
                None,
                owner("subprocess-owner", 1),
                &ProcessBlockingValue {
                    entered_path,
                    release_path,
                },
            )
        }
        "simple-create" => store.compare_and_swap(
            None,
            owner("subprocess-owner", 1),
            &json!({ "pid": std::process::id() }),
        ),
        other => panic!("unknown child mode {other}"),
    };

    let outcome = match result {
        Ok(_) => "success",
        Err(StateError::StaleRevision { .. }) => "stale",
        Err(error) => panic!("unexpected child CAS error: {error}"),
    };
    fs::write(result_path, format!("{outcome}\n")).expect("write child result");
}

#[test]
fn workspace_identity_separates_worktrees_clones_and_non_git_roots() {
    let temp = TempDir::new().expect("temporary identity roots");
    let repository = temp.path().join("repository");
    let worktree = temp.path().join("worktree");
    create_repository(&repository);
    run_git(
        &repository,
        &[
            "worktree",
            "add",
            "--detach",
            worktree.to_str().unwrap(),
            "HEAD",
        ],
    );

    let repository_identity = resolve_workspace_identity(&repository).expect("repository identity");
    let worktree_identity = resolve_workspace_identity(&worktree).expect("worktree identity");
    assert_eq!(
        repository_identity.repository_key,
        worktree_identity.repository_key
    );
    assert_ne!(
        repository_identity.workspace_key,
        worktree_identity.workspace_key
    );

    let clone_one = temp.path().join("clone-one");
    let clone_two = temp.path().join("clone-two");
    run_git(
        temp.path(),
        &[
            "clone",
            repository.to_str().unwrap(),
            clone_one.to_str().unwrap(),
        ],
    );
    run_git(
        temp.path(),
        &[
            "clone",
            repository.to_str().unwrap(),
            clone_two.to_str().unwrap(),
        ],
    );
    assert_ne!(
        resolve_workspace_identity(&clone_one)
            .expect("first clone identity")
            .repository_key,
        resolve_workspace_identity(&clone_two)
            .expect("second clone identity")
            .repository_key
    );

    let plain_one = temp.path().join("plain-one");
    let plain_two = temp.path().join("plain-two");
    fs::create_dir_all(&plain_one).expect("first plain root");
    fs::create_dir_all(&plain_two).expect("second plain root");
    assert_ne!(
        resolve_workspace_identity(&plain_one)
            .expect("first plain identity")
            .repository_key,
        resolve_workspace_identity(&plain_two)
            .expect("second plain identity")
            .repository_key
    );
}

#[test]
fn workspace_key_ignores_branch_and_head_diagnostics() {
    let temp = TempDir::new().expect("temporary repository");
    let repository = temp.path().join("repository");
    create_repository(&repository);

    let initial = resolve_workspace_identity(&repository).expect("initial identity");
    run_git(&repository, &["branch", "-m", "renamed"]);
    let renamed = resolve_workspace_identity(&repository).expect("renamed identity");
    assert_eq!(initial.repository_key, renamed.repository_key);
    assert_eq!(initial.workspace_key, renamed.workspace_key);
    assert_ne!(initial.diagnostics.branch, renamed.diagnostics.branch);

    fs::write(repository.join("README.md"), "changed\n").expect("change repository file");
    run_git(&repository, &["add", "README.md"]);
    run_git(&repository, &["commit", "-m", "change head"]);
    let changed_head = resolve_workspace_identity(&repository).expect("changed identity");
    assert_eq!(initial.repository_key, changed_head.repository_key);
    assert_eq!(initial.workspace_key, changed_head.workspace_key);
    assert_ne!(initial.diagnostics.head, changed_head.diagnostics.head);
}

#[test]
fn workspace_diagnostics_reject_escaping_refs_and_invalid_detached_heads() {
    let temp = TempDir::new().expect("temporary repository");
    let repository = temp.path().join("repository");
    create_repository(&repository);
    let git_dir = repository.join(".git");
    let outside = temp.path().join("outside-ref");
    let outside_object_id = "a".repeat(40);
    fs::write(&outside, format!("{outside_object_id}\n")).expect("outside sentinel");

    for reference in [
        outside.to_string_lossy().into_owned(),
        "../../outside-ref".to_string(),
        "refs//heads/main".to_string(),
        "refs/./heads/main".to_string(),
        "refs/heads/../main".to_string(),
        "refs/heads/".to_string(),
        "refs/".to_string(),
        "refs".to_string(),
        "/refs/heads/main".to_string(),
        "refs/heads/control\nname".to_string(),
        "C:\\outside-ref".to_string(),
    ] {
        fs::write(git_dir.join("HEAD"), format!("ref: {reference}\n"))
            .expect("write malicious HEAD");
        let identity = resolve_workspace_identity(&repository)
            .expect("invalid diagnostics must not block identity");
        assert_ne!(
            identity.diagnostics.head.as_deref(),
            Some(outside_object_id.as_str())
        );
        assert_eq!(identity.diagnostics.head, None);
        assert_eq!(identity.diagnostics.branch, None);
        assert_eq!(
            identity.diagnostics.warnings,
            vec![WorkspaceDiagnosticWarning {
                source: WorkspaceDiagnosticSource::Head,
                kind: WorkspaceDiagnosticWarningKind::InvalidReference,
            }]
        );
        let warning_debug = format!("{:?}", identity.diagnostics.warnings);
        assert!(!warning_debug.contains(temp.path().to_string_lossy().as_ref()));
        assert!(!warning_debug.contains(&outside_object_id));
    }

    fs::write(git_dir.join("HEAD"), "not-an-object-id\n").expect("write invalid detached HEAD");
    let invalid_detached = resolve_workspace_identity(&repository)
        .expect("invalid detached diagnostics must not block identity");
    assert_eq!(invalid_detached.diagnostics.head, None);
    assert_eq!(
        invalid_detached.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::Head,
            kind: WorkspaceDiagnosticWarningKind::InvalidObjectId,
        }]
    );

    for valid_object_id in ["d".repeat(40), "c".repeat(64)] {
        fs::write(git_dir.join("HEAD"), format!("{valid_object_id}\n"))
            .expect("write valid detached HEAD");
        let valid_detached =
            resolve_workspace_identity(&repository).expect("valid detached identity");
        assert_eq!(
            valid_detached.diagnostics.head.as_deref(),
            Some(valid_object_id.as_str())
        );
        assert!(valid_detached.diagnostics.warnings.is_empty());
    }
}

#[test]
fn workspace_diagnostic_read_failure_does_not_block_identity() {
    let temp = TempDir::new().expect("temporary repository");
    let repository = temp.path().join("repository");
    create_repository(&repository);
    let before = resolve_workspace_identity(&repository).expect("identity before diagnostic fault");
    let head_path = repository.join(".git/HEAD");
    fs::remove_file(&head_path).expect("remove HEAD file");
    fs::create_dir(&head_path).expect("replace HEAD with unreadable directory");

    let identity = resolve_workspace_identity(&repository)
        .expect("diagnostic read failure must not block identity");
    assert_eq!(identity.repository_key, before.repository_key);
    assert_eq!(identity.workspace_key, before.workspace_key);
    assert_eq!(identity.diagnostics.branch, None);
    assert_eq!(identity.diagnostics.head, None);
    assert_eq!(
        identity.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::Head,
            kind: WorkspaceDiagnosticWarningKind::ReadFailed,
        }]
    );
}

#[test]
fn key_defining_git_metadata_failure_still_blocks_identity() {
    let temp = TempDir::new().expect("temporary repository");
    let repository = temp.path().join("repository");
    create_repository(&repository);
    fs::write(repository.join(".git/commondir"), "missing-common-dir\n")
        .expect("write invalid common directory");

    assert!(resolve_workspace_identity(&repository).is_err());
}

#[test]
fn workspace_identity_changes_when_same_path_is_recreated() {
    let temp = TempDir::new().expect("temporary identity roots");
    let repository = temp.path().join("repository");
    create_repository(&repository);
    let first_repository =
        resolve_workspace_identity(&repository).expect("first repository identity");

    fs::remove_dir_all(&repository).expect("remove first repository");
    fs::create_dir(temp.path().join("inode-spacer")).expect("consume replacement identity");
    create_repository(&repository);
    let second_repository =
        resolve_workspace_identity(&repository).expect("second repository identity");
    assert_ne!(
        first_repository.repository_key,
        second_repository.repository_key
    );
    assert_ne!(
        first_repository.workspace_key,
        second_repository.workspace_key
    );

    let plain = temp.path().join("plain");
    fs::create_dir(&plain).expect("first plain root");
    let first_plain = resolve_workspace_identity(&plain).expect("first plain identity");
    fs::remove_dir(&plain).expect("remove first plain root");
    fs::create_dir(temp.path().join("plain-inode-spacer"))
        .expect("consume plain replacement identity");
    fs::create_dir(&plain).expect("second plain root");
    let second_plain = resolve_workspace_identity(&plain).expect("second plain identity");
    assert_ne!(first_plain.repository_key, second_plain.repository_key);
    assert_ne!(first_plain.workspace_key, second_plain.workspace_key);
}

#[cfg(unix)]
#[test]
fn workspace_diagnostics_do_not_follow_symlinked_ref_files_or_directories() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("temporary repository");
    let repository = temp.path().join("repository");
    create_repository(&repository);
    let git_dir = repository.join(".git");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");
    let outside_object_id = "b".repeat(40);
    fs::write(outside.join("leaf"), format!("{outside_object_id}\n")).expect("outside sentinel");

    symlink(outside.join("leaf"), git_dir.join("refs/heads/linked")).expect("symlinked ref file");
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/linked\n").expect("point at linked ref");
    let linked_file = resolve_workspace_identity(&repository).expect("identity with linked ref");
    assert_eq!(linked_file.diagnostics.head, None);
    assert_eq!(
        linked_file.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::LooseReference,
            kind: WorkspaceDiagnosticWarningKind::SymlinkRejected,
        }]
    );

    fs::remove_file(git_dir.join("refs/heads/linked")).expect("remove linked ref file");
    symlink(&outside, git_dir.join("refs/heads/linked-dir")).expect("symlinked ref directory");
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/linked-dir/leaf\n")
        .expect("point at linked ref directory");
    let linked_directory =
        resolve_workspace_identity(&repository).expect("identity with linked ref directory");
    assert_eq!(linked_directory.diagnostics.head, None);
    assert_eq!(
        linked_directory.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::LooseReference,
            kind: WorkspaceDiagnosticWarningKind::SymlinkRejected,
        }]
    );

    let outside_packed_refs = outside.join("packed-refs");
    fs::write(
        &outside_packed_refs,
        format!("{outside_object_id} refs/heads/packed\n"),
    )
    .expect("outside packed refs sentinel");
    symlink(&outside_packed_refs, git_dir.join("packed-refs")).expect("symlinked packed refs file");
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/packed\n").expect("point at packed ref");
    let linked_packed =
        resolve_workspace_identity(&repository).expect("identity with linked packed refs");
    assert_eq!(linked_packed.diagnostics.head, None);
    assert_eq!(
        linked_packed.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::PackedReferences,
            kind: WorkspaceDiagnosticWarningKind::SymlinkRejected,
        }]
    );

    fs::remove_file(git_dir.join("HEAD")).expect("remove HEAD file");
    symlink(outside.join("leaf"), git_dir.join("HEAD")).expect("symlinked HEAD file");
    let linked_head = resolve_workspace_identity(&repository).expect("identity with linked HEAD");
    assert_eq!(linked_head.diagnostics.head, None);
    assert_eq!(
        linked_head.diagnostics.warnings,
        vec![WorkspaceDiagnosticWarning {
            source: WorkspaceDiagnosticSource::Head,
            kind: WorkspaceDiagnosticWarningKind::SymlinkRejected,
        }]
    );
}

#[cfg(unix)]
#[test]
fn workspace_symlink_alias_is_same_but_state_symlink_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("temporary symlinks");
    let repository = temp.path().join("repository");
    let alias = temp.path().join("alias");
    create_repository(&repository);
    symlink(&repository, &alias).expect("repository alias");

    assert_eq!(
        resolve_workspace_identity(&repository).expect("repository identity"),
        resolve_workspace_identity(&alias).expect("alias identity")
    );

    let target = temp.path().join("target.json");
    let state_link = temp.path().join("state.json");
    fs::write(&target, "{}\n").expect("state target");
    symlink(&target, &state_link).expect("state symlink");
    let error = AtomicJsonStore::new(&state_link, 1)
        .load::<serde_json::Value>()
        .expect_err("state symlink must be rejected");
    assert!(matches!(error, StateError::SymlinkRejected { .. }));
}

#[cfg(unix)]
#[test]
fn state_parent_and_lock_symlinks_are_rejected_without_touching_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let temp = TempDir::new().expect("temporary symlinks");
    let real_parent = temp.path().join("real-parent");
    let linked_parent = temp.path().join("linked-parent");
    fs::create_dir(&real_parent).expect("real state parent");
    symlink(&real_parent, &linked_parent).expect("linked state parent");

    let parent_error = AtomicJsonStore::new(linked_parent.join("state.json"), 1)
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect_err("parent symlink must be rejected");
    assert!(matches!(parent_error, StateError::SymlinkRejected { .. }));
    assert!(!real_parent.join("state.json").exists());

    let real_child = real_parent.join("child");
    fs::create_dir(&real_child).expect("real child state parent");
    let intermediate_error = AtomicJsonStore::new(linked_parent.join("child/state.json"), 1)
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect_err("intermediate symlink must be rejected");
    assert!(matches!(
        intermediate_error,
        StateError::SymlinkRejected { .. }
    ));
    assert!(!real_child.join("state.json").exists());

    let nested = temp.path().join("nested");
    fs::create_dir(&nested).expect("nested state parent");
    fs::set_permissions(&nested, fs::Permissions::from_mode(0o700))
        .expect("private nested state parent");
    let store = AtomicJsonStore::new(nested.join("state.json"), 1);
    let lock_target = temp.path().join("lock-target");
    fs::write(&lock_target, b"sentinel\n").expect("lock target");
    symlink(&lock_target, lock_path(&store)).expect("linked lock file");

    let lock_error = store
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect_err("lock symlink must be rejected");
    assert!(matches!(lock_error, StateError::SymlinkRejected { .. }));
    assert_eq!(
        fs::read(&lock_target).expect("unchanged lock target"),
        b"sentinel\n"
    );
}

#[test]
fn atomic_json_is_versioned_private_and_fenced_by_revision_and_owner() {
    let temp = TempDir::new().expect("temporary state");
    let state_path = temp.path().join("private").join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);

    let first = store
        .compare_and_swap(None, owner("owner-a", 1), &json!({ "value": 1 }))
        .expect("create state");
    let loaded = store
        .load::<serde_json::Value>()
        .expect("load state")
        .expect("state exists");
    assert_eq!(loaded.schema_version, 1);
    assert_eq!(loaded.revision, first);
    assert_eq!(loaded.owner, owner("owner-a", 1));
    assert_eq!(loaded.value, json!({ "value": 1 }));

    let second = store
        .compare_and_swap(Some(&first), owner("owner-a", 1), &json!({ "value": 2 }))
        .expect("update state");
    assert_eq!(second.sequence, first.sequence + 1);
    assert!(matches!(
        store.compare_and_swap(Some(&first), owner("owner-a", 1), &json!({ "value": 3 })),
        Err(StateError::StaleRevision { .. })
    ));
    assert!(matches!(
        store.compare_and_swap(Some(&second), owner("owner-b", 1), &json!({ "value": 3 })),
        Err(StateError::StaleOwnerGeneration { .. })
    ));

    let third = store
        .compare_and_swap(Some(&second), owner("owner-b", 2), &json!({ "value": 3 }))
        .expect("new owner generation");
    assert_eq!(third.sequence, 3);
    assert!(matches!(
        AtomicJsonStore::new(&state_path, 2).load::<serde_json::Value>(),
        Err(StateError::SchemaVersionMismatch {
            expected: 2,
            actual: 1
        })
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(state_path.parent().unwrap())
                .expect("state parent metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(&state_path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
        assert_eq!(
            fs::metadata(lock_path(&store))
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
}

#[cfg(unix)]
#[test]
fn new_state_directories_are_private_and_insecure_existing_parent_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary state");
    let first = temp.path().join("first");
    let second = first.join("second");
    let state_path = second.join("state.json");
    AtomicJsonStore::new(&state_path, 1)
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect("create nested private state");
    for directory in [&first, &second] {
        assert_eq!(
            fs::metadata(directory)
                .expect("state directory metadata")
                .permissions()
                .mode()
                & 0o077,
            0,
            "{} must be private",
            directory.display()
        );
    }

    let insecure_parent = temp.path().join("insecure");
    fs::create_dir(&insecure_parent).expect("insecure state parent");
    fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o755))
        .expect("make state parent insecure");
    let error = AtomicJsonStore::new(insecure_parent.join("state.json"), 1)
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect_err("insecure state parent must fail closed");
    assert!(matches!(
        error,
        StateError::InsecurePrivatePermissions { .. }
    ));
    assert!(!insecure_parent.join("state.json").exists());
}

#[cfg(not(unix))]
#[test]
fn writes_fail_closed_without_private_permission_support() {
    let temp = TempDir::new().expect("temporary state");
    let store = AtomicJsonStore::new(temp.path().join("state.json"), 1);
    assert!(matches!(
        store.compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 })),
        Err(StateError::PrivatePermissionsUnsupported { .. })
    ));
    assert_eq!(
        store
            .load::<serde_json::Value>()
            .expect("read remains supported"),
        None
    );
}

#[test]
fn same_resource_writers_serialize_and_one_stale_cas_is_rejected() {
    let temp = TempDir::new().expect("temporary state");
    let state_path = temp.path().join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);
    assert_eq!(
        store.physical_resource_id().expect("resource identity"),
        store
            .clone()
            .physical_resource_id()
            .expect("same resource identity")
    );
    let revision = store
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 0 }))
        .expect("initial state");
    let start = Arc::new(Barrier::new(3));

    let writers = [1, 2].map(|value| {
        let store = store.clone();
        let revision = revision.clone();
        let start = Arc::clone(&start);
        thread::spawn(move || {
            start.wait();
            store.compare_and_swap(
                Some(&revision),
                owner("owner", 1),
                &json!({ "value": value }),
            )
        })
    });
    start.wait();

    let results = writers.map(|writer| writer.join().expect("writer thread"));
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StateError::StaleRevision { .. })))
            .count(),
        1
    );
}

#[test]
fn fingerprint_only_drift_is_stale_and_preserves_external_bytes() {
    let temp = TempDir::new().expect("temporary state");
    let state_path = temp.path().join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);
    let revision = store
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect("initial state");

    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).expect("state bytes"))
            .expect("valid state document");
    document["value"] = json!({ "value": 2, "external": true });
    let mut drifted = serde_json::to_vec_pretty(&document).expect("serialize drifted state");
    drifted.push(b'\n');
    fs::write(&state_path, &drifted).expect("write fingerprint-only drift");

    let error = store
        .compare_and_swap(Some(&revision), owner("owner", 1), &json!({ "value": 3 }))
        .expect_err("fingerprint drift must be stale");
    match error {
        StateError::StaleRevision {
            actual: Some(actual),
            ..
        } => {
            assert_eq!(actual.sequence, revision.sequence);
            assert_ne!(actual.fingerprint, revision.fingerprint);
        }
        other => panic!("expected stale revision, got {other}"),
    }
    assert_eq!(fs::read(&state_path).expect("preserved drift"), drifted);
}

struct FailingValue;

impl Serialize for FailingValue {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Err(serde::ser::Error::custom(
            "deliberate serialization failure",
        ))
    }
}

#[test]
fn serialization_failure_is_distinct_and_preserves_existing_state() {
    let temp = TempDir::new().expect("temporary state");
    let state_path = temp.path().join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);
    let revision = store
        .compare_and_swap(None, owner("owner", 1), &json!({ "value": 1 }))
        .expect("initial state");
    let before = fs::read(&state_path).expect("state before failed serialization");

    let error = store
        .compare_and_swap(Some(&revision), owner("owner", 1), &FailingValue)
        .expect_err("serialization must fail");
    assert!(matches!(error, StateError::Serialization { .. }));
    assert_eq!(
        fs::read(&state_path).expect("state after failed serialization"),
        before
    );
}

#[test]
fn owner_generation_bounds_and_transition_rules_are_enforced() {
    assert!(matches!(
        OwnerGeneration::new("owner", 0),
        Err(StateError::InvalidOwnerGeneration)
    ));
    assert!(matches!(
        OwnerGeneration::new("owner", u64::MAX),
        Err(StateError::InvalidOwnerGeneration)
    ));

    let temp = TempDir::new().expect("temporary state");
    let state_path = temp.path().join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);
    let first = store
        .compare_and_swap(None, owner("owner-a", 5), &json!({ "value": 1 }))
        .expect("initial generation");
    let before_rollback = fs::read(&state_path).expect("state before rollback");
    assert!(matches!(
        store.compare_and_swap(Some(&first), owner("owner-a", 4), &json!({ "value": 2 })),
        Err(StateError::StaleOwnerGeneration { .. })
    ));
    assert_eq!(
        fs::read(&state_path).expect("state after rollback rejection"),
        before_rollback
    );

    let equal = store
        .compare_and_swap(Some(&first), owner("owner-a", 5), &json!({ "value": 2 }))
        .expect("equal same-owner generation");
    let higher = store
        .compare_and_swap(Some(&equal), owner("owner-a", 6), &json!({ "value": 3 }))
        .expect("higher same-owner generation");
    assert!(matches!(
        store.compare_and_swap(Some(&higher), owner("owner-b", 6), &json!({ "value": 4 })),
        Err(StateError::StaleOwnerGeneration { .. })
    ));
    store
        .compare_and_swap(Some(&higher), owner("owner-b", 7), &json!({ "value": 4 }))
        .expect("strictly higher takeover generation");

    let boundary_path = temp.path().join("boundary.json");
    let boundary_store = AtomicJsonStore::new(&boundary_path, 1);
    let boundary = boundary_store
        .compare_and_swap(None, owner("owner-a", u64::MAX - 2), &json!({ "value": 1 }))
        .expect("largest recoverable initial generation");
    let largest_takeover = boundary_store
        .compare_and_swap(
            Some(&boundary),
            owner("owner-b", u64::MAX - 1),
            &json!({ "value": 2 }),
        )
        .expect("largest accepted takeover generation");
    boundary_store
        .compare_and_swap(
            Some(&largest_takeover),
            owner("owner-b", u64::MAX - 1),
            &json!({ "value": 3 }),
        )
        .expect("largest accepted generation remains usable by its owner");
}

#[test]
fn independent_processes_serialize_same_resource_and_reject_one_stale_cas() {
    let temp = TempDir::new().expect("temporary subprocess state");
    let state_path = temp.path().join("state.json");
    let store = AtomicJsonStore::new(&state_path, 1);
    let revision = store
        .compare_and_swap(None, owner("subprocess-owner", 1), &json!({ "value": 0 }))
        .expect("initial state");
    let start_path = temp.path().join("start");
    let ready_paths = [temp.path().join("ready-one"), temp.path().join("ready-two")];
    let result_paths = [
        temp.path().join("result-one"),
        temp.path().join("result-two"),
    ];

    let mut children = ready_paths
        .iter()
        .zip(result_paths.iter())
        .map(|(ready_path, result_path)| {
            child_command("cas-existing", &state_path, result_path)
                .env(CHILD_READY_PATH, ready_path)
                .env(CHILD_START_PATH, &start_path)
                .env(CHILD_REVISION_SEQUENCE, revision.sequence.to_string())
                .env(CHILD_REVISION_FINGERPRINT, &revision.fingerprint)
                .spawn()
                .expect("spawn CAS child")
        })
        .collect::<Vec<_>>();
    for ready_path in &ready_paths {
        assert!(
            wait_for_path(ready_path, Duration::from_secs(10)),
            "child did not reach start barrier"
        );
    }
    fs::write(&start_path, b"start\n").expect("release CAS children");

    for child in children.drain(..) {
        assert_child_success(child.wait_with_output().expect("wait for CAS child"));
    }
    let outcomes = result_paths.map(|path| fs::read_to_string(path).expect("child outcome"));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.trim() == "success")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.trim() == "stale")
            .count(),
        1
    );
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn case_equivalent_absent_targets_share_one_create_only_lock() {
    let temp = TempDir::new().expect("temporary case-equivalent state");
    let upper_probe = temp.path().join("CaseProbe");
    fs::write(&upper_probe, b"probe\n").expect("case-sensitivity probe");
    if !temp.path().join("caseprobe").exists() {
        return;
    }
    fs::remove_file(upper_probe).expect("remove case-sensitivity probe");

    let state_paths = [
        temp.path().join("State.json"),
        temp.path().join("state.json"),
    ];
    let start_path = temp.path().join("start");
    let ready_paths = [temp.path().join("ready-one"), temp.path().join("ready-two")];
    let result_paths = [
        temp.path().join("result-one"),
        temp.path().join("result-two"),
    ];
    let mut children = state_paths
        .iter()
        .zip(ready_paths.iter())
        .zip(result_paths.iter())
        .map(|((state_path, ready_path), result_path)| {
            child_command("cas-create", state_path, result_path)
                .env(CHILD_READY_PATH, ready_path)
                .env(CHILD_START_PATH, &start_path)
                .spawn()
                .expect("spawn create-only child")
        })
        .collect::<Vec<_>>();
    for ready_path in &ready_paths {
        assert!(
            wait_for_path(ready_path, Duration::from_secs(10)),
            "child did not reach start barrier"
        );
    }
    fs::write(&start_path, b"start\n").expect("release create-only children");
    for child in children.drain(..) {
        assert_child_success(
            child
                .wait_with_output()
                .expect("wait for create-only child"),
        );
    }
    let outcomes = result_paths.map(|path| fs::read_to_string(path).expect("child outcome"));
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.trim() == "success")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome.trim() == "stale")
            .count(),
        1
    );
}

struct BlockingValue {
    entered: mpsc::SyncSender<()>,
    release: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl Serialize for BlockingValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.entered.send(()).expect("signal serializer entered");
        self.release
            .lock()
            .expect("release lock")
            .recv()
            .expect("release serializer");
        serializer.serialize_str("released")
    }
}

#[test]
fn different_physical_resources_do_not_share_a_lock() {
    let temp = TempDir::new().expect("temporary state");
    let first = AtomicJsonStore::new(temp.path().join("first.json"), 1);
    let second = AtomicJsonStore::new(temp.path().join("second.json"), 1);
    assert_ne!(
        first.physical_resource_id().expect("first resource id"),
        second.physical_resource_id().expect("second resource id")
    );
    let (entered_tx, entered_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let release_rx = Arc::new(Mutex::new(release_rx));

    let blocked_writer = thread::spawn(move || {
        first.compare_and_swap(
            None,
            owner("owner", 1),
            &BlockingValue {
                entered: entered_tx,
                release: release_rx,
            },
        )
    });
    entered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("first writer holds its resource lock");

    let (completed_tx, completed_rx) = mpsc::sync_channel(0);
    let other_writer = thread::spawn(move || {
        let result = second.compare_and_swap(None, owner("owner", 1), &json!({ "ok": true }));
        completed_tx.send(result).expect("report second write");
    });
    completed_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("different resource writes concurrently")
        .expect("second resource write succeeds");

    release_tx.send(()).expect("release first writer");
    blocked_writer
        .join()
        .expect("first writer thread")
        .expect("first resource write succeeds");
    other_writer.join().expect("second writer thread");
}

#[test]
fn independent_processes_make_progress_on_different_resources() {
    let temp = TempDir::new().expect("temporary subprocess state");
    let blocked_state = temp.path().join("blocked.json");
    let independent_state = temp.path().join("independent.json");
    let entered_path = temp.path().join("blocked-entered");
    let release_path = temp.path().join("blocked-release");
    let blocked_result = temp.path().join("blocked-result");
    let independent_result = temp.path().join("independent-result");

    let blocked_child = child_command("blocking-create", &blocked_state, &blocked_result)
        .env(CHILD_READY_PATH, &entered_path)
        .env(CHILD_RELEASE_PATH, &release_path)
        .spawn()
        .expect("spawn blocking child");
    assert!(
        wait_for_path(&entered_path, Duration::from_secs(10)),
        "blocking child did not acquire its resource lock"
    );

    let mut independent_child =
        child_command("simple-create", &independent_state, &independent_result)
            .spawn()
            .expect("spawn independent child");
    let deadline = Instant::now() + Duration::from_secs(3);
    let independent_status = loop {
        if let Some(status) = independent_child
            .try_wait()
            .expect("poll independent child")
        {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        thread::sleep(Duration::from_millis(10));
    };
    if independent_status.is_none() {
        fs::write(&release_path, b"release\n").expect("release blocked child after failure");
        let _ = blocked_child.wait_with_output();
        let _ = independent_child.kill();
        panic!("different resource was blocked by unrelated process lock");
    }
    assert!(
        independent_status.expect("independent status").success(),
        "independent child failed"
    );
    assert_eq!(
        fs::read_to_string(&independent_result)
            .expect("independent child result")
            .trim(),
        "success"
    );

    fs::write(&release_path, b"release\n").expect("release blocking child");
    assert_child_success(
        blocked_child
            .wait_with_output()
            .expect("wait for blocking child"),
    );
    assert_eq!(
        fs::read_to_string(&blocked_result)
            .expect("blocking child result")
            .trim(),
        "success"
    );
}
