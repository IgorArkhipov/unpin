use std::path::Path;

#[cfg(unix)]
use std::{fs, path::PathBuf};

use zeroize::Zeroizing;

#[cfg(unix)]
use super::broker_protocol::{
    BrokerRequest, BrokerResponse, broker_socket_directory, broker_socket_path,
    configure_unix_stream, effective_uid, read_response, write_request,
};
use super::{KEYCHAIN_SERVICE, KeychainSecretStore, SecretStore};
use super::{
    approval::APPROVAL_ACCOUNT, backup_authentication::BACKUP_AUTHENTICATION_ACCOUNT,
    session_authority::SESSION_AUTHORITY_ACCOUNT,
};

const CREDENTIAL_BUNDLE_ACCOUNT: &str = "credential-bundle-v1";
const BUNDLE_VERSION: u8 = 1;
const RESPONSE_BYTES: usize = 100;
#[cfg(unix)]
const BROKER_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(unix)]
const EXISTING_BROKER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(unix)]
const BROKER_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
#[cfg(unix)]
const STABLE_BROKER_DIRECTORY: &str = "credential-broker";
#[cfg(unix)]
const STABLE_BROKER_PROTOCOL_DIRECTORY: &str = "v1";
#[cfg(unix)]
const STABLE_BROKER_EXECUTABLE: &str = "unpin-credential-broker";

#[derive(Debug, Clone, Default)]
pub(super) struct CredentialBundle {
    approval: Option<Zeroizing<[u8; 32]>>,
    backup_authentication: Option<Zeroizing<[u8; 32]>>,
    session_authority: Option<Zeroizing<[u8; 32]>>,
}

impl CredentialBundle {
    pub(super) fn approval(&self) -> Option<[u8; 32]> {
        self.approval.as_deref().copied()
    }

    pub(super) fn backup_authentication(&self) -> Option<[u8; 32]> {
        self.backup_authentication.as_deref().copied()
    }

    pub(super) fn session_authority(&self) -> Option<[u8; 32]> {
        self.session_authority.as_deref().copied()
    }

    fn is_complete(&self) -> bool {
        self.approval.is_some()
            && self.backup_authentication.is_some()
            && self.session_authority.is_some()
    }
}

pub(super) fn resolve_runtime_bundle(app_state_root: &Path) -> Result<CredentialBundle, String> {
    load_bundle_from_store(&KeychainSecretStore::new(app_state_root))
}

fn load_bundle_from_store(store: &impl SecretStore) -> Result<CredentialBundle, String> {
    if let Some(serialized) = store.get(KEYCHAIN_SERVICE, CREDENTIAL_BUNDLE_ACCOUNT)? {
        let serialized = Zeroizing::new(serialized);
        return decode_bundle(&serialized);
    }

    let bundle = CredentialBundle {
        approval: load_account(store, APPROVAL_ACCOUNT)?,
        backup_authentication: load_account(store, BACKUP_AUTHENTICATION_ACCOUNT)?,
        session_authority: load_account(store, SESSION_AUTHORITY_ACCOUNT)?,
    };
    if bundle.is_complete() {
        let serialized = encode_bundle(&bundle);
        store.set(KEYCHAIN_SERVICE, CREDENTIAL_BUNDLE_ACCOUNT, &serialized)?;
    }
    Ok(bundle)
}

#[cfg(test)]
fn refresh_incomplete_bundle(
    bundle: &mut CredentialBundle,
    store: &impl SecretStore,
) -> Result<(), String> {
    if !bundle.is_complete() {
        *bundle = load_bundle_from_store(store)?;
    }
    Ok(())
}

fn load_account(
    store: &impl SecretStore,
    account: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    let Some(secret) = store.get(KEYCHAIN_SERVICE, account)? else {
        return Ok(None);
    };
    let secret = Zeroizing::new(secret);
    let bytes: [u8; 32] = secret
        .as_slice()
        .try_into()
        .map_err(|_| format!("stored credential {account} must be exactly 32 bytes"))?;
    Ok(Some(Zeroizing::new(bytes)))
}

fn encode_bundle(bundle: &CredentialBundle) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(RESPONSE_BYTES));
    encoded.push(BUNDLE_VERSION);
    for value in [
        bundle.approval.as_deref(),
        bundle.backup_authentication.as_deref(),
        bundle.session_authority.as_deref(),
    ] {
        match value {
            Some(value) => {
                encoded.push(1);
                encoded.extend_from_slice(value);
            }
            None => {
                encoded.push(0);
                encoded.extend_from_slice(&[0; 32]);
            }
        }
    }
    encoded
}

fn decode_bundle(serialized: &[u8]) -> Result<CredentialBundle, String> {
    if serialized.len() != RESPONSE_BYTES || serialized[0] != BUNDLE_VERSION {
        return Err("stored credential bundle has an invalid format".to_string());
    }

    let mut offset = 1;
    let mut next_field = || -> Result<Option<Zeroizing<[u8; 32]>>, String> {
        let present = serialized[offset];
        offset += 1;
        let bytes: [u8; 32] = serialized[offset..offset + 32]
            .try_into()
            .expect("credential bundle field length is fixed");
        offset += 32;
        match present {
            0 if bytes == [0; 32] => Ok(None),
            1 => Ok(Some(Zeroizing::new(bytes))),
            _ => Err("stored credential bundle has an invalid field".to_string()),
        }
    };
    let approval = next_field()?;
    let backup_authentication = next_field()?;
    let session_authority = next_field()?;

    Ok(CredentialBundle {
        approval,
        backup_authentication,
        session_authority,
    })
}

#[cfg(unix)]
pub(super) fn get(app_state_root: &Path, account: &str) -> Result<Option<Vec<u8>>, String> {
    let mut response = request_or_start_broker(
        app_state_root,
        &BrokerRequest::Get {
            account: account.to_string(),
        },
    )?;
    match &mut response {
        BrokerResponse::Value(value) => Ok(Some(std::mem::take(value))),
        BrokerResponse::NotFound => Ok(None),
        BrokerResponse::Error(error) => Err(error.clone()),
        BrokerResponse::Success => {
            Err("credential broker returned an invalid response".to_string())
        }
    }
}

#[cfg(unix)]
pub(super) fn set(app_state_root: &Path, account: &str, secret: &[u8]) -> Result<(), String> {
    let response = request_or_start_broker(
        app_state_root,
        &BrokerRequest::Set {
            account: account.to_string(),
            secret: secret.to_vec(),
        },
    )?;
    match &response {
        BrokerResponse::Success => Ok(()),
        BrokerResponse::Error(error) => Err(error.clone()),
        BrokerResponse::Value(_) | BrokerResponse::NotFound => {
            Err("credential broker returned an invalid response".to_string())
        }
    }
}

#[cfg(unix)]
pub(super) fn delete(app_state_root: &Path, account: &str) -> Result<bool, String> {
    let response = request_or_start_broker(
        app_state_root,
        &BrokerRequest::Delete {
            account: account.to_string(),
        },
    )?;
    match &response {
        BrokerResponse::Success => Ok(true),
        BrokerResponse::NotFound => Ok(false),
        BrokerResponse::Error(error) => Err(error.clone()),
        BrokerResponse::Value(_) => {
            Err("credential broker returned an invalid response".to_string())
        }
    }
}

#[cfg(unix)]
pub(super) fn legacy_keyring_fallback_allowed(app_state_root: &Path) -> Result<bool, String> {
    let candidate = bundled_broker_executable_path()?;
    legacy_keyring_fallback_allowed_for_paths(app_state_root, &candidate)
}

#[cfg(unix)]
fn legacy_keyring_fallback_allowed_for_paths(
    app_state_root: &Path,
    candidate: &Path,
) -> Result<bool, String> {
    use std::io;

    validate_existing_broker_installation_directories(app_state_root)?;
    for path in [
        stable_broker_executable_path(app_state_root),
        candidate.to_path_buf(),
    ] {
        match fs::symlink_metadata(path) {
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "credential broker availability could not be checked: {error}"
                ));
            }
        }
    }

    let socket_directory = broker_socket_directory(app_state_root);
    match fs::symlink_metadata(&socket_directory) {
        Ok(_) => {
            validate_broker_socket_directory_for_client(&socket_directory)?;
            match fs::symlink_metadata(broker_socket_path(app_state_root)) {
                Ok(_) => Ok(false),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(format!(
                    "credential broker socket availability could not be checked: {error}"
                )),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!(
            "credential broker directory availability could not be checked: {error}"
        )),
    }
}

#[cfg(unix)]
fn validate_existing_broker_installation_directories(app_state_root: &Path) -> Result<(), String> {
    use std::{
        io,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    let root_metadata = match fs::symlink_metadata(app_state_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != effective_uid()
    {
        return Err("credential broker app state root must be a regular directory".to_string());
    }

    let mut directory = app_state_root.to_path_buf();
    for component in [STABLE_BROKER_DIRECTORY, STABLE_BROKER_PROTOCOL_DIRECTORY] {
        directory.push(component);
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.to_string()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != root_metadata.uid()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err("credential broker installation directory is invalid".to_string());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn request_or_start_broker(
    app_state_root: &Path,
    request: &BrokerRequest,
) -> Result<BrokerResponse, String> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Instant,
    };

    let socket_path = broker_socket_path(app_state_root);
    match request_ready_broker(&socket_path, request) {
        Ok(response) => return Ok(response),
        Err(ReadyBrokerRequestError::Operation(error)) => return Err(error),
        Err(ReadyBrokerRequestError::NotReady) => {}
    }

    let candidate = bundled_broker_executable_path()?;
    let executable =
        install_stable_broker_from(&candidate, app_state_root, verify_broker_code_signature)?;
    let deadline = Instant::now() + BROKER_STARTUP_TIMEOUT;
    let mut child = Command::new(executable)
        .arg("--app-state-root")
        .arg(app_state_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("credential broker could not start: {error}"))?;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(std::time::Duration::from_millis(20)));
        match request_ready_broker(&socket_path, request) {
            Ok(response) => {
                thread::spawn(move || {
                    let _ = child.wait();
                });
                return Ok(response);
            }
            Err(ReadyBrokerRequestError::Operation(error)) => {
                thread::spawn(move || {
                    let _ = child.wait();
                });
                return Err(error);
            }
            Err(ReadyBrokerRequestError::NotReady) => {}
        }
    }
    terminate_broker_child(&mut child);
    Err("credential broker did not become ready".to_string())
}

#[cfg(unix)]
#[derive(Debug)]
enum ReadyBrokerRequestError {
    NotReady,
    Operation(String),
}

#[cfg(unix)]
fn request_ready_broker(
    socket_path: &Path,
    request: &BrokerRequest,
) -> Result<BrokerResponse, ReadyBrokerRequestError> {
    request_ready_broker_with(request, |operation, timeout| {
        request_unix_operation(socket_path, operation, timeout)
    })
}

#[cfg(unix)]
fn request_ready_broker_with(
    request: &BrokerRequest,
    mut perform: impl FnMut(&BrokerRequest, std::time::Duration) -> Result<BrokerResponse, String>,
) -> Result<BrokerResponse, ReadyBrokerRequestError> {
    match perform(&BrokerRequest::Ping, EXISTING_BROKER_PROBE_TIMEOUT) {
        Ok(BrokerResponse::Success) => {}
        Ok(_) | Err(_) => return Err(ReadyBrokerRequestError::NotReady),
    }
    perform(request, BROKER_OPERATION_TIMEOUT).map_err(ReadyBrokerRequestError::Operation)
}

#[cfg(unix)]
fn terminate_broker_child(child: &mut std::process::Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(unix)]
fn request_unix_operation(
    socket_path: &Path,
    request: &BrokerRequest,
    timeout: std::time::Duration,
) -> Result<BrokerResponse, String> {
    use std::os::unix::net::UnixStream;

    let socket_directory = socket_path
        .parent()
        .ok_or_else(|| "credential broker socket directory is unavailable".to_string())?;
    validate_broker_socket_directory_for_client(socket_directory)?;
    let mut stream = UnixStream::connect(socket_path).map_err(|error| error.to_string())?;
    configure_unix_stream(&stream, timeout)?;
    super::broker_client_auth::authorize(&stream)?;
    write_request(&mut stream, request)?;
    read_response(&mut stream)
}

#[cfg(unix)]
fn validate_broker_socket_directory_for_client(directory: &Path) -> Result<(), String> {
    validate_broker_socket_directory_for_client_with_uid(directory, effective_uid())
}

#[cfg(unix)]
fn validate_broker_socket_directory_for_client_with_uid(
    directory: &Path,
    expected_uid: u32,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("credential broker socket directory is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("credential broker socket directory must be a regular directory".to_string());
    }
    if metadata.uid() != expected_uid {
        return Err("credential broker socket directory owner is invalid".to_string());
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err("credential broker socket directory permissions are invalid".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn bundled_broker_executable_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let parent = executable
        .parent()
        .ok_or_else(|| "Unpin executable has no parent directory".to_string())?;
    Ok(parent.join(STABLE_BROKER_EXECUTABLE))
}

#[cfg(target_os = "macos")]
fn verify_broker_code_signature(path: &Path) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let fingerprint = option_env!("UNPIN_CODESIGN_CERTIFICATE_SHA1")
        .ok_or_else(|| "Unpin was not built with a broker certificate fingerprint".to_string())?;
    let fingerprint = fingerprint.to_ascii_lowercase();
    if fingerprint.len() != 40 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Unpin broker certificate fingerprint is invalid".to_string());
    }
    let requirement = format!(
        "identifier \"dev.unpin.credential-broker\" and certificate leaf = H\"{fingerprint}\""
    );
    let status = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", &format!("-R={requirement}")])
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("credential broker signature could not be checked: {error}"))?;
    if !status.success() {
        return Err("credential broker has an invalid Unpin code signature".to_string());
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn verify_broker_code_signature(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn install_stable_broker_from(
    candidate: &Path,
    app_state_root: &Path,
    verify: impl Fn(&Path) -> Result<(), String>,
) -> Result<PathBuf, String> {
    use std::{
        io,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };

    ensure_stable_broker_directory(app_state_root)?;
    let installed = stable_broker_executable_path(app_state_root);
    match fs::symlink_metadata(&installed) {
        Ok(_) => {
            validate_regular_broker_file(&installed)?;
            verify(&installed)?;
            return Ok(installed);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }

    match fs::symlink_metadata(candidate) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(
                "credential broker companion is missing; reinstall unpin and unpin-credential-broker together"
                    .to_string(),
            );
        }
        Err(error) => return Err(error.to_string()),
        Ok(_) => validate_regular_broker_file(candidate)?,
    }
    verify(candidate)?;
    let directory = installed
        .parent()
        .expect("stable broker executable always has a parent");
    let mut entropy = [0_u8; 8];
    getrandom::fill(&mut entropy).map_err(|error| error.to_string())?;
    let suffix = entropy
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary = directory.join(format!(".broker-install-{suffix}"));
    let copy_result = (|| {
        let mut source = fs::File::open(candidate).map_err(|error| error.to_string())?;
        let mut destination = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        io::copy(&mut source, &mut destination).map_err(|error| error.to_string())?;
        destination.sync_all().map_err(|error| error.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        verify(&temporary)?;
        match fs::hard_link(&temporary, &installed) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                validate_regular_broker_file(&installed)?;
                verify(&installed)?;
            }
            Err(error) => return Err(error.to_string()),
        }
        fs::File::open(directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    let cleanup_result = fs::remove_file(&temporary);
    copy_result?;
    if let Err(error) = cleanup_result
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(format!(
            "stable broker temporary file cleanup failed: {error}"
        ));
    }
    let metadata = fs::metadata(&installed).map_err(|error| error.to_string())?;
    let root_metadata = fs::metadata(app_state_root).map_err(|error| error.to_string())?;
    if metadata.uid() != root_metadata.uid() {
        return Err("installed credential broker owner is invalid".to_string());
    }
    Ok(installed)
}

#[cfg(unix)]
fn validate_regular_broker_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("credential broker must be a regular file".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_stable_broker_directory(app_state_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::create_dir_all(app_state_root).map_err(|error| error.to_string())?;
    let root_metadata = fs::symlink_metadata(app_state_root).map_err(|error| error.to_string())?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != effective_uid()
    {
        return Err("credential broker app state root must be a regular directory".to_string());
    }
    let mut current = app_state_root.to_path_buf();
    for component in [STABLE_BROKER_DIRECTORY, STABLE_BROKER_PROTOCOL_DIRECTORY] {
        current.push(component);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != root_metadata.uid()
        {
            return Err("credential broker installation directory is invalid".to_string());
        }
        fs::set_permissions(&current, fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(unix)]
fn stable_broker_executable_path(app_state_root: &Path) -> PathBuf {
    app_state_root
        .join(STABLE_BROKER_DIRECTORY)
        .join(STABLE_BROKER_PROTOCOL_DIRECTORY)
        .join(STABLE_BROKER_EXECUTABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_bundle_round_trip_preserves_present_values() {
        let bundle = CredentialBundle {
            approval: Some(Zeroizing::new([0x11; 32])),
            backup_authentication: None,
            session_authority: Some(Zeroizing::new([0x53; 32])),
        };

        let encoded = encode_bundle(&bundle);
        let decoded = decode_bundle(&encoded).expect("decode credential bundle");

        assert_eq!(decoded.approval(), Some([0x11; 32]));
        assert_eq!(decoded.backup_authentication(), None);
        assert_eq!(decoded.session_authority(), Some([0x53; 32]));
    }

    #[test]
    fn credential_bundle_rejects_invalid_fields() {
        let mut encoded = Zeroizing::new([0; RESPONSE_BYTES]);
        encoded[0] = BUNDLE_VERSION;
        encoded[1] = 2;

        assert!(decode_bundle(encoded.as_slice()).is_err());
    }

    #[test]
    fn complete_legacy_credentials_migrate_once_to_a_bundle() {
        let store = crate::credentials::test_support::FakeSecretStore::default();
        for (account, value) in [
            (APPROVAL_ACCOUNT, 0x11),
            (BACKUP_AUTHENTICATION_ACCOUNT, 0x42),
            (SESSION_AUTHORITY_ACCOUNT, 0x53),
        ] {
            store
                .set(KEYCHAIN_SERVICE, account, &[value; 32])
                .expect("store legacy credential");
        }
        let writes_before_migration = *store.writes.borrow();

        let first = load_bundle_from_store(&store).expect("migrate complete legacy credentials");
        let second = load_bundle_from_store(&store).expect("load migrated credentials");

        assert_eq!(first.approval(), Some([0x11; 32]));
        assert_eq!(first.backup_authentication(), Some([0x42; 32]));
        assert_eq!(first.session_authority(), Some([0x53; 32]));
        assert_eq!(second.approval(), Some([0x11; 32]));
        assert_eq!(*store.writes.borrow(), writes_before_migration + 1);
    }

    #[test]
    fn incomplete_bundle_refreshes_after_a_missing_key_is_initialized() {
        let store = crate::credentials::test_support::FakeSecretStore::default();
        store
            .set(KEYCHAIN_SERVICE, APPROVAL_ACCOUNT, &[0x11; 32])
            .expect("store approval key");
        store
            .set(KEYCHAIN_SERVICE, BACKUP_AUTHENTICATION_ACCOUNT, &[0x42; 32])
            .expect("store backup key");
        let mut bundle = load_bundle_from_store(&store).expect("load partial bundle");
        assert_eq!(bundle.session_authority(), None);

        store
            .set(KEYCHAIN_SERVICE, SESSION_AUTHORITY_ACCOUNT, &[0x53; 32])
            .expect("initialize session key");
        refresh_incomplete_bundle(&mut bundle, &store).expect("refresh incomplete bundle");

        assert_eq!(bundle.session_authority(), Some([0x53; 32]));
        assert!(bundle.is_complete());
    }

    #[cfg(unix)]
    #[test]
    fn unix_broker_socket_path_is_short_for_deep_app_state_roots() {
        use std::os::unix::ffi::OsStrExt;

        let deep_root = PathBuf::from("/private/var/folders")
            .join("a".repeat(64))
            .join("b".repeat(64))
            .join("state");
        let socket = broker_socket_path(&deep_root);

        assert!(socket.starts_with("/tmp"));
        assert!(socket.as_os_str().as_bytes().len() < 104);
        let directory = socket.parent().expect("broker socket directory");
        let directory_name = directory
            .file_name()
            .expect("broker socket directory name")
            .to_string_lossy();
        assert!(directory_name.starts_with("unpin-stable-credential-broker-v1-"));
        assert!(!directory_name.starts_with("unpin-credential-broker-v1-"));
    }

    #[cfg(unix)]
    #[test]
    fn ready_broker_receives_ping_then_real_request_once() {
        let request = BrokerRequest::Delete {
            account: "cursor-dashboard-cookie-v1".to_string(),
        };
        let mut operations = Vec::new();

        let response = request_ready_broker_with(&request, |operation, timeout| match operation {
            BrokerRequest::Ping => {
                operations.push("ping");
                assert_eq!(timeout, EXISTING_BROKER_PROBE_TIMEOUT);
                Ok(BrokerResponse::Success)
            }
            BrokerRequest::Delete { .. } => {
                operations.push("delete");
                assert_eq!(timeout, BROKER_OPERATION_TIMEOUT);
                Ok(BrokerResponse::NotFound)
            }
            BrokerRequest::Get { .. } | BrokerRequest::Set { .. } => {
                panic!("unexpected request")
            }
        })
        .expect("ready broker request");

        assert_eq!(response, BrokerResponse::NotFound);
        assert_eq!(operations, ["ping", "delete"]);
    }

    #[cfg(unix)]
    #[test]
    fn stable_broker_install_is_create_once_across_companion_updates() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let first_candidate = root.path().join("first-candidate");
        let later_candidate = root.path().join("later-candidate");
        fs::write(&first_candidate, b"stable broker bytes").expect("first candidate");
        fs::write(&later_candidate, b"updated companion bytes").expect("later candidate");

        let installed = install_stable_broker_from(&first_candidate, root.path(), |_| Ok(()))
            .expect("first broker install");
        let reused = install_stable_broker_from(&later_candidate, root.path(), |_| Ok(()))
            .expect("reuse installed broker");

        assert_eq!(reused, installed);
        assert_eq!(
            fs::read(installed).expect("installed broker bytes"),
            b"stable broker bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stable_broker_install_reuses_existing_when_companion_is_missing() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let first_candidate = root.path().join("first-candidate");
        let missing_candidate = root.path().join("missing-candidate");
        fs::write(&first_candidate, b"stable broker bytes").expect("first candidate");

        let installed = install_stable_broker_from(&first_candidate, root.path(), |_| Ok(()))
            .expect("first broker install");
        let reused = install_stable_broker_from(&missing_candidate, root.path(), |_| Ok(()))
            .expect("reuse installed broker without a companion");

        assert_eq!(reused, installed);
        assert_eq!(
            fs::read(installed).expect("installed broker bytes"),
            b"stable broker bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn first_broker_update_allows_legacy_keyring_only_when_binaries_are_absent() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let missing_candidate = root.path().join("missing-candidate");

        assert!(
            legacy_keyring_fallback_allowed_for_paths(root.path(), &missing_candidate)
                .expect("missing broker paths")
        );

        fs::write(&missing_candidate, b"companion broker").expect("companion candidate");
        assert!(
            !legacy_keyring_fallback_allowed_for_paths(root.path(), &missing_candidate)
                .expect("present companion")
        );
    }

    #[cfg(unix)]
    #[test]
    fn first_broker_update_rejects_symlinked_stable_broker_directory() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let missing_candidate = root.path().join("missing-candidate");
        let redirected = root.path().join("redirected-broker-directory");
        fs::create_dir(&redirected).expect("redirected broker directory");
        std::os::unix::fs::symlink(&redirected, root.path().join(STABLE_BROKER_DIRECTORY))
            .expect("stable broker directory symlink");

        let error = legacy_keyring_fallback_allowed_for_paths(root.path(), &missing_candidate)
            .expect_err("symlinked stable broker directory must fail");

        assert_eq!(error, "credential broker installation directory is invalid");
    }

    #[cfg(unix)]
    #[test]
    fn foreign_owned_predictable_socket_directory_is_rejected() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::TempDir::new().expect("temporary broker root");
        let directory = broker_socket_directory(root.path());
        fs::create_dir(&directory).expect("socket directory");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("socket directory mode");
        let actual_uid = fs::symlink_metadata(&directory)
            .expect("socket directory metadata")
            .uid();
        let foreign_uid = actual_uid.wrapping_add(1);

        let error = validate_broker_socket_directory_for_client_with_uid(&directory, foreign_uid)
            .expect_err("foreign-owned socket directory must fail");

        assert_eq!(error, "credential broker socket directory owner is invalid");
        fs::remove_dir(directory).expect("remove socket directory");
    }

    #[cfg(unix)]
    #[test]
    fn permissive_or_symlinked_socket_directory_is_rejected() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::TempDir::new().expect("temporary broker root");
        let directory = broker_socket_directory(root.path());
        fs::create_dir(&directory).expect("socket directory");
        let uid = fs::symlink_metadata(&directory)
            .expect("socket directory metadata")
            .uid();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755))
            .expect("permissive socket directory mode");
        assert_eq!(
            validate_broker_socket_directory_for_client_with_uid(&directory, uid)
                .expect_err("permissive socket directory must fail"),
            "credential broker socket directory permissions are invalid"
        );
        fs::remove_dir(&directory).expect("remove socket directory");

        let target = root.path().join("socket-directory-target");
        fs::create_dir(&target).expect("socket directory target");
        std::os::unix::fs::symlink(&target, &directory).expect("socket directory symlink");
        assert_eq!(
            validate_broker_socket_directory_for_client_with_uid(&directory, uid)
                .expect_err("symlinked socket directory must fail"),
            "credential broker socket directory must be a regular directory"
        );
        fs::remove_file(directory).expect("remove socket directory symlink");
    }

    #[cfg(unix)]
    #[test]
    fn missing_companion_has_recovery_diagnostic_when_no_stable_broker_exists() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let missing_candidate = root.path().join("missing-candidate");

        let error = install_stable_broker_from(&missing_candidate, root.path(), |_| Ok(()))
            .expect_err("missing companion must fail");

        assert_eq!(
            error,
            "credential broker companion is missing; reinstall unpin and unpin-credential-broker together"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stable_broker_install_rejects_unverified_candidate_without_partial_state() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let candidate = root.path().join("candidate");
        fs::write(&candidate, b"untrusted broker").expect("candidate");

        let error = install_stable_broker_from(&candidate, root.path(), |_| {
            Err("signature rejected".to_string())
        })
        .expect_err("unverified candidate must fail");

        assert!(error.contains("signature rejected"));
        assert!(!stable_broker_executable_path(root.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn stable_broker_install_rejects_symlink_candidate() {
        let root = tempfile::TempDir::new().expect("temporary broker root");
        let target = root.path().join("target");
        let candidate = root.path().join("candidate");
        fs::write(&target, b"broker").expect("target");
        std::os::unix::fs::symlink(&target, &candidate).expect("candidate symlink");

        let error = install_stable_broker_from(&candidate, root.path(), |_| Ok(()))
            .expect_err("symlink candidate must fail");

        assert_eq!(error, "credential broker must be a regular file");
        assert!(!error.contains(&candidate.display().to_string()));
        assert!(!stable_broker_executable_path(root.path()).exists());
    }
}
