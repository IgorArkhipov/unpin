use std::path::Path;

#[cfg(unix)]
use std::{fs, path::PathBuf};

use zeroize::Zeroizing;

use super::{KEYCHAIN_SERVICE, KeychainSecretStore, SecretStore};
use super::{
    approval::APPROVAL_ACCOUNT, backup_authentication::BACKUP_AUTHENTICATION_ACCOUNT,
    session_authority::SESSION_AUTHORITY_ACCOUNT,
};

const CREDENTIAL_BUNDLE_ACCOUNT: &str = "credential-bundle-v1";
const BUNDLE_VERSION: u8 = 1;
#[cfg(unix)]
const REQUEST_BUNDLE: u8 = 1;
const RESPONSE_BYTES: usize = 100;
#[cfg(unix)]
const BROKER_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(unix)]
const EXISTING_BROKER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(unix)]
const BROKER_CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(unix)]
const MAX_ACTIVE_BROKER_CLIENTS: usize = 8;

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
    #[cfg(unix)]
    {
        request_or_start_broker(app_state_root)
    }

    #[cfg(not(unix))]
    {
        let _ = app_state_root;
        load_bundle_from_keychain()
    }
}

pub(crate) fn run(app_state_root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        run_unix_broker(app_state_root)
    }

    #[cfg(not(unix))]
    {
        let _ = app_state_root;
        Err("credential broker is only supported on Unix platforms".to_string())
    }
}

fn load_bundle_from_keychain() -> Result<CredentialBundle, String> {
    let store = KeychainSecretStore;
    load_bundle_from_store(&store)
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
fn run_unix_broker(app_state_root: &Path) -> Result<(), String> {
    use std::{
        os::unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
        time::Duration,
    };

    let socket_path = broker_socket_path(app_state_root);
    ensure_broker_directory(app_state_root)?;
    let listener = match UnixListener::bind(&socket_path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            if UnixStream::connect(&socket_path).is_ok() {
                return Ok(());
            }
            fs::remove_file(&socket_path).map_err(|error| error.to_string())?;
            UnixListener::bind(&socket_path).map_err(|error| error.to_string())?
        }
        Err(error) => return Err(error.to_string()),
    };
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    let result = serve_unix_broker(
        listener,
        CredentialBundle::default(),
        Duration::from_secs(600),
    );
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_dir(broker_socket_directory(app_state_root));
    result
}

#[cfg(unix)]
fn serve_unix_broker(
    listener: std::os::unix::net::UnixListener,
    bundle: CredentialBundle,
    idle_timeout: std::time::Duration,
) -> Result<(), String> {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };

    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut last_activity = Instant::now();
    let active_clients = Arc::new(AtomicUsize::new(0));
    let bundle = Arc::new(Mutex::new(bundle));
    let keychain_refresh_active = Arc::new(AtomicBool::new(false));
    refresh_incomplete_bundle_async(&bundle, &keychain_refresh_active);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                last_activity = Instant::now();
                refresh_incomplete_bundle_async(&bundle, &keychain_refresh_active);
                let active_clients = Arc::clone(&active_clients);
                if active_clients
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < MAX_ACTIVE_BROKER_CLIENTS).then_some(active + 1)
                    })
                    .is_ok()
                {
                    let bundle = bundle
                        .lock()
                        .map_err(|_| "credential broker bundle lock poisoned".to_string())?
                        .clone();
                    thread::spawn(move || {
                        let _ = serve_unix_client(stream, &bundle);
                        active_clients.fetch_sub(1, Ordering::Release);
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if last_activity.elapsed() >= idle_timeout {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

#[cfg(unix)]
fn refresh_incomplete_bundle_async(
    bundle: &std::sync::Arc<std::sync::Mutex<CredentialBundle>>,
    keychain_refresh_active: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;

    let needs_refresh = bundle
        .lock()
        .map(|bundle| !bundle.is_complete())
        .unwrap_or(false);
    if !needs_refresh
        || keychain_refresh_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }

    let bundle = std::sync::Arc::clone(bundle);
    let keychain_refresh_active = std::sync::Arc::clone(keychain_refresh_active);
    std::thread::spawn(move || {
        if let Ok(refreshed) = load_bundle_from_keychain()
            && let Ok(mut bundle) = bundle.lock()
        {
            *bundle = refreshed;
        }
        keychain_refresh_active.store(false, Ordering::Release);
    });
}

#[cfg(unix)]
fn serve_unix_client(
    mut stream: std::os::unix::net::UnixStream,
    bundle: &CredentialBundle,
) -> Result<(), String> {
    use std::io::{Read, Write};

    let mut request = [0; 1];
    configure_unix_stream(&stream, BROKER_CLIENT_TIMEOUT)?;
    stream
        .read_exact(&mut request)
        .map_err(|error| error.to_string())?;
    if request[0] != REQUEST_BUNDLE {
        return Err("credential broker received an invalid request".to_string());
    }
    let response = encode_bundle(bundle);
    stream
        .write_all(&response)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn request_or_start_broker(app_state_root: &Path) -> Result<CredentialBundle, String> {
    use std::{
        process::{Command, Stdio},
        thread,
        time::Instant,
    };

    let socket_path = broker_socket_path(app_state_root);
    let deadline = Instant::now() + BROKER_STARTUP_TIMEOUT;
    if let Ok(bundle) = request_unix_bundle(
        &socket_path,
        deadline
            .saturating_duration_since(Instant::now())
            .min(EXISTING_BROKER_PROBE_TIMEOUT),
    ) {
        return Ok(bundle);
    }
    if Instant::now() >= deadline {
        return Err("credential broker did not become ready".to_string());
    }

    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut child = Command::new(executable)
        .arg("credential-broker")
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
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Ok(bundle) = request_unix_bundle(&socket_path, remaining) {
            return Ok(bundle);
        }
    }
    terminate_broker_child(&mut child);
    Err("credential broker did not become ready".to_string())
}

#[cfg(unix)]
fn terminate_broker_child(child: &mut std::process::Child) {
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(unix)]
fn request_unix_bundle(
    socket_path: &Path,
    timeout: std::time::Duration,
) -> Result<CredentialBundle, String> {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    let mut stream = UnixStream::connect(socket_path).map_err(|error| error.to_string())?;
    configure_unix_stream(&stream, timeout)?;
    stream
        .write_all(&[REQUEST_BUNDLE])
        .map_err(|error| error.to_string())?;
    let mut response = Zeroizing::new([0; RESPONSE_BYTES]);
    stream
        .read_exact(&mut *response)
        .map_err(|error| error.to_string())?;
    decode_bundle(response.as_slice())
}

#[cfg(unix)]
fn configure_unix_stream(
    stream: &std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn ensure_broker_directory(app_state_root: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fs::create_dir_all(app_state_root).map_err(|error| error.to_string())?;
    let root_metadata = fs::symlink_metadata(app_state_root).map_err(|error| error.to_string())?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("credential broker app state root must be a regular directory".to_string());
    }
    let directory = broker_socket_directory(app_state_root);
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.to_string()),
    }
    let metadata = fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != root_metadata.uid()
    {
        return Err("credential broker directory must be a regular directory".to_string());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn broker_socket_path(app_state_root: &Path) -> PathBuf {
    broker_socket_directory(app_state_root).join("broker-v1.sock")
}

#[cfg(unix)]
fn broker_socket_directory(app_state_root: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let hash = app_state_root
        .as_os_str()
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    PathBuf::from("/tmp").join(format!("unpin-credential-broker-v1-{hash:016x}"))
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
    }

    #[cfg(unix)]
    #[test]
    fn unix_broker_serves_multiple_clients_from_one_loaded_bundle() {
        use std::{os::unix::net::UnixListener, thread, time::Duration};

        let root = tempfile::TempDir::new().expect("temporary broker root");
        ensure_broker_directory(root.path()).expect("private broker directory");
        let socket = broker_socket_path(root.path());
        let listener = UnixListener::bind(&socket).expect("bind credential broker");
        let bundle = CredentialBundle {
            approval: Some(Zeroizing::new([0x11; 32])),
            backup_authentication: Some(Zeroizing::new([0x42; 32])),
            session_authority: Some(Zeroizing::new([0x53; 32])),
        };
        let server =
            thread::spawn(move || serve_unix_broker(listener, bundle, Duration::from_secs(1)));

        let mut first = None;
        for _ in 0..100 {
            match request_unix_bundle(&socket, Duration::from_secs(2)) {
                Ok(bundle) => {
                    first = Some(bundle);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let first = first.expect("first broker client");
        let stalled_client = std::os::unix::net::UnixStream::connect(&socket)
            .expect("connect stalled broker client");
        let mut second = None;
        for _ in 0..100 {
            match request_unix_bundle(&socket, Duration::from_secs(2)) {
                Ok(bundle) => {
                    second = Some(bundle);
                    break;
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        let second = second.expect("second broker client");

        assert_eq!(first.approval(), Some([0x11; 32]));
        assert_eq!(second.backup_authentication(), Some([0x42; 32]));
        assert_eq!(second.session_authority(), Some([0x53; 32]));
        drop(stalled_client);
        server
            .join()
            .expect("broker thread")
            .expect("broker result");
        fs::remove_file(socket).expect("remove test socket");
        fs::remove_dir(broker_socket_directory(root.path()))
            .expect("remove private broker directory");
    }
}
