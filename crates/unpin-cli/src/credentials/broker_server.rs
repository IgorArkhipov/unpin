use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::broker_protocol::{
    BrokerRequest, BrokerResponse, broker_socket_directory, broker_socket_path,
    configure_unix_stream, read_request, write_response,
};

const KEYCHAIN_SERVICE: &str = "dev.unpin";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_ACTIVE_CLIENTS: usize = 8;

trait ClientAuthorizer {
    fn authorize(&self, stream: &UnixStream) -> Result<(), String>;
}

trait SecretBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, account: &str, secret: &[u8]) -> Result<(), String>;
    fn delete(&self, account: &str) -> Result<bool, String>;
}

struct KeyringBackend;

impl SecretBackend for KeyringBackend {
    fn get(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|_| "keychain entry could not be opened".to_string())?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err("keychain credential could not be read".to_string()),
        }
    }

    fn set(&self, account: &str, secret: &[u8]) -> Result<(), String> {
        keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|_| "keychain entry could not be opened".to_string())?
            .set_secret(secret)
            .map_err(|_| "keychain credential could not be stored".to_string())
    }

    fn delete(&self, account: &str) -> Result<bool, String> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, account)
            .map_err(|_| "keychain entry could not be opened".to_string())?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(_) => Err("keychain credential could not be removed".to_string()),
        }
    }
}

struct PlatformClientAuthorizer;

#[cfg(target_os = "macos")]
impl ClientAuthorizer for PlatformClientAuthorizer {
    fn authorize(&self, stream: &UnixStream) -> Result<(), String> {
        let fingerprint = option_env!("UNPIN_CODESIGN_CERTIFICATE_SHA1").ok_or_else(|| {
            "credential broker was not built with an Unpin client certificate".to_string()
        })?;
        let requirement = client_code_requirement(fingerprint)?;
        crate::broker_peer_auth::authorize(
            stream,
            &requirement,
            crate::broker_peer_auth::PeerKind::Client,
        )
    }
}

#[cfg(not(target_os = "macos"))]
impl ClientAuthorizer for PlatformClientAuthorizer {
    fn authorize(&self, stream: &UnixStream) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            crate::broker_protocol::authorize_same_user(stream, "credential broker client")
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Ok(())
        }
    }
}

pub(crate) fn run(app_state_root: &Path) -> Result<(), String> {
    ensure_socket_directory(app_state_root)?;
    let socket_path = broker_socket_path(app_state_root);
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
    let result = serve(
        listener,
        &PlatformClientAuthorizer,
        Arc::new(KeyringBackend),
    );
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_dir(broker_socket_directory(app_state_root));
    result
}

fn serve<A, B>(
    listener: UnixListener,
    authorizer: &'static A,
    backend: Arc<B>,
) -> Result<(), String>
where
    A: ClientAuthorizer + Sync,
    B: SecretBackend + Send + Sync + 'static,
{
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let mut last_activity = Instant::now();
    let active_clients = Arc::new(AtomicUsize::new(0));
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                last_activity = Instant::now();
                let active_clients = Arc::clone(&active_clients);
                if active_clients
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < MAX_ACTIVE_CLIENTS).then_some(active + 1)
                    })
                    .is_ok()
                {
                    let backend = Arc::clone(&backend);
                    thread::spawn(move || {
                        let _ = serve_client(stream, authorizer, backend.as_ref());
                        active_clients.fetch_sub(1, Ordering::Release);
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if last_activity.elapsed() >= IDLE_TIMEOUT {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn serve_client(
    mut stream: UnixStream,
    authorizer: &impl ClientAuthorizer,
    backend: &impl SecretBackend,
) -> Result<(), String> {
    authorizer.authorize(&stream)?;
    configure_unix_stream(&stream, CLIENT_TIMEOUT)?;
    let request = read_request(&mut stream)?;
    let response = match &request {
        BrokerRequest::Ping => BrokerResponse::Success,
        BrokerRequest::Get { account } => match backend.get(account) {
            Ok(Some(secret)) => BrokerResponse::Value(secret),
            Ok(None) => BrokerResponse::NotFound,
            Err(error) => BrokerResponse::Error(error),
        },
        BrokerRequest::Set { account, secret } => match backend.set(account, secret) {
            Ok(()) => BrokerResponse::Success,
            Err(error) => BrokerResponse::Error(error),
        },
        BrokerRequest::Delete { account } => match backend.delete(account) {
            Ok(true) => BrokerResponse::Success,
            Ok(false) => BrokerResponse::NotFound,
            Err(error) => BrokerResponse::Error(error),
        },
    };
    write_response(&mut stream, &response)
}

fn ensure_socket_directory(app_state_root: &Path) -> Result<(), String> {
    fs::create_dir_all(app_state_root).map_err(|error| error.to_string())?;
    let root_metadata = fs::symlink_metadata(app_state_root).map_err(|error| error.to_string())?;
    if root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || root_metadata.uid() != crate::broker_protocol::effective_uid()
    {
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
        || metadata.uid() != crate::broker_protocol::effective_uid()
    {
        return Err("credential broker directory must be a regular directory".to_string());
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn client_code_requirement(fingerprint: &str) -> Result<String, String> {
    let normalized = fingerprint.to_ascii_lowercase();
    if normalized.len() != 40 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Unpin client certificate fingerprint is invalid".to_string());
    }
    Ok(format!(
        "(identifier \"dev.unpin.cli\" or identifier \"dev.unpin.workbench.bridge\") and certificate leaf = H\"{normalized}\""
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        os::unix::net::UnixStream,
    };

    use super::*;
    use crate::broker_protocol::{BrokerRequest, BrokerResponse, read_response, write_request};

    struct AllowClient;

    impl ClientAuthorizer for AllowClient {
        fn authorize(&self, _stream: &UnixStream) -> Result<(), String> {
            Ok(())
        }
    }

    struct RejectClient;

    impl ClientAuthorizer for RejectClient {
        fn authorize(&self, _stream: &UnixStream) -> Result<(), String> {
            Err("client signature rejected".to_string())
        }
    }

    #[derive(Default)]
    struct FakeBackend {
        values: RefCell<BTreeMap<String, Vec<u8>>>,
        operations: Cell<usize>,
    }

    impl SecretBackend for FakeBackend {
        fn get(&self, account: &str) -> Result<Option<Vec<u8>>, String> {
            self.operations.set(self.operations.get() + 1);
            Ok(self.values.borrow().get(account).cloned())
        }

        fn set(&self, account: &str, secret: &[u8]) -> Result<(), String> {
            self.operations.set(self.operations.get() + 1);
            self.values
                .borrow_mut()
                .insert(account.to_string(), secret.to_vec());
            Ok(())
        }

        fn delete(&self, account: &str) -> Result<bool, String> {
            self.operations.set(self.operations.get() + 1);
            Ok(self.values.borrow_mut().remove(account).is_some())
        }
    }

    #[test]
    fn broker_authorizes_client_before_touching_backend() {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        write_request(
            &mut client,
            &BrokerRequest::Get {
                account: "transition-approval-key-v1".to_string(),
            },
        )
        .expect("request");
        let backend = FakeBackend::default();

        let error = serve_client(server, &RejectClient, &backend)
            .expect_err("unauthorized client must fail");

        assert!(error.contains("client signature rejected"));
        assert_eq!(backend.operations.get(), 0);
    }

    #[test]
    fn authorized_client_can_use_bounded_keychain_operations() {
        let backend = FakeBackend::default();
        let account = "session-authority-key-v1";

        assert_eq!(
            round_trip(BrokerRequest::Ping, &backend),
            BrokerResponse::Success
        );
        assert_eq!(backend.operations.get(), 0);
        assert_eq!(
            round_trip(
                BrokerRequest::Set {
                    account: account.to_string(),
                    secret: vec![0x53; 32],
                },
                &backend,
            ),
            BrokerResponse::Success
        );
        assert_eq!(
            round_trip(
                BrokerRequest::Get {
                    account: account.to_string(),
                },
                &backend,
            ),
            BrokerResponse::Value(vec![0x53; 32])
        );
        assert_eq!(
            round_trip(
                BrokerRequest::Delete {
                    account: account.to_string(),
                },
                &backend,
            ),
            BrokerResponse::Success
        );
        assert_eq!(
            round_trip(
                BrokerRequest::Get {
                    account: account.to_string(),
                },
                &backend,
            ),
            BrokerResponse::NotFound
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_requirement_pins_cli_and_desktop_bridge_to_one_certificate() {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";

        assert_eq!(
            client_code_requirement(fingerprint).expect("client requirement"),
            "(identifier \"dev.unpin.cli\" or identifier \"dev.unpin.workbench.bridge\") and certificate leaf = H\"0123456789abcdef0123456789abcdef01234567\""
        );
        assert!(client_code_requirement("not-a-fingerprint").is_err());
    }

    fn round_trip(request: BrokerRequest, backend: &FakeBackend) -> BrokerResponse {
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        write_request(&mut client, &request).expect("request");
        serve_client(server, &AllowClient, backend).expect("serve client");
        read_response(&mut client).expect("response")
    }
}
