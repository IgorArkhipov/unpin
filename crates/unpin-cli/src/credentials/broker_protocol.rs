use std::{
    fmt,
    io::{Read, Write},
};

use zeroize::Zeroize;

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

#[cfg(unix)]
pub(super) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the effective user ID.
    unsafe { geteuid() }
}

#[cfg(target_os = "linux")]
pub(super) fn authorize_same_user(
    stream: &std::os::unix::net::UnixStream,
    peer_description: &str,
) -> Result<(), String> {
    use std::{
        ffi::{c_int, c_void},
        mem,
        os::fd::AsRawFd,
    };

    #[repr(C)]
    struct PeerCredentials {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    unsafe extern "C" {
        fn getsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *mut c_void,
            option_length: *mut u32,
        ) -> c_int;
    }

    const SOL_SOCKET: c_int = 1;
    const SO_PEERCRED: c_int = 17;

    let mut credentials = PeerCredentials {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = u32::try_from(mem::size_of::<PeerCredentials>())
        .expect("Linux peer credential size fits socklen_t");
    let status = unsafe {
        // SAFETY: the socket is live and the credential buffer and length are valid.
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if status != 0 || usize::try_from(length) != Ok(mem::size_of::<PeerCredentials>()) {
        return Err(format!(
            "{peer_description} socket peer credentials are unavailable"
        ));
    }
    if credentials.uid != effective_uid() {
        return Err(format!("{peer_description} socket peer owner is invalid"));
    }
    Ok(())
}

pub(super) const PROTOCOL_MAGIC: &[u8; 8] = b"UNPINCB1";
pub(super) const MAX_SECRET_BYTES: usize = 128 * 1024;
const MAX_ACCOUNT_BYTES: usize = 512;
const MAX_ERROR_BYTES: usize = 4 * 1024;
#[allow(dead_code)] // The protocol module is compiled into separate client and server binaries.
const HEADER_BYTES: usize = PROTOCOL_MAGIC.len() + 1 + 2 + 4;
#[allow(dead_code)] // The protocol module is compiled into separate client and server binaries.
const RESPONSE_HEADER_BYTES: usize = PROTOCOL_MAGIC.len() + 1 + 4;
const OP_PING: u8 = 0;
const OP_GET: u8 = 1;
const OP_SET: u8 = 2;
const OP_DELETE: u8 = 3;
const STATUS_SUCCESS: u8 = 0;
const STATUS_VALUE: u8 = 1;
const STATUS_NOT_FOUND: u8 = 2;
const STATUS_ERROR: u8 = 3;

#[derive(PartialEq, Eq)]
pub(super) enum BrokerRequest {
    Ping,
    Get { account: String },
    Set { account: String, secret: Vec<u8> },
    Delete { account: String },
}

impl fmt::Debug for BrokerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ping => formatter.write_str("Ping"),
            Self::Get { account } => formatter
                .debug_struct("Get")
                .field("account", account)
                .finish(),
            Self::Set { account, secret } => formatter
                .debug_struct("Set")
                .field("account", account)
                .field("secret_bytes", &secret.len())
                .finish(),
            Self::Delete { account } => formatter
                .debug_struct("Delete")
                .field("account", account)
                .finish(),
        }
    }
}

impl Drop for BrokerRequest {
    fn drop(&mut self) {
        if let Self::Set { secret, .. } = self {
            secret.zeroize();
        }
    }
}

#[derive(PartialEq, Eq)]
pub(super) enum BrokerResponse {
    Success,
    Value(Vec<u8>),
    NotFound,
    Error(String),
}

impl fmt::Debug for BrokerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => formatter.write_str("Success"),
            Self::Value(value) => formatter
                .debug_struct("Value")
                .field("secret_bytes", &value.len())
                .finish(),
            Self::NotFound => formatter.write_str("NotFound"),
            Self::Error(error) => formatter.debug_tuple("Error").field(error).finish(),
        }
    }
}

impl Drop for BrokerResponse {
    fn drop(&mut self) {
        if let Self::Value(value) = self {
            value.zeroize();
        }
    }
}

#[cfg(unix)]
pub(super) fn broker_socket_path(app_state_root: &std::path::Path) -> std::path::PathBuf {
    broker_socket_directory(app_state_root).join("broker-v1.sock")
}

#[cfg(unix)]
pub(super) fn broker_socket_directory(app_state_root: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let hash = app_state_root
        .as_os_str()
        .as_bytes()
        .iter()
        .fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    std::path::PathBuf::from("/tmp").join(format!("unpin-stable-credential-broker-v1-{hash:016x}"))
}

#[cfg(unix)]
pub(super) fn configure_unix_stream(
    stream: &std::os::unix::net::UnixStream,
    timeout: std::time::Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| error.to_string())
}

#[allow(dead_code)] // Used by the CLI half of the split protocol.
pub(super) fn write_request(
    writer: &mut impl Write,
    request: &BrokerRequest,
) -> Result<(), String> {
    let (operation, account, secret) = match request {
        BrokerRequest::Ping => (OP_PING, "", &[][..]),
        BrokerRequest::Get { account } => (OP_GET, account.as_str(), &[][..]),
        BrokerRequest::Set { account, secret } => (OP_SET, account.as_str(), secret.as_slice()),
        BrokerRequest::Delete { account } => (OP_DELETE, account.as_str(), &[][..]),
    };
    if operation != OP_PING {
        validate_account(account)?;
    }
    if secret.len() > MAX_SECRET_BYTES {
        return Err("credential broker secret exceeds size limit".to_string());
    }
    let account_length = u16::try_from(account.len())
        .map_err(|_| "credential broker account exceeds size limit".to_string())?;
    let secret_length = u32::try_from(secret.len())
        .map_err(|_| "credential broker secret exceeds size limit".to_string())?;
    writer
        .write_all(PROTOCOL_MAGIC)
        .and_then(|()| writer.write_all(&[operation]))
        .and_then(|()| writer.write_all(&account_length.to_be_bytes()))
        .and_then(|()| writer.write_all(&secret_length.to_be_bytes()))
        .and_then(|()| writer.write_all(account.as_bytes()))
        .and_then(|()| writer.write_all(secret))
        .map_err(|error| error.to_string())
}

#[allow(dead_code)] // Used by the broker-server half of the split protocol.
pub(super) fn read_request(reader: &mut impl Read) -> Result<BrokerRequest, String> {
    let mut header = [0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if &header[..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        return Err("credential broker protocol magic is invalid".to_string());
    }
    let operation = header[PROTOCOL_MAGIC.len()];
    let account_offset = PROTOCOL_MAGIC.len() + 1;
    let account_length = usize::from(u16::from_be_bytes(
        header[account_offset..account_offset + 2]
            .try_into()
            .expect("account length field is fixed"),
    ));
    let secret_offset = account_offset + 2;
    let secret_length = usize::try_from(u32::from_be_bytes(
        header[secret_offset..secret_offset + 4]
            .try_into()
            .expect("secret length field is fixed"),
    ))
    .map_err(|_| "credential broker secret exceeds size limit".to_string())?;
    if operation == OP_PING && (account_length != 0 || secret_length != 0) {
        return Err("credential broker ping payload is invalid".to_string());
    }
    if operation != OP_PING && (account_length == 0 || account_length > MAX_ACCOUNT_BYTES) {
        return Err("credential broker account is invalid".to_string());
    }
    if secret_length > MAX_SECRET_BYTES {
        return Err("credential broker secret exceeds size limit".to_string());
    }
    if operation != OP_SET && secret_length != 0 {
        return Err("credential broker request payload is invalid".to_string());
    }
    if !matches!(operation, OP_PING | OP_GET | OP_SET | OP_DELETE) {
        return Err("credential broker operation is invalid".to_string());
    }

    let mut account = vec![0_u8; account_length];
    reader
        .read_exact(&mut account)
        .map_err(|error| error.to_string())?;
    let account = String::from_utf8(account)
        .map_err(|_| "credential broker account is invalid".to_string())?;
    if operation != OP_PING {
        validate_account(&account)?;
    }
    let mut secret = vec![0_u8; secret_length];
    reader
        .read_exact(&mut secret)
        .map_err(|error| error.to_string())?;
    Ok(match operation {
        OP_PING => BrokerRequest::Ping,
        OP_GET => BrokerRequest::Get { account },
        OP_SET => BrokerRequest::Set { account, secret },
        OP_DELETE => BrokerRequest::Delete { account },
        _ => unreachable!("operation was validated"),
    })
}

#[allow(dead_code)] // Used by the broker-server half of the split protocol.
pub(super) fn write_response(
    writer: &mut impl Write,
    response: &BrokerResponse,
) -> Result<(), String> {
    let (status, payload) = match response {
        BrokerResponse::Success => (STATUS_SUCCESS, &[][..]),
        BrokerResponse::Value(value) => {
            if value.len() > MAX_SECRET_BYTES {
                return Err("credential broker response exceeds size limit".to_string());
            }
            (STATUS_VALUE, value.as_slice())
        }
        BrokerResponse::NotFound => (STATUS_NOT_FOUND, &[][..]),
        BrokerResponse::Error(error) => {
            if error.len() > MAX_ERROR_BYTES {
                return Err("credential broker error exceeds size limit".to_string());
            }
            (STATUS_ERROR, error.as_bytes())
        }
    };
    let payload_length = u32::try_from(payload.len())
        .map_err(|_| "credential broker response exceeds size limit".to_string())?;
    writer
        .write_all(PROTOCOL_MAGIC)
        .and_then(|()| writer.write_all(&[status]))
        .and_then(|()| writer.write_all(&payload_length.to_be_bytes()))
        .and_then(|()| writer.write_all(payload))
        .map_err(|error| error.to_string())
}

#[allow(dead_code)] // Used by the CLI half of the split protocol.
pub(super) fn read_response(reader: &mut impl Read) -> Result<BrokerResponse, String> {
    let mut header = [0_u8; RESPONSE_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if &header[..PROTOCOL_MAGIC.len()] != PROTOCOL_MAGIC {
        return Err("credential broker protocol magic is invalid".to_string());
    }
    let status = header[PROTOCOL_MAGIC.len()];
    let payload_offset = PROTOCOL_MAGIC.len() + 1;
    let payload_length = usize::try_from(u32::from_be_bytes(
        header[payload_offset..payload_offset + 4]
            .try_into()
            .expect("response length field is fixed"),
    ))
    .map_err(|_| "credential broker response exceeds size limit".to_string())?;
    let maximum = if status == STATUS_ERROR {
        MAX_ERROR_BYTES
    } else {
        MAX_SECRET_BYTES
    };
    if payload_length > maximum {
        return Err("credential broker response exceeds size limit".to_string());
    }
    if matches!(status, STATUS_SUCCESS | STATUS_NOT_FOUND) && payload_length != 0 {
        return Err("credential broker response payload is invalid".to_string());
    }
    if !matches!(
        status,
        STATUS_SUCCESS | STATUS_VALUE | STATUS_NOT_FOUND | STATUS_ERROR
    ) {
        return Err("credential broker response status is invalid".to_string());
    }
    let mut payload = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    Ok(match status {
        STATUS_SUCCESS => BrokerResponse::Success,
        STATUS_VALUE => BrokerResponse::Value(payload),
        STATUS_NOT_FOUND => BrokerResponse::NotFound,
        STATUS_ERROR => BrokerResponse::Error(
            String::from_utf8(payload)
                .map_err(|_| "credential broker error response is invalid".to_string())?,
        ),
        _ => unreachable!("status was validated"),
    })
}

fn validate_account(account: &str) -> Result<(), String> {
    if account.is_empty()
        || account.len() > MAX_ACCOUNT_BYTES
        || account.bytes().any(|byte| byte.is_ascii_control())
    {
        Err("credential broker account is invalid".to_string())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn protocol_round_trips_bounded_keychain_operations() {
        for request in [
            BrokerRequest::Ping,
            BrokerRequest::Get {
                account: "transition-approval-key-v1".to_string(),
            },
            BrokerRequest::Set {
                account: "cursor-dashboard-cookie-v1".to_string(),
                secret: vec![0x53; 64],
            },
            BrokerRequest::Delete {
                account: "cursor-dashboard-cookie-v1".to_string(),
            },
        ] {
            let mut encoded = Vec::new();
            write_request(&mut encoded, &request).expect("encode request");
            let decoded = read_request(&mut Cursor::new(encoded)).expect("decode request");
            assert_eq!(decoded, request);
        }

        for response in [
            BrokerResponse::Value(vec![0x11; 32]),
            BrokerResponse::Success,
            BrokerResponse::NotFound,
            BrokerResponse::Error("keychain operation failed".to_string()),
        ] {
            let mut encoded = Vec::new();
            write_response(&mut encoded, &response).expect("encode response");
            let decoded = read_response(&mut Cursor::new(encoded)).expect("decode response");
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn protocol_rejects_oversized_secret_before_reading_payload() {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PROTOCOL_MAGIC);
        encoded.push(OP_SET);
        encoded.extend_from_slice(&1_u16.to_be_bytes());
        encoded.extend_from_slice(&((MAX_SECRET_BYTES as u32) + 1).to_be_bytes());
        encoded.push(b'a');

        let error = read_request(&mut Cursor::new(encoded)).expect_err("oversized request");

        assert!(error.contains("secret exceeds size limit"));
    }

    #[test]
    fn protocol_rejects_control_bytes_in_account() {
        let request = BrokerRequest::Get {
            account: "approval\nkey".to_string(),
        };

        let error = write_request(&mut Vec::new(), &request).expect_err("invalid account");

        assert!(error.contains("account is invalid"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_same_uid_socket_peer_is_authorized() {
        let (client, server) = std::os::unix::net::UnixStream::pair().expect("socket pair");

        authorize_same_user(&client, "credential broker").expect("authorize server peer");
        authorize_same_user(&server, "credential broker client").expect("authorize client peer");
    }
}
