use std::os::unix::net::UnixStream;

#[cfg(any(target_os = "macos", test))]
const BROKER_CODE_IDENTIFIER: &str = "dev.unpin.credential-broker";

pub(super) fn authorize(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let fingerprint = option_env!("UNPIN_CODESIGN_CERTIFICATE_SHA1").ok_or_else(|| {
            "Unpin was not built with a broker certificate fingerprint".to_string()
        })?;
        let requirement = code_requirement(BROKER_CODE_IDENTIFIER, fingerprint)?;
        super::broker_peer_auth::authorize(
            stream,
            &requirement,
            super::broker_peer_auth::PeerKind::Broker,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        {
            super::broker_protocol::authorize_same_user(stream, "credential broker")
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Ok(())
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn code_requirement(identifier: &str, fingerprint: &str) -> Result<String, String> {
    let normalized = fingerprint.to_ascii_lowercase();
    if normalized.len() != 40
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        || identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("Unpin broker certificate requirement is invalid".to_string());
    }
    Ok(format!(
        "identifier \"{identifier}\" and certificate leaf = H\"{normalized}\""
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_pins_broker_identifier_and_certificate() {
        let fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567";

        assert_eq!(
            code_requirement(BROKER_CODE_IDENTIFIER, fingerprint).expect("requirement"),
            "identifier \"dev.unpin.credential-broker\" and certificate leaf = H\"0123456789abcdef0123456789abcdef01234567\""
        );
        assert!(code_requirement(BROKER_CODE_IDENTIFIER, "not-a-fingerprint").is_err());
        assert!(code_requirement("unsafe identifier", fingerprint).is_err());
    }
}
