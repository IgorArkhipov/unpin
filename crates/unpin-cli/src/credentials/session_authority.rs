use std::path::Path;

use unpin_core::fixture::{FixtureCredentialPurpose, fixture_credential_key};
use unpin_core::sessions::SessionAuthorityKey;
use zeroize::Zeroizing;

use super::{KEYCHAIN_SERVICE, SecretStore, broker};

pub(super) const SESSION_AUTHORITY_ACCOUNT: &str = "session-authority-key-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionAuthorityKeyState {
    Missing,
    Ready { key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionAuthorityKeyInitialization {
    Created { key_id: String },
    AlreadyExists { key_id: String },
}

pub(crate) fn session_authority_key_status(
    store: &impl SecretStore,
) -> Result<SessionAuthorityKeyState, String> {
    match load_session_authority_key(store)? {
        Some(key) => Ok(SessionAuthorityKeyState::Ready {
            key_id: key.key_id(),
        }),
        None => Ok(SessionAuthorityKeyState::Missing),
    }
}

pub(crate) fn initialize_session_authority_key(
    store: &impl SecretStore,
) -> Result<SessionAuthorityKeyInitialization, String> {
    initialize_session_authority_key_with(store, |bytes| {
        getrandom::fill(bytes).map_err(|error| error.to_string())
    })
}

fn initialize_session_authority_key_with(
    store: &impl SecretStore,
    fill: impl FnOnce(&mut [u8]) -> Result<(), String>,
) -> Result<SessionAuthorityKeyInitialization, String> {
    if let Some(key) = load_session_authority_key(store)? {
        return Ok(SessionAuthorityKeyInitialization::AlreadyExists {
            key_id: key.key_id(),
        });
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    if let Err(error) = fill(&mut *bytes) {
        return Err(format!("session authority key generation failed: {error}"));
    }
    let key = SessionAuthorityKey::new(*bytes);
    let store_result = store.set(
        KEYCHAIN_SERVICE,
        SESSION_AUTHORITY_ACCOUNT,
        bytes.as_slice(),
    );
    store_result?;
    Ok(SessionAuthorityKeyInitialization::Created {
        key_id: key.key_id(),
    })
}

pub(crate) fn resolve_session_authority_key(
    fixture_mode: bool,
    app_state_root: &Path,
) -> Result<Option<SessionAuthorityKey>, String> {
    if fixture_mode {
        return Ok(Some(SessionAuthorityKey::new(fixture_credential_key(
            app_state_root,
            FixtureCredentialPurpose::SessionAuthority,
        )?)));
    }
    Ok(broker::resolve_runtime_bundle(app_state_root)?
        .session_authority()
        .map(SessionAuthorityKey::new))
}

fn load_session_authority_key(
    store: &impl SecretStore,
) -> Result<Option<SessionAuthorityKey>, String> {
    let Some(secret) = store.get(KEYCHAIN_SERVICE, SESSION_AUTHORITY_ACCOUNT)? else {
        return Ok(None);
    };
    let secret = Zeroizing::new(secret);
    let key = SessionAuthorityKey::from_bytes(&secret);
    key.map(Some)
        .map_err(|error| format!("stored session authority key is invalid: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::{
        ApprovalKeyState, BackupAuthenticationState, approval_key_status,
        backup_authentication_status, test_support::FakeSecretStore,
    };

    #[test]
    fn initializes_dedicated_session_authority_key_and_reports_id() {
        let store = FakeSecretStore::default();
        let created = initialize_session_authority_key_with(&store, |bytes| {
            bytes.fill(0x53);
            Ok(())
        })
        .expect("initialize session authority key");
        let key_id = SessionAuthorityKey::new([0x53; 32]).key_id();
        assert_eq!(
            created,
            SessionAuthorityKeyInitialization::Created {
                key_id: key_id.clone()
            }
        );
        assert_eq!(
            session_authority_key_status(&store).unwrap(),
            SessionAuthorityKeyState::Ready { key_id }
        );
        assert_eq!(
            backup_authentication_status(&store).unwrap(),
            BackupAuthenticationState::Missing
        );
        assert_eq!(
            approval_key_status(&store).unwrap(),
            ApprovalKeyState::Missing
        );
    }
}
