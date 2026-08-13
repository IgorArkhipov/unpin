mod approval;
pub(crate) use approval::require_live_apply_terminal;
mod backup_authentication;
mod broker;
mod cursor_dashboard;
mod session_authority;

pub(crate) use approval::{
    ApprovalKeyInitialization, ApprovalKeyState, approval_key_status, approval_key_status_for_mode,
    authorize_control_decision, authorize_desktop_control_decision, authorize_operator_descriptor,
    authorize_reviewed_control_decision, initialize_approval_key, issue_human_approval,
    issue_inventory_group_approval, resolve_approval_key,
};
pub(crate) use backup_authentication::{
    BackupAuthenticationInitialization, BackupAuthenticationState, backup_authentication_status,
    initialize_backup_authentication_key, resolve_backup_authentication_key,
};
pub(crate) use broker::run as run_credential_broker;
pub(crate) use cursor_dashboard::{
    CursorDashboardCredentialRemoval, CursorDashboardCredentialState,
    CursorDashboardCredentialUpdate, MAX_CURSOR_DASHBOARD_COOKIE_BYTES,
    cursor_dashboard_credential_status, remove_cursor_dashboard_cookie,
    store_cursor_dashboard_cookie,
};
pub(crate) use session_authority::{
    SessionAuthorityKeyInitialization, SessionAuthorityKeyState, initialize_session_authority_key,
    resolve_session_authority_key, session_authority_key_status,
};

const KEYCHAIN_SERVICE: &str = "dev.unpin";
const GATEWAY_CREDENTIAL_ACCOUNT_PREFIX: &str = "gateway-upstream-v1:";

pub(crate) trait SecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String>;
    fn delete(&self, service: &str, account: &str) -> Result<bool, String>;
}

pub(crate) struct KeychainSecretStore;

pub(crate) fn resolve_gateway_credential(
    fixture_mode: bool,
    app_state_root: &std::path::Path,
    key_id: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    validate_gateway_credential_key_id(key_id)?;
    if fixture_mode {
        let fixture_key = unpin_core::fixture::fixture_credential_key(
            app_state_root,
            unpin_core::fixture::FixtureCredentialPurpose::SessionAuthority,
        )?;
        let mut material = zeroize::Zeroizing::new(Vec::with_capacity(32 + key_id.len()));
        material.extend_from_slice(&fixture_key);
        material.extend_from_slice(key_id.as_bytes());
        return Ok(Some(zeroize::Zeroizing::new(unpin_core::sha256_digest(
            &material,
        ))));
    }
    resolve_gateway_credential_from_store(&KeychainSecretStore, key_id)
}

fn resolve_gateway_credential_from_store(
    store: &impl SecretStore,
    key_id: &str,
) -> Result<Option<zeroize::Zeroizing<String>>, String> {
    validate_gateway_credential_key_id(key_id)?;
    let account = format!("{GATEWAY_CREDENTIAL_ACCOUNT_PREFIX}{key_id}");
    let Some(secret) = store.get(KEYCHAIN_SERVICE, &account)? else {
        return Ok(None);
    };
    let secret = zeroize::Zeroizing::new(secret);
    let token = String::from_utf8(secret.to_vec())
        .map_err(|_| "stored gateway credential is not valid UTF-8".to_string())?;
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err("stored gateway credential is invalid".to_string());
    }
    Ok(Some(zeroize::Zeroizing::new(token)))
}

fn validate_gateway_credential_key_id(key_id: &str) -> Result<(), String> {
    if key_id.trim().is_empty() || key_id.len() > 256 || key_id.chars().any(char::is_control) {
        Err("gateway credential key id is invalid".to_string())
    } else {
        Ok(())
    }
}

impl SecretStore for KeychainSecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| format!("keychain entry could not be opened: {error}"))?;
        match entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(format!("keychain credential could not be read: {error}")),
        }
    }

    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| format!("keychain entry could not be opened: {error}"))?;
        entry
            .set_secret(secret)
            .map_err(|error| format!("keychain credential could not be stored: {error}"))
    }

    fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
        let entry = keyring::Entry::new(service, account)
            .map_err(|error| format!("keychain entry could not be opened: {error}"))?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(format!("keychain credential could not be removed: {error}")),
        }
    }
}

#[cfg(test)]
mod test_support {
    use std::{cell::RefCell, collections::BTreeMap};

    use super::SecretStore;

    #[derive(Default)]
    pub(super) struct FakeSecretStore {
        pub(super) values: RefCell<BTreeMap<(String, String), Vec<u8>>>,
        pub(super) writes: RefCell<usize>,
    }

    impl SecretStore for FakeSecretStore {
        fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String> {
            Ok(self
                .values
                .borrow()
                .get(&(service.to_string(), account.to_string()))
                .cloned())
        }

        fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String> {
            self.values
                .borrow_mut()
                .insert((service.to_string(), account.to_string()), secret.to_vec());
            *self.writes.borrow_mut() += 1;
            Ok(())
        }

        fn delete(&self, service: &str, account: &str) -> Result<bool, String> {
            Ok(self
                .values
                .borrow_mut()
                .remove(&(service.to_string(), account.to_string()))
                .is_some())
        }
    }
}

#[cfg(test)]
mod gateway_credential_tests {
    use super::{
        GATEWAY_CREDENTIAL_ACCOUNT_PREFIX, KEYCHAIN_SERVICE, SecretStore,
        resolve_gateway_credential_from_store, test_support::FakeSecretStore,
    };

    #[test]
    fn resolves_gateway_secret_by_authenticated_key_id_without_exposing_other_accounts() {
        let store = FakeSecretStore::default();
        store
            .set(
                KEYCHAIN_SERVICE,
                &format!("{GATEWAY_CREDENTIAL_ACCOUNT_PREFIX}gateway-token-a"),
                b"secret-token",
            )
            .expect("store gateway credential");
        store
            .set(KEYCHAIN_SERVICE, "gateway-token-b", b"other-account")
            .expect("store non-gateway credential");

        let token = resolve_gateway_credential_from_store(&store, "gateway-token-a")
            .expect("resolve gateway credential")
            .expect("gateway credential present");

        assert_eq!(token.as_str(), "secret-token");
        assert!(
            resolve_gateway_credential_from_store(&store, "gateway-token-b")
                .expect("resolve missing credential")
                .is_none()
        );
    }

    #[test]
    fn rejects_invalid_gateway_credential_material() {
        let store = FakeSecretStore::default();
        store
            .set(
                KEYCHAIN_SERVICE,
                &format!("{GATEWAY_CREDENTIAL_ACCOUNT_PREFIX}gateway-token-a"),
                &[0xff],
            )
            .expect("store invalid gateway credential");

        assert!(resolve_gateway_credential_from_store(&store, "gateway-token-a").is_err());
        assert!(resolve_gateway_credential_from_store(&store, "bad\nkey").is_err());
    }
}
