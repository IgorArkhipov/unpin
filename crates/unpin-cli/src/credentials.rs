mod approval;
pub(crate) use approval::require_live_apply_terminal;
mod backup_authentication;
mod broker;
mod cursor_dashboard;
mod session_authority;

pub(crate) use approval::{
    ApprovalKeyInitialization, ApprovalKeyState, approval_key_status, approval_key_status_for_mode,
    authorize_control_decision, authorize_reviewed_control_decision, initialize_approval_key,
    issue_human_approval, issue_inventory_group_approval, resolve_approval_key,
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

pub(crate) trait SecretStore {
    fn get(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, service: &str, account: &str, secret: &[u8]) -> Result<(), String>;
    fn delete(&self, service: &str, account: &str) -> Result<bool, String>;
}

pub(crate) struct KeychainSecretStore;

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
