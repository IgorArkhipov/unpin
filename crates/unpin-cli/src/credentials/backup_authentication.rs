use unpin_core::mutation::BackupAuthenticationKey;

use super::{KEYCHAIN_SERVICE, KeychainSecretStore, SecretStore};

const BACKUP_AUTHENTICATION_ACCOUNT: &str = "backup-authentication-key-v1";
const FIXTURE_BACKUP_AUTHENTICATION_KEY: [u8; 32] = [0x42; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackupAuthenticationState {
    Missing,
    Ready { key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackupAuthenticationInitialization {
    Created { key_id: String },
    AlreadyExists { key_id: String },
}

pub(crate) fn backup_authentication_status(
    store: &impl SecretStore,
) -> Result<BackupAuthenticationState, String> {
    match load_backup_authentication_key(store)? {
        Some(key) => Ok(BackupAuthenticationState::Ready {
            key_id: key.key_id(),
        }),
        None => Ok(BackupAuthenticationState::Missing),
    }
}

pub(crate) fn initialize_backup_authentication_key(
    store: &impl SecretStore,
) -> Result<BackupAuthenticationInitialization, String> {
    initialize_backup_authentication_key_with(store, |bytes| {
        getrandom::fill(bytes).map_err(|error| error.to_string())
    })
}

fn initialize_backup_authentication_key_with(
    store: &impl SecretStore,
    fill: impl FnOnce(&mut [u8]) -> Result<(), String>,
) -> Result<BackupAuthenticationInitialization, String> {
    if let Some(key) = load_backup_authentication_key(store)? {
        return Ok(BackupAuthenticationInitialization::AlreadyExists {
            key_id: key.key_id(),
        });
    }

    let mut bytes = [0_u8; 32];
    if let Err(error) = fill(&mut bytes) {
        bytes.fill(0);
        return Err(format!(
            "backup authentication key generation failed: {error}"
        ));
    }
    let key = BackupAuthenticationKey::new(bytes);
    let store_result = store.set(KEYCHAIN_SERVICE, BACKUP_AUTHENTICATION_ACCOUNT, &bytes);
    bytes.fill(0);
    store_result?;
    Ok(BackupAuthenticationInitialization::Created {
        key_id: key.key_id(),
    })
}

pub(crate) fn resolve_backup_authentication_key(
    fixture_mode: bool,
) -> Result<Option<BackupAuthenticationKey>, String> {
    if fixture_mode {
        return Ok(Some(BackupAuthenticationKey::new(
            FIXTURE_BACKUP_AUTHENTICATION_KEY,
        )));
    }
    load_backup_authentication_key(&KeychainSecretStore)
}

fn load_backup_authentication_key(
    store: &impl SecretStore,
) -> Result<Option<BackupAuthenticationKey>, String> {
    let Some(mut secret) = store.get(KEYCHAIN_SERVICE, BACKUP_AUTHENTICATION_ACCOUNT)? else {
        return Ok(None);
    };
    let key = BackupAuthenticationKey::from_bytes(&secret);
    secret.fill(0);
    key.map(Some)
        .map_err(|error| format!("stored backup authentication key is invalid: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use super::*;
    use crate::credentials::test_support::FakeSecretStore;

    #[test]
    fn initializes_once_and_reports_non_secret_key_id() {
        let store = FakeSecretStore::default();
        let created = initialize_backup_authentication_key_with(&store, |bytes| {
            bytes.fill(0x11);
            Ok(())
        })
        .expect("initialize key");
        let expected_key_id = BackupAuthenticationKey::new([0x11; 32]).key_id();
        assert_eq!(
            created,
            BackupAuthenticationInitialization::Created {
                key_id: expected_key_id.clone()
            }
        );
        assert_eq!(
            backup_authentication_status(&store).expect("key status"),
            BackupAuthenticationState::Ready {
                key_id: expected_key_id.clone()
            }
        );

        let existing = initialize_backup_authentication_key_with(&store, |_| {
            panic!("existing key must not be replaced")
        })
        .expect("existing key");
        assert_eq!(
            existing,
            BackupAuthenticationInitialization::AlreadyExists {
                key_id: expected_key_id
            }
        );
        assert_eq!(*store.writes.borrow(), 1);
    }

    #[test]
    fn rejects_malformed_stored_key_without_replacing_it() {
        let store = FakeSecretStore {
            values: RefCell::new(BTreeMap::from([(
                (
                    KEYCHAIN_SERVICE.to_string(),
                    BACKUP_AUTHENTICATION_ACCOUNT.to_string(),
                ),
                vec![0x11; 31],
            )])),
            writes: RefCell::new(0),
        };
        let error = initialize_backup_authentication_key_with(&store, |_| Ok(()))
            .expect_err("malformed key must fail");
        assert!(error.contains("exactly 32 bytes"));
        assert_eq!(*store.writes.borrow(), 0);
    }

    #[test]
    fn reports_missing_key() {
        let store = FakeSecretStore::default();
        assert_eq!(
            backup_authentication_status(&store).expect("key status"),
            BackupAuthenticationState::Missing
        );
    }
}
