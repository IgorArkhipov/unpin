use super::{KEYCHAIN_SERVICE, SecretStore};
use zeroize::Zeroizing;

const CURSOR_DASHBOARD_ACCOUNT: &str = "cursor-dashboard-cookie-v1";
const CURSOR_DASHBOARD_CREDENTIAL_PREFIX: &[u8] = b"unpin-cursor-dashboard-cookie-v1\0origin=https://cursor.com\0purpose=marketplace-plugin-mutation\0";
pub(crate) const MAX_CURSOR_DASHBOARD_COOKIE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorDashboardCredentialState {
    Missing,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorDashboardCredentialUpdate {
    Created,
    Updated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorDashboardCredentialRemoval {
    Removed,
    Missing,
}

pub(crate) fn cursor_dashboard_credential_status(
    store: &impl SecretStore,
) -> Result<CursorDashboardCredentialState, String> {
    match store.get(KEYCHAIN_SERVICE, CURSOR_DASHBOARD_ACCOUNT)? {
        Some(secret) => {
            let secret = Zeroizing::new(secret);
            let valid = decode_cursor_dashboard_cookie(&secret)
                .and_then(validate_cursor_dashboard_cookie)
                .is_ok();
            if valid {
                Ok(CursorDashboardCredentialState::Ready)
            } else {
                Err("stored Cursor dashboard credential is invalid".to_string())
            }
        }
        None => Ok(CursorDashboardCredentialState::Missing),
    }
}

pub(crate) fn store_cursor_dashboard_cookie(
    store: &impl SecretStore,
    secret: &[u8],
) -> Result<CursorDashboardCredentialUpdate, String> {
    validate_cursor_dashboard_cookie(secret)?;
    let existed = match store.get(KEYCHAIN_SERVICE, CURSOR_DASHBOARD_ACCOUNT)? {
        Some(existing) => {
            let _existing = Zeroizing::new(existing);
            true
        }
        None => false,
    };
    let mut stored = Zeroizing::new(Vec::with_capacity(
        CURSOR_DASHBOARD_CREDENTIAL_PREFIX.len() + secret.len(),
    ));
    stored.extend_from_slice(CURSOR_DASHBOARD_CREDENTIAL_PREFIX);
    stored.extend_from_slice(secret);
    let store_result = store.set(KEYCHAIN_SERVICE, CURSOR_DASHBOARD_ACCOUNT, &stored);
    store_result?;
    Ok(if existed {
        CursorDashboardCredentialUpdate::Updated
    } else {
        CursorDashboardCredentialUpdate::Created
    })
}

pub(crate) fn remove_cursor_dashboard_cookie(
    store: &impl SecretStore,
) -> Result<CursorDashboardCredentialRemoval, String> {
    Ok(
        if store.delete(KEYCHAIN_SERVICE, CURSOR_DASHBOARD_ACCOUNT)? {
            CursorDashboardCredentialRemoval::Removed
        } else {
            CursorDashboardCredentialRemoval::Missing
        },
    )
}

fn validate_cursor_dashboard_cookie(secret: &[u8]) -> Result<(), String> {
    if secret.is_empty() {
        return Err("Cursor dashboard cookie is empty".to_string());
    }
    if secret.len() > MAX_CURSOR_DASHBOARD_COOKIE_BYTES {
        return Err("Cursor dashboard cookie exceeds size limit".to_string());
    }
    if secret.iter().any(|byte| byte.is_ascii_control()) {
        return Err("Cursor dashboard cookie contains control bytes".to_string());
    }
    Ok(())
}

fn decode_cursor_dashboard_cookie(stored: &[u8]) -> Result<&[u8], String> {
    stored
        .strip_prefix(CURSOR_DASHBOARD_CREDENTIAL_PREFIX)
        .ok_or_else(|| "stored Cursor dashboard credential binding is invalid".to_string())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap};

    use super::*;
    use crate::credentials::{
        ApprovalKeyState, BackupAuthenticationState, approval_key_status,
        backup_authentication_status, test_support::FakeSecretStore,
    };

    #[test]
    fn cursor_dashboard_cookie_uses_separate_non_exporting_keychain_slot() {
        let store = FakeSecretStore::default();
        let cookie = b"WorkosCursorSessionToken=private-value";
        assert_eq!(
            store_cursor_dashboard_cookie(&store, cookie).unwrap(),
            CursorDashboardCredentialUpdate::Created
        );
        assert_eq!(
            cursor_dashboard_credential_status(&store).unwrap(),
            CursorDashboardCredentialState::Ready
        );
        let stored = store
            .values
            .borrow()
            .get(&(
                KEYCHAIN_SERVICE.to_string(),
                CURSOR_DASHBOARD_ACCOUNT.to_string(),
            ))
            .cloned()
            .expect("bound Cursor credential");
        assert!(stored.starts_with(CURSOR_DASHBOARD_CREDENTIAL_PREFIX));
        assert_eq!(decode_cursor_dashboard_cookie(&stored).unwrap(), cookie);
        assert_eq!(
            backup_authentication_status(&store).unwrap(),
            BackupAuthenticationState::Missing
        );
        assert_eq!(
            approval_key_status(&store).unwrap(),
            ApprovalKeyState::Missing
        );
        assert_eq!(
            store_cursor_dashboard_cookie(&store, b"WorkosCursorSessionToken=replaced").unwrap(),
            CursorDashboardCredentialUpdate::Updated
        );
        assert_eq!(
            remove_cursor_dashboard_cookie(&store).unwrap(),
            CursorDashboardCredentialRemoval::Removed
        );
        assert_eq!(
            cursor_dashboard_credential_status(&store).unwrap(),
            CursorDashboardCredentialState::Missing
        );
    }

    #[test]
    fn cursor_dashboard_cookie_rejects_empty_control_and_oversized_values() {
        let store = FakeSecretStore::default();
        for secret in [
            Vec::new(),
            b"cookie\nvalue".to_vec(),
            vec![b'x'; MAX_CURSOR_DASHBOARD_COOKIE_BYTES + 1],
        ] {
            assert!(store_cursor_dashboard_cookie(&store, &secret).is_err());
        }
        assert_eq!(
            cursor_dashboard_credential_status(&store).unwrap(),
            CursorDashboardCredentialState::Missing
        );
    }

    #[test]
    fn cursor_dashboard_cookie_rejects_wrong_service_account_and_unbound_payloads() {
        for key in [
            (
                "dev.unpin.workspace-substitution".to_string(),
                CURSOR_DASHBOARD_ACCOUNT.to_string(),
            ),
            (
                KEYCHAIN_SERVICE.to_string(),
                "cursor-dashboard-cookie-project-v1".to_string(),
            ),
        ] {
            let store = FakeSecretStore {
                values: RefCell::new(BTreeMap::from([(
                    key,
                    [
                        CURSOR_DASHBOARD_CREDENTIAL_PREFIX,
                        b"WorkosCursorSessionToken=private-value",
                    ]
                    .concat(),
                )])),
                writes: RefCell::new(0),
            };
            assert_eq!(
                cursor_dashboard_credential_status(&store).unwrap(),
                CursorDashboardCredentialState::Missing
            );
        }

        let store = FakeSecretStore {
            values: RefCell::new(BTreeMap::from([(
                (
                    KEYCHAIN_SERVICE.to_string(),
                    CURSOR_DASHBOARD_ACCOUNT.to_string(),
                ),
                b"WorkosCursorSessionToken=unbound".to_vec(),
            )])),
            writes: RefCell::new(0),
        };
        assert_eq!(
            cursor_dashboard_credential_status(&store).unwrap_err(),
            "stored Cursor dashboard credential is invalid"
        );
    }
}
