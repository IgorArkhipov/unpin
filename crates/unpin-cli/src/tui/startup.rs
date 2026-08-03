use super::{BackupAuthenticationKey, SessionAuthorityKey, TuiResult};

pub(super) struct StartupCredentials {
    pub(super) backup_authentication_key: Option<BackupAuthenticationKey>,
    pub(super) session_authority_key: Option<SessionAuthorityKey>,
    pub(super) warnings: Vec<String>,
}

pub(super) fn resolve_startup_credentials(
    resolve_backup_authentication_key: impl FnOnce() -> Result<Option<BackupAuthenticationKey>, String>,
    is_cancelled: impl FnOnce() -> bool,
    resolve_session_authority_key: impl FnOnce() -> Result<Option<SessionAuthorityKey>, String>,
) -> Option<StartupCredentials> {
    let (backup_authentication_key, backup_warning) = match resolve_backup_authentication_key() {
        Ok(key) => (key, None),
        Err(error) => (
            None,
            Some(format!(
                "backup authentication unavailable; writes disabled: {error}"
            )),
        ),
    };
    if is_cancelled() {
        return None;
    }
    let (session_authority_key, session_warning) = match resolve_session_authority_key() {
        Ok(key) => (key, None),
        Err(error) => (
            None,
            Some(format!(
                "session authority unavailable; session controls disabled: {error}"
            )),
        ),
    };
    Some(StartupCredentials {
        backup_authentication_key,
        session_authority_key,
        warnings: [backup_warning, session_warning]
            .into_iter()
            .flatten()
            .collect(),
    })
}

pub(super) fn finish_after_terminal_run<T>(
    run_result: TuiResult<T>,
    cleanup: impl FnOnce() -> TuiResult<()>,
) -> TuiResult<T> {
    let cleanup_result = cleanup();
    match run_result {
        Ok(value) => {
            cleanup_result?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_broker_failure_disables_only_the_affected_controls() {
        let credentials = resolve_startup_credentials(
            || Err("synthetic credential broker failure".to_string()),
            || false,
            || Ok(Some(SessionAuthorityKey::new([0x53; 32]))),
        )
        .expect("startup remains active");

        assert!(credentials.backup_authentication_key.is_none());
        assert!(credentials.session_authority_key.is_some());
        assert_eq!(
            credentials.warnings,
            [
                "backup authentication unavailable; writes disabled: synthetic credential broker failure"
            ]
        );
    }

    #[test]
    fn session_credential_failure_disables_only_session_controls() {
        let credentials = resolve_startup_credentials(
            || Ok(Some(BackupAuthenticationKey::new([0x42; 32]))),
            || false,
            || Err("synthetic session credential failure".to_string()),
        )
        .expect("startup remains active");

        assert!(credentials.backup_authentication_key.is_some());
        assert!(credentials.session_authority_key.is_none());
        assert_eq!(
            credentials.warnings,
            [
                "session authority unavailable; session controls disabled: synthetic session credential failure"
            ]
        );
    }

    #[test]
    fn cancellation_skips_the_second_credential_lookup() {
        let session_lookup_called = std::cell::Cell::new(false);
        let credentials = resolve_startup_credentials(
            || Ok(None),
            || true,
            || {
                session_lookup_called.set(true);
                Ok(None)
            },
        );

        assert!(credentials.is_none());
        assert!(!session_lookup_called.get());
    }

    #[test]
    fn terminal_cleanup_runs_after_terminal_io_failure() {
        let run_result: TuiResult<()> =
            Err(std::io::Error::other("synthetic terminal read failure").into());
        let cleanup_called = std::cell::Cell::new(false);

        let error = finish_after_terminal_run(run_result, || {
            cleanup_called.set(true);
            Ok(())
        })
        .expect_err("the terminal I/O failure is returned");

        assert!(cleanup_called.get());
        assert_eq!(error.to_string(), "synthetic terminal read failure");
    }

    #[test]
    fn terminal_cleanup_runs_after_a_successful_terminal_loop() {
        let cleanup_called = std::cell::Cell::new(false);

        finish_after_terminal_run(Ok(()), || {
            cleanup_called.set(true);
            Ok(())
        })
        .expect("the terminal loop and cleanup succeed");

        assert!(cleanup_called.get());
    }

    #[test]
    fn terminal_cleanup_failure_is_returned_after_a_successful_terminal_loop() {
        let error = finish_after_terminal_run(Ok(()), || {
            Err(std::io::Error::other("synthetic terminal cleanup failure").into())
        })
        .expect_err("a cleanup failure is returned after a successful terminal loop");

        assert_eq!(error.to_string(), "synthetic terminal cleanup failure");
    }
}
