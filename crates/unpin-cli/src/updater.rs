use std::{path::PathBuf, process::ExitCode};

use clap::{Subcommand, ValueEnum};
use serde_json::json;
use unpin_core::{
    update::UpdateTarget,
    update_service::{ApplyResult, UpdateRequest, UpdateStatus, apply_update, check_for_update},
};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub(crate) enum UpdateTargetArg {
    #[default]
    Cli,
    Desktop,
}

impl From<UpdateTargetArg> for UpdateTarget {
    fn from(target: UpdateTargetArg) -> Self {
        match target {
            UpdateTargetArg::Cli => Self::Cli,
            UpdateTargetArg::Desktop => Self::Desktop,
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum UpdateCommands {
    /// Check the latest stable GitHub release without changing files.
    Check {
        /// Artifact family to check.
        #[arg(long, value_enum, default_value_t)]
        target: UpdateTargetArg,
        /// Exact installed binary or .app bundle to inspect.
        #[arg(long)]
        install_path: Option<PathBuf>,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Download, verify, and atomically install the latest stable release.
    Apply {
        /// Artifact family to install.
        #[arg(long, value_enum, default_value_t)]
        target: UpdateTargetArg,
        /// Exact installed binary or .app bundle to replace.
        #[arg(long)]
        install_path: Option<PathBuf>,
        /// Latest version shown by `unpin update check`.
        #[arg(long)]
        confirm: String,
        /// Relaunch the desktop app after a successful swap.
        #[arg(long)]
        relaunch: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

impl UpdateCommands {
    const fn machine_output(&self) -> bool {
        match self {
            Self::Check { json, .. } | Self::Apply { json, .. } => *json,
        }
    }
}

pub(crate) fn run(command: UpdateCommands) -> ExitCode {
    let machine = command.machine_output();
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            return update_error_exit_code(
                machine,
                "update_runtime_failed",
                &format!("update runtime failed: {error}"),
                1,
            );
        }
    };
    let result = match command {
        UpdateCommands::Check {
            target,
            install_path,
            json,
        } => runtime
            .block_on(check_for_update(UpdateTarget::from(target), install_path))
            .and_then(|status| render_check(&status, json)),
        UpdateCommands::Apply {
            target,
            install_path,
            confirm,
            relaunch,
            json,
        } => runtime
            .block_on(apply_update(UpdateRequest {
                target: target.into(),
                install_path,
                confirm,
                relaunch,
            }))
            .and_then(|result| render_apply(&result, json)),
    };
    match result {
        Ok(rendered) => {
            println!("{rendered}");
            ExitCode::SUCCESS
        }
        Err(error) => update_error_exit_code(
            machine,
            "update_failed",
            &format!("update failed: {error}"),
            1,
        ),
    }
}

fn update_error_exit_code(machine: bool, error_code: &str, reason: &str, code: u8) -> ExitCode {
    match render_update_error(machine, error_code, reason) {
        Ok(output) => {
            if machine {
                println!("{output}");
            } else {
                eprintln!("{output}");
            }
        }
        Err(error) => eprintln!("failed to render update error: {error}"),
    }
    ExitCode::from(code)
}

fn render_update_error(machine: bool, error_code: &str, reason: &str) -> Result<String, String> {
    if machine {
        return serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "status": "error",
            "errorCode": error_code,
            "reason": reason,
        }))
        .map_err(|error| error.to_string());
    }
    Ok(reason.to_string())
}

fn render_check(status: &UpdateStatus, machine: bool) -> Result<String, String> {
    let available = status.archive_name.is_some();
    if machine {
        return serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "status": if available { "available" } else { "current" },
            "target": status.target.as_str(),
            "platform": status.platform.target_triple(),
            "currentVersion": status.current_version.to_string(),
            "latestVersion": status.latest_version.to_string(),
            "archiveName": status.archive_name,
            "releaseUrl": status.release_url,
        }))
        .map_err(|error| error.to_string());
    }
    if available {
        Ok(format!(
            "Update available: {} -> {}\nTarget: {} ({})\nRelease: {}\nApply: unpin update apply --target {} --confirm {}",
            status.current_version,
            status.latest_version,
            status.target.as_str(),
            status.platform.target_triple(),
            status.release_url,
            status.target.as_str(),
            status.latest_version
        ))
    } else {
        Ok(format!(
            "Unpin {} is current (latest {}).",
            status.current_version, status.latest_version
        ))
    }
}

fn render_apply(result: &ApplyResult, machine: bool) -> Result<String, String> {
    if machine {
        return serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "status": "updated",
            "target": result.target.as_str(),
            "previousVersion": result.previous_version.to_string(),
            "installedVersion": result.installed_version.to_string(),
            "installPath": result.install_path,
            "backupPath": result.backup_path,
            "keychainRequirementPreserved": result.keychain_requirement_preserved,
            "relaunchStatus": result.relaunch_status.as_str(),
            "warning": result.warning,
        }))
        .map_err(|error| error.to_string());
    }
    let warning = result
        .warning
        .as_deref()
        .map_or_else(String::new, |warning| format!("\nWarning: {warning}"));
    Ok(format!(
        "Updated {} from {} to {} at {}.\nRollback backup: {}{warning}",
        result.target.as_str(),
        result.previous_version,
        result.installed_version,
        result.install_path.display(),
        result.backup_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use unpin_core::update::{ReleaseVersion, UpdatePlatform};

    #[test]
    fn check_json_available_is_exact() {
        let status = UpdateStatus {
            current_version: ReleaseVersion::parse("1.0.2").expect("current"),
            latest_version: ReleaseVersion::parse("1.1.0").expect("latest"),
            target: UpdateTarget::Cli,
            platform: UpdatePlatform::MacOsArm64,
            archive_name: Some("unpin-v1.1.0-aarch64-apple-darwin.tar.gz".to_string()),
            release_url: "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0".to_string(),
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_check(&status, true).expect("render")).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "available",
                "target": "cli",
                "platform": "aarch64-apple-darwin",
                "currentVersion": "1.0.2",
                "latestVersion": "1.1.0",
                "archiveName": "unpin-v1.1.0-aarch64-apple-darwin.tar.gz",
                "releaseUrl": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            })
        );
    }

    #[test]
    fn check_json_current_includes_null_archive_name() {
        let status = UpdateStatus {
            current_version: ReleaseVersion::parse("1.1.0").expect("current"),
            latest_version: ReleaseVersion::parse("1.1.0").expect("latest"),
            target: UpdateTarget::Desktop,
            platform: UpdatePlatform::MacOsArm64,
            archive_name: None,
            release_url: "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0".to_string(),
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_check(&status, true).expect("render")).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "current",
                "target": "desktop",
                "platform": "aarch64-apple-darwin",
                "currentVersion": "1.1.0",
                "latestVersion": "1.1.0",
                "archiveName": null,
                "releaseUrl": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            })
        );
    }

    #[test]
    fn apply_json_without_warning_is_exact() {
        let result = ApplyResult {
            previous_version: ReleaseVersion::parse("1.0.2").expect("previous"),
            installed_version: ReleaseVersion::parse("1.1.0").expect("installed"),
            target: UpdateTarget::Desktop,
            install_path: PathBuf::from("/Applications/UnpinDesktop.app"),
            backup_path: PathBuf::from("/Applications/.UnpinDesktop.app.unpin-backup-1.0.2"),
            keychain_requirement_preserved: true,
            relaunch_status: unpin_core::update_service::RelaunchStatus::NotRequested,
            warning: None,
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_apply(&result, true).expect("render")).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "updated",
                "target": "desktop",
                "previousVersion": "1.0.2",
                "installedVersion": "1.1.0",
                "installPath": "/Applications/UnpinDesktop.app",
                "backupPath": "/Applications/.UnpinDesktop.app.unpin-backup-1.0.2",
                "keychainRequirementPreserved": true,
                "relaunchStatus": "notRequested",
                "warning": null,
            })
        );
    }

    #[test]
    fn apply_json_with_warning_is_exact() {
        let result = ApplyResult {
            previous_version: ReleaseVersion::parse("1.0.2").expect("previous"),
            installed_version: ReleaseVersion::parse("1.1.0").expect("installed"),
            target: UpdateTarget::Cli,
            install_path: PathBuf::from("/usr/local/bin/unpin"),
            backup_path: PathBuf::from("/usr/local/bin/.unpin.unpin-backup-1.0.2"),
            keychain_requirement_preserved: false,
            relaunch_status: unpin_core::update_service::RelaunchStatus::Failed,
            warning: Some("relaunch failed; start Unpin manually".to_string()),
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_apply(&result, true).expect("render")).expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "updated",
                "target": "cli",
                "previousVersion": "1.0.2",
                "installedVersion": "1.1.0",
                "installPath": "/usr/local/bin/unpin",
                "backupPath": "/usr/local/bin/.unpin.unpin-backup-1.0.2",
                "keychainRequirementPreserved": false,
                "relaunchStatus": "failed",
                "warning": "relaunch failed; start Unpin manually",
            })
        );
    }

    #[test]
    fn update_runtime_error_json_is_exact() {
        let value: serde_json::Value = serde_json::from_str(
            &render_update_error(true, "update_runtime_failed", "update runtime failed: boom")
                .expect("render"),
        )
        .expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "error",
                "errorCode": "update_runtime_failed",
                "reason": "update runtime failed: boom",
            })
        );
    }

    #[test]
    fn update_failure_json_is_exact() {
        let value: serde_json::Value = serde_json::from_str(
            &render_update_error(true, "update_failed", "update failed: bad confirmation")
                .expect("render"),
        )
        .expect("JSON");
        assert_eq!(
            value,
            json!({
                "schemaVersion": 1,
                "status": "error",
                "errorCode": "update_failed",
                "reason": "update failed: bad confirmation",
            })
        );
    }
}
