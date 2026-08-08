use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use crate::update::{
    ReleaseVersion, UpdateError, UpdatePlan, UpdatePlatform, UpdateTarget, checksum_for,
    extract_release_archive, sha256_file, verify_file_digest,
};
use futures::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt as _;

const RELEASE_OWNER: &str = "IgorArkhipov";
const RELEASE_REPOSITORY: &str = "unpin";
const CHECKSUM_ASSET_NAME: &str = "SHA256SUMS";
#[cfg(target_os = "macos")]
const DESKTOP_BRIDGE_PROTOCOL_VERSION: u64 = 2;
#[cfg(target_os = "macos")]
const CLI_CODE_IDENTIFIER: &str = "dev.unpin.cli";
#[cfg(target_os = "macos")]
const DESKTOP_CODE_IDENTIFIER: &str = "dev.unpin.workbench";
#[cfg(target_os = "macos")]
const DESKTOP_BRIDGE_CODE_IDENTIFIER: &str = "dev.unpin.workbench.bridge";
const MAX_RELEASE_METADATA_BYTES: u64 = 512 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 64 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_VERSION_OUTPUT_BYTES: usize = 4 * 1024;
const CANDIDATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(unix)]
const CHILD_TERMINATION_GRACE: Duration = Duration::from_millis(250);
#[cfg(target_os = "macos")]
const MAX_PLIST_OUTPUT_BYTES: usize = 4 * 1024;
#[cfg(target_os = "macos")]
const MAX_CODESIGN_OUTPUT_BYTES: usize = 64 * 1024;
#[cfg(target_os = "macos")]
const MAX_BRIDGE_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone)]
struct ReleaseAsset {
    download_url: String,
    digest: Option<String>,
    size: u64,
}

#[derive(Debug, Clone)]
struct LatestRelease {
    tag_name: String,
    release_url: String,
    assets: BTreeMap<String, ReleaseAsset>,
}

#[derive(Debug, Clone)]
pub struct UpdateStatus {
    pub current_version: ReleaseVersion,
    pub latest_version: ReleaseVersion,
    pub target: UpdateTarget,
    pub platform: UpdatePlatform,
    pub archive_name: Option<String>,
    pub release_url: String,
}

#[derive(Debug)]
pub struct UpdateRequest {
    pub target: UpdateTarget,
    pub install_path: Option<PathBuf>,
    pub confirm: String,
    pub relaunch: bool,
}

#[derive(Debug)]
pub struct ApplyResult {
    pub previous_version: ReleaseVersion,
    pub installed_version: ReleaseVersion,
    pub target: UpdateTarget,
    pub install_path: PathBuf,
    pub backup_path: PathBuf,
    pub keychain_requirement_preserved: bool,
    pub relaunch_status: RelaunchStatus,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaunchStatus {
    NotRequested,
    Confirmed,
    Failed,
}

impl RelaunchStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "notRequested",
            Self::Confirmed => "confirmed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CandidateVerification {
    keychain_requirement_preserved: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy)]
enum CodeSignatureScope {
    Executable,
    Bundle,
}

pub async fn check_for_update(
    target: UpdateTarget,
    install_path: Option<PathBuf>,
) -> Result<UpdateStatus, String> {
    let platform = UpdatePlatform::current().map_err(|error| error.to_string())?;
    if !platform.supports(target) {
        return Err(UpdateError::UnsupportedPlatform.to_string());
    }
    let install_path = resolve_install_path(target, install_path.as_deref())?;
    validate_install_target(&install_path, target)?;
    let current_version = resolve_installed_version(target, &install_path)?;
    let client = update_client()?;
    let release = fetch_latest_release(&client).await?;
    let latest_version =
        ReleaseVersion::parse(&release.tag_name).map_err(|error| error.to_string())?;
    let available = latest_version > current_version;
    let archive_name = if available {
        Some(
            UpdatePlan::new(
                &current_version.to_string(),
                &release.tag_name,
                target,
                platform,
            )
            .map_err(|error| error.to_string())?
            .archive_name,
        )
    } else {
        None
    };
    if let Some(archive_name) = &archive_name {
        release_asset(&release, archive_name)?;
        release_asset(&release, CHECKSUM_ASSET_NAME)?;
    }
    Ok(UpdateStatus {
        current_version,
        latest_version,
        target,
        platform,
        archive_name,
        release_url: release.release_url,
    })
}

pub async fn apply_update(request: UpdateRequest) -> Result<ApplyResult, String> {
    let platform = UpdatePlatform::current().map_err(|error| error.to_string())?;
    if !platform.supports(request.target) {
        return Err(UpdateError::UnsupportedPlatform.to_string());
    }
    if matches!(request.target, UpdateTarget::Cli) && request.relaunch {
        return Err("--relaunch requires --target desktop".to_string());
    }
    let confirmed = ReleaseVersion::parse(&request.confirm).map_err(|error| error.to_string())?;
    let install_path = resolve_install_path(request.target, request.install_path.as_deref())?;
    validate_install_target(&install_path, request.target)?;
    let _lock = UpdateLock::acquire(&install_path)?;
    let current_version = resolve_installed_version(request.target, &install_path)?;
    let installed_fingerprint = fingerprint_path(&install_path)?;
    let client = update_client()?;
    let release = fetch_latest_release(&client).await?;
    let plan = UpdatePlan::new(
        &current_version.to_string(),
        &release.tag_name,
        request.target,
        platform,
    )
    .map_err(|error| error.to_string())?;
    if confirmed != plan.latest_version {
        return Err(format!(
            "confirmation must exactly match latest version {}",
            plan.latest_version
        ));
    }
    let parent = install_path
        .parent()
        .ok_or_else(|| "install path must have a parent directory".to_string())?;
    let workspace = UpdateWorkspace::create(parent)?;
    let checksum_asset = release_asset(&release, CHECKSUM_ASSET_NAME)?;
    let archive_asset = release_asset(&release, &plan.archive_name)?;
    let checksum_path = workspace.path.join(CHECKSUM_ASSET_NAME);
    let archive_path = workspace.path.join(&plan.archive_name);
    tokio::try_join!(
        download_asset(
            &client,
            CHECKSUM_ASSET_NAME,
            &checksum_asset,
            &checksum_path,
            MAX_CHECKSUM_BYTES
        ),
        download_asset(
            &client,
            &plan.archive_name,
            &archive_asset,
            &archive_path,
            MAX_ARCHIVE_BYTES
        )
    )?;
    if let Some(digest) = &checksum_asset.digest {
        verify_file_digest(&checksum_path, digest, CHECKSUM_ASSET_NAME)
            .map_err(|error| error.to_string())?;
    }
    let checksum_bytes = fs::read(&checksum_path).map_err(|error| error.to_string())?;
    let expected_archive_digest =
        checksum_for(&checksum_bytes, &plan.archive_name).map_err(|error| error.to_string())?;
    if archive_asset
        .digest
        .as_ref()
        .is_some_and(|digest| digest != &expected_archive_digest)
    {
        return Err(format!(
            "GitHub digest disagrees with SHA256SUMS for {}",
            plan.archive_name
        ));
    }
    verify_file_digest(&archive_path, &expected_archive_digest, &plan.archive_name)
        .map_err(|error| error.to_string())?;
    let candidate = extract_release_archive(&archive_path, &workspace.path.join("unpacked"), &plan)
        .map_err(|error| error.to_string())?;
    let candidate_fingerprint = fingerprint_path(&candidate)?;
    let verification = verify_candidate(&install_path, &candidate, &plan)?;
    let backup_path = install_candidate(
        &candidate,
        &install_path,
        &plan.current_version,
        request.target,
        &installed_fingerprint,
        &candidate_fingerprint,
        &workspace.path,
    )?;
    write_update_audit_or_rollback(
        &install_path,
        &backup_path,
        &plan,
        &candidate_fingerprint,
        &workspace.path,
    )?;
    let (relaunch_status, warning) = if request.relaunch {
        match relaunch_desktop(&install_path) {
            Ok(()) => (RelaunchStatus::Confirmed, None),
            Err(error) => (
                RelaunchStatus::Failed,
                Some(format!(
                    "update committed but desktop relaunch failed: {error}"
                )),
            ),
        }
    } else {
        (RelaunchStatus::NotRequested, None)
    };
    Ok(ApplyResult {
        previous_version: plan.current_version,
        installed_version: plan.latest_version,
        target: request.target,
        install_path,
        backup_path,
        keychain_requirement_preserved: verification.keychain_requirement_preserved,
        relaunch_status,
        warning,
    })
}

fn update_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(90))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !allowed_update_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .user_agent(format!("unpin/{} self-update", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| error.to_string())
}

fn allowed_update_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https" {
        return false;
    }
    matches!(
        url.host_str(),
        Some("api.github.com" | "github.com" | "objects.githubusercontent.com")
    ) || url
        .host_str()
        .is_some_and(|host| host.ends_with(".githubusercontent.com"))
}

fn latest_release_api_url() -> String {
    format!("https://api.github.com/repos/{RELEASE_OWNER}/{RELEASE_REPOSITORY}/releases/latest")
}

fn release_web_url(tag_name: &str) -> String {
    format!("https://github.com/{RELEASE_OWNER}/{RELEASE_REPOSITORY}/releases/tag/{tag_name}")
}

fn release_asset_url(tag_name: &str, asset_name: &str) -> String {
    format!(
        "https://github.com/{RELEASE_OWNER}/{RELEASE_REPOSITORY}/releases/download/{tag_name}/{asset_name}"
    )
}

async fn fetch_latest_release(client: &reqwest::Client) -> Result<LatestRelease, String> {
    let url = reqwest::Url::parse(&latest_release_api_url()).expect("constructed update URL");
    let token = ["GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()));
    let bytes = fetch_limited(client, url, MAX_RELEASE_METADATA_BYTES, token.as_deref())
        .await
        .map_err(|error| format!("GitHub release API failed: {error}"))?;
    parse_latest_release(&bytes)
}

fn parse_latest_release(bytes: &[u8]) -> Result<LatestRelease, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.get("draft").and_then(Value::as_bool) != Some(false)
        || value.get("prerelease").and_then(Value::as_bool) != Some(false)
    {
        return Err("latest release must be published and stable".to_string());
    }
    let tag_name = required_string(&value, "tag_name")?.to_string();
    ReleaseVersion::parse(&tag_name).map_err(|error| error.to_string())?;
    let release_url = required_string(&value, "html_url")?.to_string();
    if release_url != release_web_url(&tag_name) {
        return Err("latest release URL is not trusted".to_string());
    }
    let assets = value
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| "latest release assets are missing".to_string())?;
    let mut parsed = BTreeMap::new();
    for asset in assets {
        let name = required_string(asset, "name")?.to_string();
        if Path::new(&name)
            .file_name()
            .and_then(|value| value.to_str())
            != Some(&name)
        {
            return Err("latest release contains an unsafe asset name".to_string());
        }
        let download_url = required_string(asset, "browser_download_url")?.to_string();
        let parsed_url = reqwest::Url::parse(&download_url).map_err(|error| error.to_string())?;
        let expected_download_url = release_asset_url(&tag_name, &name);
        if !allowed_update_url(&parsed_url) || download_url != expected_download_url {
            return Err(format!("release asset URL is not trusted: {download_url}"));
        }
        let digest = match asset.get("digest") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => {
                let digest = value
                    .strip_prefix("sha256:")
                    .ok_or_else(|| format!("release asset digest is not SHA-256: {name}"))?
                    .to_string();
                if !crate::is_lower_hex_digest(&digest) {
                    return Err(format!("release asset digest is invalid: {name}"));
                }
                Some(digest)
            }
            Some(_) => return Err(format!("release asset digest is invalid: {name}")),
        };
        let size = asset
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("release asset size is invalid: {name}"))?;
        let descriptor = ReleaseAsset {
            download_url,
            digest,
            size,
        };
        if parsed.insert(name.clone(), descriptor).is_some() {
            return Err(format!("duplicate release asset: {name}"));
        }
    }
    Ok(LatestRelease {
        tag_name,
        release_url,
        assets: parsed,
    })
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("latest release field is missing: {key}"))
}

fn release_asset(release: &LatestRelease, name: &str) -> Result<ReleaseAsset, String> {
    release
        .assets
        .get(name)
        .cloned()
        .ok_or_else(|| format!("latest release asset is missing: {name}"))
}

async fn download_asset(
    client: &reqwest::Client,
    asset_name: &str,
    asset: &ReleaseAsset,
    destination: &Path,
    maximum_bytes: u64,
) -> Result<(), String> {
    if asset.size == 0 || asset.size > maximum_bytes {
        return Err(format!("release asset size is out of bounds: {asset_name}"));
    }
    let url = reqwest::Url::parse(&asset.download_url).map_err(|error| error.to_string())?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes || length != asset.size)
    {
        return Err(format!("release asset length changed: {asset_name}"));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .await
        .map_err(|error| error.to_string())?;
    let mut received = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        received = received
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| "release asset length overflow".to_string())?;
        if received > maximum_bytes || received > asset.size {
            return Err(format!("release asset exceeded size: {asset_name}"));
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| error.to_string())?;
    }
    if received == 0 || received != asset.size {
        return Err(format!("release asset was truncated: {asset_name}"));
    }
    file.sync_all().await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn fetch_limited(
    client: &reqwest::Client,
    url: reqwest::Url,
    maximum_bytes: u64,
    bearer_token: Option<&str>,
) -> Result<Vec<u8>, String> {
    if !allowed_update_url(&url) {
        return Err("update URL is not trusted".to_string());
    }
    let mut request = client.get(url);
    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .map_err(|error| error.to_string())?
        .error_for_status()
        .map_err(|error| error.to_string())?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum_bytes)
    {
        return Err("update response exceeds size limit".to_string());
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| error.to_string())?;
        if bytes.len().saturating_add(chunk.len()) > maximum_bytes as usize {
            return Err("update response exceeds size limit".to_string());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn resolve_install_path(target: UpdateTarget, requested: Option<&Path>) -> Result<PathBuf, String> {
    let path = match requested {
        Some(path) => path.to_path_buf(),
        None => match target {
            UpdateTarget::Cli => std::env::current_exe().map_err(|error| error.to_string())?,
            UpdateTarget::Desktop => {
                infer_app_bundle(&std::env::current_exe().map_err(|error| error.to_string())?)?
            }
        },
    };
    if !path.is_absolute() {
        return Err("install path must be absolute".to_string());
    }
    Ok(path)
}

fn infer_app_bundle(executable: &Path) -> Result<PathBuf, String> {
    executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .map(Path::to_path_buf)
        .ok_or_else(|| "desktop install path must be provided outside an app bundle".to_string())
}

fn validate_install_target(path: &Path, target: UpdateTarget) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("install path must not be a symbolic link".to_string());
    }
    match target {
        UpdateTarget::Cli if !metadata.is_file() => {
            return Err("CLI install path must be a regular file".to_string());
        }
        UpdateTarget::Desktop
            if !metadata.is_dir()
                || path.extension().and_then(|value| value.to_str()) != Some("app") =>
        {
            return Err("desktop install path must be an .app bundle".to_string());
        }
        _ => {}
    }
    Ok(())
}

fn resolve_installed_version(
    target: UpdateTarget,
    install_path: &Path,
) -> Result<ReleaseVersion, String> {
    match target {
        UpdateTarget::Cli => {
            let mut command = Command::new(install_path);
            command.arg("--version");
            let (status, stdout) =
                bounded_stdout(&mut command, MAX_VERSION_OUTPUT_BYTES, "installed version")?;
            if !status.success() {
                return Err("installed executable version smoke failed".to_string());
            }
            parse_cli_version_output(&stdout)
        }
        UpdateTarget::Desktop => {
            #[cfg(not(target_os = "macos"))]
            {
                let _ = install_path;
                Err("desktop updates require macOS".to_string())
            }
            #[cfg(target_os = "macos")]
            {
                let info_plist = install_path.join("Contents/Info.plist");
                let value = plist_value(&info_plist, "CFBundleShortVersionString")?;
                ReleaseVersion::parse(value.trim()).map_err(|error| error.to_string())
            }
        }
    }
}

fn parse_cli_version_output(stdout: &[u8]) -> Result<ReleaseVersion, String> {
    let stdout = String::from_utf8(stdout.to_vec()).map_err(|error| error.to_string())?;
    let output = stdout.trim();
    let version = output
        .strip_prefix("unpin ")
        .filter(|version| !version.is_empty())
        .ok_or_else(|| "installed executable reported an invalid version".to_string())?;
    ReleaseVersion::parse(version).map_err(|error| error.to_string())
}

fn verify_candidate(
    installed: &Path,
    candidate: &Path,
    plan: &UpdatePlan,
) -> Result<CandidateVerification, String> {
    match plan.target {
        UpdateTarget::Cli => verify_cli_candidate(installed, candidate, &plan.latest_version),
        UpdateTarget::Desktop => {
            verify_desktop_candidate(installed, candidate, &plan.latest_version)
        }
    }
}

fn verify_cli_candidate(
    _installed: &Path,
    candidate: &Path,
    expected_version: &ReleaseVersion,
) -> Result<CandidateVerification, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(candidate)
            .map_err(|error| error.to_string())?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err("candidate CLI is not executable".to_string());
        }
    }
    #[cfg(target_os = "macos")]
    verify_matching_code_requirement(
        _installed,
        candidate,
        CodeSignatureScope::Executable,
        CLI_CODE_IDENTIFIER,
    )?;
    verify_executable_version(candidate, expected_version)?;
    Ok(CandidateVerification {
        keychain_requirement_preserved: cfg!(target_os = "macos"),
    })
}

fn verify_desktop_candidate(
    installed: &Path,
    candidate: &Path,
    expected_version: &ReleaseVersion,
) -> Result<CandidateVerification, String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (installed, candidate, expected_version);
        Err("desktop updates require macOS".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        verify_matching_code_requirement(
            installed,
            candidate,
            CodeSignatureScope::Bundle,
            DESKTOP_CODE_IDENTIFIER,
        )?;
        let info_plist = candidate.join("Contents/Info.plist");
        verify_plist_value(&info_plist, "CFBundleIdentifier", DESKTOP_CODE_IDENTIFIER)?;
        verify_plist_value(
            &info_plist,
            "CFBundleShortVersionString",
            &expected_version.to_string(),
        )?;
        let installed_bridge = installed.join("Contents/MacOS/unpin");
        let candidate_bridge = candidate.join("Contents/MacOS/unpin");
        verify_matching_code_requirement(
            &installed_bridge,
            &candidate_bridge,
            CodeSignatureScope::Executable,
            DESKTOP_BRIDGE_CODE_IDENTIFIER,
        )?;
        verify_executable_version(&candidate_bridge, expected_version)?;
        verify_desktop_bridge_manifest(
            &candidate.join("Contents/Resources/unpin-bridge-manifest.json"),
            &candidate_bridge,
            expected_version,
        )?;
        Ok(CandidateVerification {
            keychain_requirement_preserved: true,
        })
    }
}

#[cfg(target_os = "macos")]
fn verify_desktop_bridge_manifest(
    manifest_path: &Path,
    candidate_bridge: &Path,
    expected_version: &ReleaseVersion,
) -> Result<(), String> {
    let mut bytes = Vec::new();
    File::open(manifest_path)
        .map_err(|error| error.to_string())?
        .take(MAX_BRIDGE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_BRIDGE_MANIFEST_BYTES {
        return Err("candidate desktop bridge manifest is too large".to_string());
    }
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if manifest
        .get("bridgeProtocolVersion")
        .and_then(Value::as_u64)
        != Some(DESKTOP_BRIDGE_PROTOCOL_VERSION)
    {
        return Err("candidate desktop bridge protocol is incompatible".to_string());
    }
    let expected_version = expected_version.to_string();
    if manifest.get("unpinVersion").and_then(Value::as_str) != Some(expected_version.as_str()) {
        return Err("candidate desktop bridge manifest version is invalid".to_string());
    }
    let expected_digest = manifest
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "candidate desktop bridge manifest digest is missing".to_string())?;
    verify_file_digest(candidate_bridge, expected_digest, "desktop bridge")
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn verify_plist_value(path: &Path, key: &str, expected: &str) -> Result<(), String> {
    let value = plist_value(path, key)?;
    if value.trim() != expected {
        return Err(format!("candidate desktop Info.plist has unexpected {key}"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn plist_value(path: &Path, key: &str) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/plutil");
    command.args(["-extract", key, "raw", "-o", "-"]).arg(path);
    let (status, stdout) =
        bounded_stdout(&mut command, MAX_PLIST_OUTPUT_BYTES, "candidate Info.plist")?;
    if !status.success() {
        return Err(format!("candidate desktop Info.plist is invalid: {key}"));
    }
    String::from_utf8(stdout).map_err(|error| error.to_string())
}

fn verify_executable_version(path: &Path, expected: &ReleaseVersion) -> Result<(), String> {
    let mut command = Command::new(path);
    command.arg("--version");
    let (status, stdout) =
        bounded_stdout(&mut command, MAX_VERSION_OUTPUT_BYTES, "candidate version")?;
    if !status.success() {
        return Err("candidate executable version smoke failed".to_string());
    }
    let stdout = String::from_utf8(stdout).map_err(|error| error.to_string())?;
    if stdout.trim() != format!("unpin {expected}") {
        return Err(format!(
            "candidate executable reported unexpected version: {}",
            stdout.trim()
        ));
    }
    Ok(())
}

fn bounded_stdout(
    command: &mut Command,
    maximum_bytes: usize,
    description: &str,
) -> Result<(ExitStatus, Vec<u8>), String> {
    bounded_stdout_with_timeout(
        command,
        maximum_bytes,
        description,
        CANDIDATE_COMMAND_TIMEOUT,
    )
}

fn bounded_stdout_with_timeout(
    command: &mut Command,
    maximum_bytes: usize,
    description: &str,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>), String> {
    let output = bounded_output_with_timeout(command, maximum_bytes, description, timeout)?;
    Ok((output.status, output.stdout))
}

#[derive(Debug)]
struct BoundedProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    #[cfg(target_os = "macos")]
    stderr: Vec<u8>,
}

#[cfg(any(target_os = "macos", all(test, unix)))]
fn bounded_output(
    command: &mut Command,
    maximum_bytes: usize,
    description: &str,
) -> Result<BoundedProcessOutput, String> {
    bounded_output_with_timeout(
        command,
        maximum_bytes,
        description,
        CANDIDATE_COMMAND_TIMEOUT,
    )
}

fn bounded_output_with_timeout(
    command: &mut Command,
    maximum_bytes: usize,
    description: &str,
    timeout: Duration,
) -> Result<BoundedProcessOutput, String> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| format!("{description} stdout pipe is unavailable"))?;
    let mut stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| format!("{description} stderr pipe is unavailable"))?;
    let (stdout_sender, stdout_receiver) = mpsc::channel();
    let (stderr_sender, stderr_receiver) = mpsc::channel();
    let _stdout_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout_pipe
            .by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut output)
            .map(|_| output);
        let _ = stdout_sender.send(result);
    });
    let _stderr_reader = thread::spawn(move || {
        let mut output = Vec::new();
        let result = stderr_pipe
            .by_ref()
            .take(maximum_bytes as u64 + 1)
            .read_to_end(&mut output)
            .map(|_| output);
        let _ = stderr_sender.send(result);
    });
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child.try_wait().map_err(|error| error.to_string())?;
        }
        if stdout.is_none() {
            match stdout_receiver.try_recv() {
                Ok(Ok(output)) => stdout = Some(output),
                Ok(Err(error)) => {
                    terminate_child(&mut child);
                    return Err(format!("{description} stdout read failed: {error}"));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate_child(&mut child);
                    return Err(format!("{description} stdout reader failed"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if stderr.is_none() {
            match stderr_receiver.try_recv() {
                Ok(Ok(output)) => stderr = Some(output),
                Ok(Err(error)) => {
                    terminate_child(&mut child);
                    return Err(format!("{description} stderr read failed: {error}"));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    terminate_child(&mut child);
                    return Err(format!("{description} stderr reader failed"));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let (Some(status), Some(stdout), Some(stderr)) =
            (status, stdout.as_ref(), stderr.as_ref())
        {
            let output_bytes = stdout
                .len()
                .checked_add(stderr.len())
                .ok_or_else(|| format!("{description} output size overflow"))?;
            if output_bytes > maximum_bytes {
                return Err(format!("{description} output exceeds size limit"));
            }
            return Ok(BoundedProcessOutput {
                status,
                stdout: stdout.clone(),
                #[cfg(target_os = "macos")]
                stderr: stderr.clone(),
            });
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            return Err(format!("{description} timed out"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let process_group = format!("-{}", child.id());
        let signal_group = |signal: &str| {
            let _ = Command::new("/bin/kill")
                .args([signal, &process_group])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        };
        signal_group("-TERM");
        let deadline = Instant::now() + CHILD_TERMINATION_GRACE;
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        signal_group("-KILL");
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "macos")]
fn verify_matching_code_requirement(
    installed: &Path,
    candidate: &Path,
    scope: CodeSignatureScope,
    expected_identifier: &str,
) -> Result<(), String> {
    verify_codesign(candidate, scope)?;
    for path in [installed, candidate] {
        let identifier = code_identifier(path)?;
        if identifier != expected_identifier {
            return Err(format!(
                "code signing identifier changed; expected {expected_identifier}, got {identifier} ({})",
                path.display()
            ));
        }
    }
    let installed_requirement = code_requirement(installed)?;
    let candidate_requirement = code_requirement(candidate)?;
    if installed_requirement != candidate_requirement {
        return Err(format!(
            "candidate designated requirement changed; Keychain Always Allow would not persist ({installed_requirement} != {candidate_requirement})"
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn code_identifier(path: &Path) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["-d", "--verbose=4"]).arg(path);
    let output = bounded_output(
        &mut command,
        MAX_CODESIGN_OUTPUT_BYTES,
        "code signing identifier",
    )?;
    if !output.status.success() {
        return Err(format!(
            "could not inspect code signing identifier: {}",
            path.display()
        ));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let stderr = String::from_utf8(output.stderr).map_err(|error| error.to_string())?;
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(|line| line.strip_prefix("Identifier="))
        .map(str::to_string)
        .ok_or_else(|| format!("code signing identifier missing: {}", path.display()))
}

#[cfg(target_os = "macos")]
fn verify_codesign(path: &Path, scope: CodeSignatureScope) -> Result<(), String> {
    let mut command = Command::new("/usr/bin/codesign");
    command.arg("--verify");
    if matches!(scope, CodeSignatureScope::Bundle) {
        command.arg("--deep");
    }
    command.args(["--strict", "--verbose=4"]).arg(path);
    let output = bounded_output(
        &mut command,
        MAX_CODESIGN_OUTPUT_BYTES,
        "code signature verification",
    )?;
    if !output.status.success() {
        return Err(format!(
            "candidate code signature is invalid: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn code_requirement(path: &Path) -> Result<String, String> {
    let mut command = Command::new("/usr/bin/codesign");
    command.args(["-d", "-r-"]).arg(path);
    let output = bounded_output(
        &mut command,
        MAX_CODESIGN_OUTPUT_BYTES,
        "code signing requirement",
    )?;
    if !output.status.success() {
        return Err(format!(
            "installed code requirement is unavailable: {}",
            path.display()
        ));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
    let stderr = String::from_utf8(output.stderr).map_err(|error| error.to_string())?;
    stdout
        .lines()
        .chain(stderr.lines())
        .find_map(|line| {
            line.strip_prefix("# ")
                .unwrap_or(line)
                .strip_prefix("designated => ")
        })
        .map(str::to_string)
        .ok_or_else(|| format!("designated requirement is missing: {}", path.display()))
}

fn install_candidate(
    candidate: &Path,
    install_path: &Path,
    current_version: &ReleaseVersion,
    target: UpdateTarget,
    installed_fingerprint: &str,
    candidate_fingerprint: &str,
    workspace: &Path,
) -> Result<PathBuf, String> {
    install_candidate_with_sync(
        candidate,
        install_path,
        current_version,
        target,
        InstallFingerprints {
            installed: installed_fingerprint,
            candidate: candidate_fingerprint,
        },
        workspace,
        sync_tree,
    )
}

struct InstallFingerprints<'a> {
    installed: &'a str,
    candidate: &'a str,
}

fn install_candidate_with_sync<F>(
    candidate: &Path,
    install_path: &Path,
    current_version: &ReleaseVersion,
    target: UpdateTarget,
    fingerprints: InstallFingerprints<'_>,
    workspace: &Path,
    sync_tree_for_install: F,
) -> Result<PathBuf, String>
where
    F: Fn(&Path) -> Result<(), String>,
{
    validate_install_target(install_path, target)?;
    if fingerprint_path(install_path)? != fingerprints.installed {
        return Err("installed update target changed after the update began".to_string());
    }
    if fingerprint_path(candidate)? != fingerprints.candidate {
        return Err("verified update candidate changed before installation".to_string());
    }
    sync_tree_for_install(candidate)?;
    if fingerprint_path(candidate)? != fingerprints.candidate {
        return Err("verified update candidate changed during durability sync".to_string());
    }

    let parent = install_path
        .parent()
        .ok_or_else(|| "install path has no parent".to_string())?;
    let file_name = install_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "install name is invalid".to_string())?;
    let backup = parent.join(format!(".{file_name}.unpin-backup-{current_version}"));
    if fs::symlink_metadata(&backup).is_ok() {
        return Err(format!(
            "update backup already exists: {}",
            backup.display()
        ));
    }

    fs::rename(install_path, &backup).map_err(|error| error.to_string())?;
    if let Err(error) = fs::rename(candidate, install_path) {
        return Err(rollback_error(
            install_path,
            &backup,
            workspace,
            format!("update swap failed: {error}"),
        ));
    }
    if let Err(error) = sync_tree_for_install(install_path).and_then(|()| sync_directory(parent)) {
        return Err(rollback_error(
            install_path,
            &backup,
            workspace,
            format!("update durability sync failed: {error}"),
        ));
    }
    Ok(backup)
}

fn rollback_error(
    install_path: &Path,
    backup: &Path,
    workspace: &Path,
    original_error: String,
) -> String {
    match restore_backup(install_path, backup, workspace) {
        Ok(()) => format!("{original_error}; previous installation was restored"),
        Err(rollback_error) => format!(
            "{original_error}; rollback failed ({rollback_error}); backup is {}",
            backup.display()
        ),
    }
}

fn restore_backup(install_path: &Path, backup: &Path, workspace: &Path) -> Result<(), String> {
    if fs::symlink_metadata(install_path).is_ok() {
        let displaced = workspace.join("failed-install");
        fs::rename(install_path, &displaced).map_err(|error| error.to_string())?;
    }
    fs::rename(backup, install_path).map_err(|error| error.to_string())?;
    sync_tree(install_path)?;
    sync_directory(
        install_path
            .parent()
            .ok_or_else(|| "install path has no parent".to_string())?,
    )
}

fn relaunch_desktop(install_path: &Path) -> Result<(), String> {
    let mut command = Command::new("/usr/bin/open");
    command.arg("-n").arg(install_path).env_clear();
    let (status, _) = bounded_stdout(&mut command, MAX_VERSION_OUTPUT_BYTES, "desktop relaunch")?;
    if !status.success() {
        return Err(format!("/usr/bin/open exited with {status}"));
    }
    Ok(())
}

fn fingerprint_path(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "update path must not be a symbolic link: {}",
            path.display()
        ));
    }
    if metadata.is_file() {
        return sha256_file(path).map_err(|error| error.to_string());
    }
    if !metadata.is_dir() {
        return Err(format!(
            "update path has unsupported type: {}",
            path.display()
        ));
    }
    let mut hasher = Sha256::new();
    hash_tree(path, path, &mut hasher)?;
    Ok(crate::encode_lower_hex(&hasher.finalize()))
}

fn hash_tree(root: &Path, directory: &Path, hasher: &mut Sha256) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "update directory contains a symbolic link: {}",
                relative.display()
            ));
        }
        if metadata.is_dir() {
            hasher.update(b"directory\0");
            hasher.update(relative.to_string_lossy().as_bytes());
            hasher.update(b"\0");
            hash_tree(root, &path, hasher)?;
        } else if metadata.is_file() {
            hasher.update(b"file\0");
            hasher.update(relative.to_string_lossy().as_bytes());
            hasher.update(b"\0");
            hasher.update(
                sha256_file(&path)
                    .map_err(|error| error.to_string())?
                    .as_bytes(),
            );
            hasher.update(b"\0");
        } else {
            return Err(format!(
                "update directory contains an unsupported entry: {}",
                relative.display()
            ));
        }
    }
    Ok(())
}

fn sync_tree(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err(format!("cannot sync symbolic link: {}", path.display()));
    }
    if metadata.is_file() {
        return sync_file(path);
    }
    let entries = fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    for entry in entries {
        sync_tree(&entry.path())?;
    }
    sync_directory(path)
}

fn write_update_audit(
    install_path: &Path,
    backup_path: &Path,
    plan: &UpdatePlan,
    candidate_fingerprint: &str,
) -> Result<(), String> {
    let parent = install_path
        .parent()
        .ok_or_else(|| "install path has no parent".to_string())?;
    let file_name = install_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "install name is invalid".to_string())?;
    let audit_path = parent.join(format!(".{file_name}.unpin-update-audit.jsonl"));
    let record = serde_json::to_vec(&json!({
        "schemaVersion": 1,
        "status": "committed",
        "target": plan.target.as_str(),
        "previousVersion": plan.current_version.to_string(),
        "installedVersion": plan.latest_version.to_string(),
        "installPath": install_path,
        "backupPath": backup_path,
        "candidateSha256": candidate_fingerprint,
    }))
    .map_err(|error| error.to_string())?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&audit_path)
        .map_err(|error| error.to_string())?;
    file.write_all(&record).map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    sync_directory(parent)
}

fn write_update_audit_or_rollback(
    install_path: &Path,
    backup_path: &Path,
    plan: &UpdatePlan,
    candidate_fingerprint: &str,
    workspace: &Path,
) -> Result<(), String> {
    write_update_audit(install_path, backup_path, plan, candidate_fingerprint).map_err(|error| {
        rollback_error(
            install_path,
            backup_path,
            workspace,
            format!("update audit failed: {error}"),
        )
    })
}

#[derive(Debug)]
struct UpdateLock {
    _path: PathBuf,
    _file: File,
}

impl UpdateLock {
    fn acquire(install_path: &Path) -> Result<Self, String> {
        let parent = install_path
            .parent()
            .ok_or_else(|| "install path has no parent".to_string())?;
        let file_name = install_path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "install name is invalid".to_string())?;
        let path = parent.join(format!(".{file_name}.unpin-update.lock"));
        let file = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(format!(
                        "update lock path must not be a symbolic link: {}",
                        path.display()
                    ));
                }
                if !metadata.is_file() {
                    return Err(format!(
                        "update lock path is not a regular file: {}",
                        path.display()
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    if metadata.permissions().mode() & 0o777 != 0o600 {
                        return Err(format!(
                            "update lock path must have mode 0600: {}",
                            path.display()
                        ));
                    }
                }
                // A persistent lock is opened without truncating or writing its contents.
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
                    .map_err(|error| {
                        format!("could not open update lock {}: {error}", path.display())
                    })?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut options = OpenOptions::new();
                options.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt as _;
                    options.mode(0o600);
                }
                match options.open(&path) {
                    Ok(file) => {
                        file.sync_all().map_err(|error| error.to_string())?;
                        sync_directory(parent)?;
                        file
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        // Re-check the path after a create race so a symlink can never be
                        // followed into an attacker-controlled lock target.
                        let metadata = fs::symlink_metadata(&path).map_err(|error| {
                            format!("could not inspect update lock {}: {error}", path.display())
                        })?;
                        if metadata.file_type().is_symlink() {
                            return Err(format!(
                                "update lock path must not be a symbolic link: {}",
                                path.display()
                            ));
                        }
                        if !metadata.is_file() {
                            return Err(format!(
                                "update lock path is not a regular file: {}",
                                path.display()
                            ));
                        }
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt as _;
                            if metadata.permissions().mode() & 0o777 != 0o600 {
                                return Err(format!(
                                    "update lock path must have mode 0600: {}",
                                    path.display()
                                ));
                            }
                        }
                        OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)
                            .map_err(|error| {
                                format!("could not open update lock {}: {error}", path.display())
                            })?
                    }
                    Err(error) => {
                        return Err(format!(
                            "could not create update lock {}: {error}",
                            path.display()
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "could not inspect update lock {}: {error}",
                    path.display()
                ));
            }
        };
        file.try_lock().map_err(|error| {
            format!("could not acquire update lock {}: {error}", path.display())
        })?;
        Ok(Self {
            _path: path,
            _file: file,
        })
    }
}

fn sync_file(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| error.to_string())
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

struct UpdateWorkspace {
    path: PathBuf,
}

impl UpdateWorkspace {
    fn create(parent: &Path) -> Result<Self, String> {
        for _ in 0..16 {
            let mut entropy = [0_u8; 8];
            getrandom::fill(&mut entropy).map_err(|error| error.to_string())?;
            let suffix = crate::encode_lower_hex(&entropy);
            let path = parent.join(format!(".unpin-update-{suffix}"));
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            let mut builder = builder;
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => {
                    let workspace = Self { path };
                    return Ok(workspace);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Err("could not allocate update workspace".to_string())
    }
}

impl Drop for UpdateWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_parser_captures_api_digest() {
        let digest = "a".repeat(64);
        let release = json!({
            "draft": false,
            "prerelease": false,
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            "assets": [{
                "name": "SHA256SUMS",
                "browser_download_url": "https://github.com/IgorArkhipov/unpin/releases/download/v1.1.0/SHA256SUMS",
                "digest": format!("sha256:{digest}"),
                "size": 100
            }]
        });
        let parsed =
            parse_latest_release(&serde_json::to_vec(&release).expect("json")).expect("release");
        assert_eq!(parsed.tag_name, "v1.1.0");
        assert_eq!(
            parsed.assets["SHA256SUMS"].digest.as_deref(),
            Some(digest.as_str())
        );
    }

    #[test]
    fn release_parser_accepts_assets_without_api_digest() {
        let release = json!({
            "draft": false,
            "prerelease": false,
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            "assets": [{
                "name": "SHA256SUMS",
                "browser_download_url": "https://github.com/IgorArkhipov/unpin/releases/download/v1.1.0/SHA256SUMS",
                "digest": null,
                "size": 100
            }]
        });
        let parsed = parse_latest_release(&serde_json::to_vec(&release).expect("json"))
            .expect("release without API digest");

        assert!(parsed.assets["SHA256SUMS"].digest.is_none());
    }

    #[test]
    fn release_parser_rejects_untrusted_download_hosts() {
        let release = json!({
            "draft": false,
            "prerelease": false,
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            "assets": [{
                "name": "SHA256SUMS",
                "browser_download_url": "https://example.com/SHA256SUMS",
                "digest": format!("sha256:{}", "a".repeat(64)),
                "size": 100
            }]
        });
        assert!(parse_latest_release(&serde_json::to_vec(&release).expect("json")).is_err());
    }

    #[test]
    fn release_parser_rejects_cross_repository_urls() {
        let release = json!({
            "draft": false,
            "prerelease": false,
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/attacker/unpin/releases/tag/v1.1.0",
            "assets": []
        });
        assert!(parse_latest_release(&serde_json::to_vec(&release).expect("json")).is_err());

        let release = json!({
            "draft": false,
            "prerelease": false,
            "tag_name": "v1.1.0",
            "html_url": "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0",
            "assets": [{
                "name": "SHA256SUMS",
                "browser_download_url": "https://github.com/attacker/unpin/releases/download/v1.1.0/SHA256SUMS",
                "digest": format!("sha256:{}", "a".repeat(64)),
                "size": 100
            }]
        });
        assert!(parse_latest_release(&serde_json::to_vec(&release).expect("json")).is_err());
    }

    #[test]
    fn missing_api_assets_are_not_synthesized_from_release_urls() {
        let release = LatestRelease {
            tag_name: "v1.1.0".to_string(),
            release_url: "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0".to_string(),
            assets: BTreeMap::new(),
        };
        assert!(release_asset(&release, "unpin-v1.1.0-aarch64-apple-darwin.tar.gz").is_err());
    }

    #[test]
    fn api_release_does_not_synthesize_missing_assets() {
        let release = LatestRelease {
            tag_name: "v1.1.0".to_string(),
            release_url: "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0".to_string(),
            assets: BTreeMap::new(),
        };

        let error = release_asset(&release, CHECKSUM_ASSET_NAME)
            .expect_err("API metadata must list every required asset");

        assert!(error.contains("latest release asset is missing"));
    }

    #[test]
    fn release_discovery_uses_the_exact_repository_api() {
        assert_eq!(
            latest_release_api_url(),
            "https://api.github.com/repos/IgorArkhipov/unpin/releases/latest"
        );
    }

    #[test]
    fn app_bundle_inference_uses_nearest_app_ancestor() {
        let executable = Path::new("/Applications/UnpinDesktop.app/Contents/MacOS/unpin");
        assert_eq!(
            infer_app_bundle(executable).expect("bundle"),
            Path::new("/Applications/UnpinDesktop.app")
        );
    }

    #[cfg(unix)]
    #[test]
    fn installed_cli_version_comes_from_selected_executable() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let executable = temporary.path().join("selected-unpin");
        fs::write(&executable, b"#!/bin/sh\nprintf 'unpin 9.8.7\\n'\n")
            .expect("selected executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("selected executable mode");

        assert_eq!(
            resolve_installed_version(UpdateTarget::Cli, &executable).expect("installed version"),
            ReleaseVersion::parse("9.8.7").expect("version")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn installed_desktop_version_comes_from_bundle_info_plist() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let bundle = temporary.path().join("UnpinDesktop.app");
        fs::create_dir_all(bundle.join("Contents")).expect("bundle contents");
        fs::write(
            bundle.join("Contents/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>9.8.7</string></dict></plist>
"#,
        )
        .expect("Info.plist");

        assert_eq!(
            resolve_installed_version(UpdateTarget::Desktop, &bundle)
                .expect("installed desktop version"),
            ReleaseVersion::parse("9.8.7").expect("version")
        );
    }

    #[cfg(unix)]
    #[test]
    fn cli_install_atomically_replaces_preverified_candidate() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        let candidate = temporary.path().join("candidate");
        fs::write(&install_path, b"old").expect("installed binary");
        fs::write(&candidate, b"#!/bin/sh\nprintf 'unpin 1.1.0\\n'\n").expect("candidate binary");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
            .expect("candidate executable mode");

        let workspace = temporary.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace");
        let installed_fingerprint = fingerprint_path(&install_path).expect("installed fingerprint");
        let candidate_fingerprint = fingerprint_path(&candidate).expect("candidate fingerprint");
        let backup = install_candidate(
            &candidate,
            &install_path,
            &ReleaseVersion::parse("1.0.2").expect("version"),
            UpdateTarget::Cli,
            &installed_fingerprint,
            &candidate_fingerprint,
            &workspace,
        )
        .expect("CLI install");

        assert!(!candidate.exists());
        assert_eq!(
            fs::read_to_string(&install_path).expect("installed candidate"),
            "#!/bin/sh\nprintf 'unpin 1.1.0\\n'\n"
        );
        assert_eq!(fs::read(&backup).expect("rollback backup"), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn durability_failure_after_swap_restores_previous_install() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        let candidate = temporary.path().join("candidate");
        let workspace = temporary.path().join("workspace");
        fs::write(&install_path, b"old").expect("installed binary");
        fs::write(&candidate, b"new").expect("candidate binary");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
            .expect("candidate executable mode");
        fs::create_dir(&workspace).expect("workspace");

        let installed_fingerprint = fingerprint_path(&install_path).expect("installed fingerprint");
        let candidate_fingerprint = fingerprint_path(&candidate).expect("candidate fingerprint");
        let error = install_candidate_with_sync(
            &candidate,
            &install_path,
            &ReleaseVersion::parse("1.0.2").expect("version"),
            UpdateTarget::Cli,
            InstallFingerprints {
                installed: &installed_fingerprint,
                candidate: &candidate_fingerprint,
            },
            &workspace,
            |path| {
                if path == install_path.as_path() {
                    Err("injected installed durability failure".to_string())
                } else {
                    sync_tree(path)
                }
            },
        )
        .expect_err("installed durability failure must roll back");

        assert!(error.contains("update durability sync failed"), "{error}");
        assert!(
            error.contains("previous installation was restored"),
            "{error}"
        );
        assert_eq!(fs::read(&install_path).expect("restored install"), b"old");
        assert!(!temporary.path().join(".unpin.unpin-backup-1.0.2").exists());
        assert_eq!(
            fs::read(workspace.join("failed-install")).expect("displaced candidate"),
            b"new"
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_failure_after_swap_restores_previous_install() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        let candidate = temporary.path().join("candidate");
        let workspace = temporary.path().join("workspace");
        fs::write(&install_path, b"old").expect("installed binary");
        fs::write(&candidate, b"new").expect("candidate binary");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
            .expect("candidate executable mode");
        fs::create_dir(&workspace).expect("workspace");

        let installed_fingerprint = fingerprint_path(&install_path).expect("installed fingerprint");
        let candidate_fingerprint = fingerprint_path(&candidate).expect("candidate fingerprint");
        let backup = install_candidate(
            &candidate,
            &install_path,
            &ReleaseVersion::parse("1.0.2").expect("version"),
            UpdateTarget::Cli,
            &installed_fingerprint,
            &candidate_fingerprint,
            &workspace,
        )
        .expect("candidate install");
        fs::create_dir(temporary.path().join(".unpin.unpin-update-audit.jsonl"))
            .expect("audit path collision");
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("update plan");

        let error = write_update_audit_or_rollback(
            &install_path,
            &backup,
            &plan,
            &candidate_fingerprint,
            &workspace,
        )
        .expect_err("audit failure must roll back");

        assert!(error.contains("update audit failed"), "{error}");
        assert!(
            error.contains("previous installation was restored"),
            "{error}"
        );
        assert_eq!(fs::read(&install_path).expect("restored install"), b"old");
        assert!(!backup.exists());
        assert_eq!(
            fs::read(workspace.join("failed-install")).expect("displaced candidate"),
            b"new"
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_version_output_is_bounded() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let candidate = temporary.path().join("candidate");
        fs::write(&candidate, b"#!/bin/sh\n/usr/bin/head -c 8192 /dev/zero\n")
            .expect("candidate binary");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
            .expect("candidate executable mode");

        let error = verify_executable_version(
            &candidate,
            &ReleaseVersion::parse("1.1.0").expect("version"),
        )
        .expect_err("oversized version output must fail");

        assert!(error.contains("output exceeds size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn combined_process_output_is_bounded() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/usr/bin/head -c 8192 /dev/zero >&2"]);
        let error = bounded_output(&mut command, MAX_VERSION_OUTPUT_BYTES, "combined output")
            .expect_err("oversized stderr must fail");
        assert!(error.contains("output exceeds size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn candidate_process_has_a_wall_clock_deadline() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "exec /bin/sleep 5"]);
        let started = Instant::now();
        let error = bounded_stdout_with_timeout(
            &mut command,
            MAX_VERSION_OUTPUT_BYTES,
            "candidate version",
            Duration::from_millis(100),
        )
        .expect_err("hung candidate must time out");
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn descendant_holding_pipes_cannot_extend_process_deadline() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let pid_path = temporary.path().join("descendant.pid");
        let script = format!(
            "sleep 5 & child=$!; printf '%s' \"$child\" > '{}'; exit 0",
            pid_path.display()
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &script]);
        let started = Instant::now();
        let error = bounded_output_with_timeout(
            &mut command,
            MAX_VERSION_OUTPUT_BYTES,
            "descendant output",
            Duration::from_millis(100),
        )
        .expect_err("descendant-held pipes must time out");
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));

        let pid = fs::read_to_string(&pid_path).expect("descendant pid");
        let status = Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .status()
            .expect("probe descendant");
        assert!(!status.success(), "descendant process survived timeout");
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_installed_state_drift() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        let candidate = temporary.path().join("candidate");
        let workspace = temporary.path().join("workspace");
        fs::write(&install_path, b"old").expect("installed binary");
        fs::write(&candidate, b"#!/bin/sh\nprintf 'unpin 1.1.0\\n'\n").expect("candidate binary");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
            .expect("candidate executable mode");
        fs::create_dir(&workspace).expect("workspace");
        let installed_fingerprint = fingerprint_path(&install_path).expect("installed fingerprint");
        let candidate_fingerprint = fingerprint_path(&candidate).expect("candidate fingerprint");
        fs::write(&install_path, b"changed elsewhere").expect("drifted installation");

        let error = install_candidate(
            &candidate,
            &install_path,
            &ReleaseVersion::parse("1.0.2").expect("version"),
            UpdateTarget::Cli,
            &installed_fingerprint,
            &candidate_fingerprint,
            &workspace,
        )
        .expect_err("drift must block replacement");

        assert!(error.contains("changed after the update began"));
        assert_eq!(
            fs::read(&install_path).expect("drift remains"),
            b"changed elsewhere"
        );
        assert!(candidate.exists());
    }

    #[test]
    fn update_lock_is_exclusive_and_released() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        fs::write(&install_path, b"installed").expect("installed binary");
        let lock_path = temporary.path().join(".unpin.unpin-update.lock");
        let first = UpdateLock::acquire(&install_path).expect("first lock");
        assert!(lock_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&lock_path)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(UpdateLock::acquire(&install_path).is_err());
        drop(first);
        assert!(lock_path.is_file(), "lock file persists after release");
        let second = UpdateLock::acquire(&install_path).expect("released lock can be reacquired");
        drop(second);
        assert!(lock_path.is_file(), "lock file remains durable");
    }

    #[cfg(unix)]
    #[test]
    fn update_lock_rejects_symlink_path() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("unpin");
        let target = temporary.path().join("target");
        let lock_path = temporary.path().join(".unpin.unpin-update.lock");
        fs::write(&install_path, b"installed").expect("installed binary");
        fs::write(&target, b"sentinel").expect("symlink target");
        std::os::unix::fs::symlink(&target, &lock_path).expect("lock symlink");

        let error = UpdateLock::acquire(&install_path).expect_err("symlink lock must fail");
        assert!(error.contains("symbolic link"));
        assert_eq!(
            fs::read(&target).expect("symlink target contents"),
            b"sentinel"
        );
    }

    #[test]
    fn desktop_install_keeps_versioned_rollback_bundle() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let install_path = temporary.path().join("UnpinDesktop.app");
        let candidate = temporary.path().join("candidate.app");
        fs::create_dir(&install_path).expect("installed app");
        fs::create_dir(&candidate).expect("candidate app");
        fs::write(install_path.join("marker"), b"old").expect("old marker");
        fs::write(candidate.join("marker"), b"new").expect("new marker");

        let workspace = temporary.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace");
        let installed_fingerprint = fingerprint_path(&install_path).expect("installed fingerprint");
        let candidate_fingerprint = fingerprint_path(&candidate).expect("candidate fingerprint");
        let backup = install_candidate(
            &candidate,
            &install_path,
            &ReleaseVersion::parse("1.0.2").expect("version"),
            UpdateTarget::Desktop,
            &installed_fingerprint,
            &candidate_fingerprint,
            &workspace,
        )
        .expect("desktop install");

        assert_eq!(
            backup,
            temporary
                .path()
                .join(".UnpinDesktop.app.unpin-backup-1.0.2")
        );
        assert_eq!(
            fs::read(install_path.join("marker")).expect("new app"),
            b"new"
        );
        assert_eq!(fs::read(backup.join("marker")).expect("old app"), b"old");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn candidate_requirement_must_keep_exact_identifier_and_designated_requirement() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let installed = temporary.path().join("installed");
        let matching = temporary.path().join("matching");
        let wrong_identifier = temporary.path().join("wrong-identifier");
        let changed_requirement = temporary.path().join("changed-requirement");
        let source = std::env::current_exe().expect("current test executable");
        for path in [&installed, &matching, &wrong_identifier] {
            fs::copy(&source, path).expect("copy test executable");
        }
        fs::copy("/usr/bin/true", &changed_requirement).expect("copy different executable");
        sign_ad_hoc(&installed, "dev.unpin.cli");
        sign_ad_hoc(&matching, "dev.unpin.cli");
        sign_ad_hoc(&wrong_identifier, "dev.unpin.other");
        sign_ad_hoc(&changed_requirement, "dev.unpin.cli");

        verify_matching_code_requirement(
            &installed,
            &matching,
            CodeSignatureScope::Executable,
            "dev.unpin.cli",
        )
        .expect("matching designated requirement");
        let error = verify_matching_code_requirement(
            &installed,
            &wrong_identifier,
            CodeSignatureScope::Executable,
            "dev.unpin.cli",
        )
        .expect_err("changed identifier must fail");
        assert!(error.contains("identifier changed"));
        let error = verify_matching_code_requirement(
            &installed,
            &changed_requirement,
            CodeSignatureScope::Executable,
            "dev.unpin.cli",
        )
        .expect_err("changed designated requirement must fail");
        assert!(error.contains("Keychain Always Allow would not persist"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn desktop_bridge_manifest_rejects_incompatible_protocol() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let bridge = temporary.path().join("unpin");
        let manifest = temporary.path().join("unpin-bridge-manifest.json");
        fs::write(&bridge, b"bridge").expect("bridge executable");
        fs::write(
            &manifest,
            serde_json::to_vec(&json!({
                "bridgeProtocolVersion": DESKTOP_BRIDGE_PROTOCOL_VERSION + 1,
                "unpinVersion": "1.1.0",
                "sha256": crate::update::sha256_file(&bridge).expect("bridge digest")
            }))
            .expect("manifest JSON"),
        )
        .expect("bridge manifest");

        let error = verify_desktop_bridge_manifest(
            &manifest,
            &bridge,
            &ReleaseVersion::parse("1.1.0").expect("version"),
        )
        .expect_err("incompatible bridge protocol must fail");

        assert!(error.contains("bridge protocol is incompatible"));
    }

    #[cfg(target_os = "macos")]
    fn sign_ad_hoc(path: &Path, identifier: &str) {
        let status = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--identifier",
                identifier,
                "--timestamp=none",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("codesign test executable");
        assert!(status.success());
    }
}
