use std::{
    fmt,
    fs::{self, File},
    io::{self, BufReader, Read},
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

const MAX_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;

pub type UpdateResult<T> = Result<T, UpdateError>;

#[derive(Debug)]
pub enum UpdateError {
    InvalidVersion(String),
    UnsupportedPlatform,
    UpdateNotAvailable,
    InvalidChecksumManifest,
    MissingChecksum(String),
    ChecksumMismatch(String),
    UnsafeArchive(String),
    MissingCandidate(PathBuf),
    Io(io::Error),
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion(version) => {
                write!(formatter, "invalid release version: {version}")
            }
            Self::UnsupportedPlatform => {
                formatter.write_str("updates are unavailable on this platform")
            }
            Self::UpdateNotAvailable => formatter.write_str("no newer stable release is available"),
            Self::InvalidChecksumManifest => {
                formatter.write_str("release checksum manifest is invalid")
            }
            Self::MissingChecksum(name) => {
                write!(formatter, "release checksum is missing for {name}")
            }
            Self::ChecksumMismatch(name) => {
                write!(formatter, "release checksum mismatch for {name}")
            }
            Self::UnsafeArchive(reason) => write!(formatter, "release archive is unsafe: {reason}"),
            Self::MissingCandidate(path) => {
                write!(
                    formatter,
                    "release archive did not contain {}",
                    path.display()
                )
            }
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for UpdateError {}

impl From<io::Error> for UpdateError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateTarget {
    Cli,
    Desktop,
}

impl UpdateTarget {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Desktop => "desktop",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePlatform {
    MacOsArm64,
    MacOsX86_64,
    LinuxX86_64,
}

impl UpdatePlatform {
    pub fn current() -> UpdateResult<Self> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Ok(Self::MacOsArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Ok(Self::MacOsX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Ok(Self::LinuxX86_64)
        } else {
            Err(UpdateError::UnsupportedPlatform)
        }
    }

    #[must_use]
    pub const fn target_triple(self) -> &'static str {
        match self {
            Self::MacOsArm64 => "aarch64-apple-darwin",
            Self::MacOsX86_64 => "x86_64-apple-darwin",
            Self::LinuxX86_64 => "x86_64-unknown-linux-gnu",
        }
    }

    #[must_use]
    pub const fn supports(self, target: UpdateTarget) -> bool {
        !matches!((self, target), (Self::LinuxX86_64, UpdateTarget::Desktop))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl ReleaseVersion {
    pub fn parse(input: &str) -> UpdateResult<Self> {
        let version = input.strip_prefix('v').unwrap_or(input);
        let mut parts = version.split('.');
        let Some(major) = parts.next() else {
            return Err(UpdateError::InvalidVersion(input.to_string()));
        };
        let Some(minor) = parts.next() else {
            return Err(UpdateError::InvalidVersion(input.to_string()));
        };
        let Some(patch) = parts.next() else {
            return Err(UpdateError::InvalidVersion(input.to_string()));
        };
        if parts.next().is_some()
            || [major, minor, patch].iter().any(|part| {
                part.is_empty()
                    || (part.len() > 1 && part.starts_with('0'))
                    || !part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(UpdateError::InvalidVersion(input.to_string()));
        }
        Ok(Self {
            major: major
                .parse()
                .map_err(|_| UpdateError::InvalidVersion(input.to_string()))?,
            minor: minor
                .parse()
                .map_err(|_| UpdateError::InvalidVersion(input.to_string()))?,
            patch: patch
                .parse()
                .map_err(|_| UpdateError::InvalidVersion(input.to_string()))?,
        })
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub current_version: ReleaseVersion,
    pub latest_version: ReleaseVersion,
    pub target: UpdateTarget,
    pub platform: UpdatePlatform,
    pub archive_name: String,
    archive_root: String,
    candidate_relative_path: PathBuf,
    companion_relative_path: Option<PathBuf>,
}

impl UpdatePlan {
    pub(crate) fn new(
        current_version: &str,
        latest_tag: &str,
        target: UpdateTarget,
        platform: UpdatePlatform,
    ) -> UpdateResult<Self> {
        if !platform.supports(target) {
            return Err(UpdateError::UnsupportedPlatform);
        }
        let current_version = ReleaseVersion::parse(current_version)?;
        let latest_version = ReleaseVersion::parse(latest_tag)?;
        if latest_version <= current_version {
            return Err(UpdateError::UpdateNotAvailable);
        }
        let prefix = match target {
            UpdateTarget::Cli => "unpin",
            UpdateTarget::Desktop => "unpin-desktop",
        };
        let archive_root = format!("{prefix}-v{latest_version}-{}", platform.target_triple());
        let candidate_relative_path = match target {
            UpdateTarget::Cli => PathBuf::from(&archive_root).join("unpin"),
            UpdateTarget::Desktop => PathBuf::from(&archive_root).join("UnpinDesktop.app"),
        };
        let companion_relative_path = match target {
            UpdateTarget::Cli => Some(PathBuf::from(&archive_root).join("unpin-credential-broker")),
            UpdateTarget::Desktop => None,
        };
        Ok(Self {
            current_version,
            latest_version,
            target,
            platform,
            archive_name: format!("{archive_root}.tar.gz"),
            archive_root,
            candidate_relative_path,
            companion_relative_path,
        })
    }

    #[must_use]
    pub(crate) fn companion_relative_path(&self) -> Option<&Path> {
        self.companion_relative_path.as_deref()
    }
}

pub(crate) fn sha256_file(path: &Path) -> UpdateResult<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::encode_lower_hex(&hasher.finalize()))
}

pub(crate) fn verify_file_digest(path: &Path, expected: &str, name: &str) -> UpdateResult<()> {
    if !crate::is_lower_hex_digest(expected) || sha256_file(path)? != expected {
        return Err(UpdateError::ChecksumMismatch(name.to_string()));
    }
    Ok(())
}

pub(crate) fn checksum_for(manifest: &[u8], asset_name: &str) -> UpdateResult<String> {
    let manifest =
        std::str::from_utf8(manifest).map_err(|_| UpdateError::InvalidChecksumManifest)?;
    let mut result = None;
    for line in manifest.lines() {
        let Some((digest, name)) = line.split_once("  ") else {
            return Err(UpdateError::InvalidChecksumManifest);
        };
        if !crate::is_lower_hex_digest(digest)
            || name.is_empty()
            || Path::new(name).file_name().and_then(|value| value.to_str()) != Some(name)
        {
            return Err(UpdateError::InvalidChecksumManifest);
        }
        if name == asset_name && result.replace(digest.to_string()).is_some() {
            return Err(UpdateError::InvalidChecksumManifest);
        }
    }
    result.ok_or_else(|| UpdateError::MissingChecksum(asset_name.to_string()))
}

pub(crate) fn extract_release_archive(
    archive_path: &Path,
    destination: &Path,
    plan: &UpdatePlan,
) -> UpdateResult<PathBuf> {
    fs::create_dir_all(destination)?;
    let decoder = GzDecoder::new(File::open(archive_path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut entry_count = 0_usize;
    let mut unpacked_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(UpdateError::UnsafeArchive(
                "too many archive entries".to_string(),
            ));
        }
        unpacked_bytes = unpacked_bytes
            .checked_add(entry.size())
            .ok_or_else(|| UpdateError::UnsafeArchive("archive size overflow".to_string()))?;
        if unpacked_bytes > MAX_UNPACKED_BYTES {
            return Err(UpdateError::UnsafeArchive(
                "unpacked archive exceeds size limit".to_string(),
            ));
        }
        let path = entry.path()?.into_owned();
        validate_archive_path(&path, &plan.archive_root)?;
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            return Err(UpdateError::UnsafeArchive(format!(
                "unsupported entry type for {}",
                path.display()
            )));
        }
        if !entry.unpack_in(destination)? {
            return Err(UpdateError::UnsafeArchive(format!(
                "entry escaped destination: {}",
                path.display()
            )));
        }
    }
    let candidate = destination.join(&plan.candidate_relative_path);
    let metadata = fs::symlink_metadata(&candidate)
        .map_err(|_| UpdateError::MissingCandidate(candidate.clone()))?;
    let valid_type = match plan.target {
        UpdateTarget::Cli => metadata.file_type().is_file(),
        UpdateTarget::Desktop => metadata.file_type().is_dir(),
    };
    if !valid_type || metadata.file_type().is_symlink() {
        return Err(UpdateError::MissingCandidate(candidate));
    }
    if let Some(companion_relative_path) = plan.companion_relative_path() {
        let companion = destination.join(companion_relative_path);
        let metadata = fs::symlink_metadata(&companion)
            .map_err(|_| UpdateError::MissingCandidate(companion.clone()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(UpdateError::MissingCandidate(companion));
        }
    }
    Ok(candidate)
}

fn validate_archive_path(path: &Path, expected_root: &str) -> UpdateResult<()> {
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(root)) if root == expected_root => {}
        _ => {
            return Err(UpdateError::UnsafeArchive(format!(
                "unexpected archive root for {}",
                path.display()
            )));
        }
    }
    if components.any(|component| !matches!(component, Component::Normal(_))) {
        return Err(UpdateError::UnsafeArchive(format!(
            "invalid archive path {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use tempfile::TempDir;

    #[test]
    fn release_version_requires_stable_three_part_version() {
        assert_eq!(
            ReleaseVersion::parse("v1.2.3").expect("version"),
            ReleaseVersion {
                major: 1,
                minor: 2,
                patch: 3
            }
        );
        for invalid in ["1.2", "1.2.3-rc.1", "1.2.3.4", "v1.two.3", "v01.2.3"] {
            assert!(ReleaseVersion::parse(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn update_plan_selects_exact_platform_asset() {
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Desktop,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");
        assert_eq!(
            plan.archive_name,
            "unpin-desktop-v1.1.0-aarch64-apple-darwin.tar.gz"
        );
        assert_eq!(
            plan.candidate_relative_path,
            Path::new("unpin-desktop-v1.1.0-aarch64-apple-darwin/UnpinDesktop.app")
        );
        assert!(matches!(
            UpdatePlan::new(
                "1.1.0",
                "v1.1.0",
                UpdateTarget::Cli,
                UpdatePlatform::MacOsArm64
            ),
            Err(UpdateError::UpdateNotAvailable)
        ));
    }

    #[test]
    fn checksum_manifest_requires_one_safe_exact_entry() {
        let digest = "a".repeat(64);
        let manifest = format!("{digest}  unpin-v1.1.0-aarch64-apple-darwin.tar.gz\n");
        assert_eq!(
            checksum_for(
                manifest.as_bytes(),
                "unpin-v1.1.0-aarch64-apple-darwin.tar.gz"
            )
            .expect("checksum"),
            digest
        );
        assert!(checksum_for(format!("{digest}  ../unpin\n").as_bytes(), "unpin").is_err());
        assert!(
            checksum_for(
                format!("{digest}  unpin\n{digest}  unpin\n").as_bytes(),
                "unpin"
            )
            .is_err()
        );
    }

    #[test]
    fn file_digest_verification_rejects_malformed_and_mismatched_digests() {
        let temporary = TempDir::new().expect("temporary directory");
        let path = temporary.path().join("payload");
        fs::write(&path, b"payload").expect("payload");
        let digest = sha256_file(&path).expect("digest");
        verify_file_digest(&path, &digest, "payload").expect("matching digest");

        for expected in ["not-a-digest", &digest[..63], &digest.to_uppercase()] {
            assert!(matches!(
                verify_file_digest(&path, expected, "payload"),
                Err(UpdateError::ChecksumMismatch(name)) if name == "payload"
            ));
        }
        fs::write(&path, b"changed").expect("changed payload");
        assert!(matches!(
            verify_file_digest(&path, &digest, "payload"),
            Err(UpdateError::ChecksumMismatch(name)) if name == "payload"
        ));
    }

    #[test]
    fn archive_paths_must_remain_under_exact_release_root() {
        assert!(validate_archive_path(Path::new("release/unpin"), "release").is_ok());
        for unsafe_path in [
            Path::new("../release/unpin"),
            Path::new("release/../unpin"),
            Path::new("other/unpin"),
            Path::new("/release/unpin"),
        ] {
            assert!(validate_archive_path(unsafe_path, "release").is_err());
        }
    }

    #[test]
    fn extractor_accepts_expected_regular_candidate() {
        let temp = TempDir::new().expect("temp");
        let archive_path = temp.path().join("release.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        let bytes = b"candidate";
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "unpin-v1.1.0-aarch64-apple-darwin/unpin",
                bytes.as_slice(),
            )
            .expect("entry");
        let broker_bytes = b"broker candidate";
        let mut broker_header = tar::Header::new_gnu();
        broker_header.set_size(broker_bytes.len() as u64);
        broker_header.set_mode(0o755);
        broker_header.set_cksum();
        builder
            .append_data(
                &mut broker_header,
                "unpin-v1.1.0-aarch64-apple-darwin/unpin-credential-broker",
                broker_bytes.as_slice(),
            )
            .expect("broker entry");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");

        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");
        let candidate = extract_release_archive(&archive_path, &temp.path().join("out"), &plan)
            .expect("extract");
        assert_eq!(fs::read(candidate).expect("candidate"), bytes);
    }

    #[test]
    fn extractor_rejects_cli_archive_without_broker_companion() {
        let temp = TempDir::new().expect("temp");
        let archive_path = temp.path().join("release.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        let bytes = b"candidate";
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "unpin-v1.1.0-aarch64-apple-darwin/unpin",
                bytes.as_slice(),
            )
            .expect("entry");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");

        let error = extract_release_archive(&archive_path, &temp.path().join("out"), &plan)
            .expect_err("broker companion is required");

        assert!(matches!(
            error,
            UpdateError::MissingCandidate(path)
                if path.ends_with("unpin-credential-broker")
        ));
    }

    #[test]
    fn extractor_rejects_link_entries() {
        let temp = TempDir::new().expect("temp");
        let archive_path = temp.path().join("release.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("/tmp/escape").expect("link");
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "unpin-v1.1.0-aarch64-apple-darwin/unpin",
                io::empty(),
            )
            .expect("entry");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");

        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");
        assert!(matches!(
            extract_release_archive(&archive_path, &temp.path().join("out"), &plan),
            Err(UpdateError::UnsafeArchive(_))
        ));
    }

    #[test]
    fn extractor_rejects_missing_and_wrong_candidate_types() {
        let temp = TempDir::new().expect("temp");
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");

        let missing_archive = temp.path().join("missing.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&missing_archive).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        builder
            .append_dir(&plan.archive_root, temp.path())
            .expect("root entry");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
        assert!(matches!(
            extract_release_archive(&missing_archive, &temp.path().join("missing-out"), &plan),
            Err(UpdateError::MissingCandidate(_))
        ));

        let wrong_type_archive = temp.path().join("wrong-type.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&wrong_type_archive).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        builder
            .append_dir(format!("{}/unpin", plan.archive_root), temp.path())
            .expect("directory candidate");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
        assert!(matches!(
            extract_release_archive(
                &wrong_type_archive,
                &temp.path().join("wrong-type-out"),
                &plan
            ),
            Err(UpdateError::MissingCandidate(_))
        ));
    }

    #[test]
    fn extractor_rejects_expanded_size_limit_before_unpacking() {
        let temp = TempDir::new().expect("temp");
        let archive_path = temp.path().join("oversized.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_UNPACKED_BYTES + 1);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                "unpin-v1.1.0-aarch64-apple-darwin/unpin",
                io::empty(),
            )
            .expect("oversized header");
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");
        assert!(matches!(
            extract_release_archive(&archive_path, &temp.path().join("out"), &plan),
            Err(UpdateError::UnsafeArchive(reason)) if reason.contains("size limit")
        ));
    }

    #[test]
    fn extractor_rejects_entry_count_limit() {
        let temp = TempDir::new().expect("temp");
        let archive_path = temp.path().join("too-many-entries.tar.gz");
        let encoder = GzEncoder::new(
            File::create(&archive_path).expect("archive"),
            Compression::default(),
        );
        let mut builder = tar::Builder::new(encoder);
        for index in 0..=MAX_ARCHIVE_ENTRIES {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    format!("unpin-v1.1.0-aarch64-apple-darwin/entry-{index}"),
                    io::empty(),
                )
                .expect("entry");
        }
        builder
            .into_inner()
            .expect("encoder")
            .finish()
            .expect("gzip");
        let plan = UpdatePlan::new(
            "1.0.2",
            "v1.1.0",
            UpdateTarget::Cli,
            UpdatePlatform::MacOsArm64,
        )
        .expect("plan");
        assert!(matches!(
            extract_release_archive(&archive_path, &temp.path().join("out"), &plan),
            Err(UpdateError::UnsafeArchive(reason)) if reason.contains("too many archive entries")
        ));
    }
}
