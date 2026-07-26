use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::{
    BACKUP_AUTHENTICATION_ALGORITHM, BACKUP_MANIFEST_VERSION, BackupAuthenticity, BackupManifest,
    BackupPayloadDigest, backup_payload_path, decode_hex, encode_hex,
    validate_backup_payload_evidence,
};

const BACKUP_MANIFEST_AUTHENTICATION_PURPOSE: &[u8] = b"unpin-backup-manifest-authentication-v3\0";

pub struct BackupAuthenticationKey([u8; 32]);

impl BackupAuthenticationKey {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "backup authentication key must be exactly 32 bytes".to_string())?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn key_id(&self) -> String {
        let digest = Sha256::digest(self.as_bytes());
        format!("sha256:{}", encode_hex(&digest[..8]))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn authenticate_purpose(
        &self,
        purpose: &[u8],
        payload: &[u8],
    ) -> Result<String, String> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.as_bytes())
            .map_err(|error| error.to_string())?;
        mac.update(purpose);
        mac.update(payload);
        Ok(encode_hex(&mac.finalize().into_bytes()))
    }

    pub(crate) fn verify_purpose(
        &self,
        purpose: &[u8],
        payload: &[u8],
        tag: &str,
    ) -> Result<(), String> {
        let tag = decode_hex(tag)?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.as_bytes())
            .map_err(|error| error.to_string())?;
        mac.update(purpose);
        mac.update(payload);
        mac.verify_slice(&tag)
            .map_err(|_| "purpose-bound authentication failed".to_string())
    }
}

impl Clone for BackupAuthenticationKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for BackupAuthenticationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupAuthenticationKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

impl Drop for BackupAuthenticationKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) fn write_authenticated_backup_manifest(
    backup_root: &Path,
    manifest: &mut BackupManifest,
    backup_authentication_key: &BackupAuthenticationKey,
) -> Result<(), io::Error> {
    validate_backup_payload_evidence(backup_root, manifest).map_err(io::Error::other)?;
    let payload_digests = calculate_backup_payload_digests(backup_root, manifest)?;
    let post_state_fingerprint = manifest
        .authenticity
        .as_ref()
        .and_then(|authenticity| authenticity.post_state_fingerprint.clone());
    manifest.version = BACKUP_MANIFEST_VERSION;
    manifest.authenticity = Some(BackupAuthenticity {
        algorithm: BACKUP_AUTHENTICATION_ALGORITHM.to_string(),
        key_id: backup_authentication_key.key_id(),
        payload_digests,
        post_state_fingerprint,
        tag: String::new(),
    });

    let message = backup_authentication_message(manifest).map_err(io::Error::other)?;
    let tag = backup_authentication_key
        .authenticate_purpose(BACKUP_MANIFEST_AUTHENTICATION_PURPOSE, &message)
        .map_err(io::Error::other)?;
    manifest
        .authenticity
        .as_mut()
        .expect("authenticity was assigned above")
        .tag = tag;

    write_manifest_atomically(&backup_root.join("manifest.json"), manifest)
}

fn write_manifest_atomically(path: &Path, manifest: &BackupManifest) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("backup manifest path has no parent"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary_path = parent.join(format!(
        ".manifest.json.unpin-{}-{nonce}.tmp",
        process::id()
    ));
    let json = serde_json::to_string_pretty(manifest).map_err(io::Error::other)?;

    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary_path)?;
        file.write_all(json.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        replace_manifest_file(&temporary_path, path)?;
        sync_parent_directory(parent)
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

#[cfg(not(windows))]
fn replace_manifest_file(temporary_path: &Path, path: &Path) -> Result<(), io::Error> {
    fs::rename(temporary_path, path)
}

#[cfg(windows)]
fn replace_manifest_file(temporary_path: &Path, path: &Path) -> Result<(), io::Error> {
    let previous_path = temporary_path.with_extension("previous");
    match fs::rename(path, &previous_path) {
        Ok(()) => {
            if let Err(error) = fs::rename(temporary_path, path) {
                let _ = fs::rename(&previous_path, path);
                return Err(error);
            }
            let _ = fs::remove_file(previous_path);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::rename(temporary_path, path),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), io::Error> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<(), io::Error> {
    Ok(())
}

pub(super) fn verify_backup_authentication(
    backup_root: &Path,
    manifest: &BackupManifest,
    backup_authentication_key: &BackupAuthenticationKey,
) -> Result<(), String> {
    if manifest.version != BACKUP_MANIFEST_VERSION {
        return Err(format!(
            "unsupported backup manifest version: {}",
            manifest.version
        ));
    }
    let authenticity = manifest
        .authenticity
        .as_ref()
        .ok_or_else(|| "backup authenticity is missing".to_string())?;
    if authenticity.key_id != backup_authentication_key.key_id() {
        return Err("backup authentication key does not match manifest".to_string());
    }

    let message = backup_authentication_message(manifest)?;
    backup_authentication_key
        .verify_purpose(
            BACKUP_MANIFEST_AUTHENTICATION_PURPOSE,
            &message,
            &authenticity.tag,
        )
        .map_err(|_| "backup manifest authentication failed".to_string())?;

    let payload_digests = calculate_backup_payload_digests(backup_root, manifest)
        .map_err(|error| error.to_string())?;
    if authenticity.payload_digests != payload_digests {
        return Err("backup payload authentication failed".to_string());
    }
    Ok(())
}

fn backup_authentication_message(manifest: &BackupManifest) -> Result<Vec<u8>, String> {
    let mut signable = manifest.clone();
    signable
        .authenticity
        .as_mut()
        .ok_or_else(|| "backup authenticity is missing".to_string())?
        .tag
        .clear();
    serde_json::to_vec(&signable).map_err(|error| error.to_string())
}

fn calculate_backup_payload_digests(
    backup_root: &Path,
    manifest: &BackupManifest,
) -> Result<Vec<BackupPayloadDigest>, io::Error> {
    let mut digests = Vec::new();
    for entry in manifest.entries.iter().filter(|entry| entry.existed) {
        let payload = entry.payload.as_ref().ok_or_else(|| {
            io::Error::other(format!(
                "backup entry {} payload is missing",
                entry.entry_id
            ))
        })?;
        let payload_path = backup_payload_path(backup_root, payload).map_err(io::Error::other)?;
        digests.push(BackupPayloadDigest {
            entry_id: entry.entry_id.clone(),
            digest: digest_backup_payload(&payload_path)?,
        });
    }
    digests.sort_by(|left, right| left.entry_id.cmp(&right.entry_id));
    Ok(digests)
}

pub(super) fn digest_backup_payload(payload_path: &Path) -> Result<String, io::Error> {
    let mut hasher = Sha256::new();
    digest_backup_payload_node(payload_path, Path::new(""), &mut hasher)?;
    Ok(format!("sha256:{}", encode_hex(&hasher.finalize())))
}

fn digest_backup_payload_node(
    path: &Path,
    relative_path: &Path,
    hasher: &mut Sha256,
) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        hasher.update(b"symlink\0");
        digest_relative_path(hasher, relative_path);
        digest_field(hasher, &native_path_bytes(&fs::read_link(path)?));
        return Ok(());
    }
    if metadata.is_file() {
        hasher.update(b"file\0");
        digest_relative_path(hasher, relative_path);
        hasher.update(metadata.len().to_be_bytes());
        let mut file = File::open(path)?;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        return Ok(());
    }
    if metadata.is_dir() {
        hasher.update(b"directory\0");
        digest_relative_path(hasher, relative_path);
        let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            digest_backup_payload_node(
                &entry.path(),
                &relative_path.join(entry.file_name()),
                hasher,
            )?;
        }
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("backup payload contains a special file: {}", path.display()),
    ))
}

fn digest_relative_path(hasher: &mut Sha256, path: &Path) {
    hasher.update((path.components().count() as u64).to_be_bytes());
    for component in path.components() {
        digest_field(hasher, &native_os_string_bytes(component.as_os_str()));
    }
}

fn digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(unix)]
fn native_os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn native_os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;

    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn native_os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

fn native_path_bytes(path: &Path) -> Vec<u8> {
    native_os_string_bytes(path.as_os_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        ProviderId,
    };
    use crate::mutation::{BackupEntry, BackupPayload, MutationTarget};
    use tempfile::TempDir;

    #[test]
    fn version_three_authentication_vector_stays_stable_and_rejects_version_two() {
        let app_state = TempDir::new().expect("temp app state");
        let backup_root = app_state.path().join("backups/backup-vector");
        let payload_path = backup_root.join("entries/entry-1/payload");
        fs::create_dir_all(payload_path.parent().expect("payload parent"))
            .expect("create payload parent");
        fs::write(&payload_path, b"backup\n").expect("write payload");
        let target = MutationTarget {
            target_type: "path".to_string(),
            path: "/tmp/unpin-target".to_string(),
        };
        let mut manifest = BackupManifest {
            version: BACKUP_MANIFEST_VERSION,
            backup_id: "backup-vector".to_string(),
            created_at: "2026-07-14T12:00:00Z".to_string(),
            selection: DiscoveryItem {
                provider: ProviderId::Claude,
                kind: DiscoveryKind::Skill,
                category: DiscoveryCategory::Skill,
                layer: DiscoveryLayer::Project,
                id: "claude:project:skill:vector".to_string(),
                display_name: "vector".to_string(),
                enabled: true,
                mutability: DiscoveryMutability::ReadWrite,
                source_path: "/tmp/unpin-source".to_string(),
                state_path: "/tmp/unpin-target".to_string(),
                source_fingerprint: Some("sha256:fixture".to_string()),
                hook: None,
            },
            target_enabled: false,
            affected_targets: vec![target.clone()],
            entries: vec![BackupEntry {
                entry_id: "entry-1".to_string(),
                target,
                existed: true,
                path_kind: Some("file".to_string()),
                payload: Some(BackupPayload {
                    storage: "path".to_string(),
                    path: "entries/entry-1/payload".to_string(),
                }),
            }],
            authenticity: None,
        };

        let key = BackupAuthenticationKey::new([0x42; 32]);
        write_authenticated_backup_manifest(&backup_root, &mut manifest, &key)
            .expect("write authenticated manifest");
        verify_backup_authentication(&backup_root, &manifest, &key)
            .expect("verify purpose-bound manifest");
        let mut legacy = manifest.clone();
        legacy.version = 2;
        let legacy_authenticity = legacy.authenticity.as_mut().expect("backup authenticity");
        legacy_authenticity.algorithm = "hmac-sha256".to_string();
        legacy_authenticity.tag.clear();
        let legacy_message = backup_authentication_message(&legacy).expect("legacy message");
        let mut legacy_mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes()).unwrap();
        legacy_mac.update(&legacy_message);
        legacy.authenticity.as_mut().unwrap().tag = encode_hex(&legacy_mac.finalize().into_bytes());
        assert_eq!(
            verify_backup_authentication(&backup_root, &legacy, &key),
            Err("unsupported backup manifest version: 2".to_string())
        );

        let authenticity = manifest.authenticity.as_ref().expect("backup authenticity");

        assert_eq!(authenticity.key_id, "sha256:425ed4e4a36b30ea");
        assert_eq!(
            authenticity.payload_digests,
            vec![BackupPayloadDigest {
                entry_id: "entry-1".to_string(),
                digest: "sha256:30c4524483d6a4f2c728bd24fde1ceaf8942a50887735e61cb58a31b1781d975"
                    .to_string(),
            }]
        );
        assert_eq!(
            authenticity.tag,
            "1374fcb5c50b5eec9e844b5f1e07c364958f54b53b1d857f9b56ccabcdd40f52"
        );
    }
}
