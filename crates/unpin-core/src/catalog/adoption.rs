use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

#[cfg(unix)]
use std::{
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::{get_activation_root, get_catalog_dir, get_transition_journal_path},
    discovery::DiscoveryItem,
    encode_path_segment,
    mutation::BackupAuthenticationKey,
    profiles::CompiledProfileRevision,
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError},
    transitions::{
        AuthenticatedBackup, BackendFailure, EffectActivation, EffectAuthority,
        TRANSITION_JOURNAL_SCHEMA_VERSION, TransitionBackend, TransitionContext, TransitionEffect,
        TransitionEffectKind, TransitionKind, TransitionPlan,
    },
};

use super::{CapabilityId, CapabilityKind, Catalog, CatalogModelError, CatalogRecord};

const COPY_EFFECT_ID: &str = "copy-canonical-content";
const WITHDRAW_EFFECT_ID: &str = "withdraw-native-view";
const RECORD_EFFECT_ID: &str = "record-adopted-view";
const BACKUP_OWNER_SCHEMA_VERSION: u32 = 1;
const BACKUP_MANIFEST_SCHEMA_VERSION: u32 = 1;
const ADOPTION_BACKUP_PURPOSE: &[u8] = b"unpin-adoption-backup-v1\0";
const ADOPTION_MARKER_PURPOSE: &[u8] = b"unpin-adoption-marker-v1\0";
const ADOPTION_RECORD_PURPOSE: &[u8] = b"unpin-adoption-record-v1\0";
#[cfg(unix)]
static MARKER_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct AdoptionRequest {
    pub operation_id: String,
    pub capability_id: String,
    pub capability_kind: CapabilityKind,
    pub provider: ProviderId,
    pub approved_provider_root: PathBuf,
    pub source_path: PathBuf,
    pub app_state_root: PathBuf,
    pub context: TransitionContext,
    pub activation: EffectActivation,
    /// Authenticated catalog metadata used to reconstruct the gateway view.
    /// Generic callers may omit it, but such records cannot back gateway exposure.
    pub catalog_record: Option<CatalogRecord>,
}

#[derive(Debug, Clone)]
pub struct PlannedAdoption {
    pub transition: TransitionPlan,
    spec: AdoptionSpec,
}

impl PlannedAdoption {
    #[must_use]
    pub fn source_path(&self) -> &Path {
        &self.spec.source_path
    }

    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.spec.canonical_path
    }

    #[must_use]
    pub fn source_fingerprint(&self) -> &str {
        &self.spec.source_fingerprint
    }

    #[must_use]
    pub fn activation_record_path(&self) -> &Path {
        &self.spec.activation_path
    }

    #[must_use]
    pub fn backend(&self, key: BackupAuthenticationKey) -> AdoptionBackend {
        AdoptionBackend {
            spec: self.spec.clone(),
            key,
            observer: Arc::new(NoopAdoptionObserver),
        }
    }

    #[must_use]
    pub fn backend_with_observer(
        &self,
        key: BackupAuthenticationKey,
        observer: Arc<dyn AdoptionObserver>,
    ) -> AdoptionBackend {
        AdoptionBackend {
            spec: self.spec.clone(),
            key,
            observer,
        }
    }
}

pub fn plan_adoption(request: AdoptionRequest) -> Result<PlannedAdoption, AdoptionError> {
    if matches!(request.capability_kind, CapabilityKind::Plugin) {
        return Err(AdoptionError::InstalledBundleMustRemainProviderOwned);
    }
    if !matches!(
        request.capability_kind,
        CapabilityKind::Skill | CapabilityKind::Agent
    ) {
        return Err(AdoptionError::UnsupportedCapabilityKind);
    }
    validate_identifier(&request.capability_id)?;
    reject_lexical_traversal(&request.approved_provider_root)?;
    reject_lexical_traversal(&request.source_path)?;
    if !request.approved_provider_root.is_absolute() || !request.source_path.is_absolute() {
        return Err(AdoptionError::AbsolutePathRequired);
    }

    let approved_provider_root = validate_approved_root(&request.approved_provider_root)?;
    let source_path = validate_source_location(&approved_provider_root, &request.source_path)?;
    let source = stable_source_snapshot(&approved_provider_root, &source_path)?;
    if let Some(record) = &request.catalog_record
        && (record.id.as_str() != request.capability_id
            || record.kind != request.capability_kind
            || !record.supports_provider(request.provider)
            || Path::new(&record.origin.source_path) != source_path)
    {
        return Err(AdoptionError::CatalogRecordMismatch);
    }
    ensure_same_filesystem(&source_path, &request.app_state_root)?;
    let canonical_path = get_catalog_dir(&request.app_state_root)
        .join("adopted")
        .join(encode_path_segment(&request.capability_id))
        .join(&source.fingerprint);
    let canonical_resource = resource_id("canonical", &canonical_path);
    let source_resource = resource_id("provider-view", &source_path);
    let activation_path = adoption_record_path(
        &request.app_state_root,
        &request.context.repository_key,
        &request.capability_id,
        &request.operation_id,
    );
    let activation_resource = resource_id("activation-record", &activation_path);
    let activation_fingerprint = activation_logical_fingerprint(
        &request.operation_id,
        &request.capability_id,
        request.provider,
        &source.fingerprint,
        &request.context.repository_key,
        &request.context.workspace_key,
    );

    let transition = TransitionPlan::new(
        request.operation_id.clone(),
        TransitionKind::AdoptCapability,
        request.context,
        vec![
            TransitionEffect {
                effect_id: COPY_EFFECT_ID.to_string(),
                kind: TransitionEffectKind::CopyCanonicalContent,
                resource_id: canonical_resource,
                target_type: "catalog-content".to_string(),
                summary: format!("Adopt {} into canonical catalog", request.capability_id),
                authority: EffectAuthority::UserManaged,
                activation: EffectActivation::NextSessionOnly,
                expected_pre_fingerprint: None,
                expected_post_fingerprint: Some(source.fingerprint.clone()),
                provider_views: vec![request.provider],
            },
            TransitionEffect {
                effect_id: WITHDRAW_EFFECT_ID.to_string(),
                kind: TransitionEffectKind::WithdrawView,
                resource_id: source_resource,
                target_type: "provider-view".to_string(),
                summary: format!("Withdraw managed {} native view", request.capability_id),
                authority: EffectAuthority::UserManaged,
                activation: request.activation,
                expected_pre_fingerprint: Some(source.fingerprint.clone()),
                expected_post_fingerprint: None,
                provider_views: vec![request.provider],
            },
            TransitionEffect {
                effect_id: RECORD_EFFECT_ID.to_string(),
                kind: TransitionEffectKind::PublishView,
                resource_id: activation_resource,
                target_type: "adoption-record".to_string(),
                summary: format!("Record managed {} provider view", request.capability_id),
                authority: EffectAuthority::UserManaged,
                activation: request.activation,
                expected_pre_fingerprint: None,
                expected_post_fingerprint: Some(activation_fingerprint.clone()),
                provider_views: vec![request.provider],
            },
        ],
    )?;
    let spec = AdoptionSpec {
        operation_id: request.operation_id,
        capability_id: request.capability_id,
        provider: request.provider,
        app_state_root: request.app_state_root,
        repository_key: transition.context.repository_key.clone(),
        workspace_key: transition.context.workspace_key.clone(),
        approved_provider_root,
        source_path,
        canonical_path,
        source_fingerprint: source.fingerprint,
        source_identity: source.identity,
        source_kind: source.kind,
        activation: request.activation,
        activation_path,
        activation_fingerprint,
        effect_graph_digest: transition.effect_graph_digest.clone(),
        catalog_record: request.catalog_record,
    };
    Ok(PlannedAdoption { transition, spec })
}

pub fn plan_discovered_adoption(
    item: &DiscoveryItem,
    catalog_record: &CatalogRecord,
    operation_id: impl Into<String>,
    approved_provider_root: impl Into<PathBuf>,
    app_state_root: impl Into<PathBuf>,
    context: TransitionContext,
    activation: EffectActivation,
) -> Result<PlannedAdoption, AdoptionError> {
    if !item.is_catalog_adoption_candidate() {
        return Err(AdoptionError::DiscoveryItemNotAdoptable);
    }
    let capability_kind = match item.kind {
        crate::discovery::DiscoveryKind::Skill => CapabilityKind::Skill,
        crate::discovery::DiscoveryKind::Agent => CapabilityKind::Agent,
        _ => return Err(AdoptionError::DiscoveryItemNotAdoptable),
    };
    let capability_id = catalog_record.id.to_string();
    if catalog_record.kind != capability_kind
        || !catalog_record.provider_views.iter().any(|view| {
            view.provider == item.provider
                && view.discovery_id == item.id
                && view.source_path == item.source_path
        })
    {
        return Err(AdoptionError::CatalogRecordMismatch);
    }
    plan_adoption(AdoptionRequest {
        operation_id: operation_id.into(),
        capability_id,
        capability_kind,
        provider: item.provider,
        approved_provider_root: approved_provider_root.into(),
        source_path: PathBuf::from(&item.source_path),
        app_state_root: app_state_root.into(),
        context,
        activation,
        catalog_record: Some(catalog_record.clone()),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionPhase {
    AfterCanonicalCopy,
    BeforeNativeWithdrawal,
    AfterNativeWithdrawal,
    AfterActivationRecord,
}

pub trait AdoptionObserver: Send + Sync {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError>;
}

struct NoopAdoptionObserver;

impl AdoptionObserver for NoopAdoptionObserver {
    fn observe(&self, _phase: AdoptionPhase) -> Result<(), AdoptionError> {
        Ok(())
    }
}

pub struct AdoptionBackend {
    spec: AdoptionSpec,
    key: BackupAuthenticationKey,
    observer: Arc<dyn AdoptionObserver>,
}

impl TransitionBackend for AdoptionBackend {
    fn current_fingerprint(
        &self,
        effect: &TransitionEffect,
    ) -> Result<Option<String>, BackendFailure> {
        match effect.effect_id.as_str() {
            COPY_EFFECT_ID => self.canonical_fingerprint().map_err(backend_failure),
            WITHDRAW_EFFECT_ID => self.native_fingerprint().map_err(backend_failure),
            RECORD_EFFECT_ID => self.activation_fingerprint().map_err(backend_failure),
            _ => Err(failure("unknown-adoption-effect")),
        }
    }

    fn backup_transition(
        &self,
        plan: &TransitionPlan,
        backup_id: &str,
    ) -> Result<AuthenticatedBackup, BackendFailure> {
        self.create_or_verify_backup(plan, backup_id)
            .map_err(backend_failure)
    }

    fn apply_effect(&self, effect: &TransitionEffect) -> Result<(), BackendFailure> {
        match effect.effect_id.as_str() {
            COPY_EFFECT_ID => self.copy_canonical().map_err(backend_failure),
            WITHDRAW_EFFECT_ID => self.withdraw_native().map_err(backend_failure),
            RECORD_EFFECT_ID => self.record_activation().map_err(backend_failure),
            _ => Err(failure("unknown-adoption-effect")),
        }
    }

    fn rollback_effect(
        &self,
        effect: &TransitionEffect,
        backup_id: &str,
    ) -> Result<(), BackendFailure> {
        match effect.effect_id.as_str() {
            COPY_EFFECT_ID => self.remove_canonical().map_err(backend_failure),
            WITHDRAW_EFFECT_ID => self.restore_native(backup_id).map_err(backend_failure),
            RECORD_EFFECT_ID => self.deactivate_record().map_err(backend_failure),
            _ => Err(failure("unknown-adoption-effect")),
        }
    }
}

impl AdoptionBackend {
    fn canonical_fingerprint(&self) -> Result<Option<String>, AdoptionError> {
        match fs::symlink_metadata(&self.spec.canonical_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(&self.spec.canonical_path, error)),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                Err(AdoptionError::DestinationContested)
            }
            Ok(_) => {
                let marker = match self.read_marker() {
                    Ok(marker) => marker,
                    Err(AdoptionError::Io { .. }) if self.empty_owned_destination()? => {
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                };
                self.verify_marker(&marker)?;
                self.verify_canonical_owner()?;
                if !marker.complete {
                    return Ok(None);
                }
                let fingerprint =
                    snapshot_node(&self.spec.canonical_path.join("content/node"))?.fingerprint;
                if fingerprint != marker.source_fingerprint {
                    return Err(AdoptionError::DestinationContested);
                }
                Ok(Some(fingerprint))
            }
        }
    }

    fn native_fingerprint(&self) -> Result<Option<String>, AdoptionError> {
        match fs::symlink_metadata(&self.spec.source_path) {
            Ok(_) => Ok(Some(
                stable_source_snapshot(&self.spec.approved_provider_root, &self.spec.source_path)?
                    .fingerprint,
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let backup_id = self.current_backup_id()?;
                self.verify_stored_backup(&backup_id)?;
                let retained = self.backup_root(&backup_id).join("retained-original");
                let retained_snapshot = snapshot_node(&retained)?;
                if retained_snapshot.fingerprint != self.spec.source_fingerprint
                    || retained_snapshot.identity != self.spec.source_identity
                {
                    return Err(AdoptionError::RetainedOriginalInvalid);
                }
                Ok(None)
            }
            Err(error) => Err(io_error(&self.spec.source_path, error)),
        }
    }

    fn activation_fingerprint(&self) -> Result<Option<String>, AdoptionError> {
        let Some(snapshot) = self.activation_store().load::<AdoptionRecord>()? else {
            return Ok(None);
        };
        self.verify_activation_record(&snapshot.value)?;
        Ok(snapshot
            .value
            .active
            .then(|| self.spec.activation_fingerprint.clone()))
    }

    fn record_activation(&self) -> Result<(), AdoptionError> {
        let backup_id = self.current_backup_id()?;
        self.verify_stored_backup(&backup_id)?;
        self.ensure_no_other_active_record()?;
        let record = self.activation_record(&backup_id, true)?;
        let store = self.activation_store();
        let owner = backup_state_owner(&self.spec.operation_id)?;
        match store.compare_and_swap(None, owner, &record) {
            Ok(_) => self.observer.observe(AdoptionPhase::AfterActivationRecord),
            Err(StateError::StaleRevision { .. }) => {
                let existing = store
                    .load::<AdoptionRecord>()?
                    .ok_or(AdoptionError::ActivationRecordContested)?;
                self.verify_activation_record(&existing.value)?;
                if existing.value == record {
                    self.observer.observe(AdoptionPhase::AfterActivationRecord)
                } else {
                    Err(AdoptionError::ActivationRecordContested)
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn deactivate_record(&self) -> Result<(), AdoptionError> {
        let store = self.activation_store();
        let Some(snapshot) = store.load::<AdoptionRecord>()? else {
            return Ok(());
        };
        self.verify_activation_record(&snapshot.value)?;
        if !snapshot.value.active {
            return Ok(());
        }
        let mut inactive = snapshot.value;
        inactive.active = false;
        inactive.tag.clear();
        inactive.tag = self
            .key
            .authenticate_purpose(ADOPTION_RECORD_PURPOSE, &record_message(&inactive)?)
            .map_err(AdoptionError::Authentication)?;
        store.compare_and_swap(
            Some(&snapshot.revision),
            backup_state_owner(&self.spec.operation_id)?,
            &inactive,
        )?;
        Ok(())
    }

    fn set_activation_for_backup(
        &self,
        backup_id: &str,
        active: bool,
    ) -> Result<(), AdoptionError> {
        let store = self.activation_store();
        let snapshot = store
            .load::<AdoptionRecord>()?
            .ok_or(AdoptionError::ActivationRecordContested)?;
        self.verify_activation_record(&snapshot.value)?;
        if snapshot.value.backup_id != backup_id {
            return Err(AdoptionError::ActivationRecordContested);
        }
        if snapshot.value.active == active {
            return Ok(());
        }
        if active {
            self.ensure_no_other_active_record()?;
        }
        let updated = self.activation_record(backup_id, active)?;
        store.compare_and_swap(
            Some(&snapshot.revision),
            backup_state_owner(&self.spec.operation_id)?,
            &updated,
        )?;
        Ok(())
    }

    fn activation_store(&self) -> AtomicJsonStore {
        AtomicJsonStore::new(&self.spec.activation_path, 1)
    }

    fn activation_record(
        &self,
        backup_id: &str,
        active: bool,
    ) -> Result<AdoptionRecord, AdoptionError> {
        let mut record = AdoptionRecord {
            version: 1,
            operation_id: self.spec.operation_id.clone(),
            capability_id: self.spec.capability_id.clone(),
            provider: self.spec.provider,
            repository_key: self.spec.repository_key.clone(),
            workspace_key: self.spec.workspace_key.clone(),
            approved_provider_root: self
                .spec
                .approved_provider_root
                .to_string_lossy()
                .into_owned(),
            original_source_path: self.spec.source_path.to_string_lossy().into_owned(),
            canonical_path: self.spec.canonical_path.to_string_lossy().into_owned(),
            backup_id: backup_id.to_string(),
            effect_graph_digest: self.spec.effect_graph_digest.clone(),
            source_fingerprint: self.spec.source_fingerprint.clone(),
            source_identity: self.spec.source_identity.clone(),
            source_kind: self.spec.source_kind,
            activation: self.spec.activation,
            active,
            catalog_record: self.spec.catalog_record.clone(),
            algorithm: "hmac-sha256".to_string(),
            key_id: self.key.key_id(),
            tag: String::new(),
        };
        record.tag = self
            .key
            .authenticate_purpose(ADOPTION_RECORD_PURPOSE, &record_message(&record)?)
            .map_err(AdoptionError::Authentication)?;
        Ok(record)
    }

    fn verify_activation_record(&self, record: &AdoptionRecord) -> Result<(), AdoptionError> {
        verify_record_authentication(record, &self.key)?;
        if record.operation_id != self.spec.operation_id
            || record.capability_id != self.spec.capability_id
            || record.provider != self.spec.provider
            || record.repository_key != self.spec.repository_key
            || record.workspace_key != self.spec.workspace_key
            || Path::new(&record.approved_provider_root) != self.spec.approved_provider_root
            || Path::new(&record.original_source_path) != self.spec.source_path
            || Path::new(&record.canonical_path) != self.spec.canonical_path
            || record.effect_graph_digest != self.spec.effect_graph_digest
            || record.source_fingerprint != self.spec.source_fingerprint
            || record.source_identity != self.spec.source_identity
            || record.source_kind != self.spec.source_kind
            || record.activation != self.spec.activation
            || record.catalog_record != self.spec.catalog_record
        {
            return Err(AdoptionError::ActivationRecordContested);
        }
        Ok(())
    }

    fn ensure_no_other_active_record(&self) -> Result<(), AdoptionError> {
        for record in load_adoption_records(
            &self.spec.app_state_root,
            &self.spec.repository_key,
            &self.spec.capability_id,
            &self.key,
        )? {
            if record.active && record.operation_id != self.spec.operation_id {
                return Err(AdoptionError::DuplicateActiveAdoption);
            }
        }
        Ok(())
    }

    fn create_or_verify_backup(
        &self,
        plan: &TransitionPlan,
        backup_id: &str,
    ) -> Result<AuthenticatedBackup, AdoptionError> {
        if plan.operation_id != self.spec.operation_id
            || plan.effect_graph_digest != self.spec.effect_graph_digest
        {
            return Err(AdoptionError::PlanMismatch);
        }
        let backup_root = self.backup_root(backup_id);
        let owner_store =
            AtomicJsonStore::new(backup_root.join("owner.json"), BACKUP_OWNER_SCHEMA_VERSION);
        let owner_value = BackupOwner {
            operation_id: self.spec.operation_id.clone(),
            effect_graph_digest: self.spec.effect_graph_digest.clone(),
            source_fingerprint: self.spec.source_fingerprint.clone(),
        };
        let state_owner = backup_state_owner(&self.spec.operation_id)?;
        match owner_store.compare_and_swap(None, state_owner.clone(), &owner_value) {
            Ok(_) => {}
            Err(StateError::StaleRevision { .. }) => {
                let existing = owner_store
                    .load::<BackupOwner>()?
                    .ok_or(AdoptionError::BackupContested)?;
                if existing.value != owner_value {
                    return Err(AdoptionError::BackupContested);
                }
            }
            Err(error) => return Err(error.into()),
        }

        let manifest_store = AtomicJsonStore::new(
            backup_root.join("manifest.json"),
            BACKUP_MANIFEST_SCHEMA_VERSION,
        );
        if let Some(existing) = manifest_store.load::<AdoptionBackupManifest>()? {
            self.verify_backup_manifest(backup_id, &existing.value)?;
            return AuthenticatedBackup::new(fingerprint(
                &serde_json::to_vec(&existing.value)
                    .map_err(|error| AdoptionError::Serialization(error.to_string()))?,
            ))
            .map_err(|_| AdoptionError::BackupAuthenticationFailed);
        }

        let current =
            stable_source_snapshot(&self.spec.approved_provider_root, &self.spec.source_path)?;
        if current.fingerprint != self.spec.source_fingerprint
            || current.identity != self.spec.source_identity
        {
            return Err(AdoptionError::SourceChanged);
        }
        let payload = backup_root.join("payload/node");
        if fs::symlink_metadata(backup_root.join("payload")).is_ok() {
            remove_owned_tree(&backup_root.join("payload"))?;
        }
        ensure_private_directory(
            payload
                .parent()
                .ok_or(AdoptionError::DestinationContested)?,
        )?;
        copy_node_durable(&self.spec.source_path, &payload)?;
        let payload_snapshot = snapshot_node(&payload)?;
        if payload_snapshot.fingerprint != self.spec.source_fingerprint {
            return Err(AdoptionError::SourceChanged);
        }
        let mut manifest = AdoptionBackupManifest {
            version: 1,
            backup_id: backup_id.to_string(),
            operation_id: self.spec.operation_id.clone(),
            effect_graph_digest: self.spec.effect_graph_digest.clone(),
            source_fingerprint: self.spec.source_fingerprint.clone(),
            source_identity: self.spec.source_identity.clone(),
            source_kind: self.spec.source_kind,
            payload_fingerprint: payload_snapshot.fingerprint,
            algorithm: "hmac-sha256".to_string(),
            key_id: self.key.key_id(),
            tag: String::new(),
        };
        manifest.tag = self
            .key
            .authenticate_purpose(ADOPTION_BACKUP_PURPOSE, &manifest_message(&manifest)?)
            .map_err(AdoptionError::Authentication)?;
        manifest_store.compare_and_swap(None, state_owner, &manifest)?;
        let manifest_digest = fingerprint(
            &serde_json::to_vec(&manifest)
                .map_err(|error| AdoptionError::Serialization(error.to_string()))?,
        );
        AuthenticatedBackup::new(manifest_digest)
            .map_err(|_| AdoptionError::BackupAuthenticationFailed)
    }

    fn verify_backup_manifest(
        &self,
        backup_id: &str,
        manifest: &AdoptionBackupManifest,
    ) -> Result<(), AdoptionError> {
        if manifest.version != 1
            || manifest.backup_id != backup_id
            || manifest.operation_id != self.spec.operation_id
            || manifest.effect_graph_digest != self.spec.effect_graph_digest
            || manifest.source_fingerprint != self.spec.source_fingerprint
            || manifest.source_identity != self.spec.source_identity
            || manifest.source_kind != self.spec.source_kind
            || manifest.algorithm != "hmac-sha256"
            || manifest.key_id != self.key.key_id()
        {
            return Err(AdoptionError::BackupAuthenticationFailed);
        }
        self.key
            .verify_purpose(
                ADOPTION_BACKUP_PURPOSE,
                &manifest_message(manifest)?,
                &manifest.tag,
            )
            .map_err(AdoptionError::Authentication)?;
        let payload = self.backup_root(backup_id).join("payload/node");
        if snapshot_node(&payload)?.fingerprint != manifest.payload_fingerprint {
            return Err(AdoptionError::BackupAuthenticationFailed);
        }
        Ok(())
    }

    fn copy_canonical(&self) -> Result<(), AdoptionError> {
        let source =
            stable_source_snapshot(&self.spec.approved_provider_root, &self.spec.source_path)?;
        if source.fingerprint != self.spec.source_fingerprint
            || source.identity != self.spec.source_identity
        {
            return Err(AdoptionError::SourceChanged);
        }

        let parent = self
            .spec
            .canonical_path
            .parent()
            .ok_or(AdoptionError::DestinationContested)?;
        ensure_private_directory(parent)?;
        self.create_or_verify_canonical_owner()?;
        match fs::symlink_metadata(&self.spec.canonical_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                create_private_directory(&self.spec.canonical_path)?;
                let marker = self.marker(false)?;
                write_json_atomically(&self.marker_path(), &marker, false)?;
            }
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(AdoptionError::DestinationContested);
            }
            Ok(_) => match self.read_marker() {
                Ok(marker) => {
                    self.verify_marker(&marker)?;
                    if marker.complete {
                        return if self.canonical_fingerprint()?
                            == Some(self.spec.source_fingerprint.clone())
                        {
                            Ok(())
                        } else {
                            Err(AdoptionError::DestinationContested)
                        };
                    }
                }
                Err(AdoptionError::Io { .. }) if self.empty_owned_destination()? => {
                    let marker = self.marker(false)?;
                    write_json_atomically(&self.marker_path(), &marker, false)?;
                }
                Err(error) => return Err(error),
            },
            Err(error) => return Err(io_error(&self.spec.canonical_path, error)),
        }

        let content = self.spec.canonical_path.join("content");
        if fs::symlink_metadata(&content).is_ok() {
            remove_owned_tree(&content)?;
        }
        ensure_private_directory(&content)?;
        copy_node_durable(&self.spec.source_path, &content.join("node"))?;
        if snapshot_node(&content.join("node"))?.fingerprint != self.spec.source_fingerprint {
            return Err(AdoptionError::SourceChanged);
        }
        let source_after =
            stable_source_snapshot(&self.spec.approved_provider_root, &self.spec.source_path)?;
        if source_after.fingerprint != self.spec.source_fingerprint
            || source_after.identity != self.spec.source_identity
        {
            return Err(AdoptionError::SourceChanged);
        }
        write_json_atomically(&self.marker_path(), &self.marker(true)?, true)?;
        sync_directory(&self.spec.canonical_path)?;
        sync_directory(parent)?;
        self.observer.observe(AdoptionPhase::AfterCanonicalCopy)?;
        Ok(())
    }

    fn withdraw_native(&self) -> Result<(), AdoptionError> {
        let backup_id = self.current_backup_id()?;
        self.withdraw_native_with_backup(&backup_id)
    }

    fn withdraw_native_with_backup(&self, backup_id: &str) -> Result<(), AdoptionError> {
        self.observer
            .observe(AdoptionPhase::BeforeNativeWithdrawal)?;
        let source =
            stable_source_snapshot(&self.spec.approved_provider_root, &self.spec.source_path)?;
        if source.fingerprint != self.spec.source_fingerprint
            || source.identity != self.spec.source_identity
        {
            return Err(AdoptionError::SourceChanged);
        }
        if self.canonical_fingerprint()? != Some(self.spec.source_fingerprint.clone()) {
            return Err(AdoptionError::DestinationContested);
        }
        self.verify_stored_backup(backup_id)?;
        let retained = self.backup_root(backup_id).join("retained-original");
        if fs::symlink_metadata(&retained).is_ok() {
            return Err(AdoptionError::RetainedOriginalContested);
        }
        let retained_parent = retained
            .parent()
            .ok_or(AdoptionError::RetainedOriginalContested)?;
        ensure_private_directory(retained_parent)?;
        fs::rename(&self.spec.source_path, &retained)
            .map_err(|error| rename_error(&self.spec.source_path, error))?;
        sync_directory(
            self.spec
                .source_path
                .parent()
                .ok_or(AdoptionError::SourceOutsideApprovedRoot)?,
        )?;
        sync_directory(retained_parent)?;
        let retained_snapshot = snapshot_node(&retained)?;
        if retained_snapshot.identity != self.spec.source_identity
            || retained_snapshot.fingerprint != self.spec.source_fingerprint
        {
            return Err(AdoptionError::RetainedOriginalInvalid);
        }
        self.observer
            .observe(AdoptionPhase::AfterNativeWithdrawal)?;
        Ok(())
    }

    fn restore_native(&self, backup_id: &str) -> Result<(), AdoptionError> {
        self.verify_stored_backup(backup_id)?;
        let retained = self.backup_root(backup_id).join("retained-original");
        if fs::symlink_metadata(&self.spec.source_path).is_ok() {
            return Err(AdoptionError::RestoreTargetContested);
        }
        let snapshot = snapshot_node(&retained)?;
        if snapshot.fingerprint != self.spec.source_fingerprint
            || snapshot.identity != self.spec.source_identity
        {
            return Err(AdoptionError::RetainedOriginalInvalid);
        }
        validate_source_parent(&self.spec.approved_provider_root, &self.spec.source_path)?;
        fs::rename(&retained, &self.spec.source_path)
            .map_err(|error| rename_error(&self.spec.source_path, error))?;
        sync_directory(
            self.spec
                .source_path
                .parent()
                .ok_or(AdoptionError::SourceOutsideApprovedRoot)?,
        )?;
        sync_directory(
            retained
                .parent()
                .ok_or(AdoptionError::RetainedOriginalInvalid)?,
        )?;
        Ok(())
    }

    fn remove_canonical(&self) -> Result<(), AdoptionError> {
        let marker = self.read_marker()?;
        self.verify_marker(&marker)?;
        if !marker.complete
            || self.canonical_fingerprint()? != Some(self.spec.source_fingerprint.clone())
        {
            return Err(AdoptionError::DestinationContested);
        }
        remove_owned_tree(&self.spec.canonical_path)?;
        sync_directory(
            self.spec
                .canonical_path
                .parent()
                .ok_or(AdoptionError::DestinationContested)?,
        )?;
        Ok(())
    }

    fn marker(&self, complete: bool) -> Result<AdoptionMarker, AdoptionError> {
        let mut marker = AdoptionMarker {
            version: 1,
            operation_id: self.spec.operation_id.clone(),
            capability_id: self.spec.capability_id.clone(),
            source_fingerprint: self.spec.source_fingerprint.clone(),
            source_identity: self.spec.source_identity.clone(),
            source_kind: self.spec.source_kind,
            complete,
            algorithm: "hmac-sha256".to_string(),
            key_id: self.key.key_id(),
            tag: String::new(),
        };
        marker.tag = self
            .key
            .authenticate_purpose(ADOPTION_MARKER_PURPOSE, &marker_message(&marker)?)
            .map_err(AdoptionError::Authentication)?;
        Ok(marker)
    }

    fn read_marker(&self) -> Result<AdoptionMarker, AdoptionError> {
        let path = self.marker_path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AdoptionError::DestinationContested);
        }
        let raw = fs::read(&path).map_err(|error| io_error(&path, error))?;
        serde_json::from_slice(&raw).map_err(|_| AdoptionError::DestinationContested)
    }

    fn verify_marker(&self, marker: &AdoptionMarker) -> Result<(), AdoptionError> {
        if marker.version != 1
            || marker.operation_id != self.spec.operation_id
            || marker.capability_id != self.spec.capability_id
            || marker.source_fingerprint != self.spec.source_fingerprint
            || marker.source_identity != self.spec.source_identity
            || marker.source_kind != self.spec.source_kind
            || marker.algorithm != "hmac-sha256"
            || marker.key_id != self.key.key_id()
        {
            return Err(AdoptionError::DestinationContested);
        }
        self.key
            .verify_purpose(
                ADOPTION_MARKER_PURPOSE,
                &marker_message(marker)?,
                &marker.tag,
            )
            .map_err(|_| AdoptionError::DestinationContested)
    }

    fn marker_path(&self) -> PathBuf {
        self.spec.canonical_path.join("adoption.json")
    }

    fn canonical_owner_store(&self) -> AtomicJsonStore {
        let digest = fingerprint(self.spec.operation_id.as_bytes());
        AtomicJsonStore::new(
            self.spec
                .canonical_path
                .parent()
                .expect("canonical path has a parent")
                .join(format!(".adoption-owner-{digest}.json")),
            1,
        )
    }

    fn canonical_owner(&self) -> CanonicalOwner {
        CanonicalOwner {
            operation_id: self.spec.operation_id.clone(),
            capability_id: self.spec.capability_id.clone(),
            source_fingerprint: self.spec.source_fingerprint.clone(),
        }
    }

    fn create_or_verify_canonical_owner(&self) -> Result<(), AdoptionError> {
        let store = self.canonical_owner_store();
        let expected = self.canonical_owner();
        let owner = backup_state_owner(&self.spec.operation_id)?;
        match store.compare_and_swap(None, owner, &expected) {
            Ok(_) => Ok(()),
            Err(StateError::StaleRevision { .. }) => {
                if store
                    .load::<CanonicalOwner>()?
                    .is_some_and(|snapshot| snapshot.value == expected)
                {
                    Ok(())
                } else {
                    Err(AdoptionError::DestinationContested)
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn verify_canonical_owner(&self) -> Result<(), AdoptionError> {
        if self
            .canonical_owner_store()
            .load::<CanonicalOwner>()?
            .is_some_and(|snapshot| snapshot.value == self.canonical_owner())
        {
            Ok(())
        } else {
            Err(AdoptionError::DestinationContested)
        }
    }

    fn empty_owned_destination(&self) -> Result<bool, AdoptionError> {
        let owner = self
            .canonical_owner_store()
            .load::<CanonicalOwner>()?
            .ok_or(AdoptionError::DestinationContested)?;
        if owner.value != self.canonical_owner() {
            return Err(AdoptionError::DestinationContested);
        }
        let mut entries = fs::read_dir(&self.spec.canonical_path)
            .map_err(|error| io_error(&self.spec.canonical_path, error))?;
        Ok(entries.next().is_none())
    }

    fn backup_root(&self, backup_id: &str) -> PathBuf {
        self.spec.app_state_root.join("backups").join(backup_id)
    }

    fn current_backup_id(&self) -> Result<String, AdoptionError> {
        let journal_path =
            get_transition_journal_path(&self.spec.app_state_root, &self.spec.operation_id);
        let snapshot = AtomicJsonStore::new(journal_path, TRANSITION_JOURNAL_SCHEMA_VERSION)
            .load::<serde_json::Value>()?
            .ok_or(AdoptionError::BackupContested)?;
        snapshot
            .value
            .get("backupId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(AdoptionError::BackupContested)
    }

    fn verify_stored_backup(&self, backup_id: &str) -> Result<(), AdoptionError> {
        let owner = AtomicJsonStore::new(
            self.backup_root(backup_id).join("owner.json"),
            BACKUP_OWNER_SCHEMA_VERSION,
        )
        .load::<BackupOwner>()?
        .ok_or(AdoptionError::BackupContested)?;
        if owner.value
            != (BackupOwner {
                operation_id: self.spec.operation_id.clone(),
                effect_graph_digest: self.spec.effect_graph_digest.clone(),
                source_fingerprint: self.spec.source_fingerprint.clone(),
            })
        {
            return Err(AdoptionError::BackupContested);
        }
        let store = AtomicJsonStore::new(
            self.backup_root(backup_id).join("manifest.json"),
            BACKUP_MANIFEST_SCHEMA_VERSION,
        );
        let manifest = store
            .load::<AdoptionBackupManifest>()?
            .ok_or(AdoptionError::BackupContested)?;
        self.verify_backup_manifest(backup_id, &manifest.value)
    }
}

#[derive(Debug, Clone)]
struct AdoptionSpec {
    operation_id: String,
    capability_id: String,
    provider: ProviderId,
    app_state_root: PathBuf,
    repository_key: String,
    workspace_key: String,
    approved_provider_root: PathBuf,
    source_path: PathBuf,
    canonical_path: PathBuf,
    source_fingerprint: String,
    source_identity: FileIdentity,
    source_kind: NodeKind,
    activation: EffectActivation,
    activation_path: PathBuf,
    activation_fingerprint: String,
    effect_graph_digest: String,
    catalog_record: Option<CatalogRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BackupOwner {
    operation_id: String,
    effect_graph_digest: String,
    source_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalOwner {
    operation_id: String,
    capability_id: String,
    source_fingerprint: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdoptionRecord {
    version: u32,
    operation_id: String,
    capability_id: String,
    provider: ProviderId,
    repository_key: String,
    workspace_key: String,
    approved_provider_root: String,
    original_source_path: String,
    canonical_path: String,
    backup_id: String,
    effect_graph_digest: String,
    source_fingerprint: String,
    source_identity: FileIdentity,
    source_kind: NodeKind,
    activation: EffectActivation,
    active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    catalog_record: Option<CatalogRecord>,
    algorithm: String,
    key_id: String,
    tag: String,
}

impl AdoptionRecord {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn repository_key(&self) -> &str {
        &self.repository_key
    }

    #[must_use]
    pub fn workspace_key(&self) -> &str {
        &self.workspace_key
    }

    #[must_use]
    pub fn approved_provider_root(&self) -> &Path {
        Path::new(&self.approved_provider_root)
    }

    #[must_use]
    pub fn original_source_path(&self) -> &Path {
        Path::new(&self.original_source_path)
    }

    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        Path::new(&self.canonical_path)
    }

    #[must_use]
    pub fn backup_id(&self) -> &str {
        &self.backup_id
    }

    #[must_use]
    pub fn effect_graph_digest(&self) -> &str {
        &self.effect_graph_digest
    }

    #[must_use]
    pub fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    #[must_use]
    pub const fn activation(&self) -> EffectActivation {
        self.activation
    }

    #[must_use]
    pub const fn active(&self) -> bool {
        self.active
    }

    #[must_use]
    pub fn catalog_record(&self) -> Option<&CatalogRecord> {
        self.catalog_record.as_ref()
    }

    #[must_use]
    pub fn canonical_content_path(&self) -> PathBuf {
        Path::new(&self.canonical_path).join("content/node")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeViewState {
    Present,
    Withdrawn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeViewTransitionStatus {
    Applied,
    NoOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeViewTransitionOutcome {
    status: NativeViewTransitionStatus,
    state: NativeViewState,
}

impl NativeViewTransitionOutcome {
    #[must_use]
    pub const fn status(self) -> NativeViewTransitionStatus {
        self.status
    }

    #[must_use]
    pub const fn state(self) -> NativeViewState {
        self.state
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionPhysicalResource {
    resource_id: String,
    path: PathBuf,
}

impl AdoptionPhysicalResource {
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub struct AuthenticatedNativeView {
    backend: AdoptionBackend,
    backup_id: String,
    physical_resources: Vec<AdoptionPhysicalResource>,
}

impl AuthenticatedNativeView {
    pub fn new(
        record: AdoptionRecord,
        key: BackupAuthenticationKey,
    ) -> Result<Self, AdoptionViewError> {
        verify_record_authentication(&record, &key)
            .map_err(|_| AdoptionViewError::RecordContested)?;
        let spec = adoption_spec_from_record(&record)?;
        let backup_root = spec.app_state_root.join("backups").join(&record.backup_id);
        let physical_resources = [
            ("provider-view", spec.source_path.clone()),
            ("activation-record", spec.activation_path.clone()),
            ("canonical", spec.canonical_path.clone()),
            ("backup", backup_root),
        ]
        .into_iter()
        .map(|(kind, path)| AdoptionPhysicalResource {
            resource_id: resource_id(kind, &path),
            path,
        })
        .collect();
        let backend = AdoptionBackend {
            spec,
            key,
            observer: Arc::new(NoopAdoptionObserver),
        };
        backend
            .verify_activation_record(&record)
            .map_err(|_| AdoptionViewError::RecordContested)?;
        Ok(Self {
            backend,
            backup_id: record.backup_id,
            physical_resources,
        })
    }

    #[must_use]
    pub fn physical_resources(&self) -> &[AdoptionPhysicalResource] {
        &self.physical_resources
    }

    /// Reconstructs authenticated gateway metadata pointing at immutable
    /// canonical content instead of provider-visible source path.
    pub fn gateway_catalog_record(&self) -> Result<CatalogRecord, AdoptionViewError> {
        self.inspect()?;
        let mut record = self
            .backend
            .spec
            .catalog_record
            .clone()
            .ok_or(AdoptionViewError::GatewayMetadataUnavailable)?;
        if record.id.as_str() != self.backend.spec.capability_id
            || record.kind != CapabilityKind::Skill
            || !record.supports_provider(self.backend.spec.provider)
            || Path::new(&record.origin.source_path) != self.backend.spec.source_path
        {
            return Err(AdoptionViewError::RecordContested);
        }
        let canonical_node = self.backend.spec.canonical_path.join("content/node");
        let node_metadata = fs::symlink_metadata(&canonical_node)
            .map_err(|_| AdoptionViewError::CanonicalContested)?;
        if node_metadata.file_type().is_symlink() {
            return Err(AdoptionViewError::GatewayMetadataUnavailable);
        }
        let canonical_source = if node_metadata.is_file() {
            canonical_node
        } else if node_metadata.is_dir() {
            let skill_file = canonical_node.join("SKILL.md");
            let metadata = fs::symlink_metadata(&skill_file)
                .map_err(|_| AdoptionViewError::GatewayMetadataUnavailable)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(AdoptionViewError::GatewayMetadataUnavailable);
            }
            skill_file
        } else {
            return Err(AdoptionViewError::GatewayMetadataUnavailable);
        };
        record.origin.source_path = canonical_source.to_string_lossy().into_owned();
        Ok(record)
    }

    pub fn inspect(&self) -> Result<NativeViewState, AdoptionViewError> {
        let snapshot = self
            .backend
            .activation_store()
            .load::<AdoptionRecord>()
            .map_err(|_| AdoptionViewError::RecordContested)?
            .ok_or(AdoptionViewError::RecordContested)?;
        self.backend
            .verify_activation_record(&snapshot.value)
            .map_err(|_| AdoptionViewError::RecordContested)?;
        if snapshot.value.backup_id != self.backup_id {
            return Err(AdoptionViewError::RecordContested);
        }
        self.backend
            .verify_stored_backup(&self.backup_id)
            .map_err(|_| AdoptionViewError::BackupContested)?;
        validate_source_location(
            &self.backend.spec.app_state_root,
            &self.backend.spec.canonical_path,
        )
        .map_err(|_| AdoptionViewError::CanonicalContested)?;
        if self
            .backend
            .canonical_fingerprint()
            .map_err(|_| AdoptionViewError::CanonicalContested)?
            != Some(self.backend.spec.source_fingerprint.clone())
        {
            return Err(AdoptionViewError::CanonicalContested);
        }

        let retained = self
            .backend
            .backup_root(&self.backup_id)
            .join("retained-original");
        match fs::symlink_metadata(&self.backend.spec.source_path) {
            Ok(_) => {
                let source = stable_source_snapshot(
                    &self.backend.spec.approved_provider_root,
                    &self.backend.spec.source_path,
                )
                .map_err(|_| AdoptionViewError::NativeViewContested)?;
                let retained_absent = match fs::symlink_metadata(&retained) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => true,
                    Ok(_) | Err(_) => false,
                };
                if source.fingerprint != self.backend.spec.source_fingerprint
                    || source.identity != self.backend.spec.source_identity
                    || !retained_absent
                    || snapshot.value.active
                {
                    return Err(AdoptionViewError::NativeViewContested);
                }
                Ok(NativeViewState::Present)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                validate_source_parent(
                    &self.backend.spec.approved_provider_root,
                    &self.backend.spec.source_path,
                )
                .map_err(|_| AdoptionViewError::NativeViewContested)?;
                let retained_snapshot =
                    snapshot_node(&retained).map_err(|_| AdoptionViewError::BackupContested)?;
                if retained_snapshot.fingerprint != self.backend.spec.source_fingerprint
                    || retained_snapshot.identity != self.backend.spec.source_identity
                {
                    return Err(AdoptionViewError::BackupContested);
                }
                if !snapshot.value.active {
                    return Err(AdoptionViewError::NativeViewContested);
                }
                Ok(NativeViewState::Withdrawn)
            }
            Err(_) => Err(AdoptionViewError::NativeViewContested),
        }
    }

    pub fn transition(
        &self,
        desired: NativeViewState,
    ) -> Result<NativeViewTransitionOutcome, AdoptionViewError> {
        let current = self.inspect()?;
        if current == desired {
            return Ok(NativeViewTransitionOutcome {
                status: NativeViewTransitionStatus::NoOp,
                state: desired,
            });
        }

        match desired {
            NativeViewState::Present => {
                self.backend
                    .restore_native(&self.backup_id)
                    .map_err(map_restore_error)?;
                if self
                    .backend
                    .set_activation_for_backup(&self.backup_id, false)
                    .is_err()
                {
                    if self
                        .backend
                        .withdraw_native_with_backup(&self.backup_id)
                        .is_err()
                    {
                        return Err(AdoptionViewError::TransitionIncomplete);
                    }
                    return Err(AdoptionViewError::RecordContested);
                }
            }
            NativeViewState::Withdrawn => {
                self.backend
                    .withdraw_native_with_backup(&self.backup_id)
                    .map_err(map_withdraw_error)?;
                if self
                    .backend
                    .set_activation_for_backup(&self.backup_id, true)
                    .is_err()
                {
                    if self.backend.restore_native(&self.backup_id).is_err() {
                        return Err(AdoptionViewError::TransitionIncomplete);
                    }
                    return Err(AdoptionViewError::RecordContested);
                }
            }
        }
        if !matches!(self.inspect(), Ok(state) if state == desired) {
            return Err(AdoptionViewError::TransitionIncomplete);
        }
        Ok(NativeViewTransitionOutcome {
            status: NativeViewTransitionStatus::Applied,
            state: desired,
        })
    }
}

fn adoption_spec_from_record(record: &AdoptionRecord) -> Result<AdoptionSpec, AdoptionViewError> {
    if validate_identifier(&record.operation_id).is_err()
        || validate_identifier(&record.capability_id).is_err()
        || validate_identifier(&record.repository_key).is_err()
        || validate_identifier(&record.workspace_key).is_err()
        || !crate::is_lower_hex_digest(&record.source_fingerprint)
        || !crate::is_lower_hex_digest(&record.effect_graph_digest)
        || !valid_path_segment(&record.backup_id)
    {
        return Err(AdoptionViewError::RecordContested);
    }
    let approved_provider_root = PathBuf::from(&record.approved_provider_root);
    let source_path = PathBuf::from(&record.original_source_path);
    let canonical_path = PathBuf::from(&record.canonical_path);
    if !approved_provider_root.is_absolute()
        || !source_path.is_absolute()
        || !canonical_path.is_absolute()
        || reject_lexical_traversal(&approved_provider_root).is_err()
        || reject_lexical_traversal(&source_path).is_err()
        || reject_lexical_traversal(&canonical_path).is_err()
    {
        return Err(AdoptionViewError::RecordContested);
    }
    let validated_root = validate_approved_root(&approved_provider_root)
        .map_err(|_| AdoptionViewError::RecordContested)?;
    if validated_root != approved_provider_root
        || !source_path.starts_with(&approved_provider_root)
        || source_path == approved_provider_root
    {
        return Err(AdoptionViewError::RecordContested);
    }

    let app_state_root = canonical_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(AdoptionViewError::RecordContested)?
        .to_path_buf();
    let expected_canonical = get_catalog_dir(&app_state_root)
        .join("adopted")
        .join(encode_path_segment(&record.capability_id))
        .join(&record.source_fingerprint);
    if app_state_root.as_os_str().is_empty() || canonical_path != expected_canonical {
        return Err(AdoptionViewError::RecordContested);
    }
    let validated_app_state_root =
        validate_approved_root(&app_state_root).map_err(|_| AdoptionViewError::RecordContested)?;
    if validated_app_state_root != app_state_root {
        return Err(AdoptionViewError::RecordContested);
    }
    let activation_path = adoption_record_path(
        &app_state_root,
        &record.repository_key,
        &record.capability_id,
        &record.operation_id,
    );
    Ok(AdoptionSpec {
        operation_id: record.operation_id.clone(),
        capability_id: record.capability_id.clone(),
        provider: record.provider,
        app_state_root,
        repository_key: record.repository_key.clone(),
        workspace_key: record.workspace_key.clone(),
        approved_provider_root,
        source_path,
        canonical_path,
        source_fingerprint: record.source_fingerprint.clone(),
        source_identity: record.source_identity.clone(),
        source_kind: record.source_kind,
        activation: record.activation,
        activation_path,
        activation_fingerprint: activation_logical_fingerprint(
            &record.operation_id,
            &record.capability_id,
            record.provider,
            &record.source_fingerprint,
            &record.repository_key,
            &record.workspace_key,
        ),
        effect_graph_digest: record.effect_graph_digest.clone(),
        catalog_record: record.catalog_record.clone(),
    })
}

fn valid_path_segment(value: &str) -> bool {
    !value.is_empty()
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && Path::new(value).components().count() == 1
}

fn map_restore_error(error: AdoptionError) -> AdoptionViewError {
    match error {
        AdoptionError::BackupContested
        | AdoptionError::BackupAuthenticationFailed
        | AdoptionError::RetainedOriginalContested
        | AdoptionError::RetainedOriginalInvalid
        | AdoptionError::Authentication(_) => AdoptionViewError::BackupContested,
        AdoptionError::RestoreTargetContested
        | AdoptionError::SourceOutsideApprovedRoot
        | AdoptionError::SymlinkRejected(_)
        | AdoptionError::HardLinkAmbiguous(_)
        | AdoptionError::SpecialFileRejected(_) => AdoptionViewError::NativeViewContested,
        _ => AdoptionViewError::TransitionIncomplete,
    }
}

fn map_withdraw_error(error: AdoptionError) -> AdoptionViewError {
    match error {
        AdoptionError::DestinationContested => AdoptionViewError::CanonicalContested,
        AdoptionError::BackupContested
        | AdoptionError::BackupAuthenticationFailed
        | AdoptionError::RetainedOriginalContested
        | AdoptionError::RetainedOriginalInvalid => AdoptionViewError::BackupContested,
        AdoptionError::SourceChanged
        | AdoptionError::SourceOutsideApprovedRoot
        | AdoptionError::SymlinkRejected(_)
        | AdoptionError::HardLinkAmbiguous(_)
        | AdoptionError::SpecialFileRejected(_) => AdoptionViewError::NativeViewContested,
        _ => AdoptionViewError::TransitionIncomplete,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptionViewError {
    RecordContested,
    BackupContested,
    CanonicalContested,
    NativeViewContested,
    GatewayMetadataUnavailable,
    TransitionIncomplete,
}

impl fmt::Display for AdoptionViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RecordContested => "authenticated adoption record is contested",
            Self::BackupContested => "authenticated adoption backup is contested",
            Self::CanonicalContested => "authenticated canonical content is contested",
            Self::NativeViewContested => "native provider view is contested",
            Self::GatewayMetadataUnavailable => {
                "authenticated adoption cannot back gateway skill exposure"
            }
            Self::TransitionIncomplete => "native provider view transition is incomplete",
        })
    }
}

impl std::error::Error for AdoptionViewError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdoptionBackupManifest {
    version: u32,
    backup_id: String,
    operation_id: String,
    effect_graph_digest: String,
    source_fingerprint: String,
    source_identity: FileIdentity,
    source_kind: NodeKind,
    payload_fingerprint: String,
    algorithm: String,
    key_id: String,
    tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdoptionMarker {
    version: u32,
    operation_id: String,
    capability_id: String,
    source_fingerprint: String,
    source_identity: FileIdentity,
    source_kind: NodeKind,
    complete: bool,
    algorithm: String,
    key_id: String,
    tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum NodeKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeSnapshot {
    fingerprint: String,
    identity: FileIdentity,
    kind: NodeKind,
}

fn stable_source_snapshot(
    approved_root: &Path,
    source: &Path,
) -> Result<NodeSnapshot, AdoptionError> {
    validate_source_location(approved_root, source)?;
    let first = snapshot_node(source)?;
    let second = snapshot_node(source)?;
    if first == second {
        Ok(first)
    } else {
        Err(AdoptionError::SourceChanged)
    }
}

fn snapshot_node(path: &Path) -> Result<NodeSnapshot, AdoptionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    validate_node_metadata(path, &metadata)?;
    let identity = file_identity(&metadata);
    let kind = if metadata.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File
    };
    let mut hasher = Sha256::new();
    digest_node(path, Path::new(""), &mut hasher)?;
    let after = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if file_identity(&after) != identity {
        return Err(AdoptionError::SourceChanged);
    }
    Ok(NodeSnapshot {
        fingerprint: crate::encode_lower_hex(&hasher.finalize()),
        identity,
        kind,
    })
}

fn digest_node(
    path: &Path,
    relative_path: &Path,
    hasher: &mut Sha256,
) -> Result<(), AdoptionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    validate_node_metadata(path, &metadata)?;
    if metadata.is_file() {
        hasher.update(b"file\0");
        hasher.update([u8::from(node_is_executable(&metadata))]);
        digest_relative_path(hasher, relative_path);
        let bytes = read_regular_file(path, &metadata)?;
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        return Ok(());
    }
    hasher.update(b"directory\0");
    digest_relative_path(hasher, relative_path);
    let mut entries = fs::read_dir(path)
        .map_err(|error| io_error(path, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(path, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        digest_node(
            &entry.path(),
            &relative_path.join(entry.file_name()),
            hasher,
        )?;
    }
    let after = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if file_identity(&after) != file_identity(&metadata) {
        return Err(AdoptionError::SourceChanged);
    }
    Ok(())
}

fn read_regular_file(path: &Path, before: &fs::Metadata) -> Result<Vec<u8>, AdoptionError> {
    let mut file = File::open(path).map_err(|error| io_error(path, error))?;
    let opened = file.metadata().map_err(|error| io_error(path, error))?;
    if file_identity(&opened) != file_identity(before) || !opened.is_file() {
        return Err(AdoptionError::SourceChanged);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    let after = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if file_identity(&after) != file_identity(before) || after.len() != bytes.len() as u64 {
        return Err(AdoptionError::SourceChanged);
    }
    Ok(bytes)
}

fn copy_node_durable(source: &Path, destination: &Path) -> Result<(), AdoptionError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| io_error(source, error))?;
    validate_node_metadata(source, &metadata)?;
    if metadata.is_file() {
        let bytes = read_regular_file(source, &metadata)?;
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if node_is_executable(&metadata) {
                0o700
            } else {
                0o600
            });
        }
        let mut file = options
            .open(destination)
            .map_err(|error| io_error(destination, error))?;
        file.write_all(&bytes)
            .map_err(|error| io_error(destination, error))?;
        file.sync_all()
            .map_err(|error| io_error(destination, error))?;
        sync_directory(
            destination
                .parent()
                .ok_or(AdoptionError::DestinationContested)?,
        )?;
        return Ok(());
    }

    create_private_directory(destination)?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| io_error(source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(source, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        copy_node_durable(&entry.path(), &destination.join(entry.file_name()))?;
    }
    sync_directory(destination)?;
    Ok(())
}

#[cfg(unix)]
fn node_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn node_is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_node_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), AdoptionError> {
    if metadata.file_type().is_symlink() {
        return Err(AdoptionError::SymlinkRejected(path.to_path_buf()));
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(AdoptionError::SpecialFileRejected(path.to_path_buf()));
    }
    #[cfg(unix)]
    if metadata.is_file() {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(AdoptionError::HardLinkAmbiguous(path.to_path_buf()));
        }
    }
    Ok(())
}

fn validate_approved_root(path: &Path) -> Result<PathBuf, AdoptionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdoptionError::ApprovedRootInvalid);
    }
    fs::canonicalize(path).map_err(|error| io_error(path, error))
}

fn validate_source_location(approved_root: &Path, source: &Path) -> Result<PathBuf, AdoptionError> {
    reject_lexical_traversal(source)?;
    if !source.starts_with(approved_root) || source == approved_root {
        return Err(AdoptionError::SourceOutsideApprovedRoot);
    }
    let relative = source
        .strip_prefix(approved_root)
        .map_err(|_| AdoptionError::SourceOutsideApprovedRoot)?;
    let mut current = approved_root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(AdoptionError::SourceOutsideApprovedRoot);
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).map_err(|error| io_error(&current, error))?;
        if metadata.file_type().is_symlink() {
            return Err(AdoptionError::SymlinkRejected(current));
        }
    }
    let canonical = fs::canonicalize(source).map_err(|error| io_error(source, error))?;
    if canonical != source || !canonical.starts_with(approved_root) {
        return Err(AdoptionError::SourceOutsideApprovedRoot);
    }
    Ok(canonical)
}

fn validate_source_parent(approved_root: &Path, source: &Path) -> Result<(), AdoptionError> {
    let parent = source
        .parent()
        .ok_or(AdoptionError::SourceOutsideApprovedRoot)?;
    if !parent.starts_with(approved_root) {
        return Err(AdoptionError::SourceOutsideApprovedRoot);
    }
    let canonical = fs::canonicalize(parent).map_err(|error| io_error(parent, error))?;
    if canonical != parent || !canonical.starts_with(approved_root) {
        return Err(AdoptionError::SourceOutsideApprovedRoot);
    }
    Ok(())
}

fn reject_lexical_traversal(path: &Path) -> Result<(), AdoptionError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        Err(AdoptionError::PathTraversalRejected)
    } else {
        Ok(())
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), AdoptionError> {
    if path.as_os_str().is_empty() {
        return Err(AdoptionError::DestinationContested);
    }
    if let Some(parent) = path.parent()
        && parent != path
        && !parent.as_os_str().is_empty()
    {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(AdoptionError::DestinationContested);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                ensure_private_directory(parent)?;
            }
            Err(error) => return Err(io_error(parent, error)),
        }
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(AdoptionError::DestinationContested)
        }
        Ok(metadata) => verify_private_permissions(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_private_directory(path)?;
            sync_directory(path.parent().ok_or(AdoptionError::DestinationContested)?)
        }
        Err(error) => Err(io_error(path, error)),
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), AdoptionError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path).map_err(|error| io_error(path, error))
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<(), AdoptionError> {
    Err(AdoptionError::PrivatePermissionsUnsupported(
        path.to_path_buf(),
    ))
}

#[cfg(unix)]
fn verify_private_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), AdoptionError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 == 0 {
        Ok(())
    } else {
        Err(AdoptionError::InsecurePrivatePermissions(
            path.to_path_buf(),
        ))
    }
}

#[cfg(not(unix))]
fn verify_private_permissions(path: &Path, _metadata: &fs::Metadata) -> Result<(), AdoptionError> {
    Err(AdoptionError::PrivatePermissionsUnsupported(
        path.to_path_buf(),
    ))
}

#[cfg(unix)]
fn write_json_atomically<T: Serialize>(
    path: &Path,
    value: &T,
    replace: bool,
) -> Result<(), AdoptionError> {
    let parent = path.parent().ok_or(AdoptionError::DestinationContested)?;
    let temporary = parent.join(format!(
        ".adoption-marker-{}-{}.tmp",
        process::id(),
        MARKER_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
    let result = (|| {
        let mut file = options
            .open(&temporary)
            .map_err(|error| io_error(&temporary, error))?;
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| AdoptionError::Serialization(error.to_string()))?;
        file.write_all(&bytes)
            .map_err(|error| io_error(&temporary, error))?;
        file.write_all(b"\n")
            .map_err(|error| io_error(&temporary, error))?;
        file.sync_all()
            .map_err(|error| io_error(&temporary, error))?;
        if replace {
            fs::rename(&temporary, path).map_err(|error| io_error(path, error))?;
        } else {
            fs::hard_link(&temporary, path).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    AdoptionError::DestinationContested
                } else {
                    io_error(path, error)
                }
            })?;
            fs::remove_file(&temporary).map_err(|error| io_error(&temporary, error))?;
        }
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn write_json_atomically<T: Serialize>(
    path: &Path,
    _value: &T,
    _replace: bool,
) -> Result<(), AdoptionError> {
    Err(AdoptionError::PrivatePermissionsUnsupported(
        path.to_path_buf(),
    ))
}

fn remove_owned_tree(path: &Path) -> Result<(), AdoptionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(AdoptionError::DestinationContested);
    }
    if metadata.is_dir() {
        fs::remove_dir_all(path).map_err(|error| io_error(path, error))
    } else if metadata.is_file() {
        fs::remove_file(path).map_err(|error| io_error(path, error))
    } else {
        Err(AdoptionError::DestinationContested)
    }
}

fn sync_directory(path: &Path) -> Result<(), AdoptionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(path, error))
}

fn manifest_message(manifest: &AdoptionBackupManifest) -> Result<Vec<u8>, AdoptionError> {
    let mut signable = manifest.clone();
    signable.tag.clear();
    serde_json::to_vec(&signable).map_err(|error| AdoptionError::Serialization(error.to_string()))
}

fn marker_message(marker: &AdoptionMarker) -> Result<Vec<u8>, AdoptionError> {
    let mut signable = marker.clone();
    signable.tag.clear();
    serde_json::to_vec(&signable).map_err(|error| AdoptionError::Serialization(error.to_string()))
}

fn record_message(record: &AdoptionRecord) -> Result<Vec<u8>, AdoptionError> {
    let mut signable = record.clone();
    signable.tag.clear();
    serde_json::to_vec(&signable).map_err(|error| AdoptionError::Serialization(error.to_string()))
}

fn verify_record_authentication(
    record: &AdoptionRecord,
    key: &BackupAuthenticationKey,
) -> Result<(), AdoptionError> {
    if record.version != 1 || record.algorithm != "hmac-sha256" || record.key_id != key.key_id() {
        return Err(AdoptionError::ActivationRecordContested);
    }
    key.verify_purpose(
        ADOPTION_RECORD_PURPOSE,
        &record_message(record)?,
        &record.tag,
    )
    .map_err(|_| AdoptionError::ActivationRecordContested)
}

pub fn load_adoption_records(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
    capability_id: &str,
    key: &BackupAuthenticationKey,
) -> Result<Vec<AdoptionRecord>, AdoptionError> {
    let directory =
        adoption_record_directory(app_state_root.as_ref(), repository_key, capability_id);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(&directory, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdoptionError::ActivationRecordContested);
    }
    let mut paths = fs::read_dir(&directory)
        .map_err(|error| io_error(&directory, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(&directory, error))?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        let record = AtomicJsonStore::new(path, 1)
            .load::<AdoptionRecord>()?
            .ok_or(AdoptionError::ActivationRecordContested)?
            .value;
        verify_record_authentication(&record, key)?;
        if record.repository_key != repository_key || record.capability_id != capability_id {
            return Err(AdoptionError::ActivationRecordContested);
        }
        records.push(record);
    }
    Ok(records)
}

pub fn load_repository_adoption_records(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
    key: &BackupAuthenticationKey,
) -> Result<Vec<AdoptionRecord>, AdoptionError> {
    let directory = get_activation_root(app_state_root.as_ref(), repository_key).join("adoptions");
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(&directory, error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AdoptionError::ActivationRecordContested);
    }
    let mut paths = Vec::new();
    for capability_entry in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
        let capability_entry = capability_entry.map_err(|error| io_error(&directory, error))?;
        let file_type = capability_entry
            .file_type()
            .map_err(|error| io_error(&capability_entry.path(), error))?;
        if file_type.is_symlink() || !file_type.is_dir() {
            return Err(AdoptionError::ActivationRecordContested);
        }
        for record_entry in fs::read_dir(capability_entry.path())
            .map_err(|error| io_error(&capability_entry.path(), error))?
        {
            let record_entry = record_entry.map_err(|error| io_error(&directory, error))?;
            let file_type = record_entry
                .file_type()
                .map_err(|error| io_error(&record_entry.path(), error))?;
            let path = record_entry.path();
            if file_type.is_symlink() {
                return Err(AdoptionError::ActivationRecordContested);
            }
            if file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                && !path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'))
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    let mut records = Vec::with_capacity(paths.len());
    for path in paths {
        let record = AtomicJsonStore::new(&path, 1)
            .load::<AdoptionRecord>()?
            .ok_or(AdoptionError::ActivationRecordContested)?
            .value;
        verify_record_authentication(&record, key)?;
        if record.repository_key != repository_key
            || adoption_record_path(
                app_state_root.as_ref(),
                repository_key,
                &record.capability_id,
                &record.operation_id,
            ) != path
        {
            return Err(AdoptionError::ActivationRecordContested);
        }
        records.push(record);
    }
    Ok(records)
}

/// Builds one session catalog exclusively from authenticated, withdrawn views.
///
/// Current production gateway wiring supports adopted skills only. Every
/// provider-selected profile member must therefore resolve to exactly one
/// active adoption record for this repository/workspace, and its provider view
/// must still be withdrawn. This keeps startup fail-closed: an unavailable
/// upstream MCP or native duplicate cannot silently broaden session exposure.
pub fn authenticated_adopted_skill_catalog(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
    workspace_key: &str,
    provider: ProviderId,
    profile: &CompiledProfileRevision,
    key: &BackupAuthenticationKey,
) -> Result<Catalog, AdoptedGatewayCatalogError> {
    let capability_ids = profile
        .members_for_provider(provider)
        .map(|member| member.capability_id.clone())
        .collect::<Vec<_>>();
    authenticated_adopted_skill_catalog_for_capabilities(
        app_state_root,
        repository_key,
        workspace_key,
        provider,
        &capability_ids,
        key,
    )
}

pub fn authenticated_adopted_skill_catalog_for_capabilities(
    app_state_root: impl AsRef<Path>,
    repository_key: &str,
    workspace_key: &str,
    provider: ProviderId,
    capability_ids: &[CapabilityId],
    key: &BackupAuthenticationKey,
) -> Result<Catalog, AdoptedGatewayCatalogError> {
    let app_state_root = app_state_root.as_ref();
    let mut gateway_records = Vec::new();
    for capability_id in capability_ids {
        let records =
            load_adoption_records(app_state_root, repository_key, capability_id.as_str(), key)?;
        let mut matching = records.into_iter().filter(|record| {
            record.active()
                && record.workspace_key() == workspace_key
                && record
                    .catalog_record()
                    .is_some_and(|catalog| catalog.supports_provider(provider))
        });
        let record = matching.next().ok_or_else(|| {
            AdoptedGatewayCatalogError::MissingAdoption(capability_id.to_string())
        })?;
        if matching.next().is_some() {
            return Err(AdoptedGatewayCatalogError::AmbiguousAdoption(
                capability_id.to_string(),
            ));
        }
        if record.catalog_record().map(|record| record.kind) != Some(CapabilityKind::Skill) {
            return Err(AdoptedGatewayCatalogError::UnsupportedCapability(
                capability_id.to_string(),
            ));
        }
        let view = AuthenticatedNativeView::new(record, key.clone())?;
        if view.inspect()? != NativeViewState::Withdrawn {
            return Err(AdoptedGatewayCatalogError::NativeViewPresent(
                capability_id.to_string(),
            ));
        }
        gateway_records.push(view.gateway_catalog_record()?);
    }
    Catalog::from_records(gateway_records).map_err(Into::into)
}

#[derive(Debug)]
pub enum AdoptedGatewayCatalogError {
    Adoption(AdoptionError),
    View(AdoptionViewError),
    Catalog(CatalogModelError),
    MissingAdoption(String),
    AmbiguousAdoption(String),
    UnsupportedCapability(String),
    NativeViewPresent(String),
}

impl From<AdoptionError> for AdoptedGatewayCatalogError {
    fn from(error: AdoptionError) -> Self {
        Self::Adoption(error)
    }
}

impl From<AdoptionViewError> for AdoptedGatewayCatalogError {
    fn from(error: AdoptionViewError) -> Self {
        Self::View(error)
    }
}

impl From<CatalogModelError> for AdoptedGatewayCatalogError {
    fn from(error: CatalogModelError) -> Self {
        Self::Catalog(error)
    }
}

impl fmt::Display for AdoptedGatewayCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adoption(error) => error.fmt(formatter),
            Self::View(error) => error.fmt(formatter),
            Self::Catalog(error) => error.fmt(formatter),
            Self::MissingAdoption(capability_id) => write!(
                formatter,
                "profile capability has no active adopted view in this workspace: {capability_id}"
            ),
            Self::AmbiguousAdoption(capability_id) => write!(
                formatter,
                "profile capability has ambiguous adopted views: {capability_id}"
            ),
            Self::UnsupportedCapability(capability_id) => write!(
                formatter,
                "profile capability has no production gateway adapter: {capability_id}"
            ),
            Self::NativeViewPresent(capability_id) => write!(
                formatter,
                "profile capability remains natively visible and would be duplicated: {capability_id}"
            ),
        }
    }
}

impl std::error::Error for AdoptedGatewayCatalogError {}

fn adoption_record_directory(
    app_state_root: &Path,
    repository_key: &str,
    capability_id: &str,
) -> PathBuf {
    get_activation_root(app_state_root, repository_key)
        .join("adoptions")
        .join(encode_path_segment(capability_id))
}

fn adoption_record_path(
    app_state_root: &Path,
    repository_key: &str,
    capability_id: &str,
    operation_id: &str,
) -> PathBuf {
    adoption_record_directory(app_state_root, repository_key, capability_id)
        .join(format!("{}.json", encode_path_segment(operation_id)))
}

fn activation_logical_fingerprint(
    operation_id: &str,
    capability_id: &str,
    provider: ProviderId,
    source_fingerprint: &str,
    repository_key: &str,
    workspace_key: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-adoption-activation-v1\0");
    for field in [
        operation_id,
        capability_id,
        provider.as_str(),
        source_fingerprint,
        repository_key,
        workspace_key,
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    crate::encode_lower_hex(&hasher.finalize())
}

fn backup_state_owner(operation_id: &str) -> Result<OwnerGeneration, AdoptionError> {
    OwnerGeneration::new(format!("adoption-{operation_id}"), 1).map_err(AdoptionError::State)
}

fn resource_id(kind: &str, path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"unpin-adoption-resource-v1\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(path.as_os_str().as_encoded_bytes());
    format!(
        "adoption-{kind}-{}",
        crate::encode_lower_hex(&hasher.finalize())
    )
}

#[cfg(unix)]
fn ensure_same_filesystem(source: &Path, app_state_root: &Path) -> Result<(), AdoptionError> {
    use std::os::unix::fs::MetadataExt;

    let source_device = fs::metadata(source)
        .map_err(|error| io_error(source, error))?
        .dev();
    let mut current = Some(app_state_root);
    while let Some(path) = current {
        match fs::metadata(path) {
            Ok(metadata) => {
                return if metadata.dev() == source_device {
                    Ok(())
                } else {
                    Err(AdoptionError::CrossFilesystemUnsupported)
                };
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                current = path.parent();
            }
            Err(error) => return Err(io_error(path, error)),
        }
    }
    Err(AdoptionError::CrossFilesystemUnsupported)
}

#[cfg(not(unix))]
fn ensure_same_filesystem(_source: &Path, app_state_root: &Path) -> Result<(), AdoptionError> {
    Err(AdoptionError::PrivatePermissionsUnsupported(
        app_state_root.to_path_buf(),
    ))
}

fn fingerprint(bytes: &[u8]) -> String {
    crate::encode_lower_hex(&Sha256::digest(bytes))
}

fn digest_relative_path(hasher: &mut Sha256, path: &Path) {
    hasher.update((path.components().count() as u64).to_be_bytes());
    for component in path.components() {
        let bytes = component.as_os_str().as_encoded_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
    }
}

fn validate_identifier(value: &str) -> Result<(), AdoptionError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(AdoptionError::InvalidCapabilityId)
    } else {
        Ok(())
    }
}

fn failure(code: &str) -> BackendFailure {
    BackendFailure::new(code).expect("static adoption failure code is valid")
}

fn backend_failure(error: AdoptionError) -> BackendFailure {
    failure(error.code())
}

fn io_error(path: &Path, error: io::Error) -> AdoptionError {
    AdoptionError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    }
}

fn rename_error(path: &Path, error: io::Error) -> AdoptionError {
    if error.kind() == io::ErrorKind::CrossesDevices {
        AdoptionError::CrossFilesystemUnsupported
    } else {
        io_error(path, error)
    }
}

#[derive(Debug)]
pub enum AdoptionError {
    InvalidCapabilityId,
    UnsupportedCapabilityKind,
    DiscoveryItemNotAdoptable,
    CatalogRecordMismatch,
    InstalledBundleMustRemainProviderOwned,
    AbsolutePathRequired,
    PathTraversalRejected,
    ApprovedRootInvalid,
    SourceOutsideApprovedRoot,
    SymlinkRejected(PathBuf),
    HardLinkAmbiguous(PathBuf),
    SpecialFileRejected(PathBuf),
    SourceChanged,
    DestinationContested,
    BackupContested,
    BackupAuthenticationFailed,
    ActivationRecordContested,
    DuplicateActiveAdoption,
    RetainedOriginalContested,
    RetainedOriginalInvalid,
    RestoreTargetContested,
    PlanMismatch,
    InsecurePrivatePermissions(PathBuf),
    PrivatePermissionsUnsupported(PathBuf),
    CrossFilesystemUnsupported,
    Authentication(String),
    Serialization(String),
    Io { path: PathBuf, message: String },
    State(StateError),
    Transition(crate::transitions::TransitionPlanError),
    InjectedFailure,
}

impl AdoptionError {
    fn code(&self) -> &'static str {
        match self {
            Self::InvalidCapabilityId => "invalid-capability-id",
            Self::UnsupportedCapabilityKind => "unsupported-capability-kind",
            Self::DiscoveryItemNotAdoptable => "discovery-item-not-adoptable",
            Self::CatalogRecordMismatch => "catalog-record-mismatch",
            Self::InstalledBundleMustRemainProviderOwned => "installed-bundle-retained",
            Self::AbsolutePathRequired => "absolute-path-required",
            Self::PathTraversalRejected => "path-traversal-rejected",
            Self::ApprovedRootInvalid => "approved-root-invalid",
            Self::SourceOutsideApprovedRoot => "source-outside-approved-root",
            Self::SymlinkRejected(_) => "symlink-rejected",
            Self::HardLinkAmbiguous(_) => "hardlink-ambiguous",
            Self::SpecialFileRejected(_) => "special-file-rejected",
            Self::SourceChanged => "source-changed",
            Self::DestinationContested => "destination-contested",
            Self::BackupContested => "backup-contested",
            Self::BackupAuthenticationFailed => "backup-authentication-failed",
            Self::ActivationRecordContested => "activation-record-contested",
            Self::DuplicateActiveAdoption => "duplicate-active-adoption",
            Self::RetainedOriginalContested => "retained-original-contested",
            Self::RetainedOriginalInvalid => "retained-original-invalid",
            Self::RestoreTargetContested => "restore-target-contested",
            Self::PlanMismatch => "plan-mismatch",
            Self::InsecurePrivatePermissions(_) => "insecure-private-permissions",
            Self::PrivatePermissionsUnsupported(_) => "private-permissions-unsupported",
            Self::CrossFilesystemUnsupported => "cross-filesystem-unsupported",
            Self::Authentication(_) => "authentication-failed",
            Self::Serialization(_) => "serialization-failed",
            Self::Io { .. } => "io-failed",
            Self::State(_) => "state-failed",
            Self::Transition(_) => "transition-plan-failed",
            Self::InjectedFailure => "injected-failure",
        }
    }
}

impl From<StateError> for AdoptionError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<crate::transitions::TransitionPlanError> for AdoptionError {
    fn from(error: crate::transitions::TransitionPlanError) -> Self {
        Self::Transition(error)
    }
}

impl fmt::Display for AdoptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCapabilityId => formatter.write_str("capability id is invalid"),
            Self::UnsupportedCapabilityKind => {
                formatter.write_str("capability kind cannot be adopted")
            }
            Self::DiscoveryItemNotAdoptable => {
                formatter.write_str("discovered item is not an adoptable live provider source")
            }
            Self::CatalogRecordMismatch => {
                formatter.write_str("catalog record does not match adopted provider source")
            }
            Self::InstalledBundleMustRemainProviderOwned => {
                formatter.write_str("installed plugin bundles must remain provider-owned")
            }
            Self::AbsolutePathRequired => formatter.write_str("adoption paths must be absolute"),
            Self::PathTraversalRejected => formatter.write_str("adoption path traversal rejected"),
            Self::ApprovedRootInvalid => formatter.write_str("approved provider root is invalid"),
            Self::SourceOutsideApprovedRoot => {
                formatter.write_str("source is outside approved provider root")
            }
            Self::SymlinkRejected(path) => {
                write!(formatter, "adoption symlink rejected: {}", path.display())
            }
            Self::HardLinkAmbiguous(path) => write!(
                formatter,
                "adoption hard-link identity is ambiguous: {}",
                path.display()
            ),
            Self::SpecialFileRejected(path) => {
                write!(
                    formatter,
                    "adoption special file rejected: {}",
                    path.display()
                )
            }
            Self::SourceChanged => formatter.write_str("adoption source changed"),
            Self::DestinationContested => formatter.write_str("canonical destination is contested"),
            Self::BackupContested => formatter.write_str("adoption backup is contested"),
            Self::BackupAuthenticationFailed => {
                formatter.write_str("adoption backup authentication failed")
            }
            Self::ActivationRecordContested => {
                formatter.write_str("adoption activation record is contested")
            }
            Self::DuplicateActiveAdoption => {
                formatter.write_str("capability already has an active adoption")
            }
            Self::RetainedOriginalContested => {
                formatter.write_str("retained original destination is contested")
            }
            Self::RetainedOriginalInvalid => formatter.write_str("retained original is invalid"),
            Self::RestoreTargetContested => {
                formatter.write_str("original provider path is contested")
            }
            Self::PlanMismatch => formatter.write_str("adoption plan does not match backend"),
            Self::InsecurePrivatePermissions(path) => write!(
                formatter,
                "adoption state permissions are insecure: {}",
                path.display()
            ),
            Self::PrivatePermissionsUnsupported(path) => write!(
                formatter,
                "private adoption permissions are unsupported: {}",
                path.display()
            ),
            Self::CrossFilesystemUnsupported => formatter.write_str(
                "adoption requires app state and provider source on the same filesystem",
            ),
            Self::Authentication(message) | Self::Serialization(message) => {
                formatter.write_str(message)
            }
            Self::Io { path, message } => write!(formatter, "{}: {message}", path.display()),
            Self::State(error) => error.fmt(formatter),
            Self::Transition(error) => error.fmt(formatter),
            Self::InjectedFailure => formatter.write_str("injected adoption failure"),
        }
    }
}

impl std::error::Error for AdoptionError {}
