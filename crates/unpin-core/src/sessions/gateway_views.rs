use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    catalog::CapabilityScope,
    catalog::adoption::{
        AdoptionError, AdoptionRecord, AdoptionViewError, AuthenticatedNativeView, NativeViewState,
        NativeViewTransitionStatus, load_repository_adoption_records,
    },
    mutation::BackupAuthenticationKey,
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration, StateError, StateRevision},
};

use super::{GatewayModeAction, GatewayModeTarget};

const GATEWAY_VIEW_LEDGER_SCHEMA_VERSION: u32 = 1;
const GATEWAY_VIEW_LEDGER_PURPOSE: &[u8] = b"unpin-gateway-view-ledger-v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayNativeViewPlanEntry {
    pub operation_id: String,
    pub capability_id: String,
    pub backup_id: String,
    pub repository_key: String,
    pub workspace_key: String,
    pub provider_views: Vec<ProviderId>,
    pub current: NativeViewState,
    pub desired: NativeViewState,
    pub resource_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayNativeViewPlan {
    pub target: GatewayModeTarget,
    pub action: GatewayModeAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ledger_revision: Option<StateRevision>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<GatewayNativeViewPlanEntry>,
    pub plan_fingerprint: String,
}

impl GatewayNativeViewPlan {
    pub fn verify(&self) -> Result<(), GatewayNativeViewError> {
        let actual = plan_fingerprint(
            &self.target,
            self.action,
            self.expected_ledger_revision.as_ref(),
            &self.entries,
        )?;
        if actual == self.plan_fingerprint {
            Ok(())
        } else {
            Err(GatewayNativeViewError::PlanFingerprintMismatch)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayNativeViewApplyStatus {
    Applied,
    NoOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayNativeViewApplyResult {
    pub status: GatewayNativeViewApplyStatus,
    pub plan_fingerprint: String,
    pub entries: Vec<GatewayNativeViewPlanEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayViewLedger {
    version: u32,
    target: GatewayModeTarget,
    entries: Vec<GatewayViewLedgerEntry>,
    key_id: String,
    tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GatewayViewLedgerEntry {
    operation_id: String,
    capability_id: String,
    backup_id: String,
    repository_key: String,
    workspace_key: String,
    provider_views: Vec<ProviderId>,
    resource_ids: Vec<String>,
}

impl From<&GatewayNativeViewPlanEntry> for GatewayViewLedgerEntry {
    fn from(entry: &GatewayNativeViewPlanEntry) -> Self {
        Self {
            operation_id: entry.operation_id.clone(),
            capability_id: entry.capability_id.clone(),
            backup_id: entry.backup_id.clone(),
            repository_key: entry.repository_key.clone(),
            workspace_key: entry.workspace_key.clone(),
            provider_views: entry.provider_views.clone(),
            resource_ids: entry.resource_ids.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayNativeViewController {
    app_state_root: PathBuf,
    key: BackupAuthenticationKey,
}

impl GatewayNativeViewController {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>, key: BackupAuthenticationKey) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            key,
        }
    }

    pub fn plan(
        &self,
        target: GatewayModeTarget,
        action: GatewayModeAction,
    ) -> Result<GatewayNativeViewPlan, GatewayNativeViewError> {
        target.validate()?;
        if target.repository_key.is_none() {
            if matches!(action, GatewayModeAction::Install)
                || !activation_state_exists(&self.app_state_root)?
            {
                let entries = Vec::new();
                let plan_fingerprint = plan_fingerprint(&target, action, None, &entries)?;
                return Ok(GatewayNativeViewPlan {
                    target,
                    action,
                    expected_ledger_revision: None,
                    entries,
                    plan_fingerprint,
                });
            }
            return Err(GatewayNativeViewError::GlobalScopeUnsupported);
        }
        let ledger = self.load_ledger(&target)?;
        let expected_ledger_revision = ledger.as_ref().map(|ledger| ledger.revision.clone());
        let entries = match action {
            GatewayModeAction::Install => Vec::new(),
            GatewayModeAction::Activate => ledger
                .as_ref()
                .map(|ledger| self.entries_from_ledger(&ledger.value, NativeViewState::Withdrawn))
                .transpose()?
                .unwrap_or_default(),
            GatewayModeAction::Off | GatewayModeAction::Detach => match ledger.as_ref() {
                Some(ledger) => {
                    self.entries_from_ledger(&ledger.value, NativeViewState::Present)?
                }
                None => self.withdrawn_entries_for_target(&target)?,
            },
        };
        let plan_fingerprint =
            plan_fingerprint(&target, action, expected_ledger_revision.as_ref(), &entries)?;
        Ok(GatewayNativeViewPlan {
            target,
            action,
            expected_ledger_revision,
            entries,
            plan_fingerprint,
        })
    }

    pub fn protected_resources_for_session(
        &self,
        repository_key: &str,
        workspace_key: &str,
        provider: ProviderId,
    ) -> Result<BTreeSet<String>, GatewayNativeViewError> {
        let mut resources = BTreeSet::new();
        for record in
            load_repository_adoption_records(&self.app_state_root, repository_key, &self.key)?
        {
            let catalog = record
                .catalog_record()
                .ok_or(GatewayNativeViewError::GatewayMetadataUnavailable)?;
            if !catalog.supports_provider(provider)
                || (catalog.origin.scope == CapabilityScope::Repository
                    && record.workspace_key() != workspace_key)
            {
                continue;
            }
            let view = AuthenticatedNativeView::new(record, self.key.clone())?;
            view.inspect()?;
            for resource in view.physical_resources() {
                resources.insert(resource.resource_id().to_string());
            }
        }
        Ok(resources)
    }

    pub fn apply(
        &self,
        reviewed: &GatewayNativeViewPlan,
        actor_id: &str,
    ) -> Result<GatewayNativeViewApplyResult, GatewayNativeViewError> {
        let result = self.apply_pending(reviewed, actor_id)?;
        if reviewed.action == GatewayModeAction::Activate {
            self.finalize_activate(reviewed)?;
        }
        Ok(result)
    }

    pub(crate) fn cached_apply_result(
        &self,
        reviewed: &GatewayNativeViewPlan,
    ) -> Result<GatewayNativeViewApplyResult, GatewayNativeViewError> {
        reviewed.verify()?;
        for entry in &reviewed.entries {
            let record = self.record_for_entry(entry)?;
            let view = AuthenticatedNativeView::new(record.clone(), self.key.clone())?;
            let actual = plan_entry(&record, &view, entry.desired)?;
            let mut expected = entry.clone();
            expected.current = entry.desired;
            if actual != expected {
                return Err(GatewayNativeViewError::LedgerContested);
            }
        }
        match reviewed.action {
            GatewayModeAction::Activate => {
                if self.load_ledger(&reviewed.target)?.is_some() {
                    return Err(GatewayNativeViewError::LedgerContested);
                }
            }
            GatewayModeAction::Off | GatewayModeAction::Detach if !reviewed.entries.is_empty() => {
                let ledger = self
                    .load_ledger(&reviewed.target)?
                    .ok_or(GatewayNativeViewError::LedgerContested)?;
                let expected = reviewed
                    .entries
                    .iter()
                    .map(GatewayViewLedgerEntry::from)
                    .collect::<Vec<_>>();
                if ledger.value.entries != expected {
                    return Err(GatewayNativeViewError::LedgerContested);
                }
            }
            GatewayModeAction::Install | GatewayModeAction::Off | GatewayModeAction::Detach => {}
        }
        Ok(GatewayNativeViewApplyResult {
            status: if reviewed
                .entries
                .iter()
                .any(|entry| entry.current != entry.desired)
            {
                GatewayNativeViewApplyStatus::Applied
            } else {
                GatewayNativeViewApplyStatus::NoOp
            },
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            entries: reviewed.entries.clone(),
        })
    }

    pub(crate) fn apply_pending(
        &self,
        reviewed: &GatewayNativeViewPlan,
        actor_id: &str,
    ) -> Result<GatewayNativeViewApplyResult, GatewayNativeViewError> {
        reviewed.verify()?;
        let current = self.plan(reviewed.target.clone(), reviewed.action)?;
        if current != *reviewed {
            return Err(GatewayNativeViewError::PlanFingerprintMismatch);
        }
        if matches!(
            reviewed.action,
            GatewayModeAction::Off | GatewayModeAction::Detach
        ) && !reviewed.entries.is_empty()
            && reviewed.expected_ledger_revision.is_none()
        {
            self.create_ledger(reviewed, actor_id)?;
        }

        let mut changed = false;
        for (entry_index, entry) in reviewed.entries.iter().enumerate() {
            let record = self.record_for_entry(entry)?;
            let view = AuthenticatedNativeView::new(record, self.key.clone())?;
            let outcome = match view.transition(entry.desired) {
                Ok(outcome) => outcome,
                Err(error) => {
                    let compensation =
                        self.compensate_entries(reviewed.entries[..=entry_index].iter().rev());
                    return Err(match compensation {
                        Ok(()) => GatewayNativeViewError::TransitionFailed {
                            capability_id: entry.capability_id.clone(),
                            reason: error.to_string(),
                        },
                        Err(compensation_error) => GatewayNativeViewError::RecoveryRequired {
                            capability_id: entry.capability_id.clone(),
                            reason: format!(
                                "{error}; native-view compensation failed: {compensation_error}"
                            ),
                        },
                    });
                }
            };
            changed |= outcome.status() == NativeViewTransitionStatus::Applied;
        }

        Ok(GatewayNativeViewApplyResult {
            status: if changed {
                GatewayNativeViewApplyStatus::Applied
            } else {
                GatewayNativeViewApplyStatus::NoOp
            },
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            entries: reviewed.entries.clone(),
        })
    }

    pub(crate) fn resume_pending(
        &self,
        reviewed: &GatewayNativeViewPlan,
        actor_id: &str,
    ) -> Result<GatewayNativeViewApplyResult, GatewayNativeViewError> {
        reviewed.verify()?;
        let ledger = self.load_ledger(&reviewed.target)?;
        match reviewed.action {
            GatewayModeAction::Activate => {
                if ledger.as_ref().map(|ledger| &ledger.revision)
                    != reviewed.expected_ledger_revision.as_ref()
                {
                    return Err(GatewayNativeViewError::LedgerContested);
                }
            }
            GatewayModeAction::Off | GatewayModeAction::Detach if !reviewed.entries.is_empty() => {
                if reviewed.expected_ledger_revision.is_none() && ledger.is_none() {
                    self.create_ledger(reviewed, actor_id)?;
                } else {
                    let ledger = ledger.ok_or(GatewayNativeViewError::LedgerContested)?;
                    if reviewed
                        .expected_ledger_revision
                        .as_ref()
                        .is_some_and(|expected| expected != &ledger.revision)
                        || ledger.value.entries
                            != reviewed
                                .entries
                                .iter()
                                .map(GatewayViewLedgerEntry::from)
                                .collect::<Vec<_>>()
                    {
                        return Err(GatewayNativeViewError::LedgerContested);
                    }
                }
            }
            GatewayModeAction::Install | GatewayModeAction::Off | GatewayModeAction::Detach => {}
        }

        let mut changed = false;
        for entry in &reviewed.entries {
            let record = self.record_for_entry(entry)?;
            let view = AuthenticatedNativeView::new(record, self.key.clone())?;
            let current = view.inspect()?;
            if current != entry.current && current != entry.desired {
                return Err(GatewayNativeViewError::LedgerContested);
            }
            if current == entry.desired {
                continue;
            }
            if let Err(error) = view.transition(entry.desired) {
                let compensation = self.compensate_entries(reviewed.entries.iter().rev());
                return Err(match compensation {
                    Ok(()) => GatewayNativeViewError::TransitionFailed {
                        capability_id: entry.capability_id.clone(),
                        reason: error.to_string(),
                    },
                    Err(compensation_error) => GatewayNativeViewError::RecoveryRequired {
                        capability_id: entry.capability_id.clone(),
                        reason: format!(
                            "{error}; native-view compensation failed: {compensation_error}"
                        ),
                    },
                });
            }
            changed = true;
        }
        Ok(GatewayNativeViewApplyResult {
            status: if changed
                || reviewed
                    .entries
                    .iter()
                    .any(|entry| entry.current != entry.desired)
            {
                GatewayNativeViewApplyStatus::Applied
            } else {
                GatewayNativeViewApplyStatus::NoOp
            },
            plan_fingerprint: reviewed.plan_fingerprint.clone(),
            entries: reviewed.entries.clone(),
        })
    }

    /// Restores every Activate entry to the pre-state bound into the reviewed
    /// plan. This is used only while the authenticated view ledger is retained.
    pub fn compensate_activate(
        &self,
        reviewed: &GatewayNativeViewPlan,
    ) -> Result<(), GatewayNativeViewError> {
        reviewed.verify()?;
        if reviewed.action != GatewayModeAction::Activate {
            return Err(GatewayNativeViewError::PlanFingerprintMismatch);
        }
        let ledger = self.load_ledger(&reviewed.target)?;
        if ledger.as_ref().map(|ledger| &ledger.revision)
            != reviewed.expected_ledger_revision.as_ref()
        {
            return Err(GatewayNativeViewError::LedgerContested);
        }
        self.compensate_entries(reviewed.entries.iter().rev())
            .map_err(|reason| GatewayNativeViewError::RecoveryRequired {
                capability_id: reviewed.entries.first().map_or_else(
                    || "native-views".to_string(),
                    |entry| entry.capability_id.clone(),
                ),
                reason,
            })
    }

    pub(crate) fn finalize_activate(
        &self,
        reviewed: &GatewayNativeViewPlan,
    ) -> Result<(), GatewayNativeViewError> {
        if reviewed.action != GatewayModeAction::Activate {
            return Err(GatewayNativeViewError::PlanFingerprintMismatch);
        }
        self.remove_ledger(reviewed)
    }

    fn withdrawn_entries_for_target(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<Vec<GatewayNativeViewPlanEntry>, GatewayNativeViewError> {
        let repository_key = target
            .repository_key
            .as_deref()
            .ok_or(GatewayNativeViewError::GlobalScopeUnsupported)?;
        let records =
            load_repository_adoption_records(&self.app_state_root, repository_key, &self.key)?;
        let mut by_provider_resource = BTreeMap::new();
        for record in records {
            if !record_matches_target(&record, target) {
                continue;
            }
            let view = AuthenticatedNativeView::new(record.clone(), self.key.clone())?;
            if view.inspect()? != NativeViewState::Withdrawn {
                continue;
            }
            let entry = plan_entry(&record, &view, NativeViewState::Present)?;
            let provider_resource = entry
                .resource_ids
                .first()
                .ok_or(GatewayNativeViewError::RecordContested)?
                .clone();
            if by_provider_resource
                .insert(provider_resource, entry)
                .is_some()
            {
                return Err(GatewayNativeViewError::AmbiguousPhysicalView);
            }
        }
        let mut entries = by_provider_resource.into_values().collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            (&left.capability_id, &left.operation_id)
                .cmp(&(&right.capability_id, &right.operation_id))
        });
        Ok(entries)
    }

    fn entries_from_ledger(
        &self,
        ledger: &GatewayViewLedger,
        desired: NativeViewState,
    ) -> Result<Vec<GatewayNativeViewPlanEntry>, GatewayNativeViewError> {
        let mut entries = Vec::with_capacity(ledger.entries.len());
        for saved in &ledger.entries {
            let record = self.record_for_ledger_entry(saved)?;
            let view = AuthenticatedNativeView::new(record.clone(), self.key.clone())?;
            let current = view.inspect()?;
            let mut entry = plan_entry(&record, &view, desired)?;
            if entry.resource_ids != saved.resource_ids
                || entry.provider_views != saved.provider_views
            {
                return Err(GatewayNativeViewError::LedgerContested);
            }
            entry.current = current;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn record_for_entry(
        &self,
        entry: &GatewayNativeViewPlanEntry,
    ) -> Result<AdoptionRecord, GatewayNativeViewError> {
        self.record_for_ledger_entry(&GatewayViewLedgerEntry::from(entry))
    }

    fn record_for_ledger_entry(
        &self,
        entry: &GatewayViewLedgerEntry,
    ) -> Result<AdoptionRecord, GatewayNativeViewError> {
        let records = load_repository_adoption_records(
            &self.app_state_root,
            &entry.repository_key,
            &self.key,
        )?;
        let mut matching = records.into_iter().filter(|record| {
            record.operation_id() == entry.operation_id
                && record.capability_id() == entry.capability_id
                && record.backup_id() == entry.backup_id
                && record.workspace_key() == entry.workspace_key
        });
        let record = matching
            .next()
            .ok_or(GatewayNativeViewError::LedgerContested)?;
        if matching.next().is_some() {
            return Err(GatewayNativeViewError::LedgerContested);
        }
        Ok(record)
    }

    fn compensate_entries<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a GatewayNativeViewPlanEntry>,
    ) -> Result<(), String> {
        for entry in entries {
            let record = self
                .record_for_entry(entry)
                .map_err(|error| format!("{}: {error}", entry.capability_id))?;
            let view = AuthenticatedNativeView::new(record, self.key.clone())
                .map_err(|error| format!("{}: {error}", entry.capability_id))?;
            match view
                .inspect()
                .map_err(|error| format!("{}: {error}", entry.capability_id))?
            {
                state if state == entry.current => continue,
                state if state == entry.desired => {}
                _ => {
                    return Err(format!(
                        "{} changed outside reviewed native-view transition",
                        entry.capability_id
                    ));
                }
            }
            view.transition(entry.current)
                .map_err(|error| format!("{}: {error}", entry.capability_id))?;
            if view.inspect() != Ok(entry.current) {
                return Err(format!(
                    "{} could not be restored to reviewed pre-state",
                    entry.capability_id
                ));
            }
        }
        Ok(())
    }

    fn create_ledger(
        &self,
        reviewed: &GatewayNativeViewPlan,
        actor_id: &str,
    ) -> Result<(), GatewayNativeViewError> {
        let mut ledger = GatewayViewLedger {
            version: GATEWAY_VIEW_LEDGER_SCHEMA_VERSION,
            target: reviewed.target.clone(),
            entries: reviewed.entries.iter().map(Into::into).collect(),
            key_id: self.key.key_id(),
            tag: String::new(),
        };
        ledger.tag = self
            .key
            .authenticate_purpose(GATEWAY_VIEW_LEDGER_PURPOSE, &ledger_message(&ledger)?)
            .map_err(|_| GatewayNativeViewError::LedgerAuthenticationFailed)?;
        self.ledger_store(&reviewed.target)?.compare_and_swap(
            None,
            OwnerGeneration::new(actor_id, 1)?,
            &ledger,
        )?;
        Ok(())
    }

    fn remove_ledger(
        &self,
        reviewed: &GatewayNativeViewPlan,
    ) -> Result<(), GatewayNativeViewError> {
        let Some(ledger) = self.load_ledger(&reviewed.target)? else {
            return Ok(());
        };
        if reviewed.expected_ledger_revision.as_ref() != Some(&ledger.revision) {
            return Err(GatewayNativeViewError::PlanFingerprintMismatch);
        }
        self.ledger_store(&reviewed.target)?
            .remove_if_revision(&ledger.revision)?;
        Ok(())
    }

    fn load_ledger(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<
        Option<crate::state::atomic_json::StateSnapshot<GatewayViewLedger>>,
        GatewayNativeViewError,
    > {
        let ledger = self.ledger_store(target)?.load::<GatewayViewLedger>()?;
        if let Some(ledger) = &ledger {
            if ledger.value.version != GATEWAY_VIEW_LEDGER_SCHEMA_VERSION
                || ledger.value.target != *target
                || ledger.value.key_id != self.key.key_id()
            {
                return Err(GatewayNativeViewError::LedgerContested);
            }
            self.key
                .verify_purpose(
                    GATEWAY_VIEW_LEDGER_PURPOSE,
                    &ledger_message(&ledger.value)?,
                    &ledger.value.tag,
                )
                .map_err(|_| GatewayNativeViewError::LedgerAuthenticationFailed)?;
        }
        Ok(ledger)
    }

    fn ledger_store(
        &self,
        target: &GatewayModeTarget,
    ) -> Result<AtomicJsonStore, GatewayNativeViewError> {
        Ok(AtomicJsonStore::new(
            self.app_state_root
                .join("gateway")
                .join("view-ledgers")
                .join(format!("{}.json", target.key()?)),
            GATEWAY_VIEW_LEDGER_SCHEMA_VERSION,
        ))
    }
}

fn activation_state_exists(
    app_state_root: &std::path::Path,
) -> Result<bool, GatewayNativeViewError> {
    let path = app_state_root.join("activations");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(GatewayNativeViewError::RecordContested)
        }
        Ok(_) => Ok(fs::read_dir(path)?.next().transpose()?.is_some()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn record_matches_target(record: &AdoptionRecord, target: &GatewayModeTarget) -> bool {
    target
        .repository_key
        .as_ref()
        .is_none_or(|repository| record.repository_key() == repository)
        && target
            .workspace_key
            .as_ref()
            .is_none_or(|workspace| record.workspace_key() == workspace)
        && target.provider.is_none_or(|provider| {
            record
                .catalog_record()
                .is_some_and(|catalog| catalog.supports_provider(provider))
        })
}

fn plan_entry(
    record: &AdoptionRecord,
    view: &AuthenticatedNativeView,
    desired: NativeViewState,
) -> Result<GatewayNativeViewPlanEntry, GatewayNativeViewError> {
    let catalog = record
        .catalog_record()
        .ok_or(GatewayNativeViewError::GatewayMetadataUnavailable)?;
    let mut provider_views = catalog
        .provider_views
        .iter()
        .map(|view| view.provider)
        .collect::<Vec<_>>();
    provider_views.sort();
    provider_views.dedup();
    let resource_ids = view
        .physical_resources()
        .iter()
        .map(|resource| resource.resource_id().to_string())
        .collect::<Vec<_>>();
    Ok(GatewayNativeViewPlanEntry {
        operation_id: record.operation_id().to_string(),
        capability_id: record.capability_id().to_string(),
        backup_id: record.backup_id().to_string(),
        repository_key: record.repository_key().to_string(),
        workspace_key: record.workspace_key().to_string(),
        provider_views,
        current: view.inspect()?,
        desired,
        resource_ids,
    })
}

fn ledger_message(ledger: &GatewayViewLedger) -> Result<Vec<u8>, GatewayNativeViewError> {
    let mut signable = ledger.clone();
    signable.tag.clear();
    serde_json::to_vec(&signable)
        .map_err(|error| GatewayNativeViewError::Serialization(error.to_string()))
}

fn plan_fingerprint(
    target: &GatewayModeTarget,
    action: GatewayModeAction,
    expected_ledger_revision: Option<&StateRevision>,
    entries: &[GatewayNativeViewPlanEntry],
) -> Result<String, GatewayNativeViewError> {
    let bytes = serde_json::to_vec(&(target, action, expected_ledger_revision, entries))
        .map_err(|error| GatewayNativeViewError::Serialization(error.to_string()))?;
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[derive(Debug)]
pub enum GatewayNativeViewError {
    Adoption(AdoptionError),
    View(AdoptionViewError),
    State(StateError),
    Io(String),
    Lease(super::LeaseError),
    GlobalScopeUnsupported,
    GatewayMetadataUnavailable,
    AmbiguousPhysicalView,
    RecordContested,
    LedgerContested,
    LedgerAuthenticationFailed,
    PlanFingerprintMismatch,
    TransitionFailed {
        capability_id: String,
        reason: String,
    },
    RecoveryRequired {
        capability_id: String,
        reason: String,
    },
    Serialization(String),
}

impl From<AdoptionError> for GatewayNativeViewError {
    fn from(error: AdoptionError) -> Self {
        Self::Adoption(error)
    }
}

impl From<AdoptionViewError> for GatewayNativeViewError {
    fn from(error: AdoptionViewError) -> Self {
        Self::View(error)
    }
}

impl From<StateError> for GatewayNativeViewError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<std::io::Error> for GatewayNativeViewError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<super::LeaseError> for GatewayNativeViewError {
    fn from(error: super::LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl fmt::Display for GatewayNativeViewError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adoption(error) => error.fmt(formatter),
            Self::View(error) => error.fmt(formatter),
            Self::State(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "gateway native-view I/O failed: {error}"),
            Self::Lease(error) => error.fmt(formatter),
            Self::GlobalScopeUnsupported => formatter.write_str(
                "global gateway native-view transition is unavailable; use repository or workspace scope",
            ),
            Self::GatewayMetadataUnavailable => {
                formatter.write_str("adopted view has no authenticated gateway metadata")
            }
            Self::AmbiguousPhysicalView => {
                formatter.write_str("multiple adoption records claim one provider view")
            }
            Self::RecordContested => formatter.write_str("adopted provider view is contested"),
            Self::LedgerContested => formatter.write_str("gateway native-view ledger is contested"),
            Self::LedgerAuthenticationFailed => {
                formatter.write_str("gateway native-view ledger authentication failed")
            }
            Self::PlanFingerprintMismatch => {
                formatter.write_str("gateway native-view plan changed after review")
            }
            Self::TransitionFailed {
                capability_id,
                reason,
            } => write!(
                formatter,
                "gateway native-view transition failed for {capability_id}: {reason}"
            ),
            Self::RecoveryRequired {
                capability_id,
                reason,
            } => write!(
                formatter,
                "gateway native-view recovery required for {capability_id}: {reason}"
            ),
            Self::Serialization(message) => {
                write!(formatter, "gateway native-view serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for GatewayNativeViewError {}
