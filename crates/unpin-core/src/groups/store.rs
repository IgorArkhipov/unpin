use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    clock::unix_nanos_id,
    config::get_workspace_groups_dir,
    groups::{
        GroupAccessContext, GroupChangeKind, GroupContextBinding, GroupDefinitionV1,
        GroupHistoryError, GroupHistoryRecord, GroupHistoryStore, GroupRecord, GroupRevision,
        GroupScope, GroupValidationError, valid_group_name,
    },
    mutation::BackupAuthenticationKey,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateResourceLock, StateRevision,
    },
};

const PERSONAL_GROUPS_STATE_SCHEMA_VERSION: u32 = 1;
const REPOSITORY_GROUPS_DOCUMENT_SCHEMA_VERSION: u8 = 1;
const MAX_GROUPS_DOCUMENT_BYTES: usize = 2 * 1024 * 1024;
const MAX_GROUPS_PER_SCOPE: usize = 256;
const MAX_CAS_ATTEMPTS: usize = 8;
pub const GROUP_DEFINITION_OWNER_ID: &str = "unpin-inventory-group";

#[must_use]
pub fn group_definition_change_fingerprint(
    effect_revision: &GroupRevision,
    preview: &serde_json::Value,
) -> String {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "purpose": "inventory-group-definition-change-v1",
        "effectRevision": effect_revision,
        "effect": preview,
    }))
    .expect("inventory group definition change value serializes");
    crate::encode_lower_hex(&Sha256::digest(bytes))
}

pub(crate) struct GroupDefinitionLock {
    _locks: Vec<StateResourceLock>,
}

pub(crate) fn acquire_group_definition_lock(
    context: &GroupAccessContext,
    scope: GroupScope,
    names: &[&str],
) -> Result<GroupDefinitionLock, StateError> {
    let mut lock_ids = names
        .iter()
        .map(|name| {
            let mut hasher = Sha256::new();
            hasher.update(b"unpin-inventory-group-definition-lock-v1\0");
            hasher.update(scope.as_str().as_bytes());
            hasher.update([0]);
            if scope == GroupScope::Repository {
                hasher.update(context.repository_key().as_bytes());
                hasher.update([0]);
            }
            hasher.update(name.as_bytes());
            crate::encode_lower_hex(&hasher.finalize())
        })
        .collect::<Vec<_>>();
    lock_ids.sort();
    lock_ids.dedup();
    let lock_root = context
        .app_state_root()
        .join("groups")
        .join("definition-locks");
    let mut locks = Vec::with_capacity(lock_ids.len());
    for lock_id in lock_ids {
        locks.push(StateResourceLock::acquire(
            lock_root.join(format!("{lock_id}.state")),
        )?);
    }
    Ok(GroupDefinitionLock { _locks: locks })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersonalGroupsDocument {
    #[serde(default)]
    groups: BTreeMap<String, PersonalGroupEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_history_transaction_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersonalGroupEntry {
    definition: GroupDefinitionV1,
    binding: GroupContextBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RepositoryGroupsDocument {
    schema_version: u8,
    groups: BTreeMap<String, GroupDefinitionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_history_transaction_id: Option<String>,
}

#[derive(Debug)]
struct RepositoryDocumentSnapshot {
    document: RepositoryGroupsDocument,
    fingerprint: String,
}

impl Default for RepositoryGroupsDocument {
    fn default() -> Self {
        Self {
            schema_version: REPOSITORY_GROUPS_DOCUMENT_SCHEMA_VERSION,
            groups: BTreeMap::new(),
            last_history_transaction_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PersonalGroupStore {
    context: GroupAccessContext,
    history_authentication_key: Option<BackupAuthenticationKey>,
}

impl PersonalGroupStore {
    #[must_use]
    pub fn new(context: GroupAccessContext) -> Self {
        Self {
            context,
            history_authentication_key: None,
        }
    }

    #[must_use]
    pub fn with_history_authentication_key(
        mut self,
        authentication_key: BackupAuthenticationKey,
    ) -> Self {
        self.history_authentication_key = Some(authentication_key);
        self
    }

    pub fn list(&self) -> Result<Vec<GroupRecord>, GroupStoreError> {
        let document = self
            .load_document()?
            .map_or_else(PersonalGroupsDocument::default, |snapshot| snapshot.0);
        document
            .groups
            .into_values()
            .map(|entry| {
                GroupRecord::new(GroupScope::Personal, entry.definition, entry.binding)
                    .map_err(Into::into)
            })
            .collect()
    }

    pub fn load(&self, name: &str) -> Result<Option<GroupRecord>, GroupStoreError> {
        valid_group_name(name)?;
        let Some((document, _)) = self.load_document()? else {
            return Ok(None);
        };
        document
            .groups
            .get(name)
            .cloned()
            .map(|entry| {
                GroupRecord::new(GroupScope::Personal, entry.definition, entry.binding)
                    .map_err(Into::into)
            })
            .transpose()
    }

    pub fn create(
        &self,
        definition: &GroupDefinitionV1,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        self.mutate(None, definition, None, GroupChangeKind::Create, owner)
    }

    pub fn replace(
        &self,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        self.mutate(
            Some(definition.name.as_str()),
            definition,
            expected,
            GroupChangeKind::Replace,
            owner,
        )
    }

    pub fn rename(
        &self,
        old_name: &str,
        new_name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        valid_group_name(old_name)?;
        valid_group_name(new_name)?;
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let _definition_lock = acquire_group_definition_lock(
            &self.context,
            GroupScope::Personal,
            &[old_name, new_name],
        )?;
        let mut last_stale = None;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let snapshot = self.load_document()?;
            let (mut document, state_revision) = snapshot.map_or_else(
                || (PersonalGroupsDocument::default(), None),
                |value| (value.0, Some(value.1)),
            );
            if document.groups.contains_key(new_name) {
                return Err(GroupStoreError::AlreadyExists(new_name.to_string()));
            }
            let old = document
                .groups
                .remove(old_name)
                .ok_or_else(|| GroupStoreError::NotFound(old_name.to_string()))?;
            ensure_binding_compatible(&self.context, &old.binding)?;
            verify_expected_personal(&old, expected)?;
            let mut definition = old.definition.clone();
            definition.name = new_name.to_string();
            definition.canonicalize_and_validate()?;
            let binding = self.context.binding_for_personal(&definition);
            let next = PersonalGroupEntry {
                definition: definition.clone(),
                binding: binding.clone(),
            };
            document.groups.insert(new_name.to_string(), next);
            let history = self.history_record(
                GroupChangeKind::Rename,
                Some(old.definition.clone()),
                Some(old.binding.clone()),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            document.last_history_transaction_id = Some(history.history_id.clone());
            let history_store = self.history_store();
            let prepared = history_store.prepare(&history, owner.clone())?;
            match self.save_document(&document, state_revision.as_ref(), owner.clone()) {
                Ok(_) => {
                    history_store.commit(&prepared)?;
                    return GroupRecord::new(GroupScope::Personal, definition, binding)
                        .map_err(Into::into);
                }
                Err(GroupStoreError::State(StateError::StaleRevision { .. })) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                    last_stale = Some(GroupStoreError::ConcurrentUpdate);
                }
                Err(error) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                    return Err(error);
                }
            }
        }
        Err(last_stale.unwrap_or(GroupStoreError::ConcurrentUpdate))
    }

    pub fn delete(
        &self,
        name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupHistoryRecord, GroupStoreError> {
        valid_group_name(name)?;
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let _definition_lock =
            acquire_group_definition_lock(&self.context, GroupScope::Personal, &[name])?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let Some((mut document, state_revision)) = self.load_document()? else {
                return Err(GroupStoreError::NotFound(name.to_string()));
            };
            let previous = document
                .groups
                .remove(name)
                .ok_or_else(|| GroupStoreError::NotFound(name.to_string()))?;
            ensure_binding_compatible(&self.context, &previous.binding)?;
            verify_expected_personal(&previous, expected)?;
            let history = self.history_record(
                GroupChangeKind::Delete,
                Some(previous.definition.clone()),
                Some(previous.binding.clone()),
                None,
                None,
            )?;
            document.last_history_transaction_id = Some(history.history_id.clone());
            let history_store = self.history_store();
            let prepared = history_store.prepare(&history, owner.clone())?;
            match self.save_document(&document, Some(&state_revision), owner.clone()) {
                Ok(_) => {
                    return history_store.commit(&prepared).map_err(Into::into);
                }
                Err(GroupStoreError::State(StateError::StaleRevision { .. })) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                }
                Err(error) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                    return Err(error);
                }
            }
        }
        Err(GroupStoreError::ConcurrentUpdate)
    }

    pub fn history(&self) -> Result<Vec<GroupHistoryRecord>, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        self.history_store().list().map_err(Into::into)
    }

    pub fn restore(
        &self,
        history_id: &str,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let history = self
            .history_store()
            .load(history_id)?
            .ok_or_else(|| GroupStoreError::HistoryNotFound(history_id.to_string()))?;
        if history.scope != GroupScope::Personal {
            return Err(GroupStoreError::HistoryScopeMismatch);
        }
        let definition = history
            .definition_before
            .clone()
            .ok_or(GroupStoreError::HistoryNotRestorable)?;
        let binding = history
            .binding_before
            .clone()
            .ok_or(GroupStoreError::HistoryNotRestorable)?;
        ensure_binding_compatible(&self.context, &binding)?;
        if self.context.binding_for_personal(&definition) != binding {
            return Err(GroupStoreError::ContextBindingMismatch);
        }
        let current_name = history
            .definition_after
            .as_ref()
            .map_or(definition.name.as_str(), |current| current.name.as_str());
        let _definition_lock = acquire_group_definition_lock(
            &self.context,
            GroupScope::Personal,
            &[current_name, definition.name.as_str()],
        )?;
        for _ in 0..MAX_CAS_ATTEMPTS {
            let snapshot = self.load_document()?;
            let (mut document, state_revision) = snapshot.map_or_else(
                || (PersonalGroupsDocument::default(), None),
                |value| (value.0, Some(value.1)),
            );
            let previous = if history.definition_after.is_some() {
                let previous = document
                    .groups
                    .remove(current_name)
                    .ok_or_else(|| GroupStoreError::NotFound(current_name.to_string()))?;
                ensure_binding_compatible(&self.context, &previous.binding)?;
                verify_expected_personal_optional(&previous, expected)?;
                Some(previous)
            } else {
                if expected.is_some() {
                    return Err(GroupStoreError::ExpectedRevisionRequired);
                }
                None
            };
            if current_name != definition.name && document.groups.contains_key(&definition.name) {
                return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
            }
            if previous.is_none() && document.groups.contains_key(&definition.name) {
                return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
            }
            document.groups.insert(
                definition.name.clone(),
                PersonalGroupEntry {
                    definition: definition.clone(),
                    binding: binding.clone(),
                },
            );
            let restore_history = self.history_record(
                GroupChangeKind::Restore,
                previous.as_ref().map(|entry| entry.definition.clone()),
                previous.as_ref().map(|entry| entry.binding.clone()),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            document.last_history_transaction_id = Some(restore_history.history_id.clone());
            let history_store = self.history_store();
            let prepared = history_store.prepare(&restore_history, owner.clone())?;
            match self.save_document(&document, state_revision.as_ref(), owner.clone()) {
                Ok(_) => {
                    history_store.commit(&prepared)?;
                    return GroupRecord::new(
                        GroupScope::Personal,
                        definition.clone(),
                        binding.clone(),
                    )
                    .map_err(Into::into);
                }
                Err(GroupStoreError::State(StateError::StaleRevision { .. })) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                }
                Err(error) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                    return Err(error);
                }
            }
        }
        Err(GroupStoreError::ConcurrentUpdate)
    }

    fn mutate(
        &self,
        existing_name: Option<&str>,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        change: GroupChangeKind,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        self.mutate_locked(existing_name, definition, expected, change, owner)
    }

    fn mutate_locked(
        &self,
        existing_name: Option<&str>,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        change: GroupChangeKind,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let mut definition = definition.clone();
        definition.canonicalize_and_validate()?;
        let key = existing_name.unwrap_or(&definition.name);
        let _definition_lock =
            acquire_group_definition_lock(&self.context, GroupScope::Personal, &[key])?;
        let binding = self.context.binding_for_personal(&definition);
        for _ in 0..MAX_CAS_ATTEMPTS {
            let snapshot = self.load_document()?;
            let (mut document, state_revision) = snapshot.map_or_else(
                || (PersonalGroupsDocument::default(), None),
                |value| (value.0, Some(value.1)),
            );
            if document.groups.len() >= MAX_GROUPS_PER_SCOPE
                && !document.groups.contains_key(&definition.name)
            {
                return Err(GroupStoreError::TooManyGroups);
            }
            let previous = document.groups.get(key).cloned();
            match (change, previous.as_ref()) {
                (GroupChangeKind::Create, Some(_)) => {
                    return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
                }
                (GroupChangeKind::Create, None) => {}
                (_, Some(previous)) => {
                    ensure_binding_compatible(&self.context, &previous.binding)?;
                    verify_expected_personal_optional(previous, expected)?;
                }
                (_, None) if expected.is_some() => {
                    return Err(GroupStoreError::NotFound(key.to_string()));
                }
                (_, None) => {}
            }
            document.groups.insert(
                definition.name.clone(),
                PersonalGroupEntry {
                    definition: definition.clone(),
                    binding: binding.clone(),
                },
            );
            let history = self.history_record(
                change,
                previous.as_ref().map(|entry| entry.definition.clone()),
                previous.as_ref().map(|entry| entry.binding.clone()),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            document.last_history_transaction_id = Some(history.history_id.clone());
            let history_store = self.history_store();
            let prepared = history_store.prepare(&history, owner.clone())?;
            match self.save_document(&document, state_revision.as_ref(), owner.clone()) {
                Ok(_) => {
                    history_store.commit(&prepared)?;
                    return GroupRecord::new(GroupScope::Personal, definition, binding)
                        .map_err(Into::into);
                }
                Err(GroupStoreError::State(StateError::StaleRevision { .. })) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                }
                Err(error) => {
                    self.reconcile_prepared_locked(&history_store, &prepared)?;
                    return Err(error);
                }
            }
        }
        Err(GroupStoreError::ConcurrentUpdate)
    }

    fn load_document(
        &self,
    ) -> Result<Option<(PersonalGroupsDocument, StateRevision)>, GroupStoreError> {
        let Some(snapshot) = self.store().load::<PersonalGroupsDocument>()? else {
            return Ok(None);
        };
        validate_personal_document(&snapshot.value)?;
        Ok(Some((snapshot.value, snapshot.revision)))
    }

    fn save_document(
        &self,
        document: &PersonalGroupsDocument,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, GroupStoreError> {
        validate_personal_document(document)?;
        self.store()
            .compare_and_swap(expected, owner, document)
            .map_err(Into::into)
    }

    fn store(&self) -> AtomicJsonStore {
        AtomicJsonStore::new(
            self.context
                .app_state_root()
                .join("groups")
                .join("groups.json"),
            PERSONAL_GROUPS_STATE_SCHEMA_VERSION,
        )
    }

    fn history_store(&self) -> GroupHistoryStore {
        let root = self
            .context
            .app_state_root()
            .join("groups")
            .join("history")
            .join("personal");
        match self.history_authentication_key.as_ref() {
            Some(key) => GroupHistoryStore::new_authenticated(root, key.clone()),
            None => GroupHistoryStore::new(root),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn history_record(
        &self,
        change: GroupChangeKind,
        definition_before: Option<GroupDefinitionV1>,
        binding_before: Option<GroupContextBinding>,
        definition_after: Option<GroupDefinitionV1>,
        binding_after: Option<GroupContextBinding>,
    ) -> Result<GroupHistoryRecord, GroupStoreError> {
        GroupHistoryRecord::new(
            GroupScope::Personal,
            change,
            definition_before,
            binding_before,
            definition_after,
            binding_after,
        )
        .map_err(Into::into)
    }

    fn history_transaction_lock(&self) -> Result<StateResourceLock, GroupStoreError> {
        StateResourceLock::acquire(
            self.context
                .app_state_root()
                .join("groups")
                .join("history-locks")
                .join("personal.state"),
        )
        .map_err(Into::into)
    }

    fn reconcile_history_locked(&self) -> Result<(), GroupStoreError> {
        let history_store = self.history_store();
        for pending in history_store.pending()? {
            if pending.record.scope != GroupScope::Personal {
                return Err(GroupStoreError::HistoryScopeMismatch);
            }
            self.reconcile_prepared_locked(&history_store, &pending)?;
        }
        Ok(())
    }

    fn reconcile_prepared_locked(
        &self,
        history_store: &GroupHistoryStore,
        prepared: &crate::groups::history::GroupHistorySnapshot,
    ) -> Result<(), GroupStoreError> {
        let transaction_applied = self.load_document()?.is_some_and(|(document, _)| {
            document.last_history_transaction_id.as_deref()
                == Some(prepared.record.history_id.as_str())
                && personal_document_matches_history_after(&document, &prepared.record)
        });
        if transaction_applied {
            history_store.commit(prepared)?;
        } else {
            history_store.abort(prepared)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RepositoryGroupStore {
    context: GroupAccessContext,
    history_authentication_key: Option<BackupAuthenticationKey>,
}

impl RepositoryGroupStore {
    #[must_use]
    pub fn new(context: GroupAccessContext) -> Self {
        Self {
            context,
            history_authentication_key: None,
        }
    }

    #[must_use]
    pub fn with_history_authentication_key(
        mut self,
        authentication_key: BackupAuthenticationKey,
    ) -> Self {
        self.history_authentication_key = Some(authentication_key);
        self
    }

    pub fn list(&self) -> Result<Vec<GroupRecord>, GroupStoreError> {
        self.verify_workspace_root()?;
        let document =
            read_repository_document(self.context.workspace_root(), &self.document_path())?
                .unwrap_or_default();
        document
            .groups
            .into_values()
            .map(|definition| {
                let binding = self.context.binding_for_repository(&definition);
                GroupRecord::new(GroupScope::Repository, definition, binding).map_err(Into::into)
            })
            .collect()
    }

    pub fn load(&self, name: &str) -> Result<Option<GroupRecord>, GroupStoreError> {
        valid_group_name(name)?;
        self.verify_workspace_root()?;
        let document =
            read_repository_document(self.context.workspace_root(), &self.document_path())?
                .unwrap_or_default();
        document
            .groups
            .get(name)
            .cloned()
            .map(|definition| {
                let binding = self.context.binding_for_repository(&definition);
                GroupRecord::new(GroupScope::Repository, definition, binding).map_err(Into::into)
            })
            .transpose()
    }

    pub fn create(
        &self,
        definition: &GroupDefinitionV1,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        self.mutate(None, definition, None, GroupChangeKind::Create, owner)
    }

    pub fn replace(
        &self,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        self.mutate(
            Some(definition.name.as_str()),
            definition,
            expected,
            GroupChangeKind::Replace,
            owner,
        )
    }

    pub fn rename(
        &self,
        old_name: &str,
        new_name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        valid_group_name(old_name)?;
        valid_group_name(new_name)?;
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let _definition_lock = acquire_group_definition_lock(
            &self.context,
            GroupScope::Repository,
            &[old_name, new_name],
        )?;
        self.with_locked_document(owner, |document| {
            if document.groups.contains_key(new_name) {
                return Err(GroupStoreError::AlreadyExists(new_name.to_string()));
            }
            let old = document
                .groups
                .remove(old_name)
                .ok_or_else(|| GroupStoreError::NotFound(old_name.to_string()))?;
            let old_binding = self.context.binding_for_repository(&old);
            verify_expected(&old, &old_binding, expected)?;
            let mut definition = old.clone();
            definition.name = new_name.to_string();
            definition.canonicalize_and_validate()?;
            let binding = self.context.binding_for_repository(&definition);
            document
                .groups
                .insert(new_name.to_string(), definition.clone());
            let history = GroupHistoryRecord::new(
                GroupScope::Repository,
                GroupChangeKind::Rename,
                Some(old),
                Some(old_binding),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            GroupRecord::new(GroupScope::Repository, definition, binding)
                .map(|record| (record, history))
                .map_err(Into::into)
        })
        .map(|(record, _)| record)
    }

    pub fn delete(
        &self,
        name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupHistoryRecord, GroupStoreError> {
        valid_group_name(name)?;
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let _definition_lock =
            acquire_group_definition_lock(&self.context, GroupScope::Repository, &[name])?;
        self.with_locked_document(owner, |document| {
            let previous = document
                .groups
                .remove(name)
                .ok_or_else(|| GroupStoreError::NotFound(name.to_string()))?;
            let binding = self.context.binding_for_repository(&previous);
            verify_expected(&previous, &binding, expected)?;
            let history = GroupHistoryRecord::new(
                GroupScope::Repository,
                GroupChangeKind::Delete,
                Some(previous),
                Some(binding),
                None,
                None,
            )?;
            Ok(((), history))
        })
        .map(|(_, history)| history)
    }

    pub fn history(&self) -> Result<Vec<GroupHistoryRecord>, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        self.history_store().list().map_err(Into::into)
    }

    pub fn restore(
        &self,
        history_id: &str,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        let history = self
            .history_store()
            .load(history_id)?
            .ok_or_else(|| GroupStoreError::HistoryNotFound(history_id.to_string()))?;
        if history.scope != GroupScope::Repository {
            return Err(GroupStoreError::HistoryScopeMismatch);
        }
        let definition = history
            .definition_before
            .clone()
            .ok_or(GroupStoreError::HistoryNotRestorable)?;
        let binding = self.context.binding_for_repository(&definition);
        if history.binding_before.as_ref() != Some(&binding) {
            return Err(GroupStoreError::ContextBindingMismatch);
        }
        let current_name = history
            .definition_after
            .as_ref()
            .map_or(definition.name.as_str(), |current| current.name.as_str());
        let _definition_lock = acquire_group_definition_lock(
            &self.context,
            GroupScope::Repository,
            &[current_name, definition.name.as_str()],
        )?;
        self.with_locked_document(owner, |document| {
            let previous = if history.definition_after.is_some() {
                let previous = document
                    .groups
                    .remove(current_name)
                    .ok_or_else(|| GroupStoreError::NotFound(current_name.to_string()))?;
                let previous_binding = self.context.binding_for_repository(&previous);
                verify_expected_optional(&previous, &previous_binding, expected)?;
                Some((previous, previous_binding))
            } else {
                if expected.is_some() {
                    return Err(GroupStoreError::ExpectedRevisionRequired);
                }
                None
            };
            if current_name != definition.name && document.groups.contains_key(&definition.name) {
                return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
            }
            if previous.is_none() && document.groups.contains_key(&definition.name) {
                return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
            }
            document
                .groups
                .insert(definition.name.clone(), definition.clone());
            let restore_history = GroupHistoryRecord::new(
                GroupScope::Repository,
                GroupChangeKind::Restore,
                previous.as_ref().map(|(definition, _)| definition.clone()),
                previous.as_ref().map(|(_, binding)| binding.clone()),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            GroupRecord::new(GroupScope::Repository, definition.clone(), binding.clone())
                .map(|record| (record, restore_history))
                .map_err(Into::into)
        })
        .map(|(record, _)| record)
    }

    fn mutate(
        &self,
        existing_name: Option<&str>,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        change: GroupChangeKind,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let _history_lock = self.history_transaction_lock()?;
        self.reconcile_history_locked()?;
        self.mutate_locked(existing_name, definition, expected, change, owner)
    }

    fn mutate_locked(
        &self,
        existing_name: Option<&str>,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        change: GroupChangeKind,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, GroupStoreError> {
        let mut definition = definition.clone();
        definition.canonicalize_and_validate()?;
        let key = existing_name.unwrap_or(&definition.name);
        let _definition_lock =
            acquire_group_definition_lock(&self.context, GroupScope::Repository, &[key])?;
        self.with_locked_document(owner, |document| {
            if document.groups.len() >= MAX_GROUPS_PER_SCOPE
                && !document.groups.contains_key(&definition.name)
            {
                return Err(GroupStoreError::TooManyGroups);
            }
            let previous = document.groups.get(key).cloned();
            match (change, previous.as_ref()) {
                (GroupChangeKind::Create, Some(_)) => {
                    return Err(GroupStoreError::AlreadyExists(definition.name.clone()));
                }
                (GroupChangeKind::Create, None) => {}
                (_, Some(previous)) => {
                    let binding = self.context.binding_for_repository(previous);
                    verify_expected_optional(previous, &binding, expected)?;
                }
                (_, None) if expected.is_some() => {
                    return Err(GroupStoreError::NotFound(key.to_string()));
                }
                (_, None) => {}
            }
            let binding = self.context.binding_for_repository(&definition);
            document
                .groups
                .insert(definition.name.clone(), definition.clone());
            let history = GroupHistoryRecord::new(
                GroupScope::Repository,
                change,
                previous.clone(),
                previous
                    .as_ref()
                    .map(|value| self.context.binding_for_repository(value)),
                Some(definition.clone()),
                Some(binding.clone()),
            )?;
            GroupRecord::new(GroupScope::Repository, definition.clone(), binding)
                .map(|record| (record, history))
                .map_err(Into::into)
        })
        .map(|(record, _)| record)
    }

    fn with_locked_document<T>(
        &self,
        owner: OwnerGeneration,
        mutate: impl FnOnce(
            &mut RepositoryGroupsDocument,
        ) -> Result<(T, GroupHistoryRecord), GroupStoreError>,
    ) -> Result<(T, GroupHistoryRecord), GroupStoreError> {
        self.verify_workspace_root()?;
        let directory = get_workspace_groups_dir(self.context.workspace_root());
        ensure_safe_directory_tree(self.context.workspace_root(), &directory)?;
        let lock_directory = self.context.app_state_root().join("groups").join("locks");
        ensure_private_lock_directory(&lock_directory)?;
        let _lock = StateResourceLock::acquire(
            lock_directory.join(format!("{}.lock", self.context.repository_key())),
        )?;
        self.verify_workspace_root()?;
        let path = self.document_path();
        let snapshot = read_repository_document_snapshot(self.context.workspace_root(), &path)?;
        let expected_fingerprint = snapshot
            .as_ref()
            .map(|snapshot| snapshot.fingerprint.clone());
        let mut document = snapshot
            .map(|snapshot| snapshot.document)
            .unwrap_or_default();
        let (value, history) = mutate(&mut document)?;
        document.last_history_transaction_id = Some(history.history_id.clone());
        validate_repository_document(&document)?;
        let history_store = self.history_store();
        let prepared = history_store.prepare(&history, owner)?;
        match write_repository_document_if_unchanged(
            self.context.workspace_root(),
            &path,
            &document,
            expected_fingerprint.as_deref(),
        ) {
            Ok(()) => {
                let committed = history_store.commit(&prepared)?;
                Ok((value, committed))
            }
            Err(error) => {
                self.reconcile_prepared_locked(&history_store, &prepared)?;
                Err(error)
            }
        }
    }

    fn verify_workspace_root(&self) -> Result<(), GroupStoreError> {
        let current = self.context.workspace_root().canonicalize()?;
        let current_identity = crate::state::workspace::resolve_workspace_identity(&current)
            .map_err(|_| GroupStoreError::WorkspaceRootChanged)?;
        if current != self.context.workspace_root()
            || current_identity.repository_key != self.context.repository_key()
            || current_identity.workspace_key != self.context.workspace_key()
            || !self.context.workspace_incarnation_matches()?
        {
            return Err(GroupStoreError::WorkspaceRootChanged);
        }
        Ok(())
    }

    fn document_path(&self) -> PathBuf {
        get_workspace_groups_dir(self.context.workspace_root()).join("groups.json")
    }

    fn history_store(&self) -> GroupHistoryStore {
        let root = self
            .context
            .app_state_root()
            .join("groups")
            .join("history")
            .join("repository")
            .join(self.context.repository_key())
            .join(self.context.workspace_key());
        match self.history_authentication_key.as_ref() {
            Some(key) => GroupHistoryStore::new_authenticated(root, key.clone()),
            None => GroupHistoryStore::new(root),
        }
    }

    fn history_transaction_lock(&self) -> Result<StateResourceLock, GroupStoreError> {
        StateResourceLock::acquire(
            self.context
                .app_state_root()
                .join("groups")
                .join("history-locks")
                .join("repository")
                .join(self.context.repository_key())
                .join(format!("{}.state", self.context.workspace_key())),
        )
        .map_err(Into::into)
    }

    fn reconcile_history_locked(&self) -> Result<(), GroupStoreError> {
        let history_store = self.history_store();
        let pending = history_store.pending()?;
        if pending.is_empty() {
            return Ok(());
        }
        self.verify_workspace_root()?;
        ensure_safe_directory_tree(
            self.context.workspace_root(),
            &get_workspace_groups_dir(self.context.workspace_root()),
        )?;
        for pending in pending {
            if pending.record.scope != GroupScope::Repository {
                return Err(GroupStoreError::HistoryScopeMismatch);
            }
            self.reconcile_prepared_locked(&history_store, &pending)?;
        }
        Ok(())
    }

    fn reconcile_prepared_locked(
        &self,
        history_store: &GroupHistoryStore,
        prepared: &crate::groups::history::GroupHistorySnapshot,
    ) -> Result<(), GroupStoreError> {
        let transaction_applied =
            read_repository_document(self.context.workspace_root(), &self.document_path())?
                .is_some_and(|document| {
                    document.last_history_transaction_id.as_deref()
                        == Some(prepared.record.history_id.as_str())
                        && repository_document_matches_history_after(
                            &self.context,
                            &document,
                            &prepared.record,
                        )
                });
        if transaction_applied {
            history_store.commit(prepared)?;
        } else {
            history_store.abort(prepared)?;
        }
        Ok(())
    }
}

fn validate_personal_document(document: &PersonalGroupsDocument) -> Result<(), GroupStoreError> {
    validate_document_definitions(
        document.groups.len(),
        document
            .groups
            .iter()
            .map(|(name, entry)| (name.as_str(), &entry.definition)),
    )
}

fn validate_repository_document(
    document: &RepositoryGroupsDocument,
) -> Result<(), GroupStoreError> {
    if document.schema_version != REPOSITORY_GROUPS_DOCUMENT_SCHEMA_VERSION {
        return Err(GroupStoreError::UnsupportedRepositorySchema(
            document.schema_version,
        ));
    }
    validate_document_definitions(
        document.groups.len(),
        document
            .groups
            .iter()
            .map(|(name, definition)| (name.as_str(), definition)),
    )
}

fn validate_document_definitions<'a>(
    count: usize,
    definitions: impl Iterator<Item = (&'a str, &'a GroupDefinitionV1)>,
) -> Result<(), GroupStoreError> {
    if count > MAX_GROUPS_PER_SCOPE {
        return Err(GroupStoreError::TooManyGroups);
    }
    for (name, definition) in definitions {
        if name != definition.name {
            return Err(GroupStoreError::DefinitionNameMismatch);
        }
        let mut definition = definition.clone();
        definition.canonicalize_and_validate()?;
    }
    Ok(())
}

fn verify_expected_personal(
    entry: &PersonalGroupEntry,
    expected: &GroupRevision,
) -> Result<(), GroupStoreError> {
    verify_expected(&entry.definition, &entry.binding, expected)
}

fn ensure_binding_compatible(
    context: &GroupAccessContext,
    binding: &GroupContextBinding,
) -> Result<(), GroupStoreError> {
    if context.is_binding_compatible(binding) {
        Ok(())
    } else {
        Err(GroupStoreError::ContextBindingMismatch)
    }
}

fn personal_document_matches_history_after(
    document: &PersonalGroupsDocument,
    history: &GroupHistoryRecord,
) -> bool {
    match (&history.definition_after, &history.binding_after) {
        (Some(definition), Some(binding)) => {
            document
                .groups
                .get(&definition.name)
                .is_some_and(|entry| entry.definition == *definition && entry.binding == *binding)
                && history.name_before.as_ref().is_none_or(|name_before| {
                    name_before == &definition.name || !document.groups.contains_key(name_before)
                })
        }
        (None, None) => history
            .name_before
            .as_ref()
            .is_some_and(|name| !document.groups.contains_key(name)),
        _ => false,
    }
}

fn repository_document_matches_history_after(
    context: &GroupAccessContext,
    document: &RepositoryGroupsDocument,
    history: &GroupHistoryRecord,
) -> bool {
    match (&history.definition_after, &history.binding_after) {
        (Some(definition), Some(binding)) => {
            document
                .groups
                .get(&definition.name)
                .is_some_and(|entry| entry == definition)
                && context.binding_for_repository(definition) == *binding
                && history.name_before.as_ref().is_none_or(|name_before| {
                    name_before == &definition.name || !document.groups.contains_key(name_before)
                })
        }
        (None, None) => history
            .name_before
            .as_ref()
            .is_some_and(|name| !document.groups.contains_key(name)),
        _ => false,
    }
}

fn verify_expected_personal_optional(
    entry: &PersonalGroupEntry,
    expected: Option<&GroupRevision>,
) -> Result<(), GroupStoreError> {
    let Some(expected) = expected else {
        return Err(GroupStoreError::ExpectedRevisionRequired);
    };
    verify_expected_personal(entry, expected)
}

fn verify_expected(
    definition: &GroupDefinitionV1,
    binding: &GroupContextBinding,
    expected: &GroupRevision,
) -> Result<(), GroupStoreError> {
    let actual = definition.revision(binding)?;
    if &actual != expected {
        return Err(GroupStoreError::StaleRevision {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

fn verify_expected_optional(
    definition: &GroupDefinitionV1,
    binding: &GroupContextBinding,
    expected: Option<&GroupRevision>,
) -> Result<(), GroupStoreError> {
    let Some(expected) = expected else {
        return Err(GroupStoreError::ExpectedRevisionRequired);
    };
    verify_expected(definition, binding, expected)
}

fn read_repository_document(
    workspace_root: &Path,
    path: &Path,
) -> Result<Option<RepositoryGroupsDocument>, GroupStoreError> {
    read_repository_document_snapshot(workspace_root, path)
        .map(|snapshot| snapshot.map(|snapshot| snapshot.document))
}

fn read_repository_document_snapshot(
    workspace_root: &Path,
    path: &Path,
) -> Result<Option<RepositoryDocumentSnapshot>, GroupStoreError> {
    let parent = path
        .parent()
        .ok_or(GroupStoreError::UnsafeRepositoryDocument)?;
    if !verify_safe_existing_directory_tree(workspace_root, parent)? {
        return Ok(None);
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_GROUPS_DOCUMENT_BYTES as u64
    {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    if current.file_type().is_symlink()
        || !current.is_file()
        || has_multiple_links(&file)?
        || !opened_file_matches_path(path, &file, &opened, &current)?
    {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_GROUPS_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if !verify_safe_existing_directory_tree(workspace_root, parent)? {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let reopened = read_bounded_regular_file(path)?;
    if reopened != bytes {
        return Err(GroupStoreError::ConcurrentUpdate);
    }
    if bytes.len() > MAX_GROUPS_DOCUMENT_BYTES {
        return Err(GroupStoreError::DocumentTooLarge);
    }
    let document: RepositoryGroupsDocument = serde_json::from_slice(&bytes)?;
    validate_repository_document(&document)?;
    Ok(Some(RepositoryDocumentSnapshot {
        document,
        fingerprint: crate::encode_lower_hex(&Sha256::digest(&bytes)),
    }))
}

#[cfg(test)]
fn write_repository_document(
    path: &Path,
    document: &RepositoryGroupsDocument,
) -> Result<(), GroupStoreError> {
    let workspace_root = path
        .ancestors()
        .nth(3)
        .ok_or(GroupStoreError::UnsafeRepositoryDocument)?;
    let expected_fingerprint = read_repository_document_snapshot(workspace_root, path)?
        .map(|snapshot| snapshot.fingerprint);
    write_repository_document_if_unchanged(
        workspace_root,
        path,
        document,
        expected_fingerprint.as_deref(),
    )
}

fn write_repository_document_if_unchanged(
    workspace_root: &Path,
    path: &Path,
    document: &RepositoryGroupsDocument,
    expected_fingerprint: Option<&str>,
) -> Result<(), GroupStoreError> {
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_GROUPS_DOCUMENT_BYTES {
        return Err(GroupStoreError::DocumentTooLarge);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(GroupStoreError::UnsafeRepositoryDocument);
        }
        Ok(_) => {
            let file = File::open(path)?;
            let opened = file.metadata()?;
            let current = fs::symlink_metadata(path)?;
            if has_multiple_links(&file)?
                || !opened_file_matches_path(path, &file, &opened, &current)?
            {
                return Err(GroupStoreError::UnsafeRepositoryDocument);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .ok_or(GroupStoreError::UnsafeRepositoryDocument)?;
    if !verify_safe_existing_directory_tree(workspace_root, parent)? {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let pinned_parent = directory_identity(parent)?;
    let temporary = parent.join(format!(
        ".groups.{}.tmp",
        unix_nanos_id("write").map_err(GroupStoreError::Clock)?
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    if !verify_safe_existing_directory_tree(workspace_root, parent)?
        || pinned_parent != directory_identity(parent)?
    {
        let _ = fs::remove_file(&temporary);
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let actual_fingerprint = read_repository_document_snapshot(workspace_root, path)?
        .map(|snapshot| snapshot.fingerprint);
    if actual_fingerprint.as_deref() != expected_fingerprint {
        let _ = fs::remove_file(&temporary);
        return Err(GroupStoreError::ConcurrentUpdate);
    }
    // `std::fs` cannot bind this rename to an opened directory handle on every supported
    // platform. The repository store therefore pins and rechecks the physical parent before
    // publication, verifies the exact document revision immediately before the rename, and
    // rechecks the parent afterward. A hostile same-user process racing inside that final
    // pathname operation is outside this cooperative local-writer boundary.
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if !verify_safe_existing_directory_tree(workspace_root, parent)?
        || pinned_parent != directory_identity(parent)?
    {
        return Err(GroupStoreError::WorkspaceRootChanged);
    }
    sync_directory(parent)?;
    Ok(())
}

fn ensure_safe_directory_tree(root: &Path, directory: &Path) -> Result<(), GroupStoreError> {
    if !directory.starts_with(root) {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| GroupStoreError::UnsafeRepositoryDocument)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(GroupStoreError::UnsafeRepositoryDocument);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn verify_safe_existing_directory_tree(
    root: &Path,
    directory: &Path,
) -> Result<bool, GroupStoreError> {
    if !directory.starts_with(root) {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let root_metadata = fs::symlink_metadata(root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| GroupStoreError::UnsafeRepositoryDocument)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(GroupStoreError::UnsafeRepositoryDocument);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

fn read_bounded_regular_file(path: &Path) -> Result<Vec<u8>, GroupStoreError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > MAX_GROUPS_DOCUMENT_BYTES as u64
        || has_multiple_links(&file)?
        || !opened_file_matches_path(path, &file, &metadata, &fs::symlink_metadata(path)?)?
    {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_GROUPS_DOCUMENT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_GROUPS_DOCUMENT_BYTES {
        return Err(GroupStoreError::DocumentTooLarge);
    }
    Ok(bytes)
}

fn ensure_private_lock_directory(path: &Path) -> Result<(), GroupStoreError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn has_multiple_links(file: &File) -> Result<bool, GroupStoreError> {
    use std::os::unix::fs::MetadataExt;

    Ok(file.metadata()?.nlink() != 1)
}

#[cfg(windows)]
fn has_multiple_links(file: &File) -> Result<bool, GroupStoreError> {
    crate::fs_support::windows_file_identity(file)
        .map(|identity| identity.number_of_links != 1)
        .map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
fn has_multiple_links(_file: &File) -> Result<bool, GroupStoreError> {
    Ok(false)
}

#[cfg(any(unix, windows))]
fn opened_file_matches_path(
    path: &Path,
    file: &File,
    _opened: &fs::Metadata,
    _current: &fs::Metadata,
) -> Result<bool, GroupStoreError> {
    crate::fs_support::path_matches_open_file(path, file).map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
fn opened_file_matches_path(
    _path: &Path,
    _file: &File,
    opened: &fs::Metadata,
    current: &fs::Metadata,
) -> Result<bool, GroupStoreError> {
    Ok(opened.len() == current.len()
        && opened.created().ok() == current.created().ok()
        && opened.modified().ok() == current.modified().ok())
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, GroupStoreError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
type DirectoryIdentity = crate::fs_support::WindowsFileIdentity;

#[cfg(windows)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, GroupStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    crate::fs_support::windows_path_identity(path).map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentity {
    created: Option<std::time::SystemTime>,
    modified: Option<std::time::SystemTime>,
}

#[cfg(not(any(unix, windows)))]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, GroupStoreError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(GroupStoreError::UnsafeRepositoryDocument);
    }
    Ok(DirectoryIdentity {
        created: metadata.created().ok(),
        modified: metadata.modified().ok(),
    })
}

fn sync_directory(path: &Path) -> Result<(), GroupStoreError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug)]
pub enum GroupStoreError {
    State(StateError),
    History(GroupHistoryError),
    Validation(GroupValidationError),
    Io(std::io::Error),
    Json(serde_json::Error),
    AlreadyExists(String),
    NotFound(String),
    ExpectedRevisionRequired,
    StaleRevision {
        expected: GroupRevision,
        actual: GroupRevision,
    },
    ConcurrentUpdate,
    TooManyGroups,
    DefinitionNameMismatch,
    UnsupportedRepositorySchema(u8),
    UnsafeRepositoryDocument,
    DocumentTooLarge,
    WorkspaceRootChanged,
    HistoryNotFound(String),
    HistoryScopeMismatch,
    HistoryNotRestorable,
    ContextBindingMismatch,
    Clock(String),
}

impl From<StateError> for GroupStoreError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl From<GroupHistoryError> for GroupStoreError {
    fn from(error: GroupHistoryError) -> Self {
        Self::History(error)
    }
}

impl From<GroupValidationError> for GroupStoreError {
    fn from(error: GroupValidationError) -> Self {
        Self::Validation(error)
    }
}

impl From<std::io::Error> for GroupStoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for GroupStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl fmt::Display for GroupStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::History(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "group store I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "group store JSON failed: {error}"),
            Self::AlreadyExists(name) => write!(formatter, "group already exists: {name}"),
            Self::NotFound(name) => write!(formatter, "group was not found: {name}"),
            Self::ExpectedRevisionRequired => {
                formatter.write_str("expected group revision is required")
            }
            Self::StaleRevision { expected, actual } => {
                write!(
                    formatter,
                    "stale group revision: expected {expected}, found {actual}"
                )
            }
            Self::ConcurrentUpdate => formatter.write_str("group document changed concurrently"),
            Self::TooManyGroups => formatter.write_str("group scope contains too many groups"),
            Self::DefinitionNameMismatch => {
                formatter.write_str("group definition name does not match its document key")
            }
            Self::UnsupportedRepositorySchema(version) => {
                write!(formatter, "unsupported repository group schema: {version}")
            }
            Self::UnsafeRepositoryDocument => {
                formatter.write_str("repository group document is not a safe regular file")
            }
            Self::DocumentTooLarge => formatter.write_str("group document exceeds its size limit"),
            Self::WorkspaceRootChanged => {
                formatter.write_str("trusted workspace root identity changed")
            }
            Self::HistoryNotFound(history_id) => {
                write!(
                    formatter,
                    "group history record was not found: {history_id}"
                )
            }
            Self::HistoryScopeMismatch => {
                formatter.write_str("group history record belongs to another scope")
            }
            Self::HistoryNotRestorable => {
                formatter.write_str("group history record has no prior definition to restore")
            }
            Self::ContextBindingMismatch => {
                formatter.write_str("group is bound to a different trusted workspace")
            }
            Self::Clock(error) => write!(formatter, "group store clock failed: {error}"),
        }
    }
}

impl std::error::Error for GroupStoreError {}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        config::{UnpinConfig, UnpinConfigPaths},
        discovery::{DiscoveryCategory, DiscoveryKind, DiscoveryLayer, DiscoveryRoots, ProviderId},
        groups::GroupMemberIdentity,
    };

    fn context(root: &TempDir) -> GroupAccessContext {
        context_for_workspace(root, "workspace")
    }

    fn context_for_workspace(root: &TempDir, workspace_name: &str) -> GroupAccessContext {
        let workspace = root.path().join(workspace_name);
        let app_state = root.path().join("state");
        fs::create_dir_all(workspace.join(".git")).expect("workspace");
        fs::create_dir_all(&app_state).expect("app state");
        let config = UnpinConfig {
            version: 1,
            app_state_root: app_state,
            cursor_root: root.path().join("cursor"),
            project_root: workspace,
            config_paths: UnpinConfigPaths {
                user_config_path: root.path().join("user.json"),
                project_config_path: root.path().join("project.json"),
            },
        };
        let roots =
            DiscoveryRoots::fixture_root(root.path()).with_app_state_root(&config.app_state_root);
        GroupAccessContext::from_config(&config, &roots, None, None).expect("group context")
    }

    fn context_for_linked_workspace(
        root: &TempDir,
        common_git_directory: &Path,
        workspace_name: &str,
    ) -> GroupAccessContext {
        let workspace = root.path().join(workspace_name);
        let git_worktree_directory = common_git_directory.join("worktrees").join(workspace_name);
        let app_state = root.path().join("state");
        fs::create_dir_all(&workspace).expect("workspace");
        fs::create_dir_all(&git_worktree_directory).expect("Git worktree directory");
        fs::create_dir_all(&app_state).expect("app state");
        fs::write(
            workspace.join(".git"),
            format!("gitdir: {}\n", git_worktree_directory.display()),
        )
        .expect("Git worktree marker");
        fs::write(git_worktree_directory.join("commondir"), "../..\n")
            .expect("Git common directory marker");
        let config = UnpinConfig {
            version: 1,
            app_state_root: app_state,
            cursor_root: root.path().join("cursor"),
            project_root: workspace,
            config_paths: UnpinConfigPaths {
                user_config_path: root.path().join("user.json"),
                project_config_path: root.path().join("project.json"),
            },
        };
        let roots =
            DiscoveryRoots::fixture_root(root.path()).with_app_state_root(&config.app_state_root);
        GroupAccessContext::from_config(&config, &roots, None, None)
            .expect("linked-worktree group context")
    }

    fn definition(name: &str) -> GroupDefinitionV1 {
        GroupDefinitionV1::new(
            name,
            vec![
                GroupMemberIdentity::new(
                    ProviderId::Codex,
                    DiscoveryKind::Skill,
                    DiscoveryCategory::Skill,
                    DiscoveryLayer::Global,
                    format!("codex:global:skill:{name}"),
                )
                .expect("member"),
            ],
        )
        .expect("definition")
    }

    fn project_definition(name: &str) -> GroupDefinitionV1 {
        GroupDefinitionV1::new(
            name,
            vec![
                GroupMemberIdentity::new(
                    ProviderId::Codex,
                    DiscoveryKind::Skill,
                    DiscoveryCategory::Skill,
                    DiscoveryLayer::Project,
                    format!("codex:project:skill:{name}"),
                )
                .expect("member"),
            ],
        )
        .expect("definition")
    }

    fn prepared_create(
        scope: GroupScope,
        definition: &GroupDefinitionV1,
        binding: GroupContextBinding,
    ) -> GroupHistoryRecord {
        GroupHistoryRecord::new(
            scope,
            GroupChangeKind::Create,
            None,
            None,
            Some(definition.clone()),
            Some(binding),
        )
        .expect("history record")
    }

    fn owner() -> OwnerGeneration {
        OwnerGeneration::new("group-history-test", 1).expect("owner")
    }

    #[test]
    fn personal_prepared_history_without_definition_marker_is_aborted_and_hidden() {
        let root = TempDir::new().expect("tempdir");
        let store = PersonalGroupStore::new(context(&root));
        let history = prepared_create(
            GroupScope::Personal,
            &definition("personal-abort"),
            GroupContextBinding::Global,
        );
        store
            .history_store()
            .prepare(&history, owner())
            .expect("prepare history");

        assert!(store.history().expect("reconciled history").is_empty());
        assert!(
            store
                .history_store()
                .pending()
                .expect("pending history")
                .is_empty()
        );
    }

    #[test]
    fn personal_definition_marker_recovers_unfinalized_history_as_committed() {
        let root = TempDir::new().expect("tempdir");
        let store = PersonalGroupStore::new(context(&root));
        let definition = definition("personal-commit");
        let history = prepared_create(
            GroupScope::Personal,
            &definition,
            GroupContextBinding::Global,
        );
        store
            .history_store()
            .prepare(&history, owner())
            .expect("prepare history");
        let mut document = PersonalGroupsDocument::default();
        document.groups.insert(
            definition.name.clone(),
            PersonalGroupEntry {
                definition,
                binding: GroupContextBinding::Global,
            },
        );
        document.last_history_transaction_id = Some(history.history_id.clone());
        store
            .save_document(&document, None, owner())
            .expect("definition commit");

        let records = store.history().expect("reconciled history");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].history_id, history.history_id);
        assert!(
            store
                .history_store()
                .pending()
                .expect("pending history")
                .is_empty()
        );
    }

    #[test]
    fn repository_prepared_history_without_definition_marker_is_aborted_and_hidden() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let definition = definition("repository-abort");
        let history = prepared_create(
            GroupScope::Repository,
            &definition,
            store.context.binding_for_repository(&definition),
        );
        store
            .history_store()
            .prepare(&history, owner())
            .expect("prepare history");

        assert!(store.history().expect("reconciled history").is_empty());
        assert!(
            store
                .history_store()
                .pending()
                .expect("pending history")
                .is_empty()
        );
    }

    #[test]
    fn repository_definition_marker_recovers_unfinalized_history_as_committed() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let definition = definition("repository-commit");
        let history = prepared_create(
            GroupScope::Repository,
            &definition,
            store.context.binding_for_repository(&definition),
        );
        store
            .history_store()
            .prepare(&history, owner())
            .expect("prepare history");
        let directory = get_workspace_groups_dir(store.context.workspace_root());
        ensure_safe_directory_tree(store.context.workspace_root(), &directory)
            .expect("repository group directory");
        let mut document = RepositoryGroupsDocument::default();
        document.groups.insert(definition.name.clone(), definition);
        document.last_history_transaction_id = Some(history.history_id.clone());
        write_repository_document(&store.document_path(), &document).expect("definition commit");

        let records = store.history().expect("reconciled history");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].history_id, history.history_id);
        assert!(
            store
                .history_store()
                .pending()
                .expect("pending history")
                .is_empty()
        );
    }

    #[test]
    fn repository_history_recovery_is_isolated_between_linked_workspaces() {
        let root = TempDir::new().expect("tempdir");
        let common_git_directory = root.path().join("common.git");
        fs::create_dir_all(common_git_directory.join("worktrees")).expect("Git common directory");
        let first_context =
            context_for_linked_workspace(&root, &common_git_directory, "workspace-a");
        let second_context =
            context_for_linked_workspace(&root, &common_git_directory, "workspace-b");
        assert_eq!(
            first_context.repository_key(),
            second_context.repository_key()
        );
        assert_ne!(
            first_context.workspace_key(),
            second_context.workspace_key()
        );
        let first = RepositoryGroupStore::new(first_context);
        let second = RepositoryGroupStore::new(second_context);
        let definition = definition("workspace-isolated-history");
        let history = prepared_create(
            GroupScope::Repository,
            &definition,
            first.context.binding_for_repository(&definition),
        );
        first
            .history_store()
            .prepare(&history, owner())
            .expect("prepare first-workspace history");

        assert!(
            second
                .history()
                .expect("second-workspace history")
                .is_empty()
        );
        let pending = first
            .history_store()
            .pending()
            .expect("first-workspace pending history");
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].record.history_id, history.history_id);
    }

    #[test]
    fn personal_mutations_reject_an_incompatible_workspace_binding() {
        let root = TempDir::new().expect("tempdir");
        let original = PersonalGroupStore::new(context_for_workspace(&root, "workspace-a"));
        let incompatible = PersonalGroupStore::new(context_for_workspace(&root, "workspace-b"));
        let created = original
            .create(&project_definition("workspace-only"), owner())
            .expect("create workspace-bound group");

        assert!(matches!(
            incompatible.replace(
                &project_definition("workspace-only"),
                Some(&created.revision),
                owner()
            ),
            Err(GroupStoreError::ContextBindingMismatch)
        ));
        assert!(matches!(
            incompatible.rename("workspace-only", "renamed", &created.revision, owner()),
            Err(GroupStoreError::ContextBindingMismatch)
        ));
        assert!(matches!(
            incompatible.delete("workspace-only", &created.revision, owner()),
            Err(GroupStoreError::ContextBindingMismatch)
        ));
    }

    #[test]
    fn restoring_a_personal_rename_replaces_the_renamed_definition_atomically() {
        let root = TempDir::new().expect("tempdir");
        let store = PersonalGroupStore::new(context(&root));
        let created = store
            .create(&definition("before"), owner())
            .expect("create group");
        let renamed = store
            .rename("before", "after", &created.revision, owner())
            .expect("rename group");
        let rename_history = store
            .history()
            .expect("history")
            .into_iter()
            .find(|record| record.change == GroupChangeKind::Rename)
            .expect("rename history");

        let restored = store
            .restore(&rename_history.history_id, Some(&renamed.revision), owner())
            .expect("restore rename");

        assert_eq!(restored.definition.name, "before");
        assert!(store.load("before").expect("load before").is_some());
        assert!(store.load("after").expect("load after").is_none());
    }

    #[test]
    fn restoring_a_repository_rename_replaces_the_renamed_definition_atomically() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let created = store
            .create(&definition("before"), owner())
            .expect("create group");
        let renamed = store
            .rename("before", "after", &created.revision, owner())
            .expect("rename group");
        let rename_history = store
            .history()
            .expect("history")
            .into_iter()
            .find(|record| record.change == GroupChangeKind::Rename)
            .expect("rename history");

        let restored = store
            .restore(&rename_history.history_id, Some(&renamed.revision), owner())
            .expect("restore rename");

        assert_eq!(restored.definition.name, "before");
        assert!(store.load("before").expect("load before").is_some());
        assert!(store.load("after").expect("load after").is_none());
    }

    #[test]
    fn repository_history_marker_without_exact_after_state_is_aborted() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let expected_definition = definition("expected");
        let history = prepared_create(
            GroupScope::Repository,
            &expected_definition,
            store.context.binding_for_repository(&expected_definition),
        );
        store
            .history_store()
            .prepare(&history, owner())
            .expect("prepare history");
        let directory = get_workspace_groups_dir(store.context.workspace_root());
        ensure_safe_directory_tree(store.context.workspace_root(), &directory)
            .expect("repository group directory");
        let mut document = RepositoryGroupsDocument::default();
        let unexpected = definition("unexpected");
        document.groups.insert(unexpected.name.clone(), unexpected);
        document.last_history_transaction_id = Some(history.history_id.clone());
        write_repository_document(&store.document_path(), &document).expect("definition commit");

        assert!(store.history().expect("reconciled history").is_empty());
        assert!(
            store
                .history_store()
                .pending()
                .expect("pending history")
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_document_symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let directory = get_workspace_groups_dir(store.context.workspace_root());
        ensure_safe_directory_tree(store.context.workspace_root(), &directory)
            .expect("repository group directory");
        let outside_root = TempDir::new().expect("outside tempdir");
        let outside = outside_root.path().join("outside-groups.json");
        fs::write(&outside, b"{\"schemaVersion\":1,\"groups\":{}}\n").expect("outside document");
        symlink(&outside, store.document_path()).expect("repository document symlink");

        assert!(matches!(
            store.list(),
            Err(GroupStoreError::UnsafeRepositoryDocument)
        ));
        assert_eq!(
            fs::read_to_string(&outside).expect("outside document remains readable"),
            "{\"schemaVersion\":1,\"groups\":{}}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repository_document_hard_link_is_rejected() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let directory = get_workspace_groups_dir(store.context.workspace_root());
        ensure_safe_directory_tree(store.context.workspace_root(), &directory)
            .expect("repository group directory");
        let outside_root = TempDir::new().expect("outside tempdir");
        let outside = outside_root.path().join("outside-groups.json");
        fs::write(&outside, b"{\"schemaVersion\":1,\"groups\":{}}\n").expect("outside document");
        fs::hard_link(&outside, store.document_path()).expect("repository document hard link");

        assert!(matches!(
            store.list(),
            Err(GroupStoreError::UnsafeRepositoryDocument)
        ));
    }

    #[test]
    fn repository_document_replace_rejects_a_stale_content_fingerprint() {
        let root = TempDir::new().expect("tempdir");
        let store = RepositoryGroupStore::new(context(&root));
        let directory = get_workspace_groups_dir(store.context.workspace_root());
        ensure_safe_directory_tree(store.context.workspace_root(), &directory)
            .expect("repository group directory");
        let mut original = RepositoryGroupsDocument::default();
        let original_definition = definition("original");
        original
            .groups
            .insert(original_definition.name.clone(), original_definition);
        write_repository_document(&store.document_path(), &original).expect("write original");
        let stale_fingerprint = read_repository_document_snapshot(
            store.context.workspace_root(),
            &store.document_path(),
        )
        .expect("read original")
        .expect("original snapshot")
        .fingerprint;

        let mut concurrent = RepositoryGroupsDocument::default();
        let concurrent_definition = definition("concurrent");
        concurrent
            .groups
            .insert(concurrent_definition.name.clone(), concurrent_definition);
        write_repository_document(&store.document_path(), &concurrent).expect("concurrent write");

        let mut stale = RepositoryGroupsDocument::default();
        let stale_definition = definition("stale");
        stale
            .groups
            .insert(stale_definition.name.clone(), stale_definition);
        assert!(matches!(
            write_repository_document_if_unchanged(
                store.context.workspace_root(),
                &store.document_path(),
                &stale,
                Some(stale_fingerprint.as_str()),
            ),
            Err(GroupStoreError::ConcurrentUpdate)
        ));
        assert_eq!(
            read_repository_document(store.context.workspace_root(), &store.document_path())
                .expect("read current")
                .expect("current document"),
            concurrent
        );
    }
}
