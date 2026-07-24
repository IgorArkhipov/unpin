use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    config::{get_global_policy_path, get_repository_policy_path, get_workspace_policy_state_path},
    profiles::{ResolutionPolicies, ScopePolicy},
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

const POLICY_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PolicyTarget {
    Global,
    Repository {
        repository_key: String,
    },
    Workspace {
        repository_key: String,
        workspace_key: String,
    },
}

impl PolicyTarget {
    pub fn repository(repository_key: impl Into<String>) -> Result<Self, PolicyStoreError> {
        let target = Self::Repository {
            repository_key: repository_key.into(),
        };
        target.validate()?;
        Ok(target)
    }

    pub fn workspace(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
    ) -> Result<Self, PolicyStoreError> {
        let target = Self::Workspace {
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
        };
        target.validate()?;
        Ok(target)
    }

    fn validate(&self) -> Result<(), PolicyStoreError> {
        match self {
            Self::Global => Ok(()),
            Self::Repository { repository_key } => {
                validate_identity("repository policy key", repository_key)
            }
            Self::Workspace {
                repository_key,
                workspace_key,
            } => {
                validate_identity("repository policy key", repository_key)?;
                validate_identity("workspace policy key", workspace_key)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    pub revision: StateRevision,
    pub owner: OwnerGeneration,
    pub policy: ScopePolicy,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    app_state_root: PathBuf,
}

impl PolicyStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn load(&self, target: &PolicyTarget) -> Result<Option<PolicySnapshot>, PolicyStoreError> {
        target.validate()?;
        self.store(target)?
            .load::<ScopePolicy>()
            .map(|snapshot| snapshot.map(policy_snapshot))
            .map_err(Into::into)
    }

    pub fn save(
        &self,
        target: &PolicyTarget,
        policy: &ScopePolicy,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, PolicyStoreError> {
        target.validate()?;
        self.store(target)?
            .compare_and_swap(expected, owner, policy)
            .map_err(Into::into)
    }

    pub(crate) fn restore_checkpoint(
        &self,
        target: &PolicyTarget,
        checkpoint: Option<&ScopePolicy>,
        applied_revision: &StateRevision,
        owner: OwnerGeneration,
    ) -> Result<(), PolicyStoreError> {
        let store = self.store(target)?;
        match checkpoint {
            Some(policy) => store
                .compare_and_swap(Some(applied_revision), owner, policy)
                .map(|_| ())
                .map_err(Into::into),
            None => store
                .remove_if_revision(applied_revision)
                .map_err(Into::into),
        }
    }

    pub fn load_resolution_policies(
        &self,
        repository_key: &str,
        workspace_key: &str,
        session: Option<ScopePolicy>,
    ) -> Result<ResolutionPolicies, PolicyStoreError> {
        let global = self
            .load(&PolicyTarget::Global)?
            .map_or_else(ScopePolicy::default, |snapshot| snapshot.policy);
        let repository = self
            .load(&PolicyTarget::repository(repository_key)?)?
            .map(|snapshot| snapshot.policy);
        let workspace = self
            .load(&PolicyTarget::workspace(repository_key, workspace_key)?)?
            .map(|snapshot| snapshot.policy);
        Ok(ResolutionPolicies {
            global,
            repository,
            workspace,
            session,
        })
    }

    fn store(&self, target: &PolicyTarget) -> Result<AtomicJsonStore, PolicyStoreError> {
        target.validate()?;
        let path = match target {
            PolicyTarget::Global => get_global_policy_path(&self.app_state_root),
            PolicyTarget::Repository { repository_key } => {
                get_repository_policy_path(&self.app_state_root, repository_key)
            }
            PolicyTarget::Workspace {
                repository_key,
                workspace_key,
            } => {
                get_workspace_policy_state_path(&self.app_state_root, repository_key, workspace_key)
            }
        };
        Ok(AtomicJsonStore::new(path, POLICY_STATE_SCHEMA_VERSION))
    }
}

fn policy_snapshot(snapshot: StateSnapshot<ScopePolicy>) -> PolicySnapshot {
    PolicySnapshot {
        revision: snapshot.revision,
        owner: snapshot.owner,
        policy: snapshot.value,
    }
}

fn validate_identity(label: &'static str, value: &str) -> Result<(), PolicyStoreError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(PolicyStoreError::InvalidIdentity { label })
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum PolicyStoreError {
    State(StateError),
    InvalidIdentity { label: &'static str },
}

impl From<StateError> for PolicyStoreError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for PolicyStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::InvalidIdentity { label } => write!(formatter, "invalid {label}"),
        }
    }
}

impl std::error::Error for PolicyStoreError {}
