use unpin_core::{
    groups::{
        GroupDefinitionV1, GroupHistoryRecord, GroupRecord, GroupRevision, PersonalGroupStore,
        RepositoryGroupStore,
    },
    state::atomic_json::OwnerGeneration,
};

#[derive(Debug, Clone)]
pub(crate) enum ScopedGroupStore {
    Personal(PersonalGroupStore),
    Repository(RepositoryGroupStore),
}

impl ScopedGroupStore {
    pub(crate) fn create(
        &self,
        definition: &GroupDefinitionV1,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, String> {
        match self {
            Self::Personal(store) => store.create(definition, owner),
            Self::Repository(store) => store.create(definition, owner),
        }
        .map_err(|error| error.to_string())
    }

    pub(crate) fn replace(
        &self,
        definition: &GroupDefinitionV1,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, String> {
        match self {
            Self::Personal(store) => store.replace(definition, expected, owner),
            Self::Repository(store) => store.replace(definition, expected, owner),
        }
        .map_err(|error| error.to_string())
    }

    pub(crate) fn rename(
        &self,
        old_name: &str,
        new_name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, String> {
        match self {
            Self::Personal(store) => store.rename(old_name, new_name, expected, owner),
            Self::Repository(store) => store.rename(old_name, new_name, expected, owner),
        }
        .map_err(|error| error.to_string())
    }

    pub(crate) fn delete(
        &self,
        name: &str,
        expected: &GroupRevision,
        owner: OwnerGeneration,
    ) -> Result<GroupHistoryRecord, String> {
        match self {
            Self::Personal(store) => store.delete(name, expected, owner),
            Self::Repository(store) => store.delete(name, expected, owner),
        }
        .map_err(|error| error.to_string())
    }

    pub(crate) fn history(&self) -> Result<Vec<GroupHistoryRecord>, String> {
        match self {
            Self::Personal(store) => store.history(),
            Self::Repository(store) => store.history(),
        }
        .map_err(|error| error.to_string())
    }

    pub(crate) fn restore(
        &self,
        history_id: &str,
        expected: Option<&GroupRevision>,
        owner: OwnerGeneration,
    ) -> Result<GroupRecord, String> {
        match self {
            Self::Personal(store) => store.restore(history_id, expected, owner),
            Self::Repository(store) => store.restore(history_id, expected, owner),
        }
        .map_err(|error| error.to_string())
    }
}
