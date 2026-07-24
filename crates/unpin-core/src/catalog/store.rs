use std::{collections::BTreeSet, fmt, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    catalog::{Catalog, stable_hash},
    config::{get_catalog_index_path, get_catalog_object_path},
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
};

const CATALOG_STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCatalogObject {
    digest: String,
    catalog: Catalog,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogIndex {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub object_digests: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMaterialization {
    pub digest: String,
    pub object_revision: StateRevision,
    pub index_revision: StateRevision,
}

#[derive(Debug, Clone)]
pub struct CatalogStore {
    app_state_root: PathBuf,
}

impl CatalogStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>) -> Self {
        Self {
            app_state_root: app_state_root.into(),
        }
    }

    pub fn materialize(
        &self,
        catalog: &Catalog,
        owner: OwnerGeneration,
    ) -> Result<CatalogMaterialization, CatalogStoreError> {
        let bytes =
            serde_json::to_vec(catalog).map_err(|error| CatalogStoreError::Serialization {
                message: error.to_string(),
            })?;
        let digest = stable_hash(&bytes);
        let object = StoredCatalogObject {
            digest: digest.clone(),
            catalog: catalog.clone(),
        };
        let object_store = AtomicJsonStore::new(
            get_catalog_object_path(&self.app_state_root, &digest),
            CATALOG_STATE_SCHEMA_VERSION,
        );
        let object_revision = match object_store.compare_and_swap(None, owner.clone(), &object) {
            Ok(revision) => revision,
            Err(StateError::StaleRevision { .. }) => {
                let snapshot = object_store.load::<StoredCatalogObject>()?.ok_or_else(|| {
                    CatalogStoreError::MissingObject {
                        digest: digest.clone(),
                    }
                })?;
                if snapshot.value != object {
                    return Err(CatalogStoreError::ImmutableCollision { digest });
                }
                snapshot.revision
            }
            Err(error) => return Err(error.into()),
        };

        let index_store = AtomicJsonStore::new(
            get_catalog_index_path(&self.app_state_root),
            CATALOG_STATE_SCHEMA_VERSION,
        );
        let current = index_store.load::<CatalogIndex>()?;
        let mut index = current
            .as_ref()
            .map(|snapshot| snapshot.value.clone())
            .unwrap_or_default();
        let already_current = index.latest_digest.as_deref() == Some(digest.as_str())
            && index.object_digests.contains(&digest);
        let index_revision = if already_current {
            current
                .expect("current catalog digest requires existing index")
                .revision
        } else {
            index.latest_digest = Some(digest.clone());
            index.object_digests.insert(digest.clone());
            index_store.compare_and_swap(
                current.as_ref().map(|snapshot| &snapshot.revision),
                owner,
                &index,
            )?
        };

        Ok(CatalogMaterialization {
            digest,
            object_revision,
            index_revision,
        })
    }

    pub fn load(&self, digest: &str) -> Result<Option<Catalog>, CatalogStoreError> {
        if !valid_digest(digest) {
            return Err(CatalogStoreError::InvalidDigest {
                digest: digest.to_string(),
            });
        }
        let store = AtomicJsonStore::new(
            get_catalog_object_path(&self.app_state_root, digest),
            CATALOG_STATE_SCHEMA_VERSION,
        );
        let Some(snapshot) = store.load::<StoredCatalogObject>()? else {
            return Ok(None);
        };
        if snapshot.value.digest != digest {
            return Err(CatalogStoreError::DigestMismatch {
                expected: digest.to_string(),
                actual: snapshot.value.digest,
            });
        }
        let actual = stable_hash(&serde_json::to_vec(&snapshot.value.catalog).map_err(
            |error| CatalogStoreError::Serialization {
                message: error.to_string(),
            },
        )?);
        if actual != digest {
            return Err(CatalogStoreError::DigestMismatch {
                expected: digest.to_string(),
                actual,
            });
        }
        Ok(Some(snapshot.value.catalog))
    }

    pub fn load_index(&self) -> Result<Option<StateSnapshot<CatalogIndex>>, CatalogStoreError> {
        AtomicJsonStore::new(
            get_catalog_index_path(&self.app_state_root),
            CATALOG_STATE_SCHEMA_VERSION,
        )
        .load()
        .map_err(Into::into)
    }
}

#[derive(Debug)]
pub enum CatalogStoreError {
    State(StateError),
    Serialization { message: String },
    InvalidDigest { digest: String },
    MissingObject { digest: String },
    ImmutableCollision { digest: String },
    DigestMismatch { expected: String, actual: String },
}

impl From<StateError> for CatalogStoreError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for CatalogStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Serialization { message } => {
                write!(formatter, "catalog serialization failed: {message}")
            }
            Self::InvalidDigest { digest } => {
                write!(formatter, "invalid catalog digest: {digest:?}")
            }
            Self::MissingObject { digest } => {
                write!(formatter, "catalog object disappeared: {digest}")
            }
            Self::ImmutableCollision { digest } => {
                write!(formatter, "catalog object digest collision: {digest}")
            }
            Self::DigestMismatch { expected, actual } => write!(
                formatter,
                "catalog digest mismatch: expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for CatalogStoreError {}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
