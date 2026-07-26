use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    catalog::{CapabilityKind, CatalogRecord, stable_hash},
    discovery::source_fingerprint,
};

use super::GatewayError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SkillMetadata {
    pub reference: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadedSkill {
    pub reference: String,
    pub name: String,
    pub body: String,
}

#[derive(Clone)]
struct SkillBinding {
    metadata: SkillMetadata,
    source_path: PathBuf,
    source_fingerprint: String,
}

#[derive(Clone)]
pub struct SkillRegistry {
    skills: BTreeMap<String, SkillBinding>,
    maximum_body_bytes: usize,
    maximum_query_bytes: usize,
    maximum_search_results: usize,
}

impl fmt::Debug for SkillRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SkillRegistry")
            .field("skill_count", &self.skills.len())
            .field("maximum_body_bytes", &self.maximum_body_bytes)
            .field("maximum_query_bytes", &self.maximum_query_bytes)
            .field("maximum_search_results", &self.maximum_search_results)
            .finish()
    }
}

impl SkillRegistry {
    pub(crate) fn compile(
        records: Vec<&CatalogRecord>,
        exposure_revision: &str,
        maximum_skills: usize,
        maximum_body_bytes: usize,
        maximum_query_bytes: usize,
        maximum_search_results: usize,
    ) -> Result<Self, GatewayError> {
        if records.len() > maximum_skills {
            return Err(GatewayError::InvalidExposure("skill limit exceeded"));
        }
        let mut references = BTreeSet::new();
        let mut skills = BTreeMap::new();
        for record in records {
            if record.kind != CapabilityKind::Skill {
                return Err(GatewayError::InvalidExposure("non-skill in skill registry"));
            }
            let expected_fingerprint =
                record
                    .origin
                    .source_fingerprint
                    .clone()
                    .ok_or(GatewayError::InvalidExposure(
                        "selected skill has no source fingerprint",
                    ))?;
            if !valid_source_fingerprint(&expected_fingerprint) {
                return Err(GatewayError::InvalidExposure(
                    "selected skill fingerprint is invalid",
                ));
            }
            if record.display_name.trim().is_empty()
                || record.display_name.len() > 512
                || record.display_name.chars().any(char::is_control)
            {
                return Err(GatewayError::InvalidExposure(
                    "selected skill metadata is invalid",
                ));
            }
            let reference = format!(
                "skill_{}",
                &stable_hash(
                    format!(
                        "unpin-skill-ref-v1\0{exposure_revision}\0{}\0{}",
                        record.id, record.fingerprint
                    )
                    .as_bytes()
                )[..24]
            );
            if !references.insert(reference.clone()) {
                return Err(GatewayError::InvalidExposure(
                    "selected skills have ambiguous references",
                ));
            }
            let metadata = SkillMetadata {
                reference: reference.clone(),
                name: record.display_name.clone(),
            };
            let source_path = canonical_skill_source(Path::new(&record.origin.source_path))?;
            skills.insert(
                reference,
                SkillBinding {
                    metadata,
                    source_path,
                    source_fingerprint: expected_fingerprint,
                },
            );
        }
        Ok(Self {
            skills,
            maximum_body_bytes,
            maximum_query_bytes,
            maximum_search_results,
        })
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SkillMetadata>, GatewayError> {
        if query.len() > self.maximum_query_bytes || limit == 0 {
            return Err(GatewayError::ArgumentsLimitExceeded);
        }
        let limit = limit.min(self.maximum_search_results);
        let terms = query
            .split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>();
        let mut matches = self
            .skills
            .values()
            .filter(|binding| {
                let name = binding.metadata.name.to_lowercase();
                terms.iter().all(|term| name.contains(term))
            })
            .map(|binding| binding.metadata.clone())
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.reference.cmp(&right.reference))
        });
        matches.truncate(limit);
        Ok(matches)
    }

    pub fn load(&self, reference: &str) -> Result<LoadedSkill, GatewayError> {
        let binding = self
            .skills
            .get(reference)
            .ok_or(GatewayError::CapabilityUnavailable)?;
        let body = read_pinned_skill(
            &binding.source_path,
            &binding.source_fingerprint,
            self.maximum_body_bytes,
        )?;
        Ok(LoadedSkill {
            reference: binding.metadata.reference.clone(),
            name: binding.metadata.name.clone(),
            body,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }
}

fn canonical_skill_source(source_path: &Path) -> Result<PathBuf, GatewayError> {
    let metadata =
        fs::symlink_metadata(source_path).map_err(|_| GatewayError::SkillContentInvalid)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(GatewayError::SkillContentInvalid);
    }
    fs::canonicalize(source_path).map_err(|_| GatewayError::SkillContentInvalid)
}

fn read_pinned_skill(
    source_path: &Path,
    expected_fingerprint: &str,
    maximum_bytes: usize,
) -> Result<String, GatewayError> {
    let path_metadata =
        fs::symlink_metadata(source_path).map_err(|_| GatewayError::SkillContentInvalid)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(GatewayError::SkillContentInvalid);
    }
    let canonical = fs::canonicalize(source_path).map_err(|_| GatewayError::SkillContentInvalid)?;
    if canonical != source_path {
        return Err(GatewayError::SkillContentInvalid);
    }
    let mut file = File::open(source_path).map_err(|_| GatewayError::SkillContentInvalid)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| GatewayError::SkillContentInvalid)?;
    if !crate::fs_support::path_matches_open_file(source_path, &file)
        .map_err(|_| GatewayError::SkillContentInvalid)?
        || opened_metadata.len() > maximum_bytes as u64
    {
        return Err(GatewayError::SkillContentInvalid);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| GatewayError::SkillContentInvalid)?;
    if bytes.len() > maximum_bytes {
        return Err(GatewayError::SkillContentInvalid);
    }
    let current_metadata =
        fs::symlink_metadata(source_path).map_err(|_| GatewayError::SkillContentInvalid)?;
    if current_metadata.file_type().is_symlink()
        || !current_metadata.is_file()
        || !crate::fs_support::path_matches_open_file(source_path, &file)
            .map_err(|_| GatewayError::SkillContentInvalid)?
    {
        return Err(GatewayError::SkillContentInvalid);
    }
    let body = String::from_utf8(bytes).map_err(|_| GatewayError::SkillContentInvalid)?;
    if source_fingerprint(&body) != expected_fingerprint {
        return Err(GatewayError::SkillContentChanged);
    }
    Ok(body)
}

fn valid_source_fingerprint(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
