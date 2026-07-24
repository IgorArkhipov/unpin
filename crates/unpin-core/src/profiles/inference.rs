use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};

use crate::{catalog::stable_hash, providers::ProviderId};

use super::{ProfileDefinitionEntry, ProfileSourceScope};

pub const PROFILE_PROPOSAL_SCHEMA_VERSION: u32 = 1;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_PROFILE_COUNT: usize = 4_096;
const MAX_CANDIDATES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProposalCandidate {
    pub profile_id: String,
    pub display_name: String,
    pub scope: ProfileSourceScope,
    pub score: u32,
    pub matched_terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileProposal {
    pub schema_version: u32,
    pub prompt_digest: String,
    pub repository_key: String,
    pub workspace_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ProviderId>,
    pub candidates: Vec<ProfileProposalCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended: Option<ProfileProposalCandidate>,
    pub proposal_fingerprint: String,
    pub confirmation_required: bool,
    pub mutates_state: bool,
    pub activation: String,
}

pub fn propose_profile(
    prompt: &str,
    repository_key: &str,
    workspace_key: &str,
    provider: Option<ProviderId>,
    profiles: impl IntoIterator<Item = ProfileDefinitionEntry>,
) -> Result<ProfileProposal, ProfileProposalError> {
    validate_prompt(prompt)?;
    validate_context_key(repository_key)?;
    validate_context_key(workspace_key)?;
    let prompt_tokens = tokens(prompt);
    if prompt_tokens.is_empty() {
        return Err(ProfileProposalError::PromptHasNoTerms);
    }

    let mut effective = BTreeMap::<String, ProfileDefinitionEntry>::new();
    for (index, profile) in profiles.into_iter().enumerate() {
        if index >= MAX_PROFILE_COUNT {
            return Err(ProfileProposalError::ProfileLimitExceeded);
        }
        let profile_id = profile.definition.id.clone();
        match effective.get(&profile_id) {
            Some(existing) if scope_rank(existing.scope) >= scope_rank(profile.scope) => {}
            _ => {
                effective.insert(profile_id, profile);
            }
        }
    }

    let mut candidates = effective
        .into_values()
        .filter_map(|entry| score_candidate(&prompt_tokens, entry))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.profile_id.cmp(&right.profile_id))
            .then_with(|| scope_rank(right.scope).cmp(&scope_rank(left.scope)))
    });
    candidates.truncate(MAX_CANDIDATES);
    let recommended = candidates.first().and_then(|candidate| {
        let unique = candidates
            .get(1)
            .is_none_or(|next| next.score < candidate.score);
        unique.then(|| candidate.clone())
    });
    let prompt_digest = stable_hash(prompt.as_bytes());
    let proposal_fingerprint = stable_hash(
        &serde_json::to_vec(&(
            PROFILE_PROPOSAL_SCHEMA_VERSION,
            &prompt_digest,
            repository_key,
            workspace_key,
            provider,
            &candidates,
            &recommended,
        ))
        .map_err(|error| ProfileProposalError::Serialization(error.to_string()))?,
    );
    Ok(ProfileProposal {
        schema_version: PROFILE_PROPOSAL_SCHEMA_VERSION,
        prompt_digest,
        repository_key: repository_key.to_string(),
        workspace_key: workspace_key.to_string(),
        provider,
        candidates,
        recommended,
        proposal_fingerprint,
        confirmation_required: true,
        mutates_state: false,
        activation: "session-only-after-explicit-launch".to_string(),
    })
}

fn score_candidate(
    prompt_tokens: &BTreeSet<String>,
    entry: ProfileDefinitionEntry,
) -> Option<ProfileProposalCandidate> {
    let id_terms = tokens(&entry.definition.id);
    let name_terms = tokens(&entry.definition.display_name);
    let description_terms = entry
        .definition
        .description
        .as_deref()
        .map(tokens)
        .unwrap_or_default();
    let mut matched_terms = BTreeSet::new();
    let mut score = 0_u32;
    for term in prompt_tokens {
        if id_terms.contains(term) {
            score = score.saturating_add(8);
            matched_terms.insert(term.clone());
        }
        if name_terms.contains(term) {
            score = score.saturating_add(4);
            matched_terms.insert(term.clone());
        }
        if description_terms.contains(term) {
            score = score.saturating_add(2);
            matched_terms.insert(term.clone());
        }
    }
    (score > 0).then(|| ProfileProposalCandidate {
        profile_id: entry.definition.id,
        display_name: entry.definition.display_name,
        scope: entry.scope,
        score,
        matched_terms: matched_terms.into_iter().collect(),
    })
}

fn validate_prompt(prompt: &str) -> Result<(), ProfileProposalError> {
    if prompt.trim().is_empty()
        || prompt.len() > MAX_PROMPT_BYTES
        || prompt
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        Err(ProfileProposalError::InvalidPrompt)
    } else {
        Ok(())
    }
}

fn validate_context_key(value: &str) -> Result<(), ProfileProposalError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(ProfileProposalError::InvalidContext)
    } else {
        Ok(())
    }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::trim)
        .filter(|term| term.len() >= 2)
        .map(str::to_ascii_lowercase)
        .filter(|term| !STOP_WORDS.contains(&term.as_str()))
        .collect()
}

const STOP_WORDS: &[&str] = &[
    "and", "for", "from", "into", "please", "that", "the", "this", "use", "with",
];

const fn scope_rank(scope: ProfileSourceScope) -> u8 {
    match scope {
        ProfileSourceScope::Global => 0,
        ProfileSourceScope::Repository => 1,
        ProfileSourceScope::Workspace => 2,
        ProfileSourceScope::Session => 3,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileProposalError {
    InvalidPrompt,
    PromptHasNoTerms,
    InvalidContext,
    ProfileLimitExceeded,
    Serialization(String),
}

impl fmt::Display for ProfileProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrompt => formatter.write_str("profile proposal prompt is invalid"),
            Self::PromptHasNoTerms => {
                formatter.write_str("profile proposal prompt has no routable terms")
            }
            Self::InvalidContext => formatter.write_str("profile proposal context is invalid"),
            Self::ProfileLimitExceeded => formatter.write_str("profile proposal limit exceeded"),
            Self::Serialization(_) => formatter.write_str("profile proposal serialization failed"),
        }
    }
}

impl std::error::Error for ProfileProposalError {}
