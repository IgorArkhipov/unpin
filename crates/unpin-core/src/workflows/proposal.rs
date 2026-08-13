use std::{collections::BTreeSet, fmt};

use super::WorkflowDefinitionEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedWorkflowDefinition {
    pub entry: WorkflowDefinitionEntry,
    pub score: usize,
}

pub fn rank_workflow_definitions(
    prompt: &str,
    entries: impl IntoIterator<Item = WorkflowDefinitionEntry>,
) -> Result<Vec<RankedWorkflowDefinition>, WorkflowProposalError> {
    let terms = text_terms(prompt);
    if terms.is_empty() {
        return Err(WorkflowProposalError::NoRoutableTerms);
    }
    let mut ranked = entries
        .into_iter()
        .map(|entry| {
            let score = workflow_score(&entry, &terms);
            RankedWorkflowDefinition { entry, score }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.entry.definition.id.cmp(&right.entry.definition.id))
    });
    Ok(ranked)
}

fn workflow_score(entry: &WorkflowDefinitionEntry, terms: &BTreeSet<String>) -> usize {
    let mut text = format!(
        "{} {} {} {}",
        entry.definition.id,
        entry.definition.display_name,
        entry.definition.description.as_deref().unwrap_or_default(),
        entry.definition.entry_mode
    )
    .to_ascii_lowercase();
    text.push(' ');
    text.push_str(
        &entry
            .definition
            .modes
            .iter()
            .map(|mode| mode.name.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    );
    terms
        .iter()
        .filter(|term| text.contains(term.as_str()))
        .count()
}

fn text_terms(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|term| term.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowProposalError {
    NoRoutableTerms,
}

impl fmt::Display for WorkflowProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoutableTerms => {
                formatter.write_str("workflow proposal prompt has no routable terms")
            }
        }
    }
}

impl std::error::Error for WorkflowProposalError {}
