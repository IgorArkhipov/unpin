use super::WorkflowModeDefinition;

pub const GENERAL_MODE: &str = "general";
pub const PLANNING_MODE: &str = "planning";
pub const IMPLEMENTATION_MODE: &str = "implementation";
pub const REVIEW_MODE: &str = "review";
pub const PRESET_MODE_NAMES: [&str; 4] = [
    GENERAL_MODE,
    PLANNING_MODE,
    IMPLEMENTATION_MODE,
    REVIEW_MODE,
];

#[must_use]
pub fn preset_modes() -> Vec<WorkflowModeDefinition> {
    PRESET_MODE_NAMES
        .into_iter()
        .map(|name| WorkflowModeDefinition::new(name, name))
        .collect()
}
