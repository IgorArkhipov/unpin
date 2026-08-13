use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowControlEffect {
    ReadOnly,
    NonExpandingMutation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowControl {
    UnpinWorkflowStatus,
    UnpinWorkflowModes,
    UnpinWorkflowEnterMode,
    UnpinWorkflowCancelTransition,
}

impl WorkflowControl {
    pub const ALL: [Self; 4] = [
        Self::UnpinWorkflowStatus,
        Self::UnpinWorkflowModes,
        Self::UnpinWorkflowEnterMode,
        Self::UnpinWorkflowCancelTransition,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnpinWorkflowStatus => "unpin_workflow_status",
            Self::UnpinWorkflowModes => "unpin_workflow_modes",
            Self::UnpinWorkflowEnterMode => "unpin_workflow_enter_mode",
            Self::UnpinWorkflowCancelTransition => "unpin_workflow_cancel_transition",
        }
    }

    #[must_use]
    pub const fn effect(self) -> WorkflowControlEffect {
        match self {
            Self::UnpinWorkflowStatus | Self::UnpinWorkflowModes => WorkflowControlEffect::ReadOnly,
            Self::UnpinWorkflowEnterMode | Self::UnpinWorkflowCancelTransition => {
                WorkflowControlEffect::NonExpandingMutation
            }
        }
    }
}

#[must_use]
pub fn workflow_controls() -> &'static [WorkflowControl] {
    &WorkflowControl::ALL
}
