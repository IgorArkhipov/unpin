use serde::{Deserialize, Serialize};

pub mod registry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderId {
    Claude,
    Codex,
    Cursor,
    Pi,
    #[serde(rename = "opencode")]
    OpenCode,
    Zed,
}

impl ProviderId {
    pub const ALL: [Self; 6] = [
        Self::Claude,
        Self::Codex,
        Self::Cursor,
        Self::Pi,
        Self::OpenCode,
        Self::Zed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Cursor => "cursor",
            Self::Pi => "pi",
            Self::OpenCode => "opencode",
            Self::Zed => "zed",
        }
    }
}
