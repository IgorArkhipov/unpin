pub(crate) mod agent_plugins;
pub(crate) mod catalog;
pub(crate) mod gateway;
pub(crate) mod group;
pub(crate) mod hook;
pub(crate) mod profile;
pub(crate) mod session;
pub(crate) mod toggle;
pub(crate) mod workflow;

use clap::ValueEnum;
use unpin_core::{
    provider_reach::{ProviderReachInput, SelectedProviderProvenance},
    providers::ProviderId,
};

/// The mutation reach is deliberately separate from discovery/list filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ProviderReachArg {
    #[value(name = "all", alias = "all-providers")]
    All,
    #[value(name = "selected", alias = "selected-provider")]
    Selected,
}

impl ProviderReachArg {
    pub(crate) fn input(self, provider: Option<ProviderId>) -> Result<ProviderReachInput, String> {
        match self {
            Self::All => Ok(ProviderReachInput::All),
            Self::Selected => provider
                .map(|provider| {
                    ProviderReachInput::selected(
                        provider,
                        SelectedProviderProvenance::ExplicitInput,
                    )
                })
                .ok_or_else(|| "selected-provider reach requires --provider".to_string()),
        }
    }
}
