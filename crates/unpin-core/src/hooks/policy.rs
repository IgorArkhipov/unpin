use std::{collections::BTreeSet, fmt};

use crate::providers::ProviderId;

use super::{
    HookEventFamily, HookHandler, HookOwnership, HookRouteOwner, HookSourceLayer, HookTrustState,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookPolicyLimits {
    pub maximum_handlers: usize,
    pub maximum_recursion_depth: usize,
    pub maximum_payload_bytes: usize,
    pub maximum_context_bytes: usize,
}

impl Default for HookPolicyLimits {
    fn default() -> Self {
        Self {
            maximum_handlers: 256,
            maximum_recursion_depth: 4,
            maximum_payload_bytes: 1024 * 1024,
            maximum_context_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HookPolicy {
    provider: ProviderId,
    profile_digest: String,
    handlers: Vec<HookHandler>,
    limits: HookPolicyLimits,
}

impl HookPolicy {
    pub fn compile(
        provider: ProviderId,
        profile_digest: impl Into<String>,
        handlers: Vec<HookHandler>,
        limits: HookPolicyLimits,
    ) -> Result<Self, HookPolicyError> {
        let profile_digest = profile_digest.into();
        if !valid_digest(&profile_digest)
            || limits.maximum_handlers == 0
            || limits.maximum_handlers > 4_096
            || limits.maximum_recursion_depth == 0
            || limits.maximum_recursion_depth > 32
            || limits.maximum_payload_bytes == 0
            || limits.maximum_payload_bytes > 32 * 1024 * 1024
            || limits.maximum_context_bytes == 0
            || limits.maximum_context_bytes > limits.maximum_payload_bytes
            || handlers.len() > limits.maximum_handlers
        {
            return Err(HookPolicyError::InvalidPolicy);
        }
        let mut ids = BTreeSet::new();
        let mut handlers = handlers
            .into_iter()
            .filter(|handler| handler.enabled())
            .collect::<Vec<_>>();
        for handler in &handlers {
            let managed_trust_matches =
                matches!(
                    (handler.ownership(), handler.trust()),
                    (
                        HookOwnership::AdministratorManaged,
                        HookTrustState::Managed { .. }
                    )
                ) || !matches!(handler.ownership(), HookOwnership::AdministratorManaged)
                    && !matches!(handler.trust(), HookTrustState::Managed { .. });
            if handler.provider() != provider
                || !ids.insert(handler.id().to_string())
                || !managed_trust_matches
            {
                return Err(HookPolicyError::InvalidPolicy);
            }
        }
        handlers.sort_by(|left, right| handler_sort_key(left).cmp(&handler_sort_key(right)));
        Ok(Self {
            provider,
            profile_digest,
            handlers,
            limits,
        })
    }

    pub fn empty(provider: ProviderId) -> Self {
        Self {
            provider,
            profile_digest: "0".repeat(64),
            handlers: Vec::new(),
            limits: HookPolicyLimits::default(),
        }
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub fn handlers(&self) -> &[HookHandler] {
        &self.handlers
    }

    #[must_use]
    pub const fn limits(&self) -> HookPolicyLimits {
        self.limits
    }

    pub(crate) fn candidates(
        &self,
        family: HookEventFamily,
        route_owner: HookRouteOwner,
    ) -> impl Iterator<Item = &HookHandler> {
        self.handlers.iter().filter(move |handler| {
            handler.event_family() == family && handler.route_owner() == route_owner
        })
    }
}

fn handler_sort_key(handler: &HookHandler) -> (u8, u8, i32, &str) {
    let ownership = match handler.ownership() {
        HookOwnership::AdministratorManaged => 0,
        HookOwnership::ProviderManaged => 1,
        HookOwnership::User => 2,
    };
    let layer = match handler.source_layer() {
        HookSourceLayer::Managed => 0,
        HookSourceLayer::Global => 1,
        HookSourceLayer::Project => 2,
        HookSourceLayer::Session => 3,
        HookSourceLayer::Component => 4,
    };
    (ownership, layer, handler.order(), handler.id())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookPolicyError {
    InvalidPolicy,
}

impl fmt::Display for HookPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str("hook policy is invalid"),
        }
    }
}

impl std::error::Error for HookPolicyError {}
