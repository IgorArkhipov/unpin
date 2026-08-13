//! Session-scoped gateway policy and dispatch.
//!
//! This module stays transport-independent. Runtime adapters may translate its
//! descriptors and calls to MCP, but lease ownership and exposure checks remain
//! in core.

mod connection_registry;
mod control_plane;
mod data_plane;
mod runtime_registration;
mod service;
mod skills;
mod tools;
mod upstream;

use std::fmt;

use crate::sessions::LeaseError;

pub use connection_registry::{
    GatewayConnectionClaim, GatewayConnectionRegistry, GatewayConnectionRole,
    GatewayConnectionStatus,
};
pub use control_plane::{GatewayControlPlane, GatewaySessionStatus};
pub use data_plane::{GatewayCallPermit, GatewayDataPlane, GatewayHookCallContext};
pub use runtime_registration::{
    RuntimeHookRegistration, RuntimeModeRegistrations, RuntimeRegistrationContext,
    RuntimeRegistrationError, RuntimeRegistrationStore, RuntimeRegistrationValue,
    WorkflowRuntimeEnvelope,
};
pub use service::{
    GatewayExposure, GatewayHookRegistration, GatewayLimits, GatewayRefreshOutcome, GatewayService,
    ListChangeSupport,
};
pub use skills::{LoadedSkill, SkillMetadata, SkillRegistry};
pub use tools::{ProjectedTool, ToolRegistry};
pub use upstream::{
    CredentialBinding, PreparedStdioExecution, UpstreamIdentity, UpstreamToolDescriptor,
    UpstreamToolRegistration, UpstreamTransportKind, UpstreamValidationError,
};

#[derive(Debug)]
pub enum GatewayError {
    Lease(LeaseError),
    Upstream(UpstreamValidationError),
    InvalidExposure(&'static str),
    InvalidToolDescriptor,
    ToolLimitExceeded,
    SchemaLimitExceeded,
    ArgumentsLimitExceeded,
    ResponseLimitExceeded,
    ConcurrencyLimitExceeded,
    CapabilityUnavailable,
    HookDispatchIncomplete,
    HookPolicyDenied,
    ConnectionClaimInvalid,
    ConnectionEpochStale,
    ConnectionControlOnly,
    RefreshNotObserved,
    Workflow(String),
    SkillContentChanged,
    SkillContentInvalid,
    StatePoisoned,
    Serialization(String),
}

impl From<LeaseError> for GatewayError {
    fn from(error: LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl From<UpstreamValidationError> for GatewayError {
    fn from(error: UpstreamValidationError) -> Self {
        Self::Upstream(error)
    }
}

impl fmt::Display for GatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lease(error) => write!(formatter, "gateway lease error: {error}"),
            Self::Upstream(error) => write!(formatter, "gateway upstream error: {error}"),
            Self::InvalidExposure(message) => {
                write!(formatter, "invalid gateway exposure: {message}")
            }
            Self::InvalidToolDescriptor => {
                formatter.write_str("upstream tool descriptor is invalid")
            }
            Self::ToolLimitExceeded => formatter.write_str("gateway tool limit exceeded"),
            Self::SchemaLimitExceeded => formatter.write_str("gateway schema limit exceeded"),
            Self::ArgumentsLimitExceeded => formatter.write_str("gateway argument limit exceeded"),
            Self::ResponseLimitExceeded => formatter.write_str("gateway response limit exceeded"),
            Self::ConcurrencyLimitExceeded => {
                formatter.write_str("gateway concurrency limit exceeded")
            }
            Self::CapabilityUnavailable => {
                formatter.write_str("capability is unavailable in this session")
            }
            Self::HookDispatchIncomplete => {
                formatter.write_str("gateway hook dispatch is incomplete")
            }
            Self::HookPolicyDenied => formatter.write_str("gateway hook policy denied tool call"),
            Self::ConnectionClaimInvalid => {
                formatter.write_str("gateway connection claim is invalid")
            }
            Self::ConnectionEpochStale => formatter.write_str("gateway connection epoch is stale"),
            Self::ConnectionControlOnly => {
                formatter.write_str("auxiliary gateway connection is control-only")
            }
            Self::RefreshNotObserved => {
                formatter.write_str("gateway refresh requires a re-list on the same connection")
            }
            Self::Workflow(message) => write!(formatter, "gateway workflow error: {message}"),
            Self::SkillContentChanged => {
                formatter.write_str("selected skill content changed after exposure was pinned")
            }
            Self::SkillContentInvalid => {
                formatter.write_str("selected skill content is unavailable")
            }
            Self::StatePoisoned => formatter.write_str("gateway state lock is poisoned"),
            Self::Serialization(message) => {
                write!(formatter, "gateway serialization failed: {message}")
            }
        }
    }
}

impl std::error::Error for GatewayError {}
