use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    approval::{ApprovalExpectation, ApprovalResourceBinding, VerifiedApproval},
    discovery::DiscoveryLayer,
    providers::ProviderId,
};

const MAX_HANDLER_ID_BYTES: usize = 512;
const MAX_NATIVE_EVENT_BYTES: usize = 128;
const MAX_MATCHER_BYTES: usize = 4 * 1024;
const MAX_ACTION_ARGUMENTS: usize = 256;
const MAX_ACTION_ARGUMENT_BYTES: usize = 16 * 1024;
const MAX_ENVIRONMENT_NAMES: usize = 128;
const MAX_TIMEOUT_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookEventFamily {
    BeforeTool,
    AfterToolSuccess,
    AfterToolFailure,
    PromptSubmit,
    SessionStart,
    SessionEnd,
    BeforeCompaction,
    AfterCompaction,
    ProviderSpecific,
}

impl HookEventFamily {
    #[must_use]
    pub fn normalize(provider: ProviderId, native_event: &str) -> Self {
        let compact = native_event
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        match compact.as_str() {
            "pretooluse"
            | "beforeshellexecution"
            | "beforereadfile"
            | "toolcall"
            | "toolexecutebefore" => Self::BeforeTool,
            "posttooluse"
            | "aftershellexecution"
            | "afterfileedit"
            | "toolresult"
            | "toolexecuteafter" => Self::AfterToolSuccess,
            "posttoolusefailure" => Self::AfterToolFailure,
            "userpromptsubmit" | "beforesubmitprompt" | "input" => Self::PromptSubmit,
            "sessionstart" | "sessioncreated" => Self::SessionStart,
            "sessionend" | "sessionshutdown" | "sessiondeleted" => Self::SessionEnd,
            "precompact" | "sessionbeforecompact" | "experimentalsessioncompacting" => {
                Self::BeforeCompaction
            }
            "postcompact" | "sessioncompact" | "sessioncompacted" => Self::AfterCompaction,
            _ => {
                let _ = provider;
                Self::ProviderSpecific
            }
        }
    }

    #[must_use]
    pub const fn is_before_tool(self) -> bool {
        matches!(self, Self::BeforeTool)
    }

    #[must_use]
    pub const fn is_after_tool(self) -> bool {
        matches!(self, Self::AfterToolSuccess | Self::AfterToolFailure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookSourceLayer {
    Managed,
    Global,
    Project,
    Session,
    Component,
}

impl From<DiscoveryLayer> for HookSourceLayer {
    fn from(layer: DiscoveryLayer) -> Self {
        match layer {
            DiscoveryLayer::Global => Self::Global,
            DiscoveryLayer::Project => Self::Project,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookOwnership {
    User,
    ProviderManaged,
    AdministratorManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookFailurePolicy {
    FailClosed,
    ContinueDegraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookRouteOwner {
    Gateway,
    NativeDispatcher,
    ProviderBridge,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookActionType {
    Command,
    Http,
    McpTool,
    Prompt,
    Agent,
    ProviderComponent,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookMatcherMode {
    Any,
    ExactSet,
    /// Provider syntax preserved for inventory only. Dispatch reports
    /// `UnsupportedMatcher` instead of guessing regex/glob semantics.
    ProviderPattern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookMatcher {
    expression: String,
    mode: HookMatcherMode,
    exact_values: BTreeSet<String>,
}

impl HookMatcher {
    pub fn new(expression: impl Into<String>) -> Result<Self, HookModelError> {
        let expression = expression.into();
        if expression.len() > MAX_MATCHER_BYTES || expression.chars().any(char::is_control) {
            return Err(HookModelError::InvalidMatcher);
        }
        let trimmed = expression.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Ok(Self {
                expression,
                mode: HookMatcherMode::Any,
                exact_values: BTreeSet::new(),
            });
        }
        let exact_syntax = trimmed.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | ' ' | ',' | '|' | ':')
        });
        if exact_syntax {
            let exact_values = trimmed
                .split([',', '|'])
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect::<BTreeSet<_>>();
            if exact_values.is_empty() {
                return Err(HookModelError::InvalidMatcher);
            }
            Ok(Self {
                expression,
                mode: HookMatcherMode::ExactSet,
                exact_values,
            })
        } else {
            Ok(Self {
                expression,
                mode: HookMatcherMode::ProviderPattern,
                exact_values: BTreeSet::new(),
            })
        }
    }

    #[must_use]
    pub fn any() -> Self {
        Self {
            expression: "*".to_string(),
            mode: HookMatcherMode::Any,
            exact_values: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    #[must_use]
    pub const fn mode(&self) -> HookMatcherMode {
        self.mode
    }

    #[must_use]
    pub fn matches(&self, value: &str) -> bool {
        match self.mode {
            HookMatcherMode::Any => true,
            HookMatcherMode::ExactSet => self.exact_values.contains(value),
            HookMatcherMode::ProviderPattern => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookTransformCapabilities {
    pub argument_rewrite: bool,
    pub result_modification: bool,
    pub context_injection: bool,
}

impl HookTransformCapabilities {
    #[must_use]
    pub const fn none() -> Self {
        Self {
            argument_rewrite: false,
            result_modification: false,
            context_injection: false,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HookFileBinding {
    path: PathBuf,
    fingerprint: String,
}

impl fmt::Debug for HookFileBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookFileBinding")
            .field("path", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HookEnvironmentBinding {
    name: String,
    value: String,
    value_fingerprint: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MaterializedHookCommand {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
}

impl fmt::Debug for MaterializedHookCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedHookCommand")
            .field("executable", &"[REDACTED]")
            .field("argument_count", &self.arguments.len())
            .field("working_directory", &"[REDACTED]")
            .field("environment_names", &self.environment.keys())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum HookAction {
    StructuredCommand {
        executable: PathBuf,
        arguments: Vec<String>,
        working_directory: PathBuf,
        working_directory_fingerprint: String,
        environment: Vec<HookEnvironmentBinding>,
        file_bindings: Vec<HookFileBinding>,
    },
    Http {
        endpoint: String,
    },
    McpTool {
        server: String,
        tool: String,
    },
    ProviderComponent {
        reference: String,
    },
    ProviderNative {
        action_type: HookActionType,
        definition_fingerprint: String,
    },
}

impl fmt::Debug for HookAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookAction")
            .field("action_type", &self.action_type())
            .field("reference", &self.safe_reference())
            .finish()
    }
}

impl HookAction {
    pub fn structured_command(
        executable: impl AsRef<Path>,
        arguments: Vec<String>,
        working_directory: impl AsRef<Path>,
        environment: BTreeMap<String, String>,
        reviewed_files: Vec<PathBuf>,
    ) -> Result<Self, HookModelError> {
        if arguments.len() > MAX_ACTION_ARGUMENTS
            || arguments.iter().any(|argument| {
                argument.len() > MAX_ACTION_ARGUMENT_BYTES || argument.chars().any(char::is_control)
            })
            || environment.len() > MAX_ENVIRONMENT_NAMES
            || environment.iter().any(|(name, value)| {
                !valid_environment_name(name)
                    || value.len() > MAX_ACTION_ARGUMENT_BYTES
                    || value.chars().any(char::is_control)
            })
        {
            return Err(HookModelError::InvalidAction);
        }
        let executable = verified_executable_file(executable.as_ref())?;
        let (working_directory, working_directory_fingerprint) =
            verified_working_directory(working_directory.as_ref())?;
        let mut file_paths = vec![executable.clone()];
        file_paths.extend(reviewed_files);
        file_paths.sort();
        file_paths.dedup();
        let file_bindings = file_paths
            .into_iter()
            .map(|path| {
                let path = verified_regular_file(&path)?;
                let fingerprint = file_fingerprint(&path)?;
                Ok(HookFileBinding { path, fingerprint })
            })
            .collect::<Result<Vec<_>, HookModelError>>()?;
        let environment = environment_bindings(environment);
        Ok(Self::StructuredCommand {
            executable,
            arguments,
            working_directory,
            working_directory_fingerprint,
            environment,
            file_bindings,
        })
    }

    pub fn http(endpoint: impl Into<String>) -> Result<Self, HookModelError> {
        let endpoint = endpoint.into();
        let lower = endpoint.to_ascii_lowercase();
        let local_http = lower.starts_with("http://127.0.0.1:")
            || lower.starts_with("http://localhost:")
            || lower.starts_with("http://[::1]:");
        if endpoint.len() > 4 * 1024
            || endpoint.chars().any(char::is_control)
            || endpoint.contains(['?', '#', '@'])
            || !(lower.starts_with("https://") || local_http)
        {
            return Err(HookModelError::InvalidAction);
        }
        Ok(Self::Http { endpoint })
    }

    pub fn mcp_tool(
        server: impl Into<String>,
        tool: impl Into<String>,
    ) -> Result<Self, HookModelError> {
        let server = server.into();
        let tool = tool.into();
        if !valid_reference(&server) || !valid_reference(&tool) {
            return Err(HookModelError::InvalidAction);
        }
        Ok(Self::McpTool { server, tool })
    }

    pub fn provider_component(reference: impl Into<String>) -> Result<Self, HookModelError> {
        let reference = reference.into();
        if !valid_reference(&reference) {
            return Err(HookModelError::InvalidAction);
        }
        Ok(Self::ProviderComponent { reference })
    }

    #[must_use]
    pub const fn action_type(&self) -> HookActionType {
        match self {
            Self::StructuredCommand { .. } => HookActionType::Command,
            Self::Http { .. } => HookActionType::Http,
            Self::McpTool { .. } => HookActionType::McpTool,
            Self::ProviderComponent { .. } => HookActionType::ProviderComponent,
            Self::ProviderNative { action_type, .. } => *action_type,
        }
    }

    #[must_use]
    pub fn is_gateway_executable(&self) -> bool {
        matches!(
            self,
            Self::StructuredCommand { .. } | Self::Http { .. } | Self::McpTool { .. }
        )
    }

    #[must_use]
    pub fn safe_reference(&self) -> String {
        let prefix = match self.action_type() {
            HookActionType::Command => "command",
            HookActionType::Http => "http",
            HookActionType::McpTool => "mcp-tool",
            HookActionType::Prompt => "prompt",
            HookActionType::Agent => "agent",
            HookActionType::ProviderComponent => "provider-component",
            HookActionType::Unknown => "unknown",
        };
        format!("{prefix}:sha256:{}", &self.invocation_fingerprint()[..16])
    }

    #[must_use]
    pub fn invocation_fingerprint(&self) -> String {
        let value = match self {
            Self::StructuredCommand {
                executable,
                arguments,
                working_directory,
                working_directory_fingerprint,
                environment,
                file_bindings,
            } => json!({
                "type": "command",
                "executable": executable,
                "arguments": arguments,
                "workingDirectory": working_directory,
                "workingDirectoryFingerprint": working_directory_fingerprint,
                "environment": environment.iter().map(|binding| json!({
                    "name": binding.name,
                    "valueFingerprint": binding.value_fingerprint,
                })).collect::<Vec<_>>(),
                "fileBindings": file_bindings.iter().map(|binding| json!({
                    "path": binding.path,
                    "fingerprint": binding.fingerprint,
                })).collect::<Vec<_>>(),
            }),
            Self::Http { endpoint } => json!({"type": "http", "endpoint": endpoint}),
            Self::McpTool { server, tool } => {
                json!({"type": "mcp-tool", "server": server, "tool": tool})
            }
            Self::ProviderComponent { reference } => {
                json!({"type": "provider-component", "reference": reference})
            }
            Self::ProviderNative {
                action_type,
                definition_fingerprint,
            } => json!({
                "type": "provider-native",
                "actionType": action_type,
                "definitionFingerprint": definition_fingerprint,
            }),
        };
        stable_hash(&serde_json::to_vec(&value).expect("hook action serialization is infallible"))
    }

    pub fn verify_runtime(&self) -> Result<(), HookModelError> {
        match self {
            Self::StructuredCommand {
                executable,
                working_directory,
                working_directory_fingerprint,
                environment,
                file_bindings,
                ..
            } => {
                if verified_executable_file(executable)?.as_path() != executable.as_path() {
                    return Err(HookModelError::InvocationChanged);
                }
                let (current_directory, current_fingerprint) =
                    verified_working_directory(working_directory)
                        .map_err(|_| HookModelError::InvocationChanged)?;
                if current_directory != *working_directory
                    || current_fingerprint != *working_directory_fingerprint
                {
                    return Err(HookModelError::InvocationChanged);
                }
                for binding in file_bindings {
                    let canonical = verified_regular_file(&binding.path)?;
                    if canonical != binding.path
                        || file_fingerprint(&canonical)? != binding.fingerprint
                    {
                        return Err(HookModelError::InvocationChanged);
                    }
                }
                materialize_environment(environment)?;
                Ok(())
            }
            Self::ProviderNative { .. } => Err(HookModelError::ActionNotGatewayExecutable),
            Self::Http { .. } | Self::McpTool { .. } | Self::ProviderComponent { .. } => Ok(()),
        }
    }

    pub fn materialize_command(&self) -> Result<Option<MaterializedHookCommand>, HookModelError> {
        match self {
            Self::StructuredCommand {
                executable,
                arguments,
                working_directory,
                environment,
                ..
            } => {
                self.verify_runtime()?;
                Ok(Some(MaterializedHookCommand {
                    executable: executable.clone(),
                    arguments: arguments.clone(),
                    working_directory: working_directory.clone(),
                    environment: materialize_environment(environment)?,
                }))
            }
            _ => Ok(None),
        }
    }

    pub fn http_endpoint(&self) -> Option<&str> {
        match self {
            Self::Http { endpoint } => Some(endpoint),
            _ => None,
        }
    }

    pub fn mcp_target(&self) -> Option<(&str, &str)> {
        match self {
            Self::McpTool { server, tool } => Some((server, tool)),
            _ => None,
        }
    }

    pub fn component_reference(&self) -> Option<&str> {
        match self {
            Self::ProviderComponent { reference } => Some(reference),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum HookTrustState {
    #[default]
    NeedsReview,
    Reviewed {
        invocation_fingerprint: String,
        profile_digest: String,
    },
    Managed {
        invocation_fingerprint: String,
    },
}

impl HookTrustState {
    #[must_use]
    pub const fn is_needs_review(&self) -> bool {
        matches!(self, Self::NeedsReview)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HookHandler {
    id: String,
    provider: ProviderId,
    native_event: String,
    event_family: HookEventFamily,
    matcher: HookMatcher,
    action: HookAction,
    order: i32,
    timeout_ms: u64,
    failure_policy: HookFailurePolicy,
    source_layer: HookSourceLayer,
    ownership: HookOwnership,
    route_owner: HookRouteOwner,
    enabled: bool,
    transformations: HookTransformCapabilities,
    fingerprint: String,
    trust: HookTrustState,
}

impl fmt::Debug for HookHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookHandler")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("native_event", &self.native_event)
            .field("event_family", &self.event_family)
            .field("matcher", &self.matcher.expression())
            .field("action", &self.action)
            .field("order", &self.order)
            .field("timeout_ms", &self.timeout_ms)
            .field("failure_policy", &self.failure_policy)
            .field("source_layer", &self.source_layer)
            .field("ownership", &self.ownership)
            .field("route_owner", &self.route_owner)
            .field("enabled", &self.enabled)
            .field("fingerprint", &self.fingerprint)
            .field("trust", &self.trust)
            .finish()
    }
}

pub struct HookHandlerSpec {
    pub id: String,
    pub provider: ProviderId,
    pub native_event: String,
    pub event_family: HookEventFamily,
    pub matcher: HookMatcher,
    pub action: HookAction,
    pub order: i32,
    pub timeout_ms: u64,
    pub failure_policy: HookFailurePolicy,
    pub source_layer: HookSourceLayer,
    pub ownership: HookOwnership,
    pub route_owner: HookRouteOwner,
    pub enabled: bool,
    pub transformations: HookTransformCapabilities,
}

impl HookHandler {
    pub fn new(spec: HookHandlerSpec) -> Result<Self, HookModelError> {
        Self::from_spec(spec, false)
    }

    pub(crate) fn new_managed(spec: HookHandlerSpec) -> Result<Self, HookModelError> {
        if spec.ownership != HookOwnership::AdministratorManaged
            || !matches!(
                spec.source_layer,
                HookSourceLayer::Managed | HookSourceLayer::Component
            )
        {
            return Err(HookModelError::InvalidHandler);
        }
        Self::from_spec(spec, true)
    }

    fn from_spec(spec: HookHandlerSpec, managed: bool) -> Result<Self, HookModelError> {
        if !valid_identifier(&spec.id, MAX_HANDLER_ID_BYTES)
            || !valid_identifier(&spec.native_event, MAX_NATIVE_EVENT_BYTES)
            || spec.timeout_ms == 0
            || spec.timeout_ms > MAX_TIMEOUT_MS
        {
            return Err(HookModelError::InvalidHandler);
        }
        if spec.route_owner == HookRouteOwner::Gateway
            && (!spec.action.is_gateway_executable()
                || spec.matcher.mode() == HookMatcherMode::ProviderPattern)
        {
            return Err(HookModelError::ActionNotGatewayExecutable);
        }
        let fingerprint = handler_fingerprint(&spec);
        let invocation_fingerprint = spec.action.invocation_fingerprint();
        let trust = if managed {
            HookTrustState::Managed {
                invocation_fingerprint,
            }
        } else {
            HookTrustState::NeedsReview
        };
        Ok(Self {
            id: spec.id,
            provider: spec.provider,
            native_event: spec.native_event,
            event_family: spec.event_family,
            matcher: spec.matcher,
            action: spec.action,
            order: spec.order,
            timeout_ms: spec.timeout_ms,
            failure_policy: spec.failure_policy,
            source_layer: spec.source_layer,
            ownership: spec.ownership,
            route_owner: spec.route_owner,
            enabled: spec.enabled,
            transformations: spec.transformations,
            fingerprint,
            trust,
        })
    }

    pub fn trust_operation_id(&self, profile_digest: &str) -> Result<String, HookModelError> {
        validate_digest(profile_digest)?;
        Ok(format!(
            "hook-trust-{}-{}-{}-{}",
            self.provider.as_str(),
            &stable_hash(self.id.as_bytes())[..16],
            self.fingerprint,
            profile_digest
        ))
    }

    pub fn trust_approval_expectation(
        &self,
        profile_digest: &str,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<ApprovalExpectation, HookModelError> {
        Ok(ApprovalExpectation {
            issuer: issuer.into(),
            audience: audience.into(),
            operation_id: self.trust_operation_id(profile_digest)?,
            operation_kind: "hook-trust".to_string(),
            effect_graph_digest: stable_hash(
                format!(
                    "{}\n{}\n{}\n{}\n{}",
                    self.provider.as_str(),
                    self.id,
                    profile_digest,
                    self.fingerprint,
                    self.action.invocation_fingerprint()
                )
                .as_bytes(),
            ),
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            session_id: Some(session_id.into()),
            profile_digest: Some(profile_digest.to_string()),
            resources: vec![ApprovalResourceBinding {
                resource_id: format!("hook-action-{}", &stable_hash(self.id.as_bytes())[..16]),
                pre_state_fingerprint: Some(self.action.invocation_fingerprint()),
            }],
        })
    }

    pub fn review(
        mut self,
        approval: &VerifiedApproval,
        profile_digest: &str,
    ) -> Result<Self, HookModelError> {
        if approval.operation_id() != self.trust_operation_id(profile_digest)? {
            return Err(HookModelError::ApprovalMismatch);
        }
        self.action.verify_runtime()?;
        self.trust = HookTrustState::Reviewed {
            invocation_fingerprint: self.action.invocation_fingerprint(),
            profile_digest: profile_digest.to_string(),
        };
        Ok(self)
    }

    pub fn verify_for_dispatch(&self, profile_digest: &str) -> Result<(), HookModelError> {
        self.action.verify_runtime()?;
        let invocation_fingerprint = self.action.invocation_fingerprint();
        match &self.trust {
            HookTrustState::Managed {
                invocation_fingerprint: reviewed,
            } if reviewed == &invocation_fingerprint => Ok(()),
            HookTrustState::Reviewed {
                invocation_fingerprint: reviewed,
                profile_digest: reviewed_profile,
            } if reviewed == &invocation_fingerprint && reviewed_profile == profile_digest => {
                Ok(())
            }
            HookTrustState::NeedsReview
            | HookTrustState::Managed { .. }
            | HookTrustState::Reviewed { .. } => Err(HookModelError::TrustRequired),
        }
    }

    /// Restores trust carried by a record authenticated with the session
    /// authority key. Callers must authenticate the containing record first;
    /// this method revalidates the invocation and profile bindings instead of
    /// accepting the persisted trust state verbatim.
    pub(crate) fn restore_authenticated_runtime_trust(
        mut self,
        trust: HookTrustState,
    ) -> Result<Self, HookModelError> {
        let invocation_fingerprint = self.action.invocation_fingerprint();
        match &trust {
            HookTrustState::NeedsReview => {}
            HookTrustState::Managed {
                invocation_fingerprint: reviewed,
            } if self.ownership == HookOwnership::AdministratorManaged
                && reviewed == &invocation_fingerprint => {}
            HookTrustState::Reviewed {
                invocation_fingerprint: reviewed,
                profile_digest,
            } if self.ownership != HookOwnership::AdministratorManaged
                && reviewed == &invocation_fingerprint =>
            {
                validate_digest(profile_digest)?;
            }
            HookTrustState::Managed { .. } | HookTrustState::Reviewed { .. } => {
                return Err(HookModelError::TrustRequired);
            }
        }
        self.trust = trust;
        Ok(self)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn native_event(&self) -> &str {
        &self.native_event
    }

    #[must_use]
    pub const fn event_family(&self) -> HookEventFamily {
        self.event_family
    }

    #[must_use]
    pub fn matcher(&self) -> &HookMatcher {
        &self.matcher
    }

    #[must_use]
    pub fn action(&self) -> &HookAction {
        &self.action
    }

    #[must_use]
    pub const fn order(&self) -> i32 {
        self.order
    }

    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    #[must_use]
    pub const fn failure_policy(&self) -> HookFailurePolicy {
        self.failure_policy
    }

    #[must_use]
    pub const fn source_layer(&self) -> HookSourceLayer {
        self.source_layer
    }

    #[must_use]
    pub const fn ownership(&self) -> HookOwnership {
        self.ownership
    }

    #[must_use]
    pub const fn route_owner(&self) -> HookRouteOwner {
        self.route_owner
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub const fn transformations(&self) -> HookTransformCapabilities {
        self.transformations
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[must_use]
    pub fn trust(&self) -> &HookTrustState {
        &self.trust
    }

    #[must_use]
    pub fn inventory(&self) -> HookInventoryMetadata {
        HookInventoryMetadata {
            native_event: self.native_event.clone(),
            event_family: self.event_family,
            matcher: self.matcher.expression().to_string(),
            matcher_mode: self.matcher.mode(),
            action_type: self.action.action_type(),
            action_reference: self.action.safe_reference(),
            order: self.order,
            timeout_ms: self.timeout_ms,
            failure_policy: self.failure_policy,
            source_layer: self.source_layer,
            ownership: self.ownership,
            route_owner: self.route_owner,
            fingerprint: self.fingerprint.clone(),
            invocation_fingerprint: self.action.invocation_fingerprint(),
            trust: self.trust.clone(),
            transformations: self.transformations,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookInventoryMetadata {
    pub native_event: String,
    pub event_family: HookEventFamily,
    pub matcher: String,
    pub matcher_mode: HookMatcherMode,
    pub action_type: HookActionType,
    pub action_reference: String,
    pub order: i32,
    pub timeout_ms: u64,
    pub failure_policy: HookFailurePolicy,
    pub source_layer: HookSourceLayer,
    pub ownership: HookOwnership,
    pub route_owner: HookRouteOwner,
    pub fingerprint: String,
    pub invocation_fingerprint: String,
    #[serde(default, skip_serializing_if = "HookTrustState::is_needs_review")]
    pub trust: HookTrustState,
    pub transformations: HookTransformCapabilities,
}

impl HookInventoryMetadata {
    pub fn trust_operation_id(
        &self,
        provider: ProviderId,
        handler_id: &str,
        profile_digest: &str,
    ) -> Result<String, HookModelError> {
        validate_digest(profile_digest)?;
        validate_digest(&self.fingerprint)?;
        validate_digest(&self.invocation_fingerprint)?;
        Ok(format!(
            "hook-trust-{}-{}-{}-{}",
            provider.as_str(),
            &stable_hash(handler_id.as_bytes())[..16],
            self.fingerprint,
            profile_digest
        ))
    }

    pub(crate) fn legacy_trust_operation_id(
        &self,
        provider: ProviderId,
        profile_digest: &str,
    ) -> Result<String, HookModelError> {
        validate_digest(profile_digest)?;
        validate_digest(&self.fingerprint)?;
        Ok(format!(
            "hook-trust-{}-{}-{}",
            provider.as_str(),
            self.fingerprint,
            profile_digest
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn trust_approval_expectation(
        &self,
        provider: ProviderId,
        handler_id: &str,
        profile_digest: &str,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<ApprovalExpectation, HookModelError> {
        Ok(ApprovalExpectation {
            issuer: issuer.into(),
            audience: audience.into(),
            operation_id: self.trust_operation_id(provider, handler_id, profile_digest)?,
            operation_kind: "hook-trust".to_string(),
            effect_graph_digest: stable_hash(
                format!(
                    "{}\n{}\n{}\n{}\n{}",
                    provider.as_str(),
                    handler_id,
                    profile_digest,
                    self.fingerprint,
                    self.invocation_fingerprint
                )
                .as_bytes(),
            ),
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            session_id: Some(session_id.into()),
            profile_digest: Some(profile_digest.to_string()),
            resources: vec![ApprovalResourceBinding {
                resource_id: format!("hook-action-{}", &stable_hash(handler_id.as_bytes())[..16]),
                pre_state_fingerprint: Some(self.invocation_fingerprint.clone()),
            }],
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedHookHandler {
    pub handler: HookHandler,
    pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookParseIssue {
    pub event: String,
    pub code: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct HookDocumentParse {
    pub handlers: Vec<ParsedHookHandler>,
    pub issues: Vec<HookParseIssue>,
}

pub fn parse_hook_document(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    value: &Value,
    allow_top_level_events: bool,
) -> HookDocumentParse {
    let Some(document) = value.as_object() else {
        return HookDocumentParse {
            handlers: Vec::new(),
            issues: vec![HookParseIssue {
                event: "document".to_string(),
                code: "invalid-hook-document",
            }],
        };
    };
    let hook_root = document
        .get("hooks")
        .and_then(Value::as_object)
        .or_else(|| allow_top_level_events.then_some(document));
    let Some(hook_root) = hook_root else {
        return HookDocumentParse::default();
    };
    let mut events = hook_root
        .iter()
        .filter(|(name, _)| name.as_str() != "version" && name.as_str() != "hooks")
        .collect::<Vec<_>>();
    events.sort_by_key(|(name, _)| name.as_str());
    let mut parsed = HookDocumentParse::default();
    for (event, definition) in events {
        parse_event_definition(provider, layer, id_prefix, event, definition, &mut parsed);
    }
    parsed
}

fn parse_event_definition(
    provider: ProviderId,
    layer: DiscoveryLayer,
    id_prefix: &str,
    event: &str,
    definition: &Value,
    parsed: &mut HookDocumentParse,
) {
    let entries = match definition {
        Value::Array(entries) => entries.iter().collect::<Vec<_>>(),
        Value::Object(_) => vec![definition],
        _ => {
            parsed.issues.push(HookParseIssue {
                event: event.to_string(),
                code: "invalid-hook-event",
            });
            return;
        }
    };
    let mut occurrence = BTreeMap::<String, usize>::new();
    let mut order = 0_i32;
    for entry in entries {
        let Some(entry_object) = entry.as_object() else {
            parsed.issues.push(HookParseIssue {
                event: event.to_string(),
                code: "invalid-hook-group",
            });
            continue;
        };
        let group_matcher = entry_object
            .get("matcher")
            .and_then(Value::as_str)
            .unwrap_or("*");
        let handlers = entry_object
            .get("hooks")
            .and_then(Value::as_array)
            .map(|handlers| handlers.iter().collect::<Vec<_>>())
            .unwrap_or_else(|| vec![entry]);
        for definition in handlers {
            let Some(object) = definition.as_object() else {
                parsed.issues.push(HookParseIssue {
                    event: event.to_string(),
                    code: "invalid-hook-handler",
                });
                continue;
            };
            let matcher = object
                .get("matcher")
                .and_then(Value::as_str)
                .unwrap_or(group_matcher);
            let Ok(matcher) = HookMatcher::new(matcher) else {
                parsed.issues.push(HookParseIssue {
                    event: event.to_string(),
                    code: "invalid-hook-matcher",
                });
                continue;
            };
            let action_type = provider_action_type(object);
            let definition_fingerprint = stable_hash(
                &serde_json::to_vec(&json!({
                    "provider": provider,
                    "event": event,
                    "matcher": matcher.expression(),
                    "handler": definition,
                }))
                .expect("provider hook serialization is infallible"),
            );
            let duplicate = occurrence
                .entry(definition_fingerprint.clone())
                .and_modify(|count| *count += 1)
                .or_insert(0);
            let id = format!(
                "{id_prefix}{event}:{}:{duplicate}",
                &definition_fingerprint[..16]
            );
            let event_family = HookEventFamily::normalize(provider, event);
            let timeout_seconds = object.get("timeout").and_then(Value::as_u64).unwrap_or(600);
            let Some(timeout_ms) = timeout_seconds
                .checked_mul(1_000)
                .filter(|timeout| *timeout > 0 && *timeout <= MAX_TIMEOUT_MS)
            else {
                parsed.issues.push(HookParseIssue {
                    event: event.to_string(),
                    code: "invalid-hook-timeout",
                });
                continue;
            };
            let failure_policy = object
                .get("failurePolicy")
                .or_else(|| object.get("failure_policy"))
                .and_then(Value::as_str)
                .map(|value| match value {
                    "continue" | "continue-degraded" | "warn" => {
                        HookFailurePolicy::ContinueDegraded
                    }
                    _ => HookFailurePolicy::FailClosed,
                })
                .unwrap_or_else(|| {
                    if event_family.is_before_tool() {
                        HookFailurePolicy::FailClosed
                    } else {
                        HookFailurePolicy::ContinueDegraded
                    }
                });
            let spec = HookHandlerSpec {
                id,
                provider,
                native_event: event.to_string(),
                event_family,
                matcher,
                action: HookAction::ProviderNative {
                    action_type,
                    definition_fingerprint,
                },
                order: object
                    .get("order")
                    .and_then(Value::as_i64)
                    .and_then(|value| i32::try_from(value).ok())
                    .unwrap_or(order),
                timeout_ms,
                failure_policy,
                source_layer: layer.into(),
                ownership: HookOwnership::User,
                route_owner: HookRouteOwner::NativeDispatcher,
                enabled: object.get("disabled").and_then(Value::as_bool) != Some(true),
                transformations: provider_transformations(provider, event_family),
            };
            match HookHandler::new(spec) {
                Ok(handler) => parsed.handlers.push(ParsedHookHandler {
                    display_name: format!("{event} · {:?} {}", action_type, order + 1),
                    handler,
                }),
                Err(_) => parsed.issues.push(HookParseIssue {
                    event: event.to_string(),
                    code: "invalid-hook-handler",
                }),
            }
            order = order.saturating_add(1);
        }
    }
}

fn provider_action_type(object: &serde_json::Map<String, Value>) -> HookActionType {
    match object.get("type").and_then(Value::as_str) {
        Some("command") => HookActionType::Command,
        Some("http") => HookActionType::Http,
        Some("mcp_tool") | Some("mcp-tool") => HookActionType::McpTool,
        Some("prompt") => HookActionType::Prompt,
        Some("agent") => HookActionType::Agent,
        Some(_) => HookActionType::Unknown,
        None if object.contains_key("command") => HookActionType::Command,
        None if object.contains_key("url") => HookActionType::Http,
        None => HookActionType::Unknown,
    }
}

fn provider_transformations(
    provider: ProviderId,
    event_family: HookEventFamily,
) -> HookTransformCapabilities {
    HookTransformCapabilities {
        argument_rewrite: event_family == HookEventFamily::BeforeTool
            && matches!(
                provider,
                ProviderId::Claude | ProviderId::Cursor | ProviderId::Pi | ProviderId::OpenCode
            ),
        result_modification: event_family.is_after_tool()
            && matches!(provider, ProviderId::Pi | ProviderId::OpenCode),
        context_injection: provider == ProviderId::Claude
            && matches!(
                event_family,
                HookEventFamily::BeforeTool
                    | HookEventFamily::AfterToolSuccess
                    | HookEventFamily::AfterToolFailure
                    | HookEventFamily::PromptSubmit
                    | HookEventFamily::SessionStart
                    | HookEventFamily::BeforeCompaction
            ),
    }
}

fn handler_fingerprint(spec: &HookHandlerSpec) -> String {
    let value = json!({
        "provider": spec.provider,
        "nativeEvent": spec.native_event,
        "eventFamily": spec.event_family,
        "matcher": spec.matcher.expression(),
        "matcherMode": spec.matcher.mode(),
        "actionFingerprint": spec.action.invocation_fingerprint(),
        "order": spec.order,
        "timeoutMs": spec.timeout_ms,
        "failurePolicy": spec.failure_policy,
        "sourceLayer": spec.source_layer,
        "ownership": spec.ownership,
        "routeOwner": spec.route_owner,
        "enabled": spec.enabled,
        "transformations": spec.transformations,
    });
    stable_hash(&serde_json::to_vec(&value).expect("hook handler serialization is infallible"))
}

fn verified_working_directory(path: &Path) -> Result<(PathBuf, String), HookModelError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| HookModelError::InvalidWorkingDirectory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HookModelError::InvalidWorkingDirectory);
    }
    let canonical = fs::canonicalize(path).map_err(|_| HookModelError::InvalidWorkingDirectory)?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|_| HookModelError::InvalidWorkingDirectory)?;
    if !canonical_metadata.is_dir() || canonical_metadata.file_type().is_symlink() {
        return Err(HookModelError::InvalidWorkingDirectory);
    }
    Ok((
        canonical,
        directory_identity_fingerprint(&canonical_metadata)?,
    ))
}

#[cfg(unix)]
fn directory_identity_fingerprint(metadata: &fs::Metadata) -> Result<String, HookModelError> {
    use std::os::unix::fs::MetadataExt;

    Ok(stable_hash(
        format!("{}:{}", metadata.dev(), metadata.ino()).as_bytes(),
    ))
}

#[cfg(not(unix))]
fn directory_identity_fingerprint(metadata: &fs::Metadata) -> Result<String, HookModelError> {
    use std::time::UNIX_EPOCH;

    let created = metadata
        .created()
        .and_then(|value| {
            value
                .duration_since(UNIX_EPOCH)
                .map_err(std::io::Error::other)
        })
        .map_err(|_| HookModelError::InvalidWorkingDirectory)?;
    Ok(stable_hash(
        format!("{}:{}", created.as_secs(), created.subsec_nanos()).as_bytes(),
    ))
}

fn verified_regular_file(path: &Path) -> Result<PathBuf, HookModelError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HookModelError::ActionUnavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HookModelError::ActionUnavailable);
    }
    fs::canonicalize(path).map_err(|_| HookModelError::ActionUnavailable)
}

fn verified_executable_file(path: &Path) -> Result<PathBuf, HookModelError> {
    let canonical = verified_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&canonical)
            .map_err(|_| HookModelError::ActionUnavailable)?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(HookModelError::ActionUnavailable);
        }
    }
    Ok(canonical)
}

fn file_fingerprint(path: &Path) -> Result<String, HookModelError> {
    let bytes = fs::read(path).map_err(|_| HookModelError::ActionUnavailable)?;
    Ok(stable_hash(&bytes))
}

fn environment_bindings(environment: BTreeMap<String, String>) -> Vec<HookEnvironmentBinding> {
    environment
        .into_iter()
        .map(|(name, value)| HookEnvironmentBinding {
            value_fingerprint: stable_hash(value.as_bytes()),
            name,
            value,
        })
        .collect()
}

fn materialize_environment(
    bindings: &[HookEnvironmentBinding],
) -> Result<BTreeMap<String, String>, HookModelError> {
    bindings
        .iter()
        .map(|binding| {
            if stable_hash(binding.value.as_bytes()) != binding.value_fingerprint {
                return Err(HookModelError::InvocationChanged);
            }
            Ok((binding.name.clone(), binding.value.clone()))
        })
        .collect()
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_reference(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 512
        && !value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
}

fn valid_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

fn validate_digest(value: &str) -> Result<(), HookModelError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(HookModelError::InvalidDigest)
    }
}

pub(crate) fn stable_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookModelError {
    InvalidHandler,
    InvalidMatcher,
    InvalidAction,
    InvalidWorkingDirectory,
    InvalidDigest,
    ActionUnavailable,
    ActionNotGatewayExecutable,
    InvocationChanged,
    TrustRequired,
    ApprovalMismatch,
}

impl fmt::Display for HookModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandler => formatter.write_str("hook handler is invalid"),
            Self::InvalidMatcher => formatter.write_str("hook matcher is invalid"),
            Self::InvalidAction => formatter.write_str("hook action is invalid"),
            Self::InvalidWorkingDirectory => {
                formatter.write_str("hook working directory is invalid")
            }
            Self::InvalidDigest => formatter.write_str("hook digest is invalid"),
            Self::ActionUnavailable => formatter.write_str("hook action is unavailable"),
            Self::ActionNotGatewayExecutable => {
                formatter.write_str("provider hook action cannot execute through gateway")
            }
            Self::InvocationChanged => formatter.write_str("hook invocation changed after review"),
            Self::TrustRequired => formatter.write_str("hook invocation requires review"),
            Self::ApprovalMismatch => {
                formatter.write_str("hook approval does not match invocation")
            }
        }
    }
}

impl std::error::Error for HookModelError {}
