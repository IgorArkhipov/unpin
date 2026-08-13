use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use crate::{
    catalog::{CapabilityId, CapabilityKind, Catalog, CatalogRecord},
    hooks::{
        HookAction, HookEventFamily, HookFailurePolicy, HookHandler, HookHandlerSpec, HookMatcher,
        HookOwnership, HookRouteOwner, HookSourceLayer, HookTransformCapabilities, HookTrustState,
    },
    providers::ProviderId,
    sessions::SessionAuthorityKey,
    state::atomic_json::{
        AtomicJsonStore, OwnerGeneration, StateError, StateRevision, StateSnapshot,
    },
    workflows::{CompiledWorkflowProfileRevision, CompiledWorkflowRevision},
};

use super::{GatewayHookRegistration, UpstreamToolRegistration};

const RUNTIME_REGISTRATION_SCHEMA_VERSION: u32 = 1;
const RUNTIME_REGISTRATION_ALGORITHM: &str = "hmac-sha256";
const MAX_CONTEXT_ID_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRegistrationContext {
    pub repository_key: String,
    pub workspace_key: String,
    pub provider: ProviderId,
}

impl RuntimeRegistrationContext {
    pub fn new(
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        provider: ProviderId,
    ) -> Result<Self, RuntimeRegistrationError> {
        let context = Self {
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            provider,
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), RuntimeRegistrationError> {
        validate_context_id(&self.repository_key)?;
        validate_context_id(&self.workspace_key)
    }

    fn storage_digest(&self) -> Result<String, RuntimeRegistrationError> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| RuntimeRegistrationError::Serialization(error.to_string()))?;
        Ok(crate::sha256_digest(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
enum RuntimeHookAction {
    StructuredCommand {
        executable: PathBuf,
        arguments: Vec<String>,
        working_directory: PathBuf,
    },
    Http {
        endpoint: String,
    },
    McpTool {
        server: String,
        tool: String,
    },
}

impl RuntimeHookAction {
    fn from_handler(handler: &HookHandler) -> Result<Self, RuntimeRegistrationError> {
        if let Some(command) = handler
            .action()
            .materialize_command()
            .map_err(|error| RuntimeRegistrationError::InvalidHook(error.to_string()))?
        {
            if !command.environment.is_empty() {
                return Err(RuntimeRegistrationError::SecretMaterialUnsupported);
            }
            return Ok(Self::StructuredCommand {
                executable: command.executable,
                arguments: command.arguments,
                working_directory: command.working_directory,
            });
        }
        if let Some(endpoint) = handler.action().http_endpoint() {
            return Ok(Self::Http {
                endpoint: endpoint.to_string(),
            });
        }
        if let Some((server, tool)) = handler.action().mcp_target() {
            return Ok(Self::McpTool {
                server: server.to_string(),
                tool: tool.to_string(),
            });
        }
        Err(RuntimeRegistrationError::UnsupportedHookAction)
    }

    fn materialize(&self) -> Result<HookAction, RuntimeRegistrationError> {
        match self {
            Self::StructuredCommand {
                executable,
                arguments,
                working_directory,
            } => HookAction::structured_command(
                executable,
                arguments.clone(),
                working_directory,
                BTreeMap::new(),
                Vec::new(),
            ),
            Self::Http { endpoint } => HookAction::http(endpoint.clone()),
            Self::McpTool { server, tool } => HookAction::mcp_tool(server.clone(), tool.clone()),
        }
        .map_err(|error| RuntimeRegistrationError::InvalidHook(error.to_string()))
    }
}

/// Secret-free, authenticated reconstruction material for one reviewed hook.
///
/// Command environment values are deliberately unsupported: persisted runtime
/// registrations may contain credential key identifiers, never secret bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeHookRegistration {
    handler_id: String,
    provider: ProviderId,
    native_event: String,
    event_family: HookEventFamily,
    matcher: String,
    action: RuntimeHookAction,
    order: i32,
    timeout_ms: u64,
    failure_policy: HookFailurePolicy,
    source_layer: HookSourceLayer,
    ownership: HookOwnership,
    route_owner: HookRouteOwner,
    enabled: bool,
    transformations: HookTransformCapabilities,
    handler_fingerprint: String,
    trust: HookTrustState,
}

impl RuntimeHookRegistration {
    pub fn from_handler(handler: HookHandler) -> Result<Self, RuntimeRegistrationError> {
        let registration = Self {
            handler_id: handler.id().to_string(),
            provider: handler.provider(),
            native_event: handler.native_event().to_string(),
            event_family: handler.event_family(),
            matcher: handler.matcher().expression().to_string(),
            action: RuntimeHookAction::from_handler(&handler)?,
            order: handler.order(),
            timeout_ms: handler.timeout_ms(),
            failure_policy: handler.failure_policy(),
            source_layer: handler.source_layer(),
            ownership: handler.ownership(),
            route_owner: handler.route_owner(),
            enabled: handler.enabled(),
            transformations: handler.transformations(),
            handler_fingerprint: handler.fingerprint().to_string(),
            trust: handler.trust().clone(),
        };
        let reconstructed = registration.materialize()?;
        if reconstructed.fingerprint() != handler.fingerprint()
            || reconstructed.trust() != handler.trust()
        {
            return Err(RuntimeRegistrationError::UnsupportedHookAction);
        }
        Ok(registration)
    }

    fn materialize(&self) -> Result<HookHandler, RuntimeRegistrationError> {
        let spec = HookHandlerSpec {
            id: self.handler_id.clone(),
            provider: self.provider,
            native_event: self.native_event.clone(),
            event_family: self.event_family,
            matcher: HookMatcher::new(self.matcher.clone())
                .map_err(|error| RuntimeRegistrationError::InvalidHook(error.to_string()))?,
            action: self.action.materialize()?,
            order: self.order,
            timeout_ms: self.timeout_ms,
            failure_policy: self.failure_policy,
            source_layer: self.source_layer,
            ownership: self.ownership,
            route_owner: self.route_owner,
            enabled: self.enabled,
            transformations: self.transformations,
        };
        let handler = if matches!(self.trust, HookTrustState::Managed { .. }) {
            HookHandler::new_managed(spec)
        } else {
            HookHandler::new(spec)
        }
        .map_err(|error| RuntimeRegistrationError::InvalidHook(error.to_string()))?;
        if handler.fingerprint() != self.handler_fingerprint {
            return Err(RuntimeRegistrationError::InvalidHook(
                "hook execution fingerprint changed".to_string(),
            ));
        }
        handler
            .restore_authenticated_runtime_trust(self.trust.clone())
            .map_err(|error| RuntimeRegistrationError::InvalidHook(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum RuntimeExecutionRegistration {
    McpTool {
        registration: Box<UpstreamToolRegistration>,
    },
    Hook {
        handlers_by_profile: BTreeMap<String, RuntimeHookRegistration>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeRegistrationValue {
    pub context: RuntimeRegistrationContext,
    pub catalog_record: CatalogRecord,
    execution: RuntimeExecutionRegistration,
}

impl RuntimeRegistrationValue {
    pub fn mcp_tool(
        context: RuntimeRegistrationContext,
        catalog_record: CatalogRecord,
        registration: UpstreamToolRegistration,
    ) -> Result<Self, RuntimeRegistrationError> {
        let value = Self {
            context,
            catalog_record,
            execution: RuntimeExecutionRegistration::McpTool {
                registration: Box::new(registration),
            },
        };
        value.validate()?;
        Ok(value)
    }

    pub fn hook(
        context: RuntimeRegistrationContext,
        catalog_record: CatalogRecord,
        handlers_by_profile: BTreeMap<String, RuntimeHookRegistration>,
    ) -> Result<Self, RuntimeRegistrationError> {
        let value = Self {
            context,
            catalog_record,
            execution: RuntimeExecutionRegistration::Hook {
                handlers_by_profile,
            },
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), RuntimeRegistrationError> {
        self.context.validate()?;
        if !self.catalog_record.supports_provider(self.context.provider)
            || !crate::is_lower_hex_digest(&self.catalog_record.fingerprint)
        {
            return Err(RuntimeRegistrationError::InvalidRegistration);
        }
        match &self.execution {
            RuntimeExecutionRegistration::McpTool { registration } => {
                registration
                    .verify()
                    .map_err(|error| RuntimeRegistrationError::InvalidTool(error.to_string()))?;
                if self.catalog_record.kind != CapabilityKind::McpTool
                    || registration.capability_id != self.catalog_record.id
                    || registration.capability_fingerprint != self.catalog_record.fingerprint
                    || registration.provider != self.context.provider
                {
                    return Err(RuntimeRegistrationError::InvalidRegistration);
                }
            }
            RuntimeExecutionRegistration::Hook {
                handlers_by_profile,
            } => {
                if self.catalog_record.kind != CapabilityKind::Hook
                    || handlers_by_profile.is_empty()
                {
                    return Err(RuntimeRegistrationError::InvalidRegistration);
                }
                for (profile_digest, handler) in handlers_by_profile {
                    if !crate::is_lower_hex_digest(profile_digest)
                        || handler.provider != self.context.provider
                        || handler.route_owner != HookRouteOwner::Gateway
                    {
                        return Err(RuntimeRegistrationError::InvalidRegistration);
                    }
                    let materialized = handler.materialize()?;
                    if materialized.provider() != self.context.provider
                        || materialized.route_owner() != HookRouteOwner::Gateway
                    {
                        return Err(RuntimeRegistrationError::InvalidRegistration);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredRuntimeRegistration {
    value: RuntimeRegistrationValue,
    algorithm: String,
    authority_key_id: String,
    authentication_tag: String,
}

impl StoredRuntimeRegistration {
    fn authentication_message(&self) -> Result<Vec<u8>, RuntimeRegistrationError> {
        serde_json::to_vec(&(
            RUNTIME_REGISTRATION_SCHEMA_VERSION,
            &self.value,
            &self.algorithm,
            &self.authority_key_id,
        ))
        .map_err(|error| RuntimeRegistrationError::Serialization(error.to_string()))
    }

    fn seal(
        value: RuntimeRegistrationValue,
        authority_key: &SessionAuthorityKey,
    ) -> Result<Self, RuntimeRegistrationError> {
        value.validate()?;
        let mut stored = Self {
            value,
            algorithm: RUNTIME_REGISTRATION_ALGORITHM.to_string(),
            authority_key_id: authority_key.key_id(),
            authentication_tag: String::new(),
        };
        stored.authentication_tag = authority_key
            .authenticate_runtime_registration(&stored.authentication_message()?)
            .map_err(|_| RuntimeRegistrationError::AuthenticationFailed)?;
        Ok(stored)
    }

    fn verify(&self, authority_key: &SessionAuthorityKey) -> Result<(), RuntimeRegistrationError> {
        if self.algorithm != RUNTIME_REGISTRATION_ALGORITHM
            || self.authority_key_id != authority_key.key_id()
        {
            return Err(RuntimeRegistrationError::AuthenticationFailed);
        }
        authority_key
            .verify_runtime_registration(&self.authentication_message()?, &self.authentication_tag)
            .map_err(|_| RuntimeRegistrationError::AuthenticationFailed)?;
        self.value.validate()
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeRegistrationStore {
    app_state_root: PathBuf,
    authority_key: SessionAuthorityKey,
}

impl RuntimeRegistrationStore {
    #[must_use]
    pub fn new(app_state_root: impl Into<PathBuf>, authority_key: SessionAuthorityKey) -> Self {
        Self {
            app_state_root: app_state_root.into(),
            authority_key,
        }
    }

    #[must_use]
    pub fn registration_path(
        &self,
        context: &RuntimeRegistrationContext,
        capability_id: &CapabilityId,
    ) -> PathBuf {
        let context_digest = context
            .storage_digest()
            .unwrap_or_else(|_| "invalid-context".to_string());
        self.app_state_root
            .join("runtime")
            .join("registrations")
            .join(context_digest)
            .join(format!(
                "{}.json",
                crate::encode_path_segment(capability_id.as_str())
            ))
    }

    pub fn compare_and_swap(
        &self,
        value: &RuntimeRegistrationValue,
        expected: Option<&StateRevision>,
        owner: OwnerGeneration,
    ) -> Result<StateRevision, RuntimeRegistrationError> {
        value.validate()?;
        let path = self.registration_path(&value.context, &value.catalog_record.id);
        let stored = StoredRuntimeRegistration::seal(value.clone(), &self.authority_key)?;
        AtomicJsonStore::new(path, RUNTIME_REGISTRATION_SCHEMA_VERSION)
            .compare_and_swap(expected, owner, &stored)
            .map_err(Into::into)
    }

    pub fn load(
        &self,
        context: &RuntimeRegistrationContext,
        capability_id: &CapabilityId,
    ) -> Result<Option<StateSnapshot<RuntimeRegistrationValue>>, RuntimeRegistrationError> {
        context.validate()?;
        let path = self.registration_path(context, capability_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err(RuntimeRegistrationError::UnsafeRegistrationPath);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(RuntimeRegistrationError::Io(error)),
        }
        let Some(snapshot) = AtomicJsonStore::new(&path, RUNTIME_REGISTRATION_SCHEMA_VERSION)
            .load::<StoredRuntimeRegistration>()?
        else {
            return Ok(None);
        };
        snapshot.value.verify(&self.authority_key)?;
        if snapshot.value.value.context != *context {
            return Err(RuntimeRegistrationError::ContextMismatch);
        }
        if snapshot.value.value.catalog_record.id != *capability_id {
            return Err(RuntimeRegistrationError::CapabilityMismatch);
        }
        Ok(Some(StateSnapshot {
            schema_version: snapshot.schema_version,
            revision: snapshot.revision,
            owner: snapshot.owner,
            value: snapshot.value.value,
        }))
    }

    pub fn load_workflow_envelope(
        &self,
        context: &RuntimeRegistrationContext,
        workflow: &CompiledWorkflowRevision,
        catalog: &Catalog,
    ) -> Result<WorkflowRuntimeEnvelope, RuntimeRegistrationError> {
        self.load_workflow_envelope_with_skill_catalog(context, workflow, catalog, catalog)
    }

    pub fn load_workflow_envelope_with_skill_catalog(
        &self,
        context: &RuntimeRegistrationContext,
        workflow: &CompiledWorkflowRevision,
        catalog: &Catalog,
        immutable_skill_catalog: &Catalog,
    ) -> Result<WorkflowRuntimeEnvelope, RuntimeRegistrationError> {
        context.validate()?;
        workflow
            .verify_digest()
            .map_err(|error| RuntimeRegistrationError::InvalidWorkflow(error.to_string()))?;
        if workflow.provider != context.provider {
            return Err(RuntimeRegistrationError::ContextMismatch);
        }
        let mut records = Vec::with_capacity(workflow.maximum_envelope.members.len());
        let mut tools = BTreeMap::new();
        let mut hooks = BTreeMap::new();
        let mut registration_ids = BTreeSet::new();
        for member in &workflow.maximum_envelope.members {
            let catalog_record = catalog.get(&member.capability_id).ok_or_else(|| {
                RuntimeRegistrationError::StaleRegistration(member.capability_id.clone())
            })?;
            if catalog_record.fingerprint != member.capability_fingerprint
                || catalog_record.origin.canonical_key != member.catalog_origin_key
                || !catalog_record.supports_provider(context.provider)
            {
                return Err(RuntimeRegistrationError::StaleRegistration(
                    member.capability_id.clone(),
                ));
            }
            match catalog_record.kind {
                CapabilityKind::McpTool | CapabilityKind::Hook => {
                    let snapshot = self.load(context, &member.capability_id)?.ok_or_else(|| {
                        RuntimeRegistrationError::MissingRegistration(member.capability_id.clone())
                    })?;
                    if snapshot.value.catalog_record != *catalog_record {
                        return Err(RuntimeRegistrationError::StaleRegistration(
                            member.capability_id.clone(),
                        ));
                    }
                    let RuntimeRegistrationValue {
                        catalog_record,
                        execution,
                        ..
                    } = snapshot.value;
                    records.push(catalog_record.clone());
                    match execution {
                        RuntimeExecutionRegistration::McpTool { registration } => {
                            if !registration_ids.insert(registration.registration_id.clone()) {
                                return Err(
                                    RuntimeRegistrationError::DuplicateExecutionRegistration(
                                        registration.registration_id,
                                    ),
                                );
                            }
                            tools.insert(catalog_record.id, *registration);
                        }
                        RuntimeExecutionRegistration::Hook {
                            handlers_by_profile,
                        } => {
                            hooks.insert(catalog_record.id, handlers_by_profile);
                        }
                    }
                }
                CapabilityKind::Skill => {
                    let immutable = immutable_skill_catalog
                        .get(&member.capability_id)
                        .ok_or_else(|| {
                            RuntimeRegistrationError::MissingRegistration(
                                member.capability_id.clone(),
                            )
                        })?;
                    if immutable.kind != CapabilityKind::Skill
                        || immutable.fingerprint != member.capability_fingerprint
                        || immutable.origin.canonical_key != member.catalog_origin_key
                        || !immutable.supports_provider(context.provider)
                    {
                        return Err(RuntimeRegistrationError::StaleRegistration(
                            member.capability_id.clone(),
                        ));
                    }
                    records.push(immutable.clone());
                }
                _ => {
                    return Err(RuntimeRegistrationError::UnsupportedCapability(
                        member.capability_id.clone(),
                    ));
                }
            }
        }
        let catalog = Catalog::from_records(records)
            .map_err(|error| RuntimeRegistrationError::InvalidCatalog(error.to_string()))?;
        let envelope = WorkflowRuntimeEnvelope {
            catalog,
            tools,
            hooks,
            profile_digests: workflow
                .effective_profiles
                .values()
                .map(|profile| profile.digest.clone())
                .collect(),
        };
        for profile in workflow.effective_profiles.values() {
            let _ = envelope.registrations_for(profile)?;
        }
        Ok(envelope)
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeModeRegistrations {
    pub tools: Vec<UpstreamToolRegistration>,
    pub hooks: Vec<GatewayHookRegistration>,
}

#[derive(Debug, Clone)]
pub struct WorkflowRuntimeEnvelope {
    catalog: Catalog,
    tools: BTreeMap<CapabilityId, UpstreamToolRegistration>,
    hooks: BTreeMap<CapabilityId, BTreeMap<String, RuntimeHookRegistration>>,
    profile_digests: BTreeSet<String>,
}

impl WorkflowRuntimeEnvelope {
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    pub fn registrations_for(
        &self,
        profile: &CompiledWorkflowProfileRevision,
    ) -> Result<RuntimeModeRegistrations, RuntimeRegistrationError> {
        profile
            .verify_digest()
            .map_err(|error| RuntimeRegistrationError::InvalidWorkflow(error.to_string()))?;
        if !self.profile_digests.contains(&profile.digest) {
            return Err(RuntimeRegistrationError::ProfileMismatch);
        }
        let mut tools = Vec::new();
        let mut hooks = Vec::new();
        for member in &profile.members {
            let record = self.catalog.get(&member.capability_id).ok_or_else(|| {
                RuntimeRegistrationError::MissingRegistration(member.capability_id.clone())
            })?;
            if record.fingerprint != member.capability_fingerprint
                || record.origin.canonical_key != member.catalog_origin_key
            {
                return Err(RuntimeRegistrationError::StaleRegistration(
                    member.capability_id.clone(),
                ));
            }
            match record.kind {
                CapabilityKind::McpTool => tools.push(
                    self.tools
                        .get(&member.capability_id)
                        .cloned()
                        .ok_or_else(|| {
                            RuntimeRegistrationError::MissingRegistration(
                                member.capability_id.clone(),
                            )
                        })?,
                ),
                CapabilityKind::Hook => {
                    let runtime = self
                        .hooks
                        .get(&member.capability_id)
                        .and_then(|handlers| handlers.get(&profile.digest))
                        .ok_or_else(|| RuntimeRegistrationError::MissingHookTrust {
                            capability_id: member.capability_id.clone(),
                            profile_digest: profile.digest.clone(),
                        })?;
                    let handler = runtime.materialize()?;
                    handler
                        .verify_for_dispatch(&profile.digest)
                        .map_err(|error| {
                            RuntimeRegistrationError::InvalidHook(error.to_string())
                        })?;
                    hooks.push(GatewayHookRegistration {
                        capability_id: member.capability_id.clone(),
                        capability_fingerprint: member.capability_fingerprint.clone(),
                        provider: handler.provider(),
                        handler,
                    });
                }
                CapabilityKind::Skill => {}
                _ => {
                    return Err(RuntimeRegistrationError::UnsupportedCapability(
                        member.capability_id.clone(),
                    ));
                }
            }
        }
        Ok(RuntimeModeRegistrations { tools, hooks })
    }
}

fn validate_context_id(value: &str) -> Result<(), RuntimeRegistrationError> {
    if value.is_empty() || value.len() > MAX_CONTEXT_ID_BYTES || value.chars().any(char::is_control)
    {
        Err(RuntimeRegistrationError::InvalidContext)
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum RuntimeRegistrationError {
    State(StateError),
    Io(std::io::Error),
    InvalidContext,
    InvalidRegistration,
    InvalidTool(String),
    InvalidHook(String),
    InvalidWorkflow(String),
    InvalidCatalog(String),
    Serialization(String),
    AuthenticationFailed,
    ContextMismatch,
    CapabilityMismatch,
    UnsafeRegistrationPath,
    SecretMaterialUnsupported,
    UnsupportedHookAction,
    MissingRegistration(CapabilityId),
    StaleRegistration(CapabilityId),
    DuplicateExecutionRegistration(String),
    MissingHookTrust {
        capability_id: CapabilityId,
        profile_digest: String,
    },
    UnsupportedCapability(CapabilityId),
    ProfileMismatch,
}

impl From<StateError> for RuntimeRegistrationError {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl fmt::Display for RuntimeRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(error) => error.fmt(formatter),
            Self::Io(error) => write!(formatter, "runtime registration I/O failed: {error}"),
            Self::InvalidContext => formatter.write_str("runtime registration context is invalid"),
            Self::InvalidRegistration => formatter.write_str("runtime registration is invalid"),
            Self::InvalidTool(error) => {
                write!(formatter, "runtime tool registration is invalid: {error}")
            }
            Self::InvalidHook(error) => {
                write!(formatter, "runtime hook registration is invalid: {error}")
            }
            Self::InvalidWorkflow(error) => {
                write!(formatter, "runtime workflow envelope is invalid: {error}")
            }
            Self::InvalidCatalog(error) => write!(
                formatter,
                "runtime registration catalog is invalid: {error}"
            ),
            Self::Serialization(error) => write!(
                formatter,
                "runtime registration serialization failed: {error}"
            ),
            Self::AuthenticationFailed => {
                formatter.write_str("runtime registration authentication failed")
            }
            Self::ContextMismatch => {
                formatter.write_str("runtime registration context does not match launch")
            }
            Self::CapabilityMismatch => {
                formatter.write_str("runtime registration capability does not match path")
            }
            Self::UnsafeRegistrationPath => {
                formatter.write_str("runtime registration path is unsafe")
            }
            Self::SecretMaterialUnsupported => {
                formatter.write_str("runtime registrations cannot persist secret material")
            }
            Self::UnsupportedHookAction => {
                formatter.write_str("hook action cannot be represented without secret material")
            }
            Self::MissingRegistration(capability) => write!(
                formatter,
                "runtime registration is missing for {capability}"
            ),
            Self::StaleRegistration(capability) => {
                write!(formatter, "runtime registration is stale for {capability}")
            }
            Self::DuplicateExecutionRegistration(id) => {
                write!(formatter, "duplicate runtime execution registration: {id}")
            }
            Self::MissingHookTrust {
                capability_id,
                profile_digest,
            } => write!(
                formatter,
                "runtime hook trust is missing for {capability_id} in profile {profile_digest}"
            ),
            Self::UnsupportedCapability(capability) => {
                write!(formatter, "unsupported runtime capability: {capability}")
            }
            Self::ProfileMismatch => {
                formatter.write_str("runtime registration profile is outside the workflow envelope")
            }
        }
    }
}

impl std::error::Error for RuntimeRegistrationError {}
