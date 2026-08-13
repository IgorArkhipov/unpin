use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

#[cfg(unix)]
use rmcp::{ServiceExt, model::CallToolRequestParams};

use unpin_core::{
    approval::ControlApprovalContext,
    catalog::{
        CapabilityKind, Catalog, adoption::authenticated_adopted_skill_catalog_for_capabilities,
    },
    config::get_session_overlay_root,
    discovery::{DiscoveryMutability, DiscoveryRoots, discover_all},
    gateway::{
        GatewayControlPlane, GatewayError, GatewayExposure, GatewayLimits, GatewayService,
        RuntimeRegistrationContext, RuntimeRegistrationStore, WorkflowRuntimeEnvelope,
    },
    mutation::{
        BackupAuthenticationKey, NativeToggleController, RestoreController,
        load_backup_summaries_authenticated,
    },
    profiles::{CapabilityLockState, PolicyTarget, ProfileStore, policy_resource_id},
    providers::ProviderId,
    sessions::{
        BootstrapRequest, ClaimedSession, CoverageLevel, GatewayModeTarget,
        GatewayNativeViewController, IsolationLevel, LeaseError, LeaseLifecycle, PinnedExposure,
        PinnedProfile, PinnedWorkflowEnvelope, ProcessEvidence, SESSION_OVERLAY_MARKER,
        SessionAuthorityKey, SessionHandle, SessionManager, WORKFLOW_PROPOSAL_SCHEMA_VERSION,
        WorkflowJournal, WorkflowOperationLifecycle, WorkflowReloadLimitation,
        capture_process_evidence, gateway_mode_resource_id, resolved_mode_exposure,
    },
    state::atomic_json::{AtomicJsonStore, OwnerGeneration},
    workflows::WorkflowStore,
};

#[cfg(unix)]
use unpin_cli::mcp_runtime::GatewayRuntimeTimeouts;
use unpin_cli::mcp_runtime::{
    BoundBearerToken, GatewayCredentialResolver, GatewayHookAuthorizationSource,
    GatewayRuntimeError,
};

use crate::gateway_session::GatewaySessionRuntime;

const LAUNCH_CONTROL_SCHEMA_VERSION: u32 = 2;
const LAUNCH_CONTROL_VERSION: u32 = 1;
const LAUNCH_CONTROL_ALGORITHM: &str = "hmac-sha256";
const WRAPPER_START_TIMEOUT: Duration = Duration::from_secs(15);
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(250);
const SESSION_LIFETIME_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug)]
pub struct SessionLaunchRequest {
    pub app_state_root: PathBuf,
    pub discovery_roots: DiscoveryRoots,
    pub repository_key: String,
    pub workspace_key: String,
    pub workspace_revision: Option<String>,
    pub provider: ProviderId,
    pub exposure: PinnedExposure,
    /// Explicitly reviewed workflow launch handoff. Workflow proposals are
    /// metadata-only; this field is the confirmation boundary that permits
    /// pinning one to the established session.
    pub workflow: Option<WorkflowLaunchRequest>,
    pub bridge_socket: Option<PathBuf>,
    pub command: Vec<OsString>,
    pub authority_key: SessionAuthorityKey,
    pub backup_authentication_key: BackupAuthenticationKey,
    pub fixture_mode: bool,
}

/// Authenticated session metadata made available once the lease, private
/// overlay, and optional gateway are ready, but before the child command is
/// released. Desktop callers can use this handoff to publish the established
/// session while the launch worker continues waiting for the child to exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionEstablished {
    pub session_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub overlay_root: PathBuf,
    pub gateway_socket: Option<PathBuf>,
    pub workflow: Option<PinnedWorkflowEnvelope>,
}

#[derive(Debug, Clone)]
pub struct WorkflowLaunchRequest {
    pub workflow_id: String,
    pub workflow_revision: String,
    pub entry_mode: String,
    pub catalog_revision: String,
    pub proposal_id: String,
    pub proposal_fingerprint: String,
    pub prompt_digest: String,
    pub capability_count: usize,
}

#[derive(Debug, Clone)]
struct PreparedWorkflowLaunch {
    revision: unpin_core::workflows::CompiledWorkflowRevision,
    request: WorkflowLaunchRequest,
    runtime: WorkflowRuntimeEnvelope,
}

struct SessionGatewayCredentials {
    tokens: BTreeMap<(String, String), Zeroizing<String>>,
}

impl std::fmt::Debug for SessionGatewayCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionGatewayCredentials")
            .field("bindings", &self.tokens.len())
            .field("tokens", &"[REDACTED]")
            .finish()
    }
}

impl GatewayCredentialResolver for SessionGatewayCredentials {
    fn resolve(
        &self,
        key_id: &str,
        identity: &unpin_core::gateway::UpstreamIdentity,
    ) -> Result<BoundBearerToken, GatewayRuntimeError> {
        let token = self
            .tokens
            .get(&(key_id.to_string(), identity.digest.clone()))
            .ok_or(GatewayRuntimeError::CredentialUnavailable)?;
        BoundBearerToken::new(key_id, identity, token.as_str().to_owned())
    }
}

#[derive(Debug)]
struct SessionGatewayHookAuthorizations;

impl GatewayHookAuthorizationSource for SessionGatewayHookAuthorizations {
    fn authorizations_for(
        &self,
        _plan: &unpin_core::hooks::HookDispatchPlan,
    ) -> Result<Vec<unpin_core::hooks::HookRewriteAuthorization>, GatewayError> {
        // Launch preparation rejects every registered hook that can rewrite
        // arguments or results. Returning no authorizations is therefore an
        // explicit invariant for this immutable runtime, not a silent fallback.
        Ok(Vec::new())
    }
}

struct GatewayRuntimeSources {
    credentials: Arc<dyn GatewayCredentialResolver>,
    hook_authorizations: Arc<dyn GatewayHookAuthorizationSource>,
}

impl PreparedWorkflowLaunch {
    fn envelope(&self, state_sequence: u64) -> PinnedWorkflowEnvelope {
        let entry = &self.revision.effective_profiles[&self.request.entry_mode];
        PinnedWorkflowEnvelope {
            workflow_id: self.request.workflow_id.clone(),
            workflow_revision: self.revision.digest.clone(),
            baseline_profile_id: self.revision.baseline_profile_id.clone(),
            baseline_profile_digest: self.revision.baseline_profile_digest.clone(),
            profile_revisions: self
                .revision
                .effective_profiles
                .iter()
                .map(|(mode, profile)| (mode.clone(), profile.digest.clone()))
                .collect(),
            active_mode: self.request.entry_mode.clone(),
            active_effective_profile_digest: entry.digest.clone(),
            maximum_envelope_digest: self.revision.maximum_envelope.digest.clone(),
            capability_lock_digest: self.revision.capability_lock_digest.clone(),
            catalog_revision: self.request.catalog_revision.clone(),
            proposal_id: self.request.proposal_id.clone(),
            proposal_fingerprint: self.request.proposal_fingerprint.clone(),
            state_sequence,
            sealed_generation: 1,
        }
    }
}

fn gateway_runtime_sources(
    request: &SessionLaunchRequest,
    workflow: Option<&PreparedWorkflowLaunch>,
) -> Result<GatewayRuntimeSources, SessionProcessError> {
    let mut required_credentials = BTreeMap::new();
    if let Some(workflow) = workflow {
        for profile in workflow.revision.effective_profiles.values() {
            let registrations = workflow
                .runtime
                .registrations_for(profile)
                .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
            for registration in registrations.tools {
                if let Some(binding) = registration.credential {
                    required_credentials.insert(
                        (binding.key_id, registration.identity.digest.clone()),
                        registration.identity,
                    );
                }
            }
            for registration in registrations.hooks {
                let transformations = registration.handler.transformations();
                if transformations.argument_rewrite || transformations.result_modification {
                    return Err(SessionProcessError::GatewayPreparation(
                        "workflow hook rewrite authorization source is unavailable".to_string(),
                    ));
                }
            }
        }
    }

    let mut tokens = BTreeMap::new();
    for ((key_id, identity_digest), identity) in required_credentials {
        let token = crate::credentials::resolve_gateway_credential(
            request.fixture_mode,
            &request.app_state_root,
            &key_id,
        )
        .map_err(SessionProcessError::GatewayPreparation)?
        .ok_or_else(|| {
            SessionProcessError::GatewayPreparation(
                "workflow gateway credential is unavailable".to_string(),
            )
        })?;
        BoundBearerToken::new(&key_id, &identity, token.as_str().to_owned())
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
        tokens.insert((key_id, identity_digest), token);
    }
    Ok(GatewayRuntimeSources {
        credentials: Arc::new(SessionGatewayCredentials { tokens }),
        hook_authorizations: Arc::new(SessionGatewayHookAuthorizations),
    })
}

#[derive(Debug, Clone)]
struct LaunchControl {
    version: u32,
    control_path: PathBuf,
    session_id: String,
    overlay_root: PathBuf,
    repository_key: String,
    workspace_key: String,
    provider: String,
    bridge_socket: Option<PathBuf>,
    gateway_socket: Option<PathBuf>,
    process: ProcessEvidence,
    algorithm: String,
    authority_key_id: String,
    authentication_tag: String,
}

impl LaunchControl {
    fn authentication_message(&self) -> Result<Vec<u8>, SessionProcessError> {
        serde_json::to_vec(&serde_json::json!({
            "version": self.version,
            "controlPath": self.control_path,
            "sessionId": self.session_id,
            "overlayRoot": self.overlay_root,
            "repositoryKey": self.repository_key,
            "workspaceKey": self.workspace_key,
            "provider": self.provider,
            "bridgeSocket": self.bridge_socket,
            "gatewaySocket": self.gateway_socket,
            "process": self.process,
            "algorithm": self.algorithm,
            "authorityKeyId": self.authority_key_id,
        }))
        .map_err(SessionProcessError::Json)
    }

    fn to_value(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "controlPath": self.control_path,
            "sessionId": self.session_id,
            "overlayRoot": self.overlay_root,
            "repositoryKey": self.repository_key,
            "workspaceKey": self.workspace_key,
            "provider": self.provider,
            "bridgeSocket": self.bridge_socket,
            "gatewaySocket": self.gateway_socket,
            "process": self.process,
            "algorithm": self.algorithm,
            "authorityKeyId": self.authority_key_id,
            "authenticationTag": self.authentication_tag,
        })
    }

    fn from_value(value: &serde_json::Value) -> Result<Self, SessionProcessError> {
        let object = value
            .as_object()
            .filter(|object| object.len() == 13)
            .ok_or(SessionProcessError::InvalidControl("document"))?;
        let version = object
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(SessionProcessError::InvalidControl("version"))?;
        let required = |field: &'static str| -> Result<String, SessionProcessError> {
            object
                .get(field)
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or(SessionProcessError::InvalidControl(field))
        };
        let bridge_socket = match object.get("bridgeSocket") {
            Some(serde_json::Value::Null) => None,
            Some(value) => {
                Some(PathBuf::from(value.as_str().ok_or(
                    SessionProcessError::InvalidControl("bridgeSocket"),
                )?))
            }
            None => return Err(SessionProcessError::InvalidControl("bridgeSocket")),
        };
        let gateway_socket = match object.get("gatewaySocket") {
            Some(serde_json::Value::Null) => None,
            Some(value) => {
                Some(PathBuf::from(value.as_str().ok_or(
                    SessionProcessError::InvalidControl("gatewaySocket"),
                )?))
            }
            None => return Err(SessionProcessError::InvalidControl("gatewaySocket")),
        };
        let process = object
            .get("process")
            .cloned()
            .ok_or(SessionProcessError::InvalidControl("process"))
            .and_then(|value| {
                serde_json::from_value(value)
                    .map_err(|_| SessionProcessError::InvalidControl("process"))
            })?;
        Ok(Self {
            version,
            control_path: PathBuf::from(required("controlPath")?),
            session_id: required("sessionId")?,
            overlay_root: PathBuf::from(required("overlayRoot")?),
            repository_key: required("repositoryKey")?,
            workspace_key: required("workspaceKey")?,
            provider: required("provider")?,
            bridge_socket,
            gateway_socket,
            process,
            algorithm: required("algorithm")?,
            authority_key_id: required("authorityKeyId")?,
            authentication_tag: required("authenticationTag")?,
        })
    }

    fn seal(&mut self, authority_key: &SessionAuthorityKey) -> Result<(), SessionProcessError> {
        self.algorithm = LAUNCH_CONTROL_ALGORITHM.to_string();
        self.authority_key_id = authority_key.key_id();
        self.authentication_tag = authority_key
            .authenticate_launch_control(&self.authentication_message()?)
            .map_err(SessionProcessError::ControlAuthentication)?;
        Ok(())
    }

    fn verify(
        &self,
        control_path: &Path,
        authority_key: &SessionAuthorityKey,
    ) -> Result<(), SessionProcessError> {
        if self.version != LAUNCH_CONTROL_VERSION
            || self.control_path != control_path
            || self.algorithm != LAUNCH_CONTROL_ALGORITHM
            || self.authority_key_id != authority_key.key_id()
        {
            return Err(SessionProcessError::ControlAuthentication(
                "launch control binding mismatch".to_string(),
            ));
        }
        authority_key
            .verify_launch_control(&self.authentication_message()?, &self.authentication_tag)
            .map_err(SessionProcessError::ControlAuthentication)?;
        validate_control_string(&self.session_id, "sessionId")?;
        validate_control_path(&self.overlay_root, "overlayRoot")?;
        validate_control_string(&self.repository_key, "repositoryKey")?;
        validate_control_string(&self.workspace_key, "workspaceKey")?;
        validate_control_string(&self.provider, "provider")?;
        if let Some(bridge_socket) = &self.bridge_socket {
            validate_control_path(bridge_socket, "bridgeSocket")?;
        }
        if let Some(gateway_socket) = &self.gateway_socket {
            validate_control_path(gateway_socket, "gatewaySocket")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLaunchResult {
    pub session_id: String,
    pub provider: ProviderId,
    pub repository_key: String,
    pub workspace_key: String,
    pub child_exit_code: Option<i32>,
    pub cleanup_failures: Vec<String>,
    pub isolation: IsolationLevel,
    pub degradation: Vec<String>,
}

impl SessionLaunchResult {
    #[must_use]
    pub fn cleanup_complete(&self) -> bool {
        self.cleanup_failures.is_empty()
    }

    pub fn to_json(&self) -> serde_json::Value {
        let cleanup_complete = self.cleanup_complete();
        serde_json::json!({
            "status": if !cleanup_complete {
                "recovery-required"
            } else if self.child_exit_code == Some(0) {
                "completed"
            } else {
                "child-failed"
            },
            "sessionId": self.session_id,
            "provider": self.provider,
            "repositoryKey": self.repository_key,
            "workspaceKey": self.workspace_key,
            "childExitCode": self.child_exit_code,
            "cleanupComplete": cleanup_complete,
            "cleanupFailures": self.cleanup_failures,
            "isolation": "connection-scoped",
            "degradation": self.degradation,
        })
    }
}

pub fn launch(request: SessionLaunchRequest) -> Result<SessionLaunchResult, SessionProcessError> {
    launch_with_established_callback(request, |_| {})
}

/// Launch a session and invoke `on_established` after authenticated bootstrap
/// succeeds, before the child command is released. The callback receives
/// owned metadata so a desktop caller can hand it to another worker without
/// borrowing the launch stack. It is a notification only; returning from it
/// hands control back to the same blocking launch lifecycle used by [`launch`].
pub(crate) fn launch_with_established_callback<F>(
    mut request: SessionLaunchRequest,
    on_established: F,
) -> Result<SessionLaunchResult, SessionProcessError>
where
    F: FnOnce(SessionEstablished),
{
    if request.command.is_empty() {
        return Err(SessionProcessError::MissingCommand);
    }
    if requires_verified_provider_overlay(&request.exposure.profile) && !request.fixture_mode {
        return Err(SessionProcessError::ProviderOverlayUnavailable);
    }
    let workflow = prepare_workflow_launch(&mut request)?;
    request.bridge_socket = request
        .bridge_socket
        .as_deref()
        .map(verified_bridge_socket)
        .transpose()?;
    let now_unix = unix_now()?;
    let manager =
        SessionManager::with_authority_key(&request.app_state_root, request.authority_key.clone());
    let control_path = launch_control_path(&request.app_state_root)?;
    let mut child = spawn_wrapper(
        &request.app_state_root,
        &control_path,
        &request.command,
        request.fixture_mode,
    )?;
    let result = establish_and_wait(
        &manager,
        &request,
        workflow.as_ref(),
        on_established,
        &control_path,
        &mut child,
        now_unix,
    );
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = remove_control_if_present(&control_path);
    }
    result
}

fn prepare_workflow_launch(
    request: &mut SessionLaunchRequest,
) -> Result<Option<PreparedWorkflowLaunch>, SessionProcessError> {
    let Some(workflow_request) = request.workflow.clone() else {
        return Ok(None);
    };
    let revision = WorkflowStore::new(&request.app_state_root)
        .load_revision(&workflow_request.workflow_revision)
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?
        .ok_or_else(|| {
            SessionProcessError::WorkflowLaunch("workflow-revision-unavailable".to_string())
        })?;
    if revision.workflow_id != workflow_request.workflow_id {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-id-mismatch".to_string(),
        ));
    }
    if revision.entry_mode != workflow_request.entry_mode {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-entry-mode-mismatch".to_string(),
        ));
    }
    if revision.provider != request.provider {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-provider-mismatch".to_string(),
        ));
    }
    let discovery = discover_all(&request.discovery_roots)
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let catalog = Catalog::from_discovery(&discovery)
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let catalog_revision = unpin_core::sha256_digest(
        &serde_json::to_vec(&catalog)
            .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?,
    );
    if catalog_revision != workflow_request.catalog_revision {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-catalog-revision-stale".to_string(),
        ));
    }
    for (capability_id, fingerprint) in &revision.catalog_fingerprints {
        let Some(record) = catalog.get(capability_id) else {
            return Err(SessionProcessError::WorkflowLaunch(
                "workflow-catalog-capability-missing".to_string(),
            ));
        };
        if record.fingerprint != *fingerprint || !record.supports_provider(request.provider) {
            return Err(SessionProcessError::WorkflowLaunch(
                "workflow-catalog-capability-stale".to_string(),
            ));
        }
    }
    let skill_capability_ids = revision
        .maximum_envelope
        .members
        .iter()
        .filter_map(|member| {
            catalog
                .get(&member.capability_id)
                .filter(|record| record.kind == CapabilityKind::Skill)
                .map(|_| member.capability_id.clone())
        })
        .collect::<Vec<_>>();
    let immutable_skill_catalog = if skill_capability_ids.is_empty() {
        Catalog::default()
    } else if request.fixture_mode {
        Catalog::from_records(
            skill_capability_ids
                .iter()
                .map(|capability_id| {
                    catalog.get(capability_id).cloned().ok_or_else(|| {
                        SessionProcessError::WorkflowLaunch(
                            "workflow-skill-capability-missing".to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        )
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?
    } else {
        authenticated_adopted_skill_catalog_for_capabilities(
            &request.app_state_root,
            &request.repository_key,
            &request.workspace_key,
            request.provider,
            &skill_capability_ids,
            &request.backup_authentication_key,
        )
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?
    };
    let runtime_context = RuntimeRegistrationContext::new(
        &request.repository_key,
        &request.workspace_key,
        request.provider,
    )
    .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let runtime =
        RuntimeRegistrationStore::new(&request.app_state_root, request.authority_key.clone())
            .load_workflow_envelope_with_skill_catalog(
                &runtime_context,
                &revision,
                &catalog,
                &immutable_skill_catalog,
            )
            .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let locks = request.exposure.capability_locks.as_ref().ok_or_else(|| {
        SessionProcessError::WorkflowLaunch("workflow-capability-locks-missing".to_string())
    })?;
    locks
        .verify()
        .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    if locks.provider != request.provider {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-capability-lock-provider-mismatch".to_string(),
        ));
    }
    if locks.digest != revision.capability_lock_digest {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-capability-lock-revision-stale".to_string(),
        ));
    }
    verify_workflow_proposal(request, &workflow_request, &revision)?;
    let entry = revision
        .effective_profiles
        .get(&workflow_request.entry_mode)
        .ok_or_else(|| {
            SessionProcessError::WorkflowLaunch("workflow-entry-profile-missing".to_string())
        })?;
    let expected_profile = PinnedProfile::Profile {
        profile_id: entry.profile_id.clone(),
        profile_digest: entry.digest.clone(),
        origin_scope: unpin_core::profiles::ProfileSourceScope::Session,
        definition_digest: revision.digest.clone(),
    };
    if !matches!(&request.exposure.profile, PinnedProfile::None)
        && request.exposure.profile != expected_profile
    {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-entry-profile-mismatch".to_string(),
        ));
    }
    if request.exposure.revision != entry.digest {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-entry-exposure-mismatch".to_string(),
        ));
    }
    request.exposure = PinnedExposure {
        revision: entry.digest.clone(),
        profile: expected_profile,
        capability_locks: request.exposure.capability_locks.clone(),
    };
    Ok(Some(PreparedWorkflowLaunch {
        revision,
        request: workflow_request,
        runtime,
    }))
}

fn verify_workflow_proposal(
    request: &SessionLaunchRequest,
    proposal: &WorkflowLaunchRequest,
    revision: &unpin_core::workflows::CompiledWorkflowRevision,
) -> Result<(), SessionProcessError> {
    if proposal.catalog_revision.is_empty()
        || proposal.prompt_digest.len() != 64
        || !proposal
            .prompt_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-proposal-invalid".to_string(),
        ));
    }
    if proposal.capability_count != revision.maximum_envelope.authored_member_count {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-proposal-capability-count-mismatch".to_string(),
        ));
    }
    let proposal_id_material = serde_json::to_vec(&(
        &proposal.workflow_id,
        &proposal.entry_mode,
        request.provider,
        &request.repository_key,
        &request.workspace_key,
        &proposal.catalog_revision,
        &proposal.workflow_revision,
        &proposal.prompt_digest,
    ))
    .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let expected_proposal_id = format!(
        "workflow-proposal-{}",
        &workflow_domain_digest(b"unpin.workflow.proposal-id.v1", &proposal_id_material)[..24]
    );
    if proposal.proposal_id != expected_proposal_id {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-proposal-id-mismatch".to_string(),
        ));
    }
    let fingerprint_material = serde_json::to_vec(&(
        WORKFLOW_PROPOSAL_SCHEMA_VERSION,
        &proposal.proposal_id,
        &proposal.workflow_id,
        &proposal.entry_mode,
        request.provider,
        &request.repository_key,
        &request.workspace_key,
        &proposal.catalog_revision,
        &proposal.workflow_revision,
        &proposal.prompt_digest,
        proposal.capability_count,
        true,
        WorkflowReloadLimitation::LiveRefreshExpected,
    ))
    .map_err(|error| SessionProcessError::WorkflowLaunch(error.to_string()))?;
    let expected_fingerprint =
        workflow_domain_digest(b"unpin.workflow.proposal.v1", &fingerprint_material);
    if proposal.proposal_fingerprint != expected_fingerprint {
        return Err(SessionProcessError::WorkflowLaunch(
            "workflow-proposal-fingerprint-mismatch".to_string(),
        ));
    }
    Ok(())
}

fn workflow_domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut material = Vec::with_capacity(16 + domain.len() + bytes.len());
    material.extend((domain.len() as u64).to_be_bytes());
    material.extend(domain);
    material.extend((bytes.len() as u64).to_be_bytes());
    material.extend(bytes);
    unpin_core::sha256_digest(&material)
}

pub(crate) fn preflight_bridge_socket(path: Option<&Path>) -> Result<(), SessionProcessError> {
    path.map(verified_bridge_socket).transpose().map(|_| ())
}

/// Resolve the private gateway socket published for an established session.
///
/// The overlay is created by the authenticated session launcher and is kept
/// private to the app-state root. The returned socket still requires the
/// process-generation-bound transport handshake before the gateway issues a
/// connection claim; auxiliary clients are limited to the typed workflow
/// control surface.
#[cfg(unix)]
fn gateway_transport_metadata_for_session(
    app_state_root: &Path,
    session_id: &str,
) -> Result<(PathBuf, ProcessEvidence, bool), SessionProcessError> {
    if session_id.is_empty()
        || session_id.len() > 128
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let overlay_root = get_session_overlay_root(app_state_root, session_id);
    let overlay_metadata = fs::symlink_metadata(&overlay_root)
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if overlay_metadata.file_type().is_symlink() || !overlay_metadata.is_dir() {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let marker_path = overlay_root.join(SESSION_OVERLAY_MARKER);
    let marker_metadata = fs::symlink_metadata(&marker_path)
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let marker: serde_json::Value = serde_json::from_slice(
        &fs::read(&marker_path).map_err(|_| SessionProcessError::GatewayControlUnavailable)?,
    )
    .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if marker.get("version").and_then(serde_json::Value::as_u64) != Some(1)
        || marker.get("sessionId").and_then(serde_json::Value::as_str) != Some(session_id)
    {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let gateway_path = overlay_root.join("gateway-session.json");
    let gateway_metadata = fs::symlink_metadata(&gateway_path)
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if gateway_metadata.file_type().is_symlink() || !gateway_metadata.is_file() {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let gateway: serde_json::Value = serde_json::from_slice(
        &fs::read(&gateway_path).map_err(|_| SessionProcessError::GatewayControlUnavailable)?,
    )
    .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if gateway.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    if gateway.get("sessionId").and_then(serde_json::Value::as_str) != Some(session_id) {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let process = gateway
        .get("process")
        .cloned()
        .ok_or(SessionProcessError::GatewayControlUnavailable)
        .and_then(|value| {
            serde_json::from_value(value)
                .map_err(|_| SessionProcessError::GatewayControlUnavailable)
        })?;
    let fixture_mode = gateway
        .get("fixtureMode")
        .and_then(serde_json::Value::as_bool)
        .ok_or(SessionProcessError::GatewayControlUnavailable)?;
    let socket = gateway
        .get("socket")
        .and_then(serde_json::Value::as_str)
        .filter(|socket| !socket.is_empty())
        .map(PathBuf::from)
        .ok_or(SessionProcessError::GatewayControlUnavailable)?;
    Ok((verified_gateway_socket(&socket)?, process, fixture_mode))
}

#[cfg(unix)]
fn verified_gateway_socket(path: &Path) -> Result<PathBuf, SessionProcessError> {
    use std::os::unix::fs::FileTypeExt;

    if !path.is_absolute() {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err(SessionProcessError::GatewayControlUnavailable);
    }
    fs::canonicalize(path).map_err(|_| SessionProcessError::GatewayControlUnavailable)
}

/// Call one of the core-declared workflow controls over an authenticated
/// auxiliary gateway connection. No caller-provided session secret is
/// accepted: the gateway issues and validates the connection claim.
#[cfg(unix)]
pub(crate) fn call_gateway_control(
    app_state_root: &Path,
    session_id: &str,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, SessionProcessError> {
    call_gateway_control_with_timeouts(
        app_state_root,
        session_id,
        tool_name,
        arguments,
        GatewayRuntimeTimeouts::default(),
    )
}

#[cfg(unix)]
fn call_gateway_control_with_timeouts(
    app_state_root: &Path,
    session_id: &str,
    tool_name: &str,
    arguments: serde_json::Value,
    timeouts: GatewayRuntimeTimeouts,
) -> Result<serde_json::Value, SessionProcessError> {
    let (socket, process, fixture_mode) =
        gateway_transport_metadata_for_session(app_state_root, session_id)?;
    let authority_key =
        crate::credentials::resolve_session_authority_key(fixture_mode, app_state_root)
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?
            .ok_or(SessionProcessError::GatewayControlUnavailable)?;
    let authentication_tag = crate::gateway_session::gateway_transport_authentication_tag(
        &authority_key,
        session_id,
        &process,
        &socket,
    )
    .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    let object = arguments
        .as_object()
        .cloned()
        .ok_or(SessionProcessError::GatewayControlUnavailable)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
    runtime.block_on(async move {
        use tokio::io::AsyncWriteExt;

        let mut stream =
            tokio::time::timeout(timeouts.connect, tokio::net::UnixStream::connect(socket))
                .await
                .map_err(|_| SessionProcessError::GatewayControlUnavailable)?
                .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        let frame = crate::gateway_session::gateway_transport_handshake_frame_for_client(
            &authentication_tag,
        )
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        tokio::time::timeout(timeouts.call, stream.write_all(&frame))
            .await
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        let mut client = tokio::time::timeout(timeouts.call, ().serve(stream))
            .await
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        let response = tokio::time::timeout(
            timeouts.call,
            client.call_tool(
                CallToolRequestParams::new(tool_name.to_string()).with_arguments(object),
            ),
        )
        .await
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?
        .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        let value = serde_json::to_value(response)
            .map_err(|_| SessionProcessError::GatewayControlUnavailable)?;
        let _ = client
            .close_with_timeout(std::time::Duration::from_secs(2))
            .await;
        if value
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(SessionProcessError::GatewayControlRejected);
        }
        Ok(value.get("structuredContent").cloned().unwrap_or(value))
    })
}

#[cfg(not(unix))]
pub(crate) fn call_gateway_control(
    _app_state_root: &Path,
    _session_id: &str,
    _tool_name: &str,
    _arguments: serde_json::Value,
) -> Result<serde_json::Value, SessionProcessError> {
    Err(SessionProcessError::GatewayControlUnavailable)
}

fn requires_verified_provider_overlay(profile: &PinnedProfile) -> bool {
    !matches!(profile, PinnedProfile::Native)
}

fn build_gateway_service(
    manager: &SessionManager,
    request: &SessionLaunchRequest,
    handle: &SessionHandle,
    workflow: Option<&PreparedWorkflowLaunch>,
    pinned_workflow: Option<&PinnedWorkflowEnvelope>,
) -> Result<Arc<GatewayService>, SessionProcessError> {
    let profile = if workflow.is_some() {
        None
    } else {
        match &request.exposure.profile {
            PinnedProfile::Profile { profile_digest, .. } => Some(
                ProfileStore::new(&request.app_state_root)
                    .load_revision(profile_digest)
                    .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?
                    .ok_or_else(|| {
                        SessionProcessError::GatewayPreparation(
                            "compiled profile revision is unavailable".to_string(),
                        )
                    })?,
            ),
            PinnedProfile::Native | PinnedProfile::None => None,
        }
    };
    let mut capability_ids = if let Some(workflow) = workflow {
        workflow
            .revision
            .maximum_envelope
            .members
            .iter()
            .map(|member| member.capability_id.clone())
            .collect::<BTreeSet<_>>()
    } else {
        profile
            .iter()
            .flat_map(|profile| profile.members_for_provider(request.provider))
            .map(|member| member.capability_id.clone())
            .collect::<BTreeSet<_>>()
    };
    if let Some(locks) = &request.exposure.capability_locks {
        for (capability_id, state) in &locks.entries {
            match state {
                CapabilityLockState::HardEnabled => {
                    capability_ids.insert(capability_id.clone());
                }
                CapabilityLockState::HardDisabled => {
                    capability_ids.remove(capability_id);
                }
            }
        }
    }
    let catalog = if let Some(workflow) = workflow {
        workflow.runtime.catalog().clone()
    } else if capability_ids.is_empty() {
        Catalog::default()
    } else {
        authenticated_adopted_skill_catalog_for_capabilities(
            &request.app_state_root,
            &request.repository_key,
            &request.workspace_key,
            request.provider,
            &capability_ids.into_iter().collect::<Vec<_>>(),
            &request.backup_authentication_key,
        )
        .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?
    };
    let limits = GatewayLimits::default();
    let control = GatewayControlPlane::new(
        manager.clone(),
        duplicate_session_handle(handle)?,
        limits.maximum_concurrent_calls,
    )
    .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
    let exposure = if let Some(workflow) = workflow {
        let profile = workflow
            .revision
            .effective_profiles
            .get(&workflow.request.entry_mode)
            .ok_or_else(|| {
                SessionProcessError::GatewayPreparation(
                    "compiled workflow entry profile is unavailable".to_string(),
                )
            })?;
        let registrations = workflow
            .runtime
            .registrations_for(profile)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
        GatewayExposure::compile_workflow_profile_with_hooks(
            request.exposure.clone(),
            request.provider,
            &catalog,
            profile,
            registrations.tools,
            registrations.hooks,
            limits,
        )
    } else {
        GatewayExposure::compile(
            request.exposure.clone(),
            request.provider,
            &catalog,
            profile.as_ref(),
            Vec::new(),
            limits,
        )
    }
    .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
    let gateway = Arc::new(
        GatewayService::new(control, exposure, limits)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
    );
    if let (Some(workflow), Some(pinned_workflow)) = (workflow, pinned_workflow) {
        // The entry exposure is already installed as the primary gateway
        // projection. Register the remaining immutable mode projections on
        // the same service before its listener is started.
        for (mode, profile) in &workflow.revision.effective_profiles {
            let pinned = resolved_mode_exposure(
                pinned_workflow,
                mode,
                &profile.digest,
                request.exposure.capability_locks.clone(),
            );
            let registrations = workflow
                .runtime
                .registrations_for(profile)
                .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
            let exposure = GatewayExposure::compile_workflow_profile_with_hooks(
                pinned,
                request.provider,
                &catalog,
                profile,
                registrations.tools,
                registrations.hooks,
                limits,
            )
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
            if exposure.pinned() != &request.exposure {
                gateway
                    .register_workflow_exposure(exposure)
                    .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
            }
        }
    }
    Ok(gateway)
}

fn duplicate_session_handle(handle: &SessionHandle) -> Result<SessionHandle, SessionProcessError> {
    let mut encoded_secret = Zeroizing::new(Vec::with_capacity(64));
    handle.write_secret(&mut *encoded_secret)?;
    let duplicate = SessionHandle::read_secret(
        handle.session_id().to_string(),
        handle.owner_id().to_string(),
        encoded_secret.as_slice(),
    );
    duplicate.map_err(SessionProcessError::Io)
}

fn write_gateway_overlay(
    overlay_root: &Path,
    session_id: &str,
    process: &ProcessEvidence,
    request: &SessionLaunchRequest,
    socket_path: &Path,
) -> Result<(), SessionProcessError> {
    let executable = std::env::current_exe()?;
    let path = overlay_root.join("gateway-session.json");
    let value = serde_json::json!({
        "version": 1,
        "sessionId": session_id,
        "process": process,
        "fixtureMode": request.fixture_mode,
        "provider": request.provider,
        "attachment": "fixture-harness-only",
        "nativeMaskVerified": false,
        "socket": socket_path,
        "proxy": {
            "command": executable,
            "args": ["gateway-session-proxy", "--socket", socket_path],
        },
    });
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    serde_json::to_writer_pretty(&mut file, &value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(overlay_root)?.sync_all()?;
    Ok(())
}

fn establish_and_wait<F>(
    manager: &SessionManager,
    request: &SessionLaunchRequest,
    workflow: Option<&PreparedWorkflowLaunch>,
    on_established: F,
    control_path: &Path,
    child: &mut Child,
    now_unix: i64,
) -> Result<SessionLaunchResult, SessionProcessError>
where
    F: FnOnce(SessionEstablished),
{
    let process = capture_process_evidence(child.id())?;
    let protected_resources = launch_protected_resources(request)?;
    let connection_scope_id = format!(
        "launcher-{}-{}",
        child.id(),
        control_path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("session")
    );
    let degradation = if requires_verified_provider_overlay(&request.exposure.profile) {
        vec!["fixture-harness-overlay".to_string()]
    } else {
        vec!["native-provider-session".to_string()]
    };
    let authority = manager.prepare_bootstrap(
        BootstrapRequest {
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            workspace_revision: request.workspace_revision.clone(),
            exposure: request.exposure.clone(),
            process: process.clone(),
            connection_scope_id: connection_scope_id.clone(),
            isolation: IsolationLevel::ConnectionScoped,
            coverage: CoverageLevel::ExternalDegraded {
                reasons: degradation.clone(),
            },
            protected_resources,
            lease_expires_at_unix: now_unix
                .checked_add(SESSION_LIFETIME_SECONDS)
                .ok_or(SessionProcessError::Clock)?,
        },
        now_unix,
    )?;
    let overlay_root = get_session_overlay_root(&request.app_state_root, authority.session_id());
    if let Err(error) = create_overlay(
        &request.app_state_root,
        &overlay_root,
        authority.session_id(),
    ) {
        let _ = manager.cancel_bootstrap(&authority);
        let _ = manager.cleanup_overlay(authority.session_id());
        return Err(error);
    }
    let owner_id = format!("session-launcher-{}", child.id());
    let claimed = match manager.claim_bootstrap(
        &authority,
        &unpin_core::sessions::ConnectionClaim {
            connection_owner_id: owner_id,
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: process.clone(),
            connection_scope_id,
        },
        now_unix,
    ) {
        Ok(claimed) => claimed,
        Err(error) => {
            let _ = manager.cancel_bootstrap(&authority);
            let _ = manager.cleanup_overlay(authority.session_id());
            return Err(error.into());
        }
    };

    // Bind the workflow high-water to the authenticated lease state consumed
    // by this claim. Lease CAS revisions continue to advance independently
    // for heartbeats and transitions.
    let pinned_workflow =
        workflow.map(|workflow| workflow.envelope(claimed.lease.revision.sequence));
    if let Some(pinned_workflow) = &pinned_workflow
        && let Err(error) = manager.pin_workflow(
            &claimed.handle,
            &claimed.lease.revision,
            pinned_workflow.clone(),
            request.exposure.clone(),
            now_unix,
        )
    {
        return Err(startup_failure_after_claim(
            manager,
            &claimed,
            authority.session_id(),
            None,
            None,
            SessionProcessError::WorkflowLaunch(error.to_string()),
        ));
    }

    let gateway = if requires_verified_provider_overlay(&request.exposure.profile) {
        match build_gateway_service(
            manager,
            request,
            &claimed.handle,
            workflow,
            pinned_workflow.as_ref(),
        ) {
            Ok(gateway) => Some(gateway),
            Err(error) => {
                return Err(startup_failure_after_claim(
                    manager,
                    &claimed,
                    authority.session_id(),
                    None,
                    None,
                    error,
                ));
            }
        }
    } else {
        None
    };
    let mut gateway_runtime = match gateway {
        Some(gateway) => {
            let sources = gateway_runtime_sources(request, workflow).map_err(|error| {
                startup_failure_after_claim(
                    manager,
                    &claimed,
                    authority.session_id(),
                    None,
                    None,
                    error,
                )
            })?;
            match GatewaySessionRuntime::start(
                gateway,
                &overlay_root,
                sources.credentials,
                sources.hook_authorizations,
                request.authority_key.clone(),
                authority.session_id().to_string(),
                process.clone(),
            ) {
                Ok(runtime) => Some(runtime),
                Err(error) => {
                    return Err(startup_failure_after_claim(
                        manager,
                        &claimed,
                        authority.session_id(),
                        None,
                        None,
                        SessionProcessError::GatewayPreparation(error.to_string()),
                    ));
                }
            }
        }
        None => None,
    };
    let gateway_socket = gateway_runtime
        .as_ref()
        .map(|runtime| runtime.socket_path().to_path_buf());
    if let Some(socket_path) = gateway_socket.as_deref()
        && let Err(error) = write_gateway_overlay(
            &overlay_root,
            authority.session_id(),
            &process,
            request,
            socket_path,
        )
    {
        return Err(startup_failure_after_claim(
            manager,
            &claimed,
            authority.session_id(),
            gateway_runtime.take(),
            None,
            error,
        ));
    }
    on_established(SessionEstablished {
        session_id: authority.session_id().to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        overlay_root: overlay_root.clone(),
        gateway_socket: gateway_socket.clone(),
        workflow: pinned_workflow.clone(),
    });
    let run_result = (|| -> Result<ExitStatus, SessionProcessError> {
        write_control(
            control_path,
            authority.session_id(),
            &overlay_root,
            gateway_socket.clone(),
            process.clone(),
            request,
            &request.authority_key,
        )?;
        loop {
            match child.try_wait()? {
                Some(status) => return Ok(status),
                None => {
                    thread::sleep(HEARTBEAT_INTERVAL);
                    let current = match manager.load_for_handle(&claimed.handle) {
                        Ok(current) => current,
                        Err(LeaseError::SessionNotFound) => {
                            return Err(SessionProcessError::LeaseRevoked);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    if current.lease.lifecycle != LeaseLifecycle::Active {
                        return Err(SessionProcessError::LeaseRevoked);
                    }
                }
            }
        }
    })();
    let status = match run_result {
        Ok(status) => status,
        Err(error) => {
            return Err(startup_failure_after_claim(
                manager,
                &claimed,
                authority.session_id(),
                gateway_runtime.take(),
                Some(control_path),
                error,
            ));
        }
    };

    let cleanup_failures = cleanup_claimed_resources(
        manager,
        &claimed,
        authority.session_id(),
        gateway_runtime.take(),
        Some(control_path),
        "child-exit",
    );
    Ok(SessionLaunchResult {
        session_id: authority.session_id().to_string(),
        provider: request.provider,
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        child_exit_code: status.code(),
        cleanup_failures,
        isolation: IsolationLevel::ConnectionScoped,
        degradation,
    })
}

fn launch_protected_resources(
    request: &SessionLaunchRequest,
) -> Result<BTreeSet<String>, SessionProcessError> {
    let mut resources = binding_protected_resources(
        &request.repository_key,
        &request.workspace_key,
        request.provider,
    )?;
    let key = &request.backup_authentication_key;
    resources.extend(
        GatewayNativeViewController::new(&request.app_state_root, key.clone())
            .protected_resources_for_session(
                &request.repository_key,
                &request.workspace_key,
                request.provider,
            )
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
    );
    let restore_controller = RestoreController::new(&request.app_state_root);
    let approval_context =
        ControlApprovalContext::new(&request.repository_key, &request.workspace_key)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
    for backup in load_backup_summaries_authenticated(&request.app_state_root, Some(key))
        .into_iter()
        .filter(|backup| backup.restorable && backup.includes_provider(request.provider))
    {
        let plan = restore_controller
            .plan(&backup.backup_id, &approval_context, Some(key))
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
        resources.extend(
            plan.affected_resources
                .into_iter()
                .map(|resource| resource.resource_id),
        );
    }
    let discovery = discover_all(&request.discovery_roots)
        .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
    if let Some(warning) = discovery
        .warnings
        .iter()
        .find(|warning| warning.provider == request.provider)
    {
        return Err(SessionProcessError::GatewayPreparation(format!(
            "provider discovery warning prevents protected launch: {}",
            warning.code
        )));
    }
    let toggle_controller = NativeToggleController::new(&request.app_state_root);
    for item in discovery.items.into_iter().filter(|item| {
        item.provider == request.provider && item.mutability == DiscoveryMutability::ReadWrite
    }) {
        let plan = toggle_controller
            .plan(item, &approval_context)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?;
        resources.extend(
            plan.transition
                .effects
                .into_iter()
                .map(|effect| effect.resource_id),
        );
    }
    Ok(resources)
}

fn binding_protected_resources(
    repository_key: &str,
    workspace_key: &str,
    provider: ProviderId,
) -> Result<BTreeSet<String>, SessionProcessError> {
    let mode_targets = [
        GatewayModeTarget::global(),
        GatewayModeTarget::global_provider(provider),
        GatewayModeTarget::repository(repository_key)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        GatewayModeTarget::repository_provider(repository_key, provider)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        GatewayModeTarget::workspace(repository_key, workspace_key)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        GatewayModeTarget::workspace_provider(repository_key, workspace_key, provider)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
    ];
    let policy_targets = [
        PolicyTarget::Global,
        PolicyTarget::repository(repository_key)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        PolicyTarget::workspace(repository_key, workspace_key)
            .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
    ];
    let mut resources = BTreeSet::new();
    for target in mode_targets {
        resources.insert(
            gateway_mode_resource_id(&target)
                .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        );
    }
    for target in policy_targets {
        resources.insert(
            policy_resource_id(&target)
                .map_err(|error| SessionProcessError::GatewayPreparation(error.to_string()))?,
        );
    }
    Ok(resources)
}

fn cleanup_claimed_session(
    manager: &SessionManager,
    claimed: &ClaimedSession,
    reason: &str,
) -> Result<(), LeaseError> {
    match manager.load_for_handle(&claimed.handle) {
        Ok(current) if current.lease.in_flight_calls == 0 => {
            let now_unix =
                unix_now().map_err(|error| LeaseError::InvalidState(error.to_string()))?;
            cleanup_claimed_workflows(manager, &claimed.handle, &current, reason, now_unix)?;
            manager.close_owned(&claimed.handle, &current.revision, reason, now_unix)
        }
        Ok(_) => Err(LeaseError::SessionDraining),
        Err(LeaseError::SessionNotFound) => Ok(()),
        Err(error) => Err(error),
    }
}

fn cleanup_claimed_workflows(
    manager: &SessionManager,
    handle: &SessionHandle,
    current: &unpin_core::sessions::LeaseSnapshot,
    reason: &str,
    now_unix: i64,
) -> Result<(), LeaseError> {
    let journal = WorkflowJournal::new(manager.app_state_root());
    let lifecycle = if reason == "child-exit" {
        WorkflowOperationLifecycle::Cancelled
    } else {
        WorkflowOperationLifecycle::RecoveryRequired
    };
    let reason_code = if reason == "child-exit" {
        "session-ended-workflow-cancelled"
    } else {
        "session-cleanup-workflow-recovery-required"
    };
    let owner = OwnerGeneration::new(handle.owner_id(), current.revision.sequence)
        .map_err(LeaseError::from)?;

    for record in journal
        .nonterminal_records(handle.session_id())
        .map_err(|error| LeaseError::InvalidState(error.to_string()))?
    {
        let Some(snapshot) = journal
            .load(handle.session_id(), &record.operation_id)
            .map_err(|error| LeaseError::InvalidState(error.to_string()))?
        else {
            continue;
        };
        if !matches!(
            snapshot.value.lifecycle,
            WorkflowOperationLifecycle::Proposed | WorkflowOperationLifecycle::Staged
        ) {
            continue;
        }
        let mut terminal = snapshot.value;
        terminal.lifecycle = lifecycle;
        terminal.reason_code = reason_code.to_string();
        terminal.terminal_at_unix = Some(now_unix);
        journal
            .compare_and_swap(&terminal, Some(&snapshot.revision), owner.clone())
            .map_err(|error| LeaseError::InvalidState(error.to_string()))?;
    }
    Ok(())
}

fn cleanup_claimed_resources(
    manager: &SessionManager,
    claimed: &ClaimedSession,
    session_id: &str,
    gateway_runtime: Option<GatewaySessionRuntime>,
    control_path: Option<&Path>,
    reason: &str,
) -> Vec<String> {
    let mut cleanup_failures = Vec::new();
    if let Some(runtime) = gateway_runtime
        && let Err(error) = runtime.shutdown()
    {
        cleanup_failures.push(format!("gateway: {error}"));
    }
    let session_closed = match cleanup_claimed_session(manager, claimed, reason) {
        Ok(()) => true,
        Err(error) => {
            cleanup_failures.push(format!("session: {error}"));
            false
        }
    };
    if session_closed {
        if let Err(error) = manager.cleanup_overlay(session_id) {
            cleanup_failures.push(format!("overlay: {error}"));
        }
        if let Some(control_path) = control_path
            && let Err(error) = remove_control_if_present(control_path)
        {
            cleanup_failures.push(format!("control: {error}"));
        }
    }
    cleanup_failures
}

fn startup_failure_after_claim(
    manager: &SessionManager,
    claimed: &ClaimedSession,
    session_id: &str,
    gateway_runtime: Option<GatewaySessionRuntime>,
    control_path: Option<&Path>,
    original: SessionProcessError,
) -> SessionProcessError {
    let cleanup_failures = cleanup_claimed_resources(
        manager,
        claimed,
        session_id,
        gateway_runtime,
        control_path,
        "launcher-error",
    );
    if cleanup_failures.is_empty() {
        original
    } else {
        SessionProcessError::CleanupRecoveryRequired {
            session_id: session_id.to_string(),
            original: original.to_string(),
            cleanup_failures,
        }
    }
}

fn spawn_wrapper(
    app_state_root: &Path,
    control_path: &Path,
    command: &[OsString],
    fixture_mode: bool,
) -> Result<Child, SessionProcessError> {
    let executable = std::env::current_exe()?;
    let mut wrapper = Command::new(executable);
    wrapper
        .arg("session-child-wrapper")
        .arg("--control-file")
        .arg(control_path)
        .arg("--app-state-root")
        .arg(app_state_root);
    if fixture_mode {
        wrapper.arg("--fixture-mode");
    }
    wrapper
        .arg("--")
        .args(command)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(SessionProcessError::Io)
}

pub fn run_child_wrapper(
    control_file: &Path,
    command: Vec<OsString>,
    authority_key: &SessionAuthorityKey,
) -> Result<(), SessionProcessError> {
    if command.is_empty() {
        return Err(SessionProcessError::MissingCommand);
    }
    let store = AtomicJsonStore::new(control_file, LAUNCH_CONTROL_SCHEMA_VERSION);
    let deadline = Instant::now() + WRAPPER_START_TIMEOUT;
    let control = loop {
        match store.load::<serde_json::Value>()? {
            Some(snapshot) => {
                let control = LaunchControl::from_value(&snapshot.value)?;
                control.verify(control_file, authority_key)?;
                store.remove_if_revision(&snapshot.revision)?;
                break control;
            }
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => return Err(SessionProcessError::ControlTimeout),
        }
    };
    let current_process = capture_process_evidence(std::process::id())?;
    if current_process != control.process {
        return Err(SessionProcessError::ControlAuthentication(
            "launch control process generation mismatch".to_string(),
        ));
    }
    let mut target = Command::new(&command[0]);
    target
        .args(&command[1..])
        .env("UNPIN_SESSION_ID", &control.session_id)
        .env("UNPIN_GATEWAY_MODE", "session")
        .env("UNPIN_CONFIG_OVERLAY", &control.overlay_root)
        .env("UNPIN_REPOSITORY_KEY", &control.repository_key)
        .env("UNPIN_WORKSPACE_KEY", &control.workspace_key)
        .env("UNPIN_PROVIDER", &control.provider);
    if let Some(bridge_socket) = &control.bridge_socket {
        target.env("UNPIN_BRIDGE_SOCKET", bridge_socket);
    }
    if let Some(gateway_socket) = &control.gateway_socket {
        let authentication_tag = crate::gateway_session::gateway_transport_authentication_tag(
            authority_key,
            &control.session_id,
            &control.process,
            gateway_socket,
        )
        .map_err(SessionProcessError::ControlAuthentication)?;
        target.env("UNPIN_GATEWAY_SOCKET", gateway_socket);
        target.env("UNPIN_GATEWAY_AUTHENTICATION_TAG", authentication_tag);
        target.env("UNPIN_GATEWAY_PROXY_EXECUTABLE", std::env::current_exe()?);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = target.exec();
        Err(SessionProcessError::Io(error))
    }
    #[cfg(not(unix))]
    {
        let status = target.status()?;
        if status.success() {
            Ok(())
        } else {
            Err(SessionProcessError::ChildFailed(status.code()))
        }
    }
}

fn write_control(
    path: &Path,
    session_id: &str,
    overlay_root: &Path,
    gateway_socket: Option<PathBuf>,
    process: ProcessEvidence,
    request: &SessionLaunchRequest,
    authority_key: &SessionAuthorityKey,
) -> Result<(), SessionProcessError> {
    let store = AtomicJsonStore::new(path, LAUNCH_CONTROL_SCHEMA_VERSION);
    let mut control = LaunchControl {
        version: LAUNCH_CONTROL_VERSION,
        control_path: path.to_path_buf(),
        session_id: session_id.to_string(),
        overlay_root: overlay_root.to_path_buf(),
        repository_key: request.repository_key.clone(),
        workspace_key: request.workspace_key.clone(),
        provider: request.provider.as_str().to_string(),
        bridge_socket: request.bridge_socket.clone(),
        gateway_socket,
        process,
        algorithm: String::new(),
        authority_key_id: String::new(),
        authentication_tag: String::new(),
    };
    control.seal(authority_key)?;
    store.compare_and_swap(
        None,
        OwnerGeneration::new(format!("launch-control-{session_id}"), 1)?,
        &control.to_value(),
    )?;
    Ok(())
}

fn validate_control_string(value: &str, field: &'static str) -> Result<(), SessionProcessError> {
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        Err(SessionProcessError::InvalidControl(field))
    } else {
        Ok(())
    }
}

fn validate_control_path(value: &Path, field: &'static str) -> Result<(), SessionProcessError> {
    value
        .to_str()
        .ok_or(SessionProcessError::InvalidControl(field))
        .and_then(|value| validate_control_string(value, field))
}

fn verified_bridge_socket(path: &Path) -> Result<PathBuf, SessionProcessError> {
    if !path.is_absolute() {
        return Err(SessionProcessError::BridgeControlUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        let metadata = fs::symlink_metadata(path)
            .map_err(|_| SessionProcessError::BridgeControlUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
            return Err(SessionProcessError::BridgeControlUnavailable);
        }
        fs::canonicalize(path).map_err(|_| SessionProcessError::BridgeControlUnavailable)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(SessionProcessError::BridgeControlUnavailable)
    }
}

fn launch_control_path(app_state_root: &Path) -> Result<PathBuf, SessionProcessError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionProcessError::Clock)?;
    Ok(app_state_root.join("runtime").join("launch").join(format!(
        "launch-{}-{}.json",
        std::process::id(),
        elapsed.as_nanos()
    )))
}

fn create_overlay(
    app_state_root: &Path,
    overlay_root: &Path,
    session_id: &str,
) -> Result<(), SessionProcessError> {
    ensure_private_directory(app_state_root)?;
    ensure_private_directory(&app_state_root.join("runtime"))?;
    ensure_private_directory(&app_state_root.join("runtime/overlays"))?;
    create_private_directory(overlay_root)?;
    let marker_path = overlay_root.join(SESSION_OVERLAY_MARKER);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut marker = options.open(&marker_path)?;
    marker.write_all(
        serde_json::json!({ "version": 1, "sessionId": session_id })
            .to_string()
            .as_bytes(),
    )?;
    marker.write_all(b"\n")?;
    marker.sync_all()?;
    File::open(overlay_root)?.sync_all()?;
    Ok(())
}

fn remove_control_if_present(path: &Path) -> Result<(), SessionProcessError> {
    let store = AtomicJsonStore::new(path, LAUNCH_CONTROL_SCHEMA_VERSION);
    if let Some(snapshot) = store.load::<serde_json::Value>()? {
        store.remove_if_revision(&snapshot.revision)?;
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), SessionProcessError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(SessionProcessError::UnsafeOverlay)
        }
        Ok(_) => verify_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_directory(path),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<(), SessionProcessError> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    verify_private_directory(path)
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> Result<(), SessionProcessError> {
    Err(SessionProcessError::PrivatePermissionsUnsupported)
}

#[cfg(unix)]
fn verify_private_directory(path: &Path) -> Result<(), SessionProcessError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::symlink_metadata(path)?.permissions().mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err(SessionProcessError::UnsafeOverlay)
    }
}

#[cfg(not(unix))]
fn verify_private_directory(_path: &Path) -> Result<(), SessionProcessError> {
    Err(SessionProcessError::PrivatePermissionsUnsupported)
}

fn unix_now() -> Result<i64, SessionProcessError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SessionProcessError::Clock)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| SessionProcessError::Clock)
}

#[derive(Debug)]
pub enum SessionProcessError {
    Io(io::Error),
    Json(serde_json::Error),
    Lease(LeaseError),
    MissingCommand,
    Clock,
    ControlTimeout,
    InvalidControl(&'static str),
    ControlAuthentication(String),
    BridgeControlUnavailable,
    GatewayControlUnavailable,
    #[cfg(unix)]
    GatewayControlRejected,
    WorkflowLaunch(String),
    ProviderOverlayUnavailable,
    GatewayPreparation(String),
    CleanupRecoveryRequired {
        session_id: String,
        original: String,
        cleanup_failures: Vec<String>,
    },
    UnsafeOverlay,
    #[cfg(not(unix))]
    PrivatePermissionsUnsupported,
    LeaseRevoked,
    #[cfg(not(unix))]
    ChildFailed(Option<i32>),
}

impl From<io::Error> for SessionProcessError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SessionProcessError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<LeaseError> for SessionProcessError {
    fn from(error: LeaseError) -> Self {
        Self::Lease(error)
    }
}

impl From<unpin_core::state::atomic_json::StateError> for SessionProcessError {
    fn from(error: unpin_core::state::atomic_json::StateError) -> Self {
        Self::Lease(LeaseError::State(error))
    }
}

impl std::fmt::Display for SessionProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session process I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "session process JSON failed: {error}"),
            Self::Lease(error) => write!(formatter, "session lease failed: {error}"),
            Self::MissingCommand => formatter.write_str("session launch command is required"),
            Self::Clock => formatter.write_str("system clock is unavailable"),
            Self::ControlTimeout => formatter.write_str("session child control timed out"),
            Self::InvalidControl(field) => {
                write!(formatter, "invalid session control field: {field}")
            }
            Self::ControlAuthentication(message) => {
                write!(
                    formatter,
                    "session launch control authentication failed: {message}"
                )
            }
            Self::BridgeControlUnavailable => {
                formatter.write_str("session bridge control socket is unavailable")
            }
            Self::GatewayControlUnavailable => {
                formatter.write_str("session gateway control socket is unavailable")
            }
            #[cfg(unix)]
            Self::GatewayControlRejected => {
                formatter.write_str("session gateway control request was rejected")
            }
            Self::WorkflowLaunch(reason) => {
                write!(formatter, "workflow launch blocked: {reason}")
            }
            Self::ProviderOverlayUnavailable => formatter.write_str(
                "verified provider overlay is unavailable; refusing profile-scoped launch that could expose native capabilities",
            ),
            Self::GatewayPreparation(message) => {
                write!(formatter, "session gateway preparation failed: {message}")
            }
            Self::CleanupRecoveryRequired {
                session_id,
                original,
                cleanup_failures,
            } => write!(
                formatter,
                "{original}; cleanup incomplete for session {session_id}: {}; recovery required",
                cleanup_failures.join(", ")
            ),
            Self::UnsafeOverlay => formatter.write_str("session overlay is unsafe or contested"),
            #[cfg(not(unix))]
            Self::PrivatePermissionsUnsupported => {
                formatter.write_str("private session overlay permissions are unsupported")
            }
            Self::LeaseRevoked => formatter.write_str("session lease was revoked while child ran"),
            #[cfg(not(unix))]
            Self::ChildFailed(code) => {
                write!(formatter, "session child failed with status {code:?}")
            }
        }
    }
}

impl std::error::Error for SessionProcessError {}

#[cfg(test)]
mod tests {
    use super::*;
    use unpin_core::sessions::{
        ConnectionClaim, ProcessEvidence, WORKFLOW_OPERATION_SCHEMA_VERSION, WorkflowOperationKind,
        WorkflowOperationRecord,
    };

    type LaunchControlMutation = (&'static str, fn(&mut LaunchControl));

    #[test]
    fn post_claim_startup_failure_reports_incomplete_cleanup() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SessionAuthorityKey::new([0x53; 32]);
        let manager = SessionManager::with_authority_key(&root, key);
        let now = unix_now().unwrap();
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "e".repeat(64),
                profile: PinnedProfile::Native,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "startup-cleanup-test".to_string(),
            },
            connection_scope_id: "startup-cleanup-connection".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: now + 600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "startup-cleanup-owner".to_string(),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let authority = manager.prepare_bootstrap(request, now).unwrap();
        let claimed = manager
            .claim_bootstrap(&authority, &claim, now + 1)
            .unwrap();
        let overlay_root = get_session_overlay_root(&root, authority.session_id());
        create_overlay(&root, &overlay_root, authority.session_id()).unwrap();
        manager
            .admit_call(&claimed.handle, &claimed.lease.revision, now + 2)
            .unwrap();

        let error = startup_failure_after_claim(
            &manager,
            &claimed,
            authority.session_id(),
            None,
            None,
            SessionProcessError::GatewayPreparation("injected".to_string()),
        );

        let SessionProcessError::CleanupRecoveryRequired {
            cleanup_failures, ..
        } = &error
        else {
            panic!("expected cleanup recovery error: {error}");
        };
        assert!(
            cleanup_failures
                .iter()
                .any(|failure| failure.starts_with("session:"))
        );
        let message = error.to_string();
        assert!(message.contains(authority.session_id()));
        assert!(message.contains("recovery required"));
        assert!(overlay_root.exists(), "recovery overlay must be retained");

        let normal_exit_failures = cleanup_claimed_resources(
            &manager,
            &claimed,
            authority.session_id(),
            None,
            Some(&root.join("missing-control.json")),
            "child-exit",
        );
        assert!(
            normal_exit_failures
                .iter()
                .any(|failure| failure.starts_with("session:"))
        );
        assert!(
            overlay_root.exists(),
            "normal-exit recovery overlay retained"
        );
        let result = SessionLaunchResult {
            session_id: authority.session_id().to_string(),
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            child_exit_code: Some(0),
            cleanup_failures: normal_exit_failures,
            isolation: IsolationLevel::ConnectionScoped,
            degradation: Vec::new(),
        };
        assert_eq!(result.to_json()["status"], "recovery-required");
    }

    #[test]
    fn child_exit_terminalizes_claimed_workflow_records_before_closing_session() {
        let temp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = SessionAuthorityKey::new([0x54; 32]);
        let manager = SessionManager::with_authority_key(&root, key);
        let now = unix_now().unwrap();
        let request = BootstrapRequest {
            provider: ProviderId::Codex,
            repository_key: "repo".to_string(),
            workspace_key: "worktree".to_string(),
            workspace_revision: None,
            exposure: PinnedExposure {
                revision: "e".repeat(64),
                profile: PinnedProfile::Native,
                capability_locks: None,
            },
            process: ProcessEvidence {
                pid: std::process::id(),
                start_marker: "workflow-cleanup-test".to_string(),
            },
            connection_scope_id: "workflow-cleanup-connection".to_string(),
            isolation: IsolationLevel::Strict,
            coverage: CoverageLevel::VerifiedMasked,
            protected_resources: BTreeSet::new(),
            lease_expires_at_unix: now + 600,
        };
        let claim = ConnectionClaim {
            connection_owner_id: "workflow-cleanup-owner".to_string(),
            provider: request.provider,
            repository_key: request.repository_key.clone(),
            workspace_key: request.workspace_key.clone(),
            process: request.process.clone(),
            connection_scope_id: request.connection_scope_id.clone(),
        };
        let authority = manager.prepare_bootstrap(request, now).unwrap();
        let claimed = manager
            .claim_bootstrap(&authority, &claim, now + 1)
            .unwrap();
        let overlay_root = get_session_overlay_root(&root, authority.session_id());
        create_overlay(&root, &overlay_root, authority.session_id()).unwrap();

        let journal = WorkflowJournal::new(&root);
        let operation_id = "transition-one";
        let record = WorkflowOperationRecord {
            schema_version: WORKFLOW_OPERATION_SCHEMA_VERSION,
            session_id: authority.session_id().to_string(),
            operation_id: operation_id.to_string(),
            kind: WorkflowOperationKind::Transition,
            lifecycle: WorkflowOperationLifecycle::Staged,
            reason_code: "workflow-transition-staged".to_string(),
            source_state_sequence: 1,
            target_state_sequence: 2,
            operation_fingerprint: "a".repeat(64),
            source_mode: Some("review".to_string()),
            target_mode: Some("implementation".to_string()),
            created_at_unix: now,
            terminal_at_unix: None,
        };
        journal
            .compare_and_swap(
                &record,
                None,
                OwnerGeneration::new(claimed.handle.owner_id(), claimed.lease.revision.sequence)
                    .unwrap(),
            )
            .unwrap();

        let failures = cleanup_claimed_resources(
            &manager,
            &claimed,
            authority.session_id(),
            None,
            None,
            "child-exit",
        );

        assert!(failures.is_empty(), "cleanup failures: {failures:?}");
        assert!(!overlay_root.exists());
        assert!(matches!(
            manager.load_for_handle(&claimed.handle),
            Err(LeaseError::SessionNotFound)
        ));
        assert!(
            journal
                .nonterminal_records(authority.session_id())
                .unwrap()
                .is_empty()
        );
        let terminal = journal
            .load(authority.session_id(), operation_id)
            .unwrap()
            .expect("terminal workflow audit record");
        assert_eq!(
            terminal.value.lifecycle,
            WorkflowOperationLifecycle::Cancelled
        );
        assert_eq!(
            terminal.value.reason_code,
            "session-ended-workflow-cancelled"
        );
        assert!(terminal.value.terminal_at_unix.is_some());
        assert!(terminal.value.terminal_at_unix.unwrap() >= now);
    }

    fn sealed_control() -> (LaunchControl, SessionAuthorityKey) {
        let key = SessionAuthorityKey::new([0x53; 32]);
        let mut control = LaunchControl {
            version: LAUNCH_CONTROL_VERSION,
            control_path: PathBuf::from("/tmp/unpin-control-a.json"),
            session_id: "session-a".to_string(),
            overlay_root: PathBuf::from("/tmp/unpin-overlay-a"),
            repository_key: "repository-a".to_string(),
            workspace_key: "workspace-a".to_string(),
            provider: "codex".to_string(),
            bridge_socket: Some(PathBuf::from("/tmp/unpin-bridge-a.sock")),
            gateway_socket: Some(PathBuf::from("/tmp/unpin-gateway-a.sock")),
            process: ProcessEvidence {
                pid: 42,
                start_marker: "process-a".to_string(),
            },
            algorithm: String::new(),
            authority_key_id: String::new(),
            authentication_tag: String::new(),
        };
        control.seal(&key).expect("seal launch control");
        (control, key)
    }

    #[test]
    fn profile_scoped_launch_requires_verified_provider_overlay() {
        assert!(!requires_verified_provider_overlay(&PinnedProfile::Native));
        assert!(requires_verified_provider_overlay(&PinnedProfile::None));
        assert!(requires_verified_provider_overlay(
            &PinnedProfile::Profile {
                profile_id: "review".to_string(),
                profile_digest: "a".repeat(64),
                origin_scope: unpin_core::profiles::ProfileSourceScope::Global,
                definition_digest: "b".repeat(64),
            }
        ));
    }

    #[test]
    fn protected_bindings_cover_all_session_applicable_scopes() {
        let resources =
            binding_protected_resources("repository-a", "workspace-a", ProviderId::Codex)
                .expect("protected binding resources");
        let mode_targets = [
            GatewayModeTarget::global(),
            GatewayModeTarget::global_provider(ProviderId::Codex),
            GatewayModeTarget::repository("repository-a").unwrap(),
            GatewayModeTarget::repository_provider("repository-a", ProviderId::Codex).unwrap(),
            GatewayModeTarget::workspace("repository-a", "workspace-a").unwrap(),
            GatewayModeTarget::workspace_provider("repository-a", "workspace-a", ProviderId::Codex)
                .unwrap(),
        ];
        let policy_targets = [
            PolicyTarget::Global,
            PolicyTarget::repository("repository-a").unwrap(),
            PolicyTarget::workspace("repository-a", "workspace-a").unwrap(),
        ];

        assert_eq!(resources.len(), mode_targets.len() + policy_targets.len());
        for target in mode_targets {
            assert!(resources.contains(&gateway_mode_resource_id(&target).unwrap()));
        }
        for target in policy_targets {
            assert!(resources.contains(&policy_resource_id(&target).unwrap()));
        }
    }

    #[test]
    fn launch_control_authentication_binds_every_field_and_expected_path() {
        let (control, key) = sealed_control();
        control
            .verify(&control.control_path, &key)
            .expect("valid launch control");
        let mutations: [LaunchControlMutation; 13] = [
            ("version", |value| value.version += 1),
            ("controlPath", |value| {
                value.control_path = PathBuf::from("/tmp/unpin-control-b.json");
            }),
            ("sessionId", |value| {
                value.session_id = "session-b".to_string()
            }),
            ("overlayRoot", |value| {
                value.overlay_root = PathBuf::from("/tmp/unpin-overlay-b");
            }),
            ("repositoryKey", |value| {
                value.repository_key = "repository-b".to_string();
            }),
            ("workspaceKey", |value| {
                value.workspace_key = "workspace-b".to_string();
            }),
            ("provider", |value| value.provider = "claude".to_string()),
            ("bridgeSocket", |value| {
                value.bridge_socket = Some(PathBuf::from("/tmp/unpin-bridge-b.sock"));
            }),
            ("gatewaySocket", |value| {
                value.gateway_socket = Some(PathBuf::from("/tmp/unpin-gateway-b.sock"));
            }),
            ("process", |value| {
                value.process.start_marker = "process-b".to_string();
            }),
            ("algorithm", |value| {
                value.algorithm = "hmac-sha512".to_string();
            }),
            ("authorityKeyId", |value| {
                value.authority_key_id = "sha256:0000000000000000".to_string();
            }),
            ("authenticationTag", |value| {
                value.authentication_tag = "00".repeat(32);
            }),
        ];
        for (field, mutate) in mutations {
            let mut forged = control.clone();
            mutate(&mut forged);
            assert!(
                forged.verify(&control.control_path, &key).is_err(),
                "field {field} must be authenticated"
            );
        }
        assert!(
            control
                .verify(Path::new("/tmp/unpin-control-b.json"), &key)
                .is_err()
        );
        assert!(
            control
                .verify(&control.control_path, &SessionAuthorityKey::new([0x54; 32]),)
                .is_err()
        );
    }

    #[test]
    fn launch_control_parser_rejects_unknown_fields_before_execution() {
        let (control, _) = sealed_control();
        let mut value = control.to_value();
        value["forgedField"] = serde_json::json!(true);
        assert!(LaunchControl::from_value(&value).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn accepted_silent_gateway_control_peer_is_bounded() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let temp = tempfile::TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let session_id = "silent-gateway";
        let overlay_root = get_session_overlay_root(&root, session_id);
        create_overlay(&root, &overlay_root, session_id).unwrap();
        let socket_path = root.join("silent-gateway.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let process = ProcessEvidence {
            pid: std::process::id(),
            start_marker: "silent-gateway-process".to_string(),
        };
        fs::write(
            overlay_root.join("gateway-session.json"),
            serde_json::json!({
                "version": 1,
                "sessionId": session_id,
                "process": process,
                "fixtureMode": true,
                "socket": socket_path,
            })
            .to_string(),
        )
        .unwrap();

        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let accept_thread = thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _stream = stream;
                        let _ = release_rx.recv_timeout(Duration::from_secs(1));
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if release_rx.try_recv().is_ok() || Instant::now() >= deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("silent gateway peer accept failed: {error}"),
                }
            }
        });

        let started = Instant::now();
        let error = call_gateway_control_with_timeouts(
            &root,
            session_id,
            "unpin_workflow_status",
            serde_json::json!({}),
            GatewayRuntimeTimeouts {
                connect: Duration::from_millis(250),
                call: Duration::from_millis(50),
            },
        )
        .expect_err("silent peer must not complete gateway control");
        release_tx.send(()).unwrap();
        accept_thread.join().unwrap();

        assert!(matches!(
            error,
            SessionProcessError::GatewayControlUnavailable
        ));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "silent gateway control exceeded its deadline: {:?}",
            started.elapsed()
        );
    }
}
