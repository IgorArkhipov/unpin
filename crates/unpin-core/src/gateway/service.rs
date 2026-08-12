use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    catalog::{CapabilityId, CapabilityKind, Catalog},
    hooks::{HookHandler, HookPolicy, HookPolicyLimits, HookRouteOwner},
    profiles::{COMPILED_PROFILE_SCHEMA_VERSION, CapabilityLockState, CompiledProfileRevision},
    providers::ProviderId,
    sessions::{LiveExposureStatus, PinnedExposure, PinnedProfile},
};

use super::{
    GatewayConnectionClaim, GatewayConnectionRegistry, GatewayConnectionRole,
    GatewayConnectionStatus, GatewayControlPlane, GatewayDataPlane, GatewayError, LoadedSkill,
    ProjectedTool, SkillMetadata, SkillRegistry, ToolRegistry, UpstreamToolRegistration,
};

const ABSOLUTE_MAX_TOOLS: usize = 2_048;
const ABSOLUTE_MAX_SKILLS: usize = 8_192;
const ABSOLUTE_MAX_SCHEMA_BYTES: usize = 1024 * 1024;
const ABSOLUTE_MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;
const ABSOLUTE_MAX_CONCURRENT_CALLS: u32 = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayLimits {
    pub maximum_tools: usize,
    pub maximum_skills: usize,
    pub maximum_schema_bytes: usize,
    pub maximum_schema_depth: usize,
    pub maximum_tool_list_bytes: usize,
    pub maximum_argument_bytes: usize,
    pub maximum_argument_depth: usize,
    pub maximum_response_bytes: usize,
    pub maximum_response_depth: usize,
    pub maximum_concurrent_calls: u32,
    pub maximum_skill_body_bytes: usize,
    pub maximum_skill_query_bytes: usize,
    pub maximum_skill_search_results: usize,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            maximum_tools: 256,
            maximum_skills: 1_024,
            maximum_schema_bytes: 64 * 1024,
            maximum_schema_depth: 32,
            maximum_tool_list_bytes: 8 * 1024 * 1024,
            maximum_argument_bytes: 1024 * 1024,
            maximum_argument_depth: 64,
            maximum_response_bytes: 8 * 1024 * 1024,
            maximum_response_depth: 128,
            maximum_concurrent_calls: 32,
            maximum_skill_body_bytes: 1024 * 1024,
            maximum_skill_query_bytes: 4 * 1024,
            maximum_skill_search_results: 32,
        }
    }
}

impl GatewayLimits {
    pub fn validate(&self) -> Result<(), GatewayError> {
        let positive = self.maximum_tools > 0
            && self.maximum_skills > 0
            && self.maximum_schema_bytes > 0
            && self.maximum_schema_depth > 0
            && self.maximum_tool_list_bytes > 0
            && self.maximum_argument_bytes > 0
            && self.maximum_argument_depth > 0
            && self.maximum_response_bytes > 0
            && self.maximum_response_depth > 0
            && self.maximum_concurrent_calls > 0
            && self.maximum_skill_body_bytes > 0
            && self.maximum_skill_query_bytes > 0
            && self.maximum_skill_search_results > 0;
        let bounded = self.maximum_tools <= ABSOLUTE_MAX_TOOLS
            && self.maximum_skills <= ABSOLUTE_MAX_SKILLS
            && self.maximum_schema_bytes <= ABSOLUTE_MAX_SCHEMA_BYTES
            && self.maximum_schema_depth <= 128
            && self.maximum_tool_list_bytes <= ABSOLUTE_MAX_MESSAGE_BYTES
            && self.maximum_argument_bytes <= ABSOLUTE_MAX_MESSAGE_BYTES
            && self.maximum_argument_depth <= 256
            && self.maximum_response_bytes <= ABSOLUTE_MAX_MESSAGE_BYTES
            && self.maximum_response_depth <= 256
            && self.maximum_concurrent_calls <= ABSOLUTE_MAX_CONCURRENT_CALLS
            && self.maximum_skill_body_bytes <= ABSOLUTE_MAX_MESSAGE_BYTES
            && self.maximum_skill_query_bytes <= 64 * 1024
            && self.maximum_skill_search_results <= self.maximum_skills;
        if positive && bounded {
            Ok(())
        } else {
            Err(GatewayError::InvalidExposure(
                "gateway limits are outside supported bounds",
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayExposure {
    pinned: PinnedExposure,
    provider: ProviderId,
    profile_digest: Option<String>,
    skills: SkillRegistry,
    tools: ToolRegistry,
    hooks: Arc<HookPolicy>,
}

#[derive(Debug, Clone)]
pub struct GatewayHookRegistration {
    pub capability_id: CapabilityId,
    pub capability_fingerprint: String,
    pub provider: ProviderId,
    pub handler: HookHandler,
}

impl GatewayExposure {
    pub fn compile(
        pinned: PinnedExposure,
        provider: ProviderId,
        catalog: &Catalog,
        profile: Option<&CompiledProfileRevision>,
        registrations: Vec<UpstreamToolRegistration>,
        limits: GatewayLimits,
    ) -> Result<Self, GatewayError> {
        Self::compile_with_hooks(
            pinned,
            provider,
            catalog,
            profile,
            registrations,
            Vec::new(),
            limits,
        )
    }

    pub fn compile_with_hooks(
        pinned: PinnedExposure,
        provider: ProviderId,
        catalog: &Catalog,
        profile: Option<&CompiledProfileRevision>,
        registrations: Vec<UpstreamToolRegistration>,
        hook_registrations: Vec<GatewayHookRegistration>,
        limits: GatewayLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        pinned
            .validate()
            .map_err(|_| GatewayError::InvalidExposure("pinned exposure is invalid"))?;

        let profile = profile_for_pin(&pinned.profile, profile)?;
        let mut member_ids = BTreeSet::new();
        let mut profile_members = BTreeMap::new();
        if let Some(profile) = profile {
            validate_profile_pin(&pinned.profile, profile)?;
            for member in profile.members_for_provider(provider) {
                if !member_ids.insert(member.capability_id.clone()) {
                    return Err(GatewayError::InvalidExposure(
                        "compiled profile contains duplicate members",
                    ));
                }
                profile_members.insert(member.capability_id.clone(), member);
            }
        }
        if let Some(locks) = &pinned.capability_locks {
            locks
                .verify()
                .map_err(|_| GatewayError::InvalidExposure("capability lock pin is invalid"))?;
            if locks.provider != provider {
                return Err(GatewayError::InvalidExposure(
                    "capability lock provider does not match session",
                ));
            }
            for (capability_id, state) in &locks.entries {
                let record = catalog
                    .get(capability_id)
                    .ok_or(GatewayError::InvalidExposure(
                        "locked capability is missing from catalog",
                    ))?;
                if !record.supports_provider(provider) {
                    return Err(GatewayError::InvalidExposure(
                        "locked capability does not support session provider",
                    ));
                }
                match state {
                    CapabilityLockState::HardEnabled => {
                        member_ids.insert(capability_id.clone());
                    }
                    CapabilityLockState::HardDisabled => {
                        member_ids.remove(capability_id);
                    }
                }
            }
        }

        if profile.is_none() && member_ids.is_empty() {
            if !registrations.is_empty() || !hook_registrations.is_empty() {
                return Err(GatewayError::InvalidExposure(
                    "native or empty exposure cannot project gateway capabilities",
                ));
            }
            return Ok(Self {
                pinned,
                provider,
                profile_digest: None,
                skills: SkillRegistry::compile(
                    Vec::new(),
                    "empty",
                    limits.maximum_skills,
                    limits.maximum_skill_body_bytes,
                    limits.maximum_skill_query_bytes,
                    limits.maximum_skill_search_results,
                )?,
                tools: ToolRegistry::default(),
                hooks: Arc::new(HookPolicy::empty(provider)),
            });
        }

        let mut selected_skills = Vec::new();
        let mut selected_tools = BTreeMap::<CapabilityId, String>::new();
        let mut selected_hooks = BTreeMap::<CapabilityId, String>::new();
        for capability_id in member_ids {
            let record = catalog
                .get(&capability_id)
                .ok_or(GatewayError::InvalidExposure(
                    "selected capability is missing from catalog",
                ))?;
            if let Some(member) = profile_members.get(&capability_id)
                && (record.fingerprint != member.capability_fingerprint
                    || record.origin.canonical_key != member.catalog_origin_key
                    || !record.supports_provider(provider))
            {
                return Err(GatewayError::InvalidExposure(
                    "compiled profile no longer matches catalog",
                ));
            }
            match record.kind {
                CapabilityKind::Skill => selected_skills.push(record),
                CapabilityKind::McpTool => {
                    selected_tools.insert(record.id.clone(), record.fingerprint.clone());
                }
                CapabilityKind::Hook => {
                    selected_hooks.insert(record.id.clone(), record.fingerprint.clone());
                }
                CapabilityKind::McpServer
                | CapabilityKind::Plugin
                | CapabilityKind::Agent
                | CapabilityKind::Setting => {}
            }
        }

        let mut selected_registrations = BTreeMap::new();
        for registration in registrations {
            registration.verify()?;
            if registration.provider != provider {
                return Err(GatewayError::InvalidExposure(
                    "upstream tool provider does not match session",
                ));
            }
            let expected_fingerprint = selected_tools.get(&registration.capability_id).ok_or(
                GatewayError::InvalidExposure("upstream tool is not selected by profile"),
            )?;
            if &registration.capability_fingerprint != expected_fingerprint {
                return Err(GatewayError::InvalidExposure(
                    "upstream tool fingerprint does not match catalog",
                ));
            }
            if selected_registrations
                .insert(registration.capability_id.clone(), registration)
                .is_some()
            {
                return Err(GatewayError::InvalidExposure(
                    "profile has multiple registrations for one tool",
                ));
            }
        }
        if selected_registrations.len() != selected_tools.len() {
            return Err(GatewayError::InvalidExposure(
                "selected upstream tool registration is unavailable",
            ));
        }

        let mut selected_hook_registrations = BTreeMap::new();
        for registration in hook_registrations {
            let expected_fingerprint = selected_hooks.get(&registration.capability_id).ok_or(
                GatewayError::InvalidExposure("gateway hook is not selected by profile"),
            )?;
            if registration.provider != provider
                || registration.handler.provider() != provider
                || registration.handler.route_owner() != HookRouteOwner::Gateway
                || &registration.capability_fingerprint != expected_fingerprint
            {
                return Err(GatewayError::InvalidExposure(
                    "gateway hook registration does not match profile",
                ));
            }
            if selected_hook_registrations
                .insert(registration.capability_id.clone(), registration)
                .is_some()
            {
                return Err(GatewayError::InvalidExposure(
                    "profile has multiple registrations for one hook",
                ));
            }
        }
        if selected_hook_registrations.len() != selected_hooks.len() {
            return Err(GatewayError::InvalidExposure(
                "selected gateway hook registration is unavailable",
            ));
        }

        let skills = SkillRegistry::compile(
            selected_skills,
            &pinned.revision,
            limits.maximum_skills,
            limits.maximum_skill_body_bytes,
            limits.maximum_skill_query_bytes,
            limits.maximum_skill_search_results,
        )?;
        let tools = ToolRegistry::compile(
            selected_registrations.into_values().collect(),
            limits.maximum_tools,
            limits.maximum_schema_bytes,
            limits.maximum_schema_depth,
            limits.maximum_tool_list_bytes,
        )?;
        let hooks = HookPolicy::compile(
            provider,
            profile
                .map(|profile| profile.digest.clone())
                .or_else(|| {
                    pinned
                        .capability_locks
                        .as_ref()
                        .map(|locks| locks.digest.clone())
                })
                .ok_or(GatewayError::InvalidExposure(
                    "gateway hook projection is missing a policy digest",
                ))?,
            selected_hook_registrations
                .into_values()
                .map(|registration| registration.handler)
                .collect(),
            HookPolicyLimits::default(),
        )
        .map_err(|_| GatewayError::InvalidExposure("gateway hook policy is invalid"))?;
        Ok(Self {
            pinned,
            provider,
            profile_digest: profile.map(|profile| profile.digest.clone()),
            skills,
            tools,
            hooks: Arc::new(hooks),
        })
    }

    #[must_use]
    pub fn pinned(&self) -> &PinnedExposure {
        &self.pinned
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn profile_digest(&self) -> Option<&str> {
        self.profile_digest.as_deref()
    }

    #[must_use]
    pub fn skills(&self) -> &SkillRegistry {
        &self.skills
    }

    #[must_use]
    pub fn tools(&self) -> &ToolRegistry {
        &self.tools
    }

    #[must_use]
    pub fn hook_policy(&self) -> &Arc<HookPolicy> {
        &self.hooks
    }
}

fn profile_for_pin<'a>(
    pin: &PinnedProfile,
    profile: Option<&'a CompiledProfileRevision>,
) -> Result<Option<&'a CompiledProfileRevision>, GatewayError> {
    match (pin, profile) {
        (PinnedProfile::Native | PinnedProfile::None, None) => Ok(None),
        (PinnedProfile::Profile { .. }, Some(profile)) => Ok(Some(profile)),
        (PinnedProfile::Native | PinnedProfile::None, Some(_)) => Err(
            GatewayError::InvalidExposure("unexpected compiled profile for native exposure"),
        ),
        (PinnedProfile::Profile { .. }, None) => Err(GatewayError::InvalidExposure(
            "compiled profile revision is unavailable",
        )),
    }
}

fn validate_profile_pin(
    pin: &PinnedProfile,
    profile: &CompiledProfileRevision,
) -> Result<(), GatewayError> {
    profile
        .verify_digest()
        .map_err(|_| GatewayError::InvalidExposure("compiled profile digest is invalid"))?;
    if profile.schema_version != COMPILED_PROFILE_SCHEMA_VERSION {
        return Err(GatewayError::InvalidExposure(
            "compiled profile schema is unsupported",
        ));
    }
    let PinnedProfile::Profile {
        profile_id,
        profile_digest,
        origin_scope,
        definition_digest,
    } = pin
    else {
        return Err(GatewayError::InvalidExposure("profile pin is missing"));
    };
    if profile.profile_id == *profile_id
        && profile.digest == *profile_digest
        && profile.origin.scope == *origin_scope
        && profile.origin.definition_digest == *definition_digest
    {
        Ok(())
    } else {
        Err(GatewayError::InvalidExposure(
            "compiled profile does not match pinned revision",
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListChangeSupport {
    Negotiated,
    /// The host can receive a notification but has no observed re-list yet.
    NotificationOnly,
    Unsupported,
    /// The host cannot refresh this session safely; expose the proposal for a
    /// new session and keep the currently observed set callable.
    NextSessionOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayRefreshOutcome {
    NotificationRequired,
    NotificationSent,
    RefreshUnconfirmed,
    ReloadRequired,
    NextSessionOnly,
}

#[derive(Debug)]
pub struct GatewayService {
    control: Arc<GatewayControlPlane>,
    data_plane: GatewayDataPlane,
    connections: GatewayConnectionRegistry,
    pending: Mutex<Option<Arc<GatewayExposure>>>,
    limits: GatewayLimits,
}

impl GatewayService {
    pub fn new(
        control: GatewayControlPlane,
        initial_exposure: GatewayExposure,
        limits: GatewayLimits,
    ) -> Result<Self, GatewayError> {
        limits.validate()?;
        let snapshot = control.snapshot()?;
        if snapshot.lease.provider != initial_exposure.provider
            || snapshot.lease.observed_exposure != initial_exposure.pinned
        {
            return Err(GatewayError::InvalidExposure(
                "initial exposure does not match observed lease state",
            ));
        }
        let control = Arc::new(control);
        let initial_exposure = Arc::new(initial_exposure);
        let connections =
            GatewayConnectionRegistry::new(Arc::clone(&control), Arc::clone(&initial_exposure));
        let data_plane = GatewayDataPlane::new(Arc::clone(&control), initial_exposure, limits);
        Ok(Self {
            control,
            data_plane,
            connections,
            pending: Mutex::new(None),
            limits,
        })
    }

    /// Stages a desired exposure for host observation.
    ///
    /// Once control plane requests a different exposure, new capability calls
    /// fail closed until host lists and observes this staged registry. Calls
    /// admitted under previous revision remain pinned and may finish.
    pub fn stage_refresh(
        &self,
        exposure: GatewayExposure,
        support: ListChangeSupport,
        now_unix: i64,
    ) -> Result<GatewayRefreshOutcome, GatewayError> {
        let snapshot = self.control.snapshot()?;
        if snapshot.lease.provider != exposure.provider
            || snapshot.lease.desired_exposure != exposure.pinned
        {
            return Err(GatewayError::InvalidExposure(
                "refresh exposure does not match desired lease state",
            ));
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| GatewayError::StatePoisoned)?;
        *pending = Some(Arc::new(exposure));
        if support == ListChangeSupport::Unsupported {
            if let Err(error) = self
                .control
                .observe_exposure(LiveExposureStatus::ReloadRequired, now_unix)
            {
                *pending = None;
                return Err(error);
            }
            Ok(GatewayRefreshOutcome::ReloadRequired)
        } else {
            Ok(GatewayRefreshOutcome::NotificationRequired)
        }
    }

    /// Issue the server-authenticated claim for an accepted gateway
    /// connection. Transport adapters must retain and pass this opaque value
    /// to every claim-aware gateway operation.
    pub fn issue_connection_claim(&self) -> Result<GatewayConnectionClaim, GatewayError> {
        self.connections.issue_claim()
    }

    /// Alias used by transport adapters at connection-accept time.
    pub fn accept_connection(&self) -> Result<GatewayConnectionClaim, GatewayError> {
        self.issue_connection_claim()
    }

    /// Return status for a claim without exposing authored capability names.
    pub fn connection_status(
        &self,
        claim: &GatewayConnectionClaim,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        self.connections.status(claim)
    }

    #[must_use]
    pub fn connection_registry(&self) -> &GatewayConnectionRegistry {
        &self.connections
    }

    /// Disconnect and permanently fence a connection epoch. A primary
    /// disconnect reconciles the durable gateway runtime; auxiliary
    /// connections are status-only and do not affect session admission.
    pub fn disconnect_connection(
        &self,
        claim: &GatewayConnectionClaim,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        let status = self.connections.status(claim)?;
        self.connections.disconnect(claim)?;
        if status.role == GatewayConnectionRole::Primary {
            self.control.reconcile_stopped_runtime(now_unix)?;
        }
        Ok(())
    }

    /// Stage a replacement exposure in the primary connection's private
    /// registry. Auxiliary claims are intentionally unable to stage or observe
    /// a replacement. The old observed exposure remains the only one usable
    /// for calls until this exact primary connection re-lists.
    pub fn stage_refresh_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        exposure: GatewayExposure,
        support: ListChangeSupport,
        now_unix: i64,
    ) -> Result<GatewayRefreshOutcome, GatewayError> {
        self.connections.require_primary(claim)?;
        let snapshot = self.control.snapshot()?;
        if snapshot.lease.provider != exposure.provider
            || snapshot.lease.desired_exposure != exposure.pinned
        {
            return Err(GatewayError::InvalidExposure(
                "refresh exposure does not match desired lease state",
            ));
        }
        let exposure = Arc::new(exposure);
        match support {
            ListChangeSupport::NextSessionOnly => {
                // Known next-session-only coverage does not stage a pending
                // set. Keep the old observed registry intact and surface the
                // limitation to the host. A workflow operation can later use
                // cancel_transition_for_connection to restore admission.
                self.connections.clear_pending(claim)?;
                self.control
                    .observe_exposure(LiveExposureStatus::NextSessionOnly, now_unix)?;
                Ok(GatewayRefreshOutcome::NextSessionOnly)
            }
            ListChangeSupport::Unsupported => {
                self.connections.stage_pending(claim, exposure)?;
                if let Err(error) = self
                    .control
                    .observe_exposure(LiveExposureStatus::ReloadRequired, now_unix)
                {
                    let _ = self.connections.clear_pending(claim);
                    return Err(error);
                }
                Ok(GatewayRefreshOutcome::ReloadRequired)
            }
            ListChangeSupport::NotificationOnly => {
                self.connections.stage_pending(claim, exposure)?;
                self.control
                    .observe_exposure(LiveExposureStatus::NotificationSent, now_unix)?;
                Ok(GatewayRefreshOutcome::RefreshUnconfirmed)
            }
            ListChangeSupport::Negotiated => {
                self.connections.stage_pending(claim, exposure)?;
                Ok(GatewayRefreshOutcome::NotificationRequired)
            }
        }
    }

    /// Record that the host received a list-change notification. Notification
    /// alone never promotes a pending exposure; a same-claim re-list is still
    /// required.
    pub fn notify_tools_changed_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        now_unix: i64,
    ) -> Result<GatewayRefreshOutcome, GatewayError> {
        self.connections.require_primary(claim)?;
        let pending = self
            .connections
            .pending(claim)?
            .ok_or(GatewayError::RefreshNotObserved)?;
        let snapshot = self.control.snapshot()?;
        if pending.pinned() != &snapshot.lease.desired_exposure {
            return Err(GatewayError::InvalidExposure(
                "pending exposure is no longer desired",
            ));
        }
        self.control
            .observe_exposure(LiveExposureStatus::NotificationSent, now_unix)?;
        Ok(GatewayRefreshOutcome::NotificationSent)
    }

    /// Re-list and observe a replacement on the exact primary connection.
    /// This is the only operation that promotes a pending connection-local
    /// exposure. It is idempotent once the desired revision is observed.
    pub fn list_tools_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        now_unix: i64,
    ) -> Result<Vec<ProjectedTool>, GatewayError> {
        self.connections.require_primary(claim)?;
        let snapshot = self.control.snapshot()?;
        let pending = self
            .connections
            .take_pending(claim, &snapshot.lease.desired_exposure.revision)?;
        if let Some(exposure) = pending {
            if snapshot.lease.live_status != LiveExposureStatus::NotificationSent {
                self.connections.restore_pending(claim, exposure)?;
            } else {
                if let Err(error) = self.control.observe_exposure_if_desired(
                    exposure.pinned(),
                    LiveExposureStatus::ObservedRefresh,
                    now_unix,
                ) {
                    self.connections.restore_pending(claim, exposure)?;
                    return Err(error);
                }
                self.connections.mark_observed(claim, exposure)?;
            }
        }
        let exposure = self.connections.observed(claim)?;
        self.data_plane.list_tools_for_exposure(&exposure)
    }

    pub fn search_skills_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        query: &str,
        limit: usize,
        now_unix: i64,
    ) -> Result<Vec<SkillMetadata>, GatewayError> {
        let exposure = self.connections.observed(claim)?;
        self.data_plane
            .search_skills_for_exposure(exposure, query, limit, now_unix)
    }

    pub fn load_skill_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        reference: &str,
        now_unix: i64,
    ) -> Result<LoadedSkill, GatewayError> {
        let exposure = self.connections.observed(claim)?;
        self.data_plane
            .load_skill_for_exposure(exposure, reference, now_unix)
    }

    pub fn admit_tool_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        public_name: &str,
        arguments: &serde_json::Value,
        now_unix: i64,
    ) -> Result<super::GatewayCallPermit, GatewayError> {
        let exposure = self.connections.observed(claim)?;
        self.data_plane.admit_tool_for_exposure(
            exposure,
            public_name,
            arguments,
            now_unix,
            crate::hooks::HookInvocationChain::default(),
            claim.connection_epoch(),
        )
    }

    pub fn admit_tool_for_connection_with_chain(
        &self,
        claim: &GatewayConnectionClaim,
        public_name: &str,
        arguments: &serde_json::Value,
        now_unix: i64,
        hook_chain: crate::hooks::HookInvocationChain,
    ) -> Result<super::GatewayCallPermit, GatewayError> {
        let exposure = self.connections.observed(claim)?;
        self.data_plane.admit_tool_for_exposure(
            exposure,
            public_name,
            arguments,
            now_unix,
            hook_chain,
            claim.connection_epoch(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn admit_hook_tool_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        context: &super::GatewayHookCallContext,
        server_id: &str,
        tool_name: &str,
        arguments: &serde_json::Value,
        now_unix: i64,
        hook_chain: crate::hooks::HookInvocationChain,
    ) -> Result<super::GatewayCallPermit, GatewayError> {
        let exposure = self.connections.observed(claim)?;
        self.data_plane.admit_hook_tool_for_exposure(
            exposure,
            context,
            server_id,
            tool_name,
            arguments,
            now_unix,
            hook_chain,
            claim.connection_epoch(),
        )
    }

    pub fn finish_tool_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        permit: &mut super::GatewayCallPermit,
        response: &serde_json::Value,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        self.connections.require_primary(claim)?;
        if GatewayDataPlane::permit_connection_epoch(permit) != claim.connection_epoch() {
            return Err(GatewayError::ConnectionEpochStale);
        }
        self.data_plane.finish_tool(permit, response, now_unix)
    }

    pub fn cancel_tool_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        permit: &mut super::GatewayCallPermit,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        self.connections.require_primary(claim)?;
        if GatewayDataPlane::permit_connection_epoch(permit) != claim.connection_epoch() {
            return Err(GatewayError::ConnectionEpochStale);
        }
        self.data_plane.cancel_tool(permit, now_unix)
    }

    pub fn observe_refresh_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        expected_revision: &str,
        now_unix: i64,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        let _ = now_unix;
        self.connections.require_primary(claim)?;
        let status = self.connections.status(claim)?;
        if status.observed_exposure_revision != expected_revision {
            return Err(GatewayError::RefreshNotObserved);
        }
        Ok(status)
    }

    pub fn cancel_transition_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        operation_id: &str,
        now_unix: i64,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        self.connections.require_primary(claim)?;
        self.control
            .cancel_workflow_transition(operation_id, now_unix)?;
        self.connections.clear_pending(claim)?;
        self.connections.status(claim)
    }

    /// Cancel a directly staged refresh when no U2 workflow operation exists.
    /// Workflow transitions should use `cancel_transition_for_connection` so
    /// the authenticated journal can restore the source mode as well.
    pub fn cancel_refresh_for_connection(
        &self,
        claim: &GatewayConnectionClaim,
        now_unix: i64,
    ) -> Result<GatewayConnectionStatus, GatewayError> {
        self.connections.require_primary(claim)?;
        self.control.restore_observed_exposure(now_unix)?;
        self.connections.clear_pending(claim)?;
        self.connections.status(claim)
    }

    pub fn validate_notified_exposure_is_current(&self) -> Result<(), GatewayError> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| GatewayError::StatePoisoned)?;
        let snapshot = self.control.snapshot()?;
        match pending.as_ref() {
            Some(exposure)
                if exposure.pinned == snapshot.lease.desired_exposure
                    && snapshot.lease.live_status != LiveExposureStatus::ReloadRequired =>
            {
                Ok(())
            }
            None if snapshot.lease.observed_exposure == snapshot.lease.desired_exposure => Ok(()),
            _ => Err(GatewayError::InvalidExposure(
                "pending exposure is no longer desired",
            )),
        }
    }

    pub fn list_tools(&self, now_unix: i64) -> Result<Vec<ProjectedTool>, GatewayError> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| GatewayError::StatePoisoned)?;
        let snapshot = self.control.snapshot()?;
        if matches!(
            snapshot.lease.live_status,
            LiveExposureStatus::Configured | LiveExposureStatus::NotificationSent
        ) && pending
            .as_ref()
            .is_some_and(|exposure| exposure.pinned == snapshot.lease.desired_exposure)
            && let Some(exposure) = pending.take()
        {
            let previous = self.data_plane.activate(Arc::clone(&exposure))?;
            if let Err(error) = self.control.observe_exposure_if_desired(
                exposure.pinned(),
                LiveExposureStatus::ObservedRefresh,
                now_unix,
            ) {
                self.data_plane.activate(previous)?;
                *pending = Some(exposure);
                return Err(error);
            }
        }
        self.data_plane.list_tools()
    }

    pub fn search_skills(
        &self,
        query: &str,
        limit: usize,
        now_unix: i64,
    ) -> Result<Vec<SkillMetadata>, GatewayError> {
        self.data_plane.search_skills(query, limit, now_unix)
    }

    pub fn load_skill(&self, reference: &str, now_unix: i64) -> Result<LoadedSkill, GatewayError> {
        self.data_plane.load_skill(reference, now_unix)
    }

    #[must_use]
    pub fn data_plane(&self) -> &GatewayDataPlane {
        &self.data_plane
    }

    #[must_use]
    pub fn control_plane(&self) -> &GatewayControlPlane {
        &self.control
    }

    #[must_use]
    pub const fn limits(&self) -> GatewayLimits {
        self.limits
    }
}
