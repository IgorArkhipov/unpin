use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use serde_json::Value;

use crate::{
    hooks::{
        HookActionOutcome, HookAfterResult, HookBeforeDecision, HookBeforeResult, HookDispatchPlan,
        HookDispatcher, HookEventFamily, HookInvocationChain, HookPolicy, HookRewriteAuthorization,
        HookRouteOwner,
    },
    sessions::CallAdmission,
};

use super::{
    GatewayControlPlane, GatewayError, GatewayExposure, GatewayLimits, LoadedSkill, ProjectedTool,
    SkillMetadata, tools::json_shape_within,
};

pub struct GatewayCallPermit {
    tool: ProjectedTool,
    exposure: Arc<GatewayExposure>,
    admission: Option<CallAdmission>,
    hook_policy: Arc<HookPolicy>,
    hook_chain: HookInvocationChain,
    before_hook_plan: Option<HookDispatchPlan>,
    before_hook_result: Option<HookBeforeResult>,
    pending_after_plan: Option<HookDispatchPlan>,
}

impl std::fmt::Debug for GatewayCallPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayCallPermit")
            .field("tool_name", &self.tool.name)
            .field("exposure_revision", &self.exposure.pinned().revision)
            .field("admission", &self.admission.as_ref().map(|_| "[REDACTED]"))
            .field("before_hooks_pending", &self.before_hook_plan.is_some())
            .field("after_hooks_pending", &self.pending_after_plan.is_some())
            .finish()
    }
}

#[derive(Clone)]
pub struct GatewayHookCallContext {
    exposure: Arc<GatewayExposure>,
}

impl std::fmt::Debug for GatewayHookCallContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayHookCallContext")
            .field("exposure_revision", &self.exposure.pinned().revision)
            .finish_non_exhaustive()
    }
}

impl GatewayCallPermit {
    #[must_use]
    pub fn tool(&self) -> &ProjectedTool {
        &self.tool
    }

    #[must_use]
    pub fn exposure_revision(&self) -> &str {
        &self.exposure.pinned().revision
    }

    fn admission(&self) -> Result<CallAdmission, GatewayError> {
        self.admission
            .clone()
            .ok_or(GatewayError::CapabilityUnavailable)
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.admission.is_some()
    }

    #[must_use]
    pub fn before_hook_plan(&self) -> Option<&HookDispatchPlan> {
        self.before_hook_plan.as_ref()
    }

    #[must_use]
    pub fn hook_call_context(&self) -> GatewayHookCallContext {
        GatewayHookCallContext {
            exposure: Arc::clone(&self.exposure),
        }
    }

    pub fn upstream_arguments(&self) -> Result<&Value, GatewayError> {
        match self.before_hook_result.as_ref() {
            Some(result) if result.decision == HookBeforeDecision::Allow => Ok(&result.arguments),
            Some(_) => Err(GatewayError::HookPolicyDenied),
            None => Err(GatewayError::HookDispatchIncomplete),
        }
    }

    #[must_use]
    pub fn hook_context(&self) -> &[String] {
        self.before_hook_result
            .as_ref()
            .map_or(&[], |result| result.context.as_slice())
    }
}

#[derive(Debug)]
pub struct GatewayDataPlane {
    control: Arc<GatewayControlPlane>,
    active: RwLock<Arc<GatewayExposure>>,
    limits: GatewayLimits,
}

impl GatewayDataPlane {
    pub(crate) fn new(
        control: Arc<GatewayControlPlane>,
        initial_exposure: Arc<GatewayExposure>,
        limits: GatewayLimits,
    ) -> Self {
        Self {
            control,
            active: RwLock::new(initial_exposure),
            limits,
        }
    }

    pub(crate) fn activate(
        &self,
        exposure: Arc<GatewayExposure>,
    ) -> Result<Arc<GatewayExposure>, GatewayError> {
        let mut active = self
            .active
            .write()
            .map_err(|_| GatewayError::StatePoisoned)?;
        Ok(std::mem::replace(&mut *active, exposure))
    }

    pub fn list_tools(&self) -> Result<Vec<ProjectedTool>, GatewayError> {
        let active = self
            .active
            .read()
            .map_err(|_| GatewayError::StatePoisoned)?;
        Ok(active.tools().descriptors())
    }

    pub fn admit_hook_tool(
        &self,
        context: &GatewayHookCallContext,
        server_id: &str,
        tool_name: &str,
        arguments: &Value,
        now_unix: i64,
        hook_chain: HookInvocationChain,
    ) -> Result<GatewayCallPermit, GatewayError> {
        let active = self.active_exposure()?;
        if active.pinned().revision != context.exposure.pinned().revision {
            return Err(GatewayError::CapabilityUnavailable);
        }
        let projected = context
            .exposure
            .tools()
            .resolve_upstream(server_id, tool_name)
            .cloned()
            .ok_or(GatewayError::CapabilityUnavailable)?;
        self.admit_from_exposure(
            Arc::clone(&context.exposure),
            &projected.name,
            arguments,
            now_unix,
            hook_chain,
        )
    }

    pub fn search_skills(
        &self,
        query: &str,
        limit: usize,
        now_unix: i64,
    ) -> Result<Vec<SkillMetadata>, GatewayError> {
        let active = self.active_exposure()?;
        self.with_local_call(&active, now_unix, || active.skills().search(query, limit))
    }

    pub fn load_skill(&self, reference: &str, now_unix: i64) -> Result<LoadedSkill, GatewayError> {
        let active = self.active_exposure()?;
        self.with_local_call(&active, now_unix, || active.skills().load(reference))
    }

    pub fn admit_tool(
        &self,
        public_name: &str,
        arguments: &Value,
        now_unix: i64,
    ) -> Result<GatewayCallPermit, GatewayError> {
        self.admit_tool_with_chain(
            public_name,
            arguments,
            now_unix,
            HookInvocationChain::default(),
        )
    }

    pub fn admit_tool_with_chain(
        &self,
        public_name: &str,
        arguments: &Value,
        now_unix: i64,
        hook_chain: HookInvocationChain,
    ) -> Result<GatewayCallPermit, GatewayError> {
        let exposure = self.active_exposure()?;
        self.admit_from_exposure(exposure, public_name, arguments, now_unix, hook_chain)
    }

    fn admit_from_exposure(
        &self,
        exposure: Arc<GatewayExposure>,
        public_name: &str,
        arguments: &Value,
        now_unix: i64,
        hook_chain: HookInvocationChain,
    ) -> Result<GatewayCallPermit, GatewayError> {
        if !arguments.is_object()
            || !json_shape_within(
                arguments,
                self.limits.maximum_argument_depth,
                maximum_json_nodes(self.limits.maximum_argument_bytes),
            )
        {
            return Err(GatewayError::ArgumentsLimitExceeded);
        }
        let argument_bytes = serde_json::to_vec(arguments)
            .map_err(|error| GatewayError::Serialization(error.to_string()))?;
        if argument_bytes.len() > self.limits.maximum_argument_bytes {
            return Err(GatewayError::ArgumentsLimitExceeded);
        }
        let tool = exposure
            .tools()
            .get(public_name)
            .cloned()
            .ok_or(GatewayError::CapabilityUnavailable)?;
        let hook_policy = Arc::clone(exposure.hook_policy());
        let dispatcher = HookDispatcher::new(Arc::clone(&hook_policy));
        let before_hook_plan = dispatcher
            .plan_before(public_name, arguments, HookRouteOwner::Gateway, &hook_chain)
            .map_err(|_| GatewayError::HookDispatchIncomplete)?;
        let (before_hook_plan, before_hook_result) = if before_hook_plan.steps().is_empty() {
            let result = dispatcher
                .complete_before(before_hook_plan, BTreeMap::new(), &[], |_| true)
                .map_err(|_| GatewayError::HookDispatchIncomplete)?;
            (None, Some(result))
        } else {
            (Some(before_hook_plan), None)
        };
        if before_hook_result
            .as_ref()
            .is_some_and(|result| result.decision == HookBeforeDecision::Deny)
        {
            return Err(GatewayError::HookPolicyDenied);
        }
        let admission = self
            .control
            .admit_call(&exposure.pinned().revision, now_unix)?;
        Ok(GatewayCallPermit {
            tool,
            exposure,
            admission: Some(admission),
            hook_policy,
            hook_chain,
            before_hook_plan,
            before_hook_result,
            pending_after_plan: None,
        })
    }

    pub fn complete_before_hooks(
        &self,
        permit: &mut GatewayCallPermit,
        outcomes: BTreeMap<String, HookActionOutcome>,
        rewrite_authorizations: &[HookRewriteAuthorization],
        validate_arguments: impl Fn(&Value) -> bool,
    ) -> Result<HookBeforeResult, GatewayError> {
        if permit.admission.is_none() {
            return Err(GatewayError::CapabilityUnavailable);
        }
        if let Some(result) = &permit.before_hook_result {
            return Ok(result.clone());
        }
        let plan = permit
            .before_hook_plan
            .take()
            .ok_or(GatewayError::HookDispatchIncomplete)?;
        let dispatcher = HookDispatcher::new(Arc::clone(&permit.hook_policy));
        let result = dispatcher
            .complete_before(plan, outcomes, rewrite_authorizations, validate_arguments)
            .map_err(|_| GatewayError::HookDispatchIncomplete)?;
        permit.before_hook_result = Some(result.clone());
        Ok(result)
    }

    pub fn finish_tool(
        &self,
        permit: &mut GatewayCallPermit,
        response: &Value,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        let plan = match permit.pending_after_plan.as_ref() {
            Some(plan) => plan.clone(),
            None => self.plan_after_hooks(permit, true, response)?,
        };
        if !plan.steps().is_empty() {
            return Err(GatewayError::HookDispatchIncomplete);
        }
        self.finish_tool_with_hooks(permit, true, response, BTreeMap::new(), now_unix)
            .map(|_| ())
    }

    pub fn finish_tool_with_hooks(
        &self,
        permit: &mut GatewayCallPermit,
        succeeded: bool,
        response: &Value,
        outcomes: BTreeMap<String, HookActionOutcome>,
        now_unix: i64,
    ) -> Result<HookAfterResult, GatewayError> {
        self.finish_tool_with_authorized_hooks(permit, succeeded, response, outcomes, &[], now_unix)
    }

    pub fn finish_tool_with_authorized_hooks(
        &self,
        permit: &mut GatewayCallPermit,
        succeeded: bool,
        response: &Value,
        outcomes: BTreeMap<String, HookActionOutcome>,
        rewrite_authorizations: &[HookRewriteAuthorization],
        now_unix: i64,
    ) -> Result<HookAfterResult, GatewayError> {
        let dispatcher = HookDispatcher::new(Arc::clone(&permit.hook_policy));
        let expected_event = if succeeded {
            HookEventFamily::AfterToolSuccess
        } else {
            HookEventFamily::AfterToolFailure
        };
        let pending = permit
            .pending_after_plan
            .as_ref()
            .ok_or(GatewayError::HookDispatchIncomplete)?;
        if pending.event_family() != expected_event || pending.original_result() != Some(response) {
            return Err(GatewayError::HookDispatchIncomplete);
        }
        let plan = pending.clone();
        let hook_result = dispatcher
            .complete_after(plan, outcomes, rewrite_authorizations)
            .map_err(|_| GatewayError::HookDispatchIncomplete);
        let bounded = hook_result
            .as_ref()
            .map_or(response, |result| &result.result);
        let size_result = validate_response_size(bounded, self.limits);
        self.control.finish_call(permit.admission()?, now_unix)?;
        permit.pending_after_plan = None;
        permit.admission = None;
        let result = hook_result?;
        size_result?;
        if result.failures.iter().any(|failure| failure.fail_closed) {
            return Err(GatewayError::HookPolicyDenied);
        }
        Ok(result)
    }

    pub fn plan_after_hooks(
        &self,
        permit: &mut GatewayCallPermit,
        succeeded: bool,
        response: &Value,
    ) -> Result<HookDispatchPlan, GatewayError> {
        if permit.pending_after_plan.is_some() {
            return Err(GatewayError::HookDispatchIncomplete);
        }
        let arguments = permit.upstream_arguments()?.clone();
        let plan = HookDispatcher::new(Arc::clone(&permit.hook_policy))
            .plan_after(
                succeeded,
                &permit.tool.name,
                &arguments,
                response,
                HookRouteOwner::Gateway,
                &permit.hook_chain,
            )
            .map_err(|_| GatewayError::HookDispatchIncomplete)?;
        permit.pending_after_plan = Some(plan.clone());
        Ok(plan)
    }

    pub fn cancel_tool(
        &self,
        permit: &mut GatewayCallPermit,
        now_unix: i64,
    ) -> Result<(), GatewayError> {
        permit.pending_after_plan = None;
        self.control.finish_call(permit.admission()?, now_unix)?;
        permit.admission = None;
        Ok(())
    }

    fn active_exposure(&self) -> Result<Arc<GatewayExposure>, GatewayError> {
        self.active
            .read()
            .map(|active| Arc::clone(&active))
            .map_err(|_| GatewayError::StatePoisoned)
    }

    fn with_local_call<T>(
        &self,
        exposure: &GatewayExposure,
        now_unix: i64,
        operation: impl FnOnce() -> Result<T, GatewayError>,
    ) -> Result<T, GatewayError> {
        let admission = self
            .control
            .admit_call(&exposure.pinned().revision, now_unix)?;
        let result = operation();
        let finished = self.control.finish_call(admission, now_unix);
        match (result, finished) {
            (_, Err(error)) => Err(error),
            (result, Ok(_)) => result,
        }
    }
}

fn maximum_json_nodes(maximum_bytes: usize) -> usize {
    maximum_bytes.saturating_add(1)
}

fn validate_response_size(response: &Value, limits: GatewayLimits) -> Result<(), GatewayError> {
    if !json_shape_within(
        response,
        limits.maximum_response_depth,
        maximum_json_nodes(limits.maximum_response_bytes),
    ) {
        return Err(GatewayError::ResponseLimitExceeded);
    }
    let bytes = serde_json::to_vec(response)
        .map_err(|error| GatewayError::Serialization(error.to_string()))?;
    if bytes.len() > limits.maximum_response_bytes {
        Err(GatewayError::ResponseLimitExceeded)
    } else {
        Ok(())
    }
}
