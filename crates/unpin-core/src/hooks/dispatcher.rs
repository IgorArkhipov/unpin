use std::{collections::BTreeMap, fmt, sync::Arc};

use serde_json::{Value, json};

use crate::{
    approval::{ApprovalExpectation, ApprovalResourceBinding, VerifiedApproval},
    providers::ProviderId,
};

use super::{
    HookEventFamily, HookFailurePolicy, HookHandler, HookMatcherMode, HookModelError, HookPolicy,
    HookRouteOwner, stable_hash,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookInvocationChain {
    ancestry: Vec<String>,
}

impl HookInvocationChain {
    pub fn from_ancestry(ancestry: Vec<String>) -> Result<Self, HookDispatchError> {
        if ancestry.iter().any(|entry| {
            entry.trim().is_empty() || entry.len() > 512 || entry.chars().any(char::is_control)
        }) {
            return Err(HookDispatchError::InvalidInvocation);
        }
        Ok(Self { ancestry })
    }

    #[must_use]
    pub fn ancestry(&self) -> &[String] {
        &self.ancestry
    }

    fn enter(&self, handler_id: &str, maximum_depth: usize) -> Result<Self, HookDispatchError> {
        if self.ancestry.len() >= maximum_depth
            || self.ancestry.iter().any(|entry| entry == handler_id)
        {
            return Err(HookDispatchError::RecursionBlocked);
        }
        let mut ancestry = self.ancestry.clone();
        ancestry.push(handler_id.to_string());
        Ok(Self { ancestry })
    }
}

#[derive(Debug, Clone)]
pub struct HookDispatchStep {
    handler: HookHandler,
    chain: HookInvocationChain,
}

impl HookDispatchStep {
    #[must_use]
    pub fn handler(&self) -> &HookHandler {
        &self.handler
    }

    #[must_use]
    pub fn chain(&self) -> &HookInvocationChain {
        &self.chain
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookDispatchFailure {
    pub handler_id: String,
    pub fail_closed: bool,
    pub reason: HookFailureReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookFailureReason {
    TrustRequired,
    InvocationChanged,
    UnsupportedMatcher,
    RecursionBlocked,
    ActionFailed,
    MissingOutcome,
    UnsupportedTransformation,
    RewriteApprovalRequired,
    InvalidRewrite,
    OutputLimitExceeded,
    SkippedAfterTerminal,
}

#[derive(Debug, Clone)]
pub struct HookDispatchPlan {
    provider: ProviderId,
    profile_digest: String,
    maximum_payload_bytes: usize,
    maximum_context_bytes: usize,
    event_family: HookEventFamily,
    route_owner: HookRouteOwner,
    tool_name: String,
    original_arguments: Value,
    original_result: Option<Value>,
    steps: Vec<HookDispatchStep>,
    preflight_failures: Vec<HookDispatchFailure>,
}

impl HookDispatchPlan {
    #[must_use]
    pub const fn provider(&self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    #[must_use]
    pub const fn maximum_payload_bytes(&self) -> usize {
        self.maximum_payload_bytes
    }

    #[must_use]
    pub const fn maximum_context_bytes(&self) -> usize {
        self.maximum_context_bytes
    }

    #[must_use]
    pub const fn event_family(&self) -> HookEventFamily {
        self.event_family
    }

    #[must_use]
    pub const fn route_owner(&self) -> HookRouteOwner {
        self.route_owner
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn original_arguments(&self) -> &Value {
        &self.original_arguments
    }

    #[must_use]
    pub fn original_result(&self) -> Option<&Value> {
        self.original_result.as_ref()
    }

    #[must_use]
    pub fn steps(&self) -> &[HookDispatchStep] {
        &self.steps
    }

    #[must_use]
    pub fn preflight_failures(&self) -> &[HookDispatchFailure] {
        &self.preflight_failures
    }

    #[must_use]
    pub fn execution_binding(&self) -> String {
        stable_hash(
            &serde_json::to_vec(&json!({
                "provider": self.provider,
                "profileDigest": self.profile_digest,
                "eventFamily": self.event_family,
                "routeOwner": self.route_owner,
                "toolName": self.tool_name,
                "arguments": self.original_arguments,
                "result": self.original_result,
                "steps": self.steps.iter().map(|step| json!({
                    "handlerFingerprint": step.handler.fingerprint(),
                    "ancestry": step.chain.ancestry(),
                })).collect::<Vec<_>>(),
                "preflightFailures": self.preflight_failures.iter().map(|failure| json!({
                    "handlerId": failure.handler_id,
                    "failClosed": failure.fail_closed,
                    "reason": format!("{:?}", failure.reason),
                })).collect::<Vec<_>>(),
            }))
            .expect("hook execution binding serialization is infallible"),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HookActionOutcome {
    Continue,
    Deny,
    RewriteArguments(Value),
    ReplaceResult(Value),
    AddContext(String),
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookBeforeDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HookBeforeResult {
    pub decision: HookBeforeDecision,
    pub arguments: Value,
    pub context: Vec<String>,
    pub failures: Vec<HookDispatchFailure>,
    pub ancestry: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HookAfterResult {
    pub result: Value,
    pub context: Vec<String>,
    pub failures: Vec<HookDispatchFailure>,
    pub ancestry: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRewriteRequest {
    pub target: HookRewriteTarget,
    pub provider: ProviderId,
    pub profile_digest: String,
    pub handler_id: String,
    pub original_digest: String,
    pub rewritten_digest: String,
    pub operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookRewriteTarget {
    Arguments,
    Result,
}

impl HookRewriteTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Result => "result",
        }
    }
}

impl HookRewriteRequest {
    pub fn new(
        provider: ProviderId,
        profile_digest: &str,
        handler_id: &str,
        original: &Value,
        rewritten: &Value,
    ) -> Result<Self, HookDispatchError> {
        Self::new_for_target(
            HookRewriteTarget::Arguments,
            provider,
            profile_digest,
            handler_id,
            original,
            rewritten,
        )
    }

    pub fn new_result(
        provider: ProviderId,
        profile_digest: &str,
        handler_id: &str,
        original: &Value,
        rewritten: &Value,
    ) -> Result<Self, HookDispatchError> {
        Self::new_for_target(
            HookRewriteTarget::Result,
            provider,
            profile_digest,
            handler_id,
            original,
            rewritten,
        )
    }

    fn new_for_target(
        target: HookRewriteTarget,
        provider: ProviderId,
        profile_digest: &str,
        handler_id: &str,
        original: &Value,
        rewritten: &Value,
    ) -> Result<Self, HookDispatchError> {
        if !valid_digest(profile_digest)
            || handler_id.trim().is_empty()
            || handler_id.len() > 512
            || handler_id.chars().any(char::is_control)
        {
            return Err(HookDispatchError::InvalidInvocation);
        }
        let original_digest = value_digest(original)?;
        let rewritten_digest = value_digest(rewritten)?;
        let operation_id = format!(
            "hook-rewrite-{}-{}-{}-{}-{}-{}",
            provider.as_str(),
            target.as_str(),
            profile_digest,
            stable_hash(handler_id.as_bytes()),
            original_digest,
            rewritten_digest
        );
        Ok(Self {
            target,
            provider,
            profile_digest: profile_digest.to_string(),
            handler_id: handler_id.to_string(),
            original_digest,
            rewritten_digest,
            operation_id,
        })
    }

    #[must_use]
    pub fn approval_expectation(
        &self,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        repository_key: impl Into<String>,
        workspace_key: impl Into<String>,
        session_id: impl Into<String>,
    ) -> ApprovalExpectation {
        ApprovalExpectation {
            issuer: issuer.into(),
            audience: audience.into(),
            operation_id: self.operation_id.clone(),
            operation_kind: "hook-rewrite".to_string(),
            effect_graph_digest: stable_hash(
                format!(
                    "{}\n{}\n{}\n{}\n{}\n{}",
                    self.provider.as_str(),
                    self.target.as_str(),
                    self.profile_digest,
                    self.handler_id,
                    self.original_digest,
                    self.rewritten_digest
                )
                .as_bytes(),
            ),
            repository_key: repository_key.into(),
            workspace_key: workspace_key.into(),
            session_id: Some(session_id.into()),
            profile_digest: Some(self.profile_digest.clone()),
            resources: vec![ApprovalResourceBinding {
                resource_id: format!(
                    "hook-{}-rewrite-{}",
                    self.target.as_str(),
                    &stable_hash(self.handler_id.as_bytes())[..16],
                ),
                pre_state_fingerprint: Some(self.original_digest.clone()),
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRewriteAuthorization {
    operation_id: String,
}

impl HookRewriteAuthorization {
    pub fn from_verified(
        request: &HookRewriteRequest,
        approval: &VerifiedApproval,
    ) -> Result<Self, HookDispatchError> {
        if approval.operation_id() != request.operation_id {
            return Err(HookDispatchError::RewriteApprovalMismatch);
        }
        Ok(Self {
            operation_id: request.operation_id.clone(),
        })
    }

    #[must_use]
    pub fn authorizes(&self, request: &HookRewriteRequest) -> bool {
        self.operation_id == request.operation_id
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

#[derive(Debug, Clone)]
pub struct HookDispatcher {
    policy: Arc<HookPolicy>,
}

impl HookDispatcher {
    #[must_use]
    pub fn new(policy: Arc<HookPolicy>) -> Self {
        Self { policy }
    }

    #[must_use]
    pub fn policy(&self) -> &Arc<HookPolicy> {
        &self.policy
    }

    pub fn plan_before(
        &self,
        tool_name: &str,
        arguments: &Value,
        route_owner: HookRouteOwner,
        chain: &HookInvocationChain,
    ) -> Result<HookDispatchPlan, HookDispatchError> {
        self.plan(
            HookEventFamily::BeforeTool,
            tool_name,
            arguments,
            None,
            route_owner,
            chain,
        )
    }

    pub fn plan_after(
        &self,
        succeeded: bool,
        tool_name: &str,
        arguments: &Value,
        result: &Value,
        route_owner: HookRouteOwner,
        chain: &HookInvocationChain,
    ) -> Result<HookDispatchPlan, HookDispatchError> {
        self.plan(
            if succeeded {
                HookEventFamily::AfterToolSuccess
            } else {
                HookEventFamily::AfterToolFailure
            },
            tool_name,
            arguments,
            Some(result.clone()),
            route_owner,
            chain,
        )
    }

    fn plan(
        &self,
        event_family: HookEventFamily,
        tool_name: &str,
        arguments: &Value,
        original_result: Option<Value>,
        route_owner: HookRouteOwner,
        chain: &HookInvocationChain,
    ) -> Result<HookDispatchPlan, HookDispatchError> {
        if tool_name.trim().is_empty()
            || tool_name.len() > 512
            || tool_name.chars().any(char::is_control)
            || !within_payload_limit(arguments, self.policy.limits().maximum_payload_bytes)
            || original_result.as_ref().is_some_and(|result| {
                !within_payload_limit(result, self.policy.limits().maximum_payload_bytes)
            })
        {
            return Err(HookDispatchError::InvalidInvocation);
        }
        let mut steps = Vec::new();
        let mut preflight_failures = Vec::new();
        for handler in self.policy.candidates(event_family, route_owner) {
            if handler.matcher().mode() == HookMatcherMode::ProviderPattern {
                preflight_failures.push(failure(handler, HookFailureReason::UnsupportedMatcher));
                continue;
            }
            if !handler.matcher().matches(tool_name) {
                continue;
            }
            let entered = match chain
                .enter(handler.id(), self.policy.limits().maximum_recursion_depth)
            {
                Ok(entered) => entered,
                Err(_) => {
                    preflight_failures.push(failure(handler, HookFailureReason::RecursionBlocked));
                    continue;
                }
            };
            match handler.verify_for_dispatch(self.policy.profile_digest()) {
                Ok(()) => steps.push(HookDispatchStep {
                    handler: handler.clone(),
                    chain: entered,
                }),
                Err(HookModelError::InvocationChanged | HookModelError::ActionUnavailable) => {
                    preflight_failures.push(failure(handler, HookFailureReason::InvocationChanged));
                }
                Err(_) => {
                    preflight_failures.push(failure(handler, HookFailureReason::TrustRequired));
                }
            }
        }
        Ok(HookDispatchPlan {
            provider: self.policy.provider(),
            profile_digest: self.policy.profile_digest().to_string(),
            maximum_payload_bytes: self.policy.limits().maximum_payload_bytes,
            maximum_context_bytes: self.policy.limits().maximum_context_bytes,
            event_family,
            route_owner,
            tool_name: tool_name.to_string(),
            original_arguments: arguments.clone(),
            original_result,
            steps,
            preflight_failures,
        })
    }

    pub fn complete_before(
        &self,
        plan: HookDispatchPlan,
        outcomes: BTreeMap<String, HookActionOutcome>,
        rewrite_authorizations: &[HookRewriteAuthorization],
        validate_arguments: impl Fn(&Value) -> bool,
    ) -> Result<HookBeforeResult, HookDispatchError> {
        if plan.event_family != HookEventFamily::BeforeTool {
            return Err(HookDispatchError::PlanTypeMismatch);
        }
        let mut arguments = plan.original_arguments.clone();
        let mut failures = plan.preflight_failures;
        let mut context = Vec::new();
        let mut ancestry = Vec::new();
        let mut deny = failures.iter().any(|failure| failure.fail_closed);
        for step in plan.steps {
            ancestry.push(step.handler.id().to_string());
            let outcome = outcomes.get(step.handler.id()).cloned();
            let Some(outcome) = outcome else {
                let current = failure(&step.handler, HookFailureReason::MissingOutcome);
                deny |= current.fail_closed;
                failures.push(current);
                continue;
            };
            match outcome {
                HookActionOutcome::Continue => {}
                HookActionOutcome::Deny => deny = true,
                HookActionOutcome::RewriteArguments(rewritten) => {
                    if !step.handler.transformations().argument_rewrite {
                        let current =
                            failure(&step.handler, HookFailureReason::UnsupportedTransformation);
                        deny |= current.fail_closed;
                        failures.push(current);
                        continue;
                    }
                    let request = HookRewriteRequest::new(
                        self.policy.provider(),
                        self.policy.profile_digest(),
                        step.handler.id(),
                        &arguments,
                        &rewritten,
                    )?;
                    if !rewrite_authorizations
                        .iter()
                        .any(|authorization| authorization.authorizes(&request))
                    {
                        deny = true;
                        failures.push(failure(
                            &step.handler,
                            HookFailureReason::RewriteApprovalRequired,
                        ));
                    } else if !validate_arguments(&rewritten)
                        || !within_payload_limit(
                            &rewritten,
                            self.policy.limits().maximum_payload_bytes,
                        )
                    {
                        deny = true;
                        failures.push(failure(&step.handler, HookFailureReason::InvalidRewrite));
                    } else {
                        arguments = rewritten;
                    }
                }
                HookActionOutcome::AddContext(value) => {
                    let context_bytes = context
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_add(value.len());
                    if !step.handler.transformations().context_injection
                        || context_bytes > self.policy.limits().maximum_context_bytes
                        || invalid_context(&value)
                    {
                        let current =
                            failure(&step.handler, HookFailureReason::OutputLimitExceeded);
                        deny |= current.fail_closed;
                        failures.push(current);
                    } else {
                        context.push(value);
                    }
                }
                HookActionOutcome::ReplaceResult(_) => {
                    let current =
                        failure(&step.handler, HookFailureReason::UnsupportedTransformation);
                    deny |= current.fail_closed;
                    failures.push(current);
                }
                HookActionOutcome::Failed => {
                    let current = failure(&step.handler, HookFailureReason::ActionFailed);
                    deny |= current.fail_closed;
                    failures.push(current);
                }
                HookActionOutcome::Skipped => {
                    failures.push(skipped_failure(&step.handler));
                }
            }
        }
        Ok(HookBeforeResult {
            decision: if deny {
                HookBeforeDecision::Deny
            } else {
                HookBeforeDecision::Allow
            },
            arguments,
            context,
            failures,
            ancestry,
        })
    }

    pub fn complete_after(
        &self,
        plan: HookDispatchPlan,
        outcomes: BTreeMap<String, HookActionOutcome>,
        rewrite_authorizations: &[HookRewriteAuthorization],
    ) -> Result<HookAfterResult, HookDispatchError> {
        if !plan.event_family.is_after_tool() {
            return Err(HookDispatchError::PlanTypeMismatch);
        }
        let mut result = plan
            .original_result
            .ok_or(HookDispatchError::PlanTypeMismatch)?;
        let mut failures = plan.preflight_failures;
        let mut context = Vec::new();
        let mut ancestry = Vec::new();
        for step in plan.steps {
            ancestry.push(step.handler.id().to_string());
            let outcome = outcomes.get(step.handler.id()).cloned();
            let Some(outcome) = outcome else {
                failures.push(failure(&step.handler, HookFailureReason::MissingOutcome));
                continue;
            };
            match outcome {
                HookActionOutcome::Continue | HookActionOutcome::Deny => {}
                HookActionOutcome::ReplaceResult(replacement) => {
                    let request = HookRewriteRequest::new_result(
                        self.policy.provider(),
                        self.policy.profile_digest(),
                        step.handler.id(),
                        &result,
                        &replacement,
                    )?;
                    if !step.handler.transformations().result_modification {
                        failures.push(failure(
                            &step.handler,
                            HookFailureReason::UnsupportedTransformation,
                        ));
                    } else if !rewrite_authorizations
                        .iter()
                        .any(|authorization| authorization.authorizes(&request))
                    {
                        failures.push(failure(
                            &step.handler,
                            HookFailureReason::RewriteApprovalRequired,
                        ));
                    } else if within_payload_limit(
                        &replacement,
                        self.policy.limits().maximum_payload_bytes,
                    ) {
                        result = replacement;
                    } else {
                        failures.push(failure(&step.handler, HookFailureReason::InvalidRewrite));
                    }
                }
                HookActionOutcome::AddContext(value) => {
                    let context_bytes = context
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_add(value.len());
                    if step.handler.transformations().context_injection
                        && context_bytes <= self.policy.limits().maximum_context_bytes
                        && !invalid_context(&value)
                    {
                        context.push(value);
                    } else {
                        failures.push(failure(
                            &step.handler,
                            HookFailureReason::OutputLimitExceeded,
                        ));
                    }
                }
                HookActionOutcome::RewriteArguments(_) => failures.push(failure(
                    &step.handler,
                    HookFailureReason::UnsupportedTransformation,
                )),
                HookActionOutcome::Failed => {
                    failures.push(failure(&step.handler, HookFailureReason::ActionFailed));
                }
                HookActionOutcome::Skipped => {
                    failures.push(skipped_failure(&step.handler));
                }
            }
        }
        Ok(HookAfterResult {
            result,
            context,
            failures,
            ancestry,
        })
    }
}

fn failure(handler: &HookHandler, reason: HookFailureReason) -> HookDispatchFailure {
    HookDispatchFailure {
        handler_id: handler.id().to_string(),
        fail_closed: handler.failure_policy() == HookFailurePolicy::FailClosed,
        reason,
    }
}

fn skipped_failure(handler: &HookHandler) -> HookDispatchFailure {
    HookDispatchFailure {
        handler_id: handler.id().to_string(),
        fail_closed: false,
        reason: HookFailureReason::SkippedAfterTerminal,
    }
}

fn within_payload_limit(value: &Value, maximum_bytes: usize) -> bool {
    serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= maximum_bytes)
}

fn value_digest(value: &Value) -> Result<String, HookDispatchError> {
    serde_json::to_vec(value)
        .map(|bytes| stable_hash(&bytes))
        .map_err(|_| HookDispatchError::InvalidInvocation)
}

fn invalid_context(value: &str) -> bool {
    value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookDispatchError {
    InvalidInvocation,
    RecursionBlocked,
    RewriteApprovalMismatch,
    PlanTypeMismatch,
}

impl fmt::Display for HookDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInvocation => formatter.write_str("hook invocation is invalid"),
            Self::RecursionBlocked => formatter.write_str("hook recursion is blocked"),
            Self::RewriteApprovalMismatch => {
                formatter.write_str("hook rewrite approval does not match")
            }
            Self::PlanTypeMismatch => formatter.write_str("hook dispatch plan type mismatch"),
        }
    }
}

impl std::error::Error for HookDispatchError {}
