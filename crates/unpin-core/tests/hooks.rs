use std::{collections::BTreeMap, fs, path::Path};

use serde_json::json;
use tempfile::TempDir;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        VerifiedApproval,
    },
    config::get_hook_trust_path,
    discovery::DiscoveryLayer,
    hooks::{
        HookAction, HookActionOutcome, HookBeforeDecision, HookDispatcher, HookEventFamily,
        HookFailurePolicy, HookFailureReason, HookHandler, HookHandlerSpec, HookInvocationChain,
        HookMatcher, HookModelError, HookOwnership, HookPolicy, HookPolicyLimits,
        HookRewriteAuthorization, HookRewriteRequest, HookRouteOwner, HookSourceLayer,
        HookTransformCapabilities, HookTrustStore, parse_hook_document,
    },
    providers::ProviderId,
    state::atomic_json::{AtomicJsonStore, OwnerGeneration},
};

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn verified(expectation: ApprovalExpectation) -> VerifiedApproval {
    let key = ApprovalKey::new([7; 32]);
    let issuer = ApprovalIssuer::new(
        ApprovalKey::new([7; 32]),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .expect("approval issuer");
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("receipt-{}", &expectation.operation_id[..16]),
            nonce: format!("nonce-{}", &expectation.operation_id[..16]),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: 1_000,
            expires_at_unix: 1_600,
        })
        .expect("approval receipt");
    ApprovalVerifier::new(key)
        .verify(&receipt, &expectation, 1_100)
        .expect("verified approval")
}

fn review(handler: HookHandler, profile_digest: &str) -> HookHandler {
    let operation_id = handler
        .trust_operation_id(profile_digest)
        .expect("trust operation id");
    let approval = verified(ApprovalExpectation {
        issuer: "unpin-ui".to_string(),
        audience: "unpin-core".to_string(),
        operation_id,
        operation_kind: "hook-trust".to_string(),
        effect_graph_digest: digest('e'),
        repository_key: "repository-a".to_string(),
        workspace_key: "workspace-a".to_string(),
        session_id: Some("session-a".to_string()),
        profile_digest: Some(profile_digest.to_string()),
        resources: vec![unpin_core::approval::ApprovalResourceBinding {
            resource_id: "hook-action".to_string(),
            pre_state_fingerprint: Some(digest('f')),
        }],
    });
    handler
        .review(&approval, profile_digest)
        .expect("review hook")
}

fn handler(
    id: &str,
    action: HookAction,
    order: i32,
    failure_policy: HookFailurePolicy,
    transformations: HookTransformCapabilities,
) -> HookHandler {
    HookHandler::new(HookHandlerSpec {
        id: id.to_string(),
        provider: ProviderId::Codex,
        native_event: "PreToolUse".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::any(),
        action,
        order,
        timeout_ms: 10_000,
        failure_policy,
        source_layer: HookSourceLayer::Project,
        ownership: HookOwnership::User,
        route_owner: HookRouteOwner::Gateway,
        enabled: true,
        transformations,
    })
    .expect("hook handler")
}

fn reviewed_handler(
    id: &str,
    action: HookAction,
    order: i32,
    failure_policy: HookFailurePolicy,
    transformations: HookTransformCapabilities,
    profile_digest: &str,
) -> HookHandler {
    review(
        handler(id, action, order, failure_policy, transformations),
        profile_digest,
    )
}

#[test]
fn identical_hook_actions_keep_handler_scoped_trust_identity() {
    let profile = digest('a');
    let left = handler(
        "handler-left",
        HookAction::http("https://hooks.example.test/review").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
    );
    let right = handler(
        "handler-right",
        HookAction::http("https://hooks.example.test/review").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
    );

    assert_ne!(
        left.trust_operation_id(&profile).unwrap(),
        right.trust_operation_id(&profile).unwrap()
    );
    let left_expectation = left
        .trust_approval_expectation(
            &profile,
            "issuer",
            "audience",
            "repository",
            "workspace",
            "session",
        )
        .unwrap();
    let right_expectation = right
        .trust_approval_expectation(
            &profile,
            "issuer",
            "audience",
            "repository",
            "workspace",
            "session",
        )
        .unwrap();
    assert_ne!(
        left_expectation.effect_graph_digest,
        right_expectation.effect_graph_digest
    );
}

#[test]
fn provider_document_returns_stable_individual_handlers_without_payloads() {
    let document = json!({
        "hooks": {
            "PreToolUse": [{
                "matcher": "shell",
                "hooks": [
                    {"type": "command", "command": "private first", "timeout": 10},
                    {"type": "http", "url": "https://secret.example.test", "timeout": 20}
                ]
            }]
        }
    });
    let first = parse_hook_document(
        ProviderId::Claude,
        DiscoveryLayer::Project,
        "claude:project:hook:",
        &document,
        false,
    );
    let second = parse_hook_document(
        ProviderId::Claude,
        DiscoveryLayer::Project,
        "claude:project:hook:",
        &document,
        false,
    );

    assert!(first.issues.is_empty());
    assert_eq!(first.handlers.len(), 2);
    assert_eq!(
        first
            .handlers
            .iter()
            .map(|entry| entry.handler.id())
            .collect::<Vec<_>>(),
        second
            .handlers
            .iter()
            .map(|entry| entry.handler.id())
            .collect::<Vec<_>>()
    );
    let inventory = serde_json::to_string(
        &first
            .handlers
            .iter()
            .map(|entry| entry.handler.inventory())
            .collect::<Vec<_>>(),
    )
    .expect("inventory JSON");
    assert!(!inventory.contains("private first"));
    assert!(!inventory.contains("secret.example.test"));
}

#[test]
fn hook_trust_decision_is_redacted_profile_bound_and_replay_safe() {
    let temp = TempDir::new().unwrap();
    let state = fs::canonicalize(temp.path()).unwrap();
    let handler = handler(
        "codex:project:hook:review",
        HookAction::mcp_tool("review-server", "review-tool").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
    );
    let metadata = handler.inventory();
    let profile_digest = digest('a');
    let expectation = metadata
        .trust_approval_expectation(
            ProviderId::Codex,
            handler.id(),
            &profile_digest,
            "unpin-cli-human",
            "unpin-core-hook-trust",
            "repository-a",
            "workspace-a",
            "profile-policy",
        )
        .unwrap();
    let issuer = ApprovalIssuer::new(
        ApprovalKey::new([9; 32]),
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .unwrap();
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: "hook-trust-receipt".to_string(),
            nonce: "hook-trust-nonce".to_string(),
            issuer: String::new(),
            audience: String::new(),
            operation_id: expectation.operation_id.clone(),
            operation_kind: expectation.operation_kind.clone(),
            effect_graph_digest: expectation.effect_graph_digest.clone(),
            repository_key: expectation.repository_key.clone(),
            workspace_key: expectation.workspace_key.clone(),
            session_id: expectation.session_id.clone(),
            profile_digest: expectation.profile_digest.clone(),
            resources: expectation.resources.clone(),
            issued_at_unix: 1_000,
            expires_at_unix: 1_600,
        })
        .unwrap();
    let store = HookTrustStore::new(&state);
    let verifier = ApprovalVerifier::new(ApprovalKey::new([9; 32]));
    let legacy_state =
        AtomicJsonStore::new(get_hook_trust_path(&state, &expectation.operation_id), 1);
    legacy_state
        .compare_and_swap(
            None,
            OwnerGeneration::new("hook-trust-test", 1).unwrap(),
            &json!({
                "version": 1,
                "provider": ProviderId::Codex,
                "handlerId": handler.id(),
                "handlerFingerprint": metadata.fingerprint,
                "invocationFingerprint": metadata.invocation_fingerprint,
                "profileDigest": profile_digest,
                "reviewedAtUnix": receipt.claims.issued_at_unix,
                "approval": receipt,
            }),
        )
        .unwrap();
    assert!(
        store.load(&expectation.operation_id).unwrap().is_none(),
        "legacy receipt-bearing records must remain untrusted"
    );

    let owner = OwnerGeneration::new("hook-trust-test", 2).unwrap();
    let first = store
        .record(
            ProviderId::Codex,
            handler.id(),
            &metadata,
            &profile_digest,
            &receipt,
            &verifier,
            1_100,
            owner.clone(),
            "unpin-cli-human",
            "unpin-core-hook-trust",
            "repository-a",
            "workspace-a",
            "profile-policy",
        )
        .unwrap();
    let replay = store
        .record(
            ProviderId::Codex,
            handler.id(),
            &metadata,
            &profile_digest,
            &receipt,
            &verifier,
            1_101,
            owner,
            "unpin-cli-human",
            "unpin-core-hook-trust",
            "repository-a",
            "workspace-a",
            "profile-policy",
        )
        .unwrap();
    assert_eq!(first.operation_id, replay.operation_id);
    assert_eq!(
        replay.nonce,
        unpin_core::approval::NonceConsumption::AttachedToSameOperation
    );
    let saved = store.load(&first.operation_id).unwrap().unwrap();
    assert_eq!(
        saved.invocation_fingerprint,
        metadata.invocation_fingerprint
    );
    assert_eq!(saved.decision_digest, first.decision_digest);
    let persisted = fs::read_to_string(get_hook_trust_path(&state, &first.operation_id)).unwrap();
    for forbidden in [
        "receiptId",
        "nonce",
        "algorithm",
        "keyId",
        "tag",
        "signature",
        "approval",
        "hook-trust-receipt",
        "hook-trust-nonce",
    ] {
        assert!(
            !persisted.contains(forbidden),
            "stored trust decision leaked receipt field or value: {forbidden}"
        );
    }

    assert!(
        store
            .record(
                ProviderId::Codex,
                handler.id(),
                &metadata,
                &digest('c'),
                &receipt,
                &verifier,
                1_102,
                OwnerGeneration::new("hook-trust-test", 3).unwrap(),
                "unpin-cli-human",
                "unpin-core-hook-trust",
                "repository-a",
                "workspace-a",
                "profile-policy",
            )
            .is_err(),
        "receipt must not authorize a different profile"
    );

    let mut changed = metadata;
    changed.invocation_fingerprint = digest('b');
    assert!(
        store
            .record(
                ProviderId::Codex,
                handler.id(),
                &changed,
                &profile_digest,
                &receipt,
                &verifier,
                1_103,
                OwnerGeneration::new("hook-trust-test", 3).unwrap(),
                "unpin-cli-human",
                "unpin-core-hook-trust",
                "repository-a",
                "workspace-a",
                "profile-policy",
            )
            .is_err()
    );
}

#[test]
fn invalid_provider_matcher_is_rejected_instead_of_broadening_to_any() {
    let document = json!({
        "hooks": {"PreToolUse": [{"matcher": "bad\u{0}matcher", "command": "private"}]}
    });
    let parsed = parse_hook_document(
        ProviderId::Cursor,
        DiscoveryLayer::Global,
        "cursor:global:hook:",
        &document,
        false,
    );

    assert!(parsed.handlers.is_empty());
    assert_eq!(parsed.issues.len(), 1);
    assert_eq!(parsed.issues[0].code, "invalid-hook-matcher");
}

#[test]
fn deterministic_policy_order_and_deny_precedence_are_stable() {
    let profile = digest('a');
    let late = reviewed_handler(
        "late",
        HookAction::http("https://late.example.test").unwrap(),
        20,
        HookFailurePolicy::ContinueDegraded,
        HookTransformCapabilities::none(),
        &profile,
    );
    let early = reviewed_handler(
        "early",
        HookAction::http("https://early.example.test").unwrap(),
        10,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &profile,
    );
    let policy = HookPolicy::compile(
        ProviderId::Codex,
        &profile,
        vec![late, early],
        HookPolicyLimits::default(),
    )
    .expect("hook policy");
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(policy));
    let plan = dispatcher
        .plan_before(
            "shell",
            &json!({"command": "true"}),
            HookRouteOwner::Gateway,
            &HookInvocationChain::default(),
        )
        .expect("dispatch plan");
    assert_eq!(
        plan.steps()
            .iter()
            .map(|step| step.handler().id())
            .collect::<Vec<_>>(),
        vec!["early", "late"]
    );
    let result = dispatcher
        .complete_before(
            plan,
            BTreeMap::from([
                ("early".to_string(), HookActionOutcome::Continue),
                ("late".to_string(), HookActionOutcome::Deny),
            ]),
            &[],
            |_| true,
        )
        .expect("complete hooks");
    assert_eq!(result.decision, HookBeforeDecision::Deny);
}

#[test]
fn security_relevant_rewrite_requires_profile_bound_verified_approval() {
    let profile = digest('b');
    let hook = reviewed_handler(
        "rewrite",
        HookAction::http("https://rewrite.example.test").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities {
            argument_rewrite: true,
            result_modification: false,
            context_injection: false,
        },
        &profile,
    );
    let policy = HookPolicy::compile(
        ProviderId::Codex,
        &profile,
        vec![hook],
        HookPolicyLimits::default(),
    )
    .unwrap();
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(policy));
    let original = json!({"path": "safe.txt"});
    let rewritten = json!({"path": "sensitive.txt"});

    let denied = dispatcher
        .complete_before(
            dispatcher
                .plan_before(
                    "read",
                    &original,
                    HookRouteOwner::Gateway,
                    &HookInvocationChain::default(),
                )
                .unwrap(),
            BTreeMap::from([(
                "rewrite".to_string(),
                HookActionOutcome::RewriteArguments(rewritten.clone()),
            )]),
            &[],
            |_| true,
        )
        .unwrap();
    assert_eq!(denied.decision, HookBeforeDecision::Deny);
    assert!(
        denied
            .failures
            .iter()
            .any(|failure| { failure.reason == HookFailureReason::RewriteApprovalRequired })
    );

    let request = HookRewriteRequest::new(
        ProviderId::Codex,
        &profile,
        "rewrite",
        &original,
        &rewritten,
    )
    .unwrap();
    let approval = verified(request.approval_expectation(
        "unpin-ui",
        "unpin-core",
        "repository-a",
        "workspace-a",
        "session-a",
    ));
    let authorization = HookRewriteAuthorization::from_verified(&request, &approval).unwrap();
    let allowed = dispatcher
        .complete_before(
            dispatcher
                .plan_before(
                    "read",
                    &original,
                    HookRouteOwner::Gateway,
                    &HookInvocationChain::default(),
                )
                .unwrap(),
            BTreeMap::from([(
                "rewrite".to_string(),
                HookActionOutcome::RewriteArguments(rewritten.clone()),
            )]),
            &[authorization],
            |value| value.get("path").is_some(),
        )
        .unwrap();
    assert_eq!(allowed.decision, HookBeforeDecision::Allow);
    assert_eq!(allowed.arguments, rewritten);

    let other_profile_request = HookRewriteRequest::new(
        ProviderId::Codex,
        &digest('c'),
        "rewrite",
        &original,
        &allowed.arguments,
    )
    .unwrap();
    assert_ne!(request.operation_id, other_profile_request.operation_id);
}

#[test]
fn result_replacement_requires_target_bound_verified_approval() {
    let profile = digest('c');
    let hook = review(
        HookHandler::new(HookHandlerSpec {
            id: "replace-result".to_string(),
            provider: ProviderId::Codex,
            native_event: "PostToolUse".to_string(),
            event_family: HookEventFamily::AfterToolSuccess,
            matcher: HookMatcher::any(),
            action: HookAction::http("https://result.example.test").unwrap(),
            order: 0,
            timeout_ms: 10_000,
            failure_policy: HookFailurePolicy::ContinueDegraded,
            source_layer: HookSourceLayer::Project,
            ownership: HookOwnership::User,
            route_owner: HookRouteOwner::Gateway,
            enabled: true,
            transformations: HookTransformCapabilities {
                argument_rewrite: false,
                result_modification: true,
                context_injection: false,
            },
        })
        .unwrap(),
        &profile,
    );
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(
        HookPolicy::compile(
            ProviderId::Codex,
            &profile,
            vec![hook],
            HookPolicyLimits::default(),
        )
        .unwrap(),
    ));
    let original = json!({"value": "original"});
    let replacement = json!({"value": "replacement"});
    let outcomes = BTreeMap::from([(
        "replace-result".to_string(),
        HookActionOutcome::ReplaceResult(replacement.clone()),
    )]);

    let denied = dispatcher
        .complete_after(
            dispatcher
                .plan_after(
                    true,
                    "read",
                    &json!({}),
                    &original,
                    HookRouteOwner::Gateway,
                    &HookInvocationChain::default(),
                )
                .unwrap(),
            outcomes.clone(),
            &[],
        )
        .unwrap();
    assert_eq!(denied.result, original);
    assert!(
        denied
            .failures
            .iter()
            .any(|failure| { failure.reason == HookFailureReason::RewriteApprovalRequired })
    );

    let request = HookRewriteRequest::new_result(
        ProviderId::Codex,
        &profile,
        "replace-result",
        &original,
        &replacement,
    )
    .unwrap();
    let approval = verified(request.approval_expectation(
        "unpin-ui",
        "unpin-core",
        "repository-a",
        "workspace-a",
        "session-a",
    ));
    let authorization = HookRewriteAuthorization::from_verified(&request, &approval).unwrap();
    let allowed = dispatcher
        .complete_after(
            dispatcher
                .plan_after(
                    true,
                    "read",
                    &json!({}),
                    &original,
                    HookRouteOwner::Gateway,
                    &HookInvocationChain::default(),
                )
                .unwrap(),
            outcomes,
            &[authorization],
        )
        .unwrap();
    assert_eq!(allowed.result, replacement);

    let argument_request = HookRewriteRequest::new(
        ProviderId::Codex,
        &profile,
        "replace-result",
        &original,
        &allowed.result,
    )
    .unwrap();
    assert_ne!(request.operation_id, argument_request.operation_id);
}

#[test]
fn invocation_drift_and_identity_changes_invalidate_trust() {
    let temp = TempDir::new().unwrap();
    let executable = temp.path().join("hook-command");
    fs::write(&executable, "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&executable);
    let script = temp.path().join("action.sh");
    fs::write(&script, "exit 0\n").unwrap();
    let profile = digest('d');
    let action = HookAction::structured_command(
        &executable,
        vec![script.to_string_lossy().into_owned()],
        temp.path(),
        BTreeMap::from([("HOOK_MODE".to_string(), "review".to_string())]),
        vec![script.clone()],
    )
    .unwrap();
    let trusted = reviewed_handler(
        "command",
        action,
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &profile,
    );
    trusted.verify_for_dispatch(&profile).unwrap();
    fs::write(&script, "exit 1\n").unwrap();
    assert!(matches!(
        trusted.verify_for_dispatch(&profile),
        Err(HookModelError::InvocationChanged)
    ));

    let working_directory = temp.path().join("working-directory");
    fs::create_dir(&working_directory).unwrap();
    let cwd_trusted = reviewed_handler(
        "cwd-command",
        HookAction::structured_command(
            &executable,
            Vec::new(),
            &working_directory,
            BTreeMap::new(),
            Vec::new(),
        )
        .unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &profile,
    );
    cwd_trusted.verify_for_dispatch(&profile).unwrap();
    fs::rename(
        &working_directory,
        temp.path().join("original-working-directory"),
    )
    .unwrap();
    fs::create_dir(&working_directory).unwrap();
    assert!(matches!(
        cwd_trusted.verify_for_dispatch(&profile),
        Err(HookModelError::InvocationChanged)
    ));

    let identities = [
        (
            HookAction::http("https://one.example.test").unwrap(),
            HookAction::http("https://two.example.test").unwrap(),
        ),
        (
            HookAction::mcp_tool("server", "tool-one").unwrap(),
            HookAction::mcp_tool("server", "tool-two").unwrap(),
        ),
        (
            HookAction::structured_command(
                &executable,
                vec!["one".to_string()],
                temp.path(),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap(),
            HookAction::structured_command(
                &executable,
                vec!["two".to_string()],
                temp.path(),
                BTreeMap::new(),
                Vec::new(),
            )
            .unwrap(),
        ),
        (
            HookAction::structured_command(
                &executable,
                Vec::new(),
                temp.path(),
                BTreeMap::from([("HOOK_MODE".to_string(), "one".to_string())]),
                Vec::new(),
            )
            .unwrap(),
            HookAction::structured_command(
                &executable,
                Vec::new(),
                temp.path(),
                BTreeMap::from([("HOOK_MODE".to_string(), "two".to_string())]),
                Vec::new(),
            )
            .unwrap(),
        ),
    ];
    for (left, right) in identities {
        let left = handler(
            "identity",
            left,
            0,
            HookFailurePolicy::FailClosed,
            HookTransformCapabilities::none(),
        );
        let right = handler(
            "identity",
            right,
            0,
            HookFailurePolicy::FailClosed,
            HookTransformCapabilities::none(),
        );
        assert_ne!(
            left.trust_operation_id(&profile).unwrap(),
            right.trust_operation_id(&profile).unwrap()
        );
    }
}

#[test]
fn recursion_and_missing_enforcing_outcomes_fail_closed() {
    let profile = digest('e');
    let hook = reviewed_handler(
        "recursive",
        HookAction::http("https://recursive.example.test").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &profile,
    );
    let policy = HookPolicy::compile(
        ProviderId::Codex,
        &profile,
        vec![hook],
        HookPolicyLimits::default(),
    )
    .unwrap();
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(policy));
    let missing = dispatcher
        .complete_before(
            dispatcher
                .plan_before(
                    "shell",
                    &json!({}),
                    HookRouteOwner::Gateway,
                    &HookInvocationChain::default(),
                )
                .unwrap(),
            BTreeMap::new(),
            &[],
            |_| true,
        )
        .unwrap();
    assert_eq!(missing.decision, HookBeforeDecision::Deny);
    assert_eq!(
        missing.failures[0].reason,
        HookFailureReason::MissingOutcome
    );

    let chain = HookInvocationChain::from_ancestry(vec!["recursive".to_string()]).unwrap();
    let recursive = dispatcher
        .complete_before(
            dispatcher
                .plan_before("shell", &json!({}), HookRouteOwner::Gateway, &chain)
                .unwrap(),
            BTreeMap::new(),
            &[],
            |_| true,
        )
        .unwrap();
    assert_eq!(recursive.decision, HookBeforeDecision::Deny);
    assert_eq!(
        recursive.failures[0].reason,
        HookFailureReason::RecursionBlocked
    );
}

#[test]
fn provider_patterns_are_preserved_for_inventory_but_fail_closed_for_dispatch() {
    let profile = digest('f');
    let hook = HookHandler::new(HookHandlerSpec {
        id: "provider-pattern".to_string(),
        provider: ProviderId::Codex,
        native_event: "PreToolUse".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::new("mcp__.*").unwrap(),
        action: HookAction::ProviderNative {
            action_type: unpin_core::hooks::HookActionType::Command,
            definition_fingerprint: digest('1'),
        },
        order: 0,
        timeout_ms: 10_000,
        failure_policy: HookFailurePolicy::FailClosed,
        source_layer: HookSourceLayer::Project,
        ownership: HookOwnership::User,
        route_owner: HookRouteOwner::NativeDispatcher,
        enabled: true,
        transformations: HookTransformCapabilities::none(),
    })
    .unwrap();
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(
        HookPolicy::compile(
            ProviderId::Codex,
            &profile,
            vec![hook],
            HookPolicyLimits::default(),
        )
        .unwrap(),
    ));
    let plan = dispatcher
        .plan_before(
            "mcp__server__tool",
            &json!({}),
            HookRouteOwner::NativeDispatcher,
            &HookInvocationChain::default(),
        )
        .unwrap();
    assert!(plan.steps().is_empty());
    assert_eq!(
        plan.preflight_failures()[0].reason,
        HookFailureReason::UnsupportedMatcher
    );
    let result = dispatcher
        .complete_before(plan, BTreeMap::new(), &[], |_| true)
        .unwrap();
    assert_eq!(result.decision, HookBeforeDecision::Deny);
}

#[test]
fn route_ownership_prevents_gateway_and_provider_bridge_double_dispatch() {
    let profile = digest('9');
    let gateway = reviewed_handler(
        "gateway-owner",
        HookAction::http("https://gateway.example.test").unwrap(),
        0,
        HookFailurePolicy::FailClosed,
        HookTransformCapabilities::none(),
        &profile,
    );
    let bridge = review(
        HookHandler::new(HookHandlerSpec {
            id: "bridge-owner".to_string(),
            provider: ProviderId::Codex,
            native_event: "PreToolUse".to_string(),
            event_family: HookEventFamily::BeforeTool,
            matcher: HookMatcher::any(),
            action: HookAction::provider_component("unpin-hook-bridge-v1").unwrap(),
            order: 0,
            timeout_ms: 10_000,
            failure_policy: HookFailurePolicy::FailClosed,
            source_layer: HookSourceLayer::Component,
            ownership: HookOwnership::User,
            route_owner: HookRouteOwner::ProviderBridge,
            enabled: true,
            transformations: HookTransformCapabilities::none(),
        })
        .unwrap(),
        &profile,
    );
    let dispatcher = HookDispatcher::new(std::sync::Arc::new(
        HookPolicy::compile(
            ProviderId::Codex,
            &profile,
            vec![gateway, bridge],
            HookPolicyLimits::default(),
        )
        .unwrap(),
    ));
    let gateway_plan = dispatcher
        .plan_before(
            "shell",
            &json!({}),
            HookRouteOwner::Gateway,
            &HookInvocationChain::default(),
        )
        .unwrap();
    let bridge_plan = dispatcher
        .plan_before(
            "shell",
            &json!({}),
            HookRouteOwner::ProviderBridge,
            &HookInvocationChain::default(),
        )
        .unwrap();

    assert_eq!(gateway_plan.steps()[0].handler().id(), "gateway-owner");
    assert_eq!(gateway_plan.steps().len(), 1);
    assert_eq!(bridge_plan.steps()[0].handler().id(), "bridge-owner");
    assert_eq!(bridge_plan.steps().len(), 1);
}

#[test]
fn untrusted_input_cannot_self_declare_managed_precedence() {
    let profile = digest('f');
    let spoofed = HookHandler::new(HookHandlerSpec {
        id: "spoofed-managed".to_string(),
        provider: ProviderId::Codex,
        native_event: "PreToolUse".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::any(),
        action: HookAction::http("https://managed.example.test").unwrap(),
        order: 0,
        timeout_ms: 10_000,
        failure_policy: HookFailurePolicy::FailClosed,
        source_layer: HookSourceLayer::Managed,
        ownership: HookOwnership::AdministratorManaged,
        route_owner: HookRouteOwner::Gateway,
        enabled: true,
        transformations: HookTransformCapabilities::none(),
    })
    .unwrap();
    let spoofed = review(spoofed, &profile);
    assert!(
        HookPolicy::compile(
            ProviderId::Codex,
            &profile,
            vec![spoofed],
            HookPolicyLimits::default(),
        )
        .is_err()
    );
}

fn make_executable(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(_path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(_path, permissions).unwrap();
    }
}
