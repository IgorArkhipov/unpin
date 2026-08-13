use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::json;
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceiptClaims, ApprovalVerifier,
        VerifiedApproval,
    },
    catalog::{
        CanonicalOrigin, CapabilityId, CapabilityKind, CapabilityLifecycle, CapabilityMutability,
        CapabilityOwnership, CapabilityScope, CapabilityStateEvidence, CapabilityTrustRequirements,
        Catalog, CatalogRecord, ProviderView,
    },
    discovery::DiscoveryLayer,
    gateway::{
        CredentialBinding, GatewayExposure, GatewayLimits, RuntimeHookRegistration,
        RuntimeRegistrationContext, RuntimeRegistrationError, RuntimeRegistrationStore,
        RuntimeRegistrationValue, UpstreamIdentity, UpstreamToolDescriptor,
        UpstreamToolRegistration,
    },
    hooks::{
        HookAction, HookEventFamily, HookFailurePolicy, HookHandler, HookHandlerSpec, HookMatcher,
        HookOwnership, HookRouteOwner, HookSourceLayer, HookTransformCapabilities,
    },
    profiles::{
        CapabilityLockSnapshot, PROFILE_DEFINITION_VERSION, ProfileDefinition, ProfileSourceScope,
        compile_profile,
    },
    providers::ProviderId,
    sessions::{PinnedExposure, PinnedProfile, SessionAuthorityKey},
    state::atomic_json::OwnerGeneration,
    workflows::{
        WORKFLOW_DEFINITION_VERSION, WorkflowDefinition, WorkflowModeDefinition, compile_workflow,
    },
};

struct PrivateTempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl PrivateTempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary root");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private temporary root");
        }
        Self {
            _inner: inner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn digest(character: char) -> String {
    std::iter::repeat_n(character, 64).collect()
}

fn id(value: &str) -> CapabilityId {
    CapabilityId::new(value).expect("valid capability id")
}

fn record(value: &str, kind: CapabilityKind, fingerprint: char) -> CatalogRecord {
    CatalogRecord {
        id: id(value),
        kind,
        display_name: value.to_string(),
        origin: CanonicalOrigin {
            canonical_key: format!("origin-{value}"),
            source_path: format!("catalog-only-{value}"),
            state_path: format!("catalog-only-{value}"),
            scope: CapabilityScope::Repository,
            source_fingerprint: None,
        },
        ownership: CapabilityOwnership::User,
        fingerprint: digest(fingerprint),
        lifecycle: CapabilityLifecycle::discovered(true),
        state_evidence: CapabilityStateEvidence {
            observation: "runtime-registration-fixture".to_string(),
            observed_enabled: true,
        },
        trust_requirements: CapabilityTrustRequirements::default(),
        provider_views: vec![ProviderView {
            provider: ProviderId::Codex,
            discovery_id: format!("codex:{value}"),
            layer: DiscoveryLayer::Project,
            enabled: true,
            mutability: CapabilityMutability::ReadWrite,
            source_path: format!("provider-catalog-only-{value}"),
            state_path: format!("provider-catalog-only-{value}"),
            source_fingerprint: None,
        }],
        dependencies: Vec::new(),
        contributions: Vec::new(),
        contributed_by: None,
        atomic_unknown_contributions: false,
        tool_namespace: None,
        hook_conflict_key: None,
    }
}

fn profile(
    profile_id: &str,
    members: &[&str],
    catalog: &Catalog,
) -> unpin_core::profiles::CompiledProfileRevision {
    compile_profile(
        &ProfileDefinition {
            version: PROFILE_DEFINITION_VERSION,
            id: profile_id.to_string(),
            display_name: profile_id.to_string(),
            description: None,
            members: members.iter().map(|value| id(value)).collect(),
            provider_members: BTreeMap::new(),
            supported_providers: BTreeSet::from([ProviderId::Codex]),
        },
        catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("compiled profile")
}

fn workflow(catalog: &Catalog) -> unpin_core::workflows::CompiledWorkflowRevision {
    let profiles = BTreeMap::from([
        (
            "baseline".to_string(),
            profile("baseline", &["tool.shared"], catalog),
        ),
        (
            "planning".to_string(),
            profile("planning", &["tool.plan"], catalog),
        ),
        (
            "implementation".to_string(),
            profile("implementation", &["hook.build"], catalog),
        ),
    ]);
    compile_workflow(
        &WorkflowDefinition {
            version: WORKFLOW_DEFINITION_VERSION,
            id: "delivery".to_string(),
            display_name: "Delivery".to_string(),
            description: None,
            baseline_profile_id: "baseline".to_string(),
            entry_mode: "planning".to_string(),
            modes: vec![
                WorkflowModeDefinition::new("planning", "planning"),
                WorkflowModeDefinition::new("implementation", "implementation"),
            ],
        },
        &profiles,
        catalog,
        &CapabilityLockSnapshot::empty(ProviderId::Codex),
        ProviderId::Codex,
        ProfileSourceScope::Workspace,
    )
    .expect("compiled workflow")
}

fn tool_registration(
    record: &CatalogRecord,
    registration_id: &str,
    credential_key_id: Option<&str>,
) -> UpstreamToolRegistration {
    let identity = UpstreamIdentity::streamable_http(
        format!("server-{registration_id}"),
        format!("https://{registration_id}.example.test/mcp"),
    )
    .expect("HTTP identity");
    UpstreamToolRegistration {
        registration_id: registration_id.to_string(),
        capability_id: record.id.clone(),
        capability_fingerprint: record.fingerprint.clone(),
        provider: ProviderId::Codex,
        credential: credential_key_id
            .map(|key_id| CredentialBinding::new(key_id, &identity).expect("credential binding")),
        identity,
        descriptor: UpstreamToolDescriptor {
            name: format!("tool_{registration_id}"),
            title: None,
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            annotations: None,
            execution: None,
        },
    }
}

fn verified(expectation: ApprovalExpectation) -> VerifiedApproval {
    let issuer = ApprovalIssuer::new(
        ApprovalKey::new([0x29; 32]),
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
    ApprovalVerifier::new(ApprovalKey::new([0x29; 32]))
        .verify(&receipt, &expectation, 1_100)
        .expect("verified approval")
}

fn reviewed_hook(profile_digest: &str) -> HookHandler {
    let handler = HookHandler::new(HookHandlerSpec {
        id: "build-guard".to_string(),
        provider: ProviderId::Codex,
        native_event: "PreToolUse".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::any(),
        action: HookAction::http("https://hooks.example.test/guard").expect("HTTP hook"),
        order: 0,
        timeout_ms: 10_000,
        failure_policy: HookFailurePolicy::FailClosed,
        source_layer: HookSourceLayer::Session,
        ownership: HookOwnership::User,
        route_owner: HookRouteOwner::Gateway,
        enabled: true,
        transformations: HookTransformCapabilities::none(),
    })
    .expect("hook handler");
    let expectation = handler
        .trust_approval_expectation(
            profile_digest,
            "unpin-ui",
            "unpin-core",
            "repository-a",
            "workspace-a",
            "session-a",
        )
        .expect("hook trust expectation");
    handler
        .review(&verified(expectation), profile_digest)
        .expect("reviewed hook")
}

fn runtime_catalog() -> Catalog {
    Catalog::from_records([
        record("tool.shared", CapabilityKind::McpTool, 'a'),
        record("tool.plan", CapabilityKind::McpTool, 'b'),
        record("hook.build", CapabilityKind::Hook, 'c'),
    ])
    .expect("runtime catalog")
}

fn context() -> RuntimeRegistrationContext {
    RuntimeRegistrationContext::new("repository-a", "workspace-a", ProviderId::Codex)
        .expect("registration context")
}

fn owner(generation: u64) -> OwnerGeneration {
    OwnerGeneration::new("runtime-registration-test", generation).expect("owner")
}

fn save_complete_envelope(
    store: &RuntimeRegistrationStore,
    catalog: &Catalog,
    workflow: &unpin_core::workflows::CompiledWorkflowRevision,
) {
    for (capability, registration_id, credential) in [
        ("tool.shared", "shared", Some("runtime-token-shared")),
        ("tool.plan", "planning", None),
    ] {
        let catalog_record = catalog
            .get(&id(capability))
            .expect("catalog record")
            .clone();
        store
            .compare_and_swap(
                &RuntimeRegistrationValue::mcp_tool(
                    context(),
                    catalog_record.clone(),
                    tool_registration(&catalog_record, registration_id, credential),
                )
                .expect("tool runtime registration"),
                None,
                owner(1),
            )
            .expect("save tool runtime registration");
    }
    let hook_record = catalog
        .get(&id("hook.build"))
        .expect("hook catalog record")
        .clone();
    let profile_digest = &workflow.effective_profiles["implementation"].digest;
    let hook = RuntimeHookRegistration::from_handler(reviewed_hook(profile_digest))
        .expect("serializable reviewed hook");
    store
        .compare_and_swap(
            &RuntimeRegistrationValue::hook(
                context(),
                hook_record,
                BTreeMap::from([(profile_digest.clone(), hook)]),
            )
            .expect("hook runtime registration"),
            None,
            owner(1),
        )
        .expect("save hook runtime registration");
}

#[test]
fn authenticated_envelope_compiles_exact_mixed_mode_subsets_without_secret_bytes() {
    let root = PrivateTempDir::new();
    let key = SessionAuthorityKey::new([0x53; 32]);
    let store = RuntimeRegistrationStore::new(root.path(), key);
    let catalog = runtime_catalog();
    let workflow = workflow(&catalog);
    save_complete_envelope(&store, &catalog, &workflow);

    let envelope = store
        .load_workflow_envelope(&context(), &workflow, &catalog)
        .expect("authenticated runtime envelope");
    let planning_profile = &workflow.effective_profiles["planning"];
    let planning = envelope
        .registrations_for(planning_profile)
        .expect("planning registrations");
    let implementation_profile = &workflow.effective_profiles["implementation"];
    let implementation = envelope
        .registrations_for(implementation_profile)
        .expect("implementation registrations");

    assert_eq!(
        planning
            .tools
            .iter()
            .map(|registration| registration.capability_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["tool.plan", "tool.shared"])
    );
    assert!(planning.hooks.is_empty());
    assert_eq!(
        implementation
            .tools
            .iter()
            .map(|registration| registration.capability_id.as_str())
            .collect::<Vec<_>>(),
        vec!["tool.shared"]
    );
    assert_eq!(implementation.hooks.len(), 1);
    assert_eq!(implementation.hooks[0].handler.id(), "build-guard");

    for (mode, registrations) in [("planning", planning), ("implementation", implementation)] {
        let profile = &workflow.effective_profiles[mode];
        let pinned = PinnedExposure {
            revision: profile.digest.clone(),
            profile: PinnedProfile::Profile {
                profile_id: profile.profile_id.clone(),
                profile_digest: profile.digest.clone(),
                origin_scope: ProfileSourceScope::Session,
                definition_digest: workflow.digest.clone(),
            },
            capability_locks: None,
        };
        GatewayExposure::compile_workflow_profile_with_hooks(
            pinned,
            ProviderId::Codex,
            envelope.catalog(),
            profile,
            registrations.tools,
            registrations.hooks,
            GatewayLimits::default(),
        )
        .expect("mode exposure");
    }

    let shared_path = store.registration_path(&context(), &id("tool.shared"));
    let serialized = fs::read_to_string(shared_path).expect("stored registration");
    assert!(serialized.contains("runtime-token-shared"));
    assert!(!serialized.contains("fixture-secret-token-bytes"));
}

#[test]
fn envelope_rejects_missing_duplicate_and_stale_registrations() {
    let catalog = runtime_catalog();
    let workflow = workflow(&catalog);

    let missing_root = PrivateTempDir::new();
    let missing_store =
        RuntimeRegistrationStore::new(missing_root.path(), SessionAuthorityKey::new([0x53; 32]));
    let shared_record = catalog.get(&id("tool.shared")).unwrap().clone();
    missing_store
        .compare_and_swap(
            &RuntimeRegistrationValue::mcp_tool(
                context(),
                shared_record.clone(),
                tool_registration(&shared_record, "shared", None),
            )
            .unwrap(),
            None,
            owner(1),
        )
        .unwrap();
    assert!(matches!(
        missing_store.load_workflow_envelope(&context(), &workflow, &catalog),
        Err(RuntimeRegistrationError::MissingRegistration(capability))
            if capability == id("tool.plan") || capability == id("hook.build")
    ));

    let duplicate_root = PrivateTempDir::new();
    let duplicate_store =
        RuntimeRegistrationStore::new(duplicate_root.path(), SessionAuthorityKey::new([0x53; 32]));
    save_complete_envelope(&duplicate_store, &catalog, &workflow);
    let plan_record = catalog.get(&id("tool.plan")).unwrap().clone();
    let plan_revision = duplicate_store
        .load(&context(), &id("tool.plan"))
        .unwrap()
        .unwrap()
        .revision;
    duplicate_store
        .compare_and_swap(
            &RuntimeRegistrationValue::mcp_tool(
                context(),
                plan_record.clone(),
                tool_registration(&plan_record, "shared", None),
            )
            .unwrap(),
            Some(&plan_revision),
            owner(2),
        )
        .unwrap();
    assert!(matches!(
        duplicate_store.load_workflow_envelope(&context(), &workflow, &catalog),
        Err(RuntimeRegistrationError::DuplicateExecutionRegistration(id)) if id == "shared"
    ));

    let stale_root = PrivateTempDir::new();
    let stale_store =
        RuntimeRegistrationStore::new(stale_root.path(), SessionAuthorityKey::new([0x53; 32]));
    save_complete_envelope(&stale_store, &catalog, &workflow);
    let mut stale_record = catalog.get(&id("tool.plan")).unwrap().clone();
    stale_record.fingerprint = digest('d');
    let stale_revision = stale_store
        .load(&context(), &id("tool.plan"))
        .unwrap()
        .unwrap()
        .revision;
    stale_store
        .compare_and_swap(
            &RuntimeRegistrationValue::mcp_tool(
                context(),
                stale_record.clone(),
                tool_registration(&stale_record, "planning", None),
            )
            .unwrap(),
            Some(&stale_revision),
            owner(2),
        )
        .unwrap();
    assert!(matches!(
        stale_store.load_workflow_envelope(&context(), &workflow, &catalog),
        Err(RuntimeRegistrationError::StaleRegistration(capability))
            if capability == id("tool.plan")
    ));
}

#[test]
fn authenticated_records_reject_wrong_authority_and_context_replay() {
    let root = PrivateTempDir::new();
    let catalog = runtime_catalog();
    let record = catalog.get(&id("tool.shared")).unwrap().clone();
    let source_store =
        RuntimeRegistrationStore::new(root.path(), SessionAuthorityKey::new([0x53; 32]));
    source_store
        .compare_and_swap(
            &RuntimeRegistrationValue::mcp_tool(
                context(),
                record.clone(),
                tool_registration(&record, "shared", None),
            )
            .unwrap(),
            None,
            owner(1),
        )
        .unwrap();

    let wrong_key_store =
        RuntimeRegistrationStore::new(root.path(), SessionAuthorityKey::new([0x54; 32]));
    assert!(matches!(
        wrong_key_store.load(&context(), &id("tool.shared")),
        Err(RuntimeRegistrationError::AuthenticationFailed)
    ));

    let replay_context =
        RuntimeRegistrationContext::new("repository-a", "workspace-b", ProviderId::Codex).unwrap();
    let source = source_store.registration_path(&context(), &id("tool.shared"));
    let replay = source_store.registration_path(&replay_context, &id("tool.shared"));
    fs::create_dir_all(replay.parent().unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(replay.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::copy(source, replay).unwrap();
    assert!(matches!(
        source_store.load(&replay_context, &id("tool.shared")),
        Err(RuntimeRegistrationError::ContextMismatch)
    ));
}

#[test]
fn store_is_cas_safe_and_rejects_symlinked_registration_paths() {
    let root = PrivateTempDir::new();
    let store = RuntimeRegistrationStore::new(root.path(), SessionAuthorityKey::new([0x53; 32]));
    let catalog = runtime_catalog();
    let record = catalog.get(&id("tool.shared")).unwrap().clone();
    let value = RuntimeRegistrationValue::mcp_tool(
        context(),
        record.clone(),
        tool_registration(&record, "shared", None),
    )
    .unwrap();
    let first = store
        .compare_and_swap(&value, None, owner(1))
        .expect("initial registration");
    assert!(store.compare_and_swap(&value, None, owner(2)).is_err());
    store
        .compare_and_swap(&value, Some(&first), owner(2))
        .expect("CAS update");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let other = root.path().join("other.json");
        fs::write(&other, b"{}\n").unwrap();
        let registration_path = store.registration_path(&context(), &id("tool.shared"));
        fs::remove_file(&registration_path).unwrap();
        symlink(other, registration_path).unwrap();
        assert!(matches!(
            store.load(&context(), &id("tool.shared")),
            Err(RuntimeRegistrationError::State(_))
                | Err(RuntimeRegistrationError::UnsafeRegistrationPath)
        ));
    }
}
