use std::{collections::BTreeSet, fs};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
#[cfg(unix)]
use unpin_core::{
    bridges::MANAGED_COMPONENT_REFERENCE,
    hooks::{
        HookAction, HookEventFamily, HookFailurePolicy, HookHandlerSpec, HookMatcher,
        HookOwnership, HookPolicy, HookPolicyLimits, HookRouteOwner, HookSourceLayer,
        HookTransformCapabilities,
    },
};
use unpin_core::{
    bridges::{
        BridgeError, BridgeInstaller, BridgeIntegrity, BridgeLifecycle, HookBridgeAdapter,
        HookCoverageStatus,
    },
    providers::{ProviderId, registry::provider_registry},
    state::atomic_json::OwnerGeneration,
};

fn owner(generation: u64) -> OwnerGeneration {
    OwnerGeneration::new("bridge-test", generation).unwrap()
}

fn stable_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn provider_registry_declares_honest_hook_bridge_coverage() {
    let registry = provider_registry();
    assert_eq!(registry.len(), 6);
    assert_eq!(
        registry
            .iter()
            .map(|provider| provider.hook_bridge.provider)
            .collect::<BTreeSet<_>>(),
        ProviderId::ALL.into_iter().collect()
    );

    for provider in registry {
        assert_eq!(provider.hook_bridge.provider, provider.id);
        assert_eq!(
            provider.hook_bridge.gateway_mcp_tools,
            if provider.id == ProviderId::Zed {
                HookCoverageStatus::GatewayOnly
            } else {
                HookCoverageStatus::Verified
            }
        );
    }
    let zed = registry
        .iter()
        .find(|provider| provider.id == ProviderId::Zed)
        .unwrap()
        .hook_bridge;
    assert_eq!(zed.adapter, HookBridgeAdapter::GatewayOnly);
    assert_eq!(zed.built_in_tools, HookCoverageStatus::Unsupported);
    assert!(zed.native_events.is_empty());
    assert!(zed.managed_asset_file.is_none());

    let pi = registry
        .iter()
        .find(|provider| provider.id == ProviderId::Pi)
        .unwrap()
        .hook_bridge;
    assert_eq!(pi.adapter, HookBridgeAdapter::ManagedExtension);
    assert_eq!(pi.native_events, ["tool_call", "tool_result"]);
    let opencode = registry
        .iter()
        .find(|provider| provider.id == ProviderId::OpenCode)
        .unwrap()
        .hook_bridge;
    assert_eq!(opencode.adapter, HookBridgeAdapter::ManagedPlugin);
    assert_eq!(
        opencode.native_events,
        ["tool.execute.before", "tool.execute.after"]
    );
}

#[cfg(unix)]
#[test]
fn managed_assets_are_inert_until_session_binding_and_detach_exactly() {
    use std::os::unix::net::UnixListener;

    for provider in [ProviderId::Pi, ProviderId::OpenCode] {
        let temp = TempDir::new().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let state = root.join("state");
        let target = root.join("provider");
        fs::create_dir(&target).unwrap();
        let installer = BridgeInstaller::new(&state);
        let plan = installer.plan_install(provider, &target).unwrap();
        let status = installer.install(&plan, owner(1)).unwrap();
        assert_eq!(status.lifecycle, BridgeLifecycle::InstalledInactive);
        assert_eq!(status.integrity, BridgeIntegrity::Exact);
        assert!(!status.is_active());
        let inventory = installer.list_statuses(provider).unwrap();
        assert_eq!(inventory, vec![status.clone()]);
        assert_eq!(inventory[0].installation_id.len(), 64);

        let asset_path = target.join("unpin-hook-bridge.ts");
        let asset = fs::read_to_string(&asset_path).unwrap();
        assert!(asset.contains("UNPIN_BRIDGE_SOCKET"));
        assert!(asset.contains("UNPIN_SESSION_ID"));
        assert!(asset.contains("if (enforcing) throw new Error"));

        let socket_path = root.join("bridge.sock");
        let socket = UnixListener::bind(&socket_path).unwrap();
        let active = installer
            .activate(provider, &target, &socket_path, owner(1))
            .unwrap();
        assert!(active.is_active());
        assert!(active.control_plane_available);
        assert!(matches!(
            installer.detach(provider, &target, owner(1)),
            Err(BridgeError::BridgeActive)
        ));
        drop(socket);
        fs::remove_file(&socket_path).unwrap();
        let unavailable = installer.status(provider, &target).unwrap().unwrap();
        assert_eq!(unavailable.lifecycle, BridgeLifecycle::Active);
        assert!(!unavailable.control_plane_available);
        assert!(!unavailable.is_active());
        installer.deactivate(provider, &target, owner(1)).unwrap();
        let detached = installer.detach(provider, &target, owner(1)).unwrap();
        assert_eq!(detached.lifecycle, BridgeLifecycle::Detached);
        assert_eq!(detached.integrity, BridgeIntegrity::Exact);
        assert!(!asset_path.exists());
        assert_eq!(
            installer.status(provider, &target).unwrap().unwrap(),
            detached
        );
    }
}

#[cfg(unix)]
#[test]
fn bridge_tampering_and_provider_reference_rewrite_cannot_claim_active() {
    use std::os::unix::net::UnixListener;

    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let target = root.join("plugins");
    fs::create_dir(&target).unwrap();
    let installer = BridgeInstaller::new(root.join("state"));
    let plan = installer
        .plan_install(ProviderId::OpenCode, &target)
        .unwrap();
    installer.install(&plan, owner(1)).unwrap();
    let socket_path = root.join("bridge.sock");
    let _socket = UnixListener::bind(&socket_path).unwrap();
    installer
        .activate(ProviderId::OpenCode, &target, &socket_path, owner(1))
        .unwrap();

    let valid = installer
        .managed_handler(
            ProviderId::OpenCode,
            &target,
            managed_spec(MANAGED_COMPONENT_REFERENCE),
        )
        .expect("managed handler from verified active bridge");
    let policy = HookPolicy::compile(
        ProviderId::OpenCode,
        "a".repeat(64),
        vec![valid],
        HookPolicyLimits::default(),
    )
    .expect("managed policy");
    assert_eq!(policy.handlers().len(), 1);

    assert!(matches!(
        installer.managed_handler(
            ProviderId::OpenCode,
            &target,
            managed_spec("rewritten-component")
        ),
        Err(BridgeError::InvalidManagedHandler)
    ));

    let asset_path = target.join("unpin-hook-bridge.ts");
    fs::write(&asset_path, "tampered").unwrap();
    let status = installer
        .status(ProviderId::OpenCode, &target)
        .unwrap()
        .unwrap();
    assert_eq!(status.integrity, BridgeIntegrity::Tampered);
    assert!(!status.is_active());
    assert!(matches!(
        installer.deactivate(ProviderId::OpenCode, &target, owner(1)),
        Err(BridgeError::IntegrityMismatch)
    ));
    assert!(matches!(
        installer.managed_handler(
            ProviderId::OpenCode,
            &target,
            managed_spec(MANAGED_COMPONENT_REFERENCE)
        ),
        Err(BridgeError::InvalidManagedHandler)
    ));
    assert_eq!(fs::read_to_string(asset_path).unwrap(), "tampered");
}

#[test]
fn occupied_targets_symlinks_and_partial_installs_preserve_user_files() {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let target = root.join("extensions");
    fs::create_dir(&target).unwrap();
    let installer = BridgeInstaller::new(root.join("state"));
    let asset_path = target.join("unpin-hook-bridge.ts");
    fs::write(&asset_path, "user owned").unwrap();
    assert!(matches!(
        installer.plan_install(ProviderId::Pi, &target),
        Err(BridgeError::TargetOccupied)
    ));
    assert_eq!(fs::read_to_string(&asset_path).unwrap(), "user owned");

    fs::remove_file(&asset_path).unwrap();
    let plan = installer.plan_install(ProviderId::Pi, &target).unwrap();
    fs::write(&asset_path, "raced user file").unwrap();
    assert!(matches!(
        installer.install(&plan, owner(1)),
        Err(BridgeError::TargetOccupied)
    ));
    assert_eq!(fs::read_to_string(&asset_path).unwrap(), "raced user file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        let alias = root.join("alias");
        symlink(&real, &alias).unwrap();
        assert!(matches!(
            installer.plan_install(ProviderId::Pi, &alias),
            Err(BridgeError::UnsafeTarget)
        ));
    }
}

#[cfg(unix)]
#[test]
fn bridge_activation_requires_a_live_non_symlink_control_socket() {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let target = root.join("plugins");
    fs::create_dir(&target).unwrap();
    let installer = BridgeInstaller::new(root.join("state"));
    let plan = installer
        .plan_install(ProviderId::OpenCode, &target)
        .unwrap();
    installer.install(&plan, owner(1)).unwrap();

    assert!(matches!(
        installer.activate(
            ProviderId::OpenCode,
            &target,
            root.join("missing.sock"),
            owner(1)
        ),
        Err(BridgeError::ControlPlaneUnavailable)
    ));
    let status = installer
        .status(ProviderId::OpenCode, &target)
        .unwrap()
        .unwrap();
    assert_eq!(status.lifecycle, BridgeLifecycle::InstalledInactive);
    assert!(!status.is_active());
}

#[test]
fn partial_recovery_reaches_terminal_state_without_deleting_contested_asset() {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let target = root.join("extensions");
    fs::create_dir(&target).unwrap();
    let installer = BridgeInstaller::new(root.join("state"));
    let plan = installer.plan_install(ProviderId::Pi, &target).unwrap();

    let state_path = root.join("state/bridges/pi").join(format!(
        "{}.json",
        stable_hash(
            target
                .join("unpin-hook-bridge.ts")
                .to_string_lossy()
                .as_bytes()
        )
    ));
    let asset_path = target.join("unpin-hook-bridge.ts");
    let state = unpin_core::state::atomic_json::AtomicJsonStore::new(&state_path, 1);
    let installing = serde_json::json!({
        "version": 1,
        "provider": "pi",
        "adapter": "managed-extension",
        "assetPath": asset_path,
        "assetFingerprint": plan.asset_fingerprint(),
        "lifecycle": "installing"
    });
    state
        .compare_and_swap(None, owner(1), &installing)
        .expect("write installing state");
    fs::write(&asset_path, "contested user content").unwrap();

    let recovered = installer
        .recover_partial(ProviderId::Pi, &target, owner(1))
        .expect("recover contested install");
    assert_eq!(recovered.lifecycle, BridgeLifecycle::Detached);
    assert_eq!(recovered.integrity, BridgeIntegrity::Tampered);
    assert_eq!(
        fs::read_to_string(asset_path).unwrap(),
        "contested user content"
    );
}

#[test]
fn detaching_recovery_preserves_exact_asset_or_finishes_after_completed_unlink() {
    let temp = TempDir::new().unwrap();
    let root = fs::canonicalize(temp.path()).unwrap();
    let state_root = root.join("state");
    let target = root.join("extensions");
    fs::create_dir(&target).unwrap();
    let installer = BridgeInstaller::new(&state_root);
    let plan = installer.plan_install(ProviderId::Pi, &target).unwrap();
    installer.install(&plan, owner(1)).unwrap();
    let asset_path = target.join("unpin-hook-bridge.ts");
    let state_path = state_root.join("bridges/pi").join(format!(
        "{}.json",
        stable_hash(asset_path.to_string_lossy().as_bytes())
    ));
    let store = unpin_core::state::atomic_json::AtomicJsonStore::new(&state_path, 1);

    let snapshot = store
        .load::<serde_json::Value>()
        .unwrap()
        .expect("installed state");
    let mut detaching = snapshot.value;
    detaching["lifecycle"] = serde_json::json!("detaching");
    store
        .compare_and_swap(Some(&snapshot.revision), owner(1), &detaching)
        .unwrap();
    let recovered = installer
        .recover_partial(ProviderId::Pi, &target, owner(1))
        .unwrap();
    assert_eq!(recovered.lifecycle, BridgeLifecycle::InstalledInactive);
    assert_eq!(recovered.integrity, BridgeIntegrity::Exact);
    assert!(asset_path.exists());

    let snapshot = store
        .load::<serde_json::Value>()
        .unwrap()
        .expect("recovered state");
    let mut detaching = snapshot.value;
    detaching["lifecycle"] = serde_json::json!("detaching");
    store
        .compare_and_swap(Some(&snapshot.revision), owner(1), &detaching)
        .unwrap();
    fs::remove_file(&asset_path).unwrap();
    let recovered = installer
        .recover_partial(ProviderId::Pi, &target, owner(1))
        .unwrap();
    assert_eq!(recovered.lifecycle, BridgeLifecycle::Detached);
    assert_eq!(recovered.integrity, BridgeIntegrity::Exact);
}

#[cfg(unix)]
fn managed_spec(reference: &str) -> HookHandlerSpec {
    HookHandlerSpec {
        id: "managed-opencode-before".to_string(),
        provider: ProviderId::OpenCode,
        native_event: "tool.execute.before".to_string(),
        event_family: HookEventFamily::BeforeTool,
        matcher: HookMatcher::any(),
        action: HookAction::provider_component(reference).unwrap(),
        order: 0,
        timeout_ms: 10_000,
        failure_policy: HookFailurePolicy::FailClosed,
        source_layer: HookSourceLayer::Component,
        ownership: HookOwnership::AdministratorManaged,
        route_owner: HookRouteOwner::ProviderBridge,
        enabled: true,
        transformations: HookTransformCapabilities::none(),
    }
}
