use std::collections::BTreeMap;

use tempfile::TempDir;
use unpin_core::{
    profiles::{
        GatewaySelection, PolicyStore, PolicyTarget, ProfileSelection, ProviderPolicy, ScopePolicy,
    },
    providers::ProviderId,
    state::atomic_json::OwnerGeneration,
};

fn policy(gateway: GatewaySelection) -> ScopePolicy {
    ScopePolicy {
        profile: ProfileSelection::Native,
        gateway,
        providers: BTreeMap::from([(
            ProviderId::Codex,
            ProviderPolicy {
                profile: ProfileSelection::None,
                gateway,
                ..ProviderPolicy::default()
            },
        )]),
    }
}

#[test]
fn policy_store_keeps_global_repository_and_workspaces_disjoint() {
    let temp = TempDir::new().expect("temporary state");
    let store = PolicyStore::new(std::fs::canonicalize(temp.path()).unwrap());
    let repository = PolicyTarget::repository("repository").expect("repository target");
    let workspace_a =
        PolicyTarget::workspace("repository", "workspace-a").expect("workspace target");
    let workspace_b =
        PolicyTarget::workspace("repository", "workspace-b").expect("workspace target");

    store
        .save(
            &PolicyTarget::Global,
            &policy(GatewaySelection::Native),
            None,
            OwnerGeneration::new("policy-test", 1).unwrap(),
        )
        .unwrap();
    store
        .save(
            &repository,
            &policy(GatewaySelection::Gateway),
            None,
            OwnerGeneration::new("policy-test", 1).unwrap(),
        )
        .unwrap();
    store
        .save(
            &workspace_a,
            &policy(GatewaySelection::Native),
            None,
            OwnerGeneration::new("policy-test", 1).unwrap(),
        )
        .unwrap();

    let resolved_a = store
        .load_resolution_policies("repository", "workspace-a", None)
        .unwrap();
    let resolved_b = store
        .load_resolution_policies("repository", "workspace-b", None)
        .unwrap();
    assert_eq!(
        resolved_a.workspace.unwrap().gateway,
        GatewaySelection::Native
    );
    assert!(resolved_b.workspace.is_none());
    assert_eq!(
        resolved_b.repository.unwrap().gateway,
        GatewaySelection::Gateway
    );
    assert!(store.load(&workspace_b).unwrap().is_none());
}

#[test]
fn policy_store_requires_revision_cas_and_owner_progression() {
    let temp = TempDir::new().expect("temporary state");
    let store = PolicyStore::new(std::fs::canonicalize(temp.path()).unwrap());
    let target = PolicyTarget::repository("repository").unwrap();
    store
        .save(
            &target,
            &policy(GatewaySelection::Native),
            None,
            OwnerGeneration::new("policy-test", 1).unwrap(),
        )
        .unwrap();
    let snapshot = store.load(&target).unwrap().unwrap();

    assert!(
        store
            .save(
                &target,
                &policy(GatewaySelection::Gateway),
                None,
                OwnerGeneration::new("policy-test", 2).unwrap(),
            )
            .is_err()
    );
    store
        .save(
            &target,
            &policy(GatewaySelection::Gateway),
            Some(&snapshot.revision),
            OwnerGeneration::new("policy-test", 2).unwrap(),
        )
        .unwrap();
    assert_eq!(
        store.load(&target).unwrap().unwrap().policy.gateway,
        GatewaySelection::Gateway
    );
}
