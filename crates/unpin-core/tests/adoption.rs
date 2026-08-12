use std::{
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use sha2::{Digest, Sha256};
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        ApprovalIssuer, ApprovalKey, ApprovalReceipt, ApprovalReceiptClaims, ApprovalVerifier,
    },
    catalog::{
        CapabilityId, CapabilityKind, Catalog,
        adoption::{
            AdoptionError, AdoptionObserver, AdoptionPhase, AdoptionRequest, AdoptionViewError,
            AuthenticatedNativeView, NativeViewState, NativeViewTransitionStatus, PlannedAdoption,
            authenticated_adopted_skill_catalog, load_adoption_records, plan_adoption,
            plan_discovered_adoption,
        },
    },
    discovery::{
        DiscoveryCategory, DiscoveryItem, DiscoveryKind, DiscoveryLayer, DiscoveryMutability,
        DiscoveryOutput,
    },
    mutation::BackupAuthenticationKey,
    profiles::{PolicyTarget, ProfileDefinition, ProfileSourceScope, compile_profile},
    providers::ProviderId,
    sessions::{
        GatewayModeAction, GatewayModeTarget, GatewayNativeViewApplyStatus,
        GatewayNativeViewController, GatewayWorkflowController, GatewayWorkflowError,
        SessionAuthorityKey,
    },
    state::atomic_json::OwnerGeneration,
    transitions::{
        EffectActivation, TransitionContext, TransitionCoordinator, TransitionOutcomeStatus,
    },
};

mod support;
use support::{control_authorization, control_context};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary directory");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary directory");
        make_private(&path);
        Self {
            _inner: inner,
            path,
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn make_private(_path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700)).expect("private directory");
    }
}

fn fixture(temp: &TempDir, operation_id: &str) -> PlannedAdoption {
    let provider_root = temp.path().join("provider");
    let source = provider_root.join("skills/review");
    fs::create_dir_all(source.join("scripts")).expect("source directory");
    fs::write(source.join("SKILL.md"), b"# Review\nOriginal body\n").expect("skill body");
    let script = source.join("scripts/check.sh");
    fs::write(&script, b"#!/bin/sh\nexit 0\n").expect("skill script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .expect("executable skill script");
    }
    let app_state_root = temp.path().join("state");
    let item = DiscoveryItem {
        provider: ProviderId::Codex,
        kind: DiscoveryKind::Skill,
        category: DiscoveryCategory::Skill,
        layer: DiscoveryLayer::Global,
        id: "codex:global:skill:review".to_string(),
        display_name: "review".to_string(),
        enabled: true,
        mutability: DiscoveryMutability::ReadWrite,
        source_path: fs::canonicalize(&source)
            .expect("source path")
            .to_string_lossy()
            .into_owned(),
        state_path: source.to_string_lossy().into_owned(),
        source_fingerprint: Some(format!(
            "sha256:{}",
            Sha256::digest(b"# Review\nOriginal body\n")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )),
        hook: None,
    };
    let mut record = Catalog::from_discovery(&DiscoveryOutput {
        items: vec![item.clone()],
        warnings: Vec::new(),
        ..DiscoveryOutput::default()
    })
    .expect("catalog")
    .records
    .into_values()
    .next()
    .expect("catalog record");
    record.id = CapabilityId::new("catalog:skill:review").expect("capability id");
    plan_discovered_adoption(
        &item,
        &record,
        operation_id,
        fs::canonicalize(&provider_root).expect("provider root"),
        app_state_root,
        TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: None,
            profile_digest: None,
        },
        EffectActivation::NextSessionOnly,
    )
    .expect("adoption plan")
}

fn coordinator(planned: &PlannedAdoption) -> TransitionCoordinator {
    let root = planned
        .canonical_path()
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "state"))
        .expect("state root");
    TransitionCoordinator::new(root, "unpin-cli-human", "unpin-core-transition")
        .expect("coordinator")
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("adoption-test-owner", 1).expect("owner")
}

fn verifier() -> ApprovalVerifier {
    ApprovalVerifier::new(ApprovalKey::new([0x52; 32]))
}

fn receipt(planned: &PlannedAdoption, nonce: &str) -> ApprovalReceipt {
    let plan = &planned.transition;
    ApprovalIssuer::new(
        ApprovalKey::new([0x52; 32]),
        "unpin-cli-human",
        "unpin-core-transition",
    )
    .expect("issuer")
    .issue(ApprovalReceiptClaims {
        version: 1,
        receipt_id: format!("receipt-{}", plan.operation_id),
        nonce: nonce.to_string(),
        issuer: "assigned".to_string(),
        audience: "assigned".to_string(),
        operation_id: plan.operation_id.clone(),
        operation_kind: plan.kind.as_str().to_string(),
        effect_graph_digest: plan.effect_graph_digest.clone(),
        repository_key: plan.context.repository_key.clone(),
        workspace_key: plan.context.workspace_key.clone(),
        session_id: plan.context.session_id.clone(),
        profile_digest: plan.context.profile_digest.clone(),
        resources: plan.resource_bindings(),
        issued_at_unix: 1_000,
        expires_at_unix: 1_100,
    })
    .expect("receipt")
}

fn backup_key() -> BackupAuthenticationKey {
    BackupAuthenticationKey::new([0x71; 32])
}

struct PanicAfterCopy {
    fired: AtomicBool,
}

impl AdoptionObserver for PanicAfterCopy {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError> {
        if phase == AdoptionPhase::AfterCanonicalCopy && !self.fired.swap(true, Ordering::SeqCst) {
            panic!("injected process interruption after canonical copy");
        }
        Ok(())
    }
}

struct ReplaceBeforeWithdrawal {
    source_file: PathBuf,
}

impl AdoptionObserver for ReplaceBeforeWithdrawal {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError> {
        if phase == AdoptionPhase::BeforeNativeWithdrawal {
            fs::write(&self.source_file, b"external replacement\n")
                .expect("external source replacement");
        }
        Ok(())
    }
}

struct RenameBeforeWithdrawal {
    source: PathBuf,
}

impl AdoptionObserver for RenameBeforeWithdrawal {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError> {
        if phase == AdoptionPhase::BeforeNativeWithdrawal {
            fs::rename(&self.source, self.source.with_extension("externally-moved"))
                .expect("external source rename");
        }
        Ok(())
    }
}

struct FailAfterWithdrawal;

impl AdoptionObserver for FailAfterWithdrawal {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError> {
        if phase == AdoptionPhase::AfterNativeWithdrawal {
            Err(AdoptionError::InjectedFailure)
        } else {
            Ok(())
        }
    }
}

struct FailAfterActivation;

impl AdoptionObserver for FailAfterActivation {
    fn observe(&self, phase: AdoptionPhase) -> Result<(), AdoptionError> {
        if phase == AdoptionPhase::AfterActivationRecord {
            Err(AdoptionError::InjectedFailure)
        } else {
            Ok(())
        }
    }
}

#[test]
fn interruption_after_canonical_copy_resumes_without_duplicate_or_lost_origin() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-resume");
    let approval = receipt(&planned, "nonce-adoption-resume");
    let source = planned.source_path().to_path_buf();
    let canonical = planned.canonical_path().to_path_buf();
    let crashing_backend = planned.backend_with_observer(
        backup_key(),
        Arc::new(PanicAfterCopy {
            fired: AtomicBool::new(false),
        }),
    );

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        coordinator(&planned).execute(
            &planned.transition,
            Some(&approval),
            &verifier(),
            1_050,
            owner(),
            &crashing_backend,
        )
    }));
    assert!(crashed.is_err());
    assert!(source.exists());
    assert_eq!(
        fs::read(canonical.join("content/node/SKILL.md")).expect("canonical body"),
        b"# Review\nOriginal body\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(canonical.join("content/node/scripts/check.sh"))
            .expect("canonical executable")
            .permissions()
            .mode();
        assert_ne!(mode & 0o100, 0, "owner executable bit is preserved");
        assert_eq!(mode & 0o077, 0, "canonical copy remains private");
    }

    let outcome = coordinator(&planned)
        .execute(
            &planned.transition,
            None,
            &verifier(),
            2_000,
            owner(),
            &planned.backend(backup_key()),
        )
        .expect("resumed adoption");
    assert_eq!(outcome.status, TransitionOutcomeStatus::Committed);
    assert!(!source.exists());
    assert_eq!(
        fs::read(
            temp.path()
                .join("state/backups")
                .join(&outcome.backup_id)
                .join("retained-original/SKILL.md")
        )
        .expect("retained origin"),
        b"# Review\nOriginal body\n"
    );

    let manifest = fs::read_to_string(
        temp.path()
            .join("state/backups")
            .join(&outcome.backup_id)
            .join("manifest.json"),
    )
    .expect("authenticated manifest");
    assert!(manifest.contains("hmac-sha256"));
    assert!(!manifest.contains(&"71".repeat(32)));

    let records = load_adoption_records(
        temp.path().join("state"),
        "repository-key",
        "catalog:skill:review",
        &backup_key(),
    )
    .expect("authenticated adoption records");
    assert_eq!(records.len(), 1);
    assert!(records[0].active());
    assert_eq!(records[0].operation_id(), "adoption-resume");
    assert_eq!(records[0].backup_id(), outcome.backup_id);
    assert_eq!(records[0].original_source_path(), source);
    assert_eq!(records[0].canonical_path(), canonical);
}

#[test]
fn source_replacement_after_copy_is_not_withdrawn_or_overwritten() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-source-race");
    let source_file = planned.source_path().join("SKILL.md");
    let backend = planned.backend_with_observer(
        backup_key(),
        Arc::new(ReplaceBeforeWithdrawal {
            source_file: source_file.clone(),
        }),
    );

    let outcome = coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-source-race")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect("safe needs-repair result");
    assert_eq!(outcome.status, TransitionOutcomeStatus::NeedsRepair);
    assert_eq!(
        fs::read(&source_file).expect("external source survives"),
        b"external replacement\n"
    );
}

#[cfg(unix)]
#[test]
fn legacy_mutation_lock_blocks_adoption_before_backup_or_source_withdrawal() {
    use std::os::unix::fs::OpenOptionsExt;

    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-legacy-lock-conflict");
    let lock_dir = temp.path().join("state/locks");
    fs::create_dir_all(&lock_dir).expect("legacy lock directory");
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(lock_dir.join("mutation.lock"))
        .expect("legacy lock file");
    lock.lock().expect("hold legacy mutation lock");

    let error = coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-adoption-legacy-lock")),
            &verifier(),
            1_050,
            owner(),
            &planned.backend(backup_key()),
        )
        .expect_err("legacy writer must serialize with adoption");
    assert!(matches!(
        error,
        unpin_core::transitions::CoordinatorError::LegacyMutationBusy(_)
    ));
    assert!(planned.source_path().join("SKILL.md").exists());
    assert!(!planned.canonical_path().exists());
    assert!(!temp.path().join("state/backups").exists());
}

#[test]
fn failure_after_withdrawal_restores_exact_original_and_removes_canonical_copy() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-restore");
    let source = planned.source_path().to_path_buf();
    let canonical = planned.canonical_path().to_path_buf();
    let original = fs::read(source.join("SKILL.md")).expect("original bytes");
    let backend = planned.backend_with_observer(backup_key(), Arc::new(FailAfterWithdrawal));

    let outcome = coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-adoption-restore")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect("rolled-back adoption");
    assert_eq!(outcome.status, TransitionOutcomeStatus::RolledBack);
    assert_eq!(
        fs::read(source.join("SKILL.md")).expect("restored bytes"),
        original
    );
    assert!(!canonical.exists());
    assert!(
        temp.path()
            .join("state/backups")
            .join(outcome.backup_id)
            .join("payload/node/SKILL.md")
            .exists()
    );
}

#[test]
fn rollback_deactivates_persisted_adoption_record_and_restores_native_view() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-record-rollback");
    let source = planned.source_path().to_path_buf();
    let backend = planned.backend_with_observer(backup_key(), Arc::new(FailAfterActivation));

    let outcome = coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-adoption-record-rollback")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect("rolled-back activation record");
    assert_eq!(outcome.status, TransitionOutcomeStatus::RolledBack);
    assert!(source.join("SKILL.md").exists());
    let records = load_adoption_records(
        temp.path().join("state"),
        "repository-key",
        "catalog:skill:review",
        &backup_key(),
    )
    .expect("authenticated inactive record");
    assert_eq!(records.len(), 1);
    assert!(!records[0].active());
}

#[test]
fn tampered_adoption_record_is_rejected_as_contested_state() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-record-tamper");
    coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-adoption-record-tamper")),
            &verifier(),
            1_050,
            owner(),
            &planned.backend(backup_key()),
        )
        .expect("committed adoption");

    let record_path = planned.activation_record_path();
    let mut document: serde_json::Value =
        serde_json::from_slice(&fs::read(record_path).expect("persisted activation record"))
            .expect("activation JSON");
    document["value"]["active"] = serde_json::Value::Bool(false);
    fs::write(
        record_path,
        serde_json::to_vec_pretty(&document).expect("tampered activation JSON"),
    )
    .expect("tamper activation record");

    let error = match load_adoption_records(
        temp.path().join("state"),
        "repository-key",
        "catalog:skill:review",
        &backup_key(),
    ) {
        Err(error) => error,
        Ok(_) => panic!("tampered record must not be trusted"),
    };
    assert!(matches!(error, AdoptionError::ActivationRecordContested));
}

#[test]
fn source_directory_rename_before_withdrawal_enters_needs_repair_without_data_loss() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-directory-race");
    let source = planned.source_path().to_path_buf();
    let moved = source.with_extension("externally-moved");
    let backend = planned.backend_with_observer(
        backup_key(),
        Arc::new(RenameBeforeWithdrawal {
            source: source.clone(),
        }),
    );

    let outcome = coordinator(&planned)
        .execute(
            &planned.transition,
            Some(&receipt(&planned, "nonce-directory-race")),
            &verifier(),
            1_050,
            owner(),
            &backend,
        )
        .expect("safe needs-repair result");
    assert_eq!(outcome.status, TransitionOutcomeStatus::NeedsRepair);
    assert!(moved.join("SKILL.md").exists());
    assert!(!source.exists());
}

#[test]
fn symlinks_hardlinks_special_files_traversal_and_plugins_are_rejected_at_plan_time() {
    let temp = TempDir::new();
    let root = temp.path().join("provider");
    fs::create_dir_all(root.join("skills")).expect("provider skills");
    let state = temp.path().join("state");
    let request = |source_path: PathBuf, kind| AdoptionRequest {
        operation_id: "unsafe-adoption".to_string(),
        capability_id: "catalog:skill:unsafe".to_string(),
        capability_kind: kind,
        provider: ProviderId::Codex,
        approved_provider_root: fs::canonicalize(&root).expect("root"),
        source_path,
        app_state_root: state.clone(),
        context: TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: None,
            profile_digest: None,
        },
        activation: EffectActivation::NextSessionOnly,
        catalog_record: None,
    };

    let target = root.join("skills/target");
    fs::create_dir(&target).expect("target");
    fs::write(target.join("SKILL.md"), b"safe").expect("target body");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, root.join("skills/link")).expect("skill symlink");
        assert!(matches!(
            plan_adoption(request(root.join("skills/link"), CapabilityKind::Skill)),
            Err(AdoptionError::SymlinkRejected(_))
        ));
    }

    let hardlinked = root.join("skills/hardlinked");
    fs::create_dir(&hardlinked).expect("hardlinked skill");
    fs::hard_link(target.join("SKILL.md"), hardlinked.join("SKILL.md")).expect("hard link");
    assert!(matches!(
        plan_adoption(request(hardlinked, CapabilityKind::Skill)),
        Err(AdoptionError::HardLinkAmbiguous(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let special = root.join("skills/special");
        fs::create_dir(&special).expect("special skill");
        let _socket = UnixListener::bind(special.join("socket")).expect("unix socket");
        assert!(matches!(
            plan_adoption(request(special, CapabilityKind::Skill)),
            Err(AdoptionError::SpecialFileRejected(_))
        ));
    }

    assert!(matches!(
        plan_adoption(request(
            root.join("skills/../skills/target"),
            CapabilityKind::Skill
        )),
        Err(AdoptionError::PathTraversalRejected)
    ));
    assert!(matches!(
        plan_adoption(request(target, CapabilityKind::Plugin)),
        Err(AdoptionError::InstalledBundleMustRemainProviderOwned)
    ));
}

#[cfg(unix)]
#[test]
fn cross_filesystem_adoption_is_rejected_before_creating_state() {
    use std::os::unix::fs::MetadataExt;

    let temp = TempDir::new();
    let provider_root = temp.path().join("provider-cross-filesystem");
    let source = provider_root.join("skills/review");
    fs::create_dir_all(&source).expect("provider source");
    fs::write(source.join("SKILL.md"), b"# Review\n").expect("skill body");
    let source_device = fs::metadata(&source).expect("source metadata").dev();
    let Some(other_root) = [Path::new("/dev"), Path::new("/System/Volumes/VM")]
        .into_iter()
        .find(|path| {
            fs::metadata(path)
                .is_ok_and(|metadata| metadata.is_dir() && metadata.dev() != source_device)
        })
    else {
        return;
    };
    let app_state_root = other_root.join(format!(
        ".unpin-cross-filesystem-test-{}",
        std::process::id()
    ));

    let result = plan_adoption(AdoptionRequest {
        operation_id: "adoption-cross-filesystem".to_string(),
        capability_id: "catalog:skill:cross-filesystem".to_string(),
        capability_kind: CapabilityKind::Skill,
        provider: ProviderId::Codex,
        approved_provider_root: fs::canonicalize(&provider_root).expect("provider root"),
        source_path: fs::canonicalize(&source).expect("source path"),
        app_state_root: app_state_root.clone(),
        context: TransitionContext {
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: None,
            profile_digest: None,
        },
        activation: EffectActivation::NextSessionOnly,
        catalog_record: None,
    });
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("cross-filesystem adoption must be rejected"),
    };
    assert!(matches!(error, AdoptionError::CrossFilesystemUnsupported));
    assert!(!app_state_root.exists());
    assert!(source.join("SKILL.md").exists());
}

#[test]
fn contested_canonical_destination_fails_before_backup_or_native_withdrawal() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-destination-race");
    let source = planned.source_path().to_path_buf();
    fs::create_dir_all(planned.canonical_path()).expect("contested destination");
    make_private(planned.canonical_path());
    fs::write(planned.canonical_path().join("foreign"), b"external").expect("foreign content");

    let result = coordinator(&planned).execute(
        &planned.transition,
        Some(&receipt(&planned, "nonce-destination-race")),
        &verifier(),
        1_050,
        owner(),
        &planned.backend(backup_key()),
    );
    assert!(result.is_err());
    assert!(source.join("SKILL.md").exists());
    assert!(!temp.path().join("state/backups").exists());
}

fn commit_adoption(temp: &TempDir, planned: &PlannedAdoption, nonce: &str) {
    let outcome = coordinator(planned)
        .execute(
            &planned.transition,
            Some(&receipt(planned, nonce)),
            &verifier(),
            1_050,
            owner(),
            &planned.backend(backup_key()),
        )
        .expect("committed adoption");
    assert_eq!(outcome.status, TransitionOutcomeStatus::Committed);
    assert!(
        temp.path()
            .join("state/backups")
            .join(outcome.backup_id)
            .exists()
    );
}

fn adoption_record(temp: &TempDir) -> unpin_core::catalog::adoption::AdoptionRecord {
    load_adoption_records(
        temp.path().join("state"),
        "repository-key",
        "catalog:skill:review",
        &backup_key(),
    )
    .expect("authenticated adoption records")
    .into_iter()
    .next()
    .expect("adoption record")
}

#[test]
fn authenticated_gateway_catalog_uses_withdrawn_canonical_skill_body() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-gateway-catalog");
    commit_adoption(&temp, &planned, "nonce-gateway-catalog");
    let record = adoption_record(&temp)
        .catalog_record()
        .expect("stored catalog metadata")
        .clone();
    let source = record.origin.source_path.clone();
    let source_record = record.clone();
    let catalog = Catalog::from_records([source_record]).expect("profile catalog");
    let profile = compile_profile(
        &ProfileDefinition {
            version: 1,
            id: "review".to_string(),
            display_name: "Review".to_string(),
            description: None,
            members: vec![record.id.clone()],
            provider_members: Default::default(),
            supported_providers: Default::default(),
        },
        &catalog,
        ProfileSourceScope::Workspace,
    )
    .expect("compiled profile");

    let gateway = authenticated_adopted_skill_catalog(
        temp.path().join("state"),
        "repository-key",
        "workspace-key",
        ProviderId::Codex,
        &profile,
        &backup_key(),
    )
    .expect("authenticated gateway catalog");
    let gateway_record = gateway.get(&record.id).expect("gateway record");
    assert_ne!(gateway_record.origin.source_path, source);
    assert!(
        gateway_record
            .origin
            .source_path
            .ends_with("/content/node/SKILL.md")
    );
    assert_eq!(
        fs::read_to_string(&gateway_record.origin.source_path).expect("canonical skill body"),
        "# Review\nOriginal body\n"
    );
}

#[test]
fn gateway_view_ledger_restores_only_owned_workspace_view_and_rewithdraws_it() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-gateway-ledger");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-gateway-ledger");
    let controller = GatewayNativeViewController::new(temp.path().join("state"), backup_key());
    let target =
        GatewayModeTarget::workspace_provider("repository-key", "workspace-key", ProviderId::Codex)
            .expect("workspace gateway target");

    let off = controller
        .plan(target.clone(), GatewayModeAction::Off)
        .expect("gateway off view plan");
    assert_eq!(off.entries.len(), 1);
    assert_eq!(off.entries[0].current, NativeViewState::Withdrawn);
    assert_eq!(off.entries[0].desired, NativeViewState::Present);
    let restored = controller
        .apply(&off, "gateway-view-test")
        .expect("restore gateway-owned native view");
    assert_eq!(restored.status, GatewayNativeViewApplyStatus::Applied);
    assert!(source.exists());

    let unrelated = controller
        .plan(
            GatewayModeTarget::workspace_provider(
                "repository-key",
                "other-workspace",
                ProviderId::Codex,
            )
            .expect("other workspace target"),
            GatewayModeAction::Activate,
        )
        .expect("unrelated workspace plan");
    assert!(unrelated.entries.is_empty());
    assert!(source.exists());

    let on = controller
        .plan(target.clone(), GatewayModeAction::Activate)
        .expect("gateway on view plan");
    assert_eq!(on.entries.len(), 1);
    assert_eq!(on.entries[0].current, NativeViewState::Present);
    assert_eq!(on.entries[0].desired, NativeViewState::Withdrawn);
    let withdrawn = controller
        .apply(&on, "gateway-view-test")
        .expect("withdraw gateway-owned native view");
    assert_eq!(withdrawn.status, GatewayNativeViewApplyStatus::Applied);
    assert!(!source.exists());
    assert!(
        controller
            .plan(target, GatewayModeAction::Activate)
            .expect("cleared gateway view ledger")
            .entries
            .is_empty()
    );
}

#[test]
fn gateway_activate_compensation_restores_reviewed_native_view_pre_state() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-gateway-compensation");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-gateway-compensation");
    let controller = GatewayNativeViewController::new(temp.path().join("state"), backup_key());
    let target =
        GatewayModeTarget::workspace_provider("repository-key", "workspace-key", ProviderId::Codex)
            .expect("workspace gateway target");

    let off = controller
        .plan(target.clone(), GatewayModeAction::Off)
        .expect("gateway off view plan");
    controller
        .apply(&off, "gateway-view-compensation-test")
        .expect("restore gateway-owned native view");
    let activate = controller
        .plan(target.clone(), GatewayModeAction::Activate)
        .expect("gateway activate view plan");

    AuthenticatedNativeView::new(adoption_record(&temp), backup_key())
        .expect("authenticated native view")
        .transition(NativeViewState::Withdrawn)
        .expect("simulate activate withdrawal");
    assert!(!source.exists());

    controller
        .compensate_activate(&activate)
        .expect("restore reviewed activate pre-state");
    assert!(source.exists());
    let retry = controller
        .plan(target, GatewayModeAction::Activate)
        .expect("retry activate plan");
    assert_eq!(retry.entries.len(), 1);
    assert_eq!(retry.entries[0].current, NativeViewState::Present);
    assert_eq!(retry.entries[0].desired, NativeViewState::Withdrawn);
}

#[test]
fn global_adopted_view_resources_protect_sessions_in_other_worktrees() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-global-session-protection");
    commit_adoption(&temp, &planned, "nonce-global-session-protection");
    let controller = GatewayNativeViewController::new(temp.path().join("state"), backup_key());

    let resources = controller
        .protected_resources_for_session(
            "repository-key",
            "different-worktree-key",
            ProviderId::Codex,
        )
        .expect("global adopted resources");

    assert_eq!(resources.len(), 4);
    assert!(
        resources
            .iter()
            .any(|resource| resource.starts_with("adoption-provider-view-"))
    );
}

#[test]
fn gateway_workflow_restores_adopted_view_off_and_rewithdraws_it_on() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-gateway-workflow");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-gateway-workflow");
    let state_root = temp.path().join("state");
    let controller = GatewayWorkflowController::with_authority_keys(
        &state_root,
        SessionAuthorityKey::new([0x53; 32]),
        backup_key(),
    );
    let target =
        GatewayModeTarget::workspace_provider("repository-key", "workspace-key", ProviderId::Codex)
            .expect("workspace gateway target");
    let policy_target = PolicyTarget::workspace("repository-key", "workspace-key")
        .expect("workspace policy target");
    let approval_context = control_context("repository-key", "workspace-key");
    let mut cached_activate = None;

    for (index, action) in [
        GatewayModeAction::Install,
        GatewayModeAction::Activate,
        GatewayModeAction::Off,
        GatewayModeAction::Activate,
    ]
    .into_iter()
    .enumerate()
    {
        let plan = controller
            .plan(
                target.clone(),
                policy_target.clone(),
                Some(ProviderId::Codex),
                action,
                false,
            )
            .expect("gateway workflow plan");
        let expectation = plan
            .approval_expectation(&approval_context)
            .expect("gateway approval expectation");
        let authorization = control_authorization(
            &state_root,
            &expectation,
            &format!("gateway-view-workflow-{index}"),
            2_000 + index as i64,
        );
        let result = controller
            .apply(
                &plan,
                authorization,
                &approval_context,
                "gateway-view-workflow-test",
                2_000 + index as i64,
            )
            .expect("gateway workflow apply");

        match action {
            GatewayModeAction::Off => {
                assert_eq!(
                    result.native_views.expect("off native views").status,
                    GatewayNativeViewApplyStatus::Applied
                );
                assert!(source.exists());
            }
            GatewayModeAction::Activate if index == 3 => {
                assert_eq!(
                    result.native_views.expect("on native views").status,
                    GatewayNativeViewApplyStatus::Applied
                );
                assert!(!source.exists());
            }
            _ => assert!(!source.exists()),
        }
        if action == GatewayModeAction::Activate && index == 3 {
            cached_activate = Some(plan);
        }
    }

    AuthenticatedNativeView::new(adoption_record(&temp), backup_key())
        .expect("authenticated native view")
        .transition(NativeViewState::Present)
        .expect("diverge committed native view state");
    let cached_activate = cached_activate.expect("final activate plan");
    let expectation = cached_activate
        .approval_expectation(&approval_context)
        .expect("cached activate expectation");
    let retry_authorization =
        control_authorization(&state_root, &expectation, "gateway-view-workflow-3", 2_003);
    assert!(matches!(
        controller.apply(
            &cached_activate,
            retry_authorization,
            &approval_context,
            "gateway-view-workflow-test",
            2_003,
        ),
        Err(GatewayWorkflowError::RecoveryRequired {
            phase: "cached-post-state-diverged",
            ..
        })
    ));
}

#[test]
fn authenticated_native_view_restores_and_withdraws_exact_adopted_content() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-native-view-round-trip");
    let source = planned.source_path().to_path_buf();
    let canonical_body = planned.canonical_path().join("content/node/SKILL.md");
    commit_adoption(&temp, &planned, "nonce-native-view-round-trip");

    let record = adoption_record(&temp);
    let retained = temp
        .path()
        .join("state/backups")
        .join(record.backup_id())
        .join("retained-original");
    let view =
        AuthenticatedNativeView::new(record, backup_key()).expect("authenticated native view");
    assert_eq!(
        view.inspect().expect("withdrawn view"),
        NativeViewState::Withdrawn
    );
    assert!(view.physical_resources().iter().any(|resource| {
        resource.path() == source
            && resource
                .resource_id()
                .starts_with("adoption-provider-view-")
    }));

    let restored = view
        .transition(NativeViewState::Present)
        .expect("restore native view");
    assert_eq!(restored.status(), NativeViewTransitionStatus::Applied);
    assert_eq!(restored.state(), NativeViewState::Present);
    assert_eq!(
        fs::read(source.join("SKILL.md")).expect("restored source"),
        b"# Review\nOriginal body\n"
    );
    assert_eq!(
        fs::read(&canonical_body).expect("canonical content remains installed"),
        b"# Review\nOriginal body\n"
    );
    assert!(!adoption_record(&temp).active());

    let repeated = view
        .transition(NativeViewState::Present)
        .expect("repeat present transition");
    assert_eq!(repeated.status(), NativeViewTransitionStatus::NoOp);

    #[cfg(unix)]
    let restored_identity = {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&source).expect("restored source metadata");
        (metadata.dev(), metadata.ino())
    };
    let withdrawn = view
        .transition(NativeViewState::Withdrawn)
        .expect("withdraw native view");
    assert_eq!(withdrawn.status(), NativeViewTransitionStatus::Applied);
    assert_eq!(withdrawn.state(), NativeViewState::Withdrawn);
    assert!(!source.exists());
    assert_eq!(
        fs::read(retained.join("SKILL.md")).expect("retained source"),
        b"# Review\nOriginal body\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&retained).expect("retained source metadata");
        assert_eq!((metadata.dev(), metadata.ino()), restored_identity);
    }
    assert!(adoption_record(&temp).active());
    assert_eq!(
        view.transition(NativeViewState::Withdrawn)
            .expect("repeat withdrawn transition")
            .status(),
        NativeViewTransitionStatus::NoOp
    );
}

#[test]
fn native_view_rejects_tampered_record_and_backup_without_restoring_source() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-native-view-authentication");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-native-view-authentication");

    let record = adoption_record(&temp);
    let mut tampered_record = serde_json::to_value(record.clone()).expect("record JSON");
    tampered_record["canonicalPath"] = serde_json::Value::String("/private/foreign".to_string());
    let tampered_record = serde_json::from_value(tampered_record).expect("tampered record shape");
    assert!(matches!(
        AuthenticatedNativeView::new(tampered_record, backup_key()),
        Err(AdoptionViewError::RecordContested)
    ));
    assert!(!source.exists());

    let manifest_path = temp
        .path()
        .join("state/backups")
        .join(record.backup_id())
        .join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("authenticated backup manifest"))
            .expect("manifest JSON");
    manifest["value"]["tag"] = serde_json::Value::String("tampered".to_string());
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("tampered manifest JSON"),
    )
    .expect("tamper backup manifest");

    let view = AuthenticatedNativeView::new(record, backup_key())
        .expect("authenticated record still constructs view");
    let error = view
        .transition(NativeViewState::Present)
        .expect_err("tampered backup must fail closed");
    assert_eq!(error, AdoptionViewError::BackupContested);
    assert!(
        !error
            .to_string()
            .contains(&temp.path().to_string_lossy()[..])
    );
    assert!(!source.exists());
    assert!(adoption_record(&temp).active());
}

#[test]
fn native_view_rejects_canonical_or_source_drift_without_overwriting_content() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-native-view-drift");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-native-view-drift");
    let view = AuthenticatedNativeView::new(adoption_record(&temp), backup_key())
        .expect("authenticated native view");

    let canonical_body = planned.canonical_path().join("content/node/SKILL.md");
    fs::write(&canonical_body, b"contested canonical\n").expect("contest canonical content");
    assert_eq!(
        view.transition(NativeViewState::Present)
            .expect_err("canonical drift must fail closed"),
        AdoptionViewError::CanonicalContested
    );
    assert!(!source.exists());
    assert_eq!(
        fs::read(&canonical_body).expect("contested canonical survives"),
        b"contested canonical\n"
    );

    fs::write(&canonical_body, b"# Review\nOriginal body\n").expect("restore canonical bytes");
    view.transition(NativeViewState::Present)
        .expect("restore native view");
    fs::write(source.join("SKILL.md"), b"external source replacement\n")
        .expect("contest restored source");
    assert_eq!(
        view.transition(NativeViewState::Withdrawn)
            .expect_err("source drift must fail closed"),
        AdoptionViewError::NativeViewContested
    );
    assert_eq!(
        fs::read(source.join("SKILL.md")).expect("external source survives"),
        b"external source replacement\n"
    );
    assert!(!adoption_record(&temp).active());
}

#[test]
fn native_view_does_not_overwrite_contested_restore_target() {
    let temp = TempDir::new();
    let planned = fixture(&temp, "adoption-native-view-target-contested");
    let source = planned.source_path().to_path_buf();
    commit_adoption(&temp, &planned, "nonce-native-view-target-contested");
    let record = adoption_record(&temp);
    let retained = temp
        .path()
        .join("state/backups")
        .join(record.backup_id())
        .join("retained-original/SKILL.md");
    fs::create_dir_all(&source).expect("contested source directory");
    fs::write(source.join("foreign"), b"external\n").expect("contested source content");

    let view =
        AuthenticatedNativeView::new(record, backup_key()).expect("authenticated native view");
    let error = view
        .transition(NativeViewState::Present)
        .expect_err("contested target must fail closed");
    assert_eq!(error, AdoptionViewError::NativeViewContested);
    assert!(
        !error
            .to_string()
            .contains(&temp.path().to_string_lossy()[..])
    );
    assert_eq!(
        fs::read(source.join("foreign")).expect("foreign target survives"),
        b"external\n"
    );
    assert_eq!(
        fs::read(retained).expect("retained original survives"),
        b"# Review\nOriginal body\n"
    );
    assert!(adoption_record(&temp).active());
}
