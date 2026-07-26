use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use sha2::Digest;
use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        APPROVAL_NONCE_RETENTION_SECONDS, ApprovalError, ApprovalExpectation, ApprovalIssuer,
        ApprovalKey, ApprovalNonceStore, ApprovalReceipt, ApprovalReceiptClaims,
        ApprovalResourceBinding, ApprovalVerifier, MAX_APPROVAL_NONCE_LEDGER_ENTRIES,
        NonceConsumption,
    },
    config::{
        get_approval_nonce_ledger_path, get_approval_nonce_ledger_shard_path,
        get_approval_nonce_path,
    },
    state::atomic_json::{AtomicJsonStore, OwnerGeneration},
};

struct TempDir {
    _inner: RawTempDir,
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let inner = RawTempDir::new().expect("temporary directory");
        let path = fs::canonicalize(inner.path()).expect("canonical temporary directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private temporary directory");
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

fn nonce_digest(nonce: &str) -> String {
    sha2::Sha256::digest(nonce.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn nonce_shard(nonce: &str) -> String {
    nonce_digest(nonce)[..2].to_string()
}

fn resources() -> Vec<ApprovalResourceBinding> {
    vec![
        ApprovalResourceBinding {
            resource_id: "provider-file-b".to_string(),
            pre_state_fingerprint: Some(digest('b')),
        },
        ApprovalResourceBinding {
            resource_id: "provider-file-a".to_string(),
            pre_state_fingerprint: Some(digest('a')),
        },
    ]
}

fn claims(operation_id: &str, nonce: &str) -> ApprovalReceiptClaims {
    ApprovalReceiptClaims {
        version: 1,
        receipt_id: format!("receipt-{operation_id}"),
        nonce: nonce.to_string(),
        issuer: "ignored-by-issuer".to_string(),
        audience: "ignored-by-issuer".to_string(),
        operation_id: operation_id.to_string(),
        operation_kind: "apply-profile".to_string(),
        effect_graph_digest: digest('c'),
        repository_key: "repository-key".to_string(),
        workspace_key: "workspace-key".to_string(),
        session_id: Some("session-id".to_string()),
        profile_digest: Some(digest('d')),
        resources: resources(),
        issued_at_unix: 1_000,
        expires_at_unix: 1_100,
    }
}

fn expectation(receipt: &ApprovalReceipt) -> ApprovalExpectation {
    ApprovalExpectation {
        issuer: receipt.claims.issuer.clone(),
        audience: receipt.claims.audience.clone(),
        operation_id: receipt.claims.operation_id.clone(),
        operation_kind: receipt.claims.operation_kind.clone(),
        effect_graph_digest: receipt.claims.effect_graph_digest.clone(),
        repository_key: receipt.claims.repository_key.clone(),
        workspace_key: receipt.claims.workspace_key.clone(),
        session_id: receipt.claims.session_id.clone(),
        profile_digest: receipt.claims.profile_digest.clone(),
        resources: receipt.claims.resources.clone(),
    }
}

fn issuer() -> ApprovalIssuer {
    ApprovalIssuer::new(
        ApprovalKey::new([7; 32]),
        "unpin-cli-human",
        "unpin-core-transition",
    )
    .expect("approval issuer")
}

fn verifier() -> ApprovalVerifier {
    ApprovalVerifier::new(ApprovalKey::new([7; 32]))
}

fn owner() -> OwnerGeneration {
    OwnerGeneration::new("approval-test", 1).expect("valid owner")
}

#[test]
fn receipt_verification_binds_every_transition_dimension_and_time_window() {
    let receipt = issuer()
        .issue(claims("operation-one", "nonce-one"))
        .expect("issued receipt");
    let expected = expectation(&receipt);
    let verified = verifier()
        .verify(&receipt, &expected, 1_050)
        .expect("verified receipt");
    assert_eq!(verified.operation_id(), "operation-one");
    assert_eq!(verified.decision_digest(), receipt.decision_digest());
    assert_eq!(receipt.claims.resources[0].resource_id, "provider-file-a");

    let mut wrong = expected.clone();
    wrong.workspace_key = "other-workspace".to_string();
    assert!(matches!(
        verifier().verify(&receipt, &wrong, 1_050),
        Err(ApprovalError::BindingMismatch)
    ));
    let mut wrong = expected.clone();
    wrong.effect_graph_digest = digest('e');
    assert!(matches!(
        verifier().verify(&receipt, &wrong, 1_050),
        Err(ApprovalError::BindingMismatch)
    ));
    let mut wrong = expected.clone();
    wrong.resources[0].pre_state_fingerprint = Some(digest('f'));
    assert!(matches!(
        verifier().verify(&receipt, &wrong, 1_050),
        Err(ApprovalError::BindingMismatch)
    ));
    assert!(matches!(
        verifier().verify(&receipt, &expected, 999),
        Err(ApprovalError::NotYetValid)
    ));
    assert!(matches!(
        verifier().verify(&receipt, &expected, 1_100),
        Err(ApprovalError::Expired)
    ));
}

#[test]
fn issuer_rejects_long_lived_receipts_and_nonce_store_rechecks_consumption_time() {
    let mut long_lived = claims("operation-long-lived", "nonce-long-lived");
    long_lived.expires_at_unix =
        long_lived.issued_at_unix + unpin_core::approval::MAX_APPROVAL_LIFETIME_SECONDS + 1;
    assert!(matches!(
        issuer().issue(long_lived),
        Err(ApprovalError::ExpiryTooLong)
    ));

    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-time-bound", "nonce-time-bound"))
        .expect("time-bound receipt");
    let verified = verifier()
        .verify_binding(&receipt, &expectation(&receipt))
        .expect("cryptographic binding");
    let store = ApprovalNonceStore::new(temp.path());
    assert!(matches!(
        store.consume_or_attach(&verified, 999, owner()),
        Err(ApprovalError::NotYetValid)
    ));
    assert!(matches!(
        store.consume_or_attach(&verified, 1_100, owner()),
        Err(ApprovalError::Expired)
    ));
}

#[test]
fn forged_wrong_key_and_noncanonical_receipts_fail_closed_without_key_disclosure() {
    let receipt = issuer()
        .issue(claims("operation-one", "nonce-one"))
        .expect("issued receipt");
    let expected = expectation(&receipt);

    let mut forged = receipt.clone();
    forged.claims.operation_id = "operation-forged".to_string();
    assert!(matches!(
        verifier().verify(&forged, &expected, 1_050),
        Err(ApprovalError::InvalidSignature)
    ));
    assert!(matches!(
        ApprovalVerifier::new(ApprovalKey::new([8; 32])).verify(&receipt, &expected, 1_050),
        Err(ApprovalError::WrongKeyOrAlgorithm)
    ));

    let mut noncanonical = receipt.clone();
    noncanonical.claims.resources.reverse();
    assert!(matches!(
        verifier().verify(&noncanonical, &expected, 1_050),
        Err(ApprovalError::NonCanonicalClaims)
    ));
    let key_debug = format!("{:?}", ApprovalKey::new([7; 32]));
    assert!(key_debug.contains("key_id"));
    assert!(!key_debug.contains("7, 7"));
}

#[test]
fn nonce_consumption_is_atomic_and_duplicate_retry_attaches_only_to_same_decision() {
    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-one", "shared-nonce"))
        .expect("issued receipt");
    let verified = Arc::new(
        verifier()
            .verify(&receipt, &expectation(&receipt), 1_050)
            .expect("verified receipt"),
    );
    let store = Arc::new(ApprovalNonceStore::new(temp.path().join("state")));
    let workers = [(), ()].map(|()| {
        let store = Arc::clone(&store);
        let verified = Arc::clone(&verified);
        thread::spawn(move || store.consume_or_attach(&verified, 1_050, owner()))
    });
    let results = workers.map(|worker| worker.join().expect("nonce worker").expect("consumption"));
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == NonceConsumption::Consumed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == NonceConsumption::AttachedToSameOperation)
            .count(),
        1
    );

    let replay_receipt = issuer()
        .issue(claims("operation-two", "shared-nonce"))
        .expect("second receipt with replayed nonce");
    let replay = verifier()
        .verify(&replay_receipt, &expectation(&replay_receipt), 1_050)
        .expect("cryptographically valid replay");
    assert!(matches!(
        store.consume_or_attach(&replay, 1_050, owner()),
        Err(ApprovalError::Replay)
    ));
}

#[test]
fn duplicate_retry_preserves_the_original_recovery_timestamp() {
    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-retry", "nonce-retry"))
        .expect("issued receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("verified receipt");
    let store = ApprovalNonceStore::new(temp.path());

    assert_eq!(
        store
            .consume_or_attach(&verified, 1_050, owner())
            .expect("initial consumption"),
        NonceConsumption::Consumed
    );
    assert_eq!(
        store
            .consume_or_attach(&verified, 1_051, owner())
            .expect("exact retry at a later instant"),
        NonceConsumption::AttachedToSameOperation
    );

    let ledger: serde_json::Value = serde_json::from_slice(
        &fs::read(get_approval_nonce_ledger_shard_path(
            temp.path(),
            &nonce_shard("nonce-retry"),
        ))
        .expect("recovery ledger shard"),
    )
    .expect("recovery ledger JSON");
    assert_eq!(
        ledger["value"]["entries"][nonce_digest("nonce-retry")]["consumedAtUnix"],
        1_050
    );
}

#[test]
fn recovery_shard_replay_rejection_does_not_reserve_the_conflicting_decision() {
    let temp = TempDir::new();
    let store = ApprovalNonceStore::new(temp.path());
    let original_receipt = issuer()
        .issue(claims("operation-original", "nonce-recovery-only"))
        .expect("original receipt");
    let original = verifier()
        .verify(&original_receipt, &expectation(&original_receipt), 1_050)
        .expect("original verified receipt");
    store
        .consume_or_attach(&original, 1_050, owner())
        .expect("consume original nonce");

    let current_time = 1_050 + unpin_core::approval::MAX_APPROVAL_LIFETIME_SECONDS + 1;
    let mut cleanup_claims = claims("operation-cleanup", "nonce-cleanup");
    cleanup_claims.issued_at_unix = current_time - 50;
    cleanup_claims.expires_at_unix = current_time + 50;
    let cleanup_receipt = issuer().issue(cleanup_claims).expect("cleanup receipt");
    let cleanup = verifier()
        .verify(
            &cleanup_receipt,
            &expectation(&cleanup_receipt),
            current_time,
        )
        .expect("cleanup verified receipt");
    store
        .consume_or_attach(&cleanup, current_time, owner())
        .expect("prune original from active ledger");

    let original_digest = nonce_digest("nonce-recovery-only");
    let active_path = get_approval_nonce_ledger_path(temp.path());
    let active_before: serde_json::Value =
        serde_json::from_slice(&fs::read(&active_path).expect("active nonce ledger"))
            .expect("active nonce ledger JSON");
    assert!(active_before["value"]["entries"][&original_digest].is_null());

    let mut replay_claims = claims("operation-conflicting", "nonce-recovery-only");
    replay_claims.issued_at_unix = current_time - 50;
    replay_claims.expires_at_unix = current_time + 50;
    let replay_receipt = issuer().issue(replay_claims).expect("replay receipt");
    let replay = verifier()
        .verify(&replay_receipt, &expectation(&replay_receipt), current_time)
        .expect("cryptographically valid replay");
    assert!(matches!(
        store.consume_or_attach(&replay, current_time, owner()),
        Err(ApprovalError::Replay)
    ));

    let active_after: serde_json::Value =
        serde_json::from_slice(&fs::read(active_path).expect("active nonce ledger"))
            .expect("active nonce ledger JSON");
    assert!(
        active_after["value"]["entries"][&original_digest].is_null(),
        "recovery-ledger replay rejection must happen before active reservation"
    );
    assert_eq!(
        store
            .attach_existing(&original)
            .expect("original recovery evidence remains authoritative"),
        NonceConsumption::AttachedToSameOperation
    );
}

#[test]
fn nonce_reuse_after_recovery_retention_becomes_a_new_consumption() {
    let temp = TempDir::new();
    let store = ApprovalNonceStore::new(temp.path());
    let original_receipt = issuer()
        .issue(claims("operation-retained", "nonce-retained"))
        .expect("original receipt");
    let original = verifier()
        .verify(&original_receipt, &expectation(&original_receipt), 1_050)
        .expect("original verified receipt");
    store
        .consume_or_attach(&original, 1_050, owner())
        .expect("consume original nonce");

    let current_time = 1_050 + APPROVAL_NONCE_RETENTION_SECONDS + 1;
    let mut current_claims = claims("operation-after-retention", "nonce-retained");
    current_claims.issued_at_unix = current_time - 50;
    current_claims.expires_at_unix = current_time + 50;
    let current_receipt = issuer().issue(current_claims).expect("current receipt");
    let current = verifier()
        .verify(
            &current_receipt,
            &expectation(&current_receipt),
            current_time,
        )
        .expect("current verified receipt");

    assert_eq!(
        store
            .consume_or_attach(&current, current_time, owner())
            .expect("consume nonce after retention"),
        NonceConsumption::Consumed
    );
    assert!(matches!(
        store.attach_existing(&original),
        Err(ApprovalError::Replay)
    ));
    assert_eq!(
        store
            .attach_existing(&current)
            .expect("new consumption is authoritative"),
        NonceConsumption::AttachedToSameOperation
    );
}

#[test]
fn nonce_ledger_records_the_supplied_owner_generation() {
    let temp = TempDir::new();
    let store = ApprovalNonceStore::new(temp.path());
    let first_nonce = "nonce-first-owner".to_string();
    let shard = nonce_shard(&first_nonce);
    let second_nonce = (0..10_000)
        .map(|index| format!("nonce-second-owner-{index}"))
        .find(|nonce| nonce_shard(nonce) == shard)
        .expect("nonce in the same ledger shard");

    for (operation, nonce, owner_id) in [
        ("operation-first-owner", first_nonce.as_str(), "first-owner"),
        (
            "operation-second-owner",
            second_nonce.as_str(),
            "second-owner",
        ),
    ] {
        let receipt = issuer()
            .issue(claims(operation, nonce))
            .expect("issued receipt");
        let verified = verifier()
            .verify(&receipt, &expectation(&receipt), 1_050)
            .expect("verified receipt");
        store
            .consume_or_attach(
                &verified,
                1_050,
                OwnerGeneration::new(owner_id, 1).expect("owner"),
            )
            .expect("consume nonce");
    }

    let ledger: serde_json::Value = serde_json::from_slice(
        &fs::read(get_approval_nonce_ledger_shard_path(temp.path(), &shard))
            .expect("nonce ledger shard"),
    )
    .expect("nonce ledger shard JSON");
    assert_eq!(ledger["owner"]["ownerId"], "second-owner");
    assert_eq!(ledger["owner"]["generation"], 2);
}

#[test]
fn nonce_ledger_fails_closed_at_its_bounded_capacity() {
    let temp = TempDir::new();
    let target_nonce = "nonce-over-capacity";
    let target_digest = nonce_digest(target_nonce);
    let shard = nonce_shard(target_nonce);
    let entries = (0..MAX_APPROVAL_NONCE_LEDGER_ENTRIES)
        .map(|index| {
            (
                format!("{shard}{index:062x}"),
                serde_json::json!({
                    "operationId": format!("seed-{index}"),
                    "decisionDigest": digest('a'),
                    "consumedAtUnix": 1_050
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    assert!(!entries.contains_key(&target_digest));
    AtomicJsonStore::new(get_approval_nonce_ledger_shard_path(temp.path(), &shard), 1)
        .compare_and_swap(
            None,
            owner(),
            &serde_json::json!({
                "entries": entries
            }),
        )
        .expect("seed bounded nonce ledger");

    let receipt = issuer()
        .issue(claims("operation-over-capacity", target_nonce))
        .expect("issued receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("verified receipt");
    let store = ApprovalNonceStore::new(temp.path());
    assert!(matches!(
        store.consume_or_attach(&verified, 1_050, owner()),
        Err(ApprovalError::NonceLedgerCapacity)
    ));

    let active_path = get_approval_nonce_ledger_path(temp.path());
    if active_path.exists() {
        let active: serde_json::Value =
            serde_json::from_slice(&fs::read(&active_path).expect("active nonce ledger"))
                .expect("active nonce ledger JSON");
        assert!(
            active["value"]["entries"][&target_digest].is_null(),
            "failed recovery persistence must not reserve active nonce state"
        );
    }

    let available_nonce = (0..10_000)
        .map(|index| format!("nonce-available-shard-{index}"))
        .find(|nonce| nonce_shard(nonce) != shard)
        .expect("nonce outside full recovery shard");
    let available_receipt = issuer()
        .issue(claims("operation-available-shard", &available_nonce))
        .expect("available-shard receipt");
    let available = verifier()
        .verify(&available_receipt, &expectation(&available_receipt), 1_050)
        .expect("available-shard verified receipt");
    assert_eq!(
        store
            .consume_or_attach(&available, 1_050, owner())
            .expect("full shard must not pollute active capacity"),
        NonceConsumption::Consumed
    );
}

#[test]
fn active_nonce_capacity_failure_preserves_recovery_evidence() {
    let temp = TempDir::new();
    let target_nonce = "nonce-active-capacity";
    let target_digest = nonce_digest(target_nonce);
    let entries = (0..MAX_APPROVAL_NONCE_LEDGER_ENTRIES)
        .map(|index| {
            (
                format!("{index:064x}"),
                serde_json::json!({
                    "operationId": format!("seed-{index}"),
                    "decisionDigest": digest('a'),
                    "consumedAtUnix": 1_050
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    assert!(!entries.contains_key(&target_digest));
    AtomicJsonStore::new(get_approval_nonce_ledger_path(temp.path()), 1)
        .compare_and_swap(
            None,
            owner(),
            &serde_json::json!({
                "entries": entries
            }),
        )
        .expect("seed bounded active nonce ledger");

    let receipt = issuer()
        .issue(claims("operation-active-capacity", target_nonce))
        .expect("issued receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("verified receipt");
    let store = ApprovalNonceStore::new(temp.path());
    assert!(matches!(
        store.consume_or_attach(&verified, 1_050, owner()),
        Err(ApprovalError::NonceLedgerCapacity)
    ));
    assert_eq!(
        store
            .attach_existing(&verified)
            .expect("capacity failure must preserve recovery evidence"),
        NonceConsumption::AttachedToSameOperation
    );

    let conflicting_receipt = issuer()
        .issue(claims("operation-active-capacity-conflict", target_nonce))
        .expect("conflicting receipt");
    let conflicting = verifier()
        .verify(
            &conflicting_receipt,
            &expectation(&conflicting_receipt),
            1_050,
        )
        .expect("conflicting verified receipt");
    assert!(matches!(
        store.attach_existing(&conflicting),
        Err(ApprovalError::Replay)
    ));
}

#[test]
fn full_active_nonce_ledger_recovers_after_the_receipt_window() {
    let temp = TempDir::new();
    let entries = (0..MAX_APPROVAL_NONCE_LEDGER_ENTRIES)
        .map(|index| {
            (
                format!("{index:064x}"),
                serde_json::json!({
                    "operationId": format!("seed-{index}"),
                    "decisionDigest": digest('a'),
                    "consumedAtUnix": 1_050
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    AtomicJsonStore::new(get_approval_nonce_ledger_path(temp.path()), 1)
        .compare_and_swap(
            None,
            owner(),
            &serde_json::json!({
                "entries": entries
            }),
        )
        .expect("seed full active nonce ledger");

    let nonce = (0..10_000)
        .map(|index| format!("nonce-after-receipt-window-{index}"))
        .find(|nonce| nonce_shard(nonce) != "00")
        .expect("nonce outside seeded recovery shard");
    let current_time = 1_050 + unpin_core::approval::MAX_APPROVAL_LIFETIME_SECONDS + 1;
    let mut current_claims = claims("operation-after-receipt-window", &nonce);
    current_claims.issued_at_unix = current_time - 50;
    current_claims.expires_at_unix = current_time + 50;
    let receipt = issuer().issue(current_claims).expect("issued receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), current_time)
        .expect("verified receipt");

    assert_eq!(
        ApprovalNonceStore::new(temp.path())
            .consume_or_attach(&verified, current_time, owner())
            .expect("consume after rolling replay window"),
        NonceConsumption::Consumed
    );
    let active: serde_json::Value = serde_json::from_slice(
        &fs::read(get_approval_nonce_ledger_path(temp.path())).expect("active nonce ledger"),
    )
    .expect("active nonce ledger JSON");
    assert_eq!(
        active["value"]["entries"]
            .as_object()
            .expect("active entries")
            .len(),
        1
    );
    assert!(
        get_approval_nonce_ledger_shard_path(temp.path(), "00").exists(),
        "pruned replay records remain available for durable recovery"
    );
}

#[test]
fn full_nonce_ledger_shard_does_not_block_other_shards() {
    let temp = TempDir::new();
    let full_shard = "00";
    let entries = (0..MAX_APPROVAL_NONCE_LEDGER_ENTRIES)
        .map(|index| {
            (
                format!("{full_shard}{index:062x}"),
                serde_json::json!({
                    "operationId": format!("seed-{index}"),
                    "decisionDigest": digest('a'),
                    "consumedAtUnix": 1_050
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    AtomicJsonStore::new(
        get_approval_nonce_ledger_shard_path(temp.path(), full_shard),
        1,
    )
    .compare_and_swap(
        None,
        owner(),
        &serde_json::json!({
            "entries": entries
        }),
    )
    .expect("seed full nonce ledger shard");

    let nonce = (0..10_000)
        .map(|index| format!("nonce-other-shard-{index}"))
        .find(|nonce| nonce_shard(nonce) != full_shard)
        .expect("nonce outside full shard");
    let receipt = issuer()
        .issue(claims("operation-other-shard", &nonce))
        .expect("issued receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("verified receipt");
    assert_eq!(
        ApprovalNonceStore::new(temp.path())
            .consume_or_attach(&verified, 1_050, owner())
            .expect("consume nonce in available shard"),
        NonceConsumption::Consumed
    );
}

#[test]
fn nonce_ledger_prunes_records_past_the_recovery_retention_window() {
    let temp = TempDir::new();
    let store = ApprovalNonceStore::new(temp.path());

    let old_receipt = issuer()
        .issue(claims("operation-old", "nonce-old"))
        .expect("old receipt");
    let old_verified = verifier()
        .verify(&old_receipt, &expectation(&old_receipt), 1_050)
        .expect("old verified receipt");
    assert_eq!(
        store
            .consume_or_attach(&old_verified, 1_050, owner())
            .expect("consume old nonce"),
        NonceConsumption::Consumed
    );

    let current_time = 1_050 + APPROVAL_NONCE_RETENTION_SECONDS + 1;
    let old_shard = nonce_shard("nonce-old");
    let current_nonce = (0..10_000)
        .map(|index| format!("nonce-current-{index}"))
        .find(|nonce| nonce_shard(nonce) == old_shard)
        .expect("current nonce in the same ledger shard");
    let mut current_claims = claims("operation-current", &current_nonce);
    current_claims.issued_at_unix = current_time - 50;
    current_claims.expires_at_unix = current_time + 50;
    let current_receipt = issuer().issue(current_claims).expect("current receipt");
    let current_verified = verifier()
        .verify(
            &current_receipt,
            &expectation(&current_receipt),
            current_time,
        )
        .expect("current verified receipt");
    assert_eq!(
        store
            .consume_or_attach(&current_verified, current_time, owner())
            .expect("consume current nonce"),
        NonceConsumption::Consumed
    );

    assert!(matches!(
        store.attach_existing(&old_verified),
        Err(ApprovalError::NonceNotConsumed)
    ));
    assert_eq!(
        store
            .attach_existing(&current_verified)
            .expect("attach current nonce"),
        NonceConsumption::AttachedToSameOperation
    );
    assert!(
        !temp.path().join("approvals/nonces").exists(),
        "new nonce consumption must use bounded shard ledgers, not per-nonce files"
    );
}

#[test]
fn active_nonce_ledger_is_copied_into_the_recovery_shard() {
    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-legacy-ledger", "nonce-legacy-ledger"))
        .expect("legacy ledger receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("legacy ledger verified receipt");
    let digest = nonce_digest("nonce-legacy-ledger");
    let legacy_path = get_approval_nonce_ledger_path(temp.path());
    AtomicJsonStore::new(&legacy_path, 1)
        .compare_and_swap(
            None,
            owner(),
            &serde_json::json!({
                "entries": {
                    (digest): {
                        "operationId": verified.operation_id(),
                        "decisionDigest": verified.decision_digest(),
                        "consumedAtUnix": 1_050
                    }
                }
            }),
        )
        .expect("legacy singleton ledger");

    let store = ApprovalNonceStore::new(temp.path());
    assert_eq!(
        store
            .consume_or_attach(&verified, 1_050, owner())
            .expect("migrate singleton ledger"),
        NonceConsumption::AttachedToSameOperation
    );
    assert!(
        legacy_path.exists(),
        "the rolling ledger remains the cross-version replay authority"
    );
    assert!(
        get_approval_nonce_ledger_shard_path(temp.path(), &nonce_shard("nonce-legacy-ledger"))
            .exists()
    );

    let replay_receipt = issuer()
        .issue(claims("operation-replay", "nonce-legacy-ledger"))
        .expect("replay receipt");
    let replay = verifier()
        .verify(&replay_receipt, &expectation(&replay_receipt), 1_050)
        .expect("verified replay receipt");
    assert!(matches!(
        store.consume_or_attach(&replay, 1_050, owner()),
        Err(ApprovalError::Replay)
    ));
}

#[test]
fn nonce_ledger_migrates_matching_legacy_nonce_state() {
    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-legacy", "nonce-legacy"))
        .expect("legacy receipt");
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("legacy verified receipt");
    let nonce_digest = nonce_digest("nonce-legacy");
    let legacy_path = get_approval_nonce_path(temp.path(), &nonce_digest);
    AtomicJsonStore::new(&legacy_path, 1)
        .compare_and_swap(
            None,
            owner(),
            &serde_json::json!({
                "operationId": verified.operation_id(),
                "decisionDigest": verified.decision_digest(),
                "consumedAtUnix": 1_050
            }),
        )
        .expect("legacy nonce state");

    let store = ApprovalNonceStore::new(temp.path());
    assert_eq!(
        store
            .consume_or_attach(&verified, 1_050, owner())
            .expect("migrate legacy nonce"),
        NonceConsumption::AttachedToSameOperation
    );
    assert!(!legacy_path.exists());

    let replay_receipt = issuer()
        .issue(claims("operation-replay", "nonce-legacy"))
        .expect("replay receipt");
    let replay = verifier()
        .verify(&replay_receipt, &expectation(&replay_receipt), 1_050)
        .expect("verified replay receipt");
    assert!(matches!(
        store.consume_or_attach(&replay, 1_050, owner()),
        Err(ApprovalError::Replay)
    ));
}

#[test]
fn receipt_json_contains_bindings_but_no_reusable_key_material() {
    let receipt = issuer()
        .issue(claims("operation-one", "nonce-one"))
        .expect("issued receipt");
    let json = serde_json::to_string(&receipt).expect("receipt JSON");
    assert!(json.contains("effectGraphDigest"));
    assert!(json.contains("preStateFingerprint"));
    assert!(!json.contains(&"07".repeat(32)));
}

#[test]
fn nonce_consumption_is_single_use_across_processes() {
    let temp = TempDir::new();
    let receipt = issuer()
        .issue(claims("operation-process", "nonce-process"))
        .expect("issued receipt");
    let receipt_path = temp.path().join("receipt.json");
    fs::write(
        &receipt_path,
        serde_json::to_vec(&receipt).expect("receipt JSON"),
    )
    .expect("write receipt fixture");
    let start_path = temp.path().join("start");
    let executable = env::current_exe().expect("test executable");
    let mut children = (0..2)
        .map(|index| {
            Command::new(&executable)
                .args([
                    "--exact",
                    "approval_nonce_process_worker",
                    "--ignored",
                    "--nocapture",
                ])
                .env("UNPIN_APPROVAL_TEST_ROOT", temp.path())
                .env("UNPIN_APPROVAL_TEST_RECEIPT", &receipt_path)
                .env("UNPIN_APPROVAL_TEST_START", &start_path)
                .env(
                    "UNPIN_APPROVAL_TEST_RESULT",
                    temp.path().join(format!("result-{index}")),
                )
                .spawn()
                .expect("spawn approval worker")
        })
        .collect::<Vec<_>>();
    fs::write(&start_path, b"go").expect("release workers");
    for child in &mut children {
        assert!(child.wait().expect("approval worker status").success());
    }
    let mut results = (0..2)
        .map(|index| {
            fs::read_to_string(temp.path().join(format!("result-{index}"))).expect("worker result")
        })
        .collect::<Vec<_>>();
    results.sort();
    assert_eq!(results, ["attached", "consumed"]);

    let replay_receipt = issuer()
        .issue(claims("other-process-operation", "nonce-process"))
        .expect("replay receipt");
    let replay = verifier()
        .verify(&replay_receipt, &expectation(&replay_receipt), 1_050)
        .expect("valid replay signature");
    assert!(matches!(
        ApprovalNonceStore::new(temp.path()).consume_or_attach(&replay, 1_050, owner()),
        Err(ApprovalError::Replay)
    ));
}

#[test]
#[ignore = "subprocess helper"]
fn approval_nonce_process_worker() {
    let Ok(root) = env::var("UNPIN_APPROVAL_TEST_ROOT") else {
        return;
    };
    let receipt_path = env::var("UNPIN_APPROVAL_TEST_RECEIPT").expect("receipt path");
    let start_path = env::var("UNPIN_APPROVAL_TEST_START").expect("start path");
    let result_path = env::var("UNPIN_APPROVAL_TEST_RESULT").expect("result path");
    let receipt: ApprovalReceipt =
        serde_json::from_slice(&fs::read(receipt_path).expect("read subprocess receipt"))
            .expect("decode subprocess receipt");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !Path::new(&start_path).exists() {
        assert!(
            Instant::now() < deadline,
            "approval subprocess start timeout"
        );
        thread::yield_now();
    }
    let verified = verifier()
        .verify(&receipt, &expectation(&receipt), 1_050)
        .expect("verify subprocess receipt");
    let result = ApprovalNonceStore::new(root)
        .consume_or_attach(&verified, 1_050, owner())
        .expect("consume subprocess nonce");
    fs::write(
        result_path,
        match result {
            NonceConsumption::Consumed => "consumed",
            NonceConsumption::AttachedToSameOperation => "attached",
        },
    )
    .expect("write subprocess result");
}
