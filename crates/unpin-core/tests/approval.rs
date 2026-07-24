use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir as RawTempDir;
use unpin_core::{
    approval::{
        ApprovalError, ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalNonceStore,
        ApprovalReceipt, ApprovalReceiptClaims, ApprovalResourceBinding, ApprovalVerifier,
        NonceConsumption,
    },
    state::atomic_json::OwnerGeneration,
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
