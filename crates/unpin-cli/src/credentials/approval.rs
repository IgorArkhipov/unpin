use std::path::Path;

#[cfg(any(unix, test))]
use std::io::Write;
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    io::{self, IsTerminal, Read},
    os::fd::{FromRawFd, RawFd},
};

use unpin_core::{
    approval::{
        ApprovalExpectation, ApprovalIssuer, ApprovalKey, ApprovalReceipt, ApprovalReceiptClaims,
        ApprovalVerifier, ControlAuthorization, MAX_APPROVAL_LIFETIME_SECONDS, authorize_control,
    },
    fixture::{FixtureCredentialPurpose, canonical_fixture_scope_path, fixture_credential_key},
    groups::GroupTogglePlan,
    state::atomic_json::OwnerGeneration,
};
use zeroize::Zeroizing;

use super::{KEYCHAIN_SERVICE, KeychainSecretStore, SecretStore, broker};

pub(super) const APPROVAL_ACCOUNT: &str = "transition-approval-key-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApprovalKeyState {
    Missing,
    Ready { key_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApprovalKeyInitialization {
    Created { key_id: String },
    AlreadyExists { key_id: String },
}

pub(crate) fn approval_key_status(store: &impl SecretStore) -> Result<ApprovalKeyState, String> {
    match load_approval_key(store)? {
        Some(key) => Ok(ApprovalKeyState::Ready {
            key_id: key.key_id(),
        }),
        None => Ok(ApprovalKeyState::Missing),
    }
}

pub(crate) fn approval_key_status_for_mode(
    fixture_mode: bool,
    app_state_root: &Path,
) -> Result<ApprovalKeyState, String> {
    if fixture_mode {
        return Ok(ApprovalKeyState::Ready {
            key_id: fixture_approval_key(app_state_root)?.key_id(),
        });
    }
    Ok(broker::resolve_runtime_bundle(app_state_root)?
        .approval()
        .map(ApprovalKey::new)
        .map_or(ApprovalKeyState::Missing, |key| ApprovalKeyState::Ready {
            key_id: key.key_id(),
        }))
}

pub(crate) fn initialize_approval_key(
    store: &impl SecretStore,
) -> Result<ApprovalKeyInitialization, String> {
    initialize_approval_key_with(store, |bytes| {
        getrandom::fill(bytes).map_err(|error| error.to_string())
    })
}

fn initialize_approval_key_with(
    store: &impl SecretStore,
    fill: impl FnOnce(&mut [u8]) -> Result<(), String>,
) -> Result<ApprovalKeyInitialization, String> {
    if let Some(key) = load_approval_key(store)? {
        return Ok(ApprovalKeyInitialization::AlreadyExists {
            key_id: key.key_id(),
        });
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    if let Err(error) = fill(&mut *bytes) {
        return Err(format!("approval key generation failed: {error}"));
    }
    let key = ApprovalKey::new(*bytes);
    let store_result = store.set(KEYCHAIN_SERVICE, APPROVAL_ACCOUNT, bytes.as_slice());
    store_result?;
    Ok(ApprovalKeyInitialization::Created {
        key_id: key.key_id(),
    })
}

pub(crate) fn authorize_control_decision(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    actor_id: &str,
    now_unix: i64,
) -> Result<ControlAuthorization, String> {
    authorize_reviewed_control_decision(
        fixture_mode,
        app_state_root,
        expectation,
        &expectation.effect_graph_digest,
        Some(&expectation.effect_graph_digest),
        actor_id,
        now_unix,
    )
}

pub(crate) fn authorize_reviewed_control_decision(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    actor_id: &str,
    now_unix: i64,
) -> Result<ControlAuthorization, String> {
    // macOS temporary roots commonly enter through `/var`, which is itself a
    // symlink. Fixture mode uses synthetic state only, so bind nonce evidence
    // to its canonical physical root without weakening live-state checks.
    let canonical_fixture_root = if fixture_mode {
        Some(canonical_fixture_scope_path(app_state_root)?)
    } else {
        None
    };
    let approval_state_root = canonical_fixture_root.as_deref().unwrap_or(app_state_root);
    let approval = issue_human_approval(
        fixture_mode,
        approval_state_root,
        expectation,
        plan_fingerprint,
        reviewed_fingerprint,
        now_unix,
    )?;
    authorize_control(
        approval_state_root,
        approval.receipt(),
        approval.verifier(),
        expectation,
        now_unix,
        OwnerGeneration::new(actor_id, 1).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

/// Consume a signed operator approval receipt from an already-open descriptor.
///
/// The descriptor number is only a handle to a secret supplied out-of-band by
/// the operator; the receipt itself is never accepted from argv, environment,
/// stdin, or a path. The core approval nonce ledger provides the durable
/// single-use/retry boundary after the receipt is verified against the exact
/// reviewed operation and context.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authorize_operator_descriptor(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    actor_id: &str,
    now_unix: i64,
    descriptor: i32,
) -> Result<ControlAuthorization, String> {
    validate_human_approval_request(expectation, plan_fingerprint, reviewed_fingerprint)
        .map_err(|_| "approval-principal-unverified".to_string())?;
    let receipt = read_operator_receipt(descriptor)?;
    let canonical_fixture_root = if fixture_mode {
        Some(
            canonical_fixture_scope_path(app_state_root)
                .map_err(|_| "approval-principal-unverified".to_string())?,
        )
    } else {
        None
    };
    let approval_state_root = canonical_fixture_root.as_deref().unwrap_or(app_state_root);
    let key = resolve_approval_key(fixture_mode, approval_state_root)
        .map_err(|_| "approval-principal-unverified".to_string())?
        .ok_or_else(|| "approval-principal-unverified".to_string())?;
    let verifier = ApprovalVerifier::new(key);
    authorize_control(
        approval_state_root,
        &receipt,
        &verifier,
        expectation,
        now_unix,
        OwnerGeneration::new(actor_id, 1)
            .map_err(|_| "approval-principal-unverified".to_string())?,
    )
    .map_err(|_| "approval-principal-unverified".to_string())
}

#[cfg(unix)]
fn read_operator_receipt(descriptor: i32) -> Result<ApprovalReceipt, String> {
    const MAX_OPERATOR_RECEIPT_BYTES: usize = 128 * 1024;
    if descriptor <= 2 {
        return Err("approval-principal-unverified".to_string());
    }
    let raw_fd =
        RawFd::try_from(descriptor).map_err(|_| "approval-principal-unverified".to_string())?;
    // SAFETY: ownership is transferred exactly once for this short-lived
    // credential read; dropping the File closes the supplied descriptor.
    let mut file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_OPERATOR_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "approval-principal-unverified".to_string())?;
    if bytes.len() > MAX_OPERATOR_RECEIPT_BYTES {
        return Err("approval-principal-unverified".to_string());
    }
    serde_json::from_slice(&bytes).map_err(|_| "approval-principal-unverified".to_string())
}

#[cfg(not(unix))]
fn read_operator_receipt(_descriptor: i32) -> Result<ApprovalReceipt, String> {
    Err("approval-principal-unverified".to_string())
}

pub(crate) fn authorize_desktop_control_decision(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    actor_id: &str,
    now_unix: i64,
) -> Result<ControlAuthorization, String> {
    let canonical_fixture_root = if fixture_mode {
        Some(canonical_fixture_scope_path(app_state_root)?)
    } else {
        None
    };
    let approval_state_root = canonical_fixture_root.as_deref().unwrap_or(app_state_root);
    let approval = issue_desktop_human_approval(
        fixture_mode,
        approval_state_root,
        expectation,
        plan_fingerprint,
        reviewed_fingerprint,
        now_unix,
    )?;
    authorize_control(
        approval_state_root,
        approval.receipt(),
        approval.verifier(),
        expectation,
        now_unix,
        OwnerGeneration::new(actor_id, 1).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

pub(crate) struct HumanApproval {
    receipt: ApprovalReceipt,
    verifier: ApprovalVerifier,
}

impl HumanApproval {
    pub(crate) const fn receipt(&self) -> &ApprovalReceipt {
        &self.receipt
    }

    pub(crate) const fn verifier(&self) -> &ApprovalVerifier {
        &self.verifier
    }
}

pub(crate) fn issue_human_approval(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    now_unix: i64,
) -> Result<HumanApproval, String> {
    if fixture_mode {
        let key = fixture_approval_key(app_state_root)?;
        return issue_human_approval_with(
            expectation,
            plan_fingerprint,
            reviewed_fingerprint,
            now_unix,
            &FixtureHumanPresence,
            || Ok(Some(key)),
            random_suffix,
        );
    }
    issue_human_approval_with(
        expectation,
        plan_fingerprint,
        reviewed_fingerprint,
        now_unix,
        &ControllingTerminalHumanPresence,
        || load_approval_key(&KeychainSecretStore),
        random_suffix,
    )
}

/// Issue a local-desktop approval without accepting a client-provided
/// confirmation value. On macOS the Rust child creates and reads a temporary
/// Keychain item protected by `userPresence`; the approval key is opened only
/// after that OS-mediated check succeeds.
pub(crate) fn issue_desktop_human_approval(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    now_unix: i64,
) -> Result<HumanApproval, String> {
    if fixture_mode {
        let key = fixture_approval_key(app_state_root)?;
        return issue_human_approval_with(
            expectation,
            plan_fingerprint,
            reviewed_fingerprint,
            now_unix,
            &FixtureHumanPresence,
            || Ok(Some(key)),
            random_suffix,
        );
    }

    #[cfg(target_os = "macos")]
    {
        issue_human_approval_with(
            expectation,
            plan_fingerprint,
            reviewed_fingerprint,
            now_unix,
            &MacOsUserPresence,
            || load_approval_key(&KeychainSecretStore),
            random_suffix,
        )
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (
            expectation,
            plan_fingerprint,
            reviewed_fingerprint,
            now_unix,
        );
        Err("desktop approval is supported only on macOS".to_string())
    }
}

pub(crate) fn issue_inventory_group_approval(
    fixture_mode: bool,
    app_state_root: &Path,
    expectation: &ApprovalExpectation,
    plan: &GroupTogglePlan,
    now_unix: i64,
) -> Result<HumanApproval, String> {
    plan.verify().map_err(|error| error.to_string())?;
    if plan.plan_fingerprint != expectation.effect_graph_digest {
        return Err("group plan does not match approval expectation".to_string());
    }
    if !fixture_mode {
        render_inventory_group_review(plan)?;
    }
    issue_human_approval(
        fixture_mode,
        app_state_root,
        expectation,
        &plan.plan_fingerprint,
        Some(&plan.plan_fingerprint),
        now_unix,
    )
}

#[cfg(unix)]
fn render_inventory_group_review(plan: &GroupTogglePlan) -> Result<(), String> {
    let mut tty = OpenOptions::new()
        .write(true)
        .open("/dev/tty")
        .map_err(|error| {
            format!("inventory group approval requires a controlling terminal: {error}")
        })?;
    writeln!(tty, "Complete inventory group effect under review:")
        .map_err(|error| error.to_string())?;
    serde_json::to_writer_pretty(&mut tty, plan).map_err(|error| error.to_string())?;
    writeln!(tty).map_err(|error| error.to_string())?;
    tty.flush().map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn render_inventory_group_review(_plan: &GroupTogglePlan) -> Result<(), String> {
    Err("inventory group approval is unsupported on this platform".to_string())
}

fn fixture_approval_key(app_state_root: &Path) -> Result<ApprovalKey, String> {
    fixture_credential_key(app_state_root, FixtureCredentialPurpose::Approval).map(ApprovalKey::new)
}

pub(crate) fn resolve_approval_key(
    fixture_mode: bool,
    app_state_root: &Path,
) -> Result<Option<ApprovalKey>, String> {
    if fixture_mode {
        return fixture_approval_key(app_state_root).map(Some);
    }
    Ok(broker::resolve_runtime_bundle(app_state_root)?
        .approval()
        .map(ApprovalKey::new))
}

trait HumanPresence {
    fn require(
        &self,
        expectation: &ApprovalExpectation,
        plan_fingerprint: &str,
    ) -> Result<(), String>;
}

struct FixtureHumanPresence;

impl HumanPresence for FixtureHumanPresence {
    fn require(
        &self,
        _expectation: &ApprovalExpectation,
        _plan_fingerprint: &str,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct ControllingTerminalHumanPresence;

impl HumanPresence for ControllingTerminalHumanPresence {
    fn require(
        &self,
        expectation: &ApprovalExpectation,
        plan_fingerprint: &str,
    ) -> Result<(), String> {
        require_controlling_terminal_presence(expectation, plan_fingerprint)
    }
}

#[cfg(target_os = "macos")]
struct MacOsUserPresence;

#[cfg(target_os = "macos")]
impl HumanPresence for MacOsUserPresence {
    fn require(
        &self,
        expectation: &ApprovalExpectation,
        plan_fingerprint: &str,
    ) -> Result<(), String> {
        macos_user_presence::require(expectation, plan_fingerprint)
    }
}

#[cfg(unix)]
fn require_controlling_terminal_presence(
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
) -> Result<(), String> {
    let mut tty = open_controlling_terminal()?;
    render_human_approval_prompt(&mut tty, expectation, plan_fingerprint)?;
    tty.flush()
        .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    let response = read_human_presence_response(&mut tty)?;
    validate_human_presence_response(&response, plan_fingerprint)
}

#[cfg(unix)]
fn open_controlling_terminal() -> Result<std::fs::File, String> {
    if !(io::stdin().is_terminal() || io::stdout().is_terminal() || io::stderr().is_terminal()) {
        return Err(
            "interactive human approval requires a controlling terminal; --confirm and stdin are insufficient: standard streams are not terminals"
                .to_string(),
        );
    }

    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|error| {
            format!(
                "interactive human approval requires a controlling terminal; --confirm and stdin are insufficient: {error}"
            )
        })
}

pub(crate) fn require_live_apply_terminal(fixture_mode: bool) -> Result<(), String> {
    if fixture_mode {
        return Ok(());
    }

    require_controlling_terminal()
}

#[cfg(unix)]
fn require_controlling_terminal() -> Result<(), String> {
    let _tty = open_controlling_terminal()?;
    Ok(())
}

#[cfg(not(unix))]
fn require_controlling_terminal() -> Result<(), String> {
    Err(
        "interactive human approval is unsupported on this platform; live apply is blocked"
            .to_string(),
    )
}

#[cfg(not(unix))]
fn require_controlling_terminal_presence(
    _expectation: &ApprovalExpectation,
    _plan_fingerprint: &str,
) -> Result<(), String> {
    Err(
        "interactive human approval is unsupported on this platform; live apply is blocked"
            .to_string(),
    )
}

fn issue_human_approval_with(
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
    now_unix: i64,
    presence: &impl HumanPresence,
    load_key: impl FnOnce() -> Result<Option<ApprovalKey>, String>,
    random_suffix: impl FnOnce() -> Result<String, String>,
) -> Result<HumanApproval, String> {
    validate_human_approval_request(expectation, plan_fingerprint, reviewed_fingerprint)?;
    presence.require(expectation, plan_fingerprint)?;
    let key = load_key()?
        .ok_or_else(|| "approval key missing; run `unpin auth approval init`".to_string())?;
    let verifier_key = key.clone();
    let issuer = ApprovalIssuer::new(
        key,
        expectation.issuer.clone(),
        expectation.audience.clone(),
    )
    .map_err(|error| error.to_string())?;
    let random = random_suffix()?;
    let expires_at_unix = now_unix
        .checked_add(MAX_APPROVAL_LIFETIME_SECONDS.min(300))
        .ok_or_else(|| "approval expiry overflow".to_string())?;
    let receipt = issuer
        .issue(ApprovalReceiptClaims {
            version: 1,
            receipt_id: format!("human-approval-{random}"),
            nonce: format!("human-approval-nonce-{random}"),
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
            issued_at_unix: now_unix,
            expires_at_unix,
        })
        .map_err(|error| error.to_string())?;
    Ok(HumanApproval {
        receipt,
        verifier: ApprovalVerifier::new(verifier_key),
    })
}

#[cfg(target_os = "macos")]
mod macos_user_presence {
    use std::{
        ffi::{CString, c_char, c_void},
        ptr,
    };

    use zeroize::Zeroizing;

    use super::{ApprovalExpectation, random_suffix};

    type CFTypeRef = *const c_void;
    type CFDataRef = CFTypeRef;
    type CFDictionaryRef = CFTypeRef;
    type CFAllocatorRef = CFTypeRef;
    type CFIndex = isize;
    type OSStatus = i32;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_SEC_ACCESS_CONTROL_USER_PRESENCE: u32 = 1;
    const ERR_SEC_SUCCESS: OSStatus = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFBooleanTrue: CFTypeRef;
        fn CFStringCreateWithCString(
            allocator: CFAllocatorRef,
            value: *const c_char,
            encoding: u32,
        ) -> CFTypeRef;
        fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
        fn CFDataGetBytePtr(data: CFDataRef) -> *const u8;
        fn CFDataGetLength(data: CFDataRef) -> CFIndex;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            count: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
        fn CFRelease(value: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecClass: CFTypeRef;
        static kSecClassGenericPassword: CFTypeRef;
        static kSecAttrService: CFTypeRef;
        static kSecAttrAccount: CFTypeRef;
        static kSecAttrAccessControl: CFTypeRef;
        static kSecValueData: CFTypeRef;
        static kSecReturnData: CFTypeRef;
        static kSecUseOperationPrompt: CFTypeRef;
        static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFTypeRef;
        fn SecAccessControlCreateWithFlags(
            allocator: CFAllocatorRef,
            protection: CFTypeRef,
            flags: u32,
            error: *mut CFTypeRef,
        ) -> CFTypeRef;
        fn SecItemAdd(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> OSStatus;
        fn SecItemDelete(query: CFDictionaryRef) -> OSStatus;
    }

    struct CfRef(CFTypeRef);

    impl CfRef {
        fn new(value: CFTypeRef) -> Result<Self, String> {
            (!value.is_null())
                .then_some(Self(value))
                .ok_or_else(|| "desktop user presence could not be prepared".to_string())
        }

        const fn as_raw(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for CfRef {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `CfRef` owns values returned from CoreFoundation or
                // Security create/copy APIs and releases each exactly once.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    pub(super) fn require(
        expectation: &ApprovalExpectation,
        plan_fingerprint: &str,
    ) -> Result<(), String> {
        let mut proof = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut *proof)
            .map_err(|_| "desktop user presence could not be prepared".to_string())?;
        let account = format!("desktop-presence-{}", random_suffix()?);
        let prompt = format!(
            "Approve Unpin desktop operation {}",
            plan_fingerprint.chars().take(12).collect::<String>()
        );
        let service = string("dev.unpin.desktop-user-presence-v1")?;
        let account = string(&account)?;
        let prompt = string(&prompt)?;
        let proof_data = data(&proof[..])?;
        let access_control = access_control()?;

        let add_query = dictionary(&[
            (
                security_constant("class"),
                security_constant("generic-password"),
            ),
            (security_constant("service"), service.as_raw()),
            (security_constant("account"), account.as_raw()),
            (security_constant("access-control"), access_control.as_raw()),
            (security_constant("value-data"), proof_data.as_raw()),
        ])?;
        let add_status = unsafe {
            // SAFETY: the query is a valid CoreFoundation dictionary whose
            // entries remain alive for the duration of the Security call.
            SecItemAdd(add_query.as_raw(), ptr::null_mut())
        };
        if add_status != ERR_SEC_SUCCESS {
            return Err("desktop user presence could not be prepared".to_string());
        }

        let delete_query = dictionary(&[
            (
                security_constant("class"),
                security_constant("generic-password"),
            ),
            (security_constant("service"), service.as_raw()),
            (security_constant("account"), account.as_raw()),
        ])?;
        let copy_query = dictionary(&[
            (
                security_constant("class"),
                security_constant("generic-password"),
            ),
            (security_constant("service"), service.as_raw()),
            (security_constant("account"), account.as_raw()),
            (security_constant("return-data"), unsafe { kCFBooleanTrue }),
            (security_constant("operation-prompt"), prompt.as_raw()),
        ])?;
        let mut result = ptr::null();
        let copy_status = unsafe {
            // SAFETY: the query and output pointer are valid for this
            // synchronous Security call.
            SecItemCopyMatching(copy_query.as_raw(), &mut result)
        };
        let matches = if copy_status == ERR_SEC_SUCCESS && !result.is_null() {
            let result = CfRef(result);
            data_matches(result.as_raw(), &proof[..])
        } else {
            false
        };
        let delete_status = unsafe {
            // SAFETY: this removes only the unique item just created above.
            SecItemDelete(delete_query.as_raw())
        };
        if delete_status != ERR_SEC_SUCCESS {
            return Err("desktop user presence cleanup failed".to_string());
        }
        if matches {
            Ok(())
        } else {
            let _ = expectation;
            Err("desktop user presence was not approved".to_string())
        }
    }

    fn string(value: &str) -> Result<CfRef, String> {
        let value = CString::new(value)
            .map_err(|_| "desktop user presence could not be prepared".to_string())?;
        let raw = unsafe {
            // SAFETY: CString supplies a NUL-terminated UTF-8 buffer for the
            // duration of the CoreFoundation call.
            CFStringCreateWithCString(
                k_cf_allocator_default(),
                value.as_ptr(),
                K_CF_STRING_ENCODING_UTF8,
            )
        };
        CfRef::new(raw)
    }

    fn data(value: &[u8]) -> Result<CfRef, String> {
        let length = CFIndex::try_from(value.len())
            .map_err(|_| "desktop user presence could not be prepared".to_string())?;
        let raw = unsafe {
            // SAFETY: the slice remains valid while CoreFoundation copies it.
            CFDataCreate(k_cf_allocator_default(), value.as_ptr(), length)
        };
        CfRef::new(raw)
    }

    fn access_control() -> Result<CfRef, String> {
        let mut error = ptr::null();
        let raw = unsafe {
            // SAFETY: Security returns a retained access-control object or a
            // retained error object, both of which are released below.
            SecAccessControlCreateWithFlags(
                k_cf_allocator_default(),
                k_sec_accessible_when_unlocked_this_device_only(),
                K_SEC_ACCESS_CONTROL_USER_PRESENCE,
                &mut error,
            )
        };
        if !error.is_null() {
            // SAFETY: Security transferred ownership of the returned error.
            unsafe { CFRelease(error) };
        }
        CfRef::new(raw)
    }

    fn dictionary(entries: &[(CFTypeRef, CFTypeRef)]) -> Result<CfRef, String> {
        let keys = entries.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let values = entries.iter().map(|(_, value)| *value).collect::<Vec<_>>();
        let count = CFIndex::try_from(entries.len())
            .map_err(|_| "desktop user presence could not be prepared".to_string())?;
        let raw = unsafe {
            // SAFETY: all keys and values are valid CF objects retained by the
            // surrounding function for the duration of the Security call.
            CFDictionaryCreate(
                k_cf_allocator_default(),
                keys.as_ptr(),
                values.as_ptr(),
                count,
                ptr::null(),
                ptr::null(),
            )
        };
        CfRef::new(raw)
    }

    fn data_matches(data: CFDataRef, expected: &[u8]) -> bool {
        let length = unsafe {
            // SAFETY: Security returned a CFData value for `kSecReturnData`.
            CFDataGetLength(data)
        };
        let Ok(length) = usize::try_from(length) else {
            return false;
        };
        if length != expected.len() {
            return false;
        }
        let bytes = unsafe {
            // SAFETY: CFData owns an immutable buffer of `length` bytes.
            let pointer = CFDataGetBytePtr(data);
            if pointer.is_null() {
                return false;
            }
            std::slice::from_raw_parts(pointer, length)
        };
        bytes == expected
    }

    fn k_cf_allocator_default() -> CFAllocatorRef {
        unsafe {
            // SAFETY: CoreFoundation exposes this process-global constant.
            kCFAllocatorDefault
        }
    }

    fn k_sec_accessible_when_unlocked_this_device_only() -> CFTypeRef {
        unsafe {
            // SAFETY: Security exposes this process-global constant.
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    fn security_constant(name: &str) -> CFTypeRef {
        unsafe {
            // SAFETY: each selected symbol is a process-global Security
            // constant; callers use only the fixed spellings below.
            match name {
                "class" => kSecClass,
                "generic-password" => kSecClassGenericPassword,
                "service" => kSecAttrService,
                "account" => kSecAttrAccount,
                "access-control" => kSecAttrAccessControl,
                "value-data" => kSecValueData,
                "return-data" => kSecReturnData,
                "operation-prompt" => kSecUseOperationPrompt,
                _ => unreachable!("fixed Security constant"),
            }
        }
    }
}

fn validate_human_approval_request(
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
    reviewed_fingerprint: Option<&str>,
) -> Result<(), String> {
    if reviewed_fingerprint != Some(plan_fingerprint) {
        return Err("plan-fingerprint-mismatch".to_string());
    }
    if plan_fingerprint != expectation.effect_graph_digest {
        return Err("plan fingerprint does not bind approval expectation".to_string());
    }
    validate_prompt_value("plan fingerprint", plan_fingerprint)?;
    for (label, value) in [
        ("operation id", expectation.operation_id.as_str()),
        ("operation kind", expectation.operation_kind.as_str()),
        ("repository scope", expectation.repository_key.as_str()),
        ("workspace scope", expectation.workspace_key.as_str()),
    ] {
        validate_prompt_value(label, value)?;
    }
    if let Some(session_id) = expectation.session_id.as_deref() {
        validate_prompt_value("session scope", session_id)?;
    }
    if let Some(profile_digest) = expectation.profile_digest.as_deref() {
        validate_prompt_value("profile scope", profile_digest)?;
    }
    if expectation.resources.is_empty() {
        return Err("human approval expectation has no resources".to_string());
    }
    for resource in &expectation.resources {
        validate_prompt_value("resource id", &resource.resource_id)?;
        if let Some(fingerprint) = resource.pre_state_fingerprint.as_deref() {
            validate_prompt_value("resource fingerprint", fingerprint)?;
        }
    }
    Ok(())
}

fn validate_prompt_value(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(format!("invalid human approval {label}"));
    }
    Ok(())
}

#[cfg(any(unix, test))]
fn approval_challenge(plan_fingerprint: &str) -> String {
    format!(
        "approve {}",
        plan_fingerprint.chars().take(12).collect::<String>()
    )
}

#[cfg(any(unix, test))]
fn render_human_approval_prompt(
    output: &mut impl Write,
    expectation: &ApprovalExpectation,
    plan_fingerprint: &str,
) -> Result<(), String> {
    writeln!(output, "Unpin human approval required")
        .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    writeln!(
        output,
        "operation: {} ({})",
        expectation.operation_kind, expectation.operation_id
    )
    .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    writeln!(output, "fingerprint: {plan_fingerprint}")
        .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    writeln!(
        output,
        "scope: repository={} workspace={} session={} profile={}",
        expectation.repository_key,
        expectation.workspace_key,
        expectation.session_id.as_deref().unwrap_or("none"),
        expectation.profile_digest.as_deref().unwrap_or("none")
    )
    .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    writeln!(output, "resources:")
        .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    for resource in &expectation.resources {
        writeln!(
            output,
            "  - {} pre-state={}",
            resource.resource_id,
            resource.pre_state_fingerprint.as_deref().unwrap_or("none")
        )
        .map_err(|error| format!("human approval prompt could not be displayed: {error}"))?;
    }
    write!(
        output,
        "Type `{}` exactly to approve; any other response cancels: ",
        approval_challenge(plan_fingerprint)
    )
    .map_err(|error| format!("human approval prompt could not be displayed: {error}"))
}

#[cfg(unix)]
fn read_human_presence_response(input: &mut impl Read) -> Result<String, String> {
    const MAX_RESPONSE_BYTES: usize = 256;
    let mut response = Vec::with_capacity(32);
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if response.is_empty() => return Err("human approval cancelled".to_string()),
            Ok(0) => break,
            Ok(_) if matches!(byte[0], b'\n' | b'\r') => break,
            Ok(_) if response.len() == MAX_RESPONSE_BYTES => {
                return Err("human approval response is too long".to_string());
            }
            Ok(_) => response.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                return Err("human approval cancelled".to_string());
            }
            Err(error) => {
                return Err(format!(
                    "human approval response could not be read: {error}"
                ));
            }
        }
    }
    String::from_utf8(response).map_err(|_| "human approval response is invalid".to_string())
}

#[cfg(any(unix, test))]
fn validate_human_presence_response(response: &str, plan_fingerprint: &str) -> Result<(), String> {
    if response == approval_challenge(plan_fingerprint) {
        Ok(())
    } else if response.is_empty() {
        Err("human approval cancelled".to_string())
    } else {
        Err("human approval rejected: response did not match challenge".to_string())
    }
}

fn random_suffix() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn load_approval_key(store: &impl SecretStore) -> Result<Option<ApprovalKey>, String> {
    let Some(secret) = store.get(KEYCHAIN_SERVICE, APPROVAL_ACCOUNT)? else {
        return Ok(None);
    };
    let secret = Zeroizing::new(secret);
    let key = ApprovalKey::from_bytes(&secret);
    key.map(Some)
        .map_err(|error| format!("stored approval key is invalid: {error}"))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::credentials::test_support::FakeSecretStore;

    struct UnavailableHumanPresence;

    impl HumanPresence for UnavailableHumanPresence {
        fn require(
            &self,
            _expectation: &ApprovalExpectation,
            _plan_fingerprint: &str,
        ) -> Result<(), String> {
            Err("interactive human approval requires a controlling terminal".to_string())
        }
    }

    struct ResponseHumanPresence(&'static str);

    impl HumanPresence for ResponseHumanPresence {
        fn require(
            &self,
            _expectation: &ApprovalExpectation,
            plan_fingerprint: &str,
        ) -> Result<(), String> {
            validate_human_presence_response(self.0, plan_fingerprint)
        }
    }

    fn approval_expectation() -> ApprovalExpectation {
        ApprovalExpectation {
            issuer: "unpin-cli-human".to_string(),
            audience: "unpin-core-control".to_string(),
            operation_id: "profile-policy-reviewed-plan".to_string(),
            operation_kind: "profile-policy".to_string(),
            effect_graph_digest: "71".repeat(32),
            repository_key: "repository-key".to_string(),
            workspace_key: "workspace-key".to_string(),
            session_id: Some("session-id".to_string()),
            profile_digest: Some("42".repeat(32)),
            resources: vec![unpin_core::approval::ApprovalResourceBinding {
                resource_id: "profile-policy-resource".to_string(),
                pre_state_fingerprint: Some("24".repeat(32)),
            }],
        }
    }

    #[test]
    fn noninteractive_confirm_cannot_load_key_or_mint_approval() {
        let expectation = approval_expectation();
        let key_loaded = Cell::new(false);
        let error = match issue_human_approval_with(
            &expectation,
            &expectation.effect_graph_digest,
            Some(&expectation.effect_graph_digest),
            2_000_000_000,
            &UnavailableHumanPresence,
            || {
                key_loaded.set(true);
                Ok(Some(ApprovalKey::new([0x24; 32])))
            },
            || Ok("unreachable".to_string()),
        ) {
            Ok(_) => panic!("noninteractive approval must fail closed"),
            Err(error) => error,
        };
        assert!(error.contains("controlling terminal"));
        assert!(!key_loaded.get(), "signing key must remain unopened");
    }

    #[test]
    fn cancelled_and_wrong_presence_responses_fail_before_key_access() {
        let expectation = approval_expectation();
        for response in ["", "yes", "approve wrong-plan"] {
            let key_loaded = Cell::new(false);
            let result = issue_human_approval_with(
                &expectation,
                &expectation.effect_graph_digest,
                Some(&expectation.effect_graph_digest),
                2_000_000_000,
                &ResponseHumanPresence(response),
                || {
                    key_loaded.set(true);
                    Ok(Some(ApprovalKey::new([0x24; 32])))
                },
                || Ok("unreachable".to_string()),
            );
            assert!(result.is_err(), "response {response:?} must fail");
            assert!(!key_loaded.get(), "signing key must remain unopened");
        }
    }

    #[test]
    fn desktop_approval_requires_presence_before_the_signing_key_is_opened() {
        let expectation = approval_expectation();
        let key_loaded = Cell::new(false);
        let error = match issue_human_approval_with(
            &expectation,
            &expectation.effect_graph_digest,
            Some(&expectation.effect_graph_digest),
            2_000_000_000,
            &UnavailableHumanPresence,
            || {
                key_loaded.set(true);
                Ok(Some(ApprovalKey::new([0x24; 32])))
            },
            || Ok("unreachable".to_string()),
        ) {
            Ok(_) => panic!("desktop approval must fail closed without OS presence"),
            Err(error) => error,
        };
        assert!(error.contains("controlling terminal"));
        assert!(!key_loaded.get(), "signing key must remain unopened");
    }

    #[test]
    fn reviewed_fingerprint_mismatch_fails_before_presence_or_key_access() {
        let expectation = approval_expectation();
        let key_loaded = Cell::new(false);
        let error = match issue_human_approval_with(
            &expectation,
            &expectation.effect_graph_digest,
            Some(&"19".repeat(32)),
            2_000_000_000,
            &FixtureHumanPresence,
            || {
                key_loaded.set(true);
                Ok(Some(ApprovalKey::new([0x24; 32])))
            },
            || Ok("unreachable".to_string()),
        ) {
            Ok(_) => panic!("mismatched review must fail"),
            Err(error) => error,
        };
        assert_eq!(error, "plan-fingerprint-mismatch");
        assert!(!key_loaded.get(), "signing key must remain unopened");
    }

    #[test]
    fn reviewed_fingerprint_must_bind_exact_approval_expectation() {
        let expectation = approval_expectation();
        let unrelated_fingerprint = "19".repeat(32);
        let key_loaded = Cell::new(false);
        let error = match issue_human_approval_with(
            &expectation,
            &unrelated_fingerprint,
            Some(&unrelated_fingerprint),
            2_000_000_000,
            &FixtureHumanPresence,
            || {
                key_loaded.set(true);
                Ok(Some(ApprovalKey::new([0x24; 32])))
            },
            || Ok("unreachable".to_string()),
        ) {
            Ok(_) => panic!("unbound reviewed fingerprint must fail"),
            Err(error) => error,
        };
        assert!(error.contains("does not bind approval expectation"));
        assert!(!key_loaded.get(), "signing key must remain unopened");
    }

    #[test]
    fn fixture_presence_issues_short_lived_exactly_bound_approval() {
        let expectation = approval_expectation();
        let now_unix = 2_000_000_000;
        let approval = issue_human_approval_with(
            &expectation,
            &expectation.effect_graph_digest,
            Some(&expectation.effect_graph_digest),
            now_unix,
            &FixtureHumanPresence,
            || Ok(Some(ApprovalKey::new([0x24; 32]))),
            || Ok("fixture-random".to_string()),
        )
        .expect("fixture approval");
        let verified = approval
            .verifier()
            .verify(approval.receipt(), &expectation, now_unix)
            .expect("exact approval binding");
        assert_eq!(verified.operation_id(), expectation.operation_id);
        assert_eq!(
            approval.receipt().claims.expires_at_unix - approval.receipt().claims.issued_at_unix,
            300
        );
    }

    #[cfg(unix)]
    #[test]
    fn operator_receipt_descriptor_is_external_and_single_use() {
        use std::{
            io::{Seek, SeekFrom},
            os::fd::IntoRawFd,
        };

        let temp = tempfile::tempdir().expect("operator fixture tempdir");
        let app_state_root = std::fs::canonicalize(temp.path()).expect("canonical tempdir");
        let expectation = approval_expectation();
        let plan_fingerprint = expectation.effect_graph_digest.clone();
        let operator_key = fixture_approval_key(&app_state_root).expect("fixture approval key");
        let approval = issue_human_approval_with(
            &expectation,
            &plan_fingerprint,
            Some(&plan_fingerprint),
            2_000_000_000,
            &FixtureHumanPresence,
            || Ok(Some(operator_key.clone())),
            || Ok("operator-receipt".to_string()),
        )
        .expect("operator receipt");
        let receipt_bytes = serde_json::to_vec(approval.receipt()).expect("receipt JSON");

        let descriptor = || {
            let mut file = tempfile::tempfile().expect("receipt descriptor");
            file.write_all(&receipt_bytes).expect("receipt bytes");
            file.seek(SeekFrom::Start(0)).expect("receipt seek");
            file.into_raw_fd()
        };

        assert_eq!(
            read_operator_receipt(0).expect_err("stdio must be rejected"),
            "approval-principal-unverified"
        );
        assert!(
            authorize_operator_descriptor(
                true,
                &app_state_root,
                &expectation,
                &plan_fingerprint,
                Some(&plan_fingerprint),
                "operator-descriptor-test",
                2_000_000_000,
                descriptor(),
            )
            .is_ok()
        );

        let mut replay_claims = approval.receipt().claims.clone();
        replay_claims.receipt_id = "operator-replay".to_string();
        replay_claims.operation_id = "operator-replay-operation".to_string();
        let replay_receipt = ApprovalIssuer::new(
            operator_key,
            unpin_core::approval::CONTROL_APPROVAL_ISSUER,
            unpin_core::approval::CONTROL_APPROVAL_AUDIENCE,
        )
        .expect("replay issuer")
        .issue(replay_claims)
        .expect("replay receipt");
        let mut replay_expectation = expectation.clone();
        replay_expectation.operation_id = "operator-replay-operation".to_string();
        let replay_bytes = serde_json::to_vec(&replay_receipt).expect("replay receipt JSON");
        let mut replay_file = tempfile::tempfile().expect("replay descriptor");
        replay_file
            .write_all(&replay_bytes)
            .expect("replay receipt bytes");
        replay_file.seek(SeekFrom::Start(0)).expect("replay seek");
        assert_eq!(
            authorize_operator_descriptor(
                true,
                &app_state_root,
                &replay_expectation,
                &plan_fingerprint,
                Some(&plan_fingerprint),
                "operator-descriptor-test",
                2_000_000_000,
                replay_file.into_raw_fd(),
            )
            .expect_err("receipt nonce must not cross operations"),
            "approval-principal-unverified"
        );

        let mut oversized = tempfile::tempfile().expect("oversized descriptor");
        oversized
            .write_all(&vec![b' '; 128 * 1024 + 1])
            .expect("oversized receipt bytes");
        oversized.seek(SeekFrom::Start(0)).expect("oversized seek");
        assert_eq!(
            read_operator_receipt(oversized.into_raw_fd())
                .expect_err("oversized receipts must be rejected"),
            "approval-principal-unverified"
        );
    }

    #[test]
    fn human_prompt_shows_operation_fingerprint_scope_and_resources() {
        let expectation = approval_expectation();
        let mut output = Vec::new();
        render_human_approval_prompt(&mut output, &expectation, &expectation.effect_graph_digest)
            .expect("render approval prompt");
        let prompt = String::from_utf8(output).expect("UTF-8 prompt");
        assert!(prompt.contains("operation: profile-policy (profile-policy-reviewed-plan)"));
        assert!(prompt.contains(&format!("fingerprint: {}", expectation.effect_graph_digest)));
        assert!(prompt.contains("repository=repository-key workspace=workspace-key"));
        assert!(prompt.contains("profile-policy-resource"));
        assert!(prompt.contains(&approval_challenge(&expectation.effect_graph_digest)));
    }

    #[test]
    fn initializes_separate_approval_key_and_reports_id() {
        let store = FakeSecretStore::default();
        let created = initialize_approval_key_with(&store, |bytes| {
            bytes.fill(0x33);
            Ok(())
        })
        .expect("initialize approval key");
        let key_id = ApprovalKey::new([0x33; 32]).key_id();
        assert_eq!(
            created,
            ApprovalKeyInitialization::Created {
                key_id: key_id.clone()
            }
        );
        assert_eq!(
            approval_key_status(&store).unwrap(),
            ApprovalKeyState::Ready { key_id }
        );
    }
}
