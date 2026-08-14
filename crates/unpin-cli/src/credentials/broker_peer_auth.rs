use std::{
    ffi::{CString, c_char, c_int, c_void},
    mem,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr,
};

type CFTypeRef = *const c_void;
type CFDataRef = CFTypeRef;
type CFDictionaryRef = CFTypeRef;
type CFStringRef = CFTypeRef;
type CFIndex = isize;
type OSStatus = i32;
type SockLen = u32;

const SOL_LOCAL: c_int = 0;
const LOCAL_PEERTOKEN: c_int = 6;
const ERR_SEC_SUCCESS: OSStatus = 0;
const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

#[derive(Clone, Copy)]
#[allow(dead_code)] // Each companion binary authenticates only the opposite peer role.
pub(super) enum PeerKind {
    Broker,
    Client,
}

impl PeerKind {
    const fn socket_error(self) -> &'static str {
        match self {
            Self::Broker => "Unpin could not authenticate the credential broker socket",
            Self::Client => "credential broker could not authenticate client socket",
        }
    }

    const fn attributes_description(self) -> &'static str {
        match self {
            Self::Broker => "peer attributes",
            Self::Client => "client attributes",
        }
    }

    const fn requirement_description(self) -> &'static str {
        match self {
            Self::Broker => "peer requirement",
            Self::Client => "client requirement",
        }
    }

    const fn requirement_error(self) -> &'static str {
        match self {
            Self::Broker => "credential broker requirement is invalid",
            Self::Client => "credential broker client requirement is invalid",
        }
    }

    const fn identity_error(self) -> &'static str {
        match self {
            Self::Broker => "credential broker identity is unavailable",
            Self::Client => "credential broker client identity is unavailable",
        }
    }

    const fn identity_description(self) -> &'static str {
        match self {
            Self::Broker => "peer identity",
            Self::Client => "client identity",
        }
    }

    const fn signature_error(self) -> &'static str {
        match self {
            Self::Broker => "Unpin rejected the credential broker code signature",
            Self::Client => "credential broker rejected client code signature",
        }
    }
}

#[repr(C)]
struct AuditToken {
    values: [u32; 8],
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: CFIndex) -> CFDataRef;
    fn CFDictionaryCreate(
        allocator: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        count: CFIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CFDictionaryRef;
    fn CFStringCreateWithCString(
        allocator: CFTypeRef,
        value: *const c_char,
        encoding: u32,
    ) -> CFStringRef;
    fn CFRelease(value: CFTypeRef);
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributeAudit: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(
        host: CFTypeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
}

unsafe extern "C" {
    fn getsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut c_void,
        option_length: *mut SockLen,
    ) -> c_int;
}

struct CfRef(CFTypeRef);

impl CfRef {
    fn new(value: CFTypeRef, description: &str) -> Result<Self, String> {
        (!value.is_null())
            .then_some(Self(value))
            .ok_or_else(|| format!("credential broker {description} could not be prepared"))
    }

    const fn as_raw(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for CfRef {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper owns one create/copy result and releases it once.
            unsafe { CFRelease(self.0) };
        }
    }
}

pub(super) fn authorize(
    stream: &UnixStream,
    requirement: &str,
    peer: PeerKind,
) -> Result<(), String> {
    let mut token = AuditToken { values: [0; 8] };
    let mut token_length =
        SockLen::try_from(mem::size_of::<AuditToken>()).expect("audit token size fits socklen_t");
    let socket_status = unsafe {
        // SAFETY: the socket descriptor is live and the token buffer and length are valid.
        getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            (&raw mut token).cast(),
            &raw mut token_length,
        )
    };
    if socket_status != 0 || usize::try_from(token_length) != Ok(mem::size_of::<AuditToken>()) {
        return Err(peer.socket_error().to_string());
    }

    let token_data = CfRef::new(
        unsafe {
            // SAFETY: CoreFoundation copies the fixed audit token bytes synchronously.
            CFDataCreate(
                ptr::null(),
                (&raw const token).cast(),
                CFIndex::try_from(mem::size_of::<AuditToken>())
                    .expect("audit token size fits CFIndex"),
            )
        },
        "audit token",
    )?;
    let key = unsafe { kSecGuestAttributeAudit };
    let value = token_data.as_raw();
    let attributes = CfRef::new(
        unsafe {
            // SAFETY: the key and value remain alive through the synchronous lookup.
            CFDictionaryCreate(
                ptr::null(),
                &raw const key,
                &raw const value,
                1,
                ptr::null(),
                ptr::null(),
            )
        },
        peer.attributes_description(),
    )?;
    let requirement_text = CString::new(requirement).map_err(|_| peer.requirement_error())?;
    let requirement_text = CfRef::new(
        unsafe {
            // SAFETY: CString is valid UTF-8 input for the synchronous CoreFoundation call.
            CFStringCreateWithCString(
                ptr::null(),
                requirement_text.as_ptr(),
                K_CF_STRING_ENCODING_UTF8,
            )
        },
        peer.requirement_description(),
    )?;
    let mut compiled_requirement = ptr::null();
    let requirement_status = unsafe {
        // SAFETY: input text and output pointer are valid for the Security call.
        SecRequirementCreateWithString(requirement_text.as_raw(), 0, &raw mut compiled_requirement)
    };
    if requirement_status != ERR_SEC_SUCCESS {
        return Err(peer.requirement_error().to_string());
    }
    let compiled_requirement = CfRef::new(compiled_requirement, peer.requirement_description())?;
    let mut peer_code = ptr::null();
    let guest_status = unsafe {
        // SAFETY: the audit-token attribute identifies the connected peer without a PID race.
        SecCodeCopyGuestWithAttributes(ptr::null(), attributes.as_raw(), 0, &raw mut peer_code)
    };
    if guest_status != ERR_SEC_SUCCESS {
        return Err(peer.identity_error().to_string());
    }
    let peer_code = CfRef::new(peer_code, peer.identity_description())?;
    let validity_status = unsafe {
        // SAFETY: the dynamic code and compiled requirement are live Security objects.
        SecCodeCheckValidity(peer_code.as_raw(), 0, compiled_requirement.as_raw())
    };
    if validity_status != ERR_SEC_SUCCESS {
        return Err(peer.signature_error().to_string());
    }
    Ok(())
}
