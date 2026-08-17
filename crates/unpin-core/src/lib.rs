pub mod agent_plugins;
pub mod approval;
pub mod bridges;
pub mod capabilities;
pub mod catalog;
mod clock;
pub mod config;
pub mod control;
pub mod control_operation;
pub mod discovery;
pub mod fixture;
mod fs_support;
pub mod gateway;
pub mod groups;
pub mod hooks;
mod ids;
pub mod mcp;
pub mod mutation;
pub mod profiles;
pub mod provider_reach;
pub mod providers;
pub mod sessions;
pub mod snapshots;
pub mod state;
pub mod transitions;
pub mod update;
pub mod update_service;
pub mod workflows;

mod pi_packages;
mod toml_syntax;

pub(crate) fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Return the lower-case SHA-256 digest for a byte sequence.
pub fn sha256_digest(bytes: &[u8]) -> String {
    use sha2::Digest;

    encode_lower_hex(&sha2::Sha256::digest(bytes))
}

pub(crate) fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(crate) fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'
                if byte != b'.' || index != 0 =>
            {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

pub const PLANNED_COMMANDS: &[&str] = &[
    "providers",
    "doctor",
    "snapshot",
    "list",
    "toggle",
    "restore",
    "session",
    "mcp",
    "tui",
];

pub fn reserved_command_message(command: &str) -> String {
    format!(
        "unpin {command} is reserved for a future parity slice; no provider files were read or written."
    )
}
