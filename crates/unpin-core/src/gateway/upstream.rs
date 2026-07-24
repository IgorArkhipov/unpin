use std::{
    collections::BTreeMap,
    env, fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::{
    fd::AsRawFd,
    unix::ffi::OsStrExt,
    unix::fs::{MetadataExt, PermissionsExt},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    catalog::{CapabilityId, stable_hash},
    providers::ProviderId,
};

const MAX_SERVER_ID_BYTES: usize = 128;
const MAX_ENDPOINT_BYTES: usize = 4_096;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4_096;
const MAX_REGISTRATION_ID_BYTES: usize = 256;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1024;
const MAX_EXECUTION_CHAIN_DEPTH: usize = 8;
const MAX_SHEBANG_BYTES: usize = 4_096;
const STDIO_ENVIRONMENT_KEYS: &[&str] = &["HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamTransportKind {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamIdentity {
    pub server_id: String,
    pub transport: UpstreamTransportKind,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_digest: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    pub digest: String,
}

/// Open, verified stdio launch material retained for child lifetime. Runtime
/// executes reviewed snapshots, using anonymous descriptors where supported.
pub struct PreparedStdioExecution {
    program: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    files: Vec<fs::File>,
    inherited_file_indexes: Vec<usize>,
    cleanup_paths: Vec<PathBuf>,
}

impl Drop for PreparedStdioExecution {
    fn drop(&mut self) {
        for path in &self.cleanup_paths {
            let _ = fs::remove_file(path);
        }
    }
}

impl fmt::Debug for PreparedStdioExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedStdioExecution")
            .field("program", &self.program)
            .field("arguments", &self.arguments)
            .field("environment_keys", &self.environment.keys())
            .field("open_file_count", &self.files.len())
            .finish()
    }
}

impl PreparedStdioExecution {
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    #[must_use]
    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    #[must_use]
    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[cfg(unix)]
    #[must_use]
    pub fn inherited_file_descriptors(&self) -> Vec<std::os::fd::RawFd> {
        if cfg!(any(target_os = "linux", target_os = "android")) {
            self.inherited_file_indexes
                .iter()
                .filter_map(|index| self.files.get(*index))
                .map(AsRawFd::as_raw_fd)
                .collect()
        } else {
            Vec::new()
        }
    }
}

impl UpstreamIdentity {
    pub fn stdio(
        server_id: impl Into<String>,
        executable: impl AsRef<Path>,
        arguments: Vec<String>,
    ) -> Result<Self, UpstreamValidationError> {
        Self::stdio_with_environment(
            server_id,
            executable,
            arguments,
            reviewed_stdio_environment()?,
        )
    }

    pub fn stdio_with_environment(
        server_id: impl Into<String>,
        executable: impl AsRef<Path>,
        arguments: Vec<String>,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, UpstreamValidationError> {
        let server_id = server_id.into();
        validate_identifier("upstream server id", &server_id, MAX_SERVER_ID_BYTES)?;
        validate_arguments(&arguments)?;
        validate_stdio_environment(&environment)?;
        let resolved = resolve_stdio_execution(executable.as_ref(), &arguments, &environment)?;
        let endpoint = resolved.endpoint.clone();
        let executable_digest = resolved.digest()?;
        let digest = identity_digest(
            &server_id,
            UpstreamTransportKind::Stdio,
            &endpoint,
            &arguments,
            None,
            Some(&executable_digest),
            &environment,
        )?;
        Ok(Self {
            server_id,
            transport: UpstreamTransportKind::Stdio,
            endpoint,
            arguments,
            origin: None,
            executable_digest: Some(executable_digest),
            environment,
            digest,
        })
    }

    pub fn streamable_http(
        server_id: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self, UpstreamValidationError> {
        let server_id = server_id.into();
        let endpoint = endpoint.into();
        validate_identifier("upstream server id", &server_id, MAX_SERVER_ID_BYTES)?;
        let origin = http_origin(&endpoint)?;
        let digest = identity_digest(
            &server_id,
            UpstreamTransportKind::StreamableHttp,
            &endpoint,
            &[],
            Some(&origin),
            None,
            &BTreeMap::new(),
        )?;
        Ok(Self {
            server_id,
            transport: UpstreamTransportKind::StreamableHttp,
            endpoint,
            arguments: Vec::new(),
            origin: Some(origin),
            executable_digest: None,
            environment: BTreeMap::new(),
            digest,
        })
    }

    pub fn prepare_stdio_execution(
        &self,
    ) -> Result<PreparedStdioExecution, UpstreamValidationError> {
        #[cfg(not(unix))]
        {
            return Err(UpstreamValidationError::UnsupportedStdioExecution);
        }
        #[cfg(unix)]
        {
            validate_identifier("upstream server id", &self.server_id, MAX_SERVER_ID_BYTES)?;
            validate_arguments(&self.arguments)?;
            validate_stdio_environment(&self.environment)?;
            if self.transport != UpstreamTransportKind::Stdio
                || self.origin.is_some()
                || self.executable_digest.is_none()
                || self.endpoint.is_empty()
                || self.endpoint.len() > MAX_ENDPOINT_BYTES
                || !Path::new(&self.endpoint).is_absolute()
            {
                return Err(UpstreamValidationError::IdentityMismatch);
            }
            let resolved = resolve_stdio_execution(
                Path::new(&self.endpoint),
                &self.arguments,
                &self.environment,
            )?;
            if resolved.endpoint != self.endpoint
                || self.executable_digest.as_deref() != Some(resolved.digest()?.as_str())
            {
                return Err(UpstreamValidationError::IdentityMismatch);
            }
            let actual = identity_digest(
                &self.server_id,
                self.transport,
                &self.endpoint,
                &self.arguments,
                self.origin.as_deref(),
                self.executable_digest.as_deref(),
                &self.environment,
            )?;
            if actual != self.digest {
                return Err(UpstreamValidationError::IdentityMismatch);
            }
            resolved.into_prepared(self.environment.clone())
        }
    }

    pub fn verify(&self) -> Result<(), UpstreamValidationError> {
        validate_identifier("upstream server id", &self.server_id, MAX_SERVER_ID_BYTES)?;
        validate_arguments(&self.arguments)?;
        match self.transport {
            UpstreamTransportKind::Stdio => {
                self.prepare_stdio_execution()?;
                return Ok(());
            }
            UpstreamTransportKind::StreamableHttp => {
                let expected_origin = http_origin(&self.endpoint)?;
                if !self.arguments.is_empty()
                    || self.executable_digest.is_some()
                    || !self.environment.is_empty()
                    || self.origin.as_deref() != Some(expected_origin.as_str())
                {
                    return Err(UpstreamValidationError::IdentityMismatch);
                }
            }
        }
        let actual = identity_digest(
            &self.server_id,
            self.transport,
            &self.endpoint,
            &self.arguments,
            self.origin.as_deref(),
            self.executable_digest.as_deref(),
            &self.environment,
        )?;
        if actual == self.digest {
            Ok(())
        } else {
            Err(UpstreamValidationError::IdentityMismatch)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialBinding {
    pub key_id: String,
    pub intended_identity_digest: String,
}

impl CredentialBinding {
    pub fn new(
        key_id: impl Into<String>,
        identity: &UpstreamIdentity,
    ) -> Result<Self, UpstreamValidationError> {
        let key_id = key_id.into();
        validate_identifier("credential key id", &key_id, 256)?;
        identity.verify()?;
        Ok(Self {
            key_id,
            intended_identity_digest: identity.digest.clone(),
        })
    }

    pub fn verify_for(&self, identity: &UpstreamIdentity) -> Result<(), UpstreamValidationError> {
        validate_identifier("credential key id", &self.key_id, 256)?;
        identity.verify()?;
        if self.intended_identity_digest == identity.digest {
            Ok(())
        } else {
            Err(UpstreamValidationError::CredentialOriginMismatch)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamToolDescriptor {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub input_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamToolRegistration {
    pub registration_id: String,
    pub capability_id: CapabilityId,
    pub capability_fingerprint: String,
    pub provider: ProviderId,
    pub identity: UpstreamIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialBinding>,
    pub descriptor: UpstreamToolDescriptor,
}

impl UpstreamToolRegistration {
    pub fn verify(&self) -> Result<(), UpstreamValidationError> {
        validate_identifier(
            "upstream registration id",
            &self.registration_id,
            MAX_REGISTRATION_ID_BYTES,
        )?;
        validate_digest(&self.capability_fingerprint)?;
        self.identity.verify()?;
        if let Some(credential) = &self.credential {
            credential.verify_for(&self.identity)?;
        }
        validate_identifier("upstream tool name", &self.descriptor.name, 256)?;
        validate_optional_text(self.descriptor.title.as_deref(), 512)?;
        validate_optional_text(self.descriptor.description.as_deref(), 8_192)?;
        if !self.descriptor.input_schema.is_object()
            || self
                .descriptor
                .output_schema
                .as_ref()
                .is_some_and(|schema| !schema.is_object())
        {
            return Err(UpstreamValidationError::InvalidToolDescriptor);
        }
        Ok(())
    }
}

fn identity_digest(
    server_id: &str,
    transport: UpstreamTransportKind,
    endpoint: &str,
    arguments: &[String],
    origin: Option<&str>,
    executable_digest: Option<&str>,
    environment: &BTreeMap<String, String>,
) -> Result<String, UpstreamValidationError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct IdentityBody<'a> {
        server_id: &'a str,
        transport: UpstreamTransportKind,
        endpoint: &'a str,
        arguments: &'a [String],
        origin: Option<&'a str>,
        executable_digest: Option<&'a str>,
        #[serde(skip_serializing_if = "BTreeMap::is_empty")]
        environment: &'a BTreeMap<String, String>,
    }
    serde_json::to_vec(&IdentityBody {
        server_id,
        transport,
        endpoint,
        arguments,
        origin,
        executable_digest,
        environment,
    })
    .map(|bytes| stable_hash(&bytes))
    .map_err(|error| UpstreamValidationError::Serialization(error.to_string()))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecutionChainEntry {
    canonical_path: String,
    digest: String,
    shebang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argument_index: Option<usize>,
}

struct ResolvedStdioExecution {
    endpoint: String,
    entries: Vec<ExecutionChainEntry>,
    files: Vec<fs::File>,
    launch_paths: Vec<PathBuf>,
    inherited_file_indexes: Vec<usize>,
    cleanup_paths: Vec<PathBuf>,
    program_index: usize,
    arguments: Vec<String>,
}

impl ResolvedStdioExecution {
    fn digest(&self) -> Result<String, UpstreamValidationError> {
        serde_json::to_vec(&self.entries)
            .map(|bytes| stable_hash(&bytes))
            .map_err(|error| UpstreamValidationError::Serialization(error.to_string()))
    }

    #[cfg(unix)]
    fn into_prepared(
        self,
        environment: BTreeMap<String, String>,
    ) -> Result<PreparedStdioExecution, UpstreamValidationError> {
        let program = self
            .launch_paths
            .get(self.program_index)
            .cloned()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?;
        Ok(PreparedStdioExecution {
            program,
            arguments: self.arguments,
            environment,
            files: self.files,
            inherited_file_indexes: self.inherited_file_indexes,
            cleanup_paths: self.cleanup_paths,
        })
    }
}

struct OpenedExecutable {
    canonical_path: String,
    digest: String,
    shebang: Option<Shebang>,
    file: fs::File,
    launch_path: PathBuf,
    cleanup_path: Option<PathBuf>,
    inherit_descriptor: bool,
}

struct ExecutableSnapshotMaterial {
    file: fs::File,
    launch_path: PathBuf,
    cleanup_path: Option<PathBuf>,
}

struct Shebang {
    raw: String,
    interpreter: String,
    argument: Option<String>,
}

#[derive(Default)]
struct ExecutionResolution {
    entries: Vec<ExecutionChainEntry>,
    files: Vec<fs::File>,
    launch_paths: Vec<PathBuf>,
    inherited_file_indexes: Vec<usize>,
    cleanup_paths: Vec<PathBuf>,
}

fn resolve_stdio_execution(
    executable: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
) -> Result<ResolvedStdioExecution, UpstreamValidationError> {
    let mut resolution = ExecutionResolution::default();
    let (program_index, mut launch_arguments) =
        resolution.resolve(executable, arguments.to_vec(), environment, false, 0)?;
    let endpoint_entry = resolution
        .entries
        .first()
        .ok_or(UpstreamValidationError::UnsafeExecutable)?;
    let endpoint = endpoint_entry.canonical_path.clone();
    let endpoint_has_shebang = endpoint_entry.shebang.is_some();
    if !endpoint_has_shebang
        && let Some(argument_index) = interpreter_script_argument_index(&endpoint, arguments)?
    {
        let reviewed_path =
            resolution.review_script_argument(argument_index, &arguments[argument_index])?;
        let launch_index = launch_arguments
            .len()
            .checked_sub(arguments.len())
            .and_then(|prefix| prefix.checked_add(argument_index))
            .ok_or(UpstreamValidationError::UnsafeExecutable)?;
        launch_arguments[launch_index] = reviewed_path;
    }
    Ok(ResolvedStdioExecution {
        endpoint,
        entries: resolution.entries,
        files: resolution.files,
        launch_paths: resolution.launch_paths,
        inherited_file_indexes: resolution.inherited_file_indexes,
        cleanup_paths: resolution.cleanup_paths,
        program_index,
        arguments: launch_arguments,
    })
}

impl ExecutionResolution {
    fn resolve(
        &mut self,
        executable: &Path,
        arguments: Vec<String>,
        environment: &BTreeMap<String, String>,
        allow_symlink: bool,
        depth: usize,
    ) -> Result<(usize, Vec<String>), UpstreamValidationError> {
        if depth >= MAX_EXECUTION_CHAIN_DEPTH {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        let opened = open_executable(executable, allow_symlink, true, true)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.canonical_path == opened.canonical_path)
        {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        let launch_path = opened
            .launch_path
            .to_str()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?
            .to_string();
        let shebang = opened.shebang;
        self.entries.push(ExecutionChainEntry {
            canonical_path: opened.canonical_path,
            digest: opened.digest,
            shebang: shebang.as_ref().map(|value| value.raw.clone()),
            argument_index: None,
        });
        let file_index = self.files.len();
        self.files.push(opened.file);
        self.launch_paths.push(opened.launch_path);
        if opened.inherit_descriptor {
            self.inherited_file_indexes.push(file_index);
        }
        if let Some(path) = opened.cleanup_path {
            self.cleanup_paths.push(path);
        }
        let Some(shebang) = shebang else {
            return Ok((file_index, arguments));
        };
        let (interpreter, mut interpreter_arguments) =
            resolve_shebang_interpreter(&shebang, environment)?;
        interpreter_arguments.push(launch_path);
        interpreter_arguments.extend(arguments);
        self.resolve(
            &interpreter,
            interpreter_arguments,
            environment,
            true,
            depth + 1,
        )
    }

    fn review_script_argument(
        &mut self,
        argument_index: usize,
        argument: &str,
    ) -> Result<String, UpstreamValidationError> {
        let path = Path::new(argument);
        let metadata = fs::symlink_metadata(path).map_err(executable_unavailable)?;
        if !metadata.is_file() && !metadata.file_type().is_symlink() {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        let opened = open_executable(path, true, false, false)?;
        let launch_path = opened
            .launch_path
            .to_str()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?
            .to_string();
        self.entries.push(ExecutionChainEntry {
            canonical_path: opened.canonical_path,
            digest: opened.digest,
            shebang: None,
            argument_index: Some(argument_index),
        });
        let file_index = self.files.len();
        self.files.push(opened.file);
        self.launch_paths.push(opened.launch_path);
        if opened.inherit_descriptor {
            self.inherited_file_indexes.push(file_index);
        }
        if let Some(path) = opened.cleanup_path {
            self.cleanup_paths.push(path);
        }
        Ok(launch_path)
    }
}

fn interpreter_script_argument_index(
    endpoint: &str,
    arguments: &[String],
) -> Result<Option<usize>, UpstreamValidationError> {
    let name = Path::new(endpoint)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(UpstreamValidationError::UnsafeExecutable)?;
    let known_interpreter = matches!(
        name,
        "sh" | "dash" | "bash" | "zsh" | "node" | "ruby" | "perl" | "php" | "deno" | "bun"
    ) || name.starts_with("python");
    if !known_interpreter {
        return Ok(None);
    }
    let Some(first) = arguments.first().map(String::as_str) else {
        return Ok(None);
    };
    if matches!(
        first,
        "-c" | "-m" | "-e" | "--eval" | "-p" | "--print" | "eval"
    ) {
        return Ok(None);
    }
    if first == "--" {
        return arguments
            .get(1)
            .map(|_| Some(1))
            .ok_or(UpstreamValidationError::UnsafeExecutable);
    }
    if first.starts_with('-') {
        // Interpreter option grammars vary by version and many options consume
        // a following value. Refuse ambiguous forms instead of hashing the
        // wrong positional argument while executing an unreviewed script.
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    if name == "deno" {
        if first != "run" {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        return arguments
            .get(1)
            .filter(|argument| !argument.starts_with('-'))
            .map(|_| Some(1))
            .ok_or(UpstreamValidationError::UnsafeExecutable);
    }
    if name == "bun" && first == "run" {
        return arguments
            .get(1)
            .filter(|argument| !argument.starts_with('-'))
            .map(|_| Some(1))
            .ok_or(UpstreamValidationError::UnsafeExecutable);
    }
    Ok(Some(0))
}

fn resolve_shebang_interpreter(
    shebang: &Shebang,
    environment: &BTreeMap<String, String>,
) -> Result<(PathBuf, Vec<String>), UpstreamValidationError> {
    if matches!(shebang.interpreter.as_str(), "/usr/bin/env" | "/bin/env") {
        let argument = shebang
            .argument
            .as_deref()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?;
        let mut words = argument.split_ascii_whitespace().collect::<Vec<_>>();
        let split_mode = words.first() == Some(&"-S");
        if split_mode {
            words.remove(0);
            if argument
                .bytes()
                .any(|byte| matches!(byte, b'\'' | b'"' | b'\\'))
            {
                return Err(UpstreamValidationError::UnsafeExecutable);
            }
        } else if words.len() != 1 {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        let command = words
            .first()
            .copied()
            .filter(|command| !command.starts_with('-') && !command.contains('='))
            .ok_or(UpstreamValidationError::UnsafeExecutable)?;
        let path = resolve_path_command(command, environment)?;
        return Ok((
            path,
            words.into_iter().skip(1).map(str::to_string).collect(),
        ));
    }
    let interpreter = PathBuf::from(&shebang.interpreter);
    if !interpreter.is_absolute() {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    Ok((interpreter, shebang.argument.iter().cloned().collect()))
}

fn resolve_path_command(
    command: &str,
    environment: &BTreeMap<String, String>,
) -> Result<PathBuf, UpstreamValidationError> {
    if command.is_empty() || command.contains('/') || command.chars().any(char::is_control) {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let path = environment
        .get("PATH")
        .ok_or(UpstreamValidationError::UnsafeExecutable)?;
    for directory in env::split_paths(path) {
        if !directory.is_absolute() {
            return Err(UpstreamValidationError::UnsafeExecutable);
        }
        let candidate = directory.join(command);
        match fs::symlink_metadata(&candidate) {
            Ok(_) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(UpstreamValidationError::ExecutableUnavailable {
                    message: error.to_string(),
                });
            }
        }
    }
    Err(UpstreamValidationError::ExecutableUnavailable {
        message: format!("PATH command {command} was not found"),
    })
}

fn open_executable(
    requested: &Path,
    allow_symlink: bool,
    require_executable: bool,
    inspect_shebang: bool,
) -> Result<OpenedExecutable, UpstreamValidationError> {
    let requested_metadata = fs::symlink_metadata(requested).map_err(executable_unavailable)?;
    if (!allow_symlink && requested_metadata.file_type().is_symlink())
        || (!requested_metadata.is_file() && !requested_metadata.file_type().is_symlink())
    {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let canonical = fs::canonicalize(requested).map_err(executable_unavailable)?;
    if !canonical.is_absolute() {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let canonical_metadata = fs::symlink_metadata(&canonical).map_err(executable_unavailable)?;
    if canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.is_file()
        || (require_executable && !is_executable(&canonical_metadata))
    {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let mut file = fs::File::open(&canonical).map_err(executable_unavailable)?;
    let opened_metadata = file.metadata().map_err(executable_unavailable)?;
    let after_open_metadata = fs::symlink_metadata(&canonical).map_err(executable_unavailable)?;
    if !same_file(&opened_metadata, &after_open_metadata)
        || !same_file_state(&opened_metadata, &after_open_metadata)
    {
        return Err(UpstreamValidationError::IdentityMismatch);
    }
    if !requested_metadata.file_type().is_symlink()
        && !same_file(&requested_metadata, &opened_metadata)
    {
        return Err(UpstreamValidationError::IdentityMismatch);
    }
    let (digest, header, snapshot) = digest_open_file(&mut file, &opened_metadata)?;
    let canonical_path = canonical
        .to_str()
        .ok_or(UpstreamValidationError::UnsafeExecutable)?
        .to_string();
    let shebang = if inspect_shebang {
        parse_shebang(&header)?
    } else {
        None
    };
    let ExecutableSnapshotMaterial {
        file: snapshot_file,
        launch_path: snapshot_launch_path,
        cleanup_path: snapshot_cleanup_path,
    } = snapshot;
    let (launch_file, launch_path, cleanup_path, inherit_descriptor) =
        if shebang.is_none() && path_is_stable(&canonical) {
            if let Some(path) = snapshot_cleanup_path {
                let _ = fs::remove_file(path);
            }
            drop(snapshot_file);
            (file, canonical.clone(), None, false)
        } else {
            let inherit_descriptor = snapshot_cleanup_path.is_none()
                && cfg!(any(target_os = "linux", target_os = "android"));
            (
                snapshot_file,
                snapshot_launch_path,
                snapshot_cleanup_path,
                inherit_descriptor,
            )
        };
    Ok(OpenedExecutable {
        canonical_path,
        digest,
        shebang,
        file: launch_file,
        launch_path,
        cleanup_path,
        inherit_descriptor,
    })
}

fn digest_open_file(
    file: &mut fs::File,
    before: &fs::Metadata,
) -> Result<(String, Vec<u8>, ExecutableSnapshotMaterial), UpstreamValidationError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut header = Vec::new();
    let mut snapshot = ExecutableSnapshotBuilder::new()?;
    loop {
        let read = file.read(&mut buffer).map_err(executable_unavailable)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        snapshot.write_all(&buffer[..read])?;
        if !header.contains(&b'\n') && header.len() <= MAX_SHEBANG_BYTES {
            let remaining = MAX_SHEBANG_BYTES.saturating_add(1) - header.len();
            header.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
    let after = file.metadata().map_err(executable_unavailable)?;
    if !same_file_state(before, &after) {
        return Err(UpstreamValidationError::IdentityMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(executable_unavailable)?;
    let snapshot = snapshot.finish()?;
    Ok((
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        header,
        snapshot,
    ))
}

struct ExecutableSnapshotBuilder {
    path: PathBuf,
    writer: Option<fs::File>,
}

impl ExecutableSnapshotBuilder {
    #[cfg(unix)]
    fn new() -> Result<Self, UpstreamValidationError> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut entropy = [0_u8; 16];
        fs::File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut entropy))
            .map_err(executable_unavailable)?;
        let name = entropy
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let path = env::temp_dir().join(format!(".unpin-exec-{name}"));
        let writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .map_err(executable_unavailable)?;
        Ok(Self {
            path,
            writer: Some(writer),
        })
    }

    #[cfg(not(unix))]
    fn new() -> Result<Self, UpstreamValidationError> {
        Err(UpstreamValidationError::UnsupportedStdioExecution)
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), UpstreamValidationError> {
        self.writer
            .as_mut()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?
            .write_all(bytes)
            .map_err(executable_unavailable)
    }

    #[cfg(unix)]
    fn finish(mut self) -> Result<ExecutableSnapshotMaterial, UpstreamValidationError> {
        let mut writer = self
            .writer
            .take()
            .ok_or(UpstreamValidationError::UnsafeExecutable)?;
        writer.flush().map_err(executable_unavailable)?;
        writer
            .set_permissions(fs::Permissions::from_mode(0o500))
            .map_err(executable_unavailable)?;
        drop(writer);
        let reader = fs::File::open(&self.path).map_err(executable_unavailable)?;
        if cfg!(any(target_os = "linux", target_os = "android")) {
            fs::remove_file(&self.path).map_err(executable_unavailable)?;
            self.path = PathBuf::new();
            let launch_path = descriptor_path(&reader)?;
            Ok(ExecutableSnapshotMaterial {
                file: reader,
                launch_path,
                cleanup_path: None,
            })
        } else {
            let launch_path = self.path.clone();
            let cleanup_path = self.path.clone();
            self.path = PathBuf::new();
            Ok(ExecutableSnapshotMaterial {
                file: reader,
                launch_path,
                cleanup_path: Some(cleanup_path),
            })
        }
    }

    #[cfg(not(unix))]
    fn finish(self) -> Result<ExecutableSnapshotMaterial, UpstreamValidationError> {
        Err(UpstreamValidationError::UnsupportedStdioExecution)
    }
}

impl Drop for ExecutableSnapshotBuilder {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn parse_shebang(header: &[u8]) -> Result<Option<Shebang>, UpstreamValidationError> {
    if !header.starts_with(b"#!") {
        return Ok(None);
    }
    let end = header
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(header.len());
    if end > MAX_SHEBANG_BYTES {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let line = std::str::from_utf8(&header[2..end])
        .map_err(|_| UpstreamValidationError::UnsafeExecutable)?
        .trim_end_matches('\r')
        .trim();
    if line.is_empty() || line.chars().any(|character| character == '\0') {
        return Err(UpstreamValidationError::UnsafeExecutable);
    }
    let interpreter_end = line.find(char::is_whitespace).unwrap_or(line.len());
    let interpreter = line[..interpreter_end].to_string();
    let argument = line[interpreter_end..].trim().to_string();
    Ok(Some(Shebang {
        raw: line.to_string(),
        interpreter,
        argument: (!argument.is_empty()).then_some(argument),
    }))
}

#[cfg(unix)]
fn descriptor_path(file: &fs::File) -> Result<PathBuf, UpstreamValidationError> {
    let root = [Path::new("/proc/self/fd"), Path::new("/dev/fd")]
        .into_iter()
        .find(|root| root.is_dir())
        .ok_or(UpstreamValidationError::UnsupportedStdioExecution)?;
    Ok(root.join(file.as_raw_fd().to_string()))
}

#[cfg(not(unix))]
fn descriptor_path(_file: &fs::File) -> Result<PathBuf, UpstreamValidationError> {
    Err(UpstreamValidationError::UnsupportedStdioExecution)
}

#[cfg(unix)]
fn path_is_stable(path: &Path) -> bool {
    // SAFETY: geteuid has no arguments and no memory-safety preconditions.
    let effective_user = unsafe { geteuid() };
    path.ancestors().all(|candidate| {
        fs::symlink_metadata(candidate).is_ok_and(|metadata| {
            !metadata.file_type().is_symlink()
                && metadata.mode() & 0o022 == 0
                && (metadata.uid() != effective_user || metadata.mode() & 0o200 == 0)
                && !path_is_writable(candidate)
        })
    })
}

#[cfg(unix)]
fn path_is_writable(path: &Path) -> bool {
    std::ffi::CString::new(path.as_os_str().as_bytes()).is_ok_and(|path| {
        // SAFETY: CString guarantees terminated path; access does not retain it.
        unsafe { access(path.as_ptr(), W_OK) == 0 }
    })
}

#[cfg(not(unix))]
fn path_is_stable(_path: &Path) -> bool {
    false
}

#[cfg(unix)]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn access(path: *const std::ffi::c_char, mode: std::ffi::c_int) -> std::ffi::c_int;
}

#[cfg(unix)]
const W_OK: std::ffi::c_int = 2;

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file(left, right)
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file(left, right)
}

fn executable_unavailable(error: std::io::Error) -> UpstreamValidationError {
    UpstreamValidationError::ExecutableUnavailable {
        message: error.to_string(),
    }
}

fn reviewed_stdio_environment() -> Result<BTreeMap<String, String>, UpstreamValidationError> {
    let mut environment = BTreeMap::new();
    for key in STDIO_ENVIRONMENT_KEYS {
        match env::var(key) {
            Ok(value) => {
                environment.insert((*key).to_string(), value);
            }
            Err(env::VarError::NotPresent) => {}
            Err(env::VarError::NotUnicode(_)) => {
                return Err(UpstreamValidationError::InvalidEnvironment);
            }
        }
    }
    validate_stdio_environment(&environment)?;
    Ok(environment)
}

fn validate_stdio_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), UpstreamValidationError> {
    if environment.iter().any(|(key, value)| {
        !STDIO_ENVIRONMENT_KEYS.contains(&key.as_str())
            || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            || value.chars().any(char::is_control)
    }) {
        return Err(UpstreamValidationError::InvalidEnvironment);
    }
    Ok(())
}

fn validate_arguments(arguments: &[String]) -> Result<(), UpstreamValidationError> {
    if arguments.len() > MAX_ARGUMENTS {
        return Err(UpstreamValidationError::TooManyArguments);
    }
    for argument in arguments {
        if argument.len() > MAX_ARGUMENT_BYTES || argument.chars().any(char::is_control) {
            return Err(UpstreamValidationError::InvalidArgument);
        }
    }
    Ok(())
}

fn http_origin(endpoint: &str) -> Result<String, UpstreamValidationError> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('#')
    {
        return Err(UpstreamValidationError::InvalidEndpoint);
    }
    let (scheme, remainder) = endpoint
        .split_once("://")
        .ok_or(UpstreamValidationError::InvalidEndpoint)?;
    if !matches!(scheme, "http" | "https") {
        return Err(UpstreamValidationError::InvalidEndpoint);
    }
    let authority = remainder
        .split(['/', '?'])
        .next()
        .filter(|authority| !authority.is_empty() && !authority.contains('@'))
        .ok_or(UpstreamValidationError::InvalidEndpoint)?;
    if authority.chars().any(char::is_whitespace) || !valid_authority(authority) {
        return Err(UpstreamValidationError::InvalidEndpoint);
    }
    if scheme == "http" && !is_loopback_authority(authority) {
        return Err(UpstreamValidationError::InsecureRemoteEndpoint);
    }
    Ok(format!("{scheme}://{authority}"))
}

fn is_loopback_authority(authority: &str) -> bool {
    if let Some(remainder) = authority.strip_prefix('[') {
        return remainder
            .split_once(']')
            .and_then(|(host, _)| host.parse::<Ipv6Addr>().ok())
            .is_some_and(|address| address.is_loopback());
    }
    let host = authority.split(':').next().unwrap_or(authority);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<Ipv4Addr>()
            .is_ok_and(|address| address.octets()[0] == 127)
}

fn valid_authority(authority: &str) -> bool {
    if let Some(remainder) = authority.strip_prefix('[') {
        let Some((host, suffix)) = remainder.split_once(']') else {
            return false;
        };
        return host.parse::<Ipv6Addr>().is_ok()
            && (suffix.is_empty()
                || suffix
                    .strip_prefix(':')
                    .is_some_and(|port| valid_port(Some(port))));
    }
    if authority.contains('[') || authority.contains(']') || authority.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    !host.is_empty()
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && valid_port(port)
}

fn valid_port(port: Option<&str>) -> bool {
    port.is_none_or(|port| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|value| value != 0)
    })
}

fn validate_identifier(
    _label: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), UpstreamValidationError> {
    if value.trim().is_empty()
        || value.len() > maximum
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
    {
        Err(UpstreamValidationError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn validate_optional_text(
    value: Option<&str>,
    maximum: usize,
) -> Result<(), UpstreamValidationError> {
    if value.is_some_and(|value| {
        value.len() > maximum
            || value
                .chars()
                .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    }) {
        Err(UpstreamValidationError::InvalidToolDescriptor)
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), UpstreamValidationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(UpstreamValidationError::InvalidDigest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamValidationError {
    InvalidIdentifier,
    InvalidDigest,
    InvalidEndpoint,
    InsecureRemoteEndpoint,
    UnsafeExecutable,
    UnsupportedStdioExecution,
    ExecutableUnavailable { message: String },
    InvalidEnvironment,
    TooManyArguments,
    InvalidArgument,
    IdentityMismatch,
    CredentialOriginMismatch,
    InvalidToolDescriptor,
    Serialization(String),
}

impl fmt::Display for UpstreamValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier => formatter.write_str("upstream identifier is invalid"),
            Self::InvalidDigest => formatter.write_str("upstream digest is invalid"),
            Self::InvalidEndpoint => formatter.write_str("upstream HTTP endpoint is invalid"),
            Self::InsecureRemoteEndpoint => {
                formatter.write_str("cleartext upstream HTTP is limited to loopback")
            }
            Self::UnsafeExecutable => {
                formatter.write_str("upstream executable must be a canonical regular file")
            }
            Self::UnsupportedStdioExecution => {
                formatter.write_str("verified stdio execution is unsupported on this platform")
            }
            Self::ExecutableUnavailable { message } => {
                write!(formatter, "upstream executable is unavailable: {message}")
            }
            Self::InvalidEnvironment => {
                formatter.write_str("upstream stdio environment is invalid")
            }
            Self::TooManyArguments => formatter.write_str("upstream argument limit exceeded"),
            Self::InvalidArgument => formatter.write_str("upstream argument is invalid"),
            Self::IdentityMismatch => formatter.write_str("upstream server identity changed"),
            Self::CredentialOriginMismatch => {
                formatter.write_str("credential is not authorized for upstream identity")
            }
            Self::InvalidToolDescriptor => {
                formatter.write_str("upstream tool descriptor is invalid")
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "upstream identity serialization failed: {message}"
                )
            }
        }
    }
}

impl std::error::Error for UpstreamValidationError {}
