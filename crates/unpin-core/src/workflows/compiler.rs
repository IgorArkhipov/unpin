use std::collections::BTreeMap;

use crate::{
    catalog::{CapabilityId, CapabilityKind, Catalog},
    profiles::{
        CapabilityLockSnapshot, CapabilityLockState, CompiledProfileMember,
        CompiledProfileRevision, ProfileSourceScope,
    },
    providers::ProviderId,
};

use super::{
    COMPILED_WORKFLOW_SCHEMA_VERSION, CompiledWorkflowMode, CompiledWorkflowProfileRevision,
    CompiledWorkflowRevision, WorkflowControl, WorkflowDefinition, WorkflowValidationError,
};

pub fn compile_workflow(
    definition: &WorkflowDefinition,
    profiles: &BTreeMap<String, CompiledProfileRevision>,
    catalog: &Catalog,
    locks: &CapabilityLockSnapshot,
    provider: ProviderId,
    source_scope: ProfileSourceScope,
) -> Result<CompiledWorkflowRevision, WorkflowValidationError> {
    definition.validate()?;
    locks
        .verify()
        .map_err(|error| WorkflowValidationError::LockInvalid(error.to_string()))?;
    if locks.provider != provider {
        return Err(WorkflowValidationError::LockProviderMismatch {
            expected: provider,
            actual: locks.provider,
        });
    }

    let baseline = profile(profiles, &definition.baseline_profile_id)?;
    let baseline_members = routable_members(baseline, catalog, provider)?;
    let mut maximum_members = baseline_members.clone();
    let mut resolved_modes = BTreeMap::new();

    let canonical = definition.canonical();
    for mode in &canonical.modes {
        let revision = profile(profiles, &mode.profile_id)?;
        let mode_members = routable_members(revision, catalog, provider)?;
        merge_members(&mut maximum_members, &mode_members)?;
        resolved_modes.insert(mode.name.clone(), (revision, mode_members));
    }
    validate_hard_enabled_locks(&maximum_members, locks)?;

    let authored_maximum = maximum_members.clone();
    let mut modes = BTreeMap::new();
    let mut effective_profiles = BTreeMap::new();
    for (mode_name, (revision, mode_members)) in resolved_modes {
        let mut effective = baseline_members.clone();
        merge_members(&mut effective, &mode_members)?;
        apply_locks(&mut effective, locks, &authored_maximum);
        let effective = CompiledWorkflowProfileRevision::compile(
            format!("{}.{}", definition.id, mode_name),
            effective.into_values().collect(),
        )?;
        modes.insert(
            mode_name.clone(),
            CompiledWorkflowMode {
                profile_id: revision.profile_id.clone(),
                profile_digest: revision.digest.clone(),
                effective_profile_digest: effective.digest.clone(),
            },
        );
        effective_profiles.insert(mode_name, effective);
    }
    apply_locks(&mut maximum_members, locks, &authored_maximum);
    let maximum_envelope = CompiledWorkflowProfileRevision::compile(
        format!("{}.maximum-envelope", definition.id),
        maximum_members.into_values().collect(),
    )?;

    for effective in effective_profiles.values() {
        if effective
            .members
            .iter()
            .any(|member| !maximum_envelope.contains(&member.capability_id))
        {
            return Err(WorkflowValidationError::EnvelopeNotSuperset);
        }
    }

    let catalog_fingerprints = maximum_envelope
        .members
        .iter()
        .map(|member| {
            (
                member.capability_id.clone(),
                member.capability_fingerprint.clone(),
            )
        })
        .collect();
    let mut compiled = CompiledWorkflowRevision {
        schema_version: COMPILED_WORKFLOW_SCHEMA_VERSION,
        workflow_id: definition.id.clone(),
        display_name: definition.display_name.clone(),
        description: definition.description.clone(),
        origin: source_scope,
        definition_digest: definition.definition_digest()?,
        provider,
        baseline_profile_id: baseline.profile_id.clone(),
        baseline_profile_digest: baseline.digest.clone(),
        entry_mode: definition.entry_mode.clone(),
        modes,
        effective_profiles,
        maximum_envelope,
        capability_lock_digest: locks.digest.clone(),
        catalog_fingerprints,
        system_controls: WorkflowControl::ALL.to_vec(),
        digest: String::new(),
    };
    compiled.digest = compiled.computed_digest()?;
    compiled.verify_digest()?;
    Ok(compiled)
}

fn profile<'a>(
    profiles: &'a BTreeMap<String, CompiledProfileRevision>,
    profile_id: &str,
) -> Result<&'a CompiledProfileRevision, WorkflowValidationError> {
    let revision = profiles
        .get(profile_id)
        .ok_or_else(|| WorkflowValidationError::MissingProfile(profile_id.to_string()))?;
    if revision.profile_id != profile_id {
        return Err(WorkflowValidationError::ProfileIdMismatch {
            expected: profile_id.to_string(),
            actual: revision.profile_id.clone(),
        });
    }
    revision
        .verify_digest()
        .map_err(|error| WorkflowValidationError::ProfileInvalid {
            profile_id: profile_id.to_string(),
            message: error.to_string(),
        })?;
    Ok(revision)
}

fn routable_members(
    profile: &CompiledProfileRevision,
    catalog: &Catalog,
    provider: ProviderId,
) -> Result<BTreeMap<CapabilityId, CompiledProfileMember>, WorkflowValidationError> {
    let mut members = BTreeMap::new();
    for member in profile.members_for_provider(provider) {
        let record = catalog.get(&member.capability_id).ok_or_else(|| {
            WorkflowValidationError::MissingCapability(member.capability_id.clone())
        })?;
        if record.fingerprint != member.capability_fingerprint
            || record.origin.canonical_key != member.catalog_origin_key
            || !record.supports_provider(provider)
        {
            return Err(WorkflowValidationError::StaleCapability(
                member.capability_id.clone(),
            ));
        }
        match record.kind {
            CapabilityKind::Skill | CapabilityKind::McpTool | CapabilityKind::Hook => {
                if let Some(existing) = members.insert(member.capability_id.clone(), member.clone())
                    && existing != *member
                {
                    return Err(WorkflowValidationError::ConflictingCapability(
                        member.capability_id.clone(),
                    ));
                }
            }
            // Agent Plugin package records are immutable contribution provenance, not
            // a gateway exposure or transition side effect. Their routable children
            // remain pinned through `contributed_by` and source fingerprints.
            CapabilityKind::Plugin => {}
            kind => {
                return Err(WorkflowValidationError::UnsupportedCapability {
                    capability_id: member.capability_id.clone(),
                    kind: kind.as_str().to_string(),
                });
            }
        }
    }
    Ok(members)
}

fn merge_members(
    target: &mut BTreeMap<CapabilityId, CompiledProfileMember>,
    source: &BTreeMap<CapabilityId, CompiledProfileMember>,
) -> Result<(), WorkflowValidationError> {
    for (capability_id, member) in source {
        if let Some(existing) = target.get(capability_id) {
            if existing != member {
                return Err(WorkflowValidationError::ConflictingCapability(
                    capability_id.clone(),
                ));
            }
        } else {
            target.insert(capability_id.clone(), member.clone());
        }
    }
    Ok(())
}

fn validate_hard_enabled_locks(
    maximum_members: &BTreeMap<CapabilityId, CompiledProfileMember>,
    locks: &CapabilityLockSnapshot,
) -> Result<(), WorkflowValidationError> {
    for (capability_id, state) in &locks.entries {
        if *state == CapabilityLockState::HardEnabled
            && !maximum_members.contains_key(capability_id)
        {
            return Err(WorkflowValidationError::HardEnabledOutsideEnvelope(
                capability_id.clone(),
            ));
        }
    }
    Ok(())
}

fn apply_locks(
    members: &mut BTreeMap<CapabilityId, CompiledProfileMember>,
    locks: &CapabilityLockSnapshot,
    authored_maximum: &BTreeMap<CapabilityId, CompiledProfileMember>,
) {
    for (capability_id, state) in &locks.entries {
        match state {
            CapabilityLockState::HardDisabled => {
                members.remove(capability_id);
            }
            CapabilityLockState::HardEnabled => {
                let member = authored_maximum
                    .get(capability_id)
                    .expect("hard-enabled workflow lock was validated against the envelope");
                members.insert(capability_id.clone(), member.clone());
            }
        }
    }
}
