use super::super::*;

pub(crate) fn discover_pi(
    roots: &DiscoveryRoots,
    state: &mut DiscoveryState,
) -> Result<(), DiscoveryError> {
    let DiscoveryState {
        project_scope_cache,
        shared_skill_views,
        items,
        warnings,
        ..
    } = state;
    let native_global_root = roots.pi_global.join("skills");
    let shared_global_root = roots.shared_global.join(".agents").join("skills");
    let mut global_live_ids = discover_recursive_skill_dirs(
        &native_global_root,
        ProviderId::Pi,
        DiscoveryLayer::Global,
        PI_GLOBAL_SKILL_ID_PREFIX,
        DiscoveryMutability::ReadWrite,
        items,
        warnings,
    )?;
    let global_file_skill_ids = discover_direct_skill_markdown_files(
        &native_global_root,
        SkillItemDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Global,
            id_prefix: &format!("{PI_GLOBAL_SKILL_ID_PREFIX}@file/"),
            mutability: DiscoveryMutability::ReadWrite,
            max_fingerprint_bytes: Some(MAX_CONFIGURED_SKILL_BYTES),
            scan_scope: None,
        },
        items,
        warnings,
    )?;
    global_live_ids.extend(global_file_skill_ids);
    let shared_global_id_prefix =
        format!("{PI_GLOBAL_SKILL_ID_PREFIX}{PI_COMPAT_AGENTS_SKILL_NAMESPACE}");
    global_live_ids.extend(discover_recursive_skill_dirs(
        &shared_global_root,
        ProviderId::Pi,
        DiscoveryLayer::Global,
        &shared_global_id_prefix,
        DiscoveryMutability::ReadWrite,
        items,
        warnings,
    )?);
    shared_skill_views.push(SkillView::new(
        ProviderId::Pi,
        DiscoveryLayer::Global,
        shared_global_root.clone(),
        shared_global_id_prefix,
        SkillRootTraversal::Recursive,
    ));
    let mut global_skill_roots = vec![native_global_root.clone(), shared_global_root];
    let pi_home_root = roots
        .pi_global
        .parent()
        .and_then(Path::parent)
        .unwrap_or(roots.pi_global.as_path())
        .to_path_buf();
    let mut global_settings_target = PiSettingsTarget {
        live_skill_ids: &mut global_live_ids,
        skill_roots: &mut global_skill_roots,
        items: &mut *items,
        warnings: &mut *warnings,
    };
    discover_pi_settings(
        &roots.pi_global.join("settings.json"),
        DiscoveryLayer::Global,
        "settings.json",
        &pi_home_root,
        None,
        roots.app_state_root.as_deref(),
        &mut global_settings_target,
    )?;
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Global,
            live_ids: &global_live_ids,
            allowed_skill_roots: &global_skill_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_file_items(
        roots.app_state_root.as_deref(),
        ProviderId::Pi,
        DiscoveryLayer::Global,
        &global_live_ids,
        std::slice::from_ref(&native_global_root),
        items,
        warnings,
    )?;

    let native_project_skills = discover_project_skill_dirs(
        &roots.pi_project,
        Path::new(".pi/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            id_prefix: PI_PROJECT_SKILL_ID_PREFIX,
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Selected,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    let shared_project_id_prefix =
        format!("{PI_PROJECT_SKILL_ID_PREFIX}{PI_COMPAT_AGENTS_SKILL_NAMESPACE}");
    let shared_project_skills = discover_project_skill_dirs(
        &roots.shared_project,
        Path::new(".agents/skills"),
        SkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            id_prefix: &shared_project_id_prefix,
            mutability: DiscoveryMutability::ReadWrite,
            traversal: ProjectSkillTraversal::Ancestors,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        roots.scan_project_scopes,
        project_scope_cache,
        warnings,
        items,
    )?;
    shared_skill_views.extend(shared_project_skills.skill_views.iter().cloned());
    let mut project_live_ids = native_project_skills.live_ids;
    project_live_ids.extend(shared_project_skills.live_ids);
    let mut project_skill_roots = native_project_skills.skill_roots;
    project_skill_roots.extend(shared_project_skills.skill_roots);
    let native_project_skill_root = roots.pi_project.join(".pi").join("skills");
    project_live_ids.extend(discover_direct_skill_markdown_files(
        &native_project_skill_root,
        SkillItemDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            id_prefix: &format!("{PI_PROJECT_SKILL_ID_PREFIX}@file/"),
            mutability: DiscoveryMutability::ReadWrite,
            max_fingerprint_bytes: Some(MAX_CONFIGURED_SKILL_BYTES),
            scan_scope: Some(&roots.pi_project),
        },
        items,
        warnings,
    )?);
    let mut project_settings_target = PiSettingsTarget {
        live_skill_ids: &mut project_live_ids,
        skill_roots: &mut project_skill_roots,
        items: &mut *items,
        warnings: &mut *warnings,
    };
    discover_pi_settings(
        &roots.pi_project.join(".pi").join("settings.json"),
        DiscoveryLayer::Project,
        ".pi/settings.json",
        &pi_home_root,
        Some(&roots.pi_project),
        roots.app_state_root.as_deref(),
        &mut project_settings_target,
    )?;
    discover_vaulted_skill_items(
        roots.app_state_root.as_deref(),
        VaultedSkillDiscoverySpec {
            provider: ProviderId::Pi,
            layer: DiscoveryLayer::Project,
            live_ids: &project_live_ids,
            allowed_skill_roots: &project_skill_roots,
            skill_root_traversal: SkillRootTraversal::Recursive,
        },
        items,
        warnings,
    )?;
    discover_vaulted_skill_file_items(
        roots.app_state_root.as_deref(),
        ProviderId::Pi,
        DiscoveryLayer::Project,
        &project_live_ids,
        std::slice::from_ref(&native_project_skill_root),
        items,
        warnings,
    )?;

    Ok(())
}

struct PiSettingsTarget<'a> {
    live_skill_ids: &'a mut BTreeSet<String>,
    skill_roots: &'a mut Vec<PathBuf>,
    items: &'a mut Vec<DiscoveryItem>,
    warnings: &'a mut Vec<DiscoveryWarning>,
}

const MAX_PI_SKILL_RULES: usize = 512;
const MAX_PI_SKILL_RULE_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct PiSkillRules {
    includes: Vec<globset::GlobMatcher>,
    excludes: Vec<globset::GlobMatcher>,
    force_includes: Vec<String>,
    force_excludes: Vec<String>,
    accepted_count: usize,
    accepted_bytes: usize,
}

impl PiSkillRules {
    fn add(&mut self, raw: &str) -> Result<bool, globset::Error> {
        if self.accepted_count == MAX_PI_SKILL_RULES
            || raw.len() > MAX_PI_SKILL_RULE_BYTES.saturating_sub(self.accepted_bytes)
        {
            return Ok(false);
        }
        self.accepted_count += 1;
        self.accepted_bytes += raw.len();
        let normalized = raw.replace('\\', "/");
        let (prefix, pattern) = normalized
            .chars()
            .next()
            .filter(|prefix| matches!(prefix, '!' | '+' | '-'))
            .map_or((None, normalized.as_str()), |prefix| {
                (Some(prefix), &normalized[1..])
            });
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        match prefix {
            Some('+') => self.force_includes.push(pattern.to_string()),
            Some('-') => self.force_excludes.push(pattern.to_string()),
            Some('!') => self.excludes.push(pi_skill_glob(pattern)?),
            _ => self.includes.push(pi_skill_glob(pattern)?),
        }
        Ok(true)
    }

    fn is_empty(&self) -> bool {
        self.includes.is_empty()
            && self.excludes.is_empty()
            && self.force_includes.is_empty()
            && self.force_excludes.is_empty()
    }

    fn enabled(&self, path: &Path, settings_root: &Path) -> bool {
        let mut candidates = vec![
            path.strip_prefix(settings_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/"),
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            path.to_string_lossy().replace('\\', "/"),
        ];
        let mut exact_candidates = vec![candidates[0].clone(), candidates[2].clone()];
        if path.file_name() == Some(OsStr::new("SKILL.md")) {
            let parent = path.parent().unwrap_or(path);
            let relative_parent = parent
                .strip_prefix(settings_root)
                .unwrap_or(parent)
                .to_string_lossy()
                .replace('\\', "/");
            let absolute_parent = parent.to_string_lossy().replace('\\', "/");
            candidates.extend([
                relative_parent.clone(),
                parent
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                absolute_parent.clone(),
            ]);
            exact_candidates.extend([relative_parent, absolute_parent]);
        }

        let matches_glob = |rules: &[globset::GlobMatcher]| {
            rules
                .iter()
                .any(|rule| candidates.iter().any(|candidate| rule.is_match(candidate)))
        };
        let matches_exact =
            |rules: &[String]| rules.iter().any(|rule| exact_candidates.contains(rule));
        let mut enabled = self.includes.is_empty() || matches_glob(&self.includes);
        if matches_glob(&self.excludes) {
            enabled = false;
        }
        if matches_exact(&self.force_includes) {
            enabled = true;
        }
        if matches_exact(&self.force_excludes) {
            enabled = false;
        }
        enabled
    }
}

fn pi_skill_glob(pattern: &str) -> Result<globset::GlobMatcher, globset::Error> {
    Ok(globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()?
        .compile_matcher())
}

fn discover_pi_settings(
    path: &Path,
    layer: DiscoveryLayer,
    display_name: &str,
    pi_home_root: &Path,
    project_boundary: Option<&Path>,
    app_state_root: Option<&Path>,
    target: &mut PiSettingsTarget<'_>,
) -> Result<(), DiscoveryError> {
    let items = &mut *target.items;
    let warnings = &mut *target.warnings;
    if !path.exists() {
        return Ok(());
    }
    items.push(provider_setting_item(
        ProviderId::Pi,
        layer,
        format!("pi:{}:setting:settings-json", layer.as_str()),
        display_name,
        path,
    ));

    let Some(document) =
        read_json_if_exists::<serde_json::Value>(path, ProviderId::Pi, Some(layer), warnings)?
    else {
        return Ok(());
    };
    let Some(document) = document.as_object() else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Pi,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{display_name} must contain a JSON object"),
        });
        return Ok(());
    };
    let packages: &[serde_json::Value] = match document.get("packages") {
        None => &[],
        Some(value) => match value.as_array() {
            Some(packages) => packages,
            None => {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::Pi,
                    layer: Some(layer),
                    code: "invalid-shape".to_string(),
                    message: format!("{display_name} packages must be an array"),
                });
                &[]
            }
        },
    };

    let package_item_start = items.len();
    let mut validated_sources = BTreeSet::new();
    let mutability = if packages.iter().all(|package| {
        pi_package_extension_state(package)
            .ok()
            .is_some_and(|(source, _)| validated_sources.insert(source.to_string()))
    }) {
        DiscoveryMutability::ReadWrite
    } else {
        DiscoveryMutability::ReadOnly
    };
    let id_prefix = match layer {
        DiscoveryLayer::Global => PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX,
    };
    let mut item_ids = BTreeSet::new();
    for (index, package) in packages.iter().enumerate() {
        let (source, enabled) = match pi_package_extension_state(package) {
            Ok(state) => state,
            Err(reason) => {
                warnings.push(DiscoveryWarning {
                    provider: ProviderId::Pi,
                    layer: Some(layer),
                    code: "invalid-shape".to_string(),
                    message: format!("{display_name} packages[{index}] {reason}"),
                });
                continue;
            }
        };
        let item_id = format!("{id_prefix}{source}");
        if !item_ids.insert(item_id.clone()) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "duplicate-id".to_string(),
                message: format!("{display_name} packages contains a duplicate source"),
            });
            continue;
        }
        let mut item = plugin_config_item(ProviderId::Pi, layer, item_id, source, enabled, path);
        item.mutability = mutability;
        item.source_fingerprint = Some(json_value_source_fingerprint(package));
        items.push(item);
    }
    validate_pi_package_vaults(
        app_state_root,
        path,
        layer,
        &mut items[package_item_start..],
        warnings,
    )?;
    discover_pi_configured_skills(
        document,
        path,
        layer,
        pi_home_root,
        project_boundary,
        target,
    )?;
    Ok(())
}

fn discover_pi_configured_skills(
    document: &serde_json::Map<String, serde_json::Value>,
    settings_path: &Path,
    layer: DiscoveryLayer,
    pi_home_root: &Path,
    project_boundary: Option<&Path>,
    target: &mut PiSettingsTarget<'_>,
) -> Result<(), DiscoveryError> {
    let PiSettingsTarget {
        live_skill_ids,
        skill_roots,
        items,
        warnings,
    } = target;
    let settings_name = settings_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("settings.json");
    let Some(value) = document.get("skills") else {
        return Ok(());
    };
    let Some(skills) = value.as_array() else {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Pi,
            layer: Some(layer),
            code: "invalid-shape".to_string(),
            message: format!("{settings_name} skills must be an array"),
        });
        return Ok(());
    };

    let settings_root = settings_path.parent().unwrap_or(settings_path);
    let mut rules = PiSkillRules::default();
    let mut rules_limited = false;
    let mut configured_roots = Vec::new();
    for (index, skill) in skills.iter().enumerate() {
        let Some(raw_path) = skill.as_str() else {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!("{settings_name} skills[{index}] must be a non-empty string"),
            });
            continue;
        };
        if raw_path.trim().is_empty() {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "invalid-shape".to_string(),
                message: format!("{settings_name} skills[{index}] must be a non-empty string"),
            });
            continue;
        }
        if raw_path.starts_with(['!', '+', '-']) || raw_path.contains(['*', '?']) {
            match rules.add(raw_path) {
                Ok(true) => {}
                Ok(false) => rules_limited = true,
                Err(_) => {
                    warnings.push(DiscoveryWarning {
                        provider: ProviderId::Pi,
                        layer: Some(layer),
                        code: "invalid-shape".to_string(),
                        message: format!("{settings_name} skills[{index}] has an invalid pattern"),
                    });
                }
            }
            continue;
        }

        let resolved_root =
            crate::config::normalize_absolute_path(raw_path, settings_root, pi_home_root);
        if resolved_root.exists()
            && project_boundary.is_some_and(|project| !path_within_scope(&resolved_root, project))
        {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "scope-outside-project".to_string(),
                message: format!("{settings_name} skills[{index}] is outside the selected project"),
            });
            continue;
        }
        let mutability = pi_configured_skill_mutability(settings_root, &resolved_root);
        let id_prefix = pi_configured_skill_id_prefix(layer, &resolved_root);
        let configured_ids = discover_pi_configured_skill_path(
            &resolved_root,
            id_prefix.as_str(),
            layer,
            mutability,
            project_boundary,
            items,
            warnings,
        )?;
        configured_roots.push((resolved_root, mutability, configured_ids));
    }

    if rules_limited {
        warnings.push(DiscoveryWarning {
            provider: ProviderId::Pi,
            layer: Some(layer),
            code: "pi-skill-rules-limited".to_string(),
            message: format!("{settings_name} skill rules exceeded the safe scan limit"),
        });
    }

    if !rules.is_empty() || rules_limited {
        for item in items.iter_mut() {
            if item.provider == ProviderId::Pi
                && item.layer == layer
                && item.category == DiscoveryCategory::Skill
                && configured_roots
                    .iter()
                    .any(|(root, _, _)| Path::new(&item.source_path).starts_with(root))
            {
                item.enabled = rules.enabled(Path::new(&item.source_path), settings_root);
                if !item.enabled || rules_limited {
                    item.mutability = DiscoveryMutability::ReadOnly;
                }
            }
        }
    }

    for (resolved_root, mutability, configured_ids) in configured_roots {
        // Physical items must shadow stale vault entries even when Pi rules disable them.
        live_skill_ids.extend(configured_ids.iter().cloned());
        let writable_ids = configured_ids
            .into_iter()
            .filter(|id| {
                items.iter().any(|item| {
                    item.provider == ProviderId::Pi
                        && item.layer == layer
                        && item.id == *id
                        && item.enabled
                        && item.mutability == DiscoveryMutability::ReadWrite
                })
            })
            .collect::<BTreeSet<_>>();
        if !writable_ids.is_empty()
            && mutability == DiscoveryMutability::ReadWrite
            && resolved_root.is_dir()
            && !skill_roots.contains(&resolved_root)
        {
            skill_roots.push(resolved_root);
        }
    }

    Ok(())
}

fn pi_configured_skill_mutability(
    settings_root: &Path,
    resolved_root: &Path,
) -> DiscoveryMutability {
    if !resolved_root.starts_with(settings_root) {
        return DiscoveryMutability::ReadOnly;
    }

    let canonical_root = fs::canonicalize(resolved_root);
    let canonical_settings_root = fs::canonicalize(settings_root);
    if canonical_root
        .as_ref()
        .ok()
        .zip(canonical_settings_root.as_ref().ok())
        .is_some_and(|(root, base)| root.starts_with(base))
    {
        DiscoveryMutability::ReadWrite
    } else {
        DiscoveryMutability::ReadOnly
    }
}

fn pi_configured_skill_id_prefix(layer: DiscoveryLayer, resolved_root: &Path) -> String {
    let prefix = match layer {
        DiscoveryLayer::Global => PI_GLOBAL_SKILL_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_SKILL_ID_PREFIX,
    };
    let scope = source_fingerprint(&resolved_root.to_string_lossy());
    format!("{prefix}@settings/{scope}/")
}

fn discover_pi_configured_skill_path(
    root: &Path,
    id_prefix: &str,
    layer: DiscoveryLayer,
    mutability: DiscoveryMutability,
    project_boundary: Option<&Path>,
    items: &mut Vec<DiscoveryItem>,
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<BTreeSet<String>, DiscoveryError> {
    let item_start = items.len();
    if root.is_dir() && root.join("SKILL.md").is_file() {
        if project_boundary
            .is_some_and(|project| !path_within_scope(&root.join("SKILL.md"), project))
        {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "scope-outside-project".to_string(),
                message: "Pi configured skill file is outside the selected project".to_string(),
            });
            return Ok(BTreeSet::new());
        }
        if fs::metadata(root.join("SKILL.md"))
            .is_ok_and(|metadata| metadata.len() > MAX_CONFIGURED_SKILL_BYTES)
        {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "scope-scan-limited".to_string(),
                message: "Pi configured skill fingerprint exceeded the scan byte limit".to_string(),
            });
        }
        push_pi_configured_skill_dir(root, id_prefix, layer, DiscoveryMutability::ReadOnly, items)?;
    } else if root.is_dir() {
        discover_configured_skill_dirs(
            root,
            SkillItemDiscoverySpec {
                provider: ProviderId::Pi,
                layer,
                id_prefix,
                mutability,
                max_fingerprint_bytes: None,
                scan_scope: project_boundary,
            },
            false,
            items,
            warnings,
        )?;
        discover_direct_skill_markdown_files(
            root,
            SkillItemDiscoverySpec {
                provider: ProviderId::Pi,
                layer,
                id_prefix: &format!("{id_prefix}@file/"),
                mutability: DiscoveryMutability::ReadOnly,
                max_fingerprint_bytes: Some(MAX_CONFIGURED_SKILL_BYTES),
                scan_scope: project_boundary,
            },
            items,
            warnings,
        )?;
    } else if root.is_file() && root.extension().and_then(OsStr::to_str) == Some("md") {
        if fs::metadata(root).is_ok_and(|metadata| metadata.len() > MAX_CONFIGURED_SKILL_BYTES) {
            warnings.push(DiscoveryWarning {
                provider: ProviderId::Pi,
                layer: Some(layer),
                code: "scope-scan-limited".to_string(),
                message: "Pi configured skill fingerprint exceeded the scan byte limit".to_string(),
            });
        }
        push_pi_configured_skill_file(
            root,
            id_prefix,
            layer,
            DiscoveryMutability::ReadOnly,
            items,
        )?;
    }

    let existing_sources = items[..item_start]
        .iter()
        .filter(|item| item.provider == ProviderId::Pi && item.layer == layer)
        .map(|item| item.source_path.clone())
        .collect::<BTreeSet<_>>();
    let mut seen_sources = existing_sources;
    let discovered = items.split_off(item_start);
    let mut live_ids = BTreeSet::new();
    for item in discovered {
        if seen_sources.insert(item.source_path.clone()) {
            live_ids.insert(item.id.clone());
            items.push(item);
        }
    }
    Ok(live_ids)
}

fn push_pi_configured_skill_dir(
    skill_dir: &Path,
    id_prefix: &str,
    layer: DiscoveryLayer,
    mutability: DiscoveryMutability,
    items: &mut Vec<DiscoveryItem>,
) -> Result<(), DiscoveryError> {
    let skill_file = skill_dir.join("SKILL.md");
    let Some(display_name) = skill_dir.file_name().and_then(OsStr::to_str) else {
        return Ok(());
    };
    let id = format!("{id_prefix}{}", skill_id_path(Path::new(display_name)));
    let source_fingerprint = skill_file_fingerprint(&skill_file, Some(MAX_CONFIGURED_SKILL_BYTES));
    items.push(DiscoveryItem {
        provider: ProviderId::Pi,
        kind: DiscoveryKind::Skill,
        category: DiscoveryCategory::Skill,
        layer,
        id,
        display_name: display_name.to_string(),
        enabled: true,
        mutability: skill_path_mutability(skill_dir, &skill_file, mutability, true)?,
        source_path: path_string(&skill_file),
        state_path: path_string(skill_dir),
        source_fingerprint,
        hook: None,
    });
    Ok(())
}

fn push_pi_configured_skill_file(
    skill_file: &Path,
    id_prefix: &str,
    layer: DiscoveryLayer,
    mutability: DiscoveryMutability,
    items: &mut Vec<DiscoveryItem>,
) -> Result<(), DiscoveryError> {
    let Some(display_name) = skill_file.file_stem().and_then(OsStr::to_str) else {
        return Ok(());
    };
    let id = format!("{id_prefix}{}", skill_id_path(Path::new(display_name)));
    let source_fingerprint = skill_file_fingerprint(skill_file, Some(MAX_CONFIGURED_SKILL_BYTES));
    let parent = skill_file.parent().unwrap_or(skill_file);
    items.push(DiscoveryItem {
        provider: ProviderId::Pi,
        kind: DiscoveryKind::Skill,
        category: DiscoveryCategory::Skill,
        layer,
        id,
        display_name: display_name.to_string(),
        enabled: true,
        mutability: skill_path_mutability(parent, skill_file, mutability, false)?,
        source_path: path_string(skill_file),
        state_path: path_string(skill_file),
        source_fingerprint,
        hook: None,
    });
    Ok(())
}

fn validate_pi_package_vaults(
    app_state_root: Option<&Path>,
    settings_path: &Path,
    layer: DiscoveryLayer,
    package_items: &mut [DiscoveryItem],
    warnings: &mut Vec<DiscoveryWarning>,
) -> Result<(), DiscoveryError> {
    let Some(app_state_root) = app_state_root else {
        return Ok(());
    };
    let provider = ProviderId::Pi;
    let vault_root = app_state_root
        .join("vault")
        .join(provider.as_str())
        .join(layer.as_str())
        .join("plugin");
    match fs::symlink_metadata(&vault_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &vault_root,
                "Pi plugin vault root must be a regular directory",
            );
            for item in package_items {
                item.mutability = DiscoveryMutability::ReadOnly;
            }
            return Ok(());
        }
        Ok(_) => {}
    }
    let mut entries = fs::read_dir(vault_root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    let expected_id_prefix = match layer {
        DiscoveryLayer::Global => PI_GLOBAL_PACKAGE_EXTENSION_ID_PREFIX,
        DiscoveryLayer::Project => PI_PROJECT_PACKAGE_EXTENSION_ID_PREFIX,
    };

    for entry in entries {
        let warning_count = warnings.len();
        let Some((entry_path, vault_entry)) = read_stored_vault_entry(
            &entry,
            provider,
            layer,
            "plugin",
            "json-payload",
            expected_id_prefix,
            warnings,
        ) else {
            if warnings.len() > warning_count {
                for item in package_items.iter_mut() {
                    item.mutability = DiscoveryMutability::ReadOnly;
                }
            }
            continue;
        };
        let package_source = vault_entry
            .item_id
            .strip_prefix(expected_id_prefix)
            .expect("stored Pi vault id prefix validated");
        let Some(item) = package_items
            .iter_mut()
            .find(|item| item.id == vault_entry.item_id)
        else {
            push_invalid_vault_entry_warning(
                warnings,
                provider,
                layer,
                &entry_path,
                "vaulted package is missing from the live Pi settings packages array",
            );
            continue;
        };
        let expected_payload = entry.path().join("payload.json");
        let invalid_reason = if Path::new(&vault_entry.original_path) != settings_path {
            Some("originalPath does not match the discovered Pi settings path")
        } else if !vault_payload_path_matches(
            Path::new(&vault_entry.vaulted_path),
            &expected_payload,
        ) {
            Some("vaultedPath does not match the entry payload path")
        } else if !fs::symlink_metadata(&vault_entry.vaulted_path)
            .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            Some("vaultedPath is not a regular file")
        } else if item.enabled {
            Some("vault exists but the live Pi package extensions are enabled")
        } else {
            let payload_matches = fs::read_to_string(&vault_entry.vaulted_path)
                .ok()
                .and_then(|raw| serde_json::from_str::<StoredPiPackageVaultPayload>(&raw).ok())
                .is_some_and(|payload| {
                    let original_matches =
                        serde_json::from_str::<serde_json::Value>(&payload.original_raw)
                            .is_ok_and(|original_raw| original_raw == payload.original_entry);
                    let disabled_matches = pi_disabled_package_entry(&payload.original_entry)
                        .ok()
                        .flatten()
                        .is_some_and(|disabled| {
                            payload.disabled_entry_fingerprint
                                == json_value_source_fingerprint(&disabled)
                        });
                    payload.package_source == package_source
                        && original_matches
                        && disabled_matches
                        && item.source_fingerprint.as_deref()
                            == Some(payload.disabled_entry_fingerprint.as_str())
                        && vault_entry.display_name == package_source
                });
            if payload_matches {
                None
            } else {
                Some("vault payload does not match the Pi package identity or disabled state")
            }
        };
        if let Some(reason) = invalid_reason {
            item.mutability = DiscoveryMutability::ReadOnly;
            push_invalid_vault_entry_warning(warnings, provider, layer, &entry_path, reason);
        }
    }
    Ok(())
}
