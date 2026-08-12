use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    time::{Duration, Instant},
};

use unpin_core::discovery::{DiscoveryOutput, DiscoveryRoots, ProviderId, discover_all};

const CI_DIRECTORY_COUNT: usize = 192;
const BENCHMARK_DIRECTORY_COUNTS: [usize; 3] = [256, 2_048, 8_192];
const SKILL_INTERVAL: usize = 16;
const WARM_RUNS: usize = 5;
const AGENT_PLUGIN_PACKAGE_COUNT: usize = 128;

struct ProjectSkillFixture {
    _home_root: tempfile::TempDir,
    _repository_parent: tempfile::TempDir,
    _cursor_root: tempfile::TempDir,
    roots: DiscoveryRoots,
    skill_names: Vec<String>,
}

#[test]
fn large_project_scope_fixture_is_complete_and_deterministic() {
    let fixture = project_skill_fixture(CI_DIRECTORY_COUNT);

    let first = discover_all(&fixture.roots).expect("first discovery succeeds");
    let second = discover_all(&fixture.roots).expect("second discovery succeeds");

    assert_discovery_matches(&first, &second);
    assert!(
        first.warnings.is_empty(),
        "unexpected warnings: {:#?}",
        first.warnings
    );
    for name in fixture.skill_names {
        assert!(
            first.items.iter().any(|item| item.display_name == name),
            "missing project skill {name}"
        );
    }

    let providers = first
        .items
        .iter()
        .map(|item| item.provider)
        .collect::<BTreeSet<_>>();
    for provider in [ProviderId::Claude, ProviderId::Codex, ProviderId::Cursor] {
        assert!(
            providers.contains(&provider),
            "missing {provider:?} project skills"
        );
    }
}

#[test]
fn large_agent_plugin_fixture_projects_deterministically() {
    let fixture = tempfile::TempDir::new().expect("temporary Agent Plugins benchmark fixture");
    let mut config = String::new();
    for index in 0..AGENT_PLUGIN_PACKAGE_COUNT {
        let native_id = format!("plugin-{index:03}@benchmark");
        config.push_str(&format!("[plugins.\"{native_id}\"]\nenabled = true\n\n"));
        let package = fixture.path().join(format!(
            "codex/global/plugins/cache/benchmark/plugin-{index:03}/1.0.0"
        ));
        write_file(
            &package.join("plugin.json"),
            &format!(
                "{{\"$schema\":\"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json\",\"name\":\"plugin-{index:03}\"}}"
            ),
        );
        write_file(
            &package.join("skills/benchmark/SKILL.md"),
            "---\nname: benchmark\ndescription: Benchmark package projection.\n---\nBenchmark.\n",
        );
    }
    write_file(&fixture.path().join("codex/global/config.toml"), &config);
    let roots = DiscoveryRoots::fixture_root(fixture.path());

    let (first, first_duration) = timed_discovery(&roots);
    let (second, second_duration) = timed_discovery(&roots);
    assert_discovery_matches(&first, &second);
    assert_eq!(first.agent_plugins().len(), AGENT_PLUGIN_PACKAGE_COUNT);
    eprintln!(
        "Agent Plugins benchmark packages={} first={first_duration:?} second={second_duration:?}",
        AGENT_PLUGIN_PACKAGE_COUNT
    );
}

#[test]
#[ignore = "manual discovery performance baseline; run with --ignored --nocapture"]
fn benchmarks_large_project_scope_discovery() {
    for directory_count in BENCHMARK_DIRECTORY_COUNTS {
        benchmark_project_scope_discovery(directory_count);
    }
}

fn benchmark_project_scope_discovery(directory_count: usize) {
    let fixture = project_skill_fixture(directory_count);
    let scope_only_fixture = project_scope_fixture(directory_count, false);
    let mut selected_roots = fixture.roots.clone();
    selected_roots.scan_project_scopes = false;

    let (selected, selected_duration) = timed_discovery(&selected_roots);
    let (_, scope_enumeration_duration) = timed_discovery(&scope_only_fixture.roots);
    let (first_full, first_full_duration) = timed_discovery(&fixture.roots);
    let mut warm_durations = Vec::with_capacity(WARM_RUNS);

    for _ in 0..WARM_RUNS {
        let (discovery, duration) = timed_discovery(&fixture.roots);
        assert_discovery_matches(&first_full, &discovery);
        warm_durations.push(duration);
    }

    warm_durations.sort();
    let warm_median = warm_durations[warm_durations.len() / 2];
    let scope_enumeration_estimate = scope_enumeration_duration.saturating_sub(selected_duration);
    let skill_root_walk_estimate = first_full_duration.saturating_sub(scope_enumeration_duration);
    eprintln!(
        "discovery benchmark directories={directory_count} skills={} items={} selected_provider_baseline={selected_duration:?} scope_enumeration_estimate={scope_enumeration_estimate:?} skill_root_walk_estimate={skill_root_walk_estimate:?} first_full={first_full_duration:?} warm_median={warm_median:?}",
        fixture.skill_names.len(),
        first_full.items.len(),
    );
    assert!(
        selected.items.len() <= first_full.items.len(),
        "scoped discovery cannot contain more items than a complete repository scan"
    );
}

fn timed_discovery(roots: &DiscoveryRoots) -> (DiscoveryOutput, Duration) {
    let started = Instant::now();
    let discovery = discover_all(roots).expect("discovery succeeds");
    (discovery, started.elapsed())
}

fn assert_discovery_matches(expected: &DiscoveryOutput, actual: &DiscoveryOutput) {
    assert_eq!(
        actual.items, expected.items,
        "discovery items changed between runs"
    );
    assert_eq!(
        actual.warnings, expected.warnings,
        "discovery warnings changed between runs"
    );
}

fn project_skill_fixture(directory_count: usize) -> ProjectSkillFixture {
    project_scope_fixture(directory_count, true)
}

fn project_scope_fixture(directory_count: usize, include_skills: bool) -> ProjectSkillFixture {
    let home_root = tempfile::TempDir::new().expect("temporary home root");
    let repository_parent = tempfile::TempDir::new().expect("temporary repository parent");
    let cursor_root = tempfile::TempDir::new().expect("temporary cursor root");
    let repository_root = repository_parent.path().join("repository");
    let project_root = repository_root.join("workspace").join("app");
    write_file(
        &repository_root.join(".git"),
        "gitdir: /tmp/unpin-discovery-benchmark.git\n",
    );
    fs::create_dir_all(&project_root).expect("create selected project root");
    if include_skills {
        write_file(
            &repository_root
                .join(".agents")
                .join("skills")
                .join("benchmark-codex-ancestor")
                .join("SKILL.md"),
            "# Benchmark Codex ancestor skill\n",
        );
    }

    let mut skill_names = Vec::new();
    for index in 0..directory_count {
        let module_root = project_root
            .join("packages")
            .join(format!("group-{:03}", index / 32))
            .join(format!("module-{index:05}"));
        write_file(
            &module_root.join("src").join("generated").join("file.txt"),
            "fixture\n",
        );

        if include_skills && index % SKILL_INTERVAL == 0 {
            let skill_name = format!("benchmark-{index:05}");
            for relative_root in [".claude/skills", ".agents/skills", ".cursor/skills"] {
                write_file(
                    &module_root
                        .join(relative_root)
                        .join(&skill_name)
                        .join("SKILL.md"),
                    "# Benchmark skill\n",
                );
            }
            skill_names.push(skill_name);
        }
    }

    let mut roots =
        DiscoveryRoots::from_locations(home_root.path(), &project_root, cursor_root.path());
    roots.codex_admin = home_root.path().join("empty-codex-admin");

    ProjectSkillFixture {
        roots,
        _home_root: home_root,
        _repository_parent: repository_parent,
        _cursor_root: cursor_root,
        skill_names,
    }
}

fn write_file(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directory");
    }
    fs::write(path, contents).expect("write fixture file");
}
