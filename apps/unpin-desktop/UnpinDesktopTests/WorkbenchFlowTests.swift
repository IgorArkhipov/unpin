import AppKit
import Foundation
import SwiftUI
import XCTest
@testable import UnpinDesktop

@MainActor
final class WorkbenchFlowTests: XCTestCase {
    func testSelectingWorkspaceLoadsFixtureInventoryThroughBundledBridge() async throws {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-workbench-flow-\(UUID().uuidString)", isDirectory: true)
        let projectRoot = temporary.appendingPathComponent("workspace", isDirectory: true)
        let appStateRoot = temporary.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: projectRoot.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: appStateRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }

        let fixtureRoot = try FixtureResources.root()
        let store = WorkspaceStore(bridgeRoots: BridgeLaunchRoots(
            fixtureRoot: fixtureRoot,
            homeRoot: fixtureRoot,
            appStateRoot: appStateRoot
        ))

        await store.selectWorkspace(projectRoot)

        guard case .ready = store.state else {
            return XCTFail("fixture workspace should become ready: \(store.statusMessage ?? "unknown")")
        }
        let snapshot = try XCTUnwrap(store.snapshot)
        XCTAssertFalse(snapshot.inventory.isEmpty)
        XCTAssertTrue(Set(snapshot.inventory.map(\.provider)).isSuperset(of: [
            "claude", "codex", "cursor", "opencode", "pi", "zed",
        ]))
        XCTAssertEqual(store.workspaceName, "workspace")
    }

    func testWorkAreasKeepWorkOrientedNavigationOrder() {
        XCTAssertEqual(
            WorkArea.allCases.map(\.title),
            [
                "Discover and Organize",
                "Govern and Automate",
                "Change Safely",
                "Recover and Audit",
            ]
        )
    }

    func testInventorySortDefaultsToDeterministicNameOrder() {
        let items = [
            inventoryItem(name: "Zulu", provider: "claude", id: "zulu"),
            inventoryItem(name: "Alpha", provider: "zed", id: "zed-alpha"),
            inventoryItem(name: "Alpha", provider: "codex", id: "codex-alpha"),
        ]

        let sorted = InventorySortState().sorted(items)

        XCTAssertEqual(sorted.map(\.id), ["codex-alpha", "zed-alpha", "zulu"])
    }

    func testInventorySortSupportsAscendingDescendingAndOrderedPriorities() {
        let items = [
            inventoryItem(name: "Beta", provider: "zed", id: "zed-beta"),
            inventoryItem(name: "Alpha", provider: "zed", id: "zed-alpha"),
            inventoryItem(name: "Beta", provider: "codex", id: "codex-beta"),
            inventoryItem(name: "Alpha", provider: "codex", id: "codex-alpha"),
        ]
        var sort = InventorySortState()

        sort.add(.provider)
        sort.move(.provider, towardStart: true)
        XCTAssertEqual(sort.descriptors.map(\.column), [.provider, .name])
        XCTAssertEqual(
            sort.sorted(items).map(\.id),
            ["codex-alpha", "codex-beta", "zed-alpha", "zed-beta"]
        )

        sort.setDirection(.descending, for: .provider)
        XCTAssertEqual(
            sort.sorted(items).map(\.id),
            ["zed-alpha", "zed-beta", "codex-alpha", "codex-beta"]
        )

        sort.move(.name, towardStart: true)
        XCTAssertEqual(sort.descriptors.map(\.column), [.name, .provider])
        XCTAssertEqual(
            sort.sorted(items).map(\.id),
            ["zed-alpha", "codex-alpha", "zed-beta", "codex-beta"]
        )
    }

    func testAgentPluginSortingAndFilteringCoverAllPackageColumns() throws {
        let packages = [
            try agentPlugin(
                name: "Zulu",
                provider: "claude",
                componentKinds: ["skill"],
                state: "off",
                access: "diagnostics-only"
            ),
            try agentPlugin(
                name: "Alpha",
                provider: "codex",
                componentKinds: ["mcp", "skill"],
                state: "on",
                access: "actionable"
            ),
        ]

        XCTAssertEqual(AgentPluginSortState().sorted(packages).map(\.name), ["Alpha", "Zulu"])
        var sort = AgentPluginSortState()
        sort.add(.provider)
        sort.remove(.name)
        sort.setDirection(.descending, for: .provider)
        XCTAssertEqual(sort.sorted(packages).map(\.providerDisplay), ["codex", "claude"])

        let filters = [
            AgentPluginFilterState(provider: "codex"),
            AgentPluginFilterState(type: "mcp"),
            AgentPluginFilterState(state: "on"),
            AgentPluginFilterState(access: "actionable"),
            AgentPluginFilterState(search: "alpha"),
        ]
        for filter in filters {
            XCTAssertEqual(packages.filter(filter.matches).map(\.name), ["Alpha"])
        }
    }

    func testAgentPluginPackageInventoryRendersInLightAndDarkThemes() throws {
        let package = try agentPlugin(
            name: "Connector Kit",
            provider: "codex",
            componentKinds: ["mcp", "skill"],
            state: "mixed",
            access: "actionable"
        )
        let presentation = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "fixture"
        )

        var renderings = [Data]()
        for scheme in [ColorScheme.light, .dark] {
            let host = NSHostingView(
                rootView: DiscoverOrganizeView(
                    inventoryOverride: [],
                    packagesOverride: [package],
                    modeOverride: .packages
                )
                .environmentObject(WorkspaceStore())
                .environment(\.workbenchPresentation, presentation)
                .preferredColorScheme(scheme)
            )
            host.frame = NSRect(x: 0, y: 0, width: 1_180, height: 760)
            let window = NSWindow(
                contentRect: host.bounds,
                styleMask: [.titled],
                backing: .buffered,
                defer: false
            )
            window.isReleasedWhenClosed = false
            window.contentView = host
            window.makeKeyAndOrderFront(nil)
            defer { window.close() }
            host.layoutSubtreeIfNeeded()
            host.displayIfNeeded()
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))
            XCTAssertGreaterThan(host.fittingSize.width, 0)
            let bitmap = try XCTUnwrap(host.bitmapImageRepForCachingDisplay(in: host.bounds))
            host.cacheDisplay(in: host.bounds, to: bitmap)
            let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
            XCTAssertFalse(png.isEmpty)
            renderings.append(png)
        }
        XCTAssertNotEqual(renderings[0], renderings[1])
    }

    func testDiscoverClassifierPrioritizesWorkspaceAndConnectionState() {
        let inventory = [inventoryItem(name: "Alpha", provider: "codex", id: "alpha")]
        let filters = DiscoverFilterState(search: "missing")

        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: .fixture(
                    state: .needsWorkspace,
                    hasWorkspace: false,
                    isBusy: false,
                    workspaceName: nil
                ),
                inventory: inventory,
                filters: filters,
                matchingInventory: []
            ),
            .needsWorkspace
        )
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: .fixture(
                    state: .loading,
                    hasWorkspace: true,
                    isBusy: true,
                    workspaceName: "fixture"
                ),
                inventory: inventory,
                filters: filters,
                matchingInventory: []
            ),
            .loading
        )
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: .fixture(
                    state: .blocked("bridge unavailable"),
                    hasWorkspace: true,
                    isBusy: false,
                    workspaceName: "fixture"
                ),
                inventory: [],
                filters: DiscoverFilterState(),
                matchingInventory: []
            ),
            .blocked("bridge unavailable")
        )
    }

    func testDiscoverClassifierDistinguishesEmptyInventoryAndFilterZero() {
        let ready = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "fixture"
        )
        let inventory = [inventoryItem(name: "Alpha", provider: "codex", id: "alpha")]

        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: ready,
                inventory: [],
                filters: DiscoverFilterState(),
                matchingInventory: []
            ),
            .emptyInventory
        )
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: ready,
                inventory: inventory,
                filters: DiscoverFilterState(search: "missing"),
                matchingInventory: []
            ),
            .filterZero
        )

        let facetFilters = [
            DiscoverFilterState(provider: "zed"),
            DiscoverFilterState(layer: "project"),
            DiscoverFilterState(category: "mcp"),
            DiscoverFilterState(state: "off"),
        ]
        for filters in facetFilters {
            XCTAssertEqual(
                classifyDiscoverPresentation(
                    presentation: ready,
                    inventory: inventory,
                    filters: filters,
                    matchingInventory: []
                ),
                .filterZero
            )
        }
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: ready,
                inventory: inventory,
                filters: DiscoverFilterState(),
                matchingInventory: inventory
            ),
            .ready
        )
    }

    func testPresentationStatusMessageMatchesRuntimeStatesForFixtures() {
        XCTAssertEqual(
            WorkbenchPresentationInputs.fixture(
                state: .needsWorkspace,
                hasWorkspace: false,
                isBusy: false,
                workspaceName: nil
            ).statusMessage,
            "Choose a workspace folder to begin."
        )
        XCTAssertEqual(
            WorkbenchPresentationInputs.fixture(
                state: .loading,
                hasWorkspace: true,
                isBusy: true,
                workspaceName: "fixture"
            ).statusMessage,
            "Connecting to the bundled Unpin bridge…"
        )
        XCTAssertNil(
            WorkbenchPresentationInputs.fixture(
                state: .ready,
                hasWorkspace: true,
                isBusy: false,
                workspaceName: "fixture"
            ).statusMessage
        )
        XCTAssertEqual(
            WorkbenchPresentationInputs.fixture(
                state: .blocked("bridge unavailable"),
                hasWorkspace: true,
                isBusy: false,
                workspaceName: "fixture"
            ).statusMessage,
            "bridge unavailable"
        )
    }

    func testDiscoverFiltersClearAllFiveDimensions() {
        let inventory = [inventoryItem(name: "Alpha", provider: "codex", id: "alpha")]
        var filters = DiscoverFilterState(
            search: "skill",
            provider: "codex",
            layer: "project",
            category: "skill",
            state: "on"
        )

        XCTAssertTrue(filters.isActive)
        XCTAssertTrue(inventory.filter(filters.matches).isEmpty)
        filters.clear()

        XCTAssertEqual(filters, DiscoverFilterState())
        XCTAssertFalse(filters.isActive)
        XCTAssertEqual(
            inventory.filter(filters.matches).map(\.id),
            inventory.map(\.id)
        )
    }

    func testGroupCreationRouteSelectsDiscoverAndPresentsOnce() {
        var navigation = WorkbenchNavigationState(workArea: .change)

        navigation.presentGroupCreation()

        XCTAssertEqual(navigation.workArea, .discover)
        XCTAssertTrue(navigation.isPresentingGroupEditor)

        navigation.isPresentingGroupEditor = false
        XCTAssertFalse(navigation.isPresentingGroupEditor)
    }

    func testInventoryFilterSelectionsFitAtDefaultWindowWidth() {
        let host = NSHostingView(
            rootView: DiscoverOrganizeView(
                inventoryOverride: [
                    inventoryItem(name: "Alpha", provider: "codex", id: "alpha"),
                ]
            )
                .environmentObject(WorkspaceStore())
        )
        host.frame = NSRect(x: 0, y: 0, width: 1_180, height: 760)
        let window = NSWindow(
            contentRect: host.bounds,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = host
        window.makeKeyAndOrderFront(nil)
        defer { window.close() }
        host.layoutSubtreeIfNeeded()
        host.displayIfNeeded()
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))

        let popupButtons = host.descendants(of: NSPopUpButton.self)
        let expectedTitles = ["All provider", "All layer", "All category", "Any state"]

        for title in expectedTitles {
            let popup = popupButtons.first { $0.titleOfSelectedItem == title }
            XCTAssertNotNil(popup, "Missing filter selection named \(title)")
            if let popup {
                XCTAssertGreaterThanOrEqual(
                    popup.bounds.width,
                    popup.fittingSize.width,
                    "Filter selection \(title) is clipped at the default window width"
                )
            }
        }
    }

    func testInventoryFiltersDeclareMeaningfulAccessibilityLabels() {
        XCTAssertEqual(
            WorkbenchFilterAccessibility.discoverLabels,
            ["Provider", "Layer", "Category", "State"]
        )
        XCTAssertEqual(
            WorkbenchFilterAccessibility.groupLabels,
            ["Provider", "Layer", "Category", "State", "Membership"]
        )
        XCTAssertTrue(
            (WorkbenchFilterAccessibility.discoverLabels + WorkbenchFilterAccessibility.groupLabels)
                .allSatisfy { !$0.isEmpty }
        )
    }

    func testWorkbenchOffersExactlyLightAndDarkAppearances() {
        XCTAssertEqual(WorkbenchColorScheme.allCases, [.light, .dark])
        XCTAssertEqual(WorkbenchColorScheme.allCases.map(\.title), ["Light", "Dark"])
        XCTAssertEqual(WorkbenchColorScheme.defaultValue, .dark)
    }

    func testWorkbenchAppearanceResolutionIsDeterministic() {
        XCTAssertEqual(WorkbenchColorScheme.resolve(storedValue: "light"), .light)
        XCTAssertEqual(WorkbenchColorScheme.resolve(storedValue: "dark"), .dark)
        XCTAssertEqual(WorkbenchColorScheme.resolve(storedValue: "unsupported"), .dark)
        XCTAssertEqual(WorkbenchPalette.resolve(for: .light).scheme, .light)
        XCTAssertEqual(WorkbenchPalette.resolve(for: .dark).scheme, .dark)
    }

    func testWorkbenchAppearanceSelectionPersistsInIsolatedDefaults() throws {
        let suiteName = "unpin-workbench-appearance-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let first = WorkbenchAppearanceStorageProbe(defaults: defaults)
        XCTAssertEqual(first.value, WorkbenchColorScheme.defaultValue.rawValue)

        first.value = WorkbenchColorScheme.light.rawValue
        XCTAssertEqual(WorkbenchAppearanceStorageProbe(defaults: defaults).value, "light")

        first.value = WorkbenchColorScheme.dark.rawValue
        XCTAssertEqual(WorkbenchAppearanceStorageProbe(defaults: defaults).value, "dark")
    }

    func testWorkbenchGuidanceDefaultsExpandEachAreaAndPersistIndependently() throws {
        let suiteName = "unpin-workbench-guidance-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let discover = WorkbenchGuidanceStorageProbe(area: .discover, defaults: defaults)
        let govern = WorkbenchGuidanceStorageProbe(area: .govern, defaults: defaults)
        let change = WorkbenchGuidanceStorageProbe(area: .change, defaults: defaults)
        let recover = WorkbenchGuidanceStorageProbe(area: .recover, defaults: defaults)

        XCTAssertTrue(discover.value)
        XCTAssertTrue(govern.value)
        XCTAssertTrue(change.value)
        XCTAssertTrue(recover.value)

        discover.value = false

        XCTAssertFalse(WorkbenchGuidanceStorageProbe(area: .discover, defaults: defaults).value)
        XCTAssertTrue(WorkbenchGuidanceStorageProbe(area: .govern, defaults: defaults).value)
        XCTAssertTrue(WorkbenchGuidanceStorageProbe(area: .change, defaults: defaults).value)
        XCTAssertTrue(WorkbenchGuidanceStorageProbe(area: .recover, defaults: defaults).value)
    }

    func testWorkbenchGuidanceDisclosureControlPersistsCollapseAndRestore() throws {
        let suiteName = "unpin-workbench-guidance-control-\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        defer { defaults.removePersistentDomain(forName: suiteName) }

        var isExpanded = true
        let guidanceBinding = Binding(
            get: { isExpanded },
            set: { value in
                isExpanded = value
                defaults.set(value, forKey: WorkbenchGuidanceStorage.key(for: .discover))
            }
        )
        let descriptor = WorkbenchGuidanceDescriptor(area: .discover)
        let hideControl = WorkbenchGuidanceToggleButton(
            title: descriptor.hideGuidanceLabel,
            systemImage: "chevron.up",
            accessibilityIdentifier: "workbench-guidance-discover-hide",
            allowsDisclosure: true,
            targetExpanded: false,
            isExpanded: guidanceBinding
        )
        hideControl.activate()
        XCTAssertFalse(isExpanded)
        XCTAssertEqual(
            defaults.object(forKey: WorkbenchGuidanceStorage.key(for: .discover)) as? Bool,
            false
        )

        let showControl = WorkbenchGuidanceToggleButton(
            title: descriptor.showGuidanceLabel,
            systemImage: "questionmark.circle",
            accessibilityIdentifier: "workbench-guidance-discover-restore",
            allowsDisclosure: true,
            targetExpanded: true,
            isExpanded: guidanceBinding
        )
        showControl.activate()
        XCTAssertTrue(isExpanded)

        XCTAssertEqual(
            defaults.object(forKey: WorkbenchGuidanceStorage.key(for: .discover)) as? Bool,
            true
        )
    }

    func testWorkbenchRenderBoundaryKeepsPrimerVisibleWithoutWorkspace() {
        var expanded = true
        let boundary = WorkbenchRenderBoundary(
            workArea: .discover,
            presentation: .fixture(
                state: .needsWorkspace,
                hasWorkspace: false,
                isBusy: false,
                workspaceName: nil
            ),
            isGuidanceExpanded: Binding(
                get: { expanded },
                set: { expanded = $0 }
            )
        ) {
            WorkbenchWorkspaceStateView(
                title: "Choose a workspace",
                message: "Workspace evidence is unavailable.",
                actionTitle: nil,
                action: nil
            )
        }
        XCTAssertEqual(boundary.presentation.state, .needsWorkspace)
        XCTAssertEqual(
            boundary.guidanceDescriptor,
            WorkbenchGuidanceDescriptor(area: .discover)
        )
    }

    func testWorkbenchBusyPresentationKeepsSafeControlsAvailable() {
        let inputs = WorkbenchPresentationInputs.fixture(
            state: .loading,
            hasWorkspace: true,
            isBusy: true,
            workspaceName: "fixture"
        )

        XCTAssertTrue(inputs.allowsNavigation)
        XCTAssertTrue(inputs.allowsGuidanceDisclosure)
        XCTAssertTrue(inputs.allowsCopy)
        XCTAssertFalse(inputs.allowsWorkspaceMutation)
    }

    func testGroupEditorFilterSelectionsFitAtCaptureWidth() {
        let host = NSHostingView(
            rootView: GroupEditorView(group: nil)
                .environmentObject(WorkspaceStore())
        )
        host.frame = NSRect(x: 0, y: 0, width: 1_040, height: 720)
        host.layoutSubtreeIfNeeded()

        let popupButtons = host.descendants(of: NSPopUpButton.self)
        let expectedTitles = [
            "All provider",
            "All layer",
            "All category",
            "Any state",
            "All items",
        ]

        for title in expectedTitles {
            let popup = popupButtons.first { $0.titleOfSelectedItem == title }
            XCTAssertNotNil(popup, "Missing group filter selection named \(title)")
            if let popup {
                XCTAssertGreaterThanOrEqual(
                    popup.bounds.width,
                    popup.fittingSize.width,
                    "Group filter selection \(title) is clipped at the capture width"
                )
            }
        }
    }

    func testInventoryFilterRevisionNormalizesSameSecondReplacement() {
        let original = [inventoryItem(name: "Claude skill", provider: "claude", id: "old")]
        let replacement = [inventoryItem(
            name: "Zed MCP",
            provider: "zed",
            id: "new",
            category: "mcp",
            layer: "project"
        )]

        XCTAssertNotEqual(
            InventoryFilterRevision(inventory: original),
            InventoryFilterRevision(inventory: replacement),
            "Facet revision must change even when a bridge snapshot shares capturedAtUnix"
        )

        let normalized = normalizedInventoryFacetSelection(
            InventoryFacetSelection(provider: "claude", layer: "global", category: "skill"),
            facets: InventoryFacets(inventory: replacement)
        )
        XCTAssertEqual(normalized, InventoryFacetSelection())
    }

    func testDiscoverFacetReplacementDoesNotRemainInStaleFilterZeroState() {
        let original = [inventoryItem(name: "Claude skill", provider: "claude", id: "old")]
        let replacement = [inventoryItem(
            name: "Zed MCP",
            provider: "zed",
            id: "new",
            category: "mcp",
            layer: "project"
        )]
        let workspace = WorkspaceStore()
        let host = NSHostingView(
            rootView: DiscoverOrganizeView(
                inventoryOverride: original,
                filtersOverride: DiscoverFilterState(
                    provider: "claude",
                    layer: "global",
                    category: "skill"
                )
            )
                .environmentObject(workspace)
        )
        host.frame = NSRect(x: 0, y: 0, width: 1_180, height: 760)
        host.layoutSubtreeIfNeeded()

        host.rootView = DiscoverOrganizeView(inventoryOverride: replacement)
            .environmentObject(workspace)
        host.layoutSubtreeIfNeeded()
        let deadline = Date(timeIntervalSinceNow: 1)
        var selectedTitles = Set<String>()
        repeat {
            host.layoutSubtreeIfNeeded()
            selectedTitles = Set(
                host.descendants(of: NSPopUpButton.self).compactMap(\.titleOfSelectedItem)
            )
            if selectedTitles.isSuperset(of: ["All provider", "All layer", "All category"]) {
                break
            }
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01))
        } while Date() < deadline

        XCTAssertTrue(selectedTitles.contains("All provider"))
        XCTAssertTrue(selectedTitles.contains("All layer"))
        XCTAssertTrue(selectedTitles.contains("All category"))
        XCTAssertFalse(
            host.descendants(of: NSButton.self).contains { $0.title == "Clear filters" },
            "a removed facet must be normalized before the view settles in filterZero"
        )
    }

    func testGroupMemberFilterCoversEveryDimension() {
        let target = inventoryItem(
            name: "Alpha skill",
            provider: "codex",
            id: "target",
            category: "skill",
            layer: "project",
            enabled: true
        )
        let selectedKeys = Set([groupMemberKey(for: target)])
        var filter = GroupMemberFilterState()

        XCTAssertTrue(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))

        filter.provider = "claude"
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
        filter = GroupMemberFilterState(layer: "global")
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
        filter = GroupMemberFilterState(category: "mcp")
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
        filter = GroupMemberFilterState(state: "off")
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))

        filter = GroupMemberFilterState(membership: "included")
        XCTAssertTrue(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
        filter.membership = "excluded"
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))

        filter = GroupMemberFilterState(search: "alpha")
        XCTAssertTrue(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
        filter.search = "missing"
        XCTAssertFalse(matchesGroupMemberFilter(target, selectedMemberKeys: selectedKeys, filter: filter))
    }

    func testGovernHandoffCatalogSeparatesVerifiedAndUnavailablePaths() {
        XCTAssertEqual(
            GovernHandoff.catalog.map(\.id),
            ["profiles", "gateways", "sessions", "hooks", "native-controls"]
        )

        for handoff in GovernHandoff.catalog.prefix(4) {
            guard case .verified(let cliCommand, let mcpToolIDs) = handoff.availability else {
                return XCTFail("\(handoff.id) should provide a verified CLI and MCP handoff")
            }
            XCTAssertTrue(cliCommand.hasPrefix("unpin "))
            XCTAssertFalse(mcpToolIDs.isEmpty)
            XCTAssertEqual(handoff.copyableValues, [cliCommand] + mcpToolIDs)
        }

        guard case .unavailable(let reason) = GovernHandoff.catalog.last?.availability else {
            return XCTFail("native desktop automation should remain explicitly unavailable")
        }
        XCTAssertFalse(reason.isEmpty)
        XCTAssertTrue(GovernHandoff.catalog.last?.copyableValues.isEmpty == true)
    }

    func testChangeClassifierDistinguishesPrerequisiteStates() {
        XCTAssertEqual(
            classifyChangePresentation(
                presentation: .fixture(
                    state: .needsWorkspace,
                    hasWorkspace: false,
                    isBusy: false,
                    workspaceName: nil
                ),
                snapshotAvailable: false,
                groupCount: 0
            ),
            .needsWorkspace
        )
        XCTAssertEqual(
            classifyChangePresentation(
                presentation: .fixture(
                    state: .loading,
                    hasWorkspace: true,
                    isBusy: true,
                    workspaceName: "fixture"
                ),
                snapshotAvailable: false,
                groupCount: 0
            ),
            .loading
        )
        XCTAssertEqual(
            classifyChangePresentation(
                presentation: .fixture(
                    state: .blocked("bridge unavailable"),
                    hasWorkspace: true,
                    isBusy: false,
                    workspaceName: "fixture"
                ),
                snapshotAvailable: false,
                groupCount: 0
            ),
            .blocked("bridge unavailable")
        )
        let ready = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "fixture"
        )
        XCTAssertEqual(
            classifyChangePresentation(
                presentation: ready,
                snapshotAvailable: true,
                groupCount: 0
            ),
            .noGroups
        )
        XCTAssertEqual(
            classifyChangePresentation(
                presentation: ready,
                snapshotAvailable: true,
                groupCount: 1
            ),
            .ready
        )
    }

    func testRecoverClassifierPreservesEvidenceAndSelectionStates() {
        let ready = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "fixture"
        )

        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: .fixture(
                    state: .needsWorkspace,
                    hasWorkspace: false,
                    isBusy: false,
                    workspaceName: nil
                ),
                facts: RecoverPresentationFacts()
            ),
            .needsWorkspace
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: .fixture(
                    state: .loading,
                    hasWorkspace: true,
                    isBusy: true,
                    workspaceName: "fixture"
                ),
                facts: RecoverPresentationFacts()
            ),
            .loading
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(hasRecovery: true)
            ),
            .emptyEvidence
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(hasRecovery: true, hasEvidence: true)
            ),
            .noSelection
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(
                    hasRecovery: true,
                    hasEvidence: true,
                    selectedBackupExists: true
                )
            ),
            .backupSelected
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(
                    hasRecovery: true,
                    hasEvidence: true,
                    selectedOperationExists: true
                )
            ),
            .operationSelected
        )

        let unavailable = classifyRecoverPresentation(
            presentation: .fixture(
                state: .blocked("recovery unavailable"),
                hasWorkspace: true,
                isBusy: false,
                workspaceName: "fixture"
            ),
            facts: RecoverPresentationFacts(hasRecovery: true, hasEvidence: true)
        )
        XCTAssertEqual(
            unavailable,
            .unavailable(message: "recovery unavailable", preservesEvidence: true)
        )
    }

    func testRecoverClassifierCoversRefreshBlockersAndSelectionPrecedence() {
        let ready = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "fixture"
        )
        let refreshing = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: true,
            workspaceName: "fixture"
        )

        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: refreshing,
                facts: RecoverPresentationFacts(hasRecovery: false)
            ),
            .loading
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(
                    blocker: "Recovery refresh failed"
                )
            ),
            .unavailable(
                message: "Recovery refresh failed",
                preservesEvidence: false
            )
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(
                    hasRecovery: true,
                    hasEvidence: true,
                    evidenceAvailable: false
                )
            ),
            .unavailable(
                message: "Some authenticated backup or durable operation evidence is unavailable.",
                preservesEvidence: true
            )
        )
        XCTAssertEqual(
            classifyRecoverPresentation(
                presentation: ready,
                facts: RecoverPresentationFacts(
                    hasRecovery: true,
                    hasEvidence: true,
                    selectedBackupExists: true,
                    selectedOperationExists: true
                )
            ),
            .backupSelected
        )
    }

    func testRecoverEmptyEvidenceRouteSelectsChangeSafely() {
        var navigation = WorkbenchNavigationState(workArea: .recover)

        navigation.presentChange()

        XCTAssertEqual(navigation.workArea, .change)
    }

    func testGovernViewCopiesEveryVerifiedValueExactlyOnce() {
        var copiedValues = [String]()
        let view = GovernAutomateView(
            clipboardWriter: GovernClipboardWriter { copiedValues.append($0) }
        )
        let expectedValues = GovernHandoff.catalog.flatMap(\.copyableValues)

        expectedValues.forEach { view.copy($0, statusLabel: $0) }

        XCTAssertEqual(copiedValues, expectedValues)
    }

    private func inventoryItem(
        name: String,
        provider: String,
        id: String,
        kind: String = "skill",
        category: String = "skill",
        layer: String = "global",
        enabled: Bool = true,
        mutability: String = "read-write"
    ) -> InventoryItem {
        InventoryItem(
            provider: provider,
            kind: kind,
            category: category,
            layer: layer,
            id: id,
            displayName: name,
            enabled: enabled,
            mutability: mutability
        )
    }

    private func agentPlugin(
        name: String,
        provider: String,
        componentKinds: [String],
        state: String,
        access: String
    ) throws -> AgentPluginSummary {
        let kinds = try String(
            data: JSONEncoder().encode(componentKinds),
            encoding: .utf8
        ).map { $0 } ?? "[]"
        return try JSONDecoder().decode(
            AgentPluginSummary.self,
            from: Data(#"""
            {
              "logicalId":"agent-plugin:\#(name):\#(provider)",
              "name":"\#(name)",
              "componentSignature":"\#(componentKinds.joined(separator: "+"))",
              "projectionFingerprint":"sha256:projection-\#(provider)",
              "state":"\#(state)",
              "access":"\#(access)",
              "providers":["\#(provider)"],
              "componentKinds":\#(kinds),
              "instanceCount":0,
              "instances":[]
            }
            """#.utf8)
        )
    }
}

private struct WorkbenchAppearanceStorageProbe {
    @AppStorage(WorkbenchColorScheme.storageKey)
    var value = WorkbenchColorScheme.defaultValue.rawValue

    init(defaults: UserDefaults) {
        _value = AppStorage(
            wrappedValue: WorkbenchColorScheme.defaultValue.rawValue,
            WorkbenchColorScheme.storageKey,
            store: defaults
        )
    }
}

private struct WorkbenchGuidanceStorageProbe {
    @AppStorage(WorkbenchGuidanceStorage.key(for: .discover))
    var value = true

    init(area: WorkArea, defaults: UserDefaults) {
        _value = AppStorage(
            wrappedValue: true,
            WorkbenchGuidanceStorage.key(for: area),
            store: defaults
        )
    }
}

private extension NSView {
    func descendants<ViewType: NSView>(of type: ViewType.Type) -> [ViewType] {
        subviews.flatMap { subview in
            (subview as? ViewType).map { [$0] } ?? []
                + subview.descendants(of: type)
        }
    }
}
