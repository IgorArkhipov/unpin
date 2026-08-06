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
                filters: filters
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
                filters: filters
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
                filters: DiscoverFilterState()
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
                filters: DiscoverFilterState()
            ),
            .emptyInventory
        )
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: ready,
                inventory: inventory,
                filters: DiscoverFilterState(search: "missing")
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
                    filters: filters
                ),
                .filterZero
            )
        }
        XCTAssertEqual(
            classifyDiscoverPresentation(
                presentation: ready,
                inventory: inventory,
                filters: DiscoverFilterState()
            ),
            .ready
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
        host.layoutSubtreeIfNeeded()

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

    func testWorkbenchGuidanceCollapsedRestoreControlIsAccessible() {
        var expanded = false
        let descriptor = WorkbenchGuidanceDescriptor(area: .discover)
        let binding = Binding(
            get: { expanded },
            set: { expanded = $0 }
        )

        XCTAssertEqual(descriptor.showGuidanceLabel, "Show Discover and Organize guidance")
        XCTAssertFalse(descriptor.showGuidanceLabel.isEmpty)

        binding.wrappedValue = true

        XCTAssertTrue(expanded)
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
            isPrimerExpanded: Binding(
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
        XCTAssertFalse(inputs.allowsMutation)
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
