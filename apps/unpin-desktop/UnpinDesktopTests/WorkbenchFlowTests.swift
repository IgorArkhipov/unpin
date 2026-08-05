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

    func testInventoryFilterSelectionsFitAtDefaultWindowWidth() {
        let host = NSHostingView(
            rootView: DiscoverOrganizeView()
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

    private func inventoryItem(
        name: String,
        provider: String,
        id: String
    ) -> InventoryItem {
        InventoryItem(
            provider: provider,
            kind: "skill",
            category: "skill",
            layer: "global",
            id: id,
            displayName: name,
            enabled: true,
            mutability: "read-write"
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
