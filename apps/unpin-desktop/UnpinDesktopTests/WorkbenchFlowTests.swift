import Foundation
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

        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let fixtureRoot = repositoryRoot
            .appendingPathComponent("crates")
            .appendingPathComponent("unpin-core")
            .appendingPathComponent("tests")
            .appendingPathComponent("fixtures", isDirectory: true)
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
}
