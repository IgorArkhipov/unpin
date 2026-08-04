import Foundation
import XCTest
@testable import UnpinDesktop

@MainActor
final class WorkspaceStoreTests: XCTestCase {
    func testLaunchStartsWithoutAnImplicitWorkspace() async {
        let store = WorkspaceStore()

        await store.launch()

        guard case .needsWorkspace = store.state else {
            return XCTFail("launch should require an explicit workspace")
        }
        XCTAssertFalse(store.hasWorkspace)
        XCTAssertEqual(store.statusMessage, "Choose a workspace folder to begin.")
    }

    func testSelectingAFileBlocksBeforeStartingTheBridge() async throws {
        let temporary = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-workspace-store-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let file = temporary.appendingPathComponent("not-a-workspace")
        try Data().write(to: file)
        let store = WorkspaceStore()

        await store.selectWorkspace(file)

        guard case .blocked(let message) = store.state else {
            return XCTFail("file selection should block")
        }
        XCTAssertEqual(message, "Choose a workspace folder, not a file.")
        XCTAssertFalse(store.hasWorkspace)
    }
}
