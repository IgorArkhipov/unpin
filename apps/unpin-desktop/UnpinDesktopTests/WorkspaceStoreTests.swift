import Foundation
import XCTest
@testable import UnpinDesktop

private actor ReadBarrier {
    private var reached = false
    private var released = false
    private var reachWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func pause() async {
        reached = true
        let reachWaiters = self.reachWaiters
        self.reachWaiters.removeAll()
        reachWaiters.forEach { $0.resume() }
        guard released == false else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilReached() async {
        guard reached == false else { return }
        await withCheckedContinuation { continuation in
            reachWaiters.append(continuation)
        }
    }

    func release() {
        released = true
        let releaseWaiters = self.releaseWaiters
        self.releaseWaiters.removeAll()
        releaseWaiters.forEach { $0.resume() }
    }
}

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

    func testDefinitionPlanRetryClearsBlockedState() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)

        await store.planDefinition(GroupDefinitionPlanParameters(
            action: "unsupported",
            scope: "personal",
            qualifiedName: nil,
            name: "retry",
            newName: nil,
            members: nil,
            expectedRevision: nil,
            historyId: nil
        ))
        guard case .blocked = store.state else {
            return XCTFail("an unsupported definition action should block")
        }

        await store.planDefinition(makeCreateParameters(name: "retry"))

        XCTAssertNotNil(store.reviewedDefinition)
        guard case .ready = store.state else {
            return XCTFail("a successful definition retry should clear the stale blocker")
        }
        await store.discardReviewedDefinition()
    }

    func testDefinitionHistoryRetryClearsBlockedState() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)

        await store.loadDefinitionHistory(scope: "unsupported")
        guard case .blocked = store.state else {
            return XCTFail("an unsupported history scope should block")
        }

        await store.loadDefinitionHistory(scope: "personal")

        guard case .ready = store.state else {
            return XCTFail("a successful history retry should clear the stale blocker")
        }
    }

    func testGroupPlanApprovalApplyAndRestoreFlowUsesFixtureBridge() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)
        let group = try await createGroup(in: store, name: "desktop-flow")

        await store.plan(group: group, target: "disable")
        XCTAssertNotNil(store.reviewedPlan)
        XCTAssertFalse(store.reviewedPlanIsApproved)

        await store.approveReviewedPlan()
        XCTAssertTrue(store.reviewedPlanIsApproved)

        await store.applyApprovedPlan()
        XCTAssertNotNil(store.lastApply)
        XCTAssertNil(store.reviewedPlan)
        XCTAssertNil(store.approvedPlanFingerprint)

        await store.refreshRecovery()
        let backup = try XCTUnwrap(store.recovery?.backups.first(where: \.restorable))
        await store.planRestore(backupID: backup.backupId)
        XCTAssertNotNil(store.reviewedRestore)
        await store.approveReviewedRestore()
        XCTAssertTrue(store.reviewedRestoreIsApproved)

        await store.applyApprovedRestore()
        XCTAssertNil(store.reviewedRestore)
        XCTAssertTrue(store.lastRestore?.status.isRestored == true)
    }

    func testApprovalMismatchClearsReviewAndDiscardLeavesNoReview() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)
        let group = try await createGroup(in: store, name: "approval-flow")

        await store.plan(group: group, target: "disable")
        await store.applyApprovedPlan()

        XCTAssertNil(store.reviewedPlan)
        XCTAssertNil(store.approvedPlanFingerprint)
        XCTAssertNotNil(store.lastChangeBlocker)

        await store.plan(group: group, target: "disable")
        XCTAssertNotNil(store.reviewedPlan)
        await store.discardReviewedPlan()
        XCTAssertNil(store.reviewedPlan)
        XCTAssertNil(store.approvedPlanFingerprint)
        XCTAssertNil(store.lastChangeBlocker)
    }

    func testRecoveryRefreshFailurePreservesEvidenceAndBlocksNewActions() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)
        await store.refreshRecovery()
        let previousRecovery = try XCTUnwrap(store.recovery)

        await store.stopBridgeForTesting()
        await store.refreshRecovery()

        XCTAssertEqual(store.recovery?.backups.map(\.backupId), previousRecovery.backups.map(\.backupId))
        XCTAssertNotNil(store.recoveryBlocker)
        guard case .blocked = store.state else {
            return XCTFail("a recovery refresh failure should block the workspace")
        }

        await store.planDefinition(makeCreateParameters(name: "blocked"))
        XCTAssertNil(store.reviewedDefinition)
        XCTAssertEqual(store.statusMessage, store.recoveryBlocker)

        await store.reloadWorkspace()
        XCTAssertNil(store.recoveryBlocker)
        guard case .ready = store.state else {
            return XCTFail("a successful workspace reload should clear the recovery blocker")
        }
    }

    func testInFlightReadsCannotPublishAfterWorkspaceSwitch() async throws {
        let fixture = try makeFixtureStore()
        defer { try? FileManager.default.removeItem(at: fixture.temporaryRoot) }
        let store = fixture.store
        await store.selectWorkspace(fixture.workspaceRoot)
        let group = try await createGroup(in: store, name: "generation-flow")
        let switchedWorkspace = fixture.temporaryRoot.appendingPathComponent("switched-workspace", isDirectory: true)
        try FileManager.default.createDirectory(
            at: switchedWorkspace.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )

        let responseBarrier = ReadBarrier()
        let errorBarrier = ReadBarrier()
        store.installTestHooksForTesting(WorkspaceStoreTestHooks(
            beforeReadResponse: { await responseBarrier.pause() },
            beforeReadError: { await errorBarrier.pause() }
        ))

        let planTask = Task { await store.plan(group: group, target: "disable") }
        await responseBarrier.waitUntilReached()

        await store.selectWorkspace(switchedWorkspace)
        guard case .ready = store.state else {
            return XCTFail("the replacement workspace should finish connecting before the old response is released")
        }
        XCTAssertNil(store.reviewedPlan)

        await responseBarrier.release()
        await planTask.value

        XCTAssertNil(store.reviewedPlan)
        XCTAssertEqual(store.workspaceName, switchedWorkspace.lastPathComponent)
        guard case .ready = store.state else {
            return XCTFail("a stale successful response should not change the replacement workspace state")
        }

        let historyTask = Task { await store.loadDefinitionHistory(scope: "unsupported") }
        await errorBarrier.waitUntilReached()

        await store.reloadWorkspace()
        guard case .ready = store.state else {
            return XCTFail("the reloaded workspace should finish connecting before the old error is released")
        }
        await errorBarrier.release()
        await historyTask.value

        XCTAssertTrue(store.definitionHistory.isEmpty)
        XCTAssertEqual(store.workspaceName, switchedWorkspace.lastPathComponent)
        guard case .ready = store.state else {
            return XCTFail("a stale read error should not block the replacement workspace")
        }
    }

    private struct FixtureStore {
        let store: WorkspaceStore
        let temporaryRoot: URL
        let workspaceRoot: URL
    }

    private func makeFixtureStore() throws -> FixtureStore {
        let temporaryRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-workspace-store-\(UUID().uuidString)", isDirectory: true)
        let workspaceRoot = temporaryRoot.appendingPathComponent("workspace", isDirectory: true)
        let appStateRoot = temporaryRoot.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(
            at: workspaceRoot.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(at: appStateRoot, withIntermediateDirectories: true)

        let repositoryRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceFixtureRoot = repositoryRoot
            .appendingPathComponent("crates")
            .appendingPathComponent("unpin-core")
            .appendingPathComponent("tests")
            .appendingPathComponent("fixtures", isDirectory: true)
        let fixtureRoot = temporaryRoot.appendingPathComponent("fixtures", isDirectory: true)
        try FileManager.default.copyItem(at: sourceFixtureRoot, to: fixtureRoot)
        let store = WorkspaceStore(bridgeRoots: BridgeLaunchRoots(
            fixtureRoot: fixtureRoot,
            homeRoot: fixtureRoot,
            appStateRoot: appStateRoot
        ))
        return FixtureStore(store: store, temporaryRoot: temporaryRoot, workspaceRoot: workspaceRoot)
    }

    private func makeCreateParameters(name: String) -> GroupDefinitionPlanParameters {
        GroupDefinitionPlanParameters(
            action: "create",
            scope: "personal",
            qualifiedName: nil,
            name: name,
            newName: nil,
            members: [GroupMemberIdentity(
                provider: "opencode",
                layer: "global",
                kind: "mcp",
                category: "configured-mcp",
                id: "opencode:global:configured-mcp:example-global"
            )],
            expectedRevision: nil,
            historyId: nil
        )
    }

    private func createGroup(in store: WorkspaceStore, name: String) async throws -> GroupSummary {
        await store.planDefinition(makeCreateParameters(name: name))
        XCTAssertNotNil(store.reviewedDefinition)
        let applied = await store.applyDefinition()
        XCTAssertTrue(applied, store.statusMessage ?? "definition apply failed without a status")
        return try XCTUnwrap(store.snapshot?.groups.first(where: { $0.qualifiedName == "personal:\(name)" }))
    }
}
