import Combine
import Foundation

struct InventoryFacets {
    let providers: [String]
    let layers: [String]
    let categories: [String]

    init(inventory: [InventoryItem]) {
        var providers = Set<String>()
        var layers = Set<String>()
        var categories = Set<String>()
        for item in inventory {
            providers.insert(item.provider)
            layers.insert(item.layer)
            categories.insert(item.category)
        }
        self.providers = providers.sorted()
        self.layers = layers.sorted()
        self.categories = categories.sorted()
    }
}

struct WorkspaceStoreTestHooks {
    var beforeReadResponse: (() async -> Void)?
    var beforeReadError: (() async -> Void)?
    var beforeDefinitionApply: (() async -> Void)?
    var beforeWorkspaceConnect: (() async throws -> Void)?

    init(
        beforeReadResponse: (() async -> Void)? = nil,
        beforeReadError: (() async -> Void)? = nil,
        beforeDefinitionApply: (() async -> Void)? = nil,
        beforeWorkspaceConnect: (() async throws -> Void)? = nil
    ) {
        self.beforeReadResponse = beforeReadResponse
        self.beforeReadError = beforeReadError
        self.beforeDefinitionApply = beforeDefinitionApply
        self.beforeWorkspaceConnect = beforeWorkspaceConnect
    }
}

@MainActor
final class WorkspaceStore: ObservableObject {
    enum State { case needsWorkspace, loading, ready, blocked(String) }

    private static let recoveryUnavailableMessage =
        "Recovery evidence is unavailable. The last known evidence is preserved; refresh Recover and Audit or reload the workspace before trying another change."

    @Published private(set) var state: State = .needsWorkspace
    @Published private(set) var snapshot: BridgeSnapshot?
    @Published private(set) var reviewedPlan: GroupPlan?
    @Published private(set) var approvedPlanFingerprint: String?
    @Published private(set) var lastChangeBlocker: String?
    @Published private(set) var lastApply: GroupApplyResult?
    @Published private(set) var reviewedDefinition: GroupDefinitionPlanEnvelope?
    @Published private(set) var definitionHistory: [GroupDefinitionHistory] = []
    @Published private(set) var recovery: RecoverySnapshot?
    @Published private(set) var recoveryBlocker: String?
    @Published private(set) var reviewedRestore: RestorePlanEnvelope?
    @Published private(set) var approvedRestoreFingerprint: String?
    @Published private(set) var lastRestoreBlocker: String?
    @Published private(set) var lastRestore: RestoreApplyResult?
    @Published private(set) var workspaceName: String?

    private var bridge: BridgeClient?
    private var workspaceRoot: URL?
    private var connectionGeneration = 0
    private let bridgeRoots: BridgeLaunchRoots
    private var testHooks = WorkspaceStoreTestHooks()
    @Published private(set) var controlRequestInFlight = false

    init(bridgeRoots: BridgeLaunchRoots = BridgeLaunchRoots()) {
        self.bridgeRoots = bridgeRoots
    }

    func installTestHooksForTesting(_ hooks: WorkspaceStoreTestHooks) {
        testHooks = hooks
    }

    var statusMessage: String? {
        switch state {
        case .needsWorkspace: "Choose a workspace folder to begin."
        case .loading: "Connecting to the bundled Unpin bridge…"
        case .ready: nil
        case .blocked(let message): message
        }
    }

    var reviewedPlanIsApproved: Bool {
        reviewedPlan?.planFingerprint == approvedPlanFingerprint
    }

    var reviewedRestoreIsApproved: Bool {
        reviewedRestore?.plan.planFingerprint == approvedRestoreFingerprint
    }

    var hasWorkspace: Bool { workspaceRoot != nil }

    var actionsBlocked: Bool { recoveryBlocker != nil }

    var isBusy: Bool {
        if case .loading = state { return true }
        return controlRequestInFlight
    }

    func launch() async {
        state = .needsWorkspace
    }

    func selectWorkspace(_ root: URL) async {
        guard controlRequestInFlight == false else { return }
        let selectedRoot = root.standardizedFileURL
        guard selectedRoot.hasDirectoryPath else {
            state = .blocked("Choose a workspace folder, not a file.")
            return
        }
        let preserveRecovery = workspaceRoot == selectedRoot
        if preserveRecovery == false {
            recovery = nil
            recoveryBlocker = nil
        }
        workspaceRoot = selectedRoot
        workspaceName = selectedRoot.lastPathComponent
        connectionGeneration &+= 1
        await connectWorkspace(
            root: selectedRoot,
            generation: connectionGeneration,
            loadRecovery: preserveRecovery && (recovery != nil || recoveryBlocker != nil),
            preserveRecovery: preserveRecovery
        )
    }

    func reloadWorkspace() async {
        guard controlRequestInFlight == false else { return }
        guard let workspaceRoot else {
            state = .needsWorkspace
            return
        }
        let preserveRecovery = recovery != nil || recoveryBlocker != nil
        let loadRecovery = recovery != nil || recoveryBlocker != nil
        connectionGeneration &+= 1
        await connectWorkspace(
            root: workspaceRoot,
            generation: connectionGeneration,
            loadRecovery: loadRecovery,
            preserveRecovery: preserveRecovery
        )
    }

    private func connectWorkspace(
        root: URL,
        generation: Int,
        loadRecovery: Bool,
        preserveRecovery: Bool
    ) async {
        guard connectionIsCurrent(generation) else { return }
        state = .loading
        let previousBridge = bridge
        if let previousBridge, await previousBridge.stop() == false {
            guard connectionIsCurrent(generation) else { return }
            if preserveRecovery {
                setRecoveryUnavailable()
            } else {
                state = .blocked("Unpin is still confirming a configuration change. Wait for it to finish before reloading the workspace.")
            }
            return
        }
        guard connectionIsCurrent(generation) else { return }
        bridge = nil
        clearWorkspaceState(preservingRecovery: preserveRecovery)
        var replacement: BridgeClient?
        do {
            if let hook = testHooks.beforeWorkspaceConnect {
                try await hook()
            }
            let bundledBridge = try Self.bundledBridge()
            let bridge = BridgeClient(
                executableURL: bundledBridge.executable,
                projectRoot: root,
                manifest: bundledBridge.manifest,
                roots: bridgeRoots
            )
            replacement = bridge
            try await bridge.start()
            guard connectionIsCurrent(generation) else {
                await bridge.stop()
                return
            }
            _ = try await bridge.handshake()
            guard connectionIsCurrent(generation) else {
                await bridge.stop()
                return
            }
            self.bridge = bridge
            try await refresh(connectionGeneration: generation)
            guard connectionIsCurrent(generation) else { return }
            if loadRecovery {
                await refreshRecovery(connectionGeneration: generation)
            } else {
                recoveryBlocker = nil
            }
        } catch {
            if let replacement {
                await replacement.stop()
            }
            guard connectionIsCurrent(generation) else { return }
            if preserveRecovery {
                setRecoveryUnavailable()
            } else {
                state = .blocked(error.localizedDescription)
            }
        }
    }

    private func connectionIsCurrent(_ generation: Int) -> Bool {
        generation == connectionGeneration
    }

    private func awaitReadResponseHook() async {
        if let hook = testHooks.beforeReadResponse {
            await hook()
        }
    }

    private func awaitReadErrorHook() async {
        if let hook = testHooks.beforeReadError {
            await hook()
        }
    }

    private func clearWorkspaceState(preservingRecovery: Bool) {
        snapshot = nil
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
        lastApply = nil
        reviewedDefinition = nil
        definitionHistory = []
        if preservingRecovery == false {
            recovery = nil
            recoveryBlocker = nil
        }
        reviewedRestore = nil
        approvedRestoreFingerprint = nil
        lastRestoreBlocker = nil
        lastRestore = nil
    }

    func refresh(connectionGeneration: Int? = nil) async throws {
        guard let bridge else { throw BridgeClientError.childStopped }
        let expectedGeneration = connectionGeneration ?? self.connectionGeneration
        let freshSnapshot = try await bridge.snapshot()
        guard connectionIsCurrent(expectedGeneration) else { return }
        snapshot = freshSnapshot
        state = .ready
    }

    func refreshRecovery(connectionGeneration: Int? = nil) async {
        let expectedGeneration = connectionGeneration ?? self.connectionGeneration
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshRecovery = try await bridge.recoverySnapshot()
            guard connectionIsCurrent(expectedGeneration) else { return }
            recovery = freshRecovery
            recoveryBlocker = nil
            state = .ready
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            setRecoveryUnavailable()
        }
    }

    func plan(group: GroupSummary, target: String) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        await discardReviewedPlan()
        guard connectionIsCurrent(expectedGeneration) else { return }
        lastApply = nil
        lastChangeBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshPlan = try await bridge.planGroup(name: group.qualifiedName, target: target).plan
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedPlan = freshPlan
            approvedPlanFingerprint = nil
            lastChangeBlocker = nil
            lastApply = nil
            state = .ready
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func approveReviewedPlan() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveGroup(operationID: operationID, fingerprint: plan.planFingerprint)
            guard connectionIsCurrent(expectedGeneration) else { return }
            approvedPlanFingerprint = plan.planFingerprint
            lastChangeBlocker = nil
            state = .ready
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyApprovedPlan() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId,
                  approvedPlanFingerprint == plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            let result = try await bridge.applyGroup(operationID: operationID, fingerprint: plan.planFingerprint).result
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastApply = result
            self.reviewedPlan = nil
            approvedPlanFingerprint = nil
            do {
                try await refresh(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
            } catch {
                guard connectionIsCurrent(expectedGeneration) else { return }
                lastChangeBlocker = "The change completed, but its fresh observation could not be loaded. Reload the workspace or inspect Recover and Audit."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedPlan = nil
            approvedPlanFingerprint = nil
            lastChangeBlocker = "Unpin did not confirm this change. It may have written configuration; inspect Recover and Audit before creating another plan."
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return }
            if recoveryRefreshed {
                state = .blocked(error.localizedDescription)
            }
        }
    }

    func discardReviewedPlan() async {
        let review = reviewedPlan
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
        guard let bridge, let operationID = review?.operationId,
              let fingerprint = review?.planFingerprint else { return }
        try? await bridge.discardGroup(operationID: operationID, fingerprint: fingerprint)
    }

    func planDefinition(_ parameters: GroupDefinitionPlanParameters) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        await discardReviewedDefinition()
        guard connectionIsCurrent(expectedGeneration) else { return }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshDefinition = try await bridge.planDefinition(parameters)
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedDefinition = freshDefinition
            state = .ready
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyDefinition() async -> Bool {
        guard controlRequestInFlight == false else { return false }
        guard guardActionsAllowed() else { return false }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedDefinition else {
                throw BridgeClientError.malformedResponse
            }
            if let hook = testHooks.beforeDefinitionApply {
                await hook()
            }
            _ = try await bridge.applyDefinition(
                operationID: reviewedDefinition.operationId,
                fingerprint: reviewedDefinition.plan.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return false }
            self.reviewedDefinition = nil
            try await refresh(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return false }
            return true
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return false }
            self.reviewedDefinition = nil
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(
                connectionGeneration: expectedGeneration
            )
            guard connectionIsCurrent(expectedGeneration) else { return false }
            if recoveryRefreshed {
                state = .blocked(error.localizedDescription)
            }
            return false
        }
    }

    func discardReviewedDefinition() async {
        let review = reviewedDefinition
        reviewedDefinition = nil
        guard let bridge, let review else { return }
        try? await bridge.discardDefinition(
            operationID: review.operationId,
            fingerprint: review.plan.planFingerprint
        )
    }

    func loadDefinitionHistory(scope: String) async {
        let expectedGeneration = connectionGeneration
        definitionHistory = []
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshHistory = try await bridge.definitionHistory(scope: scope).history
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            definitionHistory = freshHistory
            state = .ready
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func planRestore(backupID: String) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        await discardReviewedRestore()
        guard connectionIsCurrent(expectedGeneration) else { return }
        lastRestore = nil
        lastRestoreBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshRestore = try await bridge.planRestore(backupID: backupID)
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedRestore = freshRestore
            approvedRestoreFingerprint = nil
            lastRestoreBlocker = nil
            lastRestore = nil
            state = .ready
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func approveReviewedRestore() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedRestore else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return }
            approvedRestoreFingerprint = reviewedRestore.plan.planFingerprint
            lastRestoreBlocker = nil
            state = .ready
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyApprovedRestore() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedRestore,
                  approvedRestoreFingerprint == reviewedRestore.plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            let result = try await bridge.applyRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            ).result
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastRestore = result
            self.reviewedRestore = nil
            approvedRestoreFingerprint = nil
            do {
                try await refresh(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
                await refreshRecovery(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
            } catch {
                guard connectionIsCurrent(expectedGeneration) else { return }
                lastRestoreBlocker = "The restore completed, but its fresh observation could not be loaded. Reload the workspace before another change."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedRestore = nil
            approvedRestoreFingerprint = nil
            lastRestoreBlocker = "Unpin did not confirm this restore. Inspect Recover and Audit before creating another restore plan."
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return }
            if recoveryRefreshed {
                state = .blocked(error.localizedDescription)
            }
        }
    }

    func discardReviewedRestore() async {
        let review = reviewedRestore
        reviewedRestore = nil
        approvedRestoreFingerprint = nil
        lastRestoreBlocker = nil
        guard let bridge, let review else { return }
        try? await bridge.discardRestore(
            operationID: review.operationId,
            fingerprint: review.plan.planFingerprint
        )
    }

    private func refreshRecoveryAfterUnconfirmedChange(connectionGeneration expectedGeneration: Int) async -> Bool {
        do {
            guard let bridge else {
                guard connectionIsCurrent(expectedGeneration) else { return false }
                setRecoveryUnavailable()
                return false
            }
            let freshRecovery = try await bridge.recoverySnapshot()
            guard connectionIsCurrent(expectedGeneration) else { return false }
            recovery = freshRecovery
            recoveryBlocker = nil
            return true
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return false }
            setRecoveryUnavailable()
            return false
        }
    }

    private func guardActionsAllowed() -> Bool {
        guard actionsBlocked == false else {
            state = .blocked(recoveryBlocker ?? Self.recoveryUnavailableMessage)
            return false
        }
        return true
    }

    private func setRecoveryUnavailable() {
        recoveryBlocker = Self.recoveryUnavailableMessage
        state = .blocked(Self.recoveryUnavailableMessage)
    }

    func stopBridgeForTesting() async {
        _ = await bridge?.stop()
    }

    private static func bundledBridge() throws -> (executable: URL, manifest: BundledBridgeManifest) {
        let executable = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("unpin")
        guard FileManager.default.fileExists(atPath: executable.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        guard let manifestURL = Bundle.main.url(
            forResource: "unpin-bridge-manifest",
            withExtension: "json"
        ) else {
            throw BridgeClientError.bundledManifestInvalid
        }
        do {
            return (executable, try JSONDecoder().decode(
                BundledBridgeManifest.self,
                from: Data(contentsOf: manifestURL)
            ))
        } catch {
            throw BridgeClientError.bundledManifestInvalid
        }
    }
}
