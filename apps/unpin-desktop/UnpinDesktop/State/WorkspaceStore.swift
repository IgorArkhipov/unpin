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

@MainActor
final class WorkspaceStore: ObservableObject {
    enum State { case needsWorkspace, loading, ready, blocked(String) }

    @Published private(set) var state: State = .needsWorkspace
    @Published private(set) var snapshot: BridgeSnapshot?
    @Published private(set) var reviewedPlan: GroupPlan?
    @Published private(set) var approvedPlanFingerprint: String?
    @Published private(set) var lastChangeBlocker: String?
    @Published private(set) var lastApply: GroupApplyResult?
    @Published private(set) var reviewedDefinition: GroupDefinitionPlanEnvelope?
    @Published private(set) var definitionHistory: [GroupDefinitionHistory] = []
    @Published private(set) var recovery: RecoverySnapshot?
    @Published private(set) var reviewedRestore: RestorePlanEnvelope?
    @Published private(set) var approvedRestoreFingerprint: String?
    @Published private(set) var lastRestoreBlocker: String?
    @Published private(set) var lastRestore: RestoreApplyResult?
    @Published private(set) var workspaceName: String?

    private var bridge: BridgeClient?
    private var workspaceRoot: URL?
    private var connectionGeneration = 0
    @Published private(set) var controlRequestInFlight = false

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
        workspaceRoot = selectedRoot
        workspaceName = selectedRoot.lastPathComponent
        connectionGeneration &+= 1
        await connectWorkspace(root: selectedRoot, generation: connectionGeneration, loadRecovery: false)
    }

    func reloadWorkspace() async {
        guard controlRequestInFlight == false else { return }
        guard let workspaceRoot else {
            state = .needsWorkspace
            return
        }
        let loadRecovery = recovery != nil
        connectionGeneration &+= 1
        await connectWorkspace(
            root: workspaceRoot,
            generation: connectionGeneration,
            loadRecovery: loadRecovery
        )
    }

    private func connectWorkspace(root: URL, generation: Int, loadRecovery: Bool) async {
        guard connectionIsCurrent(generation) else { return }
        state = .loading
        let previousBridge = bridge
        if let previousBridge, await previousBridge.stop() == false {
            guard connectionIsCurrent(generation) else { return }
            state = .blocked("Unpin is still confirming a configuration change. Wait for it to finish before reloading the workspace.")
            return
        }
        guard connectionIsCurrent(generation) else { return }
        bridge = nil
        clearWorkspaceState()
        var replacement: BridgeClient?
        do {
            let bundledBridge = try Self.bundledBridge()
            let bridge = BridgeClient(
                executableURL: bundledBridge.executable,
                projectRoot: root,
                manifest: bundledBridge.manifest
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
            if loadRecovery {
                await refreshRecovery(connectionGeneration: generation)
            }
        } catch {
            if let replacement {
                await replacement.stop()
            }
            guard connectionIsCurrent(generation) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    private func connectionIsCurrent(_ generation: Int) -> Bool {
        generation == connectionGeneration
    }

    private func clearWorkspaceState() {
        snapshot = nil
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
        lastApply = nil
        reviewedDefinition = nil
        definitionHistory = []
        recovery = nil
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
            state = .ready
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            recovery = nil
            state = .blocked(error.localizedDescription)
        }
    }

    func plan(group: GroupSummary, target: String) async {
        await discardReviewedPlan()
        lastApply = nil
        lastChangeBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedPlan = try await bridge.planGroup(name: group.qualifiedName, target: target).plan
            approvedPlanFingerprint = nil
            lastChangeBlocker = nil
            lastApply = nil
            state = .ready
        } catch { state = .blocked(error.localizedDescription) }
    }

    func approveReviewedPlan() async {
        guard controlRequestInFlight == false else { return }
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveGroup(operationID: operationID, fingerprint: plan.planFingerprint)
            approvedPlanFingerprint = plan.planFingerprint
            lastChangeBlocker = nil
            state = .ready
        } catch { state = .blocked(error.localizedDescription) }
    }

    func applyApprovedPlan() async {
        guard controlRequestInFlight == false else { return }
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId,
                  approvedPlanFingerprint == plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            let result = try await bridge.applyGroup(operationID: operationID, fingerprint: plan.planFingerprint).result
            lastApply = result
            self.reviewedPlan = nil
            approvedPlanFingerprint = nil
            do {
                try await refresh()
            } catch {
                lastChangeBlocker = "The change completed, but its fresh observation could not be loaded. Reload the workspace or inspect Recover and Audit."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            reviewedPlan = nil
            approvedPlanFingerprint = nil
            lastChangeBlocker = "Unpin did not confirm this change. It may have written configuration; inspect Recover and Audit before creating another plan."
            await refreshRecoveryAfterUnconfirmedChange()
            state = .blocked(error.localizedDescription)
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
        await discardReviewedDefinition()
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedDefinition = try await bridge.planDefinition(parameters)
        } catch { state = .blocked(error.localizedDescription) }
    }

    func applyDefinition() async -> Bool {
        guard controlRequestInFlight == false else { return false }
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedDefinition else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.applyDefinition(
                operationID: reviewedDefinition.operationId,
                fingerprint: reviewedDefinition.plan.planFingerprint
            )
            self.reviewedDefinition = nil
            try await refresh()
            return true
        } catch {
            state = .blocked(error.localizedDescription)
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
        definitionHistory = []
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            definitionHistory = try await bridge.definitionHistory(scope: scope).history
        } catch { state = .blocked(error.localizedDescription) }
    }

    func planRestore(backupID: String) async {
        await discardReviewedRestore()
        lastRestore = nil
        lastRestoreBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedRestore = try await bridge.planRestore(backupID: backupID)
            approvedRestoreFingerprint = nil
            lastRestoreBlocker = nil
            lastRestore = nil
            state = .ready
        } catch { state = .blocked(error.localizedDescription) }
    }

    func approveReviewedRestore() async {
        guard controlRequestInFlight == false else { return }
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
            approvedRestoreFingerprint = reviewedRestore.plan.planFingerprint
            lastRestoreBlocker = nil
            state = .ready
        } catch { state = .blocked(error.localizedDescription) }
    }

    func applyApprovedRestore() async {
        guard controlRequestInFlight == false else { return }
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
            lastRestore = result
            self.reviewedRestore = nil
            approvedRestoreFingerprint = nil
            do {
                try await refresh()
                await refreshRecovery()
            } catch {
                lastRestoreBlocker = "The restore completed, but its fresh observation could not be loaded. Reload the workspace before another change."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            reviewedRestore = nil
            approvedRestoreFingerprint = nil
            lastRestoreBlocker = "Unpin did not confirm this restore. Inspect Recover and Audit before creating another restore plan."
            await refreshRecoveryAfterUnconfirmedChange()
            state = .blocked(error.localizedDescription)
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

    private func refreshRecoveryAfterUnconfirmedChange() async {
        do {
            guard let bridge else { return }
            recovery = try await bridge.recoverySnapshot()
        } catch {
            recovery = nil
        }
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
