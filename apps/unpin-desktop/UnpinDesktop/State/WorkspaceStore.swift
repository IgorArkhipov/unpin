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
    enum State { case loading, ready, blocked(String) }

    @Published private(set) var state: State = .loading
    @Published private(set) var snapshot: BridgeSnapshot?
    @Published private(set) var reviewedPlan: GroupPlan?
    @Published private(set) var approvedPlanFingerprint: String?
    @Published private(set) var lastChangeBlocker: String?
    @Published private(set) var lastApply: GroupApplyResult?
    @Published private(set) var reviewedDefinition: GroupDefinitionPlanEnvelope?
    @Published private(set) var lastDefinitionChange: GroupDefinitionApplyResult?
    @Published private(set) var definitionHistory: [GroupDefinitionHistory] = []
    @Published private(set) var recovery: RecoverySnapshot?
    @Published private(set) var reviewedRestore: RestorePlanEnvelope?
    @Published private(set) var lastRestore: RestoreApplyResult?

    private var bridge: BridgeClient?

    var statusMessage: String? {
        switch state {
        case .loading: "Connecting to the bundled Unpin bridge…"
        case .ready: nil
        case .blocked(let message): message
        }
    }

    var reviewedPlanIsApproved: Bool {
        reviewedPlan?.planFingerprint == approvedPlanFingerprint
    }

    func launch() async {
        do {
            let executable = try Self.bundledUnpin()
            let bridge = BridgeClient(executableURL: executable)
            try await bridge.start()
            _ = try await bridge.handshake()
            self.bridge = bridge
            try await refresh()
        } catch {
            state = .blocked(error.localizedDescription)
        }
    }

    func refresh() async throws {
        guard let bridge else { throw BridgeClientError.childStopped }
        snapshot = try await bridge.snapshot()
        state = .ready
    }

    func refreshRecovery() async {
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            recovery = try await bridge.recoverySnapshot()
            state = .ready
        } catch { state = .blocked(error.localizedDescription) }
    }

    func plan(group: GroupSummary, target: String) async {
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
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId,
                  approvedPlanFingerprint == plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            lastApply = try await bridge.applyGroup(operationID: operationID, fingerprint: plan.planFingerprint).result
            self.reviewedPlan = nil
            approvedPlanFingerprint = nil
            try await refresh()
            await refreshRecovery()
        } catch {
            reviewedPlan = nil
            approvedPlanFingerprint = nil
            lastChangeBlocker = "The reviewed change is no longer current. Create a fresh plan before retrying."
            try? await refresh()
            state = .blocked(error.localizedDescription)
        }
    }

    func discardReviewedPlan() {
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
    }

    func planDefinition(_ parameters: GroupDefinitionPlanParameters) async {
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedDefinition = try await bridge.planDefinition(parameters)
            lastDefinitionChange = nil
        } catch { state = .blocked(error.localizedDescription) }
    }

    func applyDefinition() async -> Bool {
        do {
            guard let bridge, let reviewedDefinition else {
                throw BridgeClientError.malformedResponse
            }
            lastDefinitionChange = try await bridge.applyDefinition(
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

    func loadDefinitionHistory(scope: String) async {
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            definitionHistory = try await bridge.definitionHistory(scope: scope).history
        } catch { state = .blocked(error.localizedDescription) }
    }

    func planRestore(backupID: String) async {
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedRestore = try await bridge.planRestore(backupID: backupID)
            lastRestore = nil
        } catch { state = .blocked(error.localizedDescription) }
    }

    func approveAndRestore() async {
        do {
            guard let bridge, let reviewedRestore else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            )
            lastRestore = try await bridge.applyRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            ).result
            self.reviewedRestore = nil
            try await refresh()
            await refreshRecovery()
        } catch { state = .blocked(error.localizedDescription) }
    }

    private static func bundledUnpin() throws -> URL {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("unpin")
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        return url
    }
}
