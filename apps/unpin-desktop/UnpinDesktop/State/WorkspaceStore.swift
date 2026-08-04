import Combine
import Foundation

@MainActor
final class WorkspaceStore: ObservableObject {
    enum State { case loading, ready, blocked(String) }

    @Published private(set) var state: State = .loading
    @Published private(set) var snapshot: BridgeSnapshot?
    @Published private(set) var reviewedPlan: GroupPlan?
    @Published private(set) var lastApply: GroupApplyResult?

    private var bridge: BridgeClient?

    var statusMessage: String? {
        switch state {
        case .loading: "Connecting to the bundled Unpin bridge…"
        case .ready: nil
        case .blocked(let message): message
        }
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

    func plan(group: GroupSummary, target: String) async {
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            reviewedPlan = try await bridge.planGroup(name: group.qualifiedName, target: target).plan
        } catch { state = .blocked(error.localizedDescription) }
    }

    func approveAndApply() async {
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveGroup(operationID: operationID, fingerprint: plan.planFingerprint)
            lastApply = try await bridge.applyGroup(operationID: operationID, fingerprint: plan.planFingerprint).result
            try await refresh()
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
