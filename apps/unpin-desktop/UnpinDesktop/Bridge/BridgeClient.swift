import CryptoKit
import Darwin
import Foundation

enum BridgeClientError: LocalizedError {
    case bundledExecutableMissing
    case bundledManifestInvalid
    case bundleIntegrityMismatch
    case incompatibleProtocol
    case incompatibleBinary
    case incompatibleCapabilities
    case malformedResponse
    case requestFailed(String)
    case requestTimedOut
    case controlRequestUncertain
    case childStopped

    var errorDescription: String? {
        switch self {
        case .bundledExecutableMissing: "The bundled Unpin executable is missing. Rebuild the app."
        case .bundledManifestInvalid: "The bundled Unpin manifest is invalid. Rebuild the app."
        case .bundleIntegrityMismatch: "The bundled Unpin executable did not match its manifest. Rebuild the app."
        case .incompatibleProtocol: "The bundled Unpin executable does not support this workbench."
        case .incompatibleBinary: "The bundled Unpin executable does not match this workbench release."
        case .incompatibleCapabilities: "The bundled Unpin executable does not support Agent Plugin workbench controls."
        case .malformedResponse: "The Unpin bridge returned an invalid response."
        case .requestFailed(let code): "The Unpin bridge blocked this request: \(code)."
        case .requestTimedOut: "The bundled Unpin bridge did not respond. Select Reload workspace to restart it."
        case .controlRequestUncertain: "The Unpin bridge did not confirm this change. Inspect Recover and Audit before trying again."
        case .childStopped: "The bundled Unpin process stopped unexpectedly."
        }
    }
}

struct BundledBridgeManifest: Decodable, Sendable {
    let bridgeProtocolVersion: Int
    let unpinVersion: String
    let sha256: String
}

/// Shared verification for every executable launched from the app bundle.
/// The updater injects this verifier in tests, while production loads the
/// bundled manifest through `verifyBundled`.
struct BundledBridgeVerifier: Sendable {
    static let protocolVersion = 2

    let manifest: BundledBridgeManifest

    init(manifest: BundledBridgeManifest) {
        self.manifest = manifest
    }

    func verify(executableURL: URL) throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        guard manifest.bridgeProtocolVersion == Self.protocolVersion,
              manifest.unpinVersion.isEmpty == false,
              manifest.sha256.count == 64,
              manifest.sha256.allSatisfy(\.isHexDigit)
        else {
            throw BridgeClientError.bundledManifestInvalid
        }
        guard try Self.sha256(of: executableURL) == manifest.sha256.lowercased() else {
            throw BridgeClientError.bundleIntegrityMismatch
        }
    }

    static func verifyBundled(executableURL: URL, bundle: Bundle = .main) throws {
        guard let manifestURL = bundle.url(
            forResource: "unpin-bridge-manifest",
            withExtension: "json"
        ) else {
            throw BridgeClientError.bundledManifestInvalid
        }
        do {
            let manifest = try JSONDecoder().decode(
                BundledBridgeManifest.self,
                from: Data(contentsOf: manifestURL)
            )
            try Self(manifest: manifest).verify(executableURL: executableURL)
        } catch let error as BridgeClientError {
            throw error
        } catch {
            throw BridgeClientError.bundledManifestInvalid
        }
    }

    private static func sha256(of url: URL) throws -> String {
        let file = try FileHandle(forReadingFrom: url)
        defer { try? file.close() }
        var hasher = SHA256()
        while let chunk = try file.read(upToCount: 1_048_576), chunk.isEmpty == false {
            hasher.update(data: chunk)
        }
        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

struct BridgeLaunchRoots: Sendable {
    let fixtureRoot: URL?
    let homeRoot: URL?
    let appStateRoot: URL?

    init(
        fixtureRoot: URL? = nil,
        homeRoot: URL? = nil,
        appStateRoot: URL? = nil
    ) {
        self.fixtureRoot = fixtureRoot
        self.homeRoot = homeRoot
        self.appStateRoot = appStateRoot
    }
}

struct BridgeTerminationPolicy: Sendable {
    let gracePeriodNanoseconds: UInt64
    let settlePeriodNanoseconds: UInt64

    static let production = Self(
        gracePeriodNanoseconds: 1_000_000_000,
        settlePeriodNanoseconds: 1_000_000_000
    )

    init(gracePeriodNanoseconds: UInt64, settlePeriodNanoseconds: UInt64) {
        self.gracePeriodNanoseconds = gracePeriodNanoseconds
        self.settlePeriodNanoseconds = settlePeriodNanoseconds
    }
}

actor BridgeClient {
    static let protocolVersion = BundledBridgeVerifier.protocolVersion
    static let requiredAgentPluginCapabilities: Set<String> = [
        "agentPlugins.inspect",
        "agentPlugins.plan",
        "agentPlugins.approve",
        "agentPlugins.apply",
        "agentPlugins.discard",
    ]
    private static let maximumFrameBytes = 1_048_576
    private static let readOnlyRequestTimeoutMilliseconds = 15_000
    private static let defaultControlRequestTimeoutMilliseconds = 180_000

    private let executableURL: URL
    private let projectRoot: URL
    private let manifest: BundledBridgeManifest
    private let roots: BridgeLaunchRoots
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var outputBuffer = Data()
    private var requestSequence = 0
    private var controlRequestInFlight = false
    private let controlRequestTimeoutMilliseconds: Int
    private let terminationPolicy: BridgeTerminationPolicy

    init(
        executableURL: URL,
        projectRoot: URL,
        manifest: BundledBridgeManifest,
        roots: BridgeLaunchRoots = BridgeLaunchRoots(),
        controlRequestTimeoutMilliseconds: Int = BridgeClient.defaultControlRequestTimeoutMilliseconds,
        terminationPolicy: BridgeTerminationPolicy = .production
    ) {
        self.executableURL = executableURL
        self.projectRoot = projectRoot
        self.manifest = manifest
        self.roots = roots
        self.controlRequestTimeoutMilliseconds = max(1, controlRequestTimeoutMilliseconds)
        self.terminationPolicy = terminationPolicy
    }

    func start() throws {
        try BundledBridgeVerifier(manifest: manifest).verify(executableURL: executableURL)
        let child = Process()
        child.executableURL = executableURL
        var arguments = ["desktop", "bridge", "--project-root", projectRoot.path]
        if let fixtureRoot = roots.fixtureRoot {
            arguments.append(contentsOf: ["--fixture-root", fixtureRoot.path])
        }
        if let homeRoot = roots.homeRoot {
            arguments.append(contentsOf: ["--home-root", homeRoot.path])
        }
        if let appStateRoot = roots.appStateRoot {
            arguments.append(contentsOf: ["--app-state-root", appStateRoot.path])
        }
        child.arguments = arguments
        child.currentDirectoryURL = projectRoot
        let standardInput = Pipe()
        let standardOutput = Pipe()
        child.standardInput = standardInput
        child.standardOutput = standardOutput
        child.standardError = FileHandle.nullDevice
        try child.run()
        process = child
        input = standardInput.fileHandleForWriting
        output = standardOutput.fileHandleForReading
    }

    func handshake() async throws -> BridgeHandshake {
        let handshake: BridgeHandshake = try await request(
            method: "handshake",
            parameters: EmptyParameters(),
            kind: .readOnly
        )
        guard handshake.protocolVersion == Self.protocolVersion else {
            await stop()
            throw BridgeClientError.incompatibleProtocol
        }
        guard handshake.binaryVersion == manifest.unpinVersion else {
            await stop()
            throw BridgeClientError.incompatibleBinary
        }
        guard Set(handshake.capabilities).isSuperset(of: Self.requiredAgentPluginCapabilities) else {
            await stop()
            throw BridgeClientError.incompatibleCapabilities
        }
        return handshake
    }

    func snapshot() async throws -> BridgeSnapshot {
        try await request(method: "snapshot", parameters: EmptyParameters(), kind: .readOnly)
    }

    func planGroup(name: String, target: String) async throws -> GroupPlanEnvelope {
        try await request(
            method: "group.plan",
            parameters: GroupPlanParameters(qualifiedName: name, target: target),
            kind: .readOnly
        )
    }

    func approveGroup(operationID: String, fingerprint: String) async throws -> GroupApprovalEnvelope {
        try await request(
            method: "group.approve",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .localControl
        )
    }

    func applyGroup(operationID: String, fingerprint: String) async throws -> GroupApplyEnvelope {
        try await request(
            method: "group.apply",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .mutation
        )
    }

    func discardGroup(operationID: String, fingerprint: String) async throws {
        let _: DiscardedReview = try await request(
            method: "group.discard",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .readOnly
        )
    }

    func planAgentPlugin(
        logicalID: String,
        target: String,
        reach: String,
        selectedProvider: String?
    ) async throws -> AgentPluginPlanEnvelope {
        try await request(
            method: "agentPlugins.plan",
            parameters: AgentPluginPlanParameters(
                logicalId: logicalID,
                target: target,
                reach: reach,
                selectedProvider: selectedProvider
            ),
            kind: .readOnly
        )
    }

    func inspectAgentPlugin(logicalID: String) async throws -> AgentPluginInspectEnvelope {
        try await request(
            method: "agentPlugins.inspect",
            parameters: AgentPluginInspectParameters(logicalId: logicalID),
            kind: .readOnly
        )
    }

    func approveAgentPlugin(
        operationID: String,
        fingerprint: String
    ) async throws -> GroupApprovalEnvelope {
        try await request(
            method: "agentPlugins.approve",
            parameters: GroupApprovalParameters(
                operationId: operationID,
                planFingerprint: fingerprint
            ),
            kind: .localControl
        )
    }

    func applyAgentPlugin(
        operationID: String,
        fingerprint: String
    ) async throws -> AgentPluginApplyEnvelope {
        try await request(
            method: "agentPlugins.apply",
            parameters: GroupApprovalParameters(
                operationId: operationID,
                planFingerprint: fingerprint
            ),
            kind: .mutation
        )
    }

    func discardAgentPlugin(operationID: String, fingerprint: String) async throws {
        let _: DiscardedReview = try await request(
            method: "agentPlugins.discard",
            parameters: GroupApprovalParameters(
                operationId: operationID,
                planFingerprint: fingerprint
            ),
            kind: .readOnly
        )
    }

    func planDefinition(_ parameters: GroupDefinitionPlanParameters) async throws -> GroupDefinitionPlanEnvelope {
        try await request(method: "group.definition.plan", parameters: parameters, kind: .readOnly)
    }

    func applyDefinition(operationID: String, fingerprint: String) async throws -> GroupDefinitionApplyResult {
        try await request(
            method: "group.definition.apply",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .mutation
        )
    }

    func discardDefinition(operationID: String, fingerprint: String) async throws {
        let _: DiscardedReview = try await request(
            method: "group.definition.discard",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .readOnly
        )
    }

    func definitionHistory(scope: String) async throws -> GroupDefinitionHistoryEnvelope {
        try await request(
            method: "group.definition.history",
            parameters: GroupDefinitionHistoryParameters(scope: scope),
            kind: .readOnly
        )
    }

    func recoverySnapshot() async throws -> RecoverySnapshot {
        try await request(method: "recovery.snapshot", parameters: EmptyParameters(), kind: .readOnly)
    }

    func planRestore(backupID: String) async throws -> RestorePlanEnvelope {
        try await request(
            method: "restore.plan",
            parameters: RestorePlanParameters(backupId: backupID),
            kind: .readOnly
        )
    }

    func approveRestore(operationID: String, fingerprint: String) async throws -> GroupApprovalEnvelope {
        try await request(
            method: "restore.approve",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .localControl
        )
    }

    func applyRestore(operationID: String, fingerprint: String) async throws -> RestoreApplyEnvelope {
        try await request(
            method: "restore.apply",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .mutation
        )
    }

    func discardRestore(operationID: String, fingerprint: String) async throws {
        let _: DiscardedReview = try await request(
            method: "restore.discard",
            parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint),
            kind: .readOnly
        )
    }

    @discardableResult
    func stop() async -> Bool {
        guard controlRequestInFlight == false else { return false }
        await forceStop()
        return true
    }

    private func forceStop() async {
        let child = process
        input?.closeFile()
        output?.closeFile()
        process = nil
        input = nil
        output = nil
        outputBuffer.removeAll(keepingCapacity: false)
        if let child, child.isRunning {
            child.terminate()
            await Self.waitForTermination(of: child, timeoutNanoseconds: terminationPolicy.gracePeriodNanoseconds)
            if child.isRunning {
                _ = kill(child.processIdentifier, SIGKILL)
                await Self.waitForTermination(
                    of: child,
                    timeoutNanoseconds: terminationPolicy.settlePeriodNanoseconds
                )
            }
        }
    }

    private func request<Parameters: Encodable, Response: Decodable>(
        method: String,
        parameters: Parameters,
        kind: BridgeRequestKind
    ) async throws -> Response {
        guard let process, process.isRunning, let input, let output else {
            throw BridgeClientError.childStopped
        }
        requestSequence += 1
        let request = BridgeRequest(
            version: Self.protocolVersion,
            id: "desktop-\(requestSequence)",
            method: method,
            params: parameters
        )
        let encoded = try JSONEncoder().encode(request)
        guard encoded.count <= Self.maximumFrameBytes else { throw BridgeClientError.malformedResponse }
        if kind != .readOnly {
            controlRequestInFlight = true
        }
        defer {
            if kind != .readOnly {
                controlRequestInFlight = false
            }
        }
        do {
            try Task.checkCancellation()
            input.write(encoded)
            input.write(Data([0x0A]))
            let responseData = try await readFrame(from: output, kind: kind)
            let response = try JSONDecoder().decode(BridgeResponse<Response>.self, from: responseData)
            guard response.version == Self.protocolVersion, response.id == request.id else {
                throw BridgeClientError.malformedResponse
            }
            if let error = response.error { throw BridgeClientError.requestFailed(error.code) }
            guard let result = response.result else { throw BridgeClientError.malformedResponse }
            return result
        } catch is CancellationError {
            if kind == .readOnly {
                await forceStop()
                throw CancellationError()
            }
            await forceStop()
            throw BridgeClientError.controlRequestUncertain
        } catch let error as BridgeClientError {
            if case .requestFailed = error {
                throw error
            }
            if kind == .readOnly {
                await forceStop()
                throw error
            }
            await forceStop()
            if case .requestTimedOut = error {
                throw BridgeClientError.controlRequestUncertain
            }
            throw error
        } catch {
            if kind == .readOnly {
                await forceStop()
                throw error
            }
            await forceStop()
            throw error
        }
    }

    private nonisolated static func waitForTermination(
        of child: Process,
        timeoutNanoseconds: UInt64
    ) async {
        await withCheckedContinuation { continuation in
            let completion = ProcessTerminationCompletion(continuation)
            child.terminationHandler = { _ in completion.finish() }
            let deadline = DispatchTime.now() + .nanoseconds(Int(timeoutNanoseconds))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: deadline) {
                completion.finish()
            }
        }
    }

    private func readFrame(from output: FileHandle, kind: BridgeRequestKind) async throws -> Data {
        let timeoutMilliseconds = kind == .readOnly
            ? Self.readOnlyRequestTimeoutMilliseconds
            : controlRequestTimeoutMilliseconds
        let deadline = Date().timeIntervalSinceReferenceDate + Double(timeoutMilliseconds) / 1_000
        while true {
            try Task.checkCancellation()
            if let newline = outputBuffer.firstIndex(of: 0x0A) {
                let frame = outputBuffer.prefix(upTo: newline)
                outputBuffer.removeSubrange(...newline)
                guard frame.count <= Self.maximumFrameBytes else { throw BridgeClientError.malformedResponse }
                return Data(frame)
            }
            if Date().timeIntervalSinceReferenceDate >= deadline {
                throw BridgeClientError.requestTimedOut
            }
            var descriptor = pollfd(fd: output.fileDescriptor, events: Int16(POLLIN), revents: 0)
            let readiness = poll(&descriptor, 1, 100)
            if readiness < 0 {
                if errno == EINTR { continue }
                throw BridgeClientError.childStopped
            }
            guard readiness > 0 else { continue }
            let chunk = output.availableData
            guard chunk.isEmpty == false else { throw BridgeClientError.childStopped }
            outputBuffer.append(chunk)
            guard outputBuffer.count <= Self.maximumFrameBytes else { throw BridgeClientError.malformedResponse }
        }
    }

}

private final class ProcessTerminationCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Never>?

    init(_ continuation: CheckedContinuation<Void, Never>) {
        self.continuation = continuation
    }

    func finish() {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume()
    }
}

private enum BridgeRequestKind {
    case readOnly
    case localControl
    case mutation
}

private struct BridgeRequest<Parameters: Encodable>: Encodable {
    let version: Int
    let id: String
    let method: String
    let params: Parameters
}

private struct BridgeResponse<Result: Decodable>: Decodable {
    let version: Int
    let id: String?
    let result: Result?
    let error: BridgeErrorPayload?
}

private struct BridgeErrorPayload: Decodable { let code: String }
private struct DiscardedReview: Decodable { let discarded: Bool }
private struct EmptyParameters: Codable {}
private struct GroupPlanParameters: Codable { let qualifiedName: String; let target: String }
private struct AgentPluginInspectParameters: Codable { let logicalId: String }
private struct AgentPluginPlanParameters: Codable {
    let logicalId: String
    let target: String
    let reach: String
    let selectedProvider: String?
}
private struct GroupApprovalParameters: Codable { let operationId: String; let planFingerprint: String }
private struct RestorePlanParameters: Codable { let backupId: String }
private struct GroupDefinitionHistoryParameters: Codable { let scope: String }

struct GroupDefinitionPlanParameters: Encodable {
    let action: String
    let scope: String?
    let qualifiedName: String?
    let name: String?
    let newName: String?
    let members: [GroupMemberIdentity]?
    let expectedRevision: String?
    let historyId: String?

    enum CodingKeys: String, CodingKey {
        case action, scope, qualifiedName, name, newName, members, expectedRevision, historyId
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(action, forKey: .action)
        try container.encodeIfPresent(scope, forKey: .scope)
        try container.encodeIfPresent(qualifiedName, forKey: .qualifiedName)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(newName, forKey: .newName)
        try container.encodeIfPresent(members, forKey: .members)
        try container.encodeIfPresent(expectedRevision, forKey: .expectedRevision)
        try container.encodeIfPresent(historyId, forKey: .historyId)
    }
}

struct BridgeHandshake: Decodable { let protocolVersion: Int; let binaryVersion: String; let capabilities: [String] }
struct BridgeSnapshot: Decodable {
    let capturedAtUnix: Int
    let inventory: [InventoryItem]
    let warnings: [BridgeWarning]
    let agentPluginInventoryComplete: Bool
    let agentPlugins: [AgentPluginSummary]
    let groups: [GroupSummary]
    let groupWarnings: [GroupWarning]

    private enum CodingKeys: String, CodingKey {
        case capturedAtUnix, inventory, warnings, agentPluginInventoryComplete, agentPlugins, groups, groupWarnings
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        capturedAtUnix = try container.decode(Int.self, forKey: .capturedAtUnix)
        inventory = try container.decode([InventoryItem].self, forKey: .inventory)
        warnings = try container.decode([BridgeWarning].self, forKey: .warnings)
        agentPluginInventoryComplete = try container.decode(
            Bool.self,
            forKey: .agentPluginInventoryComplete
        )
        agentPlugins = try container.decode([AgentPluginSummary].self, forKey: .agentPlugins)
        groups = try container.decode([GroupSummary].self, forKey: .groups)
        groupWarnings = try container.decode([GroupWarning].self, forKey: .groupWarnings)
    }
}
struct InventoryItem: Decodable, Identifiable { let provider: String; let kind: String; let category: String; let layer: String; let id: String; let displayName: String; let enabled: Bool; let mutability: String }
struct BridgeWarning: Decodable, Identifiable { let provider: String; let layer: String?; let code: String; var id: String { "\(provider)-\(code)" } }
struct GroupWarning: Decodable, Identifiable {
    let scope: String
    let code: String

    var id: String { "\(scope)-\(code)" }
}

struct AgentPluginSummary: Decodable, Identifiable {
    let logicalId: String
    let name: String
    let componentSignature: String
    let projectionFingerprint: String
    let state: String
    let access: String
    let providers: [String]
    let componentKinds: [String]
    let instanceCount: Int
    let instances: [AgentPluginInstance]

    var id: String { logicalId }
    var providerDisplay: String { providers.joined(separator: ", ") }
    var typeDisplay: String { componentKinds.joined(separator: " + ") }
}

struct AgentPluginInstance: Decodable, Identifiable {
    let instanceId: String
    let provider: String
    let layer: String
    let state: String
    let access: String
    let version: String?
    let components: [AgentPluginComponent]
    let activations: [AgentPluginActivation]
    let blockers: [String]
    let diagnostics: [String]

    var id: String { instanceId }
}

struct AgentPluginComponent: Decodable, Identifiable {
    let kind: String
    let name: String
    let disposition: String
    let reason: String?

    var id: String { "\(kind):\(name):\(disposition)" }
}

struct AgentPluginActivation: Decodable {
    let enabled: Bool
    let mutability: String
}

struct AgentPluginInspectEnvelope: Decodable { let package: AgentPluginSummary }
struct AgentPluginPlanEnvelope: Decodable { let plan: AgentPluginPlan }
struct AgentPluginPlan: Decodable, Identifiable {
    let logicalId: String
    let name: String
    let componentSignature: String
    let projectionFingerprint: String
    let state: String
    let access: String
    let providers: [String]
    let componentKinds: [String]
    let instanceCount: Int
    let instances: [AgentPluginInstance]
    let operationId: String
    let planFingerprint: String
    let target: String
    @ProviderReachField var providerReach: String
    let coverage: [AgentPluginCoverage]
    let lifecycle: String
    let counts: AgentPluginPlanCounts
    let review: AgentPluginPlanReview

    var id: String { operationId }
}

struct AgentPluginCoverage: Decodable, Identifiable {
    let provider: String
    let included: Int
    let excluded: Int
    let reasonCodes: [String]

    var id: String { provider }
}

struct AgentPluginPlanCounts: Decodable {
    let instances: Int
    let activations: Int
    let components: Int
    let diagnostics: Int
    let included: Int
    let writes: Int
    let noOp: Int
    let blocked: Int
    let reachExcluded: Int
}

struct AgentPluginPlanReview: Decodable {
    let included: [AgentPluginDisposition]
    let noOp: [AgentPluginDisposition]
    let blocked: [AgentPluginDisposition]
    let reachExcluded: [AgentPluginDisposition]
    let componentDiagnostics: [AgentPluginDisposition]
}

struct AgentPluginDisposition: Decodable, Identifiable {
    let provider: String
    let layer: String
    let outcome: String?
    let reasonCode: String?
    let activationCount: Int?
    let kind: String?
    let name: String?
    let disposition: String?
    let reason: String?

    var id: String {
        [provider, layer, kind, name, outcome, disposition, reasonCode, reason]
            .compactMap { $0 }
            .joined(separator: ":")
    }
}

struct AgentPluginApplyEnvelope: Decodable {
    let result: AgentPluginApplyResult
    let refreshStatus: String
}

struct AgentPluginApplyResult: Decodable {
    let operationId: String
    let planFingerprint: String
    let lifecycle: String
    @ProviderReachField var providerReach: String
    let coverage: [AgentPluginCoverage]
    let logicalId: String
    let name: String
    let state: String
    let access: String
    let counts: AgentPluginApplyCounts
}

struct AgentPluginApplyCounts: Decodable {
    let applied: Int
    let noOp: Int
    let blocked: Int
    let recoveryRequired: Int
    let backupCount: Int
    let reasonCodes: [String]
}

enum ProviderReachValue: Decodable, Equatable {
    case all
    case selected(provider: String, provenance: String)

    private enum CodingKeys: String, CodingKey {
        case selected
    }

    private struct Selected: Decodable {
        let provider: String
        let provenance: String
    }

    init(from decoder: Decoder) throws {
        let singleValue = try decoder.singleValueContainer()
        if let value = try? singleValue.decode(String.self) {
            guard value == "all" else {
                throw DecodingError.dataCorruptedError(
                    in: singleValue,
                    debugDescription: "Unsupported provider reach value: \(value)"
                )
            }
            self = .all
            return
        }

        let object = try decoder.container(keyedBy: CodingKeys.self)
        let selected = try object.decode(Selected.self, forKey: .selected)
        self = .selected(provider: selected.provider, provenance: selected.provenance)
    }

    var displayName: String {
        switch self {
        case .all:
            "all"
        case .selected(let provider, let provenance):
            "selected · \(provider) · \(provenance)"
        }
    }
}

@propertyWrapper
struct ProviderReachField: Decodable {
    private let value: ProviderReachValue

    var wrappedValue: String { value.displayName }
    var projectedValue: ProviderReachValue { value }

    init(from decoder: Decoder) throws {
        value = try ProviderReachValue(from: decoder)
    }
}

@propertyWrapper
struct OptionalProviderReachField: Decodable {
    private let value: ProviderReachValue?

    var wrappedValue: String? { value?.displayName }
    var projectedValue: ProviderReachValue? { value }

    init(value: ProviderReachValue?) {
        self.value = value
    }

    init(from decoder: Decoder) throws {
        let singleValue = try decoder.singleValueContainer()
        value = singleValue.decodeNil() ? nil : try ProviderReachValue(from: decoder)
    }
}

struct GroupSummary: Decodable, Identifiable {
    let qualifiedName: String
    let scope: String
    let revision: String
    let contextCompatible: Bool
    let members: [GroupMemberView]
    let state: String?
    let fresh: Bool?

    var id: String { qualifiedName }
    var name: String { qualifiedName.split(separator: ":", maxSplits: 1).last.map(String.init) ?? qualifiedName }

    private enum CodingKeys: String, CodingKey {
        case qualifiedName
        case scope
        case revision
        case contextCompatible
        case members
        case state
        case fresh
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        qualifiedName = try container.decode(String.self, forKey: .qualifiedName)
        scope = try container.decode(String.self, forKey: .scope)
        revision = try container.decode(String.self, forKey: .revision)
        contextCompatible = try container.decode(Bool.self, forKey: .contextCompatible)
        members = try container.decodeIfPresent([GroupMemberView].self, forKey: .members) ?? []
        state = try container.decodeIfPresent(String.self, forKey: .state)
        fresh = try container.decodeIfPresent(Bool.self, forKey: .fresh)
    }
}
struct GroupPlanEnvelope: Decodable { let plan: GroupPlan }
struct GroupPlan: Decodable {
    let operationId: String?
    let disposition: String
    let mode: String
    let qualifiedName: String
    let scope: String
    let groupRevision: String
    let target: String
    let totalMembers: Int
    @ProviderReachField var providerReach: String
    let providerCoverage: ProviderReachCoverage
    let lifecycle: String
    let members: [GroupPlanMember]
    let resources: [GroupPlanResource]
    let cohorts: [GroupPlanCohort]
    let planFingerprint: String
}
struct ProviderReachCoverage: Decodable { let entries: [ProviderCoverageEntry] }
struct ProviderCoverageEntry: Decodable, Identifiable {
    let provider: String
    let targetId: String
    let included: Bool
    let reason: String?

    var id: String { "\(provider):\(targetId)" }
}
struct GroupPlanMember: Decodable, Identifiable {
    let identity: GroupMemberIdentity
    let currentEnabled: Bool?
    let requestedEnabled: Bool
    let outcome: String
    let reason: String?
    let affectedResources: [String]

    var id: String { "\(identity.provider):\(identity.layer):\(identity.kind):\(identity.category):\(identity.id)" }
}
struct GroupPlanResource: Decodable, Identifiable {
    let resourceId: String
    let targetType: String
    let memberIndices: [Int]
    let activation: String

    var id: String { resourceId }
}
struct GroupPlanCohort: Decodable, Identifiable {
    let cohortId: String
    let memberIndices: [Int]
    let resourceIds: [String]

    var id: String { cohortId }
}
struct GroupMemberIdentity: Codable { let provider: String; let layer: String; let kind: String; let category: String; let id: String }
struct GroupMemberView: Decodable { let identity: GroupMemberIdentity; let enabled: Bool?; let eligible: Bool; let reason: String?; let displayName: String? }
struct GroupApprovalEnvelope: Decodable { let operationId: String; let planFingerprint: String; let approval: String }
struct GroupApplyEnvelope: Decodable { let result: GroupApplyResult }
struct GroupApplyResult: Decodable {
    let operationId: String
    let qualifiedName: String
    let planFingerprint: String
    let requestedState: String
    let lifecycle: String
    @ProviderReachField var providerReach: String
    let providerCoverage: ProviderReachCoverage
    let providerReachLifecycle: String
    let members: [GroupApplyMemberResult]
    let backupIds: [String]
    let finalState: String
    let observationFresh: Bool
    let observationReason: String?
}
struct GroupApplyMemberResult: Decodable, Identifiable {
    let identity: GroupMemberIdentity
    let status: String
    let failureMode: String?
    let reason: String?
    let cohortId: String?
    let backupId: String?

    var id: String { "\(identity.provider):\(identity.layer):\(identity.kind):\(identity.category):\(identity.id)" }
}
struct GroupDefinitionPlanEnvelope: Decodable { let operationId: String; let plan: GroupDefinitionPlan }
struct GroupDefinitionPlan: Decodable {
    let action: String
    let scope: String
    let qualifiedName: String?
    let memberCount: Int?
    let newName: String?
    let expectedRevision: String?
    let historyId: String?
    let planFingerprint: String
}
struct GroupDefinitionApplyResult: Decodable {
    let action: String
    let scope: String
    let qualifiedName: String
    let revision: String?
    let historyId: String?
}
struct GroupDefinitionHistoryEnvelope: Decodable { let history: [GroupDefinitionHistory] }
struct GroupDefinitionHistory: Decodable, Identifiable {
    let historyId: String
    let createdAt: String
    let scope: String
    let change: String
    let nameBefore: String?
    let nameAfter: String?
    let revisionBefore: String?
    let revisionAfter: String?
    let definitionAfterExists: Bool

    var id: String { historyId }
}
enum RecoveryEvidenceAvailability: Decodable, Equatable {
    case available
    case unavailable
    case unknown(String)

    init(from decoder: Decoder) throws {
        switch try decoder.singleValueContainer().decode(String.self) {
        case "available": self = .available
        case "unavailable": self = .unavailable
        case let value: self = .unknown(value)
        }
    }

    var isAvailable: Bool {
        self == .available
    }
}

enum RestoreStatus: Decodable, Equatable {
    case restored
    case other(String)

    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode(String.self)
        self = value == "restored" ? .restored : .other(value)
    }

    var displayName: String {
        switch self {
        case .restored: "restored"
        case .other(let value): value
        }
    }

    var isRestored: Bool {
        self == .restored
    }
}

struct RecoverySnapshot: Decodable { let backups: [RecoveryBackup]; let backupStatus: RecoveryEvidenceAvailability; let operations: [RecoveryOperation]; let operationStatus: RecoveryEvidenceAvailability; let groupOperationStatus: RecoveryEvidenceAvailability }
struct RecoveryBackup: Decodable, Identifiable { let backupId: String; let createdAt: String; let itemCount: Int; let providers: [String]; let layers: [String]; let restorable: Bool; let authentication: String; let targetEnabled: Bool?; var id: String { backupId } }
struct RecoveryOperation: Decodable, Identifiable {
    let operationId: String
    let operationKind: String
    let lifecycle: String
    let qualifiedName: String?
    let requestedState: String?
    let createdAt: String?
    let updatedAt: String?
    let effectGraphDigest: String?
    let authorizationRecorded: Bool?
    let terminalCode: String?
    @OptionalProviderReachField var providerReach: String?
    let providerCoverage: ProviderReachCoverage?
    let providerReachLifecycle: String?
    let providerWritesStarted: Bool?
    let recoveryRequired: Bool
    let resourceCount: Int
    let backupIds: [String]?
    let evidenceAvailable: Bool?
    let finalState: String?
    let observationFresh: Bool?
    let observationReason: String?
    let members: [GroupApplyMemberResult]?

    var id: String { operationId }

    private enum CodingKeys: String, CodingKey {
        case operationId
        case operationKind
        case lifecycle
        case qualifiedName
        case requestedState
        case createdAt
        case updatedAt
        case effectGraphDigest
        case authorizationRecorded
        case terminalCode
        case providerReach
        case providerCoverage
        case providerReachLifecycle
        case providerWritesStarted
        case recoveryRequired
        case resourceCount
        case backupIds
        case evidenceAvailable
        case finalState
        case observationFresh
        case observationReason
        case members
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        operationId = try container.decode(String.self, forKey: .operationId)
        operationKind = try container.decode(String.self, forKey: .operationKind)
        lifecycle = try container.decode(String.self, forKey: .lifecycle)
        qualifiedName = try container.decodeIfPresent(String.self, forKey: .qualifiedName)
        requestedState = try container.decodeIfPresent(String.self, forKey: .requestedState)
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt)
        updatedAt = try container.decodeIfPresent(String.self, forKey: .updatedAt)
        effectGraphDigest = try container.decodeIfPresent(String.self, forKey: .effectGraphDigest)
        authorizationRecorded = try container.decodeIfPresent(Bool.self, forKey: .authorizationRecorded)
        terminalCode = try container.decodeIfPresent(String.self, forKey: .terminalCode)
        _providerReach = try container.decodeIfPresent(OptionalProviderReachField.self, forKey: .providerReach)
            ?? OptionalProviderReachField(value: nil)
        providerCoverage = try container.decodeIfPresent(ProviderReachCoverage.self, forKey: .providerCoverage)
        providerReachLifecycle = try container.decodeIfPresent(String.self, forKey: .providerReachLifecycle)
        providerWritesStarted = try container.decodeIfPresent(Bool.self, forKey: .providerWritesStarted)
        recoveryRequired = try container.decode(Bool.self, forKey: .recoveryRequired)
        resourceCount = try container.decode(Int.self, forKey: .resourceCount)
        backupIds = try container.decodeIfPresent([String].self, forKey: .backupIds)
        evidenceAvailable = try container.decodeIfPresent(Bool.self, forKey: .evidenceAvailable)
        finalState = try container.decodeIfPresent(String.self, forKey: .finalState)
        observationFresh = try container.decodeIfPresent(Bool.self, forKey: .observationFresh)
        observationReason = try container.decodeIfPresent(String.self, forKey: .observationReason)
        members = try container.decodeIfPresent([GroupApplyMemberResult].self, forKey: .members)
    }
}
struct RestorePlanEnvelope: Decodable { let operationId: String; let plan: RestorePlan }
struct RestorePlan: Decodable { let backupId: String; let providers: [String]; let authentication: String; let affectedResourceIds: [String]; let planFingerprint: String }
struct RestoreApplyEnvelope: Decodable { let result: RestoreApplyResult }
struct RestoreApplyResult: Decodable { let status: RestoreStatus; let backupId: String; let affectedTargetCount: Int }
