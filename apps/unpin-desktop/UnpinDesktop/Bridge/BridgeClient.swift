import CryptoKit
import Darwin
import Foundation

enum BridgeClientError: LocalizedError {
    case bundledExecutableMissing
    case bundledManifestInvalid
    case bundleIntegrityMismatch
    case incompatibleProtocol
    case incompatibleBinary
    case malformedResponse
    case requestFailed(String)
    case requestTimedOut
    case childStopped

    var errorDescription: String? {
        switch self {
        case .bundledExecutableMissing: "The bundled Unpin executable is missing. Rebuild the app."
        case .bundledManifestInvalid: "The bundled Unpin manifest is invalid. Rebuild the app."
        case .bundleIntegrityMismatch: "The bundled Unpin executable did not match its manifest. Rebuild the app."
        case .incompatibleProtocol: "The bundled Unpin executable does not support this workbench."
        case .incompatibleBinary: "The bundled Unpin executable does not match this workbench release."
        case .malformedResponse: "The Unpin bridge returned an invalid response."
        case .requestFailed(let code): "The Unpin bridge blocked this request: \(code)."
        case .requestTimedOut: "The bundled Unpin bridge did not respond. Select Reload workspace to restart it."
        case .childStopped: "The bundled Unpin process stopped unexpectedly."
        }
    }
}

struct BundledBridgeManifest: Decodable {
    let bridgeProtocolVersion: Int
    let unpinVersion: String
    let sha256: String
}

actor BridgeClient {
    static let protocolVersion = 2
    private static let maximumFrameBytes = 1_048_576
    private static let readOnlyRequestTimeoutMilliseconds = 15_000

    private let executableURL: URL
    private let projectRoot: URL
    private let manifest: BundledBridgeManifest
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var outputBuffer = Data()
    private var requestSequence = 0
    private var controlRequestInFlight = false

    init(executableURL: URL, projectRoot: URL, manifest: BundledBridgeManifest) {
        self.executableURL = executableURL
        self.projectRoot = projectRoot
        self.manifest = manifest
    }

    func start() throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        guard manifest.bridgeProtocolVersion == Self.protocolVersion,
              manifest.unpinVersion.isEmpty == false,
              manifest.sha256.count == 64,
              manifest.sha256.allSatisfy(\.isHexDigit) else {
            throw BridgeClientError.bundledManifestInvalid
        }
        guard try Self.sha256(of: executableURL) == manifest.sha256.lowercased() else {
            throw BridgeClientError.bundleIntegrityMismatch
        }
        let child = Process()
        child.executableURL = executableURL
        child.arguments = ["desktop", "bridge", "--project-root", projectRoot.path]
        child.currentDirectoryURL = projectRoot
        let standardInput = Pipe()
        let standardOutput = Pipe()
        let standardError = Pipe()
        child.standardInput = standardInput
        child.standardOutput = standardOutput
        child.standardError = standardError
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
            stop()
            throw BridgeClientError.incompatibleProtocol
        }
        guard handshake.binaryVersion == manifest.unpinVersion else {
            stop()
            throw BridgeClientError.incompatibleBinary
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
    func stop() -> Bool {
        guard controlRequestInFlight == false else { return false }
        let child = process
        input?.closeFile()
        output?.closeFile()
        process = nil
        input = nil
        output = nil
        outputBuffer.removeAll(keepingCapacity: false)
        if let child, child.isRunning {
            child.terminate()
            child.waitUntilExit()
        }
        return true
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
        input.write(encoded)
        input.write(Data([0x0A]))
        if kind != .readOnly {
            controlRequestInFlight = true
        }
        defer {
            if kind != .readOnly {
                controlRequestInFlight = false
            }
        }
        do {
            let responseData = try await readFrame(from: output, kind: kind)
            let response = try JSONDecoder().decode(BridgeResponse<Response>.self, from: responseData)
            guard response.version == Self.protocolVersion, response.id == request.id else {
                throw BridgeClientError.malformedResponse
            }
            if let error = response.error { throw BridgeClientError.requestFailed(error.code) }
            guard let result = response.result else { throw BridgeClientError.malformedResponse }
            return result
        } catch let error as BridgeClientError {
            if case .requestFailed = error {
                throw error
            }
            if kind == .readOnly {
                stop()
            }
            throw error
        } catch {
            if kind == .readOnly {
                stop()
            }
            throw error
        }
    }

    private func readFrame(from output: FileHandle, kind: BridgeRequestKind) async throws -> Data {
        let deadline = kind == .readOnly
            ? Date().timeIntervalSinceReferenceDate + Double(Self.readOnlyRequestTimeoutMilliseconds) / 1_000
            : nil
        while true {
            if kind == .readOnly {
                try Task.checkCancellation()
            }
            if let newline = outputBuffer.firstIndex(of: 0x0A) {
                let frame = outputBuffer.prefix(upTo: newline)
                outputBuffer.removeSubrange(...newline)
                guard frame.count <= Self.maximumFrameBytes else { throw BridgeClientError.malformedResponse }
                return Data(frame)
            }
            if let deadline, Date().timeIntervalSinceReferenceDate >= deadline {
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

    private static func sha256(of url: URL) throws -> String {
        let digest = SHA256.hash(data: try Data(contentsOf: url))
        return digest.map { String(format: "%02x", $0) }.joined()
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
    let groups: [GroupSummary]
    let groupWarnings: [GroupWarning]
}
struct InventoryItem: Decodable, Identifiable { let provider: String; let kind: String; let category: String; let layer: String; let id: String; let displayName: String; let enabled: Bool; let mutability: String }
struct BridgeWarning: Decodable, Identifiable { let provider: String; let layer: String?; let code: String; var id: String { "\(provider)-\(code)" } }
struct GroupWarning: Decodable, Identifiable {
    let scope: String
    let code: String

    var id: String { "\(scope)-\(code)" }
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
    let providerReach: String
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
    let providerReach: String
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
    let providerReach: String?
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
}
struct RestorePlanEnvelope: Decodable { let operationId: String; let plan: RestorePlan }
struct RestorePlan: Decodable { let backupId: String; let providers: [String]; let authentication: String; let affectedResourceIds: [String]; let planFingerprint: String }
struct RestoreApplyEnvelope: Decodable { let result: RestoreApplyResult }
struct RestoreApplyResult: Decodable { let status: RestoreStatus; let backupId: String; let affectedTargetCount: Int }
