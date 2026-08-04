import Foundation

enum BridgeClientError: LocalizedError {
    case bundledExecutableMissing
    case incompatibleProtocol
    case malformedResponse
    case requestFailed(String)
    case childStopped

    var errorDescription: String? {
        switch self {
        case .bundledExecutableMissing: "The bundled Unpin executable is missing. Rebuild the app."
        case .incompatibleProtocol: "The bundled Unpin executable does not support this workbench."
        case .malformedResponse: "The Unpin bridge returned an invalid response."
        case .requestFailed(let code): "The Unpin bridge blocked this request: \(code)."
        case .childStopped: "The bundled Unpin process stopped unexpectedly."
        }
    }
}

actor BridgeClient {
    static let protocolVersion = 1

    private let executableURL: URL
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var outputBuffer = Data()
    private var requestSequence = 0

    init(executableURL: URL) {
        self.executableURL = executableURL
    }

    func start() throws {
        guard FileManager.default.isExecutableFile(atPath: executableURL.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        let child = Process()
        child.executableURL = executableURL
        child.arguments = ["desktop", "bridge"]
        child.currentDirectoryURL = executableURL.deletingLastPathComponent()
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

    func handshake() throws -> BridgeHandshake {
        let handshake: BridgeHandshake = try request(method: "handshake", parameters: EmptyParameters())
        guard handshake.protocolVersion == Self.protocolVersion else {
            throw BridgeClientError.incompatibleProtocol
        }
        return handshake
    }

    func snapshot() throws -> BridgeSnapshot {
        try request(method: "snapshot", parameters: EmptyParameters())
    }

    func planGroup(name: String, target: String) throws -> GroupPlanEnvelope {
        try request(method: "group.plan", parameters: GroupPlanParameters(qualifiedName: name, target: target))
    }

    func approveGroup(operationID: String, fingerprint: String) throws -> GroupApprovalEnvelope {
        try request(method: "group.approve", parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint))
    }

    func applyGroup(operationID: String, fingerprint: String) throws -> GroupApplyEnvelope {
        try request(method: "group.apply", parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint))
    }

    func recoverySnapshot() throws -> RecoverySnapshot {
        try request(method: "recovery.snapshot", parameters: EmptyParameters())
    }

    func planRestore(backupID: String) throws -> RestorePlanEnvelope {
        try request(method: "restore.plan", parameters: RestorePlanParameters(backupId: backupID))
    }

    func approveRestore(operationID: String, fingerprint: String) throws -> GroupApprovalEnvelope {
        try request(method: "restore.approve", parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint))
    }

    func applyRestore(operationID: String, fingerprint: String) throws -> RestoreApplyEnvelope {
        try request(method: "restore.apply", parameters: GroupApprovalParameters(operationId: operationID, planFingerprint: fingerprint))
    }

    func stop() {
        input?.closeFile()
        output?.closeFile()
        process?.terminate()
        process = nil
        input = nil
        output = nil
        outputBuffer.removeAll(keepingCapacity: false)
    }

    private func request<Parameters: Encodable, Response: Decodable>(
        method: String,
        parameters: Parameters
    ) throws -> Response {
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
        guard encoded.count <= 1_048_576 else { throw BridgeClientError.malformedResponse }
        input.write(encoded)
        input.write(Data([0x0A]))
        let responseData = try readFrame(from: output)
        let response = try JSONDecoder().decode(BridgeResponse<Response>.self, from: responseData)
        guard response.version == Self.protocolVersion, response.id == request.id else {
            throw BridgeClientError.malformedResponse
        }
        if let error = response.error { throw BridgeClientError.requestFailed(error.code) }
        guard let result = response.result else { throw BridgeClientError.malformedResponse }
        return result
    }

    private func readFrame(from output: FileHandle) throws -> Data {
        while true {
            if let newline = outputBuffer.firstIndex(of: 0x0A) {
                let frame = outputBuffer.prefix(upTo: newline)
                outputBuffer.removeSubrange(...newline)
                guard frame.count <= 1_048_576 else { throw BridgeClientError.malformedResponse }
                return Data(frame)
            }
            guard let chunk = try output.read(upToCount: 4_096), !chunk.isEmpty else {
                throw BridgeClientError.childStopped
            }
            outputBuffer.append(chunk)
            guard outputBuffer.count <= 1_048_576 else { throw BridgeClientError.malformedResponse }
        }
    }
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
private struct EmptyParameters: Codable {}
private struct GroupPlanParameters: Codable { let qualifiedName: String; let target: String }
private struct GroupApprovalParameters: Codable { let operationId: String; let planFingerprint: String }
private struct RestorePlanParameters: Codable { let backupId: String }

struct BridgeHandshake: Decodable { let protocolVersion: Int; let binaryVersion: String; let capabilities: [String] }
struct BridgeSnapshot: Decodable { let capturedAtUnix: Int; let inventory: [InventoryItem]; let warnings: [BridgeWarning]; let groups: [GroupSummary] }
struct InventoryItem: Decodable, Identifiable { let provider: String; let kind: String; let category: String; let layer: String; let id: String; let displayName: String; let enabled: Bool; let mutability: String }
struct BridgeWarning: Decodable, Identifiable { let provider: String; let layer: String?; let code: String; var id: String { "\(provider)-\(code)" } }
struct GroupSummary: Decodable, Identifiable { let qualifiedName: String; let state: String?; let fresh: Bool?; var id: String { qualifiedName } }
struct GroupPlanEnvelope: Decodable { let plan: GroupPlan }
struct GroupPlan: Decodable { let operationId: String?; let qualifiedName: String; let target: String; let planFingerprint: String; let providerReach: String; let members: [GroupPlanMember] }
struct GroupPlanMember: Decodable, Identifiable { let identity: GroupMemberIdentity; let outcome: String; let reason: String?; var id: String { identity.id } }
struct GroupMemberIdentity: Decodable { let provider: String; let layer: String; let kind: String; let category: String; let id: String }
struct GroupApprovalEnvelope: Decodable { let operationId: String; let planFingerprint: String; let approval: String }
struct GroupApplyEnvelope: Decodable { let result: GroupApplyResult }
struct GroupApplyResult: Decodable { let operationId: String; let requestedState: String; let lifecycle: String; let backupIds: [String]; let observationFresh: Bool }
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
struct RecoveryOperation: Decodable, Identifiable { let operationId: String; let operationKind: String; let lifecycle: String; let effectGraphDigest: String?; let authorizationRecorded: Bool?; let terminalCode: String?; let recoveryRequired: Bool; let resourceCount: Int; let backupIds: [String]?; let evidenceAvailable: Bool?; var id: String { operationId } }
struct RestorePlanEnvelope: Decodable { let operationId: String; let plan: RestorePlan }
struct RestorePlan: Decodable { let backupId: String; let providers: [String]; let authentication: String; let affectedResourceIds: [String]; let planFingerprint: String }
struct RestoreApplyEnvelope: Decodable { let result: RestoreApplyResult }
struct RestoreApplyResult: Decodable { let status: RestoreStatus; let backupId: String; let affectedTargetCount: Int }
