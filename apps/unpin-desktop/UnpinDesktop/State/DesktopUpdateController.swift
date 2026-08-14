import AppKit
import Darwin
import Foundation

struct DesktopUpdateCommand: Equatable, Sendable {
    let executableURL: URL
    let arguments: [String]
}

enum DesktopUpdateTarget: String, Decodable, Sendable {
    case desktop
}

enum DesktopUpdatePlatform: String, Decodable, Sendable {
    case macOSArm64 = "aarch64-apple-darwin"
    case macOSX86_64 = "x86_64-apple-darwin"
}

enum DesktopUpdateApplyStatus: String, Decodable, Sendable {
    case updated
}

enum DesktopUpdateRelaunchStatus: String, Decodable, Sendable {
    case notRequested
    case confirmed
    case failed
}

struct DesktopUpdateStatus: Decodable, Equatable, Sendable {
    enum Availability: String, Decodable, Sendable {
        case available
        case current
    }

    let schemaVersion: Int
    let status: Availability
    let target: DesktopUpdateTarget
    let platform: DesktopUpdatePlatform
    let currentVersion: String
    let latestVersion: String
    let archiveName: String?
    let releaseUrl: URL

    func validate() throws {
        guard schemaVersion == 1,
              target == .desktop,
              currentVersion.isEmpty == false,
              latestVersion.isEmpty == false,
              releaseUrl.scheme == "https",
              releaseUrl.host == "github.com"
        else {
            throw DesktopUpdateError.invalidResponse
        }
        if status == .available, archiveName?.isEmpty != false {
            throw DesktopUpdateError.invalidResponse
        }
    }
}

struct DesktopUpdateApplyResult: Decodable, Equatable, Sendable {
    let schemaVersion: Int
    let status: DesktopUpdateApplyStatus
    let target: DesktopUpdateTarget
    let previousVersion: String
    let installedVersion: String
    let installPath: String
    let backupPath: String
    let credentialBrokerPreserved: Bool
    let relaunchStatus: DesktopUpdateRelaunchStatus
    let warning: String?

    func validate(expectedVersion: String, expectedInstallPath: URL) throws {
        guard schemaVersion == 1,
              status == .updated,
              target == .desktop,
              previousVersion.isEmpty == false,
              installedVersion == expectedVersion,
              URL(fileURLWithPath: installPath).standardizedFileURL.path
                  == expectedInstallPath.standardizedFileURL.path,
              backupPath.isEmpty == false,
              credentialBrokerPreserved,
              relaunchStatus == .notRequested,
              warning == nil
        else {
            throw DesktopUpdateError.invalidResponse
        }
    }
}

private struct DesktopUpdateErrorEnvelope: Decodable {
    let schemaVersion: Int
    let status: String
    let errorCode: String
    let reason: String
}

enum DesktopUpdatePhase: Equatable {
    case idle
    case checking
    case current(String)
    case available(DesktopUpdateStatus)
    case installing(String)
    case installed(String)
    case failed(String)
}

enum DesktopUpdatePrompt: Identifiable, Equatable {
    case available(DesktopUpdateStatus)
    case current(String)
    case failure(String)

    var id: String {
        switch self {
        case let .available(status): "available-\(status.latestVersion)"
        case let .current(version): "current-\(version)"
        case let .failure(message): "failure-\(message)"
        }
    }
}

enum DesktopUpdateError: LocalizedError {
    case commandFailed(String)
    case invalidResponse
    case outputTooLarge
    case timedOut

    var errorDescription: String? {
        switch self {
        case let .commandFailed(message): message
        case .invalidResponse: "The update service returned an invalid response."
        case .outputTooLarge: "The update command returned too much data."
        case .timedOut: "The update command timed out."
        }
    }
}

typealias DesktopUpdateCommandRunner = @Sendable (DesktopUpdateCommand) async throws -> Data
typealias DesktopUpdateBridgeVerifier = @Sendable (URL) async throws -> Void

enum DesktopUpdateProcess {
    private static let maximumOutputBytes = 1_048_576
    private static let commandTimeout: TimeInterval = 120

    static func run(_ command: DesktopUpdateCommand) async throws -> Data {
        try await run(command, timeout: commandTimeout)
    }

    static func run(
        _ command: DesktopUpdateCommand,
        timeout: TimeInterval
    ) async throws -> Data {
        let running = DesktopUpdateRunningProcess(maximumOutputBytes: maximumOutputBytes)
        return try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: Data.self) { group in
                group.addTask {
                    try await withCheckedThrowingContinuation { continuation in
                        DispatchQueue.global(qos: .utility).async {
                            continuation.resume(with: Result { try running.execute(command) })
                        }
                    }
                }
                group.addTask {
                    let timeoutNanoseconds = UInt64(max(timeout, 0) * 1_000_000_000)
                    try await Task.sleep(nanoseconds: timeoutNanoseconds)
                    running.stop(.timedOut)
                    throw DesktopUpdateError.timedOut
                }
                defer { group.cancelAll() }
                guard let data = try await group.next() else {
                    throw CancellationError()
                }
                return data
            }
        } onCancel: {
            running.stop(.cancelled)
        }
    }
}

private final class DesktopUpdateOutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var stdoutData = Data()
    private var stderrData = Data()
    private var readError: Error?

    func setStdout(_ data: Data) {
        lock.lock()
        stdoutData = data
        lock.unlock()
    }

    func setStderr(_ data: Data) {
        lock.lock()
        stderrData = data
        lock.unlock()
    }

    func setError(_ error: Error) {
        lock.lock()
        if readError == nil {
            readError = error
        }
        lock.unlock()
    }

    func result() -> (stdout: Data, stderr: Data, error: Error?) {
        lock.lock()
        defer { lock.unlock() }
        return (stdoutData, stderrData, readError)
    }
}

private final class DesktopUpdateRunningProcess: @unchecked Sendable {
    enum StopReason {
        case cancelled
        case timedOut
    }

    private let maximumOutputBytes: Int
    private let lock = NSLock()
    private var process: Process?
    private var processGroupID: pid_t?
    private var stopReason: StopReason?

    init(maximumOutputBytes: Int) {
        self.maximumOutputBytes = maximumOutputBytes
    }

    func execute(_ command: DesktopUpdateCommand) throws -> Data {
        let process = Process()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.executableURL = command.executableURL
        process.arguments = command.arguments
        process.environment = [:]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        lock.lock()
        if let stopReason {
            lock.unlock()
            throw error(for: stopReason)
        }
        self.process = process
        lock.unlock()

        var didLaunch = false
        var readers: DispatchGroup?
        do {
            try process.run()
            didLaunch = true

            let groupID: pid_t? = setpgid(process.processIdentifier, process.processIdentifier) == 0
                ? process.processIdentifier
                : nil
            lock.lock()
            processGroupID = groupID
            let stopReasonAfterLaunch = self.stopReason
            lock.unlock()
            if let stopReasonAfterLaunch {
                stop(stopReasonAfterLaunch)
            }

            let collector = DesktopUpdateOutputCollector()
            let outputReaders = DispatchGroup()
            readers = outputReaders
            outputReaders.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { outputReaders.leave() }
                do {
                    collector.setStdout(try self.readBoundedOutput(
                        from: stdoutPipe.fileHandleForReading
                    ))
                } catch {
                    collector.setError(error)
                    self.terminate(process)
                    try? stdoutPipe.fileHandleForReading.close()
                    try? stderrPipe.fileHandleForReading.close()
                }
            }
            outputReaders.enter()
            DispatchQueue.global(qos: .utility).async {
                defer { outputReaders.leave() }
                do {
                    collector.setStderr(try self.readBoundedOutput(
                        from: stderrPipe.fileHandleForReading
                    ))
                } catch {
                    collector.setError(error)
                    self.terminate(process)
                    try? stdoutPipe.fileHandleForReading.close()
                    try? stderrPipe.fileHandleForReading.close()
                }
            }

            process.waitUntilExit()
            // A child that daemonizes can retain the pipe forever.  Give normal
            // readers a short grace period, then close and kill the process group
            // so the direct process is always reaped and this method is bounded.
            if outputReaders.wait(timeout: .now() + 0.5) == .timedOut {
                terminate(process)
                try? stdoutPipe.fileHandleForReading.close()
                try? stderrPipe.fileHandleForReading.close()
                outputReaders.wait()
            }

            let output = collector.result()
            if let readError = output.error {
                throw readError
            }
            let stopReason = clearProcess()
            if let stopReason {
                throw error(for: stopReason)
            }
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                throw DesktopUpdateError.commandFailed(
                    Self.commandFailureMessage(stdout: output.stdout, stderr: output.stderr)
                )
            }
            return output.stdout
        } catch {
            if didLaunch {
                terminate(process)
                if process.isRunning {
                    process.waitUntilExit()
                }
                try? stdoutPipe.fileHandleForReading.close()
                try? stderrPipe.fileHandleForReading.close()
                readers?.wait()
            }
            let stopReason = clearProcess()
            if let stopReason {
                throw self.error(for: stopReason)
            }
            throw error
        }
    }

    func stop(_ reason: StopReason) {
        lock.lock()
        if stopReason == nil {
            stopReason = reason
        }
        let process = process
        lock.unlock()
        guard let process else { return }
        terminate(process)
    }

    private func terminate(_ process: Process) {
        lock.lock()
        let groupID = processGroupID
        lock.unlock()
        if process.isRunning {
            process.terminate()
        }
        if let groupID {
            _ = kill(-groupID, SIGTERM)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.25) {
                _ = kill(-groupID, SIGKILL)
            }
        }
    }

    private func clearProcess() -> StopReason? {
        lock.lock()
        defer { lock.unlock() }
        let recordedStopReason = stopReason
        process = nil
        processGroupID = nil
        return recordedStopReason
    }

    private func error(for reason: StopReason) -> Error {
        switch reason {
        case .cancelled: CancellationError()
        case .timedOut: DesktopUpdateError.timedOut
        }
    }

    private func readBoundedOutput(from handle: FileHandle) throws -> Data {
        var data = Data()
        while let chunk = try handle.read(upToCount: 64 * 1024), chunk.isEmpty == false {
            guard chunk.count <= maximumOutputBytes - data.count else {
                throw DesktopUpdateError.outputTooLarge
            }
            data.append(chunk)
        }
        return data
    }

    private static func commandFailureMessage(stdout: Data, stderr: Data) -> String {
        for data in [stdout, stderr] {
            guard let envelope = try? JSONDecoder().decode(
                DesktopUpdateErrorEnvelope.self,
                from: data
            ),
            envelope.schemaVersion == 1,
            envelope.status == "error",
            envelope.errorCode.isEmpty == false,
            envelope.reason.isEmpty == false
            else {
                continue
            }
            return boundedMessage(envelope.reason)
        }
        for data in [stdout, stderr] {
            guard let raw = String(data: data, encoding: .utf8) else { continue }
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty == false {
                return boundedMessage(trimmed)
            }
        }
        return "The update command failed."
    }

    private static func boundedMessage(_ message: String) -> String {
        String(message.prefix(8_192))
    }
}

typealias DesktopUpdateApplicationRelauncher =
    @MainActor @Sendable (URL) async throws -> Void

private enum DesktopUpdateRelauncher {
    private static let startupGraceNanoseconds: UInt64 = 300_000_000

    @MainActor
    static func relaunch(_ applicationURL: URL) async throws {
        try await relaunch(applicationURL, wait: { nanoseconds in
            try? await Task.sleep(nanoseconds: nanoseconds)
        })
    }

    @MainActor
    static func relaunch(
        _ applicationURL: URL,
        wait: @escaping @Sendable (UInt64) async -> Void
    ) async throws {
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.createsNewApplicationInstance = true
        let application: NSRunningApplication = try await withCheckedThrowingContinuation {
            continuation in
            NSWorkspace.shared.openApplication(
                at: applicationURL,
                configuration: configuration
            ) { application, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let application {
                    continuation.resume(returning: application)
                } else {
                    continuation.resume(
                        throwing: DesktopUpdateError.commandFailed(
                            "The updated application did not launch."
                        )
                    )
                }
            }
        }
        await wait(startupGraceNanoseconds)
        guard application.isTerminated == false else {
            throw DesktopUpdateError.commandFailed(
                "The updated application terminated during relaunch."
            )
        }
    }
}

@MainActor
final class DesktopUpdateController: ObservableObject {
    @Published private(set) var phase: DesktopUpdatePhase = .idle
    @Published var prompt: DesktopUpdatePrompt?
    @Published private(set) var recoveryEvidence: DesktopUpdateApplyResult?

    private let appBundleURL: URL
    private let bridgeExecutableURL: URL
    private let runCommand: DesktopUpdateCommandRunner
    private let verifyBridge: DesktopUpdateBridgeVerifier
    private let relaunchApplication: DesktopUpdateApplicationRelauncher
    private let terminateApplication: @MainActor @Sendable () -> Void
    private var performedAutomaticCheck = false

    init(
        appBundleURL: URL = Bundle.main.bundleURL,
        bridgeExecutableURL: URL = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/unpin", isDirectory: false),
        runCommand: @escaping DesktopUpdateCommandRunner = DesktopUpdateProcess.run,
        verifyBridge: @escaping DesktopUpdateBridgeVerifier = { executableURL in
            try await Task.detached(priority: .utility) {
                try BundledBridgeVerifier.verifyBundled(executableURL: executableURL)
            }.value
        },
        relaunchApplication: @escaping DesktopUpdateApplicationRelauncher =
            DesktopUpdateRelauncher.relaunch,
        terminateApplication: @escaping @MainActor @Sendable () -> Void = {
            NSApplication.shared.terminate(nil)
        }
    ) {
        self.appBundleURL = appBundleURL
        self.bridgeExecutableURL = bridgeExecutableURL
        self.runCommand = runCommand
        self.verifyBridge = verifyBridge
        self.relaunchApplication = relaunchApplication
        self.terminateApplication = terminateApplication
    }

    var isBusy: Bool {
        switch phase {
        case .checking, .installing: true
        default: false
        }
    }

    static func checkCommand(
        executableURL: URL,
        appBundleURL: URL = Bundle.main.bundleURL
    ) -> DesktopUpdateCommand {
        DesktopUpdateCommand(
            executableURL: executableURL,
            arguments: [
                "update",
                "check",
                "--target",
                "desktop",
                "--install-path",
                appBundleURL.path,
                "--json",
            ]
        )
    }

    static func applyCommand(
        executableURL: URL,
        appBundleURL: URL,
        version: String
    ) -> DesktopUpdateCommand {
        DesktopUpdateCommand(
            executableURL: executableURL,
            arguments: [
                "update",
                "apply",
                "--target",
                "desktop",
                "--install-path",
                appBundleURL.path,
                "--confirm",
                version,
                "--json",
            ]
        )
    }

    func startCheck(interactive: Bool) {
        guard isBusy == false else { return }
        if interactive == false {
            guard performedAutomaticCheck == false else {
                return
            }
            performedAutomaticCheck = true
        }
        prompt = nil
        phase = .checking
        Task { [weak self] in
            await self?.performCheck(interactive: interactive, phaseAlreadySet: true)
        }
    }

    func startInstall(_ status: DesktopUpdateStatus) {
        guard status.status == .available, isBusy == false else { return }
        prompt = nil
        recoveryEvidence = nil
        phase = .installing(status.latestVersion)
        Task { [weak self] in
            await self?.performInstall(status, phaseAlreadySet: true)
        }
    }

    func check(interactive: Bool) async {
        await performCheck(interactive: interactive, phaseAlreadySet: false)
    }

    private func performCheck(interactive: Bool, phaseAlreadySet: Bool) async {
        guard phaseAlreadySet || isBusy == false else { return }
        if interactive == false, performedAutomaticCheck == false {
            performedAutomaticCheck = true
        }
        if phaseAlreadySet == false {
            prompt = nil
            phase = .checking
        }
        do {
            try await verifyBridge(bridgeExecutableURL)
            let data = try await runCommand(
                Self.checkCommand(
                    executableURL: bridgeExecutableURL,
                    appBundleURL: appBundleURL
                )
            )
            try Task.checkCancellation()
            let status = try JSONDecoder().decode(DesktopUpdateStatus.self, from: data)
            try status.validate()
            switch status.status {
            case .available:
                phase = .available(status)
                prompt = .available(status)
            case .current:
                phase = .current(status.currentVersion)
                if interactive {
                    prompt = .current(status.currentVersion)
                }
            }
        } catch is CancellationError {
            if case .checking = phase {
                phase = .idle
            }
        } catch {
            let message = Self.message(for: error)
            phase = .failed(message)
            if interactive {
                prompt = .failure(message)
            }
        }
    }

    func install(_ status: DesktopUpdateStatus) async {
        guard status.status == .available, isBusy == false else { return }
        prompt = nil
        recoveryEvidence = nil
        phase = .installing(status.latestVersion)
        await performInstall(status, phaseAlreadySet: true)
    }

    private func performInstall(
        _ status: DesktopUpdateStatus,
        phaseAlreadySet: Bool
    ) async {
        if phaseAlreadySet == false {
            guard status.status == .available, isBusy == false else { return }
            prompt = nil
            recoveryEvidence = nil
            phase = .installing(status.latestVersion)
        }

        var applyReturned = false
        var decodedResult: DesktopUpdateApplyResult?
        do {
            try await verifyBridge(bridgeExecutableURL)
            let command = Self.applyCommand(
                executableURL: bridgeExecutableURL,
                appBundleURL: appBundleURL,
                version: status.latestVersion
            )
            let data = try await runCommand(command)
            // From this point on the updater may already have swapped the app.
            // Cancellation is deliberately not translated back to idle.
            applyReturned = true
            let result = try JSONDecoder().decode(DesktopUpdateApplyResult.self, from: data)
            decodedResult = result
            recoveryEvidence = result
            try result.validate(
                expectedVersion: status.latestVersion,
                expectedInstallPath: appBundleURL
            )
            try await relaunchApplication(appBundleURL)
            phase = .installed(result.installedVersion)
            terminateApplication()
        } catch is CancellationError {
            if applyReturned {
                failAfterApply(
                    error: DesktopUpdateError.commandFailed(
                        "The update install was cancelled after the apply command returned."
                    ),
                    result: decodedResult
                )
            } else {
                phase = .idle
            }
        } catch {
            if applyReturned {
                failAfterApply(error: error, result: decodedResult)
            } else {
                let message = Self.message(for: error)
                phase = .failed(message)
                prompt = .failure(message)
            }
        }
    }

    private func failAfterApply(
        error: Error,
        result: DesktopUpdateApplyResult?
    ) {
        var message = "The update command returned, but validation or relaunch failed. The update may have been committed."
        if let result {
            message += " Installed version: \(result.installedVersion). Rollback backup: \(result.backupPath)."
        }
        message += " " + Self.message(for: error)
        phase = .failed(message)
        prompt = .failure(message)
    }

    func dismissPrompt() {
        prompt = nil
    }

    private static func message(for error: Error) -> String {
        if let localized = error as? LocalizedError,
           let description = localized.errorDescription,
           description.isEmpty == false
        {
            return description
        }
        return error.localizedDescription
    }
}
