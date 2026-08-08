import AppKit
import Darwin
import Foundation
import XCTest
@testable import UnpinDesktop

@MainActor
final class DesktopUpdateControllerTests: XCTestCase {
    private let app = URL(fileURLWithPath: "/Applications/UnpinDesktop.app", isDirectory: true)

    func testDesktopUpdateCommandsUseBundledBridgeAndExactConfirmation() {
        let bridge = app.appendingPathComponent("Contents/MacOS/unpin")

        XCTAssertEqual(
            DesktopUpdateController.checkCommand(
                executableURL: bridge,
                appBundleURL: app
            ),
            DesktopUpdateCommand(
                executableURL: bridge,
                arguments: [
                    "update", "check",
                    "--target", "desktop",
                    "--install-path", "/Applications/UnpinDesktop.app",
                    "--json",
                ]
            )
        )
        XCTAssertEqual(
            DesktopUpdateController.applyCommand(
                executableURL: bridge,
                appBundleURL: app,
                version: "1.1.0"
            ),
            DesktopUpdateCommand(
                executableURL: bridge,
                arguments: [
                    "update", "apply",
                    "--target", "desktop",
                    "--install-path", "/Applications/UnpinDesktop.app",
                    "--confirm", "1.1.0",
                    "--json",
                ]
            )
        )
    }

    func testDesktopUpdateProcessKeepsStdoutPureAndDrainsStderr() async {
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "printf stdout; printf stderr >&2"]
        )

        do {
            let output = try await DesktopUpdateProcess.run(command)
            XCTAssertEqual(String(data: output, encoding: .utf8), "stdout")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDesktopUpdateProcessBoundsChildOutput() async {
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "/usr/bin/head -c 1048577 /dev/zero"]
        )

        do {
            _ = try await DesktopUpdateProcess.run(command)
            XCTFail("expected oversized child output to fail")
        } catch DesktopUpdateError.outputTooLarge {
            // Expected bounded-output rejection.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDesktopUpdateProcessBoundsStderrWithoutDeadlock() async {
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "/usr/bin/head -c 1048577 /dev/zero >&2"]
        )

        do {
            _ = try await DesktopUpdateProcess.run(command)
            XCTFail("expected oversized stderr to fail")
        } catch DesktopUpdateError.outputTooLarge {
            // Expected bounded-output rejection.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDesktopUpdateProcessDecodesJSONErrorEnvelope() async {
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: [
                "-c",
                "printf '{\"schemaVersion\":1,\"status\":\"error\",\"errorCode\":\"update_failed\",\"reason\":\"bad confirmation\"}'; exit 1",
            ]
        )

        do {
            _ = try await DesktopUpdateProcess.run(command)
            XCTFail("expected command failure")
        } catch DesktopUpdateError.commandFailed(let message) {
            XCTAssertEqual(message, "bad confirmation")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDesktopUpdateProcessTimesOutAndReapsDirectChildAndDescendant() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-update-timeout-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let pidFile = root.appendingPathComponent("pid")
        let pidPath = pidFile.path.replacingOccurrences(of: "'", with: "'\\''")
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: [
                "-c",
                "printf '%s' $$ > '\(pidPath)'; (while :; do printf x >&2; done) & while :; do sleep 1; done",
            ]
        )

        do {
            _ = try await DesktopUpdateProcess.run(command, timeout: 0.1)
            XCTFail("expected hung child to time out")
        } catch DesktopUpdateError.timedOut {
            let pid = try await waitForPID(in: pidFile)
            XCTAssertNotEqual(kill(pid, 0), 0, "timed out process group should be gone")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testDesktopUpdateProcessCancellationTerminatesChild() async {
        let command = DesktopUpdateCommand(
            executableURL: URL(fileURLWithPath: "/bin/sh"),
            arguments: ["-c", "exec /bin/sleep 5"]
        )
        let task = Task {
            try await DesktopUpdateProcess.run(command, timeout: 5)
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("expected cancellation")
        } catch is CancellationError {
            // Expected process termination and task cancellation.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testBridgeVerifierFailurePreventsUpdaterCommand() async {
        let recorder = DesktopUpdateCommandRecorder(result: Data())
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { command in try await recorder.run(command) },
            verifyBridge: { _ in throw BridgeClientError.bundleIntegrityMismatch }
        )

        await controller.check(interactive: true)

        let invocationCount = await recorder.invocationCount()
        XCTAssertEqual(invocationCount, 0)
        guard case let .failed(message) = controller.phase else {
            return XCTFail("expected verifier failure")
        }
        XCTAssertTrue(message.contains("did not match"))
    }

    func testRepeatedAutomaticCheckDoesNotCancelActiveCheck() async {
        let recorder = DesktopUpdateCommandRecorder(result: Self.checkJSON(status: "current"))
        let controller = DesktopUpdateController(
            runCommand: { command in try await recorder.run(command) },
            verifyBridge: { _ in }
        )

        controller.startCheck(interactive: false)
        controller.startCheck(interactive: false)
        try? await Task.sleep(nanoseconds: 300_000_000)

        let invocationCount = await recorder.invocationCount()
        XCTAssertEqual(invocationCount, 1)
        XCTAssertEqual(controller.phase, DesktopUpdatePhase.current("1.0.2"))
    }

    func testInteractiveRecheckCannotCancelActiveInstall() async {
        let recorder = DesktopUpdateCommandRecorder(result: Self.applyJSON())
        let lifecycle = DesktopUpdateLifecycleRecorder()
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { command in try await recorder.run(command) },
            verifyBridge: { _ in },
            relaunchApplication: { _ in lifecycle.events.append("relaunch") },
            terminateApplication: { lifecycle.events.append("terminate") }
        )
        let status = availableStatus()

        controller.startInstall(status)
        XCTAssertEqual(controller.phase, DesktopUpdatePhase.installing("1.1.0"))
        controller.startCheck(interactive: true)
        XCTAssertEqual(controller.phase, DesktopUpdatePhase.installing("1.1.0"))

        try? await Task.sleep(nanoseconds: 300_000_000)
        let invocationCount = await recorder.invocationCount()
        XCTAssertEqual(invocationCount, 1)
        XCTAssertEqual(lifecycle.events, ["relaunch", "terminate"])
    }

    func testCancellationAfterApplyReturnsSurfacesRecoveryAndDoesNotTerminate() async {
        let recorder = ApplyReturnRecorder(result: Self.applyJSON())
        let termination = DesktopUpdateTerminationRecorder()
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { _ in await recorder.returnResult() },
            verifyBridge: { _ in },
            relaunchApplication: { _ in
                try await Task.sleep(nanoseconds: 1_000_000_000)
            },
            terminateApplication: { termination.didTerminate = true }
        )
        let task = Task { await controller.install(self.availableStatus()) }
        await recorder.waitUntilReturned()
        task.cancel()
        await task.value

        guard case let .failed(message) = controller.phase else {
            return XCTFail("expected post-apply cancellation failure")
        }
        XCTAssertTrue(message.contains("may have been committed"))
        XCTAssertTrue(message.contains("Rollback backup"))
        XCTAssertFalse(termination.didTerminate)
    }

    func testMalformedApplyResponseRetainsRecoveryMessageAndDoesNotTerminate() async {
        let termination = DesktopUpdateTerminationRecorder()
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { _ in Data("not json".utf8) },
            verifyBridge: { _ in },
            relaunchApplication: { _ in },
            terminateApplication: { termination.didTerminate = true }
        )

        await controller.install(availableStatus())

        guard case let .failed(message) = controller.phase else {
            return XCTFail("expected malformed response failure")
        }
        XCTAssertTrue(message.contains("may have been committed"))
        XCTAssertFalse(termination.didTerminate)
    }

    func testRelaunchFailureDoesNotTerminateAndPreservesEvidence() async {
        let termination = DesktopUpdateTerminationRecorder()
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { _ in Self.applyJSON() },
            verifyBridge: { _ in },
            relaunchApplication: { _ in
                throw DesktopUpdateError.commandFailed("launch failed")
            },
            terminateApplication: { termination.didTerminate = true }
        )

        await controller.install(availableStatus())

        XCTAssertEqual(controller.recoveryEvidence?.installedVersion, "1.1.0")
        guard case let .failed(message) = controller.phase else {
            return XCTFail("expected relaunch failure")
        }
        XCTAssertTrue(message.contains("launch failed"))
        XCTAssertTrue(message.contains("Rollback backup"))
        XCTAssertFalse(termination.didTerminate)
    }

    func testApplyContractRequiresNotRequestedRelaunchAndNoWarning() async {
        let termination = DesktopUpdateTerminationRecorder()
        let controller = DesktopUpdateController(
            appBundleURL: app,
            bridgeExecutableURL: app.appendingPathComponent("Contents/MacOS/unpin"),
            runCommand: { _ in Self.applyJSON(relaunchStatus: "failed", warning: "relaunch failed") },
            verifyBridge: { _ in },
            relaunchApplication: { _ in XCTFail("desktop flow must not relaunch") },
            terminateApplication: { termination.didTerminate = true }
        )

        await controller.install(availableStatus())

        XCTAssertEqual(controller.recoveryEvidence?.backupPath, "/Applications/.UnpinDesktop.app.unpin-backup-1.0.2")
        XCTAssertFalse(termination.didTerminate)
        guard case let .failed(message) = controller.phase else {
            return XCTFail("expected contradictory relaunch contract failure")
        }
        XCTAssertTrue(message.contains("may have been committed"))
    }

    func testDesktopUpdateCheckPresentsAvailableRelease() async {
        let controller = DesktopUpdateController(
            runCommand: { _ in Self.checkJSON(status: "available") },
            verifyBridge: { _ in }
        )

        await controller.check(interactive: false)

        guard case let .available(status) = controller.phase else {
            return XCTFail("expected an available update")
        }
        XCTAssertEqual(status.latestVersion, "1.1.0")
        XCTAssertEqual(controller.prompt, DesktopUpdatePrompt.available(status))
    }

    func testDesktopManualCheckReportsCurrentRelease() async {
        let controller = DesktopUpdateController(
            runCommand: { _ in Self.checkJSON(status: "current") },
            verifyBridge: { _ in }
        )

        await controller.check(interactive: true)

        XCTAssertEqual(controller.phase, DesktopUpdatePhase.current("1.0.2"))
        XCTAssertEqual(controller.prompt, DesktopUpdatePrompt.current("1.0.2"))
    }

    private func availableStatus() -> DesktopUpdateStatus {
        DesktopUpdateStatus(
            schemaVersion: 1,
            status: .available,
            target: .desktop,
            platform: .macOSArm64,
            currentVersion: "1.0.2",
            latestVersion: "1.1.0",
            archiveName: "unpin-desktop-v1.1.0-aarch64-apple-darwin.tar.gz",
            releaseUrl: URL(string: "https://github.com/IgorArkhipov/unpin/releases/tag/v1.1.0")!
        )
    }

    private nonisolated static func checkJSON(status: String) -> Data {
        let archive = status == "available"
            ? "\"unpin-desktop-v1.1.0-aarch64-apple-darwin.tar.gz\""
            : "null"
        let latest = status == "available" ? "1.1.0" : "1.0.2"
        return Data(
            "{\"schemaVersion\":1,\"status\":\"\(status)\",\"target\":\"desktop\",\"platform\":\"aarch64-apple-darwin\",\"currentVersion\":\"1.0.2\",\"latestVersion\":\"\(latest)\",\"archiveName\":\(archive),\"releaseUrl\":\"https://github.com/IgorArkhipov/unpin/releases/tag/v\(latest)\"}".utf8
        )
    }

    private nonisolated static func applyJSON(
        relaunchStatus: String = "notRequested",
        warning: String? = nil
    ) -> Data {
        let warningJSON = warning.map { "\"\($0)\"" } ?? "null"
        return Data(
            "{\"schemaVersion\":1,\"status\":\"updated\",\"target\":\"desktop\",\"previousVersion\":\"1.0.2\",\"installedVersion\":\"1.1.0\",\"installPath\":\"/Applications/UnpinDesktop.app\",\"backupPath\":\"/Applications/.UnpinDesktop.app.unpin-backup-1.0.2\",\"keychainRequirementPreserved\":true,\"relaunchStatus\":\"\(relaunchStatus)\",\"warning\":\(warningJSON)}".utf8
        )
    }

    private func waitForPID(in path: URL) async throws -> pid_t {
        for _ in 0..<100 {
            if let value = try? String(contentsOf: path, encoding: .utf8),
               let pid = Int32(value.trimmingCharacters(in: .whitespacesAndNewlines))
            {
                return pid
            }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        throw NSError(domain: "DesktopUpdateControllerTests", code: 1)
    }
}

@MainActor
private final class DesktopUpdateTerminationRecorder {
    var didTerminate = false
}

@MainActor
private final class DesktopUpdateLifecycleRecorder {
    var events: [String] = []
}

private actor DesktopUpdateCommandRecorder {
    private let result: Data
    private var count = 0

    init(result: Data) {
        self.result = result
    }

    func run(_: DesktopUpdateCommand) async throws -> Data {
        count += 1
        try await Task.sleep(nanoseconds: 100_000_000)
        return result
    }

    func invocationCount() -> Int {
        count
    }
}

private actor ApplyReturnRecorder {
    private let result: Data
    private var returned = false
    private var continuation: CheckedContinuation<Void, Never>?

    init(result: Data) {
        self.result = result
    }

    func returnResult() -> Data {
        returned = true
        continuation?.resume()
        continuation = nil
        return result
    }

    func waitUntilReturned() async {
        if returned { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }
}
