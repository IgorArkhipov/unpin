import CryptoKit
import Foundation
import XCTest
@testable import UnpinDesktop

final class BridgeClientTests: XCTestCase {
    func testBundledBridgeCompletesHandshake() async throws {
        let executable = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("unpin")
        let manifestURL = try XCTUnwrap(Bundle.main.url(
            forResource: "unpin-bridge-manifest",
            withExtension: "json"
        ))
        let manifest = try JSONDecoder().decode(
            BundledBridgeManifest.self,
            from: Data(contentsOf: manifestURL)
        )
        let projectRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-desktop-handshake-\(UUID().uuidString)", isDirectory: true)
        let fixtureRoot = projectRoot.appendingPathComponent("fixtures", isDirectory: true)
        let appStateRoot = projectRoot.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(at: projectRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fixtureRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: appStateRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: projectRoot) }

        let bridge = BridgeClient(
            executableURL: executable,
            projectRoot: projectRoot,
            manifest: manifest,
            roots: BridgeLaunchRoots(
                fixtureRoot: fixtureRoot,
                homeRoot: fixtureRoot,
                appStateRoot: appStateRoot
            )
        )

        do {
            try await bridge.start()
            let handshake = try await bridge.handshake()
            XCTAssertEqual(handshake.protocolVersion, BridgeClient.protocolVersion)
            XCTAssertEqual(handshake.binaryVersion, manifest.unpinVersion)
            let stopped = await bridge.stop()
            XCTAssertTrue(stopped)
        } catch {
            _ = await bridge.stop()
            throw error
        }
    }

    func testStartRejectsManifestDigestMismatch() async throws {
        let temporary = try temporaryExecutable(script: "#!/bin/sh\nexit 0\n")
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: String(repeating: "0", count: 64)
            )
        )

        do {
            try await bridge.start()
            XCTFail("digest mismatch should fail before launch")
        } catch BridgeClientError.bundleIntegrityMismatch {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testHandshakeRejectsBinaryVersionMismatch() async throws {
        let script = """
        #!/bin/sh
        IFS= read -r request
        printf '%s\\n' '{"version":2,"id":"desktop-1","result":{"protocolVersion":2,"binaryVersion":"0.6.2","capabilities":[]}}'
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            )
        )

        do {
            try await bridge.start()
            _ = try await bridge.handshake()
            XCTFail("binary version mismatch should fail the handshake")
        } catch BridgeClientError.incompatibleBinary {
            // Expected.
        } catch {
            _ = await bridge.stop()
            XCTFail("unexpected error: \(error)")
        }
    }

    func testStalledControlTimeoutStopsChildAndAllowsRestart() async throws {
        let script = """
        #!/bin/sh
        while IFS= read -r request; do
            case "$request" in
                *group.approve*)
                    while :; do sleep 1; done
                    ;;
                *handshake*)
                    printf '%s\\n' '{"version":2,"id":"desktop-2","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":[]}}'
                    ;;
            esac
        done
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            ),
            controlRequestTimeoutMilliseconds: 50
        )

        try await bridge.start()
        do {
            _ = try await bridge.approveGroup(operationID: "operation", fingerprint: "fingerprint")
            XCTFail("a stalled control request must not complete")
        } catch BridgeClientError.controlRequestUncertain {
            // The child was stopped because the mutation outcome is uncertain.
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        try await bridge.start()
        let handshake = try await bridge.handshake()
        XCTAssertEqual(handshake.binaryVersion, "1.0.0")
        let stopped = await bridge.stop()
        XCTAssertTrue(stopped)
    }

    func testStalledControlTimeoutKillsChildIgnoringSigterm() async throws {
        let script = """
        #!/bin/sh
        trap '' TERM
        while IFS= read -r request; do
            case "$request" in
                *group.approve*)
                    while :; do :; done
                    ;;
                *handshake*)
                    printf '%s\\n' '{"version":2,"id":"desktop-2","result":{"protocolVersion":2,"binaryVersion":"1.0.0","capabilities":[]}}'
                    ;;
            esac
        done
        """
        let temporary = try temporaryExecutable(script: script)
        defer { try? FileManager.default.removeItem(at: temporary.root) }
        let digest = SHA256.hash(data: try Data(contentsOf: temporary.executable))
            .map { String(format: "%02x", $0) }
            .joined()
        let bridge = BridgeClient(
            executableURL: temporary.executable,
            projectRoot: temporary.root,
            manifest: BundledBridgeManifest(
                bridgeProtocolVersion: BridgeClient.protocolVersion,
                unpinVersion: "1.0.0",
                sha256: digest
            ),
            controlRequestTimeoutMilliseconds: 50,
            terminationPolicy: BridgeTerminationPolicy(
                gracePeriodNanoseconds: 10_000_000,
                settlePeriodNanoseconds: 10_000_000
            )
        )

        try await bridge.start()
        do {
            _ = try await bridge.approveGroup(operationID: "operation", fingerprint: "fingerprint")
            XCTFail("a stalled control request must not complete")
        } catch BridgeClientError.controlRequestUncertain {
            // SIGTERM is ignored; forceStop must escalate to SIGKILL and return.
        } catch {
            XCTFail("unexpected error: \(error)")
        }

        try await bridge.start()
        let handshake = try await bridge.handshake()
        XCTAssertEqual(handshake.binaryVersion, "1.0.0")
        let stopped = await bridge.stop()
        XCTAssertTrue(stopped)
    }

    func testIncompatibleGroupDefaultsMissingMembersToEmpty() throws {
        let data = Data(#"""
        {
          "qualifiedName": "personal:incompatible",
          "scope": "personal",
          "revision": "revision-1",
          "contextCompatible": false,
          "state": null,
          "fresh": true
        }
        """#.utf8)

        let group = try JSONDecoder().decode(GroupSummary.self, from: data)

        XCTAssertFalse(group.contextCompatible)
        XCTAssertTrue(group.members.isEmpty)
    }

    func testProviderReachDecodesAllAndSelected() throws {
        let all = try JSONDecoder().decode(
            ProviderReachValue.self,
            from: Data("\"all\"".utf8)
        )
        XCTAssertEqual(all, .all)

        let selected = try JSONDecoder().decode(
            ProviderReachValue.self,
            from: Data(#"""
            {"selected":{"provider":"codex","provenance":"explicit-input"}}
            """#.utf8)
        )
        XCTAssertEqual(selected, .selected(provider: "codex", provenance: "explicit-input"))

        let plan = try JSONDecoder().decode(
            GroupPlan.self,
            from: Data(#"""
            {
              "operationId": null,
              "disposition": "actionable",
              "mode": "native",
              "qualifiedName": "personal:example",
              "scope": "personal",
              "groupRevision": "revision-1",
              "target": "enable",
              "totalMembers": 0,
              "providerReach": {"selected":{"provider":"codex","provenance":"explicit-input"}},
              "providerCoverage": {"entries":[]},
              "lifecycle": "planned",
              "members": [],
              "resources": [],
              "cohorts": [],
              "planFingerprint": "fingerprint"
            }
            """#.utf8)
        )
        XCTAssertEqual(plan.providerReach, "selected · codex · explicit-input")
        XCTAssertEqual(plan.$providerReach, selected)
    }

    func testRecoveryOperationAllowsMissingProviderReach() throws {
        let operation = try JSONDecoder().decode(
            RecoveryOperation.self,
            from: Data(#"""
            {
              "operationId": "operation-1",
              "operationKind": "group-toggle",
              "lifecycle": "planned",
              "recoveryRequired": false,
              "resourceCount": 0
            }
            """#.utf8)
        )

        XCTAssertNil(operation.providerReach)
    }

    private func temporaryExecutable(script: String) throws -> (root: URL, executable: URL) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-bridge-client-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let executable = root.appendingPathComponent("unpin-test-bridge")
        try Data(script.utf8).write(to: executable)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755],
            ofItemAtPath: executable.path
        )
        return (root, executable)
    }
}
