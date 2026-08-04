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
                unpinVersion: "1.0.0-rc.1",
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
                unpinVersion: "1.0.0-rc.1",
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
