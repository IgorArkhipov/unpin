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
        try FileManager.default.createDirectory(at: projectRoot, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: projectRoot) }

        let bridge = BridgeClient(
            executableURL: executable,
            projectRoot: projectRoot,
            manifest: manifest
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
}
