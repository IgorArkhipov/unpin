import AppKit
import SwiftUI
import WebKit
import XCTest
@testable import UnpinDesktop

private struct ProviderMatrixSection: Codable, Equatable {
    let id: String
    let filename: String
}

private enum ProviderMatrixSnapshotError: LocalizedError {
    case dashboardLoadFailed(String)
    case invalidSectionInventory
    case javascriptFailed(String)
    case invalidSectionMetrics(String)
    case missingSection(String)
    case snapshotFailed(String)
    case bitmapCreationFailed
    case pngEncodingFailed

    var errorDescription: String? {
        switch self {
        case let .dashboardLoadFailed(message):
            "Provider matrix dashboard failed to load: \(message)"
        case .invalidSectionInventory:
            "Provider matrix screenshot inventory does not match the repository contract"
        case let .javascriptFailed(message):
            "Provider matrix dashboard JavaScript failed: \(message)"
        case let .invalidSectionMetrics(sectionID):
            "Provider matrix section returned invalid metrics: \(sectionID)"
        case let .missingSection(sectionID):
            "Provider matrix dashboard is missing section: \(sectionID)"
        case let .snapshotFailed(message):
            "Provider matrix dashboard snapshot failed: \(message)"
        case .bitmapCreationFailed:
            "AppKit could not allocate the provider matrix screenshot bitmap"
        case .pngEncodingFailed:
            "AppKit could not encode the provider matrix screenshot as PNG"
        }
    }
}

@MainActor
private final class ProviderMatrixNavigationObserver: NSObject, WKNavigationDelegate {
    private(set) var finished = false
    private(set) var error: Error?

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation?) {
        finished = true
    }

    func webView(
        _ webView: WKWebView,
        didFail navigation: WKNavigation?,
        withError error: Error
    ) {
        self.error = error
    }

    func webView(
        _ webView: WKWebView,
        didFailProvisionalNavigation navigation: WKNavigation?,
        withError error: Error
    ) {
        self.error = error
    }
}

@MainActor
final class ProviderMatrixDashboardSnapshotTests: XCTestCase {
    private static let dashboardWidth = 1_480
    private static let sections = [
        ProviderMatrixSection(id: "overview", filename: "overview.png"),
        ProviderMatrixSection(id: "live-library", filename: "live-library.png"),
        ProviderMatrixSection(id: "coverage-matrix", filename: "coverage-matrix.png"),
        ProviderMatrixSection(id: "tui-library", filename: "tui-library.png"),
        ProviderMatrixSection(id: "provider-claude", filename: "claude-states.png"),
        ProviderMatrixSection(id: "provider-codex", filename: "codex-states.png"),
        ProviderMatrixSection(id: "provider-cursor", filename: "cursor-states.png"),
        ProviderMatrixSection(id: "provider-pi", filename: "pi-states.png"),
        ProviderMatrixSection(id: "provider-opencode", filename: "opencode-states.png"),
        ProviderMatrixSection(id: "provider-zed", filename: "zed-states.png"),
        ProviderMatrixSection(id: "mcp-states", filename: "mcp-states.png"),
        ProviderMatrixSection(id: "desktop-packages-light", filename: "desktop-packages-light.png"),
        ProviderMatrixSection(id: "desktop-packages-dark", filename: "desktop-packages-dark.png"),
    ]

    func testCaptureProviderMatrixDashboard() throws {
        let environment = ProcessInfo.processInfo.environment
        let optionalDashboard = nonEmptyEnvironmentValue(
            environment["UNPIN_PROVIDER_MATRIX_DASHBOARD"]
        )
        let optionalOutput = nonEmptyEnvironmentValue(
            environment["UNPIN_PROVIDER_MATRIX_SCREENSHOTS_DIR"]
        )
        let optionalSections = nonEmptyEnvironmentValue(
            environment["UNPIN_PROVIDER_MATRIX_SECTIONS"]
        )

        if optionalDashboard == nil,
           optionalOutput == nil,
           optionalSections == nil
        {
            throw XCTSkip("Provider matrix capture is enabled only by the repository orchestrator")
        }

        let dashboardValue = try XCTUnwrap(optionalDashboard)
        let outputValue = try XCTUnwrap(optionalOutput)
        let sectionsValue = try XCTUnwrap(optionalSections)
        let requestedSections = try JSONDecoder().decode(
            [ProviderMatrixSection].self,
            from: Data(sectionsValue.utf8)
        )
        guard requestedSections == Self.sections else {
            throw ProviderMatrixSnapshotError.invalidSectionInventory
        }

        let dashboardURL = URL(fileURLWithPath: dashboardValue)
        let outputRoot = URL(fileURLWithPath: outputValue, isDirectory: true)
        try FileManager.default.createDirectory(
            at: outputRoot,
            withIntermediateDirectories: true
        )

        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        let initialSize = CGSize(width: Self.dashboardWidth, height: 900)
        let webView = WKWebView(
            frame: NSRect(origin: .zero, size: initialSize),
            configuration: configuration
        )
        let window = NSWindow(
            contentRect: webView.bounds,
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = webView
        window.setFrameOrigin(NSPoint(x: -10_000, y: -10_000))
        window.orderFrontRegardless()
        defer {
            window.orderOut(nil)
            window.close()
        }

        try loadDashboard(dashboardURL, in: webView)
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

        for section in requestedSections {
            if let colorScheme = packageColorScheme(for: section.id) {
                let png = try packageWorkbenchPNG(colorScheme: colorScheme)
                let destination = outputRoot.appendingPathComponent(section.filename)
                try png.write(to: destination, options: .atomic)
                continue
            }
            var height = try prepare(section: section, in: webView)
            resize(webView: webView, window: window, height: height)
            RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))

            let settledHeight = try prepare(section: section, in: webView)
            if settledHeight != height {
                height = settledHeight
                resize(webView: webView, window: window, height: height)
                RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
            }

            let snapshot = try takeSnapshot(of: webView)
            let png = try pngData(
                from: snapshot,
                size: CGSize(width: Self.dashboardWidth, height: height)
            )
            let destination = outputRoot.appendingPathComponent(section.filename)
            try png.write(to: destination, options: .atomic)
        }
    }

    func testPackageWorkbenchCaptureUsesCanonicalPixelDimensions() throws {
        for colorScheme in [WorkbenchColorScheme.light, .dark] {
            let png = try packageWorkbenchPNG(colorScheme: colorScheme)
            let bitmap = try XCTUnwrap(NSBitmapImageRep(data: png))

            XCTAssertEqual(bitmap.pixelsWide, Self.dashboardWidth)
            XCTAssertEqual(bitmap.pixelsHigh, 900)
        }
    }

    private func packageColorScheme(for sectionID: String) -> WorkbenchColorScheme? {
        switch sectionID {
        case "desktop-packages-light": .light
        case "desktop-packages-dark": .dark
        default: nil
        }
    }

    private func packageWorkbenchPNG(colorScheme: WorkbenchColorScheme) throws -> Data {
        let fixture = WorkbenchViewFixture(
            workArea: .discover,
            colorScheme: colorScheme,
            guidanceExpanded: true,
            presentation: .fixture(
                state: .ready,
                hasWorkspace: true,
                isBusy: false,
                workspaceName: "agent-plugins-matrix"
            ),
            inventory: [],
            agentPlugins: try packageFixtures(),
            discoverMode: .packages,
            discoverFilters: nil,
            groups: nil,
            recovery: nil
        )
        let size = CGSize(width: Self.dashboardWidth, height: 900)
        let host = NSHostingView(
            rootView: WorkbenchView(fixture: fixture)
                .environmentObject(WorkspaceStore())
                .frame(width: size.width, height: size.height)
        )
        host.frame = NSRect(origin: .zero, size: size)
        host.appearance = NSAppearance(
            named: colorScheme == .dark ? .darkAqua : .aqua
        )
        let window = NSWindow(
            contentRect: host.bounds,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = host
        window.setFrameOrigin(NSPoint(x: -10_000, y: -10_000))
        window.orderFrontRegardless()
        defer {
            window.orderOut(nil)
            window.close()
        }
        host.layoutSubtreeIfNeeded()
        host.displayIfNeeded()
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.05))
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: Int(size.width),
            pixelsHigh: Int(size.height),
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            throw ProviderMatrixSnapshotError.bitmapCreationFailed
        }
        bitmap.size = size
        host.cacheDisplay(in: host.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw ProviderMatrixSnapshotError.pngEncodingFailed
        }
        return png
    }

    private func packageFixtures() throws -> [AgentPluginSummary] {
        try JSONDecoder().decode(
            [AgentPluginSummary].self,
            from: Data(
                """
                [{
                  "logicalId": "agent-plugin:connector-kit",
                  "name": "Connector Kit",
                  "componentSignature": "mcp+skill",
                  "projectionFingerprint": "sha256:matrix-projection",
                  "state": "mixed",
                  "access": "actionable",
                  "providers": ["claude", "codex"],
                  "componentKinds": ["mcp", "skill"],
                  "instanceCount": 2,
                  "instances": [{
                    "instanceId": "instance-connector-kit-claude-global",
                    "provider": "claude",
                    "layer": "global",
                    "state": "on",
                    "access": "actionable",
                    "version": "1.0.0",
                    "description": "Review and context tools for agent workbenches.",
                    "components": [
                      {"kind": "mcp", "name": "context", "disposition": "available"},
                      {"kind": "skill", "name": "review", "disposition": "available"}
                    ],
                    "activations": [{"enabled": true, "mutability": "read-write"}],
                    "blockers": [],
                    "diagnostics": []
                  }, {
                    "instanceId": "instance-connector-kit-codex-global",
                    "provider": "codex",
                    "layer": "global",
                    "state": "off",
                    "access": "actionable",
                    "version": "1.0.0",
                    "description": "Review and context tools for agent workbenches.",
                    "components": [
                      {"kind": "mcp", "name": "context", "disposition": "available"},
                      {"kind": "skill", "name": "review", "disposition": "available"}
                    ],
                    "activations": [{"enabled": false, "mutability": "read-write"}],
                    "blockers": [],
                    "diagnostics": []
                  }]
                }]
                """.utf8
            )
        )
    }

    private func nonEmptyEnvironmentValue(_ value: String?) -> String? {
        guard let value, value.isEmpty == false, value.hasPrefix("$(") == false else {
            return nil
        }
        return value
    }

    private func loadDashboard(_ url: URL, in webView: WKWebView) throws {
        let dashboardHTML: String
        do {
            dashboardHTML = try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw ProviderMatrixSnapshotError.dashboardLoadFailed(
                error.localizedDescription
            )
        }
        let observer = ProviderMatrixNavigationObserver()
        webView.navigationDelegate = observer
        defer { webView.navigationDelegate = nil }
        webView.loadHTMLString(dashboardHTML, baseURL: nil)
        try pumpRunLoop(
            until: { observer.finished || observer.error != nil },
            timeoutError: .dashboardLoadFailed("timed out after 30 seconds")
        )
        if let error = observer.error {
            throw ProviderMatrixSnapshotError.dashboardLoadFailed(
                error.localizedDescription
            )
        }
    }

    private func prepare(
        section: ProviderMatrixSection,
        in webView: WKWebView
    ) throws -> Int {
        let sectionData = try JSONEncoder().encode(section.id)
        let sectionLiteral = String(decoding: sectionData, as: UTF8.self)
        let script = """
        (() => {
          const sectionID = \(sectionLiteral);
          const target = document.getElementById(sectionID);
          if (!target) return { missing: true };
          const body = document.body;
          const main = document.querySelector("main");
          document.documentElement.style.width = "\(Self.dashboardWidth)px";
          document.documentElement.style.minHeight = "0";
          document.documentElement.style.overflow = "hidden";
          body.style.width = "\(Self.dashboardWidth)px";
          body.style.minHeight = "0";
          body.style.margin = "0";
          body.style.overflow = "hidden";
          main.style.width = "\(Self.dashboardWidth)px";
          main.style.maxWidth = "none";
          main.style.margin = "0";
          for (const candidate of main.querySelectorAll(":scope > section.panel")) {
            candidate.style.display = candidate === target ? "block" : "none";
          }
          target.style.width = "\(Self.dashboardWidth)px";
          target.style.margin = "0";
          target.style.boxShadow = "none";
          const rect = target.getBoundingClientRect();
          return {
            missing: false,
            width: Math.ceil(rect.width),
            height: Math.ceil(rect.height)
          };
        })()
        """
        guard let metrics = try evaluateJavaScript(script, in: webView) as? [String: Any]
        else {
            throw ProviderMatrixSnapshotError.invalidSectionMetrics(section.id)
        }
        if metrics["missing"] as? Bool == true {
            throw ProviderMatrixSnapshotError.missingSection(section.id)
        }
        guard let width = metrics["width"] as? NSNumber,
              let height = metrics["height"] as? NSNumber,
              width.intValue == Self.dashboardWidth,
              height.intValue >= 120,
              height.intValue <= 12_000
        else {
            throw ProviderMatrixSnapshotError.invalidSectionMetrics(section.id)
        }
        return height.intValue
    }

    private func resize(webView: WKWebView, window: NSWindow, height: Int) {
        let size = CGSize(width: Self.dashboardWidth, height: height)
        webView.frame = NSRect(origin: .zero, size: size)
        window.setContentSize(size)
        webView.layoutSubtreeIfNeeded()
        webView.displayIfNeeded()
    }

    private func evaluateJavaScript(_ script: String, in webView: WKWebView) throws -> Any? {
        var completed = false
        var result: Any?
        var failure: Error?
        webView.evaluateJavaScript(script) { value, error in
            result = value
            failure = error
            completed = true
        }
        try pumpRunLoop(
            until: { completed },
            timeoutError: .javascriptFailed("timed out after 30 seconds")
        )
        if let failure {
            throw ProviderMatrixSnapshotError.javascriptFailed(
                failure.localizedDescription
            )
        }
        return result
    }

    private func takeSnapshot(of webView: WKWebView) throws -> NSImage {
        let configuration = WKSnapshotConfiguration()
        configuration.rect = webView.bounds
        configuration.snapshotWidth = NSNumber(value: Self.dashboardWidth)
        var completed = false
        var result: NSImage?
        var failure: Error?
        webView.takeSnapshot(with: configuration) { image, error in
            result = image
            failure = error
            completed = true
        }
        try pumpRunLoop(
            until: { completed },
            timeoutError: .snapshotFailed("timed out after 30 seconds")
        )
        if let failure {
            throw ProviderMatrixSnapshotError.snapshotFailed(
                failure.localizedDescription
            )
        }
        return try XCTUnwrap(result)
    }

    private func pumpRunLoop(
        until condition: () -> Bool,
        timeoutError: @autoclosure () -> ProviderMatrixSnapshotError
    ) throws {
        let deadline = Date(timeIntervalSinceNow: 30)
        while condition() == false {
            guard Date() < deadline else { throw timeoutError() }
            _ = RunLoop.current.run(
                mode: .default,
                before: min(deadline, Date(timeIntervalSinceNow: 0.05))
            )
        }
    }

    private func pngData(from image: NSImage, size: CGSize) throws -> Data {
        guard let bitmap = NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: Int(size.width),
            pixelsHigh: Int(size.height),
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: 0,
            bitsPerPixel: 0
        ) else {
            throw ProviderMatrixSnapshotError.bitmapCreationFailed
        }
        bitmap.size = size
        guard let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
            throw ProviderMatrixSnapshotError.bitmapCreationFailed
        }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        image.draw(
            in: NSRect(origin: .zero, size: size),
            from: NSRect(origin: .zero, size: image.size),
            operation: .copy,
            fraction: 1
        )
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw ProviderMatrixSnapshotError.pngEncodingFailed
        }
        return png
    }
}
