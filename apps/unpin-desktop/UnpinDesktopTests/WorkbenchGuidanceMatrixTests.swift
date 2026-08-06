import AppKit
import SwiftUI
import XCTest
@testable import UnpinDesktop

@MainActor
final class WorkbenchGuidanceMatrixTests: XCTestCase {
    static let scenarioIDs = [
        "discover-ready-expanded",
        "discover-ready-collapsed",
        "discover-no-workspace",
        "discover-loading",
        "discover-blocked",
        "discover-empty",
        "discover-filter-zero",
        "govern-no-workspace-expanded",
        "govern-no-workspace-collapsed",
        "govern-workspace-context-expanded",
        "govern-workspace-context-collapsed",
        "change-ready-expanded",
        "change-ready-collapsed",
        "change-no-workspace",
        "change-loading",
        "change-blocked",
        "change-no-groups",
        "recover-ready-selected-expanded",
        "recover-ready-selected-collapsed",
        "recover-no-workspace",
        "recover-loading",
        "recover-unavailable",
        "recover-unavailable-preserved",
        "recover-empty",
        "recover-no-selection",
        "recover-operation-selected",
    ]

    func testCaptureGuidanceMatrix() throws {
        let environment = ProcessInfo.processInfo.environment
        let optionalOutputValue = nonEmptyEnvironmentValue(
            environment["UNPIN_GUIDANCE_MATRIX_DIR"]
        )
        let optionalScenariosValue = nonEmptyEnvironmentValue(
            environment["UNPIN_GUIDANCE_MATRIX_SCENARIOS"]
        )

        if optionalOutputValue == nil, optionalScenariosValue == nil {
            throw XCTSkip("Guidance matrix capture is enabled only by the repository orchestrator")
        }

        let outputValue = try XCTUnwrap(optionalOutputValue)
        let scenariosValue = try XCTUnwrap(optionalScenariosValue)
        let requested = try JSONDecoder().decode(
            [String].self,
            from: Data(scenariosValue.utf8)
        )
        XCTAssertEqual(Set(requested).count, requested.count, "Scenario IDs must be unique")
        XCTAssertEqual(Set(requested), Set(Self.scenarioIDs), "Scenario inventory must be complete")

        let outputRoot = URL(fileURLWithPath: outputValue, isDirectory: true)
        for theme in WorkbenchColorScheme.allCases {
            for scenarioID in requested {
                let fixture = try fixture(for: scenarioID, theme: theme)
                let png = try renderPNG(fixture: fixture, size: CGSize(width: 1180, height: 760))
                let destination = outputRoot
                    .appendingPathComponent(theme.rawValue, isDirectory: true)
                    .appendingPathComponent("\(scenarioID).png")
                try FileManager.default.createDirectory(
                    at: destination.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                try png.write(to: destination, options: Data.WritingOptions.atomic)

                let image = try XCTUnwrap(NSBitmapImageRep(data: png))
                XCTAssertEqual(image.pixelsWide, 1180)
                XCTAssertEqual(image.pixelsHigh, 760)
            }
        }
    }

    private func nonEmptyEnvironmentValue(_ value: String?) -> String? {
        guard let value, value.isEmpty == false, value.hasPrefix("$(") == false else {
            return nil
        }
        return value
    }

    func testGuidanceFixturesRenderAtCompactWorkbenchSize() throws {
        for scenarioID in Self.scenarioIDs {
            let fixture = try fixture(for: scenarioID, theme: .dark)
            let png = try renderPNG(fixture: fixture, size: CGSize(width: 1040, height: 720))
            let image = try XCTUnwrap(NSBitmapImageRep(data: png))
            XCTAssertEqual(image.pixelsWide, 1040, scenarioID)
            XCTAssertEqual(image.pixelsHigh, 720, scenarioID)
        }
    }

    private func fixture(
        for scenarioID: String,
        theme: WorkbenchColorScheme
    ) throws -> WorkbenchViewFixture {
        let ready = WorkbenchPresentationInputs.fixture(
            state: .ready,
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "unpin-demo"
        )
        let noWorkspace = WorkbenchPresentationInputs.fixture(
            state: .needsWorkspace,
            hasWorkspace: false,
            isBusy: false,
            workspaceName: nil
        )
        let loading = WorkbenchPresentationInputs.fixture(
            state: .loading,
            hasWorkspace: true,
            isBusy: true,
            workspaceName: "unpin-demo"
        )
        let blocked = WorkbenchPresentationInputs.fixture(
            state: .blocked("The bundled bridge closed before workspace evidence was available."),
            hasWorkspace: true,
            isBusy: false,
            workspaceName: "unpin-demo"
        )

        switch scenarioID {
        case "discover-ready-expanded":
            return workbench(
                area: .discover,
                theme: theme,
                guidanceExpanded: true,
                presentation: ready,
                inventory: inventory
            )
        case "discover-ready-collapsed":
            return workbench(
                area: .discover,
                theme: theme,
                guidanceExpanded: false,
                presentation: ready,
                inventory: inventory
            )
        case "discover-no-workspace":
            return workbench(area: .discover, theme: theme, presentation: noWorkspace)
        case "discover-loading":
            return workbench(area: .discover, theme: theme, presentation: loading)
        case "discover-blocked":
            return workbench(area: .discover, theme: theme, presentation: blocked)
        case "discover-empty":
            return workbench(
                area: .discover,
                theme: theme,
                presentation: ready,
                inventory: []
            )
        case "discover-filter-zero":
            return workbench(
                area: .discover,
                theme: theme,
                presentation: ready,
                inventory: inventory,
                discoverFilters: DiscoverFilterState(search: "no-such-capability")
            )
        case "govern-no-workspace-expanded":
            return workbench(
                area: .govern,
                theme: theme,
                guidanceExpanded: true,
                presentation: noWorkspace
            )
        case "govern-no-workspace-collapsed":
            return workbench(
                area: .govern,
                theme: theme,
                guidanceExpanded: false,
                presentation: noWorkspace
            )
        case "govern-workspace-context-expanded":
            return workbench(
                area: .govern,
                theme: theme,
                guidanceExpanded: true,
                presentation: ready
            )
        case "govern-workspace-context-collapsed":
            return workbench(
                area: .govern,
                theme: theme,
                guidanceExpanded: false,
                presentation: ready
            )
        case "change-ready-expanded":
            return workbench(
                area: .change,
                theme: theme,
                guidanceExpanded: true,
                presentation: ready,
                groups: try groups
            )
        case "change-ready-collapsed":
            return workbench(
                area: .change,
                theme: theme,
                guidanceExpanded: false,
                presentation: ready,
                groups: try groups
            )
        case "change-no-workspace":
            return workbench(area: .change, theme: theme, presentation: noWorkspace)
        case "change-loading":
            return workbench(area: .change, theme: theme, presentation: loading)
        case "change-blocked":
            return workbench(area: .change, theme: theme, presentation: blocked)
        case "change-no-groups":
            return workbench(
                area: .change,
                theme: theme,
                presentation: ready,
                groups: []
            )
        case "recover-ready-selected-expanded":
            return workbench(
                area: .recover,
                theme: theme,
                guidanceExpanded: true,
                presentation: ready,
                recovery: RecoverAuditFixture(
                    recovery: try recoverySnapshot(),
                    selectedBackupID: "backup-2026-08-05"
                )
            )
        case "recover-ready-selected-collapsed":
            return workbench(
                area: .recover,
                theme: theme,
                guidanceExpanded: false,
                presentation: ready,
                recovery: RecoverAuditFixture(
                    recovery: try recoverySnapshot(),
                    selectedBackupID: "backup-2026-08-05"
                )
            )
        case "recover-no-workspace":
            return workbench(area: .recover, theme: theme, presentation: noWorkspace)
        case "recover-loading":
            return workbench(area: .recover, theme: theme, presentation: loading)
        case "recover-unavailable":
            return workbench(
                area: .recover,
                theme: theme,
                presentation: ready,
                recovery: RecoverAuditFixture(
                    recovery: nil,
                    blocker: "Authenticated recovery evidence could not be loaded."
                )
            )
        case "recover-unavailable-preserved":
            return workbench(
                area: .recover,
                theme: theme,
                presentation: ready,
                recovery: RecoverAuditFixture(
                    recovery: try recoverySnapshot(backupStatus: "unavailable"),
                    blocker: "The newest backup index is unavailable."
                )
            )
        case "recover-empty":
            return workbench(
                area: .recover,
                theme: theme,
                presentation: ready,
                recovery: RecoverAuditFixture(recovery: try emptyRecoverySnapshot())
            )
        case "recover-no-selection":
            return workbench(
                area: .recover,
                theme: theme,
                presentation: ready,
                recovery: RecoverAuditFixture(recovery: try recoverySnapshot())
            )
        case "recover-operation-selected":
            return workbench(
                area: .recover,
                theme: theme,
                presentation: ready,
                recovery: RecoverAuditFixture(
                    recovery: try recoverySnapshot(),
                    selectedOperationID: "operation-2026-08-05"
                )
            )
        default:
            throw MatrixFixtureError.unknownScenario(scenarioID)
        }
    }

    private func workbench(
        area: WorkArea,
        theme: WorkbenchColorScheme,
        guidanceExpanded: Bool = true,
        presentation: WorkbenchPresentationInputs,
        inventory: [InventoryItem]? = nil,
        discoverFilters: DiscoverFilterState? = nil,
        groups: [GroupSummary]? = nil,
        recovery: RecoverAuditFixture? = nil
    ) -> WorkbenchViewFixture {
        WorkbenchViewFixture(
            workArea: area,
            colorScheme: theme,
            guidanceExpanded: guidanceExpanded,
            presentation: presentation,
            inventory: inventory,
            discoverFilters: discoverFilters,
            groups: groups,
            recovery: recovery
        )
    }

    private func renderPNG(
        fixture: WorkbenchViewFixture,
        size: CGSize
    ) throws -> Data {
        let workspace = WorkspaceStore()
        let root = AnyView(
            WorkbenchView(fixture: fixture)
                .environmentObject(workspace)
                .frame(width: size.width, height: size.height)
        )
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.appearance = NSAppearance(
            named: fixture.colorScheme == .light ? .aqua : .darkAqua
        )
        hostingView.wantsLayer = true

        let window = NSWindow(
            contentRect: hostingView.bounds,
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        window.isReleasedWhenClosed = false
        window.contentView = hostingView
        window.setFrameOrigin(NSPoint(x: -10_000, y: -10_000))
        window.orderFrontRegardless()
        hostingView.layoutSubtreeIfNeeded()
        hostingView.displayIfNeeded()
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.03))

        defer {
            window.orderOut(nil)
            window.close()
        }

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
            throw MatrixFixtureError.bitmapCreationFailed
        }
        bitmap.size = size
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        guard let png = bitmap.representation(using: .png, properties: [:]) else {
            throw MatrixFixtureError.pngEncodingFailed
        }
        return png
    }

    private var inventory: [InventoryItem] {
        [
            InventoryItem(
                provider: "Claude Code",
                kind: "skill",
                category: "skill",
                layer: "global",
                id: "skills/release-verification",
                displayName: "Release verification",
                enabled: true,
                mutability: "read-write"
            ),
            InventoryItem(
                provider: "Codex CLI",
                kind: "mcp-server",
                category: "mcp",
                layer: "workspace",
                id: "mcp_servers.context7",
                displayName: "Context documentation server",
                enabled: true,
                mutability: "read-write"
            ),
            InventoryItem(
                provider: "Cursor",
                kind: "instruction",
                category: "instruction",
                layer: "project",
                id: ".cursor/rules/review-safety.mdc",
                displayName: "Review and mutation safety",
                enabled: false,
                mutability: "read-only"
            ),
            InventoryItem(
                provider: "Zed",
                kind: "context-server",
                category: "mcp",
                layer: "global",
                id: "context_servers.unpin-workbench-long-identifier",
                displayName: "Unpin workbench control context",
                enabled: true,
                mutability: "read-write"
            ),
        ]
    }

    private var groups: [GroupSummary] {
        get throws {
            try JSONDecoder().decode(
                [GroupSummary].self,
                from: Data(
                    """
                    [{
                      "qualifiedName": "project:release-workbench",
                      "scope": "project",
                      "revision": "sha256:fixture-revision",
                      "contextCompatible": true,
                      "members": [],
                      "state": "mixed",
                      "fresh": true
                    }]
                    """.utf8
                )
            )
        }
    }

    private func emptyRecoverySnapshot() throws -> RecoverySnapshot {
        try JSONDecoder().decode(
            RecoverySnapshot.self,
            from: Data(
                """
                {
                  "backups": [],
                  "backupStatus": "available",
                  "operations": [],
                  "operationStatus": "available",
                  "groupOperationStatus": "available"
                }
                """.utf8
            )
        )
    }

    private func recoverySnapshot(
        backupStatus: String = "available"
    ) throws -> RecoverySnapshot {
        let json = """
        {
          "backups": [{
            "backupId": "backup-2026-08-05",
            "createdAt": "2026-08-05T18:42:00Z",
            "itemCount": 4,
            "providers": ["Claude Code", "Codex CLI"],
            "layers": ["global", "project"],
            "restorable": true,
            "authentication": "authenticated",
            "targetEnabled": true
          }],
          "backupStatus": "\(backupStatus)",
          "operations": [{
            "operationId": "operation-2026-08-05",
            "operationKind": "group-toggle",
            "lifecycle": "applied",
            "qualifiedName": "project:release-workbench",
            "requestedState": "enable",
            "createdAt": "2026-08-05T18:41:00Z",
            "updatedAt": "2026-08-05T18:42:00Z",
            "effectGraphDigest": "sha256:fixture-effect-graph",
            "authorizationRecorded": true,
            "terminalCode": "ok",
            "providerReach": "all",
            "providerReachLifecycle": "complete",
            "providerWritesStarted": true,
            "recoveryRequired": false,
            "resourceCount": 4,
            "backupIds": ["backup-2026-08-05"],
            "evidenceAvailable": true,
            "finalState": "on",
            "observationFresh": true,
            "members": []
          }],
          "operationStatus": "available",
          "groupOperationStatus": "available"
        }
        """
        return try JSONDecoder().decode(RecoverySnapshot.self, from: Data(json.utf8))
    }
}

private enum MatrixFixtureError: LocalizedError {
    case unknownScenario(String)
    case bitmapCreationFailed
    case pngEncodingFailed

    var errorDescription: String? {
        switch self {
        case .unknownScenario(let scenarioID):
            "Unknown guidance matrix scenario: \(scenarioID)"
        case .bitmapCreationFailed:
            "AppKit could not allocate the screenshot bitmap"
        case .pngEncodingFailed:
            "AppKit could not encode the screenshot as PNG"
        }
    }
}
