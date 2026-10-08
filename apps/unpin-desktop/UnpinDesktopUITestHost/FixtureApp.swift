import SwiftUI

// Compiled only into the separate fixture application, never the shipping app.
@main
struct FixtureApp: App {
    private let environment = ProcessInfo.processInfo.environment
    @StateObject private var workspace: WorkspaceStore

    init() {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("unpin-ui-fixture-\(UUID().uuidString)", isDirectory: true)
        _workspace = StateObject(
            wrappedValue: WorkspaceStore(
                bridgeRoots: BridgeLaunchRoots(
                    fixtureRoot: root, homeRoot: root, appStateRoot: root
                )))
    }

    var body: some Scene {
        Window("Unpin UI Fixtures", id: "fixture") {
            FixtureContent(scenario: environment["UNPIN_UI_SCENARIO"] ?? "inventory")
                .environmentObject(workspace)
                .frame(width: width, height: height)
        }
        .defaultSize(width: width, height: height)
        .windowResizability(.contentSize)
    }

    private var width: CGFloat { CGFloat(Int(environment["UNPIN_UI_WIDTH"] ?? "") ?? 1180) }
    private var height: CGFloat { CGFloat(Int(environment["UNPIN_UI_HEIGHT"] ?? "") ?? 760) }
}

private struct FixtureContent: View {
    let scenario: String
    @State private var replaced = false

    var body: some View {
        if scenario == "group-editor" {
            GroupEditorView(group: nil)
        } else if scenario == "facet-replacement" {
            VStack(spacing: 8) {
                Button("Replace fixture inventory") { replaced = true }
                DiscoverOrganizeView(
                    inventoryOverride: replaced ? [Self.replacement] : [Self.original],
                    filtersOverride: DiscoverFilterState(provider: "claude", layer: "global", category: "skill")
                )
            }
        } else {
            DiscoverOrganizeView(inventoryOverride: [
                InventoryItem(
                    provider: "codex", kind: "skill", category: "skill", layer: "global",
                    id: "alpha", displayName: "Alpha Codex skill", enabled: true, mutability: "read-only"),
                InventoryItem(
                    provider: "zed", kind: "mcp", category: "mcp", layer: "project",
                    id: "beta", displayName: "Beta Zed MCP", enabled: false, mutability: "read-only"),
            ])
        }
    }

    private static let original = InventoryItem(
        provider: "claude", kind: "skill", category: "skill", layer: "global", id: "old",
        displayName: "Original Claude skill", enabled: true, mutability: "read-only"
    )
    private static let replacement = InventoryItem(
        provider: "zed", kind: "mcp", category: "mcp", layer: "project", id: "new",
        displayName: "Replacement Zed MCP", enabled: false, mutability: "read-only"
    )
}
