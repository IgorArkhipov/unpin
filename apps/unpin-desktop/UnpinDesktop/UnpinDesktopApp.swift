import SwiftUI

@main
struct UnpinDesktopApp: App {
    @StateObject private var workspace = WorkspaceStore()

    var body: some Scene {
        WindowGroup("Unpin Workbench") {
            WorkbenchView()
                .environmentObject(workspace)
                .task { await workspace.launch() }
        }
        .defaultSize(width: 1180, height: 760)
    }
}

private struct WorkbenchView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var workArea = WorkArea.discover

    var body: some View {
        VStack(spacing: 0) {
            Picker("Work area", selection: $workArea) {
                ForEach(WorkArea.allCases) { area in
                    Text(area.title).tag(area)
                }
            }
            .pickerStyle(.segmented)
            .padding()

            Divider()

            Group {
                switch workArea {
                case .discover:
                    DiscoverOrganizeView()
                case .govern:
                    GovernAutomateView()
                case .change:
                    SafeChangeView()
                case .recover:
                    RecoverAuditView()
                }
            }
            .onChange(of: workArea) { _, area in
                if area == .recover {
                    Task { await workspace.refreshRecovery() }
                }
            }
        }
        .overlay(alignment: .bottomLeading) {
            if let message = workspace.statusMessage {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding()
            }
        }
    }
}

enum WorkArea: String, CaseIterable, Identifiable {
    case discover
    case govern
    case change
    case recover

    var id: String { rawValue }

    var title: String {
        switch self {
        case .discover: "Discover and Organize"
        case .govern: "Govern and Automate"
        case .change: "Change Safely"
        case .recover: "Recover and Audit"
        }
    }
}
