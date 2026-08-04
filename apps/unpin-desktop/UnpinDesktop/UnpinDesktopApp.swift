import SwiftUI
import UniformTypeIdentifiers

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
    @State private var choosingWorkspace = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Picker("Work area", selection: $workArea) {
                    ForEach(WorkArea.allCases) { area in
                        Text(area.title).tag(area)
                    }
                }
                .pickerStyle(.segmented)

                Spacer()

                Text(workspace.workspaceName ?? "No workspace selected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Choose workspace") { choosingWorkspace = true }
                if workspace.hasWorkspace {
                    Button("Reload workspace") { Task { await workspace.reloadWorkspace() } }
                }
            }
            .padding()

            Divider()

            if workspace.hasWorkspace {
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
            } else {
                ContentUnavailableView(
                    "Choose a workspace",
                    systemImage: "folder.badge.gearshape",
                    description: Text("Select the repository whose project configuration you want to inspect. Unpin will pass that exact folder to its bundled bridge.")
                )
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .disabled(workspace.isBusy)
        .overlay(alignment: .bottomLeading) {
            if let message = workspace.statusMessage {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding()
            }
        }
        .fileImporter(
            isPresented: $choosingWorkspace,
            allowedContentTypes: [.folder],
            allowsMultipleSelection: false
        ) { result in
            if case let .success(urls) = result, let root = urls.first {
                Task { await workspace.selectWorkspace(root) }
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
