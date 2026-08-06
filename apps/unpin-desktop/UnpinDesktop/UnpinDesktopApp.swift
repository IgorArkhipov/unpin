import SwiftUI
import UniformTypeIdentifiers

enum WorkbenchColorScheme: String, CaseIterable, Identifiable {
    case light
    case dark

    static let defaultValue = WorkbenchColorScheme.dark
    static let storageKey = "unpin.workbench.color-scheme"

    var id: String { rawValue }
    var title: String { rawValue.capitalized }

    var colorScheme: ColorScheme {
        switch self {
        case .light: .light
        case .dark: .dark
        }
    }

    static func resolve(storedValue: String?) -> WorkbenchColorScheme {
        storedValue.flatMap(WorkbenchColorScheme.init(rawValue:)) ?? defaultValue
    }
}

struct WorkbenchPalette {
    let scheme: WorkbenchColorScheme
    let canvas: Color
    let panel: Color
    let table: Color
    let border: Color
    let cyan: Color
    let green: Color
    private let backgroundHighlight: Color

    static let light = WorkbenchPalette(
        scheme: .light,
        canvas: Color(red: 244 / 255, green: 247 / 255, blue: 251 / 255),
        panel: .white,
        table: Color(red: 248 / 255, green: 250 / 255, blue: 253 / 255),
        border: Color(red: 200 / 255, green: 214 / 255, blue: 230 / 255),
        cyan: Color(red: 5 / 255, green: 126 / 255, blue: 157 / 255),
        green: Color(red: 23 / 255, green: 125 / 255, blue: 85 / 255),
        backgroundHighlight: Color(red: 216 / 255, green: 234 / 255, blue: 247 / 255)
    )

    static let dark = WorkbenchPalette(
        scheme: .dark,
        canvas: Color(red: 8 / 255, green: 17 / 255, blue: 29 / 255),
        panel: Color(red: 16 / 255, green: 29 / 255, blue: 45 / 255),
        table: Color(red: 10 / 255, green: 22 / 255, blue: 36 / 255),
        border: Color(red: 41 / 255, green: 65 / 255, blue: 94 / 255),
        cyan: Color(red: 83 / 255, green: 216 / 255, blue: 251 / 255),
        green: Color(red: 84 / 255, green: 230 / 255, blue: 154 / 255),
        backgroundHighlight: Color(red: 23 / 255, green: 52 / 255, blue: 84 / 255)
    )

    static func resolve(for colorScheme: ColorScheme) -> WorkbenchPalette {
        switch colorScheme {
        case .light: light
        case .dark: dark
        @unknown default: dark
        }
    }

    var background: RadialGradient {
        RadialGradient(
            colors: [
                backgroundHighlight,
                canvas,
            ],
            center: .topTrailing,
            startRadius: 0,
            endRadius: 900
        )
    }
}

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

struct WorkbenchView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @AppStorage(WorkbenchColorScheme.storageKey)
    private var storedColorScheme = WorkbenchColorScheme.defaultValue.rawValue
    @AppStorage(WorkbenchGuidanceStorage.discoverKey)
    private var discoverGuidanceExpanded = true
    @AppStorage(WorkbenchGuidanceStorage.governKey)
    private var governGuidanceExpanded = true
    @AppStorage(WorkbenchGuidanceStorage.changeKey)
    private var changeGuidanceExpanded = true
    @AppStorage(WorkbenchGuidanceStorage.recoverKey)
    private var recoverGuidanceExpanded = true
    @State private var navigation = WorkbenchNavigationState()
    @State private var choosingWorkspace = false

    var body: some View {
        let selectedColorScheme = WorkbenchColorScheme.resolve(storedValue: storedColorScheme)
        let palette = WorkbenchPalette.resolve(for: selectedColorScheme.colorScheme)
        let presentation = WorkbenchPresentationInputs.runtime(workspace)

        ZStack {
            palette.background
                .ignoresSafeArea()

            VStack(spacing: 0) {
                VStack(spacing: 10) {
                    HStack(spacing: 14) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("UNPIN")
                                .font(.caption.bold().monospaced())
                                .tracking(2)
                                .foregroundStyle(palette.cyan)
                            Text("Local AI Workbench")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }

                        Spacer()

                        Picker("Appearance", selection: colorSchemeSelection) {
                            ForEach(WorkbenchColorScheme.allCases) { colorScheme in
                                Text(colorScheme.title).tag(colorScheme)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 132)
                        .help("Choose light or dark appearance")

                        Text(workspace.workspaceName ?? "No workspace selected")
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Button("Choose workspace") { choosingWorkspace = true }
                            .disabled(!presentation.allowsWorkspaceMutation)
                        if workspace.hasWorkspace {
                            Button("Reload workspace") { Task { await workspace.reloadWorkspace() } }
                                .disabled(!presentation.allowsWorkspaceMutation)
                        }
                    }

                    Picker("Work area", selection: $navigation.workArea) {
                        ForEach(WorkArea.allCases) { area in
                            Text(area.title).tag(area)
                        }
                    }
                    .pickerStyle(.segmented)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 14)
                .background(palette.panel.opacity(0.82))

                Divider()
                    .overlay(palette.border)

                WorkbenchRenderBoundary(
                    workArea: navigation.workArea,
                    presentation: presentation,
                    isPrimerExpanded: guidanceBinding(for: navigation.workArea)
                ) {
                    selectedWorkAreaView
                }
                .environment(\.workbenchChooseWorkspace, { choosingWorkspace = true })
                .environment(\.workbenchCreateGroup, {
                    navigation.presentGroupCreation()
                })
                .onChange(of: navigation.workArea) { _, area in
                    if area == .recover, workspace.hasWorkspace {
                        Task { await workspace.refreshRecovery() }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(palette.panel.opacity(0.96))
                .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 18, style: .continuous)
                        .stroke(palette.border, lineWidth: 1)
                }
                .padding(16)

                if let message = workspace.statusMessage {
                    HStack(spacing: 8) {
                        Circle()
                            .fill(palette.green)
                            .frame(width: 7, height: 7)
                        Text(message)
                            .font(.footnote.monospaced())
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, 18)
                    .padding(.bottom, 12)
                }
            }
        }
        .environment(\.colorScheme, selectedColorScheme.colorScheme)
        .preferredColorScheme(selectedColorScheme.colorScheme)
        .tint(palette.cyan)
        .sheet(isPresented: $navigation.isPresentingGroupEditor) {
            GroupEditorView(group: nil)
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

    private var colorSchemeSelection: Binding<WorkbenchColorScheme> {
        Binding(
            get: { WorkbenchColorScheme.resolve(storedValue: storedColorScheme) },
            set: { storedColorScheme = $0.rawValue }
        )
    }

    @ViewBuilder
    private var selectedWorkAreaView: some View {
        switch navigation.workArea {
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

    private func guidanceBinding(for area: WorkArea) -> Binding<Bool> {
        switch area {
        case .discover:
            $discoverGuidanceExpanded
        case .govern:
            $governGuidanceExpanded
        case .change:
            $changeGuidanceExpanded
        case .recover:
            $recoverGuidanceExpanded
        }
    }
}

struct WorkbenchNavigationState: Equatable {
    var workArea: WorkArea = .discover
    var isPresentingGroupEditor = false

    mutating func presentGroupCreation() {
        workArea = .discover
        isPresentingGroupEditor = true
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
