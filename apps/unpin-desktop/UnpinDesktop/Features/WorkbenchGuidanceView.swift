import SwiftUI

enum WorkbenchGuidanceStorage {
    static let discoverKey = "unpin.workbench.guidance.discover.expanded"
    static let governKey = "unpin.workbench.guidance.govern.expanded"
    static let changeKey = "unpin.workbench.guidance.change.expanded"
    static let recoverKey = "unpin.workbench.guidance.recover.expanded"

    static func key(for area: WorkArea) -> String {
        switch area {
        case .discover:
            discoverKey
        case .govern:
            governKey
        case .change:
            changeKey
        case .recover:
            recoverKey
        }
    }
}

struct WorkbenchGuidanceDescriptor: Equatable {
    let area: WorkArea
    let task: String
    let outcome: String

    init(area: WorkArea) {
        self.area = area
        switch area {
        case .discover:
            task = "Review discovered skills, MCP servers, instructions, hooks, and their current state."
            outcome = "Finish with a clear inventory and organize related capabilities into reusable groups."
        case .govern:
            task = "Continue profiles, gateways, sessions, and hooks through supported CLI or MCP entry points."
            outcome = "Finish with an exact, copyable handoff without granting the desktop new control authority."
        case .change:
            task = "Choose a group and target state, then review the exact plan before approval."
            outcome = "Finish with a locally approved change backed by Unpin's existing safety evidence."
        case .recover:
            task = "Select a backup or operation, inspect its evidence, and review any restore before applying it."
            outcome = "Finish with an auditable recovery decision that preserves approval and restore boundaries."
        }
    }

    var showGuidanceLabel: String {
        "Show \(area.title) guidance"
    }

    var hideGuidanceLabel: String {
        "Hide \(area.title) guidance"
    }
}

struct WorkbenchGuidanceView: View {
    let descriptor: WorkbenchGuidanceDescriptor
    @Binding var isExpanded: Bool

    var body: some View {
        if isExpanded {
            GroupBox {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(descriptor.task)
                            .font(.headline)
                            .foregroundStyle(.primary)
                        Text(descriptor.outcome)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    Button(descriptor.hideGuidanceLabel, systemImage: "chevron.up") {
                        isExpanded = false
                    }
                    .labelStyle(.titleAndIcon)
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                    .accessibilityLabel(descriptor.hideGuidanceLabel)
                }
                .padding(.vertical, 2)
            } label: {
                Label("\(descriptor.area.title) guidance", systemImage: "lightbulb")
                    .foregroundStyle(.primary)
            }
            .accessibilityIdentifier("workbench-guidance-\(descriptor.area.rawValue)")
        } else {
            HStack {
                Button(descriptor.showGuidanceLabel, systemImage: "questionmark.circle") {
                    isExpanded = true
                }
                .labelStyle(.titleAndIcon)
                .buttonStyle(.bordered)
                .controlSize(.small)
                .accessibilityLabel(descriptor.showGuidanceLabel)
                .accessibilityIdentifier("workbench-guidance-\(descriptor.area.rawValue)-restore")
                Spacer()
            }
        }
    }
}

enum WorkbenchPresentationState: Equatable {
    case needsWorkspace
    case loading
    case ready
    case blocked(String)
}

struct WorkbenchPresentationInputs: Equatable {
    let state: WorkbenchPresentationState
    let hasWorkspace: Bool
    let isBusy: Bool
    let workspaceName: String?

    var allowsNavigation: Bool { true }
    var allowsGuidanceDisclosure: Bool { true }
    var allowsCopy: Bool { true }
    var allowsWorkspaceMutation: Bool { !isBusy }

    var allowsMutation: Bool {
        guard hasWorkspace, isBusy == false else { return false }
        if case .ready = state { return true }
        return false
    }

    @MainActor
    static func runtime(_ workspace: WorkspaceStore) -> Self {
        Self(
            state: WorkbenchPresentationState(workspace.state),
            hasWorkspace: workspace.hasWorkspace,
            isBusy: workspace.isBusy,
            workspaceName: workspace.workspaceName
        )
    }

    static func fixture(
        state: WorkbenchPresentationState,
        hasWorkspace: Bool,
        isBusy: Bool,
        workspaceName: String?
    ) -> Self {
        Self(
            state: state,
            hasWorkspace: hasWorkspace,
            isBusy: isBusy,
            workspaceName: workspaceName
        )
    }
}

private extension WorkbenchPresentationState {
    @MainActor
    init(_ state: WorkspaceStore.State) {
        switch state {
        case .needsWorkspace:
            self = .needsWorkspace
        case .loading:
            self = .loading
        case .ready:
            self = .ready
        case .blocked(let message):
            self = .blocked(message)
        }
    }
}

private struct WorkbenchPresentationInputsKey: EnvironmentKey {
    static let defaultValue = WorkbenchPresentationInputs.fixture(
        state: .ready,
        hasWorkspace: true,
        isBusy: false,
        workspaceName: nil
    )
}

private struct WorkbenchChooseWorkspaceKey: EnvironmentKey {
    static let defaultValue: (@MainActor @Sendable () -> Void)? = nil
}

private struct WorkbenchCreateGroupKey: EnvironmentKey {
    static let defaultValue: (@MainActor @Sendable () -> Void)? = nil
}

extension EnvironmentValues {
    var workbenchPresentation: WorkbenchPresentationInputs {
        get { self[WorkbenchPresentationInputsKey.self] }
        set { self[WorkbenchPresentationInputsKey.self] = newValue }
    }

    var workbenchChooseWorkspace: (@MainActor @Sendable () -> Void)? {
        get { self[WorkbenchChooseWorkspaceKey.self] }
        set { self[WorkbenchChooseWorkspaceKey.self] = newValue }
    }

    var workbenchCreateGroup: (@MainActor @Sendable () -> Void)? {
        get { self[WorkbenchCreateGroupKey.self] }
        set { self[WorkbenchCreateGroupKey.self] = newValue }
    }
}

struct WorkbenchRenderBoundary<Content: View>: View {
    let workArea: WorkArea
    let presentation: WorkbenchPresentationInputs
    let guidanceDescriptor: WorkbenchGuidanceDescriptor
    @Binding var isPrimerExpanded: Bool
    private let content: Content

    init(
        workArea: WorkArea,
        presentation: WorkbenchPresentationInputs,
        isPrimerExpanded: Binding<Bool>,
        @ViewBuilder content: () -> Content
    ) {
        self.workArea = workArea
        self.presentation = presentation
        guidanceDescriptor = WorkbenchGuidanceDescriptor(area: workArea)
        _isPrimerExpanded = isPrimerExpanded
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            WorkbenchGuidanceView(
                descriptor: guidanceDescriptor,
                isExpanded: $isPrimerExpanded
            )
            content
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .padding(16)
        .environment(\.workbenchPresentation, presentation)
    }
}

struct WorkbenchWorkspaceStateView: View {
    let title: String
    let message: String
    let actionTitle: String?
    let action: (() -> Void)?

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: "folder.badge.gearshape")
        } description: {
            Text(message)
        } actions: {
            if let actionTitle, let action {
                Button(actionTitle, action: action)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
