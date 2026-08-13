import AppKit
import SwiftUI

struct GovernHandoff: Identifiable, Equatable {
    enum Availability: Equatable {
        case verified(cliCommand: String, mcpToolIDs: [String])
        case unavailable(reason: String)
    }

    let id: String
    let title: String
    let summary: String
    let availability: Availability

    var copyableValues: [String] {
        guard case .verified(let cliCommand, let mcpToolIDs) = availability else { return [] }
        return [cliCommand] + mcpToolIDs
    }

    static func verified(
        id: String,
        title: String,
        summary: String,
        cliCommand: String,
        mcpToolIDs: [String]
    ) -> Self {
        Self(
            id: id,
            title: title,
            summary: summary,
            availability: .verified(cliCommand: cliCommand, mcpToolIDs: mcpToolIDs)
        )
    }

    static func unavailable(
        id: String,
        title: String,
        summary: String,
        reason: String
    ) -> Self {
        Self(
            id: id,
            title: title,
            summary: summary,
            availability: .unavailable(reason: reason)
        )
    }

    static let catalog: [GovernHandoff] = [
        GovernHandoff.verified(
            id: "profiles",
            title: "Profiles",
            summary: "Inspect profiles in the CLI, then validate or plan policy through MCP.",
            cliCommand: "unpin profile list",
            mcpToolIDs: [
                "unpin_validate_profile",
                "unpin_plan_profile_policy",
                "unpin_apply_profile_policy",
            ]
        ),
        GovernHandoff.verified(
            id: "gateways",
            title: "Gateways",
            summary: "Check workspace gateway status before planning or applying a mode change.",
            cliCommand: "unpin gateway status --scope workspace",
            mcpToolIDs: [
                "unpin_get_gateway_status",
                "unpin_plan_gateway_mode",
                "unpin_apply_gateway_mode",
            ]
        ),
        GovernHandoff.verified(
            id: "sessions",
            title: "Sessions",
            summary: "List sessions in the CLI and use MCP for reviewed launch or end plans.",
            cliCommand: "unpin session list",
            mcpToolIDs: [
                "unpin_plan_session_launch",
                "unpin_plan_session_end",
                "unpin_apply_session_end",
            ]
        ),
        GovernHandoff.verified(
            id: "hooks",
            title: "Hooks",
            summary: "List hooks before reviewing trust plans and approved trust changes through MCP.",
            cliCommand: "unpin hook list",
            mcpToolIDs: [
                "unpin_list_hooks",
                "unpin_plan_hook_trust",
                "unpin_apply_hook_trust",
            ]
        ),
        GovernHandoff.unavailable(
            id: "native-controls",
            title: "Native automation controls",
            summary: "The desktop workbench does not run profile, gateway, session, or hook automation.",
            reason: "Use one of the verified CLI or MCP handoffs above. Native controls remain unavailable so the desktop does not claim authority it has not implemented."
        ),
    ]
}

struct GovernClipboardWriter {
    let write: (String) -> Void

    init(_ write: @escaping (String) -> Void) {
        self.write = write
    }

    static var system: Self {
        Self { value in
            let pasteboard = NSPasteboard.general
            pasteboard.clearContents()
            pasteboard.setString(value, forType: .string)
        }
    }
}

enum WorkflowSurfaceState: Equatable {
    case empty
    case loading
    case denied
    case reloadRequired
    case refreshUnconfirmed
    case nextSessionOnly
    case recoveryRequired
    case ready
}

struct WorkflowSurfaceFacts: Equatable {
    let presentation: WorkbenchPresentationState
    let hasDraft: Bool
    let hasProposal: Bool
    let hasSession: Bool
    let blocker: String?
    let recoveryRequired: Bool
    let reloadLimitation: String?

    init(
        presentation: WorkbenchPresentationState,
        hasDraft: Bool = false,
        hasProposal: Bool = false,
        hasSession: Bool = false,
        blocker: String? = nil,
        recoveryRequired: Bool = false,
        reloadLimitation: String? = nil
    ) {
        self.presentation = presentation
        self.hasDraft = hasDraft
        self.hasProposal = hasProposal
        self.hasSession = hasSession
        self.blocker = blocker
        self.recoveryRequired = recoveryRequired
        self.reloadLimitation = reloadLimitation
    }
}

func classifyWorkflowSurface(_ facts: WorkflowSurfaceFacts) -> WorkflowSurfaceState {
    switch facts.presentation {
    case .needsWorkspace:
        return .empty
    case .loading:
        return .loading
    case .ready, .blocked:
        break
    }
    if facts.recoveryRequired { return .recoveryRequired }
    if let limitation = facts.reloadLimitation {
        switch limitation {
        case "reload-required": return .reloadRequired
        case "refresh-unconfirmed": return .refreshUnconfirmed
        case "next-session-only": return .nextSessionOnly
        default: break
        }
    }
    let presentationBlocked: Bool
    if case .blocked = facts.presentation {
        presentationBlocked = true
    } else {
        presentationBlocked = false
    }
    if facts.blocker != nil || presentationBlocked {
        return .denied
    }
    guard facts.hasDraft || facts.hasProposal || facts.hasSession else { return .empty }
    return .ready
}

func parseWorkflowHostCommand(_ input: String) -> [String] {
    var arguments = [String]()
    var current = ""
    var quote: Character?
    var escaped = false
    var hasToken = false

    func appendCurrent() {
        guard hasToken else { return }
        arguments.append(current)
        current = ""
        hasToken = false
    }

    for character in input {
        if character == "\u{0}" {
            return []
        }
        if escaped {
            current.append(character)
            hasToken = true
            escaped = false
            continue
        }
        if character == "\\" {
            escaped = true
            hasToken = true
            continue
        }
        if let activeQuote = quote {
            if character == activeQuote {
                quote = nil
            } else {
                current.append(character)
            }
            continue
        }
        if character == "'" || character == "\"" {
            quote = character
            hasToken = true
        } else if character == " " || character == "\t" || character == "\n" || character == "\r" {
            appendCurrent()
        } else {
            current.append(character)
            hasToken = true
        }
    }

    guard quote == nil, escaped == false else { return [] }
    appendCurrent()
    guard arguments.first?.isEmpty == false,
          arguments.allSatisfy({ $0.rangeOfCharacter(from: .controlCharacters) == nil }) else {
        return []
    }
    return arguments
}

private extension WorkflowSurfaceState {
    var title: String {
        switch self {
        case .empty: "No workflow selected"
        case .loading: "Loading workflow controls"
        case .denied: "Workflow action denied"
        case .reloadRequired: "Reload required"
        case .refreshUnconfirmed: "Refresh unconfirmed"
        case .nextSessionOnly: "Next session only"
        case .recoveryRequired: "Recovery required"
        case .ready: "Workflow mode routing"
        }
    }

    var systemImage: String {
        switch self {
        case .empty: "square.stack.3d.up"
        case .loading: "arrow.triangle.2.circlepath"
        case .denied: "nosign"
        case .reloadRequired: "arrow.clockwise.circle"
        case .refreshUnconfirmed: "questionmark.circle"
        case .nextSessionOnly: "clock.arrow.circlepath"
        case .recoveryRequired: "exclamationmark.triangle"
        case .ready: "point.3.connected.trianglepath.dotted"
        }
    }
}

struct GovernAutomateView: View {
    @Environment(\.workbenchPresentation) private var presentation
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var copyStatus: String?
    @State private var workflowHostCommandText = ""

    private let handoffs: [GovernHandoff]
    private let clipboardWriter: GovernClipboardWriter

    init(
        handoffs: [GovernHandoff] = GovernHandoff.catalog,
        clipboardWriter: GovernClipboardWriter = .system
    ) {
        self.handoffs = handoffs
        self.clipboardWriter = clipboardWriter
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Govern and Automate")
                            .font(.title2)
                        Text(workspaceContext)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label("Copy-only handoffs", systemImage: "doc.on.doc")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if let copyStatus {
                    Label(copyStatus, systemImage: "checkmark.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(copyStatus)
                        .accessibilityIdentifier("govern-copy-status")
                }

                workflowCard

                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 340), spacing: 12, alignment: .top)],
                    alignment: .leading,
                    spacing: 12
                ) {
                    ForEach(handoffs) { handoff in
                        handoffCard(handoff)
                    }
                }
            }
            .padding()
        }
    }

    private var workflowCard: some View {
        let facts = WorkflowSurfaceFacts(
            presentation: presentation.state,
            hasDraft: workspace.workflowDraft != nil,
            hasProposal: workspace.workflowProposal != nil,
            hasSession: workspace.workflowSession != nil,
            blocker: workspace.workflowBlocker,
            recoveryRequired: workspace.workflowRecoveryRequired,
            reloadLimitation: workspace.workflowProposal?.reloadLimitation
                ?? workspace.workflowStatus?.liveStatus
        )
        let surface = classifyWorkflowSurface(facts)
        return GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text(workflowSummary(surface))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                switch surface {
                case .empty:
                    Label(
                        presentation.hasWorkspace ? "Compose or propose a workflow to begin." : "Choose a workspace before routing workflow modes.",
                        systemImage: surface.systemImage
                    )
                    .foregroundStyle(.secondary)
                case .loading:
                    ProgressView(surface.title)
                        .controlSize(.small)
                case .denied, .reloadRequired, .refreshUnconfirmed, .nextSessionOnly, .recoveryRequired:
                    Label(surface.title, systemImage: surface.systemImage)
                        .font(.headline)
                    if let blocker = workspace.workflowBlocker {
                        Text(blocker)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    HStack {
                        Button("Refresh status") { Task { await workspace.refreshWorkflowStatus() } }
                            .disabled(!presentation.allowsWorkspaceMutation)
                        if surface == .recoveryRequired {
                            Button("Recover") { Task { await workspace.recoverWorkflow() } }
                                .disabled(!presentation.allowsWorkspaceMutation)
                        }
                    }
                case .ready:
                    workflowReadyControls
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 2)
        } label: {
            Label("Workflow mode routing", systemImage: "point.3.connected.trianglepath.dotted")
                .font(.headline)
        }
        .accessibilityIdentifier("govern-workflow-router")
    }

    @ViewBuilder
    private var workflowReadyControls: some View {
        if let session = workspace.workflowSession {
            HStack {
                Label(
                    "Active mode: \(session.activeMode ?? "unknown")",
                    systemImage: "checkmark.circle"
                )
                Spacer()
                Button("Observe") { Task { await workspace.observeWorkflow() } }
                    .disabled(!presentation.allowsWorkspaceMutation)
            }
            if let desired = workspace.workflowStatus?.desiredMode,
               desired != session.activeMode {
                Text("Pending mode: \(desired)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        } else if let proposal = workspace.workflowProposal {
            VStack(alignment: .leading, spacing: 6) {
                Text("Review \(proposal.workflowId) → \(proposal.entryMode)")
                    .font(.callout.bold())
                TextField("Child host command (executable and arguments)", text: $workflowHostCommandText)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityLabel("Child host command")
                    .accessibilityIdentifier("govern-workflow-host-command")
                Text("Arguments are passed directly to the child host; no shell is invoked.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Launch reviewed workflow") {
                    let hostCommand = parseWorkflowHostCommand(workflowHostCommandText)
                    Task { await workspace.launchReviewedWorkflow(hostCommand: hostCommand) }
                }
                .disabled(
                    !presentation.allowsWorkspaceMutation
                        || parseWorkflowHostCommand(workflowHostCommandText).isEmpty
                )
            }
        } else {
            Text("Workflow definitions are validated and proposed before a session is launched.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Refresh workflows") { Task { await workspace.refreshWorkflowStatus() } }
                    .disabled(!presentation.allowsWorkspaceMutation)
                Button("Propose from prompt") {
                    Task { await workspace.proposeWorkflow(prompt: "Start a reviewed workflow") }
                }
                .disabled(!presentation.allowsWorkspaceMutation)
            }
        }
    }

    private func workflowSummary(_ surface: WorkflowSurfaceState) -> String {
        switch surface {
        case .empty: "A workflow must be explicit about its provider, entry mode, and sealed capability envelope."
        case .loading: "Reading the authenticated workflow session and its current exposure."
        case .denied: "The requested workflow operation was blocked; no unreviewed expansion is applied."
        case .reloadRequired: "The selected mode is staged, but the provider requires a reload before it is visible."
        case .refreshUnconfirmed: "The provider did not confirm a fresh exposure; inspect status and recovery before retrying."
        case .nextSessionOnly: "The mode is recorded for the next session and is not live in this process."
        case .recoveryRequired: "A workflow operation needs recovery evidence before another transition is allowed."
        case .ready: "Compose, validate, propose, and explicitly launch a workflow before entering a new mode."
        }
    }

    private var workspaceContext: String {
        if presentation.hasWorkspace {
            let name = presentation.workspaceName ?? "the selected workspace"
            return "Verified external paths remain available for \(name); this screen never executes them."
        }
        return "No workspace is required to review or copy these verified external paths. This screen never executes them."
    }

    @ViewBuilder
    private func handoffCard(_ handoff: GovernHandoff) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 10) {
                Text(handoff.summary)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                switch handoff.availability {
                case .verified(let cliCommand, let mcpToolIDs):
                    verifiedHandoff(
                        handoff: handoff,
                        cliCommand: cliCommand,
                        mcpToolIDs: mcpToolIDs
                    )
                case .unavailable(let reason):
                    Label("Unavailable in the desktop app", systemImage: "desktopcomputer.trianglebadge.exclamationmark")
                        .font(.headline)
                    Text(reason)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 2)
        } label: {
            Text(handoff.title)
                .font(.headline)
        }
        .accessibilityIdentifier("govern-handoff-\(handoff.id)")
    }

    @ViewBuilder
    private func verifiedHandoff(
        handoff: GovernHandoff,
        cliCommand: String,
        mcpToolIDs: [String]
    ) -> some View {
        Text("CLI")
            .font(.caption.bold())
            .foregroundStyle(.secondary)
        copyableRow(
            value: cliCommand,
            buttonLabel: "Copy \(handoff.title) CLI",
            statusLabel: "\(handoff.title) CLI command"
        )

        Text("MCP tools")
            .font(.caption.bold())
            .foregroundStyle(.secondary)
        ForEach(mcpToolIDs, id: \.self) { toolID in
            copyableRow(
                value: toolID,
                buttonLabel: "Copy \(toolID)",
                statusLabel: "MCP tool \(toolID)"
            )
        }
    }

    private func copyableRow(
        value: String,
        buttonLabel: String,
        statusLabel: String
    ) -> some View {
        HStack(alignment: .center, spacing: 8) {
            Text(value)
                .font(.system(.callout, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button("Copy") {
                copy(value, statusLabel: statusLabel)
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
            .disabled(!presentation.allowsCopy)
            .accessibilityLabel(buttonLabel)
        }
    }

    func copy(_ value: String, statusLabel: String) {
        clipboardWriter.write(value)
        copyStatus = "Copied \(statusLabel)."
    }
}
