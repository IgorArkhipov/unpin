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

struct GovernAutomateView: View {
    @Environment(\.workbenchPresentation) private var presentation
    @State private var copyStatus: String?

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
