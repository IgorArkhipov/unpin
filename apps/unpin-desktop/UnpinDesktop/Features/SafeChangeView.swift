import SwiftUI

struct SafeChangeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.workbenchPresentation) private var presentation
    @Environment(\.workbenchChooseWorkspace) private var chooseWorkspace

    var body: some View {
        switch presentation.state {
        case .needsWorkspace:
            WorkbenchWorkspaceStateView(
                title: "Choose a workspace",
                message: "Select a repository or project before planning a group change.",
                actionTitle: chooseWorkspace == nil ? nil : "Choose workspace",
                action: chooseWorkspace
            )
        case .loading:
            WorkbenchWorkspaceStateView(
                title: "Loading change prerequisites",
                message: "Unpin is refreshing workspace groups and safety evidence.",
                actionTitle: nil,
                action: nil
            )
        case .blocked(let message):
            WorkbenchWorkspaceStateView(
                title: "Change planning is unavailable",
                message: message,
                actionTitle: "Retry",
                action: { Task { await workspace.reloadWorkspace() } }
            )
        case .ready:
            changeContent
        }
    }

    private var changeContent: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Change Safely").font(.title2)
                    Text("Review the exact group plan before issuing local approval.")
                        .foregroundStyle(.secondary)
                }
            Spacer()
            Button("Reload") { Task { await workspace.reloadWorkspace() } }
                .disabled(workspace.isBusy)
            }

            if let blocker = workspace.lastChangeBlocker {
                Label(blocker, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            if let blocker = workspace.recoveryBlocker {
                Label(blocker, systemImage: "lock.trianglebadge.exclamationmark")
                    .foregroundStyle(.orange)
            }

            if let plan = workspace.reviewedPlan {
                PlanReviewView(plan: plan)
            } else {
                groupChooser
            }

            if let result = workspace.lastApply {
                changeResult(result)
            }
        }
        .padding()
    }

    private var groupChooser: some View {
        GroupBox("Choose a group") {
            if let groups = workspace.snapshot?.groups, !groups.isEmpty {
                List(groups) { group in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(group.qualifiedName)
                            Text(group.fresh == false ? "Observation needs refresh" : group.state ?? "State unavailable")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Enable") { Task { await workspace.plan(group: group, target: "enable") } }
                        Button("Disable") { Task { await workspace.plan(group: group, target: "disable") } }
                    }
                .disabled(
        !group.contextCompatible || workspace.mutationsBlocked
                )
                }
                .frame(minHeight: 220)
            } else {
                ContentUnavailableView("No groups are available", systemImage: "folder.badge.questionmark", description: Text("Create a group in Discover and Organize, then return here to review its change."))
            }
        }
    }

    private func changeResult(_ result: GroupApplyResult) -> some View {
        GroupBox("Verified result") {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("Group", value: result.qualifiedName)
                LabeledContent("Lifecycle", value: result.lifecycle)
                LabeledContent("Final state", value: result.finalState)
                LabeledContent("Observation", value: result.observationFresh ? "fresh" : "needs attention")
                if let reason = result.observationReason {
                    Text(reason).foregroundStyle(.secondary)
                }
                if !result.backupIds.isEmpty {
                    Text("Backup evidence").font(.headline)
                    ForEach(result.backupIds, id: \.self) { backupID in
                        Text(backupID).font(.caption.monospaced())
                    }
                }
                List(result.members) { member in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(member.identity.id)
                        Text(member.reason ?? member.failureMode ?? member.status)
                            .font(.caption)
                            .foregroundStyle(member.failureMode == "recovery-required" ? .orange : .secondary)
                    }
                }
                .frame(minHeight: 120)
                if result.lifecycle == "partial" || result.lifecycle == "recovery-required" {
                    Label("Open Recover and Audit to inspect durable operation and backup evidence.", systemImage: "arrow.clockwise.heart")
                        .foregroundStyle(.orange)
                }
            }
        }
    }
}
