import SwiftUI

enum ChangePresentationState: Equatable {
    case needsWorkspace
    case loading
    case blocked(String)
    case noGroups
    case ready
}

func classifyChangePresentation(
    presentation: WorkbenchPresentationInputs,
    snapshotAvailable: Bool,
    groupCount: Int
) -> ChangePresentationState {
    switch presentation.state {
    case .needsWorkspace:
        return .needsWorkspace
    case .loading:
        return .loading
    case .blocked(let message):
        return .blocked(message)
    case .ready:
        guard snapshotAvailable else {
            return .blocked("Workspace group evidence is unavailable. Reload the workspace before planning a change.")
        }
        return groupCount == 0 ? .noGroups : .ready
    }
}

struct SafeChangeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.workbenchPresentation) private var presentation
    @Environment(\.workbenchChooseWorkspace) private var chooseWorkspace
    @Environment(\.workbenchCreateGroup) private var createGroup

    let groupsOverride: [GroupSummary]?

    init(groupsOverride: [GroupSummary]? = nil) {
        self.groupsOverride = groupsOverride
    }

    var body: some View {
        let groups = groupsOverride ?? workspace.snapshot?.groups
        switch classifyChangePresentation(
            presentation: presentation,
            snapshotAvailable: groups != nil,
            groupCount: groups?.count ?? 0
        ) {
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
        case .noGroups:
            WorkbenchWorkspaceStateView(
                title: "Create a group before planning a change",
                message: "Change Safely works on an inventory group so Unpin can show one exact plan, approval boundary, and recovery evidence. Create the group in Discover and Organize, then return here.",
                actionTitle: createGroup == nil ? nil : "Create group",
                action: createGroup
            )
        case .ready:
            changeContent(groups ?? [])
        }
    }

    private func changeContent(_ groups: [GroupSummary]) -> some View {
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
                groupChooser(groups)
            }

            if let result = workspace.lastApply {
                changeResult(result)
            }
        }
        .padding()
    }

    private func groupChooser(_ groups: [GroupSummary]) -> some View {
        GroupBox("Choose group") {
            List(groups) { group in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.qualifiedName)
                        Text(
                            group.fresh == false
                                ? "Observation needs refresh"
                                : group.state ?? "State unavailable"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Group {
                        Button("Enable") {
                            Task { await workspace.plan(group: group, target: "enable") }
                        }
                        Button("Disable") {
                            Task { await workspace.plan(group: group, target: "disable") }
                        }
                    }
                    .disabled(!group.contextCompatible || workspace.mutationsBlocked)
                }
            }
            .frame(minHeight: 220)
        }
    }

    private func changeResult(_ result: GroupApplyResult) -> some View {
        GroupBox("Verified result") {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("Group", value: result.qualifiedName)
                LabeledContent("Lifecycle", value: result.lifecycle)
                LabeledContent("Final state", value: result.finalState)
                LabeledContent(
                    "Observation",
                    value: result.observationFresh ? "fresh" : "needs attention"
                )
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
                            .foregroundStyle(
                                member.failureMode == "recovery-required" ? .orange : .secondary
                            )
                    }
                }
                .frame(minHeight: 120)
                if result.lifecycle == "partial" || result.lifecycle == "recovery-required" {
                    Label(
                        "Open Recover and Audit to inspect durable operation and backup evidence.",
                        systemImage: "arrow.clockwise.heart"
                    )
                    .foregroundStyle(.orange)
                }
            }
        }
    }
}
