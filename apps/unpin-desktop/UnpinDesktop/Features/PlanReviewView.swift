import SwiftUI

struct PlanReviewView: View {
    @EnvironmentObject private var workspace: WorkspaceStore

    private enum ReviewedPlan {
        case group(GroupPlan)
        case agentPlugin(AgentPluginPlan)
    }

    private let reviewedPlan: ReviewedPlan

    init(plan: GroupPlan) {
        reviewedPlan = .group(plan)
    }

    init(agentPluginPlan: AgentPluginPlan) {
        reviewedPlan = .agentPlugin(agentPluginPlan)
    }

    @ViewBuilder
    var body: some View {
        switch reviewedPlan {
        case .group(let plan):
            groupReview(plan)
        case .agentPlugin(let plan):
            agentPluginReview(plan)
        }
    }

    private func groupReview(_ plan: GroupPlan) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Reviewed reach-aware plan") {
                VStack(alignment: .leading, spacing: 12) {
                    LabeledContent("Group", value: plan.qualifiedName)
                    LabeledContent("Requested state", value: plan.target)
                    LabeledContent("Provider reach", value: plan.providerReach)
                    LabeledContent("Plan lifecycle", value: plan.lifecycle)
                    LabeledContent("Plan disposition", value: plan.disposition)
                    LabeledContent("Definition revision", value: plan.groupRevision)
                    LabeledContent("Fingerprint", value: plan.planFingerprint)
                        .font(.caption.monospaced())
                }
            }

            GroupBox("Provider reach coverage") {
                Text(groupCoverageSummary(plan))
                    .font(.caption.monospaced())
            }

            GroupBox("Affected native configuration") {
                List(plan.members) { member in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(member.identity.id)
                        Text(member.reason ?? member.outcome)
                            .font(.caption)
                            .foregroundStyle(
                                member.outcome == "blocked" ? .orange : .secondary
                            )
                    }
                }
                .frame(minHeight: 120, maxHeight: 240)
            }

            HStack {
                Text("\(plan.cohorts.count) execution cohort(s) · \(plan.resources.count) protected resource(s)")
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Discard review") {
                    Task { await workspace.discardReviewedPlan() }
                }
                .disabled(workspace.mutationsBlocked)

                if workspace.reviewedPlanIsApproved {
                    Label("Local approval current", systemImage: "checkmark.shield")
                    Button("Apply reviewed change") {
                        Task { await workspace.applyApprovedPlan() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(workspace.mutationsBlocked)
                } else {
                    Button("Approve with macOS") {
                        Task { await workspace.approveReviewedPlan() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!groupPlanIsActionable(plan) || workspace.mutationsBlocked)
                }
            }
        }
    }

    private func agentPluginReview(_ plan: AgentPluginPlan) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Reviewed Agent Plugin operation") {
                VStack(alignment: .leading, spacing: 8) {
                    LabeledContent("Package", value: plan.name)
                    LabeledContent("Current state", value: plan.state)
                    LabeledContent("Access", value: plan.access)
                    LabeledContent("Requested state", value: plan.target)
                    LabeledContent("Provider reach", value: plan.providerReach)
                    LabeledContent("Lifecycle", value: plan.lifecycle)
                    LabeledContent("Operation", value: plan.operationId)
                        .font(.caption.monospaced())
                    LabeledContent("Plan fingerprint", value: plan.planFingerprint)
                        .font(.caption.monospaced())
                }
            }

            GroupBox("Coverage and counts") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(plan.coverage) { coverage in
                        Label(
                            "\(coverage.provider): \(coverage.included) included, \(coverage.excluded) excluded",
                            systemImage: coverage.excluded == 0
                                ? "checkmark.circle"
                                : "circle.lefthalf.filled"
                        )
                    }
                    Text(
                        "\(plan.counts.writes) write(s) · \(plan.counts.noOp) no-op · \(plan.counts.blocked) blocked · \(plan.counts.reachExcluded) reach-excluded"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }

            dispositionGroup(
                "Included activation anchors",
                rows: plan.review.included,
                emptyMessage: "No activation anchors are included."
            )
            dispositionGroup(
                "Already at requested state",
                rows: plan.review.noOp,
                emptyMessage: "No no-op anchors."
            )
            dispositionGroup(
                "Blocked activation anchors",
                rows: plan.review.blocked,
                emptyMessage: "No blocked anchors."
            )
            dispositionGroup(
                "Outside selected reach",
                rows: plan.review.reachExcluded,
                emptyMessage: "No package instances are excluded by reach."
            )
            dispositionGroup(
                "Component diagnostics",
                rows: plan.review.componentDiagnostics,
                emptyMessage: "No component diagnostics."
            )

            HStack(spacing: 10) {
                Button("Cancel review") {
                    Task { await workspace.discardReviewedAgentPlugin() }
                }
                .disabled(workspace.mutationsBlocked)

                Button("Replan from fresh discovery") {
                    Task { await replanAgentPlugin(plan) }
                }
                .disabled(workspace.mutationsBlocked)

                Button("Refresh Recover Audit") {
                    Task { await workspace.refreshRecovery() }
                }
                .disabled(workspace.recoveryRequestInFlight)

                Spacer()

                if workspace.reviewedAgentPluginIsApproved {
                    Label("Local approval current", systemImage: "checkmark.shield")
                    Button("Apply reviewed package change") {
                        Task { await workspace.applyApprovedAgentPlugin() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(workspace.mutationsBlocked)
                } else {
                    Button("Approve with macOS") {
                        Task { await workspace.approveReviewedAgentPlugin() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!agentPluginPlanIsActionable(plan) || workspace.mutationsBlocked)
                }
            }
        }
    }

    private func dispositionGroup(
        _ title: String,
        rows: [AgentPluginDisposition],
        emptyMessage: String
    ) -> some View {
        GroupBox(title) {
            VStack(alignment: .leading, spacing: 5) {
                if rows.isEmpty {
                    Label(emptyMessage, systemImage: "minus.circle")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                        Label(dispositionText(row), systemImage: dispositionIcon(row))
                            .font(.caption)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func dispositionText(_ row: AgentPluginDisposition) -> String {
        let subject = [row.provider, row.layer, row.kind, row.name]
            .compactMap { $0 }
            .joined(separator: " · ")
        let detail = row.reasonCode ?? row.reason ?? row.outcome ?? row.disposition ?? "included"
        let count = row.activationCount.map { " · \($0) activation(s)" } ?? ""
        return "\(subject) — \(detail)\(count)"
    }

    private func dispositionIcon(_ row: AgentPluginDisposition) -> String {
        if row.reasonCode != nil || row.disposition == "blocked" {
            return "exclamationmark.octagon"
        }
        if row.outcome == "no-op" {
            return "minus.circle"
        }
        if row.disposition == "diagnostic" {
            return "stethoscope"
        }
        return "checkmark.circle"
    }

    private func replanAgentPlugin(_ plan: AgentPluginPlan) async {
        guard let package = workspace.snapshot?.agentPlugins.first(where: {
            $0.logicalId == plan.logicalId
        }) else { return }
        switch plan.$providerReach {
        case .all:
            await workspace.planAgentPlugin(
                package,
                target: plan.target,
                reach: "all",
                selectedProvider: nil
            )
        case .selected(let provider, _):
            await workspace.planAgentPlugin(
                package,
                target: plan.target,
                reach: "selected",
                selectedProvider: provider
            )
        }
    }

    private func groupPlanIsActionable(_ plan: GroupPlan) -> Bool {
        plan.disposition == "actionable" && plan.operationId != nil
    }

    private func agentPluginPlanIsActionable(_ plan: AgentPluginPlan) -> Bool {
        plan.access == "actionable"
            && plan.counts.writes > 0
            && ["applied", "partial"].contains(plan.lifecycle)
    }

    private func groupCoverageSummary(_ plan: GroupPlan) -> String {
        plan.providerCoverage.entries.map { entry in
            "\(entry.provider) · \(entry.included ? "included" : entry.reason ?? "excluded") · \(entry.targetId)"
        }
        .joined(separator: "\n")
    }
}
