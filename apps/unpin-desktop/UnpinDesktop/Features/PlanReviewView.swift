import SwiftUI

struct PlanReviewView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    let plan: GroupPlan

    var body: some View {
        GroupBox("Reviewed change") {
            VStack(alignment: .leading, spacing: 12) {
                LabeledContent("Group", value: plan.qualifiedName)
                LabeledContent("Requested state", value: plan.target)
                LabeledContent("Provider reach", value: plan.providerReach)
                LabeledContent("Plan lifecycle", value: plan.lifecycle)
                LabeledContent("Plan state", value: plan.disposition)
                LabeledContent("Definition revision", value: plan.groupRevision)
                LabeledContent("Fingerprint", value: plan.planFingerprint)
                    .font(.caption.monospaced())

                GroupBox("Provider coverage") {
                    Text(coverageSummary)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                GroupBox("Affected items") {
                    List(plan.members) { member in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(member.identity.id)
                            Text(member.reason ?? member.outcome)
                                .font(.caption)
                                .foregroundStyle(member.outcome == "blocked" || member.outcome == "missing" ? .orange : .secondary)
                        }
                    }
                    .frame(minHeight: 120, maxHeight: 240)
                }

                HStack {
                    Text("\(plan.cohorts.count) execution cohort(s) · \(plan.resources.count) protected resource(s)")
                        .foregroundStyle(.secondary)
                    Spacer()
                Button("Discard review") { Task { await workspace.discardReviewedPlan() } }
            .disabled(workspace.mutationsBlocked)
                    if workspace.reviewedPlanIsApproved {
                        Label("Local approval is current", systemImage: "checkmark.shield")
                            .foregroundStyle(.green)
                        Button("Apply reviewed change") { Task { await workspace.applyApprovedPlan() } }
                            .buttonStyle(.borderedProminent)
            .disabled(workspace.mutationsBlocked)
                    } else {
                        Button("Approve with macOS") { Task { await workspace.approveReviewedPlan() } }
                            .buttonStyle(.borderedProminent)
            .disabled(!isActionable || workspace.mutationsBlocked)
                    }
                }
            }
        }
    }

    private var isActionable: Bool {
        plan.disposition == "actionable" && plan.operationId != nil
    }

    private var coverageSummary: String {
        plan.providerCoverage.entries.map { entry in
            "\(entry.provider) · \(entry.included ? "included" : entry.reason ?? "excluded") · \(entry.targetId)"
        }
        .joined(separator: "\n")
    }
}
