import SwiftUI

struct RestoreReviewView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    let reviewed: RestorePlanEnvelope

    var body: some View {
        GroupBox("Reviewed restore") {
            VStack(alignment: .leading, spacing: 8) {
                LabeledContent("Backup", value: reviewed.plan.backupId)
                LabeledContent("Providers", value: reviewed.plan.providers.joined(separator: ", "))
                LabeledContent("Authentication", value: reviewed.plan.authentication)
                LabeledContent("Resources", value: "\(reviewed.plan.affectedResourceIds.count)")
                LabeledContent("Fingerprint", value: reviewed.plan.planFingerprint)
                    .font(.caption.monospaced())
                ForEach(reviewed.plan.affectedResourceIds, id: \.self) { resourceID in
                    Text(resourceID).font(.caption.monospaced())
                }
                HStack {
                    Button("Discard review") { Task { await workspace.discardReviewedRestore() } }
                    Spacer()
                    if workspace.reviewedRestoreIsApproved {
                        Label("Local approval is current", systemImage: "checkmark.shield")
                            .foregroundStyle(.green)
                        Button("Apply reviewed restore") { Task { await workspace.applyApprovedRestore() } }
                            .buttonStyle(.borderedProminent)
                            .disabled(workspace.actionsBlocked)
                    } else {
                        Button("Approve with macOS") { Task { await workspace.approveReviewedRestore() } }
                            .buttonStyle(.borderedProminent)
                            .disabled(workspace.actionsBlocked)
                    }
                }
            }
        }
    }
}
