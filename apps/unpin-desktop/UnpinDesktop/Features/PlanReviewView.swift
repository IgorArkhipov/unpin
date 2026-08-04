import SwiftUI

struct PlanReviewView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    let plan: GroupPlan

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Review change").font(.title2)
            LabeledContent("Group", value: plan.qualifiedName)
            LabeledContent("Requested state", value: plan.target)
            LabeledContent("Provider reach", value: plan.providerReach)
            LabeledContent("Fingerprint", value: plan.planFingerprint)
            List(plan.members) { member in
                VStack(alignment: .leading) {
                    Text(member.identity.id)
                    Text(member.reason ?? member.outcome).foregroundStyle(.secondary)
                }
            }
            Button("Approve with macOS and apply") { Task { await workspace.approveAndApply() } }
                .buttonStyle(.borderedProminent)
        }
        .padding()
    }
}
