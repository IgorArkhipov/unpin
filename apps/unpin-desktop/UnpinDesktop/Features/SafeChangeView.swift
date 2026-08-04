import SwiftUI

struct SafeChangeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore

    var body: some View {
        Group {
            if let plan = workspace.reviewedPlan {
                PlanReviewView(plan: plan)
            } else if let result = workspace.lastApply {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Latest change").font(.title2)
                    Text("\(result.lifecycle) · requested \(result.requestedState)")
                    Text("Backups: \(result.backupIds.isEmpty ? "none" : result.backupIds.joined(separator: ", "))")
                }
                .padding()
            } else {
                ContentUnavailableView("Choose a group", systemImage: "checklist", description: Text("Open Discover and Organize, then review a group change."))
            }
        }
    }
}
