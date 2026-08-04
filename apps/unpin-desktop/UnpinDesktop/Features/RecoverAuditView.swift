import SwiftUI

struct RecoverAuditView: View {
    @EnvironmentObject private var workspace: WorkspaceStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Recover and Audit").font(.title2)
            if let result = workspace.lastApply {
                Text("Latest operation: \(result.operationId)")
                Text("Backup evidence: \(result.backupIds.isEmpty ? "none" : result.backupIds.joined(separator: ", "))")
                Text(result.observationFresh ? "Final observation is fresh." : "Final observation needs a refresh.")
            } else {
                Text("No desktop operation is active. Backup and durable-operation browsing will appear here as bridge recovery endpoints are added.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding()
    }
}
