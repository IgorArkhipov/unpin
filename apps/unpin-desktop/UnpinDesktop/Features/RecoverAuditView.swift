import SwiftUI

struct RecoverAuditView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var selectedBackupID: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recover and Audit").font(.title2)
                    Text("Authenticated backups and durable operation evidence.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Reload") { Task { await workspace.refreshRecovery() } }
            }

            if let recovery = workspace.recovery {
                if !recovery.backupStatus.isAvailable || !recovery.operationStatus.isAvailable {
                    Label("Some recovery evidence is currently unavailable.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                HStack(alignment: .top, spacing: 24) {
                    backupList(recovery)
                    operationList(recovery)
                }
            } else {
                ContentUnavailableView("Recovery evidence is loading", systemImage: "arrow.triangle.2.circlepath")
            }

            if let reviewed = workspace.reviewedRestore {
                Divider()
                restoreReview(reviewed)
            }

            if let result = workspace.lastRestore {
                Label("Restore \(result.status.displayName): \(result.affectedTargetCount) target(s)", systemImage: "checkmark.shield")
                    .foregroundStyle(result.status.isRestored ? .green : .orange)
            }
        }
        .padding()
    }

    private func backupList(_ recovery: RecoverySnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Backups").font(.headline)
            List(selection: $selectedBackupID) {
                ForEach(recovery.backups) { backup in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(backup.backupId).font(.callout.monospaced())
                        Text("\(backup.itemCount) item(s) · \(backup.providers.joined(separator: ", ")) · \(backup.authentication)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .tag(Optional(backup.id))
                }
            }
            .frame(minWidth: 410, minHeight: 240)

            if let backup = recovery.backups.first(where: { $0.id == selectedBackupID }) {
                Button("Review restore") {
                    Task { await workspace.planRestore(backupID: backup.backupId) }
                }
                .disabled(!backup.restorable)
                if !backup.restorable {
                    Text("This backup cannot be restored with the current authenticated evidence.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Select a backup to review a restore.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func operationList(_ recovery: RecoverySnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Operations").font(.headline)
            List(recovery.operations) { operation in
                VStack(alignment: .leading, spacing: 3) {
                    Text(operation.operationKind.replacingOccurrences(of: "-", with: " ").capitalized)
                    Text("\(operation.lifecycle) · \(operation.resourceCount) resource(s)")
                        .font(.caption)
                        .foregroundStyle(operation.recoveryRequired ? .orange : .secondary)
                    Text(operation.operationId).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            .frame(minWidth: 360, minHeight: 240)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func restoreReview(_ reviewed: RestorePlanEnvelope) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Review restore").font(.headline)
            LabeledContent("Backup", value: reviewed.plan.backupId)
            LabeledContent("Providers", value: reviewed.plan.providers.joined(separator: ", "))
            LabeledContent("Resources", value: "\(reviewed.plan.affectedResourceIds.count)")
            LabeledContent("Fingerprint", value: reviewed.plan.planFingerprint)
                .font(.caption.monospaced())
            Button("Approve and restore") { Task { await workspace.approveAndRestore() } }
                .buttonStyle(.borderedProminent)
        }
    }
}
