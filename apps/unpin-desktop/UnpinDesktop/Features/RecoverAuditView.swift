import SwiftUI

struct RecoverAuditView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var selectedBackupID: String?
    @State private var selectedOperationID: String?

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
                RestoreReviewView(reviewed: reviewed)
            }

            if let blocker = workspace.lastRestoreBlocker {
                Label(blocker, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
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
                LabeledContent("Created", value: backup.createdAt)
                LabeledContent("Scope", value: backup.layers.joined(separator: ", "))
                LabeledContent("Target state", value: backup.targetEnabled == true ? "On" : backup.targetEnabled == false ? "Off" : "Unavailable")
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
            List(selection: $selectedOperationID) {
                ForEach(recovery.operations) { operation in
                VStack(alignment: .leading, spacing: 3) {
                    Text(operation.operationKind.replacingOccurrences(of: "-", with: " ").capitalized)
                    Text("\(operation.lifecycle) · \(operation.resourceCount) resource(s)")
                        .font(.caption)
                        .foregroundStyle(operation.recoveryRequired ? .orange : .secondary)
                    Text(operation.operationId).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                .tag(Optional(operation.id))
                }
            }
            .frame(minWidth: 360, minHeight: 240)

            if let operation = recovery.operations.first(where: { $0.id == selectedOperationID }) {
                operationDetail(operation)
            } else {
                Text("Select an operation to inspect its durable evidence.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func operationDetail(_ operation: RecoveryOperation) -> some View {
        GroupBox("Operation evidence") {
            VStack(alignment: .leading, spacing: 6) {
                if let name = operation.qualifiedName {
                    LabeledContent("Group", value: name)
                }
                if let state = operation.requestedState {
                    LabeledContent("Requested state", value: state)
                }
                if let reach = operation.providerReach {
                    LabeledContent("Provider reach", value: reach)
                }
                if let fingerprint = operation.effectGraphDigest {
                    LabeledContent("Fingerprint", value: fingerprint)
                        .font(.caption.monospaced())
                }
                LabeledContent("Lifecycle", value: operation.lifecycle)
                LabeledContent("Resources", value: "\(operation.resourceCount)")
                if let finalState = operation.finalState {
                    LabeledContent("Final state", value: finalState)
                }
                if let createdAt = operation.createdAt {
                    LabeledContent("Created", value: createdAt)
                }
                if let reason = operation.observationReason {
                    Label(reason, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                if let backups = operation.backupIds, !backups.isEmpty {
                    Text("Backup references: \(backups.joined(separator: ", "))")
                        .font(.caption.monospaced())
                }
                if let members = operation.members {
                    List(members) { member in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(member.identity.id)
                            Text(member.reason ?? member.failureMode ?? member.status)
                                .font(.caption)
                                .foregroundStyle(member.failureMode == "recovery-required" ? .orange : .secondary)
                        }
                    }
                    .frame(minHeight: 100, maxHeight: 180)
                }
            }
        }
    }
}
