import SwiftUI

enum RecoverPresentationState: Equatable {
    case needsWorkspace
    case loading
    case unavailable(message: String, preservesEvidence: Bool)
    case emptyEvidence
    case noSelection
    case backupSelected
    case operationSelected
}

struct RecoverPresentationFacts: Equatable {
    var hasRecovery = false
    var hasEvidence = false
    var evidenceAvailable = true
    var blocker: String?
    var selectedBackupExists = false
    var selectedOperationExists = false
}

func classifyRecoverPresentation(
    presentation: WorkbenchPresentationInputs,
    facts: RecoverPresentationFacts
) -> RecoverPresentationState {
    switch presentation.state {
    case .needsWorkspace:
        return .needsWorkspace
    case .loading:
        return .loading
    case .blocked(let message):
        return .unavailable(
            message: facts.blocker ?? message,
            preservesEvidence: facts.hasEvidence
        )
    case .ready:
        if let blocker = facts.blocker {
            return .unavailable(message: blocker, preservesEvidence: facts.hasEvidence)
        }
        if presentation.isBusy, facts.hasRecovery == false {
            return .loading
        }
        guard facts.hasRecovery else {
            return .unavailable(
                message: "Recovery evidence has not been loaded. Retry the read-only recovery refresh.",
                preservesEvidence: false
            )
        }
        guard facts.evidenceAvailable else {
            return .unavailable(
                message: "Some authenticated backup or durable operation evidence is unavailable.",
                preservesEvidence: facts.hasEvidence
            )
        }
        guard facts.hasEvidence else { return .emptyEvidence }
        if facts.selectedBackupExists { return .backupSelected }
        if facts.selectedOperationExists { return .operationSelected }
        return .noSelection
    }
}

struct RecoverAuditFixture {
    let recovery: RecoverySnapshot?
    let blocker: String?
    let selectedBackupID: String?
    let selectedOperationID: String?

    init(
        recovery: RecoverySnapshot?,
        blocker: String? = nil,
        selectedBackupID: String? = nil,
        selectedOperationID: String? = nil
    ) {
        self.recovery = recovery
        self.blocker = blocker
        self.selectedBackupID = selectedBackupID
        self.selectedOperationID = selectedOperationID
    }
}

struct RecoverAuditView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.workbenchPresentation) private var presentation
    @Environment(\.workbenchChooseWorkspace) private var chooseWorkspace
    @Environment(\.workbenchOpenChange) private var openChange
    @State private var selectedBackupID: String?
    @State private var selectedOperationID: String?

    let fixture: RecoverAuditFixture?

    init(fixture: RecoverAuditFixture? = nil) {
        self.fixture = fixture
        _selectedBackupID = State(initialValue: fixture?.selectedBackupID)
        _selectedOperationID = State(initialValue: fixture?.selectedOperationID)
    }

    var body: some View {
        let recovery = fixture.map(\.recovery) ?? workspace.recovery
        let blocker = fixture.map(\.blocker) ?? workspace.recoveryBlocker
        let facts = presentationFacts(recovery: recovery, blocker: blocker)
        let state = classifyRecoverPresentation(presentation: presentation, facts: facts)

        Group {
            switch state {
            case .needsWorkspace:
                WorkbenchWorkspaceStateView(
                    title: "Choose a workspace",
                    message: "Select a repository or project before reviewing backup and operation evidence.",
                    actionTitle: chooseWorkspace == nil ? nil : "Choose workspace",
                    action: chooseWorkspace
                )
            case .loading:
                WorkbenchWorkspaceStateView(
                    title: "Loading recovery evidence",
                    message: "Unpin is refreshing authenticated backups and durable operation evidence.",
                    actionTitle: nil,
                    action: nil
                )
            case .unavailable(let message, let preservesEvidence):
                if preservesEvidence, let recovery {
                    recoveryContent(
                        recovery,
                        state: state,
                        warning: "\(message) Last-known evidence is preserved below for inspection."
                    )
                } else {
                    WorkbenchWorkspaceStateView(
                        title: "Recovery evidence is unavailable",
                        message: message,
                        actionTitle: "Retry",
                        action: { Task { await workspace.refreshRecovery() } }
                    )
                }
            case .emptyEvidence:
                WorkbenchWorkspaceStateView(
                    title: "No recovery evidence recorded yet",
                    message: "Change Safely creates authenticated backup and audit evidence when a supported change is applied. Supported CLI and MCP workflows can also create durable evidence.",
                    actionTitle: openChange == nil ? nil : "Go to Change Safely",
                    action: openChange
                )
            case .noSelection, .backupSelected, .operationSelected:
                if let recovery {
                    recoveryContent(recovery, state: state, warning: nil)
                }
            }
        }
        .task(id: presentation.state) {
            guard fixture == nil,
                  presentation.state == .ready,
                  workspace.recovery == nil,
                  workspace.recoveryRequestInFlight == false else { return }
            await workspace.refreshRecovery()
        }
        .onChange(of: selectedBackupID) { _, backupID in
            if backupID != nil, selectedOperationID != nil {
                selectedOperationID = nil
            }
        }
        .onChange(of: selectedOperationID) { _, operationID in
            if operationID != nil, selectedBackupID != nil {
                selectedBackupID = nil
            }
        }
    }

    private func presentationFacts(
        recovery: RecoverySnapshot?,
        blocker: String?
    ) -> RecoverPresentationFacts {
        let selectedBackupExists = recovery?.backups.contains { $0.id == selectedBackupID } ?? false
        let selectedOperationExists = recovery?.operations.contains {
            $0.id == selectedOperationID
        } ?? false
        let evidenceAvailable = recovery.map {
            $0.backupStatus.isAvailable
                && $0.operationStatus.isAvailable
                && $0.groupOperationStatus.isAvailable
        } ?? true
        let hasEvidence = recovery.map {
            !$0.backups.isEmpty || !$0.operations.isEmpty
        } ?? false
        return RecoverPresentationFacts(
            hasRecovery: recovery != nil,
            hasEvidence: hasEvidence,
            evidenceAvailable: evidenceAvailable,
            blocker: blocker,
            selectedBackupExists: selectedBackupExists,
            selectedOperationExists: selectedOperationExists
        )
    }

    private func recoveryContent(
        _ recovery: RecoverySnapshot,
        state: RecoverPresentationState,
        warning: String?
    ) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Recover and Audit").font(.title2)
                        Text("Authenticated backups and durable operation evidence.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Reload") { Task { await workspace.refreshRecovery() } }
                        .disabled(workspace.isBusy)
                }

                if let warning {
                    Label(warning, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } else if state == .noSelection {
                    Text(
                        "Select a backup to review restore evidence or an operation to inspect its durable lifecycle."
                    )
                    .foregroundStyle(.secondary)
                }

                if !recovery.backupStatus.isAvailable
                    || !recovery.operationStatus.isAvailable
                    || !recovery.groupOperationStatus.isAvailable
                {
                    Label(recoveryWarning(recovery), systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                HStack(alignment: .top, spacing: 24) {
                    backupList(recovery)
                    operationList(recovery)
                }

                if let selectedBackup = selectedBackup(in: recovery),
                    selectedBackup.restorable,
                    let reviewed = workspace.reviewedRestore,
                    reviewed.plan.backupId == selectedBackup.backupId
                {
                    Divider()
                    RestoreReviewView(reviewed: reviewed)
                }

                if let blocker = workspace.lastRestoreBlocker {
                    Label(blocker, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }

                if let result = workspace.lastRestore {
                    Label(
                        "Restore \(result.status.displayName): \(result.affectedTargetCount) target(s)",
                        systemImage: "checkmark.shield"
                    )
                    .foregroundStyle(result.status.isRestored ? .green : .orange)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
        }
    }

    private func backupList(_ recovery: RecoverySnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Backups").font(.headline)
            List(selection: $selectedBackupID) {
                ForEach(recovery.backups) { backup in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(backup.backupId).font(.callout.monospaced())
                        Text(
                            "\(backup.itemCount) item(s) · \(backup.providers.joined(separator: ", ")) · \(backup.authentication)"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                    .tag(Optional(backup.id))
                }
            }
            .frame(minWidth: 410, minHeight: 240)

            if let backup = selectedBackup(in: recovery) {
                LabeledContent("Created", value: backup.createdAt)
                LabeledContent("Scope", value: backup.layers.joined(separator: ", "))
                LabeledContent(
                    "Target state",
                    value: backup.targetEnabled == true
                        ? "On"
                        : backup.targetEnabled == false ? "Off" : "Unavailable"
                )
                Button("Review restore") {
                    Task { await workspace.planRestore(backupID: backup.backupId) }
                }
                .disabled(!backup.restorable || workspace.mutationsBlocked)
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

    private func selectedBackup(in recovery: RecoverySnapshot) -> RecoveryBackup? {
        recovery.backups.first { $0.id == selectedBackupID }
    }

    private func operationList(_ recovery: RecoverySnapshot) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Operations").font(.headline)
            List(selection: $selectedOperationID) {
                ForEach(recovery.operations) { operation in
                    VStack(alignment: .leading, spacing: 3) {
                        Text(
                            operation.operationKind
                                .replacingOccurrences(of: "-", with: " ")
                                .capitalized
                        )
                        Text("\(operation.lifecycle) · \(operation.resourceCount) resource(s)")
                            .font(.caption)
                            .foregroundStyle(operation.recoveryRequired ? .orange : .secondary)
                        Text(operation.operationId)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
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
                                .foregroundStyle(
                                    member.failureMode == "recovery-required" ? .orange : .secondary
                                )
                        }
                    }
                    .frame(minHeight: 100, maxHeight: 180)
                }
            }
        }
    }

    private func recoveryWarning(_ recovery: RecoverySnapshot) -> String {
        var unavailable = [String]()
        if !recovery.backupStatus.isAvailable { unavailable.append("backup") }
        if !recovery.operationStatus.isAvailable { unavailable.append("operation") }
        if !recovery.groupOperationStatus.isAvailable { unavailable.append("group operation") }
        return "Some \(unavailable.joined(separator: ", ")) evidence is currently unavailable."
    }
}
