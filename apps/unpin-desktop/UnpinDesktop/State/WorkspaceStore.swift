import Combine
import CryptoKit
import Foundation

enum WorkspaceStatusText {
    static let chooseWorkspace = "Choose a workspace folder to begin."
    static let connecting = "Connecting to the bundled Unpin bridge…"
}

struct InventoryFacets {
    let providers: [String]
    let layers: [String]
    let categories: [String]

    init(inventory: [InventoryItem]) {
        var providers = Set<String>()
        var layers = Set<String>()
        var categories = Set<String>()
        for item in inventory {
            providers.insert(item.provider)
            layers.insert(item.layer)
            categories.insert(item.category)
        }
        self.providers = providers.sorted()
        self.layers = layers.sorted()
        self.categories = categories.sorted()
    }
}

func matchesInventoryFilter(
    _ item: InventoryItem,
    search: String,
    provider: String,
    layer: String,
    category: String,
    state: String
) -> Bool {
    (provider == "all" || item.provider == provider)
        && (layer == "all" || item.layer == layer)
        && (category == "all" || item.category == category)
        && (state == "all" || (state == "on") == item.enabled)
        && (
            search.isEmpty
                || item.displayName.localizedCaseInsensitiveContains(search)
                || item.id.localizedCaseInsensitiveContains(search)
        )
}

struct WorkspaceStoreTestHooks {
    var beforeReadResponse: (() async -> Void)?
    var beforeReadError: (() async -> Void)?
    var beforeGroupPlan: (() async -> Void)?
    var beforeGroupApply: (() async -> Void)?
    var beforeAgentPluginPlan: (() async -> Void)?
    var beforeAgentPluginApply: (() async -> Void)?
    var beforeAgentPluginDiscard: (() async -> Void)?
    var beforeDefinitionApply: (() async -> Void)?
    var beforeRestoreApply: (() async -> Void)?
    var beforeRecoveryRefresh: (() async -> Void)?
    var beforeWorkflowRequest: (() async -> Void)?
    var beforeWorkflowControl: (() async -> Void)?
    var beforeWorkspaceConnect: (() async throws -> Void)?

    init(
        beforeReadResponse: (() async -> Void)? = nil,
        beforeReadError: (() async -> Void)? = nil,
        beforeGroupPlan: (() async -> Void)? = nil,
        beforeGroupApply: (() async -> Void)? = nil,
        beforeAgentPluginPlan: (() async -> Void)? = nil,
        beforeAgentPluginApply: (() async -> Void)? = nil,
        beforeAgentPluginDiscard: (() async -> Void)? = nil,
        beforeDefinitionApply: (() async -> Void)? = nil,
        beforeRestoreApply: (() async -> Void)? = nil,
        beforeRecoveryRefresh: (() async -> Void)? = nil,
        beforeWorkflowRequest: (() async -> Void)? = nil,
        beforeWorkflowControl: (() async -> Void)? = nil,
        beforeWorkspaceConnect: (() async throws -> Void)? = nil
    ) {
        self.beforeReadResponse = beforeReadResponse
        self.beforeReadError = beforeReadError
        self.beforeGroupPlan = beforeGroupPlan
        self.beforeGroupApply = beforeGroupApply
        self.beforeAgentPluginPlan = beforeAgentPluginPlan
        self.beforeAgentPluginApply = beforeAgentPluginApply
        self.beforeAgentPluginDiscard = beforeAgentPluginDiscard
        self.beforeDefinitionApply = beforeDefinitionApply
        self.beforeRestoreApply = beforeRestoreApply
        self.beforeRecoveryRefresh = beforeRecoveryRefresh
        self.beforeWorkflowRequest = beforeWorkflowRequest
        self.beforeWorkflowControl = beforeWorkflowControl
        self.beforeWorkspaceConnect = beforeWorkspaceConnect
    }
}

@MainActor
final class WorkspaceStore: ObservableObject {
    enum State { case needsWorkspace, loading, ready, blocked(String) }

    private static let recoveryUnavailableMessage =
        "Recovery evidence is unavailable. The last known evidence is preserved; refresh Recover and Audit or reload the workspace before trying another change."
    private static let configurationChangeInProgressMessage =
        "Unpin is still confirming a configuration change. Wait for it to finish before reloading the workspace."
    private static let definitionChangeUnconfirmedMessage =
        "Unpin did not confirm this definition change. It may have written configuration; inspect Recover and Audit before creating another definition change."
    private static let mutationUncertaintyMessage =
        "Unpin did not confirm this change. It may have written configuration; inspect Recover and Audit or reload the workspace before trying another change."

    @Published private(set) var state: State = .needsWorkspace
    @Published private(set) var snapshot: BridgeSnapshot?
    @Published private(set) var reviewedPlan: GroupPlan?
    @Published private(set) var approvedPlanFingerprint: String?
    @Published private(set) var lastChangeBlocker: String?
    @Published private(set) var lastApply: GroupApplyResult?
    @Published private(set) var reviewedAgentPlugin: AgentPluginPlan?
    @Published private(set) var approvedAgentPluginFingerprint: String?
    @Published private(set) var lastAgentPluginBlocker: String?
    @Published private(set) var lastAgentPluginApply: AgentPluginApplyResult?
    @Published private(set) var reviewedDefinition: GroupDefinitionPlanEnvelope?
    @Published private(set) var definitionHistory: [GroupDefinitionHistory] = []
    @Published private(set) var lastDefinitionBlocker: String?
    @Published private(set) var recovery: RecoverySnapshot?
    @Published private(set) var recoveryBlocker: String?
    @Published private(set) var reviewedRestore: RestorePlanEnvelope?
    @Published private(set) var approvedRestoreFingerprint: String?
    @Published private(set) var lastRestoreBlocker: String?
    @Published private(set) var lastRestore: RestoreApplyResult?
    @Published private(set) var workspaceName: String?
    @Published private(set) var mutationUncertaintyBlocker: String?
    @Published private(set) var workflowDraft: WorkflowDraft?
    @Published private(set) var workflowDefinitions: [WorkflowDraft] = []
    @Published private(set) var workflowValidation: WorkflowValidationEnvelope?
    @Published private(set) var workflowProposal: WorkflowProposal?
    @Published private(set) var workflowCandidates: [WorkflowCandidate] = []
    @Published private(set) var workflowSession: WorkflowSessionSnapshot?
    @Published private(set) var workflowStatus: WorkflowStatusSnapshot?
    @Published private(set) var workflowOperations: [WorkflowOperationSnapshot] = []
    @Published private(set) var workflowRecovery: WorkflowRecoveryEnvelope?
    @Published private(set) var workflowBlocker: String?
    @Published private(set) var workflowRecoveryRequired = false
    @Published private(set) var workflowHostCommand: [String] = []

    private var bridge: BridgeClient?
    private var workspaceRoot: URL?
    private var connectionGeneration = 0
    private let bridgeRoots: BridgeLaunchRoots
    private var testHooks = WorkspaceStoreTestHooks()
    private var groupPlanRequestGeneration = 0
    private var agentPluginPlanRequestGeneration = 0
    private var recoveryRequestGeneration = 0
    @Published private(set) var controlRequestInFlight = false
    @Published private(set) var recoveryRequestInFlight = false
    @Published private(set) var workflowRequestInFlight = false

    init(bridgeRoots: BridgeLaunchRoots = BridgeLaunchRoots()) {
        self.bridgeRoots = bridgeRoots
    }

    func installTestHooksForTesting(_ hooks: WorkspaceStoreTestHooks) {
        testHooks = hooks
    }

    var statusMessage: String? {
        switch state {
        case .needsWorkspace: WorkspaceStatusText.chooseWorkspace
        case .loading: WorkspaceStatusText.connecting
        case .ready: nil
        case .blocked(let message): message
        }
    }

    var reviewedPlanIsApproved: Bool {
        reviewedPlan?.planFingerprint == approvedPlanFingerprint
    }

    var reviewedRestoreIsApproved: Bool {
        reviewedRestore?.plan.planFingerprint == approvedRestoreFingerprint
    }

    var reviewedAgentPluginIsApproved: Bool {
        reviewedAgentPlugin?.planFingerprint == approvedAgentPluginFingerprint
    }

    var hasWorkspace: Bool { workspaceRoot != nil }

    var actionsBlocked: Bool {
        recoveryBlocker != nil || mutationUncertaintyBlocker != nil || workflowRecoveryRequired
    }

    var mutationsBlocked: Bool {
        isBusy || actionsBlocked
    }

    var isBusy: Bool {
        if case .loading = state { return true }
        return controlRequestInFlight || recoveryRequestInFlight || workflowRequestInFlight
    }

    func launch() async {
        state = .needsWorkspace
    }

    func selectWorkspace(_ root: URL) async {
        guard isBusy == false else { return }
        let selectedRoot = root.standardizedFileURL
        guard selectedRoot.hasDirectoryPath else {
            state = .blocked("Choose a workspace folder, not a file.")
            return
        }
        let preserveRecovery = workspaceRoot == selectedRoot
        if preserveRecovery == false {
            recovery = nil
            recoveryBlocker = nil
            mutationUncertaintyBlocker = nil
        }
        workspaceRoot = selectedRoot
        workspaceName = selectedRoot.lastPathComponent
        connectionGeneration &+= 1
        await connectWorkspace(
            root: selectedRoot,
            generation: connectionGeneration,
            loadRecovery: preserveRecovery && (recovery != nil || recoveryBlocker != nil),
            preserveRecovery: preserveRecovery
        )
    }

    func reloadWorkspace() async {
        guard isBusy == false else { return }
        guard let workspaceRoot else {
            state = .needsWorkspace
            return
        }
        let preserveRecovery = recovery != nil || recoveryBlocker != nil
        connectionGeneration &+= 1
        await connectWorkspace(
            root: workspaceRoot,
            generation: connectionGeneration,
            loadRecovery: preserveRecovery,
            preserveRecovery: preserveRecovery
        )
    }

    private func connectWorkspace(
        root: URL,
        generation: Int,
        loadRecovery: Bool,
        preserveRecovery: Bool
    ) async {
        guard connectionIsCurrent(generation) else { return }
        state = .loading
        let previousBridge = bridge
        if let previousBridge, await previousBridge.stop() == false {
            guard connectionIsCurrent(generation) else { return }
            if preserveRecovery {
                setRecoveryUnavailable(message: Self.configurationChangeInProgressMessage)
            } else {
                state = .blocked(Self.configurationChangeInProgressMessage)
            }
            return
        }
        guard connectionIsCurrent(generation) else { return }
        bridge = nil
        clearWorkspaceState(preservingRecovery: preserveRecovery)
        var replacement: BridgeClient?
        do {
            if let hook = testHooks.beforeWorkspaceConnect {
                try await hook()
            }
            let bundledBridge = try Self.bundledBridge()
            let bridge = BridgeClient(
                executableURL: bundledBridge.executable,
                projectRoot: root,
                manifest: bundledBridge.manifest,
                roots: bridgeRoots
            )
            replacement = bridge
            try await bridge.start()
            guard connectionIsCurrent(generation) else {
                await bridge.stop()
                return
            }
            _ = try await bridge.handshake()
            guard connectionIsCurrent(generation) else {
                await bridge.stop()
                return
            }
            self.bridge = bridge
            try await refresh(connectionGeneration: generation)
            guard connectionIsCurrent(generation) else { return }
            await refreshWorkflowStatus(connectionGeneration: generation)
            guard connectionIsCurrent(generation) else { return }
            if loadRecovery {
                await refreshRecovery(connectionGeneration: generation)
            } else {
                recoveryBlocker = nil
            }
        } catch {
            if let replacement {
                await replacement.stop()
            }
            guard connectionIsCurrent(generation) else { return }
            if preserveRecovery {
                setRecoveryUnavailable(message: error.localizedDescription)
            } else {
                state = .blocked(error.localizedDescription)
            }
        }
    }

    private func connectionIsCurrent(_ generation: Int) -> Bool {
        generation == connectionGeneration
    }

    private func awaitReadResponseHook() async {
        if let hook = testHooks.beforeReadResponse {
            await hook()
        }
    }

    private func awaitReadErrorHook() async {
        if let hook = testHooks.beforeReadError {
            await hook()
        }
    }

    private func clearWorkspaceState(preservingRecovery: Bool) {
        snapshot = nil
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
        lastApply = nil
        agentPluginPlanRequestGeneration &+= 1
        reviewedAgentPlugin = nil
        approvedAgentPluginFingerprint = nil
        lastAgentPluginBlocker = nil
        lastAgentPluginApply = nil
        reviewedDefinition = nil
        definitionHistory = []
        lastDefinitionBlocker = nil
        if preservingRecovery == false {
            recovery = nil
            recoveryBlocker = nil
            mutationUncertaintyBlocker = nil
        }
        reviewedRestore = nil
        approvedRestoreFingerprint = nil
        lastRestoreBlocker = nil
        lastRestore = nil
        workflowDraft = nil
        workflowDefinitions = []
        workflowValidation = nil
        workflowProposal = nil
        workflowCandidates = []
        workflowSession = nil
        workflowStatus = nil
        workflowOperations = []
        workflowRecovery = nil
        workflowBlocker = nil
        workflowRecoveryRequired = false
        workflowHostCommand = []
    }

    func refresh(connectionGeneration: Int? = nil) async throws {
        guard let bridge else { throw BridgeClientError.childStopped }
        let expectedGeneration = connectionGeneration ?? self.connectionGeneration
        let freshSnapshot = try await bridge.snapshot()
        guard connectionIsCurrent(expectedGeneration) else { return }
        if let reviewedAgentPlugin,
           freshSnapshot.agentPlugins.first(where: {
               $0.logicalId == reviewedAgentPlugin.logicalId
                   && $0.projectionFingerprint == reviewedAgentPlugin.projectionFingerprint
           }) == nil {
            if let hook = testHooks.beforeAgentPluginDiscard {
                await hook()
            }
            try? await bridge.discardAgentPlugin(
                operationID: reviewedAgentPlugin.operationId,
                fingerprint: reviewedAgentPlugin.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return }
            self.reviewedAgentPlugin = nil
            approvedAgentPluginFingerprint = nil
            lastAgentPluginBlocker = "The package changed after review. Create a fresh review before applying."
        }
        snapshot = freshSnapshot
        setReadyUnlessDefinitionBlocked()
    }

    func refreshRecovery(connectionGeneration: Int? = nil) async {
        guard recoveryRequestInFlight == false else { return }
        recoveryRequestGeneration &+= 1
        let requestGeneration = recoveryRequestGeneration
        recoveryRequestInFlight = true
        defer {
            if recoveryRequestGeneration == requestGeneration {
                recoveryRequestInFlight = false
            }
        }
        let expectedGeneration = connectionGeneration ?? self.connectionGeneration
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeRecoveryRefresh {
                await hook()
            }
            let freshRecovery = try await bridge.recoverySnapshot()
            guard recoveryRequestIsCurrent(
                requestGeneration,
                connectionGeneration: expectedGeneration
            ) else { return }
            recovery = freshRecovery
            recoveryBlocker = nil
            mutationUncertaintyBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch is CancellationError {
            // View/task cancellation is an expected interruption of a read-only
            // refresh. Leave the last-known evidence and workspace state unchanged.
            return
        } catch {
            guard recoveryRequestIsCurrent(
                requestGeneration,
                connectionGeneration: expectedGeneration
            ) else { return }
            setRecoveryUnavailable()
        }
    }

    // MARK: - Workflow mode routing

    func composeWorkflow(_ parameters: WorkflowComposeParameters) async {
        guard guardActionsAllowed() else { return }
        await performWorkflowRead { bridge in
            try await bridge.composeWorkflow(parameters)
        } onSuccess: { envelope in
            guard let draft = envelope.workflow else {
                throw BridgeClientError.malformedResponse
            }
            self.workflowDraft = draft
            self.workflowValidation = nil
            self.workflowProposal = nil
            self.workflowCandidates = []
            self.workflowBlocker = nil
        }
    }

    func composeWorkflow(
        workflowID: String,
        displayName: String,
        description: String? = nil,
        provider: String,
        baselineProfileID: String,
        entryMode: String,
        modes: [WorkflowModeDraft]
    ) async {
        await composeWorkflow(WorkflowComposeParameters(
            workflowId: workflowID,
            displayName: displayName,
            description: description,
            provider: provider,
            baselineProfileId: baselineProfileID,
            entryMode: entryMode,
            modes: modes
        ))
    }

    @MainActor
    func selectWorkflow(workflowID: String) {
        guard let selected = workflowDefinitions.first(where: { $0.workflowId == workflowID }) else {
            workflowBlocker = "The selected workflow is no longer available. Refresh workflow status and choose it again."
            return
        }
        workflowDraft = selected
        workflowValidation = nil
        workflowProposal = nil
        workflowCandidates = []
        workflowHostCommand = []
        workflowBlocker = nil
    }

    func validateWorkflow() async {
        guard guardActionsAllowed() else { return }
        guard let draft = workflowDraft else {
            workflowBlocker = "Compose a workflow before validating it."
            return
        }
        await performWorkflowRead { bridge in
            try await bridge.validateWorkflow(WorkflowValidateParameters(
                workflowId: draft.workflowId,
                provider: draft.provider,
                workflowRevision: draft.workflowRevision.isEmpty ? nil : draft.workflowRevision
            ))
        } onSuccess: { validation in
            self.workflowValidation = validation
            self.workflowBlocker = validation.valid ? nil : "Workflow validation was denied. Review the reported constraints before proposing a launch."
        }
    }

    func proposeWorkflow(prompt: String, provider: String? = nil) async {
        guard guardActionsAllowed() else { return }
        guard let draft = workflowDraft else {
            workflowBlocker = "Select a hydrated workflow before proposing a session."
            return
        }
        let selectedProvider = provider ?? draft.provider
        guard selectedProvider.isEmpty == false else {
            workflowBlocker = "The selected workflow has no provider. Refresh workflow status and choose a complete workflow."
            return
        }
        await performWorkflowRead { bridge in
            try await bridge.proposeWorkflow(WorkflowProposeParameters(
                prompt: prompt,
                workflowId: draft.workflowId,
                provider: selectedProvider
            ))
        } onSuccess: { proposal in
            self.workflowProposal = proposal.proposal
            self.workflowCandidates = proposal.candidates
            self.workflowHostCommand = []
            self.workflowBlocker = nil
            if proposal.proposal == nil, proposal.confirmationRequired == true {
                self.state = .ready
            }
        }
    }

    func setWorkflowHostCommand(_ command: [String]) {
        workflowHostCommand = Self.normalizedWorkflowHostCommand(command)
    }

    func launchReviewedWorkflow(hostCommand: [String]? = nil) async {
        guard controlRequestInFlight == false, guardActionsAllowed() else { return }
        guard let proposal = workflowProposal else {
            workflowBlocker = "Review a workflow proposal before launching a session."
            return
        }
        let requestedHostCommand = hostCommand ?? workflowHostCommand
        let normalizedHostCommand = Self.normalizedWorkflowHostCommand(requestedHostCommand)
        guard normalizedHostCommand.isEmpty == false else {
            workflowBlocker = "Enter a child host command before launching a workflow session."
            return
        }
        workflowHostCommand = normalizedHostCommand
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        workflowRequestInFlight = true
        defer {
            controlRequestInFlight = false
            workflowRequestInFlight = false
        }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeWorkflowControl { await hook() }
            let envelope = try await bridge.launchWorkflow(WorkflowLaunchParameters(
                proposalId: proposal.proposalId,
                proposalFingerprint: proposal.proposalFingerprint,
                hostCommand: normalizedHostCommand
            ))
            guard connectionIsCurrent(expectedGeneration) else { return }
            guard let session = envelope.session else {
                workflowBlocker = envelope.nextAction
                    ?? "The workflow launch did not establish a child-host session."
                return
            }
            workflowSession = session
            workflowProposal = nil
            workflowBlocker = nil
            workflowRecoveryRequired = false
            workflowRequestInFlight = false
            await refreshWorkflowStatus(connectionGeneration: expectedGeneration)
            workflowRequestInFlight = true
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            workflowProposal = nil
            if mutationMayBeUnconfirmed(error) {
                workflowBlocker = "The workflow launch was not confirmed. Inspect workflow recovery before retrying."
                workflowRecoveryRequired = true
                workflowRequestInFlight = false
                await refreshWorkflowRecovery(connectionGeneration: expectedGeneration)
            } else {
                workflowBlocker = error.localizedDescription
                state = .blocked(error.localizedDescription)
            }
        }
    }

    func transitionWorkflow(
        targetMode: String,
        operationID: String? = nil,
        operationFingerprint: String? = nil
    ) async {
        guard controlRequestInFlight == false, guardActionsAllowed() else { return }
        guard let session = workflowSession else {
            workflowBlocker = "Launch a workflow session before changing modes."
            return
        }
        guard targetMode.isEmpty == false else {
            workflowBlocker = "Choose a target workflow mode before transitioning."
            return
        }
        let sourceSequence = session.stateSequence ?? 0
        let generatedOperationID = operationID ?? Self.workflowTransitionOperationID()
        let generatedFingerprint = operationFingerprint ?? Self.workflowFingerprint(
            operationID: generatedOperationID,
            sourceSequence: sourceSequence,
            targetMode: targetMode,
            workflowID: session.workflowId ?? ""
        )
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        workflowRequestInFlight = true
        defer {
            controlRequestInFlight = false
            workflowRequestInFlight = false
        }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeWorkflowControl { await hook() }
            let envelope = try await bridge.transitionWorkflow(WorkflowTransitionParameters(
                operationId: generatedOperationID,
                operationFingerprint: generatedFingerprint,
                sourceStateSequence: sourceSequence,
                targetMode: targetMode,
                requestedAtUnix: Int(Date().timeIntervalSince1970)
            ))
            guard connectionIsCurrent(expectedGeneration) else { return }
            if let session = envelope.session {
                workflowSession = session
            }
            if let status = envelope.status {
                workflowStatus = status
            }
            if let result = envelope.result {
                workflowOperations.append(WorkflowOperationSnapshot(
                    operationId: result.operationId,
                    lifecycle: result.lifecycle,
                    reasonCode: result.reasonCode,
                    sourceMode: result.previousMode,
                    targetMode: result.desiredMode,
                    sourceStateSequence: sourceSequence,
                    targetStateSequence: result.leaseStateSequence,
                    operationFingerprint: generatedFingerprint
                ))
            }
            workflowRequestInFlight = false
            await observeWorkflow()
            workflowRequestInFlight = true
            workflowBlocker = nil
            if envelope.result?.lifecycle == "denied" {
                workflowBlocker = "The requested mode would expand the sealed workflow envelope and was denied."
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            workflowBlocker = error.localizedDescription
            if mutationMayBeUnconfirmed(error) {
                workflowRecoveryRequired = true
                workflowRequestInFlight = false
                await refreshWorkflowRecovery(connectionGeneration: expectedGeneration)
            } else {
                state = .blocked(error.localizedDescription)
            }
        }
    }

    func observeWorkflow() async {
        guard guardActionsAllowed() else { return }
        await performWorkflowRead { bridge in
            try await bridge.observeWorkflow()
        } onSuccess: { observation in
            if let session = observation.session { self.workflowSession = session }
            if let status = observation.status { self.workflowStatus = status }
            self.workflowBlocker = nil
            self.setReadyUnlessDefinitionBlocked()
        }
    }

    func cancelWorkflowTransition(operationID: String) async {
        guard controlRequestInFlight == false, guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        workflowRequestInFlight = true
        defer {
            controlRequestInFlight = false
            workflowRequestInFlight = false
        }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeWorkflowControl { await hook() }
            let envelope = try await bridge.cancelWorkflowTransition(operationID: operationID)
            guard connectionIsCurrent(expectedGeneration) else { return }
            if let session = envelope.session { workflowSession = session }
            workflowOperations.removeAll { $0.operationId == operationID }
            workflowBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            workflowBlocker = error.localizedDescription
            state = .blocked(error.localizedDescription)
        }
    }

    func refreshWorkflowStatus(connectionGeneration expectedGeneration: Int? = nil) async {
        let generation = expectedGeneration ?? connectionGeneration
        guard connectionIsCurrent(generation) else { return }
        await performWorkflowRead(
            { bridge in
                try await bridge.workflowStatus()
            },
            onSuccess: { status in
                let hydratedDefinitions = status.workflows
                    + (status.workflow.map { [ $0 ] } ?? [])
                if hydratedDefinitions.isEmpty == false {
                    var uniqueDefinitions = [WorkflowDraft]()
                    for definition in hydratedDefinitions where uniqueDefinitions.contains(where: {
                        $0.workflowId == definition.workflowId
                    }) == false {
                        uniqueDefinitions.append(definition)
                    }
                    self.workflowDefinitions = uniqueDefinitions
                    let selectedID = status.selectedWorkflowId
                        ?? status.status?.workflowId
                        ?? status.session?.workflowId
                    if let selectedID,
                       let selected = uniqueDefinitions.first(where: { $0.workflowId == selectedID }) {
                        self.workflowDraft = selected
                    } else if self.workflowDraft == nil, uniqueDefinitions.count == 1 {
                        self.workflowDraft = uniqueDefinitions[0]
                    }
                }
        self.workflowSession = status.session
                if let snapshot = status.status { self.workflowStatus = snapshot }
                self.workflowOperations = status.operations
                self.workflowRecoveryRequired = status.recoveryRequired == true
                self.workflowBlocker = self.workflowRecoveryRequired
                    ? "Workflow recovery is required before another transition."
                    : nil
                self.setReadyUnlessDefinitionBlocked()
            },
            connectionGeneration: generation
        )
    }

    func refreshWorkflowRecovery(connectionGeneration expectedGeneration: Int? = nil) async {
        guard workflowRequestInFlight == false else { return }
        let generation = expectedGeneration ?? connectionGeneration
        workflowRequestInFlight = true
        defer { workflowRequestInFlight = false }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeWorkflowRequest { await hook() }
            let recovery = try await bridge.workflowRecovery()
            guard connectionIsCurrent(generation) else { return }
            workflowRecovery = recovery
            workflowOperations = recovery.operations
            workflowRecoveryRequired = recovery.recoveryRequired == true
            if workflowRecoveryRequired == false { workflowBlocker = nil }
        } catch {
            guard connectionIsCurrent(generation) else { return }
            workflowRecoveryRequired = true
            workflowBlocker = "Workflow recovery evidence is unavailable. Reload the workspace before retrying."
        }
    }

    func refreshWorkflowRecovery() async {
        guard controlRequestInFlight == false else { return }
        let expectedGeneration = connectionGeneration
        await refreshWorkflowRecovery(connectionGeneration: expectedGeneration)
        guard connectionIsCurrent(expectedGeneration) else { return }
        if workflowRecoveryRequired {
            workflowBlocker = workflowRecovery?.message
                ?? "End the routed child session and relaunch it after inspecting recovery evidence."
            return
        }
        await refreshWorkflowStatus(connectionGeneration: expectedGeneration)
    }

    private func performWorkflowRead<Response: Decodable>(
        _ request: @escaping (BridgeClient) async throws -> Response,
        onSuccess: @escaping (Response) throws -> Void,
        connectionGeneration expectedGeneration: Int? = nil
    ) async {
        guard workflowRequestInFlight == false else { return }
        let generation = expectedGeneration ?? connectionGeneration
        workflowRequestInFlight = true
        defer { workflowRequestInFlight = false }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeWorkflowRequest { await hook() }
            let response = try await request(bridge)
            guard connectionIsCurrent(generation) else { return }
            try onSuccess(response)
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(generation) else { return }
            workflowBlocker = error.localizedDescription
            state = .blocked(error.localizedDescription)
        }
    }

    private static func workflowFingerprint(
        operationID: String,
        sourceSequence: UInt64,
        targetMode: String,
        workflowID: String
    ) -> String {
        let material = "unpin.desktop.workflow.transition.v1\u{0}\(operationID)\u{0}\(sourceSequence)\u{0}\(targetMode)\u{0}\(workflowID)"
        return SHA256.hash(data: Data(material.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func workflowTransitionOperationID() -> String {
        "workflow-transition-\(UUID().uuidString.lowercased())"
    }

    private static func normalizedWorkflowHostCommand(_ command: [String]) -> [String] {
        guard command.isEmpty == false,
              command.allSatisfy({
                  $0.isEmpty == false && $0.rangeOfCharacter(from: .controlCharacters) == nil
              }) else {
            return []
        }
        return command
    }

    func plan(group: GroupSummary, target: String) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        groupPlanRequestGeneration &+= 1
        let requestGeneration = groupPlanRequestGeneration
        await discardReviewedPlanContents()
        guard planRequestIsCurrent(requestGeneration, connectionGeneration: expectedGeneration) else { return }
        lastApply = nil
        lastChangeBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeGroupPlan {
                await hook()
            }
            let freshPlan = try await bridge.planGroup(name: group.qualifiedName, target: target).plan
            await awaitReadResponseHook()
            guard planRequestIsCurrent(requestGeneration, connectionGeneration: expectedGeneration) else { return }
            reviewedPlan = freshPlan
            approvedPlanFingerprint = nil
            lastChangeBlocker = nil
            lastApply = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            await awaitReadErrorHook()
            guard planRequestIsCurrent(requestGeneration, connectionGeneration: expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func approveReviewedPlan() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveGroup(operationID: operationID, fingerprint: plan.planFingerprint)
            guard connectionIsCurrent(expectedGeneration) else { return }
            approvedPlanFingerprint = plan.planFingerprint
            lastChangeBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyApprovedPlan() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedPlan, let operationID = plan.operationId,
                  approvedPlanFingerprint == plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            if let hook = testHooks.beforeGroupApply {
                await hook()
            }
            let result = try await bridge.applyGroup(operationID: operationID, fingerprint: plan.planFingerprint).result
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastApply = result
            self.reviewedPlan = nil
            approvedPlanFingerprint = nil
            do {
                try await refresh(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
            } catch {
                guard connectionIsCurrent(expectedGeneration) else { return }
                lastChangeBlocker = "The change completed, but its fresh observation could not be loaded. Reload the workspace or inspect Recover and Audit."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedPlan = nil
            approvedPlanFingerprint = nil
            guard mutationMayBeUnconfirmed(error) else {
                lastChangeBlocker = nil
                state = .blocked(error.localizedDescription)
                return
            }
            lastChangeBlocker = Self.mutationUncertaintyMessage
            mutationUncertaintyBlocker = Self.mutationUncertaintyMessage
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return }
            if recoveryRefreshed {
                state = .blocked(Self.mutationUncertaintyMessage)
            }
        }
    }

    func discardReviewedPlan() async {
        groupPlanRequestGeneration &+= 1
        await discardReviewedPlanContents()
    }

    private func discardReviewedPlanContents() async {
        let review = reviewedPlan
        reviewedPlan = nil
        approvedPlanFingerprint = nil
        lastChangeBlocker = nil
        guard let bridge, let operationID = review?.operationId,
              let fingerprint = review?.planFingerprint else { return }
        try? await bridge.discardGroup(operationID: operationID, fingerprint: fingerprint)
    }

    private func planRequestIsCurrent(_ requestGeneration: Int, connectionGeneration: Int) -> Bool {
        requestGeneration == groupPlanRequestGeneration
            && connectionIsCurrent(connectionGeneration)
    }

    func planAgentPlugin(
        _ package: AgentPluginSummary,
        target: String,
        reach: String,
        selectedProvider: String?
    ) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        agentPluginPlanRequestGeneration &+= 1
        let requestGeneration = agentPluginPlanRequestGeneration
        await discardReviewedAgentPluginContents()
        guard agentPluginPlanRequestIsCurrent(
            requestGeneration,
            connectionGeneration: expectedGeneration
        ) else { return }
        lastAgentPluginApply = nil
        lastAgentPluginBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            if let hook = testHooks.beforeAgentPluginPlan {
                await hook()
            }
            let freshPlan = try await bridge.planAgentPlugin(
                logicalID: package.logicalId,
                target: target,
                reach: reach,
                selectedProvider: selectedProvider
        ).plan
        await awaitReadResponseHook()
        guard agentPluginPlanRequestIsCurrent(
            requestGeneration,
            connectionGeneration: expectedGeneration
        ) else {
            try? await bridge.discardAgentPlugin(
                operationID: freshPlan.operationId,
                fingerprint: freshPlan.planFingerprint
            )
            return
        }
            reviewedAgentPlugin = freshPlan
            approvedAgentPluginFingerprint = nil
            lastAgentPluginBlocker = nil
            lastAgentPluginApply = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            await awaitReadErrorHook()
            guard agentPluginPlanRequestIsCurrent(
                requestGeneration,
                connectionGeneration: expectedGeneration
            ) else { return }
            lastAgentPluginBlocker = error.localizedDescription
            state = .blocked(error.localizedDescription)
        }
    }

    func approveReviewedAgentPlugin() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedAgentPlugin else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveAgentPlugin(
                operationID: plan.operationId,
                fingerprint: plan.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return }
            approvedAgentPluginFingerprint = plan.planFingerprint
            lastAgentPluginBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastAgentPluginBlocker = error.localizedDescription
            state = .blocked(error.localizedDescription)
        }
    }

    func applyApprovedAgentPlugin() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let plan = reviewedAgentPlugin,
                  approvedAgentPluginFingerprint == plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            if let hook = testHooks.beforeAgentPluginApply {
                await hook()
            }
            let result = try await bridge.applyAgentPlugin(
                operationID: plan.operationId,
                fingerprint: plan.planFingerprint
            ).result
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastAgentPluginApply = result
            reviewedAgentPlugin = nil
            approvedAgentPluginFingerprint = nil
            if result.lifecycle == "recovery-required" || result.counts.recoveryRequired > 0 {
                lastAgentPluginBlocker = Self.mutationUncertaintyMessage
                mutationUncertaintyBlocker = Self.mutationUncertaintyMessage
                let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(
                    connectionGeneration: expectedGeneration
                )
                guard connectionIsCurrent(expectedGeneration) else { return }
                if recoveryRefreshed {
                    state = .blocked(Self.mutationUncertaintyMessage)
                }
                return
            }
            do {
                try await refresh(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
            } catch {
                guard connectionIsCurrent(expectedGeneration) else { return }
                lastAgentPluginBlocker = "The package change completed, but its fresh observation could not be loaded. Reload the workspace or inspect Recover and Audit."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedAgentPlugin = nil
            approvedAgentPluginFingerprint = nil
            guard mutationMayBeUnconfirmed(error) else {
                lastAgentPluginBlocker = nil
                state = .blocked(error.localizedDescription)
                return
            }
            lastAgentPluginBlocker = Self.mutationUncertaintyMessage
            mutationUncertaintyBlocker = Self.mutationUncertaintyMessage
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(
                connectionGeneration: expectedGeneration
            )
            guard connectionIsCurrent(expectedGeneration) else { return }
            if recoveryRefreshed {
                state = .blocked(Self.mutationUncertaintyMessage)
            }
        }
    }

    func discardReviewedAgentPlugin() async {
        agentPluginPlanRequestGeneration &+= 1
        await discardReviewedAgentPluginContents()
    }

    private func discardReviewedAgentPluginContents() async {
        let review = reviewedAgentPlugin
        reviewedAgentPlugin = nil
        approvedAgentPluginFingerprint = nil
        lastAgentPluginBlocker = nil
        guard let bridge, let review else { return }
        try? await bridge.discardAgentPlugin(
            operationID: review.operationId,
            fingerprint: review.planFingerprint
        )
    }

    private func agentPluginPlanRequestIsCurrent(
        _ requestGeneration: Int,
        connectionGeneration: Int
    ) -> Bool {
        requestGeneration == agentPluginPlanRequestGeneration
            && connectionIsCurrent(connectionGeneration)
    }

    func planDefinition(_ parameters: GroupDefinitionPlanParameters) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        await discardReviewedDefinition()
        guard connectionIsCurrent(expectedGeneration) else { return }
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshDefinition = try await bridge.planDefinition(parameters)
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedDefinition = freshDefinition
            lastDefinitionBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyDefinition() async -> Bool {
        guard controlRequestInFlight == false else { return false }
        guard guardActionsAllowed() else { return false }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedDefinition else {
                throw BridgeClientError.malformedResponse
            }
            if let hook = testHooks.beforeDefinitionApply {
                await hook()
            }
            _ = try await bridge.applyDefinition(
                operationID: reviewedDefinition.operationId,
                fingerprint: reviewedDefinition.plan.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return false }
            self.reviewedDefinition = nil
            try await refresh(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return false }
            return true
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return false }
            self.reviewedDefinition = nil
            lastDefinitionBlocker = Self.definitionChangeUnconfirmedMessage
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(
                connectionGeneration: expectedGeneration
            )
            guard connectionIsCurrent(expectedGeneration) else { return false }
            if recoveryRefreshed {
                state = .blocked(error.localizedDescription)
            }
            return false
        }
    }

    func discardReviewedDefinition() async {
        let review = reviewedDefinition
        reviewedDefinition = nil
        guard let bridge, let review else { return }
        try? await bridge.discardDefinition(
            operationID: review.operationId,
            fingerprint: review.plan.planFingerprint
        )
    }

    func loadDefinitionHistory(scope: String) async {
        let expectedGeneration = connectionGeneration
        definitionHistory = []
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshHistory = try await bridge.definitionHistory(scope: scope).history
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            definitionHistory = freshHistory
            setReadyUnlessDefinitionBlocked()
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func planRestore(backupID: String) async {
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        await discardReviewedRestore()
        guard connectionIsCurrent(expectedGeneration) else { return }
        lastRestore = nil
        lastRestoreBlocker = nil
        do {
            guard let bridge else { throw BridgeClientError.childStopped }
            let freshRestore = try await bridge.planRestore(backupID: backupID)
            await awaitReadResponseHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedRestore = freshRestore
            approvedRestoreFingerprint = nil
            lastRestoreBlocker = nil
            lastRestore = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            await awaitReadErrorHook()
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func approveReviewedRestore() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedRestore else {
                throw BridgeClientError.malformedResponse
            }
            _ = try await bridge.approveRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            )
            guard connectionIsCurrent(expectedGeneration) else { return }
            approvedRestoreFingerprint = reviewedRestore.plan.planFingerprint
            lastRestoreBlocker = nil
            setReadyUnlessDefinitionBlocked()
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            state = .blocked(error.localizedDescription)
        }
    }

    func applyApprovedRestore() async {
        guard controlRequestInFlight == false else { return }
        guard guardActionsAllowed() else { return }
        let expectedGeneration = connectionGeneration
        controlRequestInFlight = true
        defer { controlRequestInFlight = false }
        do {
            guard let bridge, let reviewedRestore,
                  approvedRestoreFingerprint == reviewedRestore.plan.planFingerprint else {
                throw BridgeClientError.requestFailed("desktop-approval-required")
            }
            if let hook = testHooks.beforeRestoreApply {
                await hook()
            }
            let result = try await bridge.applyRestore(
                operationID: reviewedRestore.operationId,
                fingerprint: reviewedRestore.plan.planFingerprint
            ).result
            guard connectionIsCurrent(expectedGeneration) else { return }
            lastRestore = result
            self.reviewedRestore = nil
            approvedRestoreFingerprint = nil
            do {
                try await refresh(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
                await refreshRecovery(connectionGeneration: expectedGeneration)
                guard connectionIsCurrent(expectedGeneration) else { return }
            } catch {
                guard connectionIsCurrent(expectedGeneration) else { return }
                lastRestoreBlocker = "The restore completed, but its fresh observation could not be loaded. Reload the workspace before another change."
                state = .blocked(error.localizedDescription)
            }
        } catch {
            guard connectionIsCurrent(expectedGeneration) else { return }
            reviewedRestore = nil
            approvedRestoreFingerprint = nil
            guard mutationMayBeUnconfirmed(error) else {
                lastRestoreBlocker = nil
                state = .blocked(error.localizedDescription)
                return
            }
            lastRestoreBlocker = "Unpin did not confirm this restore. Inspect Recover and Audit or reload the workspace before trying another restore."
            mutationUncertaintyBlocker = Self.mutationUncertaintyMessage
            let recoveryRefreshed = await refreshRecoveryAfterUnconfirmedChange(connectionGeneration: expectedGeneration)
            guard connectionIsCurrent(expectedGeneration) else { return }
            if recoveryRefreshed {
                state = .blocked(Self.mutationUncertaintyMessage)
            }
        }
    }

    func discardReviewedRestore() async {
        let review = reviewedRestore
        reviewedRestore = nil
        approvedRestoreFingerprint = nil
        lastRestoreBlocker = nil
        guard let bridge, let review else { return }
        try? await bridge.discardRestore(
            operationID: review.operationId,
            fingerprint: review.plan.planFingerprint
        )
    }

    private func refreshRecoveryAfterUnconfirmedChange(connectionGeneration expectedGeneration: Int) async -> Bool {
        recoveryRequestGeneration &+= 1
        let requestGeneration = recoveryRequestGeneration
        recoveryRequestInFlight = true
        defer {
            if recoveryRequestGeneration == requestGeneration {
                recoveryRequestInFlight = false
            }
        }
        do {
            guard let bridge else {
                guard recoveryRequestIsCurrent(
                    requestGeneration,
                    connectionGeneration: expectedGeneration
                ) else { return false }
                setRecoveryUnavailable()
                return false
            }
            if let hook = testHooks.beforeRecoveryRefresh {
                await hook()
            }
            let freshRecovery = try await bridge.recoverySnapshot()
            guard recoveryRequestIsCurrent(
                requestGeneration,
                connectionGeneration: expectedGeneration
            ) else { return false }
            recovery = freshRecovery
            recoveryBlocker = nil
            return true
        } catch {
            guard recoveryRequestIsCurrent(
                requestGeneration,
                connectionGeneration: expectedGeneration
            ) else { return false }
            setRecoveryUnavailable()
            return false
        }
    }

    private func recoveryRequestIsCurrent(
        _ requestGeneration: Int,
        connectionGeneration: Int
    ) -> Bool {
        self.recoveryRequestGeneration == requestGeneration
            && connectionIsCurrent(connectionGeneration)
    }

    private func mutationMayBeUnconfirmed(_ error: Error) -> Bool {
        guard let bridgeError = error as? BridgeClientError else { return true }
        if case let .requestFailed(code) = bridgeError {
            return code == "agent-plugin-recovery-required"
        }
        return true
    }

    private func guardActionsAllowed() -> Bool {
        guard actionsBlocked == false else {
            state = .blocked(
                mutationUncertaintyBlocker
                    ?? recoveryBlocker
                    ?? Self.recoveryUnavailableMessage
            )
            return false
        }
        return true
    }

    private func setReadyUnlessDefinitionBlocked() {
        guard lastDefinitionBlocker == nil, actionsBlocked == false else { return }
        state = .ready
    }

    private func setRecoveryUnavailable(message: String? = nil) {
        recoveryBlocker = Self.recoveryUnavailableMessage
        state = .blocked(message ?? Self.recoveryUnavailableMessage)
    }

    func stopBridgeForTesting() async {
        _ = await bridge?.stop()
    }

    private static func bundledBridge() throws -> (executable: URL, manifest: BundledBridgeManifest) {
        let executable = Bundle.main.bundleURL
            .appendingPathComponent("Contents")
            .appendingPathComponent("MacOS")
            .appendingPathComponent("unpin")
        guard FileManager.default.fileExists(atPath: executable.path) else {
            throw BridgeClientError.bundledExecutableMissing
        }
        guard let manifestURL = Bundle.main.url(
            forResource: "unpin-bridge-manifest",
            withExtension: "json"
        ) else {
            throw BridgeClientError.bundledManifestInvalid
        }
        do {
            return (executable, try JSONDecoder().decode(
                BundledBridgeManifest.self,
                from: Data(contentsOf: manifestURL)
            ))
        } catch {
            throw BridgeClientError.bundledManifestInvalid
        }
    }
}
