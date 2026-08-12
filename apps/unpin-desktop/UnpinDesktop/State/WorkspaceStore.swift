import Combine
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
        recoveryBlocker != nil || mutationUncertaintyBlocker != nil
    }

    var mutationsBlocked: Bool {
        isBusy || actionsBlocked
    }

    var isBusy: Bool {
        if case .loading = state { return true }
        return controlRequestInFlight || recoveryRequestInFlight
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
