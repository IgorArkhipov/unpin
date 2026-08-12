import Foundation
import SwiftUI

enum InventorySortColumn: String, CaseIterable, Identifiable {
    case name
    case provider
    case type
    case state
    case access

    var id: String { rawValue }

    var title: String {
        switch self {
        case .name: "Name"
        case .provider: "Provider"
        case .type: "Type"
        case .state: "State"
        case .access: "Access"
        }
    }
}

enum InventorySortDirection: Equatable {
    case ascending
    case descending

    var title: String {
        switch self {
        case .ascending: "Ascending"
        case .descending: "Descending"
        }
    }

    var systemImage: String {
        switch self {
        case .ascending: "arrow.up"
        case .descending: "arrow.down"
        }
    }

}

struct InventorySortDescriptor: Equatable, Identifiable {
    let column: InventorySortColumn
    var direction: InventorySortDirection

    var id: InventorySortColumn { column }
}

struct InventorySortState {
    private(set) var descriptors = [
        InventorySortDescriptor(column: .name, direction: .ascending),
    ]

    mutating func add(_ column: InventorySortColumn) {
        guard descriptors.contains(where: { $0.column == column }) == false else { return }
        descriptors.append(InventorySortDescriptor(column: column, direction: .ascending))
    }

    mutating func setDirection(
        _ direction: InventorySortDirection,
        for column: InventorySortColumn
    ) {
        guard let index = descriptors.firstIndex(where: { $0.column == column }) else { return }
        descriptors[index].direction = direction
    }

    mutating func move(_ column: InventorySortColumn, towardStart: Bool) {
        guard let index = descriptors.firstIndex(where: { $0.column == column }) else { return }
        let destination = towardStart ? index - 1 : index + 1
        guard descriptors.indices.contains(destination) else { return }
        descriptors.swapAt(index, destination)
    }

    mutating func remove(_ column: InventorySortColumn) {
        descriptors.removeAll { $0.column == column }
    }

    mutating func replace(with comparators: [KeyPathComparator<InventoryItem>]) {
        descriptors = comparators.compactMap { comparator in
            guard let column = InventorySortColumn(keyPath: comparator.keyPath) else { return nil }
            return InventorySortDescriptor(
                column: column,
                direction: comparator.order == .forward ? .ascending : .descending
            )
        }
    }

    func descriptor(for column: InventorySortColumn) -> InventorySortDescriptor? {
        descriptors.first { $0.column == column }
    }

    var comparators: [KeyPathComparator<InventoryItem>] {
        descriptors.map { descriptor in
            let order: SortOrder = descriptor.direction == .ascending ? .forward : .reverse
            switch descriptor.column {
            case .name:
                return KeyPathComparator(\InventoryItem.displayName, order: order)
            case .provider:
                return KeyPathComparator(\InventoryItem.provider, order: order)
            case .type:
                return KeyPathComparator(\InventoryItem.typeSortValue, order: order)
            case .state:
                return KeyPathComparator(\InventoryItem.stateSortValue, order: order)
            case .access:
                return KeyPathComparator(\InventoryItem.mutability, order: order)
            }
        }
    }

    func sorted(_ items: [InventoryItem]) -> [InventoryItem] {
        items.sorted { left, right in
            for descriptor in descriptors {
                let comparison = compare(left, right, by: descriptor.column)
                guard comparison != .orderedSame else { continue }
                return descriptor.direction == .ascending
                    ? comparison == .orderedAscending
                    : comparison == .orderedDescending
            }

            return fallbackKey(left).localizedCaseInsensitiveCompare(fallbackKey(right))
                == .orderedAscending
        }
    }

    private func compare(
        _ left: InventoryItem,
        _ right: InventoryItem,
        by column: InventorySortColumn
    ) -> ComparisonResult {
        switch column {
        case .name:
            left.displayName.localizedCaseInsensitiveCompare(right.displayName)
        case .provider:
            left.provider.localizedCaseInsensitiveCompare(right.provider)
        case .type:
            "\(left.category)\u{0}\(left.layer)"
                .localizedCaseInsensitiveCompare("\(right.category)\u{0}\(right.layer)")
        case .state:
            left.enabled == right.enabled
                ? .orderedSame
                : (left.enabled ? .orderedDescending : .orderedAscending)
        case .access:
            left.mutability.localizedCaseInsensitiveCompare(right.mutability)
        }
    }

    private func fallbackKey(_ item: InventoryItem) -> String {
        "\(item.provider)\u{0}\(item.category)\u{0}\(item.layer)\u{0}\(item.id)"
    }
}

private extension InventorySortColumn {
    init?(keyPath: PartialKeyPath<InventoryItem>) {
        switch keyPath {
        case \InventoryItem.displayName: self = .name
        case \InventoryItem.provider: self = .provider
        case \InventoryItem.typeSortValue: self = .type
        case \InventoryItem.stateSortValue: self = .state
        case \InventoryItem.mutability: self = .access
        default: return nil
        }
    }
}

private extension InventoryItem {
    var typeSortValue: String { "\(category)\u{0}\(layer)" }
    var stateSortValue: Int { enabled ? 1 : 0 }
}

struct InventoryFilterRevision: Equatable {
    let providers: [String]
    let layers: [String]
    let categories: [String]

    init(inventory: [InventoryItem]) {
        let facets = InventoryFacets(inventory: inventory)
        providers = facets.providers
        layers = facets.layers
        categories = facets.categories
    }
}

struct InventoryFacetSelection: Equatable {
    var provider: String = "all"
    var layer: String = "all"
    var category: String = "all"
}

struct DiscoverFilterState: Equatable {
    var search = ""
    var provider = "all"
    var layer = "all"
    var category = "all"
    var state = "all"

    var isActive: Bool {
        !search.isEmpty
            || provider != "all"
            || layer != "all"
            || category != "all"
            || state != "all"
    }

    func matches(_ item: InventoryItem) -> Bool {
        matchesInventoryFilter(
            item,
            search: search,
            provider: provider,
            layer: layer,
            category: category,
            state: state
        )
    }

    mutating func clear() {
        self = Self()
    }
}

enum DiscoverPresentationState: Equatable {
    case needsWorkspace
    case loading
    case blocked(String)
    case emptyInventory
    case filterZero
    case ready
}

func classifyDiscoverPresentation(
    presentation: WorkbenchPresentationInputs,
    inventory: [InventoryItem],
    filters: DiscoverFilterState,
    matchingInventory: [InventoryItem]
) -> DiscoverPresentationState {
    switch presentation.state {
    case .needsWorkspace:
        return .needsWorkspace
    case .loading:
        return .loading
    case .blocked(let message):
        return .blocked(message)
    case .ready:
        guard !inventory.isEmpty else { return .emptyInventory }
        if filters.isActive, matchingInventory.isEmpty {
            return .filterZero
        }
        return .ready
    }
}

enum WorkbenchFilterAccessibility {
    static let provider = "Provider"
    static let layer = "Layer"
    static let category = "Category"
    static let state = "State"
    static let membership = "Membership"

    static let discoverLabels = [provider, layer, category, state]
    static let groupLabels = [provider, layer, category, state, membership]

    static func label(for title: String) -> String { title }
}

func normalizedInventoryFacetSelection(
    _ selection: InventoryFacetSelection,
    facets: InventoryFacets
) -> InventoryFacetSelection {
    InventoryFacetSelection(
        provider: selection.provider == "all" || facets.providers.contains(selection.provider)
            ? selection.provider
            : "all",
        layer: selection.layer == "all" || facets.layers.contains(selection.layer)
            ? selection.layer
            : "all",
        category: selection.category == "all" || facets.categories.contains(selection.category)
            ? selection.category
            : "all"
    )
}

enum DiscoverInventoryMode: String, CaseIterable, Identifiable {
    case inventory = "Inventory"
    case packages = "Packages"

    var id: String { rawValue }
}

struct AgentPluginFacets {
    let providers: [String]
    let types: [String]
    let states: [String]
    let access: [String]

    init(packages: [AgentPluginSummary]) {
        providers = Set(packages.flatMap(\.providers)).sorted()
        types = Set(packages.flatMap(\.componentKinds)).sorted()
        states = Set(packages.map(\.state)).sorted()
        access = Set(packages.map(\.access)).sorted()
    }
}

struct AgentPluginFilterState: Equatable {
    var search = ""
    var provider = "all"
    var type = "all"
    var state = "all"
    var access = "all"

    var isActive: Bool {
        !search.isEmpty || provider != "all" || type != "all" || state != "all" || access != "all"
    }

    func matches(_ package: AgentPluginSummary) -> Bool {
        (provider == "all" || package.providers.contains(provider))
            && (type == "all" || package.componentKinds.contains(type))
            && (state == "all" || package.state == state)
            && (access == "all" || package.access == access)
            && (
                search.isEmpty
                    || package.name.localizedCaseInsensitiveContains(search)
                    || package.logicalId.localizedCaseInsensitiveContains(search)
            )
    }

    mutating func clear() { self = Self() }
}

struct AgentPluginSortState {
    private(set) var descriptors = [
        InventorySortDescriptor(column: .name, direction: .ascending),
    ]

    mutating func add(_ column: InventorySortColumn) {
        guard descriptors.contains(where: { $0.column == column }) == false else { return }
        descriptors.append(InventorySortDescriptor(column: column, direction: .ascending))
    }

    mutating func setDirection(
        _ direction: InventorySortDirection,
        for column: InventorySortColumn
    ) {
        guard let index = descriptors.firstIndex(where: { $0.column == column }) else { return }
        descriptors[index].direction = direction
    }

    mutating func remove(_ column: InventorySortColumn) {
        descriptors.removeAll { $0.column == column }
    }

    func descriptor(for column: InventorySortColumn) -> InventorySortDescriptor? {
        descriptors.first { $0.column == column }
    }

    func sorted(_ packages: [AgentPluginSummary]) -> [AgentPluginSummary] {
        packages.sorted { left, right in
            for descriptor in descriptors {
                let comparison: ComparisonResult = switch descriptor.column {
                case .name:
                    left.name.localizedCaseInsensitiveCompare(right.name)
                case .provider:
                    left.providerDisplay.localizedCaseInsensitiveCompare(right.providerDisplay)
                case .type:
                    left.typeDisplay.localizedCaseInsensitiveCompare(right.typeDisplay)
                case .state:
                    left.state.localizedCaseInsensitiveCompare(right.state)
                case .access:
                    left.access.localizedCaseInsensitiveCompare(right.access)
                }
                guard comparison != .orderedSame else { continue }
                return descriptor.direction == .ascending
                    ? comparison == .orderedAscending
                    : comparison == .orderedDescending
            }
            return left.logicalId.localizedCaseInsensitiveCompare(right.logicalId) == .orderedAscending
        }
    }
}

struct AgentPluginDetailsSheet: View {
    let package: AgentPluginSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(package.name)
                .font(.title2)
            Text("\(package.state.capitalized) · \(package.access.replacingOccurrences(of: "-", with: " ")) · \(package.instanceCount) instance(s)")
                .foregroundStyle(.secondary)

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(package.instances) { instance in
                        VStack(alignment: .leading, spacing: 8) {
                            Text("\(instance.provider) \(instance.layer) · \(instance.state) · \(instance.access)")
                                .font(.headline)

                            if instance.components.isEmpty {
                                Text("No declared package components were readable.")
                                    .foregroundStyle(.secondary)
                            } else {
                                ForEach(instance.components) { component in
                                    Label {
                                        Text(componentDetail(component))
                                    } icon: {
                                        Image(systemName: component.disposition == "available" ? "checkmark.circle" : "exclamationmark.triangle")
                                    }
                                }
                            }

                            ForEach(instance.blockers, id: \.self) { blocker in
                                Label(blocker, systemImage: "hand.raised")
                                    .foregroundStyle(.orange)
                            }
                            ForEach(instance.diagnostics, id: \.self) { diagnostic in
                                Label(diagnostic, systemImage: "stethoscope")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
            }
        }
        .padding()
        .frame(minWidth: 560, minHeight: 420)
    }

    private func componentDetail(_ component: AgentPluginComponent) -> String {
        let status = component.disposition.replacingOccurrences(of: "-", with: " ")
        let reason = component.reason.map { ": \($0)" } ?? ""
        return "\(component.kind) · \(component.name) · \(status)\(reason)"
    }
}

struct DiscoverOrganizeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.workbenchPresentation) private var presentation
    @Environment(\.workbenchChooseWorkspace) private var chooseWorkspace
    @Environment(\.workbenchCreateGroup) private var createGroup
    let inventoryOverride: [InventoryItem]?
    let packagesOverride: [AgentPluginSummary]?
    @State private var filters = DiscoverFilterState()
    @State private var sort = InventorySortState()
    @State private var inventoryMode = DiscoverInventoryMode.inventory
    @State private var packageFilters = AgentPluginFilterState()
    @State private var packageSort = AgentPluginSortState()
    @State private var editingGroup: GroupSummary?
    @State private var inspectedPackage: AgentPluginSummary?

    init(
        inventoryOverride: [InventoryItem]? = nil,
        filtersOverride: DiscoverFilterState? = nil,
        packagesOverride: [AgentPluginSummary]? = nil,
        modeOverride: DiscoverInventoryMode? = nil
    ) {
        self.inventoryOverride = inventoryOverride
        self.packagesOverride = packagesOverride
        _filters = State(initialValue: filtersOverride ?? DiscoverFilterState())
        _inventoryMode = State(initialValue: modeOverride ?? .inventory)
    }

    var body: some View {
        let inventory = inventoryOverride ?? workspace.snapshot?.inventory ?? []
        let packages = packagesOverride ?? workspace.snapshot?.agentPlugins ?? []
        let filterRevision = InventoryFilterRevision(inventory: inventory)
        let matchingInventory: [InventoryItem] = {
            guard case .ready = presentation.state else { return [] }
            return inventory.filter(filters.matches)
        }()
        VStack(spacing: 0) {
            Picker("Inventory mode", selection: $inventoryMode) {
                ForEach(DiscoverInventoryMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 320)
            .padding(.top)

            if inventoryMode == .packages {
                packagePresentation(packages)
            } else {
                Group {
                    switch classifyDiscoverPresentation(
                presentation: presentation,
                inventory: inventory,
                filters: filters,
                matchingInventory: matchingInventory
                    ) {
            case .needsWorkspace:
                WorkbenchWorkspaceStateView(
                    title: "Choose a workspace",
                    message: "Select a repository or project before reviewing discovered inventory.",
                    actionTitle: chooseWorkspace == nil ? nil : "Choose workspace",
                    action: chooseWorkspace
                )
            case .loading:
                WorkbenchWorkspaceStateView(
                    title: "Loading workspace inventory",
                    message: "Unpin is connecting to the bundled bridge and refreshing discovery evidence.",
                    actionTitle: nil,
                    action: nil
                )
            case .blocked(let message):
                WorkbenchWorkspaceStateView(
                    title: "Workspace inventory is unavailable",
                    message: message,
                    actionTitle: "Retry",
                    action: { Task { await workspace.reloadWorkspace() } }
                )
            case .emptyInventory:
                WorkbenchWorkspaceStateView(
                    title: "No supported inventory found",
                    message: "Discovery completed without supported skills, MCP servers, instructions, or hooks. Reload the selected workspace or review its status below for diagnostics.",
                    actionTitle: "Reload discovery",
                    action: { Task { await workspace.reloadWorkspace() } }
                )
            case .filterZero:
                WorkbenchWorkspaceStateView(
                    title: "No inventory matches these filters",
                    message: "The workspace has discovered inventory, but the current search and filters exclude every item.",
                    actionTitle: "Clear filters",
                    action: clearFilters
                )
            case .ready:
                inventoryContent(inventory, matchingInventory: matchingInventory)
                    }
                }
            }
        }
        .onChange(of: filterRevision) { _, _ in
            normalizeInventoryFilters(inventory)
        }
    }

    @ViewBuilder
    private func packagePresentation(_ packages: [AgentPluginSummary]) -> some View {
        let matching = packages.filter(packageFilters.matches)
        switch presentation.state {
        case .needsWorkspace:
            WorkbenchWorkspaceStateView(
                title: "Choose a workspace",
                message: "Select a repository or project before deriving Agent Plugin packages.",
                actionTitle: chooseWorkspace == nil ? nil : "Choose workspace",
                action: chooseWorkspace
            )
        case .loading:
            WorkbenchWorkspaceStateView(
                title: "Loading derived packages",
                message: "Packages are recomputed from fresh discovery on every scan.",
                actionTitle: nil,
                action: nil
            )
        case .blocked(let message):
            WorkbenchWorkspaceStateView(
                title: "Package refresh failed",
                message: message,
                actionTitle: "Retry",
                action: { Task { await workspace.reloadWorkspace() } }
            )
        case .ready where workspace.snapshot?.agentPluginInventoryComplete == false:
            WorkbenchWorkspaceStateView(
                title: "Agent Plugin inventory is incomplete",
                message: "Unpin could not safely enumerate every installed package. Reload discovery after resolving the reported cache diagnostics before reviewing package changes.",
                actionTitle: "Reload discovery",
                action: { Task { await workspace.reloadWorkspace() } }
            )
        case .ready where packages.isEmpty:
            WorkbenchWorkspaceStateView(
                title: "No Agent Plugin packages derived",
                message: "Skills and MCP manifests describe package coverage; Unpin never synthesizes component rows or installs package contents.",
                actionTitle: "Reload discovery",
                action: { Task { await workspace.reloadWorkspace() } }
            )
        case .ready where packageFilters.isActive && matching.isEmpty:
            WorkbenchWorkspaceStateView(
                title: "No packages match these filters",
                message: "Visibility filters do not change selected-provider or all-provider operation reach.",
                actionTitle: "Clear package filters",
                action: { packageFilters.clear() }
            )
        case .ready:
            packageContent(packages, matchingPackages: matching)
        }
    }

    private func inventoryContent(
        _ inventory: [InventoryItem],
        matchingInventory: [InventoryItem]
    ) -> some View {
        let facets = InventoryFacets(inventory: inventory)
        let palette = WorkbenchPalette.resolve(for: colorScheme)
        let items = sort.sorted(matchingInventory)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Text("Discover and Organize").font(.title2)
                Spacer()
                Menu("Groups") {
                    ForEach(workspace.snapshot?.groups ?? []) { group in
                        Button(group.qualifiedName) { editingGroup = group }
                    }
                }
                .disabled(workspace.mutationsBlocked)
                Button("New group") { createGroup?() }
                    .disabled(createGroup == nil || workspace.mutationsBlocked)
                Button("Reload") { Task { await workspace.reloadWorkspace() } }
                    .disabled(workspace.isBusy)
            }

            VStack(alignment: .leading, spacing: 8) {
                TextField("Search inventory", text: $filters.search)
                    .frame(maxWidth: .infinity)

                HStack(alignment: .bottom, spacing: 12) {
                    filter("Provider", selection: $filters.provider, values: facets.providers)
                    filter("Layer", selection: $filters.layer, values: facets.layers)
                    filter("Category", selection: $filters.category, values: facets.categories)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("State")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Picker("State", selection: $filters.state) {
                            Text("Any state").tag("all")
                            Text("On").tag("on")
                            Text("Off").tag("off")
                        }
                        .accessibilityLabel(WorkbenchFilterAccessibility.state)
                        .labelsHidden()
                        .frame(minWidth: 170, maxWidth: .infinity)
                    }
                    .frame(minWidth: 170, maxWidth: .infinity, alignment: .leading)
                }
            }

            if let snapshot = workspace.snapshot,
               !snapshot.warnings.isEmpty || !snapshot.groupWarnings.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Label("Some discovery or group evidence is incomplete.", systemImage: "exclamationmark.triangle")
                    if !snapshot.groupWarnings.isEmpty {
                        Text(snapshot.groupWarnings.map { "\($0.scope): \($0.code)" }.joined(separator: " · "))
                            .font(.caption)
                    }
                }
                .foregroundStyle(.orange)
            }

            sortControls

            Table(items, sortOrder: tableSortOrder) {
                TableColumn("Name", value: \.displayName) {
                    Text($0.displayName)
                }
                TableColumn("Provider", value: \.provider) {
                    Text($0.provider)
                }
                TableColumn("Type", value: \.typeSortValue) {
                    Text("\($0.category) · \($0.layer)")
                }
                TableColumn("State", value: \.stateSortValue) {
                    Text($0.enabled ? "On" : "Off")
                }
                TableColumn("Access", value: \.mutability) {
                    Text($0.mutability)
                }
            }
            .scrollContentBackground(.hidden)
            .background(palette.table)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(palette.border, lineWidth: 1)
            }
            .overlay {
                if items.isEmpty {
                    ContentUnavailableView("No matching inventory", systemImage: "magnifyingglass")
                }
            }
        }
        .padding()
        .sheet(item: $editingGroup) { group in
            GroupEditorView(group: group)
        }
        .sheet(item: $inspectedPackage) { package in
            AgentPluginDetailsSheet(package: package)
        }
    }

    private func packageContent(
        _ packages: [AgentPluginSummary],
        matchingPackages: [AgentPluginSummary]
    ) -> some View {
        let facets = AgentPluginFacets(packages: packages)
        let palette = WorkbenchPalette.resolve(for: colorScheme)
        let visiblePackages = packageSort.sorted(matchingPackages)
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Derived Agent Plugin packages").font(.title2)
                    Text("Packages are recomputed from discovery. Groups are Unpin-owned reusable selections; packages are not a registry or installation state.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Reload") { Task { await workspace.reloadWorkspace() } }
                    .disabled(workspace.isBusy)
            }

            VStack(alignment: .leading, spacing: 8) {
                TextField("Search packages", text: $packageFilters.search)
                    .frame(maxWidth: .infinity)
                HStack(alignment: .bottom, spacing: 12) {
                    packageFilter("Provider", selection: $packageFilters.provider, values: facets.providers)
                    packageFilter("Type", selection: $packageFilters.type, values: facets.types)
                    packageFilter("State", selection: $packageFilters.state, values: facets.states)
                    packageFilter("Access", selection: $packageFilters.access, values: facets.access)
                }
            }

            Label(
                "Selected-provider and all-provider reach are chosen in each review menu and never inferred from these visibility filters.",
                systemImage: "scope"
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            if packages.allSatisfy({ $0.access != "actionable" }) {
                Label(
                    "These packages are diagnostics only. Their coverage can be inspected, but no native activation anchor can be changed safely.",
                    systemImage: "stethoscope"
                )
                .foregroundStyle(.secondary)
            }

            if let blocker = workspace.lastAgentPluginBlocker {
                Label(blocker, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }

            packageSortControls

            if let plan = workspace.reviewedAgentPlugin {
                PlanReviewView(agentPluginPlan: plan)
            }

            Table(visiblePackages) {
                TableColumn("Name") { package in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(package.name)
                        Text("\(package.instanceCount) instance(s)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                TableColumn("Provider") { package in
                    Text(package.providerDisplay)
                }
                TableColumn("Type") { package in
                    Text(package.typeDisplay.isEmpty ? "manifest only" : package.typeDisplay)
                }
                TableColumn("State") { package in
                    packageStateLabel(package.state)
                }
        TableColumn("Access") { package in
            packageAccessLabel(package.access)
        }
        TableColumn("Details") { package in
            Button("Details") {
                inspectedPackage = package
            }
            .accessibilityLabel("Inspect \(package.name) package diagnostics")
        }
        TableColumn("Review") { package in
            packageReviewMenu(package)
                }
            }
            .scrollContentBackground(.hidden)
            .background(palette.table)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(palette.border, lineWidth: 1)
            }

            if let result = workspace.lastAgentPluginApply {
                Label(
                    "Package change \(result.lifecycle): \(result.counts.applied) applied, \(result.counts.noOp) already matched, \(result.counts.blocked) blocked.",
                    systemImage: result.counts.recoveryRequired > 0
                        ? "exclamationmark.arrow.triangle.2.circlepath"
                        : "checkmark.circle"
                )
                .font(.callout)
            }
        }
        .padding()
    }

    private var packageSortControls: some View {
        HStack(spacing: 8) {
            Text("Sort packages by")
                .font(.caption)
                .foregroundStyle(.secondary)
            ForEach(packageSort.descriptors) { descriptor in
                Menu {
                    Button("Ascending") {
                        packageSort.setDirection(.ascending, for: descriptor.column)
                    }
                    Button("Descending") {
                        packageSort.setDirection(.descending, for: descriptor.column)
                    }
                    Divider()
                    Button("Remove") { packageSort.remove(descriptor.column) }
                } label: {
                    Label(descriptor.column.title, systemImage: descriptor.direction.systemImage)
                }
            }
            Menu {
                ForEach(InventorySortColumn.allCases) { column in
                    Button(column.title) { packageSort.add(column) }
                        .disabled(packageSort.descriptor(for: column) != nil)
                }
            } label: {
                Label("Add sort", systemImage: "plus")
            }
            Spacer()
        }
    }

    private func packageReviewMenu(_ package: AgentPluginSummary) -> some View {
        Menu("Review") {
            ForEach(["on", "off"], id: \.self) { target in
                Menu(target == "on" ? "Turn on" : "Turn off") {
                    Section("Selected provider reach") {
                        ForEach(package.providers, id: \.self) { provider in
                            Button(provider) {
                                Task {
                                    await workspace.planAgentPlugin(
                                        package,
                                        target: target,
                                        reach: "selected",
                                        selectedProvider: provider
                                    )
                                }
                            }
                        }
                    }
                    Section("All provider reach") {
                        Button("Every provider instance") {
                            Task {
                                await workspace.planAgentPlugin(
                                    package,
                                    target: target,
                                    reach: "all",
                                    selectedProvider: nil
                                )
                            }
                        }
                    }
                }
            }
        }
        .disabled(
            package.access != "actionable"
                || workspace.snapshot?.agentPluginInventoryComplete != true
                || workspace.mutationsBlocked
        )
    }

    private func packageStateLabel(_ state: String) -> some View {
        let icon = switch state {
        case "on": "checkmark.circle"
        case "off": "circle"
        case "mixed", "partial": "circle.lefthalf.filled"
        case "blocked": "exclamationmark.octagon"
        default: "questionmark.circle"
        }
        return Label(state.capitalized, systemImage: icon)
    }

    private func packageAccessLabel(_ access: String) -> some View {
        switch access {
        case "actionable":
            Label("Actionable", systemImage: "pencil.and.list.clipboard")
        case "diagnostics-only":
            Label("Diagnostics only", systemImage: "stethoscope")
        case "unsupported":
            Label("Unsupported", systemImage: "nosign")
        default:
            Label("Unknown", systemImage: "questionmark.circle")
        }
    }

    private func packageFilter(
        _ title: String,
        selection: Binding<String>,
        values: [String]
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            Picker(title, selection: selection) {
                Text("All \(title.lowercased())").tag("all")
                ForEach(values, id: \.self) { Text($0).tag($0) }
            }
            .labelsHidden()
            .accessibilityLabel(title)
            .frame(maxWidth: .infinity)
        }
        .frame(minWidth: 140, maxWidth: .infinity, alignment: .leading)
    }

    private func clearFilters() {
        filters.clear()
    }

    private var sortControls: some View {
        let palette = WorkbenchPalette.resolve(for: colorScheme)

        return HStack(spacing: 8) {
            Text("Sort by")
                .font(.caption)
                .foregroundStyle(.secondary)

            ForEach(Array(sort.descriptors.enumerated()), id: \.element.id) { index, descriptor in
                Menu {
                    Button("Ascending") {
                        sort.setDirection(.ascending, for: descriptor.column)
                    }
                    Button("Descending") {
                        sort.setDirection(.descending, for: descriptor.column)
                    }
                    Divider()
                    Button("Move earlier") {
                        sort.move(descriptor.column, towardStart: true)
                    }
                    .disabled(index == 0)
                    Button("Move later") {
                        sort.move(descriptor.column, towardStart: false)
                    }
                    .disabled(index == sort.descriptors.count - 1)
                    Divider()
                    Button("Remove") {
                        sort.remove(descriptor.column)
                    }
                } label: {
                    Label(
                        "\(index + 1) \(descriptor.column.title)",
                        systemImage: descriptor.direction.systemImage
                    )
                }
                .tint(palette.green)
                .help("Sort priority \(index + 1): \(descriptor.column.title), \(descriptor.direction.title.lowercased())")
            }

            Menu {
                ForEach(InventorySortColumn.allCases) { column in
                    Button(column.title) { sort.add(column) }
                        .disabled(sort.descriptor(for: column) != nil)
                }
            } label: {
                Label("Add sort", systemImage: "plus")
            }

            Spacer()
        }
    }

    private var tableSortOrder: Binding<[KeyPathComparator<InventoryItem>]> {
        Binding(
            get: { sort.comparators },
            set: { sort.replace(with: $0) }
        )
    }

    private func normalizeInventoryFilters(_ inventory: [InventoryItem]) {
        let normalized = normalizedInventoryFacetSelection(
            InventoryFacetSelection(
                provider: filters.provider,
                layer: filters.layer,
                category: filters.category
            ),
            facets: InventoryFacets(inventory: inventory)
        )
        var normalizedFilters = filters
        normalizedFilters.provider = normalized.provider
        normalizedFilters.layer = normalized.layer
        normalizedFilters.category = normalized.category
        guard normalizedFilters != filters else { return }
        filters = normalizedFilters
    }

    private func filter(
        _ title: String,
        selection: Binding<String>,
        values: [String]
    ) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Picker(title, selection: selection) {
                Text("All \(title.lowercased())").tag("all")
                ForEach(values, id: \.self) { Text($0).tag($0) }
            }
            .accessibilityLabel(WorkbenchFilterAccessibility.label(for: title))
            .labelsHidden()
            .frame(minWidth: 170, maxWidth: .infinity)
        }
        .frame(minWidth: 170, maxWidth: .infinity, alignment: .leading)
    }
}
