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
        && (search.isEmpty
            || item.displayName.localizedCaseInsensitiveContains(search)
            || item.id.localizedCaseInsensitiveContains(search))
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
    matchingInventory: [InventoryItem]? = nil
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
        if filters.isActive, (matchingInventory ?? inventory.filter(filters.matches)).isEmpty {
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

struct DiscoverOrganizeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.workbenchPresentation) private var presentation
    @Environment(\.workbenchChooseWorkspace) private var chooseWorkspace
    @Environment(\.workbenchCreateGroup) private var createGroup
    let inventoryOverride: [InventoryItem]?
    @State private var filters = DiscoverFilterState()
    @State private var sort = InventorySortState()
    @State private var editingGroup: GroupSummary?

    init(inventoryOverride: [InventoryItem]? = nil) {
        self.inventoryOverride = inventoryOverride
    }

    var body: some View {
        let inventory = inventoryOverride ?? workspace.snapshot?.inventory ?? []
        let matchingInventory = inventory.filter(filters.matches)
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

    private func inventoryContent(
        _ inventory: [InventoryItem],
        matchingInventory: [InventoryItem]
    ) -> some View {
        let facets = InventoryFacets(inventory: inventory)
        let filterRevision = InventoryFilterRevision(inventory: inventory)
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
        .onChange(of: filterRevision) { _, _ in
            normalizeInventoryFilters(inventory)
        }
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
        filters.provider = normalized.provider
        filters.layer = normalized.layer
        filters.category = normalized.category
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
