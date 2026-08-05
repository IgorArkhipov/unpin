import SwiftUI

struct GroupMemberFilterState: Equatable {
    var search = ""
    var provider = "all"
    var layer = "all"
    var category = "all"
    var state = "all"
    var membership = "all"
}

func groupMemberKey(for identity: GroupMemberIdentity) -> String {
    "\(identity.provider):\(identity.layer):\(identity.kind):\(identity.category):\(identity.id)"
}

func groupMemberKey(for item: InventoryItem) -> String {
    "\(item.provider):\(item.layer):\(item.kind):\(item.category):\(item.id)"
}

func matchesGroupMemberFilter(
    _ item: InventoryItem,
    selectedMemberKeys: Set<String>,
    filter: GroupMemberFilterState
) -> Bool {
    let included = selectedMemberKeys.contains(groupMemberKey(for: item))
    return (filter.provider == "all" || item.provider == filter.provider)
        && (filter.layer == "all" || item.layer == filter.layer)
        && (filter.category == "all" || item.category == filter.category)
        && (filter.state == "all" || (filter.state == "on") == item.enabled)
        && (filter.membership == "all" || (filter.membership == "included") == included)
        && (filter.search.isEmpty
            || item.displayName.localizedCaseInsensitiveContains(filter.search)
            || item.id.localizedCaseInsensitiveContains(filter.search))
}

struct GroupEditorView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @Environment(\.dismiss) private var dismiss

    let group: GroupSummary?
    @State private var name: String
    @State private var scope: String
    @State private var selectedMembers: [String: GroupMemberIdentity]
    @State private var search = ""
    @State private var selectedProvider = "all"
    @State private var selectedLayer = "all"
    @State private var selectedCategory = "all"
    @State private var selectedState = "all"
    @State private var membership = "all"
    @State private var historyVisible = false

    init(group: GroupSummary?) {
        self.group = group
        _name = State(initialValue: group?.name ?? "")
        _scope = State(initialValue: group?.scope ?? "personal")
        _selectedMembers = State(initialValue: Dictionary(
            uniqueKeysWithValues: (group?.members ?? []).map { member in
                (groupMemberKey(for: member.identity), member.identity)
            }
        ))
    }

    private var selectedMemberList: [GroupMemberIdentity] {
        selectedMembers.values.sorted { groupMemberKey(for: $0) < groupMemberKey(for: $1) }
    }

    var body: some View {
        let inventory = workspace.snapshot?.inventory ?? []
        let facets = InventoryFacets(inventory: inventory)
        let filterRevision = InventoryFilterRevision(inventory: inventory)
        let selectedKeys = Set(selectedMembers.keys)
        let memberFilter = GroupMemberFilterState(
            search: search,
            provider: selectedProvider,
            layer: selectedLayer,
            category: selectedCategory,
            state: selectedState,
            membership: membership
        )
        let visibleItems = inventory.filter {
            matchesGroupMemberFilter($0, selectedMemberKeys: selectedKeys, filter: memberFilter)
        }
        let visibleKeys = Set(visibleItems.map { groupMemberKey(for: $0) })
        let hiddenSelectionCount = selectedKeys.subtracting(visibleKeys).count
        let inventoryKeys = Set(inventory.map { groupMemberKey(for: $0) })
        let missingSelectionCount = selectedKeys.subtracting(inventoryKeys).count
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(group == nil ? "New inventory group" : group!.qualifiedName).font(.title2)
                Spacer()
                Button("Done") { dismiss() }
            }

            HStack(spacing: 12) {
                if group == nil {
                    TextField("Group name", text: $name)
                        .frame(minWidth: 220)
                    Picker("Scope", selection: $scope) {
                        Text("Personal").tag("personal")
                        Text("Repository").tag("repository")
                    }
                    .frame(width: 150)
                } else {
                    LabeledContent("Scope", value: scope)
                    LabeledContent("Revision", value: group!.revision)
                        .font(.caption.monospaced())
                    Text(group!.fresh == false ? "Observation needs refresh" : group!.state ?? "State unavailable")
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                TextField("Filter members", text: $search)
                    .frame(maxWidth: .infinity)

                HStack(alignment: .bottom, spacing: 12) {
                    filter("Provider", selection: $selectedProvider, values: facets.providers)
                    filter("Layer", selection: $selectedLayer, values: facets.layers)
                    filter("Category", selection: $selectedCategory, values: facets.categories)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("State")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Picker("State", selection: $selectedState) {
                            Text("Any state").tag("all")
                            Text("On").tag("on")
                            Text("Off").tag("off")
                        }
                        .accessibilityLabel(WorkbenchFilterAccessibility.state)
                        .labelsHidden()
                        .frame(minWidth: 150, maxWidth: .infinity)
                    }
                    .frame(minWidth: 150, maxWidth: .infinity, alignment: .leading)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Membership")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Picker("Membership", selection: $membership) {
                            Text("All items").tag("all")
                            Text("Included").tag("included")
                            Text("Not included").tag("excluded")
                        }
                        .accessibilityLabel(WorkbenchFilterAccessibility.membership)
                        .labelsHidden()
                        .frame(minWidth: 150, maxWidth: .infinity)
                    }
                    .frame(minWidth: 150, maxWidth: .infinity, alignment: .leading)
                }
            }

            HStack {
                Text("\(selectedMembers.count) explicit member(s)")
                    .font(.callout.weight(.medium))
                if hiddenSelectionCount > 0 {
                    Text("\(hiddenSelectionCount) selected outside this filter")
                        .foregroundStyle(.secondary)
                }
                if missingSelectionCount > 0 {
                    Label("\(missingSelectionCount) selected item(s) are currently unavailable", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                }
                Spacer()
                Button(group == nil ? "Review create" : "Review member changes") {
                    Task { await reviewDefinition() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(name.isEmpty || selectedMembers.isEmpty || workspace.actionsBlocked)
                if let group {
                    Menu("Plan change") {
                        Button("Enable") {
                            Task {
                                await workspace.plan(group: group, target: "enable")
                                dismiss()
                            }
                        }
                        Button("Disable") {
                            Task {
                                await workspace.plan(group: group, target: "disable")
                                dismiss()
                            }
                        }
                    }
                    .disabled(!group.contextCompatible || workspace.actionsBlocked)
                    Button("Review delete", role: .destructive) {
                        Task { await reviewDelete(group) }
                    }
                    .disabled(workspace.actionsBlocked)
                }
            }

            Table(visibleItems) {
                TableColumn("Include") { item in
                    Toggle("", isOn: includedBinding(for: item))
                        .labelsHidden()
                        .accessibilityLabel("Include \(item.displayName) in this group")
                }
                TableColumn("Name") { Text($0.displayName) }
                TableColumn("Provider") { Text($0.provider) }
                TableColumn("Type") { Text("\($0.category) · \($0.layer)") }
                TableColumn("State") { Text($0.enabled ? "On" : "Off") }
                TableColumn("Access") { Text($0.mutability) }
            }
            .frame(minHeight: 300)

            if let review = workspace.reviewedDefinition {
                definitionReview(review)
            }

            if let group {
                DisclosureGroup("Definition history", isExpanded: $historyVisible) {
                    Button("Load history") { Task { await workspace.loadDefinitionHistory(scope: group.scope) } }
                    ForEach(workspace.definitionHistory.filter { $0.scope == group.scope }) { record in
                        HStack {
                            Text("\(record.change) · \(record.nameAfter ?? record.nameBefore ?? "group")")
                            Spacer()
                            Text(record.createdAt).font(.caption.monospaced()).foregroundStyle(.secondary)
                            if record.nameBefore != nil {
                                Button("Review restore") {
                                    Task { await reviewRestore(record, group: group) }
                                }
                            }
                        }
                    }
                }
            }
        }
        .padding()
        .frame(minWidth: 900, minHeight: 650)
        .onChange(of: filterRevision) { _, _ in
            normalizeInventoryFilters(inventory)
        }
    }

    private func reviewDefinition() async {
        let parameters = GroupDefinitionPlanParameters(
            action: group == nil ? "create" : "replace",
            scope: group == nil ? scope : nil,
            qualifiedName: group?.qualifiedName,
            name: name,
            newName: nil,
            members: selectedMemberList,
            expectedRevision: group?.revision,
            historyId: nil
        )
        await workspace.planDefinition(parameters)
    }

    private func reviewDelete(_ group: GroupSummary) async {
        await workspace.planDefinition(GroupDefinitionPlanParameters(
            action: "delete",
            scope: nil,
            qualifiedName: group.qualifiedName,
            name: nil,
            newName: nil,
            members: nil,
            expectedRevision: group.revision,
            historyId: nil
        ))
    }

    private func reviewRestore(_ record: GroupDefinitionHistory, group: GroupSummary) async {
        await workspace.planDefinition(GroupDefinitionPlanParameters(
            action: "restore",
            scope: group.scope,
            qualifiedName: nil,
            name: nil,
            newName: nil,
            members: nil,
            expectedRevision: record.definitionAfterExists ? group.revision : nil,
            historyId: record.historyId
        ))
    }

    @ViewBuilder
    private func definitionReview(_ review: GroupDefinitionPlanEnvelope) -> some View {
        GroupBox("Review definition change") {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(review.plan.action) \(review.plan.qualifiedName ?? review.plan.historyId ?? "group")")
                    if let memberCount = review.plan.memberCount {
                        Text("\(memberCount) explicit member(s)").foregroundStyle(.secondary)
                    }
                    Text(review.plan.planFingerprint).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Spacer()
                Button("Discard review") {
                    Task { await workspace.discardReviewedDefinition() }
                }
                Button("Confirm \(review.plan.action)") {
                    Task {
                        if await workspace.applyDefinition() {
                            dismiss()
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(workspace.actionsBlocked)
            }
        }
    }

    private func includedBinding(for item: InventoryItem) -> Binding<Bool> {
        let identity = GroupMemberIdentity(
            provider: item.provider,
            layer: item.layer,
            kind: item.kind,
            category: item.category,
            id: item.id
        )
        let identityKey = groupMemberKey(for: identity)
        return Binding(
            get: { selectedMembers[identityKey] != nil },
            set: { included in
                if included {
                    selectedMembers[identityKey] = identity
                } else {
                    selectedMembers.removeValue(forKey: identityKey)
                }
            }
        )
    }

    private func normalizeInventoryFilters(_ inventory: [InventoryItem]) {
        let normalized = normalizedInventoryFacetSelection(
            InventoryFacetSelection(
                provider: selectedProvider,
                layer: selectedLayer,
                category: selectedCategory
            ),
            facets: InventoryFacets(inventory: inventory)
        )
        selectedProvider = normalized.provider
        selectedLayer = normalized.layer
        selectedCategory = normalized.category
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
            .frame(minWidth: 150, maxWidth: .infinity)
        }
        .frame(minWidth: 150, maxWidth: .infinity, alignment: .leading)
    }

}
