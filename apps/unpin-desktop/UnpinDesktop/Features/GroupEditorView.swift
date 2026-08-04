import SwiftUI

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
                (Self.key(for: member.identity), member.identity)
            }
        ))
    }

    private var selectedMemberList: [GroupMemberIdentity] {
        selectedMembers.values.sorted { key(for: $0) < key(for: $1) }
    }

    var body: some View {
        let inventory = workspace.snapshot?.inventory ?? []
        let facets = InventoryFacets(inventory: inventory)
        let selectedKeys = Set(selectedMembers.keys)
        let visibleItems = inventory.filter { item in
            let included = selectedKeys.contains(key(for: item))
            return (selectedProvider == "all" || item.provider == selectedProvider)
                && (selectedLayer == "all" || item.layer == selectedLayer)
                && (selectedCategory == "all" || item.category == selectedCategory)
                && (selectedState == "all" || (selectedState == "on") == item.enabled)
                && (membership == "all" || (membership == "included") == included)
                && (search.isEmpty
                    || item.displayName.localizedCaseInsensitiveContains(search)
                    || item.id.localizedCaseInsensitiveContains(search))
        }
        let visibleKeys = Set(visibleItems.map { key(for: $0) })
        let hiddenSelectionCount = selectedKeys.subtracting(visibleKeys).count
        let inventoryKeys = Set(inventory.map { key(for: $0) })
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

            HStack(spacing: 8) {
                TextField("Filter members", text: $search).frame(minWidth: 220)
                filter("Provider", selection: $selectedProvider, values: facets.providers)
                filter("Layer", selection: $selectedLayer, values: facets.layers)
                filter("Category", selection: $selectedCategory, values: facets.categories)
                Picker("State", selection: $selectedState) {
                    Text("Any state").tag("all")
                    Text("On").tag("on")
                    Text("Off").tag("off")
                }
                Picker("Membership", selection: $membership) {
                    Text("All items").tag("all")
                    Text("Included").tag("included")
                    Text("Not included").tag("excluded")
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
                .disabled(name.isEmpty || selectedMembers.isEmpty)
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
                    .disabled(!group.contextCompatible)
                    Button("Review delete", role: .destructive) {
                        Task { await reviewDelete(group) }
                    }
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
        .onChange(of: workspace.snapshot?.capturedAtUnix) { _, _ in
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
        let identityKey = key(for: identity)
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
        let facets = InventoryFacets(inventory: inventory)
        if selectedProvider != "all", !facets.providers.contains(selectedProvider) {
            selectedProvider = "all"
        }
        if selectedLayer != "all", !facets.layers.contains(selectedLayer) {
            selectedLayer = "all"
        }
        if selectedCategory != "all", !facets.categories.contains(selectedCategory) {
            selectedCategory = "all"
        }
    }

    private func filter(
        _ title: String,
        selection: Binding<String>,
        values: [String]
    ) -> some View {
        Picker(title, selection: selection) {
            Text("All \(title.lowercased())").tag("all")
            ForEach(values, id: \.self) { Text($0).tag($0) }
        }
        .frame(width: 130)
    }

    private static func key(for identity: GroupMemberIdentity) -> String {
        "\(identity.provider):\(identity.layer):\(identity.kind):\(identity.category):\(identity.id)"
    }

    private static func key(for item: InventoryItem) -> String {
        "\(item.provider):\(item.layer):\(item.kind):\(item.category):\(item.id)"
    }

    private func key(for identity: GroupMemberIdentity) -> String { Self.key(for: identity) }
    private func key(for item: InventoryItem) -> String { Self.key(for: item) }
}
