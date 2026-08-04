import SwiftUI

struct DiscoverOrganizeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var search = ""
    @State private var selectedProvider = "all"
    @State private var selectedLayer = "all"
    @State private var selectedCategory = "all"
    @State private var selectedState = "all"
    @State private var editingGroup: GroupSummary?
    @State private var creatingGroup = false

    var body: some View {
        let inventory = workspace.snapshot?.inventory ?? []
        let facets = InventoryFacets(inventory: inventory)
        let items = inventory.filter { item in
            (selectedProvider == "all" || item.provider == selectedProvider)
                && (selectedLayer == "all" || item.layer == selectedLayer)
                && (selectedCategory == "all" || item.category == selectedCategory)
                && (selectedState == "all" || (selectedState == "on") == item.enabled)
                && (search.isEmpty
                    || item.displayName.localizedCaseInsensitiveContains(search)
                    || item.id.localizedCaseInsensitiveContains(search))
        }
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Text("Discover and Organize").font(.title2)
                Spacer()
                Menu("Groups") {
                    ForEach(workspace.snapshot?.groups ?? []) { group in
                        Button(group.qualifiedName) { editingGroup = group }
                    }
                }
                Button("New group") { creatingGroup = true }
                Button("Reload") { Task { try? await workspace.refresh() } }
            }

            HStack(spacing: 8) {
                TextField("Search inventory", text: $search)
                    .frame(minWidth: 240)
                filter("Provider", selection: $selectedProvider, values: facets.providers)
                filter("Layer", selection: $selectedLayer, values: facets.layers)
                filter("Category", selection: $selectedCategory, values: facets.categories)
                Picker("State", selection: $selectedState) {
                    Text("Any state").tag("all")
                    Text("On").tag("on")
                    Text("Off").tag("off")
                }
                .frame(width: 110)
            }

            if let warnings = workspace.snapshot?.warnings, !warnings.isEmpty {
                Label("Some provider discovery results are incomplete.", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }

            Table(items) {
                TableColumn("Name") { Text($0.displayName) }
                TableColumn("Provider") { Text($0.provider) }
                TableColumn("Type") { Text("\($0.category) · \($0.layer)") }
                TableColumn("State") { Text($0.enabled ? "On" : "Off") }
                TableColumn("Access") { Text($0.mutability) }
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
        .sheet(isPresented: $creatingGroup) {
            GroupEditorView(group: nil)
        }
        .onChange(of: workspace.snapshot?.capturedAtUnix) { _, _ in
            normalizeInventoryFilters(inventory)
        }
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
}
