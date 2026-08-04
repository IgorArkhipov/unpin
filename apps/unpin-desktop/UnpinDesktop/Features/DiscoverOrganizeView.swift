import SwiftUI

struct DiscoverOrganizeView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    @State private var search = ""
    @State private var selectedProvider = "all"

    private var items: [InventoryItem] {
        (workspace.snapshot?.inventory ?? []).filter { item in
            (selectedProvider == "all" || item.provider == selectedProvider)
                && (search.isEmpty
                    || item.displayName.localizedCaseInsensitiveContains(search)
                    || item.id.localizedCaseInsensitiveContains(search))
        }
    }

    private var providers: [String] {
        Array(Set((workspace.snapshot?.inventory ?? []).map(\.provider))).sorted()
    }

    var body: some View {
        NavigationSplitView {
            List(workspace.snapshot?.groups ?? []) { group in
                NavigationLink(group.qualifiedName) { GroupEditorView(group: group) }
            }
            .navigationTitle("Groups")
        } detail: {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    TextField("Search inventory", text: $search)
                    Picker("Provider", selection: $selectedProvider) {
                        Text("All providers").tag("all")
                        ForEach(providers, id: \.self) { Text($0).tag($0) }
                    }
                    Button("Reload") { Task { try? await workspace.refresh() } }
                }
                .padding([.horizontal, .top])

                Table(items) {
                    TableColumn("Name") { Text($0.displayName) }
                    TableColumn("Provider") { Text($0.provider) }
                    TableColumn("Type") { Text("\($0.category) · \($0.layer)") }
                    TableColumn("State") { Text($0.enabled ? "On" : "Off") }
                    TableColumn("Access") { Text($0.mutability) }
                }
                .overlay {
                    if items.isEmpty { ContentUnavailableView("No matching inventory", systemImage: "magnifyingglass") }
                }
            }
        }
    }
}
