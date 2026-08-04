import SwiftUI

struct GroupEditorView: View {
    @EnvironmentObject private var workspace: WorkspaceStore
    let group: GroupSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(group.qualifiedName).font(.title2)
            Text(group.fresh == false ? "Observation needs refresh" : group.state ?? "State unavailable")
                .foregroundStyle(.secondary)
            HStack {
                Button("Enable") { Task { await workspace.plan(group: group, target: "enable") } }
                Button("Disable") { Task { await workspace.plan(group: group, target: "disable") } }
            }
            Text("Group definitions remain revision-bound. Creating and editing definitions is delivered through the bridge in the next workbench update.")
                .font(.callout)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding()
    }
}
