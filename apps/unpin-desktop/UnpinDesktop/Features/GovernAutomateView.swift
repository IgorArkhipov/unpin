import SwiftUI

struct GovernAutomateView: View {
    var body: some View {
        ContentUnavailableView(
            "Automation remains available",
            systemImage: "terminal",
            description: Text("Profiles, gateways, sessions, and hooks remain on their supported CLI and MCP paths until their dedicated workbench workflows arrive.")
        )
    }
}
