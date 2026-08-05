import Foundation

enum FixtureResources {
    private final class BundleMarker: NSObject {}

    static func root() throws -> URL {
        guard let resourceRoot = Bundle(for: BundleMarker.self).resourceURL else {
            throw FixtureResourceError.missing("test bundle resource root")
        }

        let fixtureRoot = resourceRoot.appendingPathComponent("fixtures", isDirectory: true)
        var isDirectory = ObjCBool(false)
        guard FileManager.default.fileExists(
            atPath: fixtureRoot.path,
            isDirectory: &isDirectory
        ), isDirectory.boolValue else {
            throw FixtureResourceError.missing(fixtureRoot.path)
        }

        return fixtureRoot
    }
}

private enum FixtureResourceError: LocalizedError {
    case missing(String)

    var errorDescription: String? {
        switch self {
        case let .missing(path):
            "Bundled desktop test fixtures are missing at \(path)"
        }
    }
}
