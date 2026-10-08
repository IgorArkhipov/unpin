import AppKit
import XCTest
import XCUIAutomation

@MainActor
final class WorkbenchUITests: XCTestCase {
    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    override func tearDown() async throws {
        await MainActor.run { XCUIApplication().terminate() }
    }

    func testInventoryFilterSelectionsFitAtDefaultWindowWidth() {
        let app = launch("inventory", width: 1180, height: 760)
        assertFilters(
            app,
            expected: [
                ("Provider", "All provider"), ("Layer", "All layer"),
                ("Category", "All category"), ("State", "Any state"),
            ])
        choose("codex", in: filter("Provider", in: app), app: app)
        XCTAssertTrue(app.staticTexts["Alpha Codex skill"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Beta Zed MCP"].exists)
        choose("All provider", in: filter("Provider", in: app), app: app)
        XCTAssertTrue(app.staticTexts["Beta Zed MCP"].waitForExistence(timeout: 5))
    }

    func testGroupEditorFilterSelectionsFitAtCaptureWidth() {
        let app = launch("group-editor", width: 1040, height: 720)
        assertFilters(
            app, prefix: "group-member",
            expected: [
                ("Provider", "All provider"), ("Layer", "All layer"),
                ("Category", "All category"), ("State", "Any state"),
                ("Membership", "All items"),
            ])
        choose("Included", in: filter("Membership", in: app, prefix: "group-member"), app: app)
        XCTAssertEqual(filter("Membership", in: app, prefix: "group-member").value as? String, "Included")
        choose("All items", in: filter("Membership", in: app, prefix: "group-member"), app: app)
        XCTAssertEqual(filter("Membership", in: app, prefix: "group-member").value as? String, "All items")
    }

    func testDiscoverFacetReplacementDoesNotRemainInStaleFilterZeroState() {
        let app = launch("facet-replacement", width: 1180, height: 760)
        XCTAssertTrue(filter("Provider", in: app).waitForExistence(timeout: 5))
        XCTAssertEqual(filter("Provider", in: app).value as? String, "claude")
        XCTAssertEqual(filter("Layer", in: app).value as? String, "global")
        XCTAssertEqual(filter("Category", in: app).value as? String, "skill")
        let window = app.windows["fixture"]
        let replace = window.buttons["Replace fixture inventory"]
        XCTAssertTrue(replace.isHittable)
        XCTAssertTrue(window.frame.contains(replace.frame))
        replace.click()
        XCTAssertTrue(window.staticTexts["Replacement Zed MCP"].waitForExistence(timeout: 5))
        assertFilters(
            app,
            expected: [
                ("Provider", "All provider"), ("Layer", "All layer"),
                ("Category", "All category"),
            ])
        XCTAssertFalse(app.buttons["Clear filters"].exists)
        XCTAssertFalse(app.staticTexts["No inventory matches these filters"].exists)
    }

    private func launch(_ scenario: String, width: Int, height: Int) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-ApplePersistenceIgnoreState", "YES"]
        app.launchEnvironment = [
            "UNPIN_UI_SCENARIO": scenario,
            "UNPIN_UI_WIDTH": String(width), "UNPIN_UI_HEIGHT": String(height),
        ]
        app.launch()
        return app
    }

    private func filter(_ label: String, in app: XCUIApplication, prefix: String = "inventory") -> XCUIElement {
        app.windows["fixture"].popUpButtons["\(prefix)-filter-\(label.lowercased())"]
    }

    private func assertFilters(
        _ app: XCUIApplication, prefix: String = "inventory", expected: [(String, String)],
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let window = app.windows["fixture"]
        XCTAssertTrue(window.waitForExistence(timeout: 5), file: file, line: line)
        for (label, selected) in expected {
            let picker = filter(label, in: app, prefix: prefix)
            XCTAssertTrue(picker.waitForExistence(timeout: 5), "Missing \(label) control", file: file, line: line)
            XCTAssertEqual(picker.value as? String, selected, file: file, line: line)
            XCTAssertTrue(
                picker.label.contains(label), "\(label) lacks its accessibility label", file: file, line: line)
            XCTAssertTrue(picker.isHittable, "\(label) is not reachable", file: file, line: line)
            let frame = picker.frame
            let windowFrame = window.frame
            XCTAssertTrue(
                windowFrame.contains(frame),
                "\(label) frame \(frame) is outside window \(windowFrame)", file: file, line: line)
            let caption = window.staticTexts[label].firstMatch
            XCTAssertTrue(caption.exists, "\(label) lacks a visible caption", file: file, line: line)
            let captionFrame = caption.frame
            XCTAssertLessThanOrEqual(
                abs(captionFrame.minX - frame.minX), 4,
                "\(label) caption and dropdown are not leading-aligned", file: file, line: line)
            XCTAssertGreaterThanOrEqual(
                frame.minY - captionFrame.maxY, 0,
                "\(label) caption overlaps its dropdown", file: file, line: line)
            XCTAssertLessThanOrEqual(
                frame.minY - captionFrame.maxY, 12,
                "\(label) caption is detached from its dropdown", file: file, line: line)
            // A text-budget check complements fixture-window visual review;
            // accessibility values alone cannot establish absence of clipping.
            let textWidth = (selected as NSString).size(withAttributes: [
                .font: NSFont.systemFont(ofSize: NSFont.systemFontSize)
            ]).width
            XCTAssertGreaterThanOrEqual(
                frame.width, textWidth + 20,
                "\(label) lacks room for its selected text", file: file, line: line)
        }
    }

    private func choose(_ value: String, in picker: XCUIElement, app: XCUIApplication) {
        picker.click()
        let item = app.menuItems[value]
        XCTAssertTrue(item.waitForExistence(timeout: 5))
        item.click()
    }
}
