import Foundation
import Testing
@testable import iSafety

private func fixture(_ name: String) -> String {
    URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("crates/ibackup/tests/fixtures/\(name)").path
}

@Test func swiftReadsEncryptedBackupThroughRust() throws {
    let response = try Engine.scan(path: fixture("encrypted-modern"), password: "fixture-password-🔐")
    #expect(response.report.backup.encrypted)
    #expect(response.report.findings.count == 4)
    #expect(response.report.warnings.isEmpty)
    #expect(!String(decoding: response.json, as: UTF8.self).contains("fixture-password"))
}

@Test func swiftReceivesPasswordRequiredError() throws {
    do {
        _ = try Engine.scan(path: fixture("encrypted-modern"), password: nil)
        Issue.record("Expected password request")
    } catch let failure as ScanFailure {
        #expect(failure.code == "password_required")
    }
}

@Test func emptyPasswordIsDifferentFromNoPassword() throws {
    let response = try Engine.scan(path: fixture("encrypted-empty-password"), password: "")
    #expect(response.report.findings.count == 4)
}
