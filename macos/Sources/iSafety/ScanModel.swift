import AppKit
import CIsafety
import Combine
import Foundation
import UniformTypeIdentifiers

struct Finding: Decodable, Identifiable, Sendable {
    let id: String
    let category: String
    let title: String
    let explanation: String
    let domain: String
    let relativePath: String
    let fileId: String
}

struct Coverage: Decodable, Identifiable, Sendable {
    var id: String { category }
    let category: String
    let matched: UInt64
    let inspected: UInt64
    let errors: UInt64
}

struct BackupInfo: Decodable, Sendable {
    let deviceName: String
    let productType: String
    let productVersion: String
    let encrypted: Bool
    let fileCount: UInt64
}

struct Report: Decodable, Sendable {
    let schemaVersion: Int
    let backup: BackupInfo
    let findings: [Finding]
    let coverage: [Coverage]
    let warnings: [String]
    let scope: String
}

struct ScanFailure: Decodable, Error, LocalizedError, Sendable {
    let code: String
    let message: String
    var errorDescription: String? { message }
}

struct Engine {
    struct Response: Sendable {
        let report: Report
        let json: Data
    }

    static func scan(path: String, password: String?) throws -> Response {
        // C borrows this buffer only for the duration of the call. Swift's String
        // and SecureField storage cannot promise forensic erasure of all copies.
        var bytes = password.map { Array($0.utf8) + [0] }
        defer {
            if bytes != nil {
                bytes!.withUnsafeMutableBytes { buffer in
                    if let address = buffer.baseAddress { isafety_clear_bytes(address.assumingMemoryBound(to: UInt8.self), buffer.count) }
                }
            }
        }
        let pointer = path.withCString { pathPointer in
            if let bytes {
                return bytes.withUnsafeBufferPointer { isafety_scan_backup(pathPointer, $0.baseAddress, $0.count - 1) }
            }
            return isafety_scan_backup(pathPointer, nil, 0)
        }
        guard let pointer else { throw ScanFailure(code: "internal_error", message: "The scanning engine returned no response.") }
        defer { isafety_string_free(pointer) }
        let json = Data(bytes: pointer, count: strlen(pointer))
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        struct ErrorEnvelope: Decodable { let error: ScanFailure }
        if let envelope = try? decoder.decode(ErrorEnvelope.self, from: json) { throw envelope.error }
        let report = try decoder.decode(Report.self, from: json)
        guard report.schemaVersion == 1 else { throw ScanFailure(code: "unsupported_report", message: "Unsupported report version.") }
        return Response(report: report, json: json)
    }
}

@MainActor
final class ScanModel: ObservableObject {
    @Published var report: Report?
    @Published var busy = false
    @Published var needsPassword = false
    @Published var password = ""
    @Published var error: String?
    @Published var selectedCategory: String?
    @Published var search = ""
    private var selectedURL: URL?
    private var reportJSON: Data?

    var findings: [Finding] {
        (report?.findings ?? []).filter {
            (selectedCategory == nil || $0.category == selectedCategory) &&
            (search.isEmpty || "\($0.title) \($0.domain) \($0.relativePath)".localizedCaseInsensitiveContains(search))
        }
    }

    func chooseBackup() {
        let panel = NSOpenPanel()
        panel.title = "Choose an iPhone or iPad backup"
        panel.message = "Select the folder containing Manifest.plist and Manifest.db. iSafety reads the backup locally."
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        selectedURL = url
        runScan(password: nil)
    }

    func unlock() {
        let supplied = password
        password = ""
        needsPassword = false
        runScan(password: supplied)
    }

    func cancelPassword() {
        password = ""
        needsPassword = false
        selectedURL = nil
    }

    private func runScan(password: String?) {
        guard let url = selectedURL, !busy else { return }
        busy = true
        report = nil
        reportJSON = nil
        error = nil
        selectedCategory = nil
        search = ""
        let granted = url.startAccessingSecurityScopedResource()
        Task {
            defer {
                if granted { url.stopAccessingSecurityScopedResource() }
                busy = false
            }
            do {
                let response = try await Task.detached(priority: .userInitiated) {
                    try Engine.scan(path: url.path, password: password)
                }.value
                report = response.report
                reportJSON = response.json
            } catch let failure as ScanFailure where failure.code == "password_required" || failure.code == "password_or_keybag" {
                if failure.code == "password_or_keybag" { error = failure.message }
                needsPassword = true
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    func exportReport() {
        guard let reportJSON else { return }
        let panel = NSSavePanel()
        panel.title = "Export scan report"
        panel.message = "This report includes device details and artifact identifiers. Save it somewhere private."
        panel.nameFieldStringValue = "iSafety-report.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try reportJSON.write(to: url, options: .atomic) }
        catch { self.error = error.localizedDescription }
    }
}
