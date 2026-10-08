import SwiftUI

@main
struct iSafetyApp: App {
    @StateObject private var model = ScanModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                .frame(minWidth: 960, minHeight: 660)
        }
        .defaultSize(width: 1180, height: 780)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Backup…", action: model.chooseBackup)
                    .keyboardShortcut("o")
                    .disabled(model.busy)
                Button("Export Report…", action: model.exportReport)
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                    .disabled(model.report == nil || model.busy)
            }
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: ScanModel

    var body: some View {
        NavigationSplitView {
            VStack(alignment: .leading, spacing: 20) {
                Label("iSafety", systemImage: "checkmark.shield")
                    .font(.system(size: 26, weight: .semibold)).padding(.horizontal, 16).padding(.top, 20)
                Text("DEVICE SAFETY REVIEW").font(.caption.weight(.medium)).foregroundStyle(.secondary).padding(.horizontal, 16)
                List(selection: $model.selectedCategory) {
                    Label("All findings", systemImage: "square.grid.2x2").tag(nil as String?)
                    if let report = model.report {
                        Section("Backup artifacts") {
                            ForEach(report.coverage) { coverage in
                                HStack {
                                    Text(coverage.category)
                                    Spacer()
                                    Text("\(report.findings.filter { $0.category == coverage.category }.count)")
                                        .foregroundStyle(.secondary).monospacedDigit()
                                }.tag(Optional(coverage.category))
                            }
                        }
                    }
                }.listStyle(.sidebar)
                Label("Processed on this Mac", systemImage: "lock.shield")
                    .font(.caption).foregroundStyle(.secondary).padding(16)
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 250)
        } detail: {
            VStack(spacing: 0) {
                if let error = model.error, !model.needsPassword {
                    HStack(alignment: .top) {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                        Text(error).textSelection(.enabled)
                        Spacer()
                        Button { model.error = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain)
                            .accessibilityLabel("Dismiss error")
                    }.padding().background(.orange.opacity(0.10))
                }
                if model.busy { progress }
                else if let report = model.report { reportView(report) }
                else { welcome }
            }
            .navigationTitle(model.report?.backup.deviceName ?? "iSafety")
            .toolbar {
                ToolbarItemGroup {
                    Button(action: model.chooseBackup) { Label("Open Backup", systemImage: "folder.badge.plus") }.disabled(model.busy)
                    Button(action: model.exportReport) { Label("Export", systemImage: "square.and.arrow.up") }.disabled(model.report == nil || model.busy)
                }
            }
        }
        .sheet(isPresented: $model.needsPassword, onDismiss: { model.password = "" }) {
            VStack(alignment: .leading, spacing: 18) {
                Label("Unlock encrypted backup", systemImage: "lock").font(.title2.weight(.semibold))
                Text("Enter the password you set when encrypting this backup in Finder or iTunes. It is used for this scan and is not saved.")
                    .foregroundStyle(.secondary)
                SecureField("Backup password", text: $model.password).onSubmit(model.unlock)
                if let error = model.error { Text(error).foregroundStyle(.red).font(.callout) }
                HStack {
                    Button("Cancel", action: model.cancelPassword).keyboardShortcut(.cancelAction)
                    Spacer()
                    Button("Unlock and Scan", action: model.unlock).keyboardShortcut(.defaultAction)
                }
            }.padding(28).frame(width: 440)
        }
    }

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 24) {
            Image(systemName: "checkmark.shield").font(.system(size: 52, weight: .light)).foregroundStyle(.teal)
            Text("Understand what’s\nin your backup.").font(.system(size: 38, weight: .semibold, design: .rounded))
            Text("Review configuration profiles, paired devices, and other security-relevant artifacts from an iPhone or iPad backup.")
                .font(.title3).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Button(action: model.chooseBackup) { Label("Choose Backup Folder…", systemImage: "folder") }
                .buttonStyle(.borderedProminent).controlSize(.large).tint(.teal)
            Divider()
            Label("Encrypted and unencrypted local backups", systemImage: "externaldrive")
            Label("Read-only analysis • No uploads", systemImage: "lock.shield")
            Text("A review helps you understand the evidence available in a backup. It cannot establish that a device is free of compromise.")
                .font(.callout).foregroundStyle(.secondary)
        }.frame(maxWidth: 570, alignment: .leading).padding(48).frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var progress: some View {
        VStack(spacing: 18) {
            ProgressView().controlSize(.large)
            Text("Reading your backup").font(.title2.weight(.medium))
            Text("Encrypted backups require a deliberately slow password check.\nYour backup stays unchanged.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func reportView(_ report: Report) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Backup review").font(.largeTitle.weight(.semibold))
                        Text("\(report.backup.productType) · iOS \(report.backup.productVersion)").foregroundStyle(.secondary)
                    }
                    Spacer()
                    Label(report.backup.encrypted ? "Encrypted backup" : "Unencrypted backup", systemImage: report.backup.encrypted ? "lock.fill" : "lock.open")
                        .font(.caption.weight(.medium)).padding(9).background(.teal.opacity(0.1), in: Capsule())
                }
                HStack(spacing: 16) {
                    metric("Artifacts to review", "\(report.findings.count)")
                    metric("Manifest entries", "\(report.backup.fileCount)")
                    metric("Read warnings", "\(report.warnings.count)")
                }
                Text(report.scope).font(.callout).foregroundStyle(.secondary)
                DisclosureGroup("Scan coverage") {
                    ForEach(report.coverage) { item in
                        HStack {
                            Text(item.category)
                            Spacer()
                            Text(item.matched == 0 ? "No matching artifacts" : "\(item.inspected)/\(item.matched) processed · \(item.errors) errors")
                                .foregroundStyle(item.errors > 0 ? .orange : .secondary)
                        }.font(.callout).padding(.vertical, 3)
                    }
                }
                if !report.warnings.isEmpty {
                    DisclosureGroup("Warnings — some evidence could not be evaluated") {
                        ForEach(Array(report.warnings.enumerated()), id: \.offset) { _, warning in
                            Text(warning).font(.callout).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 4)
                        }
                    }.foregroundStyle(.orange)
                }
                Divider()
                HStack {
                    Text(model.selectedCategory ?? "All findings").font(.title2.weight(.semibold))
                    Spacer()
                    TextField("Filter findings", text: $model.search).textFieldStyle(.roundedBorder).frame(width: 220)
                }
                if model.findings.isEmpty {
                    ContentUnavailableView("No matching findings", systemImage: "doc.text.magnifyingglass", description: Text("Check scan coverage and warnings for artifacts that were absent or could not be read."))
                }
                LazyVStack(alignment: .leading, spacing: 14) {
                    ForEach(model.findings) { finding in
                        VStack(alignment: .leading, spacing: 9) {
                            Text(finding.category.uppercased()).font(.caption.weight(.medium)).foregroundStyle(.teal)
                            Text(finding.title).font(.headline).textSelection(.enabled)
                            Text(finding.explanation).foregroundStyle(.secondary)
                            DisclosureGroup("Evidence location") {
                                Text("\(finding.domain)\n\(finding.relativePath)\nFile ID: \(finding.fileId)")
                                    .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }.font(.caption)
                        }.padding(18).frame(maxWidth: .infinity, alignment: .leading)
                            .background(.background, in: RoundedRectangle(cornerRadius: 12))
                            .overlay(RoundedRectangle(cornerRadius: 12).stroke(.quaternary))
                    }
                }
            }.padding(30)
        }.background(Color(nsColor: .windowBackgroundColor))
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(value).font(.system(size: 28, weight: .semibold, design: .rounded)).monospacedDigit()
            Text(label).font(.callout).foregroundStyle(.secondary)
        }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(.teal.opacity(0.06), in: RoundedRectangle(cornerRadius: 12))
    }
}
