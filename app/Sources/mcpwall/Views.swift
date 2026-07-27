import AppKit
import SwiftUI

// ---------------------------------------------------------------------------
// Popover
// ---------------------------------------------------------------------------

/// What a left click on the icon shows.
///
/// Deliberately sparse: some counters, the latest prompts, three ways out.
/// Anything that needs careful reading belongs in the Journal window, not in a
/// panel that closes the moment you look away.
struct PopoverView: View {
    @ObservedObject var model: AppModel
    let actions: PopoverActions

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            counters
            Divider()
            recent
            Divider()
            footer
        }
        .frame(width: 320)
    }

    private var header: some View {
        HStack {
            Image(systemName: model.daemonConnected ? "shield.lefthalf.filled" : "shield.slash")
                .foregroundStyle(model.daemonConnected ? Color.accentColor : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text("mcpwall").font(.headline)
                Text(model.daemonConnected ? "active" : "daemon unreachable")
                    .font(.caption)
                    .foregroundStyle(model.daemonConnected ? Color.secondary : Color.orange)
            }
            Spacer()
        }
        .padding(12)
    }

    private var counters: some View {
        HStack(spacing: 0) {
            counter("\(model.status.callsToday)", "calls")
            Divider().frame(height: 34)
            counter("\(model.status.blockedToday)", "blocked")
            Divider().frame(height: 34)
            counter("\(model.status.activeSessions)", "servers")
        }
        .padding(.vertical, 10)
    }

    private func counter(_ value: String, _ label: String) -> some View {
        VStack(spacing: 2) {
            Text(value).font(.system(.title3, design: .rounded)).bold()
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private var recent: some View {
        if model.recent.isEmpty {
            Text("No prompts today.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Text("Latest prompts")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(model.recent) { prompt in
                    HStack(spacing: 6) {
                        Image(systemName: "questionmark.circle")
                            .font(.caption2)
                            .foregroundStyle(.orange)
                        Text(prompt.title)
                            .font(.system(.caption, design: .monospaced))
                            .lineLimit(1)
                        Spacer()
                        Text(prompt.rule ?? "—")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
            }
            .padding(12)
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            // The loss counter is only shown when non-zero: it is a bug signal,
            // not a normal regime, and the user is entitled to know their audit
            // trail is incomplete.
            if model.status.droppedEntries > 0 {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text("\(model.status.droppedEntries) journal entries lost")
                        .font(.caption2)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.top, 8)
            }

            HStack(spacing: 8) {
                Button("Journal", action: actions.openJournal)
                Button("Policy", action: actions.openPolicy)
                Spacer()
                Menu {
                    Button("Reinstall into MCP clients…", action: actions.runOnboarding)
                    Divider()
                    Button("Quit mcpwall", action: actions.quit)
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
            }
            .padding(12)
        }
    }
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

struct JournalEntry: Identifiable, Hashable {
    let id = UUID()
    let timestamp: Date
    let direction: String
    let method: String
    let disposition: String
    let verdict: String?
    let rule: String?
    let server: String
    let scope: String
    let scopeSource: String
    let bytes: Int
}

/// The Journal window.
///
/// The data comes from `mcpwall log --json` rather than from SQLite accessed
/// via Swift. One read path, already covered by the core's tests, and no risk
/// of the interface holding a lock on the database while the shim writes.
struct JournalView: View {
    @State private var entries: [JournalEntry] = []
    @State private var filter = ""
    @State private var onlyBlocked = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if let error {
                ContentUnavailableView(
                    "Journal unreadable",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error)
                )
            } else if filtered.isEmpty {
                ContentUnavailableView(
                    "No entries",
                    systemImage: "tray",
                    description: Text("Traffic from your MCP servers will appear here.")
                )
            } else {
                table
            }
        }
        .onAppear(perform: reload)
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            TextField("Filter by tool, server or project", text: $filter)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            Toggle("Blocked only", isOn: $onlyBlocked)
                .toggleStyle(.checkbox)
            Spacer()
            Button("Export JSONL…", action: export)
            Button(action: reload) { Image(systemName: "arrow.clockwise") }
        }
        .padding(10)
    }

    private var table: some View {
        Table(filtered) {
            TableColumn("Time") { e in
                Text(e.timestamp, format: .dateTime.hour().minute().second())
                    .font(.system(.caption, design: .monospaced))
            }
            .width(70)

            TableColumn("") { e in
                Image(systemName: e.direction == "to_server" ? "arrow.up" : "arrow.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            .width(20)

            TableColumn("Method") { e in
                Text(e.method).font(.system(.caption, design: .monospaced))
            }

            TableColumn("Server") { e in Text(e.server).font(.caption) }
            TableColumn("Project") { e in
                Text(e.scope).font(.caption).help("provenance: \(e.scopeSource)")
            }

            TableColumn("Verdict") { e in
                if let verdict = e.verdict, verdict == "deny" {
                    Label(e.rule ?? "blocked", systemImage: "hand.raised.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                } else {
                    Text(e.verdict ?? "—").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var filtered: [JournalEntry] {
        entries.filter { e in
            if onlyBlocked && e.verdict != "deny" { return false }
            guard !filter.isEmpty else { return true }
            let needle = filter.lowercased()
            return e.method.lowercased().contains(needle)
                || e.server.lowercased().contains(needle)
                || e.scope.lowercased().contains(needle)
        }
    }

    private func reload() {
        do {
            let output = try CoreCommand.run(["log", "-n", "500", "--json"])
            entries = output
                .split(separator: "\n")
                .compactMap { Self.parse(String($0)) }
                .reversed()
            error = nil
        } catch {
            self.error = "\(error)"
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "mcpwall-journal.jsonl"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let output = try CoreCommand.run(["log", "-n", "100000", "--json"])
            try output.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            NSAlert(error: error).runModal()
        }
    }

    static func parse(_ line: String) -> JournalEntry? {
        guard let data = line.data(using: .utf8),
              let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let ts = dict["ts_ms"] as? Double
        else { return nil }

        return JournalEntry(
            timestamp: Date(timeIntervalSince1970: ts / 1000),
            direction: dict["direction"] as? String ?? "",
            method: dict["method"] as? String ?? "(response)",
            disposition: dict["disposition"] as? String ?? "",
            verdict: dict["verdict"] as? String,
            rule: dict["rule"] as? String,
            server: dict["server"] as? String ?? "?",
            scope: (dict["scope"] as? String ?? "").replacingOccurrences(of: "project:", with: ""),
            scopeSource: dict["scope_source"] as? String ?? "unknown",
            bytes: dict["bytes"] as? Int ?? 0
        )
    }
}

// ---------------------------------------------------------------------------
// Onboarding
// ---------------------------------------------------------------------------

/// First launch.
///
/// **Success criterion: zero terminal.** If the user has to copy-paste JSON
/// after mounting the `.dmg`, onboarding has failed. The diff is shown before
/// any write, and a single button puts everything back.
struct OnboardingView: View {
    let binary: URL
    let onDone: () -> Void

    @State private var preview = ""
    @State private var applied = false
    @State private var working = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Install mcpwall into your MCP clients")
                    .font(.title2).bold()
                Text("mcpwall will wrap the MCP servers declared in your configurations. "
                     + "Nothing is written before you have read what will change, and "
                     + "everything is reversible in one click.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            GroupBox("What will change") {
                ScrollView {
                    Text(preview.isEmpty ? "Analysing…" : preview)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(4)
                }
                .frame(height: 260)
            }

            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if applied {
                Label(
                    "Done. Restart your MCP clients for the configuration to take effect.",
                    systemImage: "checkmark.circle.fill"
                )
                .font(.callout)
                .foregroundStyle(.green)
            }

            HStack {
                Button("Put everything back", action: restore)
                    .disabled(working)
                Spacer()
                Button("Later", action: onDone)
                Button(applied ? "Close" : "Install") {
                    if applied { onDone() } else { apply() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(working)
            }
        }
        .padding(20)
        .frame(width: 620)
        .onAppear(perform: loadPreview)
    }

    private func loadPreview() {
        working = true
        run(["init"]) { output in
            preview = output
            working = false
        }
    }

    private func apply() {
        working = true
        run(["init", "--apply"]) { output in
            preview = output
            applied = true
            working = false
        }
    }

    private func restore() {
        working = true
        run(["restore"]) { output in
            preview = output
            applied = false
            working = false
        }
    }

    private func run(_ args: [String], completion: @escaping (String) -> Void) {
        DispatchQueue.global().async {
            do {
                let output = try CoreCommand.run(args, binary: binary)
                DispatchQueue.main.async {
                    error = nil
                    completion(output)
                }
            } catch {
                DispatchQueue.main.async {
                    self.error = "\(error)"
                    self.working = false
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Calling the core
// ---------------------------------------------------------------------------

/// Runs a subcommand of the mcpwall binary.
///
/// The interface never reimplements what the core already does: reading the
/// journal, computing an install diff, restoring backups. One implementation,
/// already tested, and no drift between what the command line does and what the
/// app displays.
enum CoreCommand {
    struct Failure: LocalizedError {
        let code: Int32
        let message: String
        var errorDescription: String? {
            message.isEmpty ? "the core failed (code \(code))" : message
        }
    }

    static func run(_ args: [String], binary: URL? = nil) throws -> String {
        let executable = binary ?? Paths.shimLink
        let process = Process()
        process.executableURL = executable
        process.arguments = args

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        try process.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            throw Failure(
                code: process.terminationStatus,
                message: String(data: errData, encoding: .utf8) ?? ""
            )
        }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
