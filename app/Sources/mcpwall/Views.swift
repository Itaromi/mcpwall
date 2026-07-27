import AppKit
import SwiftUI

// ---------------------------------------------------------------------------
// Popover
// ---------------------------------------------------------------------------

/// What a left click on the icon shows.
///
/// Deliberately sparse: some counters, the latest prompts, three ways out.
/// The journal opens *inside* the popover rather than in a separate window —
/// checking what just went past is the common case, and sending the user to a
/// 900-point window for it is friction. The window stays one click away for
/// what a 320-point column genuinely cannot do: filtering and export.
struct PopoverView: View {
    @ObservedObject var model: AppModel
    let actions: PopoverActions

    private enum Page {
        case home
        case journal
    }

    @State private var page: Page = .home

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            switch page {
            case .home:
                header
                Divider()
                counters
                Divider()
                recent
                Divider()
                footer
            case .journal:
                PopoverJournalView(
                    onBack: { page = .home },
                    onOpenWindow: actions.openJournal
                )
            }
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
                Button("Journal") { page = .journal }
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

/// The journal, inside the popover.
///
/// Deliberately not the window's `Table`: six columns do not fit in 320 points,
/// and a popover you have to scroll sideways is worse than no popover at all.
/// Two lines per entry, newest first, and the full window one click away for
/// filtering and export.
private struct PopoverJournalView: View {
    let onBack: () -> Void
    let onOpenWindow: () -> Void

    @State private var entries: [JournalEntry] = []
    @State private var error: String?
    @State private var loading = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            content
        }
        .onAppear(perform: load)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Button(action: onBack) {
                Image(systemName: "chevron.backward")
            }
            .buttonStyle(.borderless)
            .help("Back")

            Text("Journal").font(.headline)

            Spacer()

            Button(action: onOpenWindow) {
                Image(systemName: "arrow.up.left.and.arrow.down.right")
            }
            .buttonStyle(.borderless)
            .help("Open the full journal — filtering and JSONL export")
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var content: some View {
        if loading {
            note("Reading the journal…")
        } else if let error {
            note(error)
        } else if entries.isEmpty {
            note("Nothing yet. Traffic from your MCP servers will appear here.")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(entries) { entry in
                        JournalRow(entry: entry)
                        Divider()
                    }
                }
            }
            // A definite height, not a `maxHeight`. A `ScrollView` has no
            // intrinsic height, and the popover is sized from the content's
            // fitting size — left to itself the list collapses to nothing.
            // Rows are a fixed height for exactly this reason, so the arithmetic
            // holds: few entries give a short bubble, many stop at the cap and
            // scroll.
            .frame(height: min(CGFloat(entries.count) * JournalRow.height, 320))
        }
    }

    private func note(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
    }

    private func load() {
        JournalEntry.loadRecent(limit: 200) { result in
            loading = false
            switch result {
            case .success(let rows): entries = rows
            case .failure(let failure): error = "\(failure)"
            }
        }
    }
}

/// One journal line, on two rows because 320 points is not a table.
private struct JournalRow: View {
    /// Fixed, divider included. The list computes its own height from this, so
    /// a row that grew to fit its text would desynchronise the two.
    static let height: CGFloat = 35

    let entry: JournalEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: icon)
                .font(.caption2)
                .foregroundStyle(tint)
                .frame(width: 11)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(entry.method)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer(minLength: 4)
                    Text(entry.timestamp, format: .dateTime.hour().minute().second())
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 4) {
                    Text(entry.server)
                    if !entry.scope.isEmpty {
                        Text("·")
                        // Truncated at the head: the tail of a path is what
                        // identifies the project, the prefix is always /Users/…
                        Text(entry.scope).lineLimit(1).truncationMode(.head)
                    }
                    if entry.verdict == "deny", let rule = entry.rule {
                        Text("·")
                        Text(rule).foregroundStyle(.red)
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
            }
        }
        .padding(.horizontal, 12)
        .frame(height: Self.height - 1, alignment: .center)
    }

    private var icon: String {
        if entry.verdict == "deny" { return "hand.raised.fill" }
        return entry.direction == "to_server" ? "arrow.up" : "arrow.down"
    }

    private var tint: Color {
        entry.verdict == "deny" ? .red : .secondary
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

extension JournalEntry {
    /// Reads the journal, newest first, off the main thread.
    ///
    /// `CoreCommand.run` spawns a process and waits for it. Doing that on the
    /// main thread stutters the popover's opening animation — which is exactly
    /// the moment the user is looking at it. The completion runs on the main
    /// queue, so callers can assign to `@State` directly.
    static func loadRecent(
        limit: Int,
        completion: @escaping (Result<[JournalEntry], Error>) -> Void
    ) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Result {
                let output = try CoreCommand.run(["log", "-n", "\(limit)", "--json"])
                // `mcpwall log` prints oldest first; the interface wants the
                // newest at the top.
                return Array(output.split(separator: "\n").compactMap { parse(String($0)) }.reversed())
            }
            DispatchQueue.main.async { completion(result) }
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
        JournalEntry.loadRecent(limit: 500) { result in
            switch result {
            case .success(let rows):
                entries = rows
                error = nil
            case .failure(let failure):
                error = "\(failure)"
            }
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
