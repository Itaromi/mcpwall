import AppKit
import SwiftUI

// ---------------------------------------------------------------------------
// Popover
// ---------------------------------------------------------------------------

/// Contenu du clic gauche sur l'icône.
///
/// Volontairement pauvre : des compteurs, les dernières demandes, trois portes
/// de sortie. Tout ce qui demande à être lu attentivement appartient à la
/// fenêtre Journal, pas à un panneau qui se ferme dès qu'on regarde ailleurs.
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
                Text(model.daemonConnected ? "actif" : "daemon injoignable")
                    .font(.caption)
                    .foregroundStyle(model.daemonConnected ? Color.secondary : Color.orange)
            }
            Spacer()
        }
        .padding(12)
    }

    private var counters: some View {
        HStack(spacing: 0) {
            counter("\(model.status.callsToday)", "appels")
            Divider().frame(height: 34)
            counter("\(model.status.blockedToday)", "bloqués")
            Divider().frame(height: 34)
            counter("\(model.status.activeSessions)", "serveurs")
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
            Text("Aucune demande aujourd'hui.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Text("Dernières demandes")
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
            // Le compteur de pertes n'est montré que s'il n'est pas nul : c'est
            // un signal de bug, pas un régime normal, et l'utilisateur a le
            // droit de savoir que son audit est incomplet.
            if model.status.droppedEntries > 0 {
                HStack {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                    Text("\(model.status.droppedEntries) entrées de journal perdues")
                        .font(.caption2)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.top, 8)
            }

            HStack(spacing: 8) {
                Button("Journal", action: actions.openJournal)
                Button("Politique", action: actions.openPolicy)
                Spacer()
                Menu {
                    Button("Réinstaller dans les clients MCP…", action: actions.runOnboarding)
                    Divider()
                    Button("Quitter mcpwall", action: actions.quit)
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

/// Fenêtre Journal.
///
/// Les données viennent de `mcpwall log --json` plutôt que d'un accès SQLite
/// depuis Swift. Un seul chemin de lecture, déjà couvert par les tests du core,
/// et aucun risque que l'interface tienne un verrou sur la base pendant que le
/// shim écrit.
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
                    "Journal illisible",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error)
                )
            } else if filtered.isEmpty {
                ContentUnavailableView(
                    "Aucune entrée",
                    systemImage: "tray",
                    description: Text("Le trafic de vos serveurs MCP apparaîtra ici.")
                )
            } else {
                table
            }
        }
        .onAppear(perform: reload)
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            TextField("Filtrer par outil, serveur ou projet", text: $filter)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 320)
            Toggle("Bloqués seulement", isOn: $onlyBlocked)
                .toggleStyle(.checkbox)
            Spacer()
            Button("Exporter JSONL…", action: export)
            Button(action: reload) { Image(systemName: "arrow.clockwise") }
        }
        .padding(10)
    }

    private var table: some View {
        Table(filtered) {
            TableColumn("Heure") { e in
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

            TableColumn("Méthode") { e in
                Text(e.method).font(.system(.caption, design: .monospaced))
            }

            TableColumn("Serveur") { e in Text(e.server).font(.caption) }
            TableColumn("Projet") { e in
                Text(e.scope).font(.caption).help("provenance : \(e.scopeSource)")
            }

            TableColumn("Verdict") { e in
                if let verdict = e.verdict, verdict == "deny" {
                    Label(e.rule ?? "bloqué", systemImage: "hand.raised.fill")
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
            method: dict["method"] as? String ?? "(réponse)",
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

/// Premier lancement.
///
/// **Critère de réussite : zéro terminal.** Si l'utilisateur doit copier-coller
/// du JSON après avoir monté le `.dmg`, l'onboarding a échoué. Le diff est
/// montré avant toute écriture, et un bouton unique remet tout en état.
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
                Text("Installer mcpwall dans vos clients MCP")
                    .font(.title2).bold()
                Text("mcpwall va envelopper les serveurs MCP déclarés dans vos configurations. "
                     + "Rien n'est écrit avant que vous ayez lu ce qui va changer, et tout est "
                     + "réversible en un clic.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            GroupBox("Ce qui va changer") {
                ScrollView {
                    Text(preview.isEmpty ? "Analyse en cours…" : preview)
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
                    "Terminé. Redémarrez vos clients MCP pour que la configuration prenne effet.",
                    systemImage: "checkmark.circle.fill"
                )
                .font(.callout)
                .foregroundStyle(.green)
            }

            HStack {
                Button("Tout remettre en état", action: restore)
                    .disabled(working)
                Spacer()
                Button("Plus tard", action: onDone)
                Button(applied ? "Fermer" : "Installer") {
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
// Appel du core
// ---------------------------------------------------------------------------

/// Exécute une sous-commande du binaire mcpwall.
///
/// L'interface ne réimplémente jamais ce que le core sait faire : lire le
/// journal, calculer un diff d'installation, restaurer des sauvegardes. Une
/// seule implémentation, déjà testée, et pas de dérive entre ce que la ligne de
/// commande fait et ce que l'app affiche.
enum CoreCommand {
    struct Failure: LocalizedError {
        let code: Int32
        let message: String
        var errorDescription: String? {
            message.isEmpty ? "le core a échoué (code \(code))" : message
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
