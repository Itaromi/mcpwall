import AppKit
import SwiftUI

/// Panneau de décision.
///
/// **Pas un `NSPopover`.** Un popover se ferme à la perte de focus et ne
/// s'affiche pas au-dessus d'un terminal en plein écran — c'est-à-dire
/// exactement la situation dans laquelle l'utilisateur se trouve quand son
/// agent tourne. Le panneau doit apparaître par-dessus ce qu'il fait, sans
/// voler le focus au clavier.
final class DecisionPanelController {
    private var panels: [UInt64: NSPanel] = [:]
    private let onDecision: (UInt64, Bool, Until) -> Void

    init(onDecision: @escaping (UInt64, Bool, Until) -> Void) {
        self.onDecision = onDecision
    }

    func present(_ prompt: Prompt) {
        // Une seule fenêtre par demande, même si le daemon renvoie la demande.
        guard panels[prompt.promptID] == nil else { return }

        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 300),
            styleMask: [.titled, .nonactivatingPanel, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )

        panel.title = "mcpwall"
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        panel.isMovableByWindowBackground = true
        panel.hidesOnDeactivate = false

        // Au-dessus du terminal, y compris en plein écran, et sur tous les
        // bureaux : l'utilisateur ne doit pas avoir à chercher la fenêtre.
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

        // Le panneau ne prend le clavier que si l'utilisateur y va. Voler le
        // focus pendant qu'on tape dans son terminal serait une agression.
        panel.becomesKeyOnlyIfNeeded = true

        let view = DecisionView(
            prompt: prompt,
            onDecide: { [weak self] allow, until in
                self?.dismiss(prompt.promptID)
                self?.onDecision(prompt.promptID, allow, until)
            }
        )
        panel.contentView = NSHostingView(rootView: view)
        panel.setContentSize(panel.contentView?.fittingSize ?? NSSize(width: 460, height: 300))

        position(panel, index: panels.count)
        panels[prompt.promptID] = panel
        panel.orderFrontRegardless()

        NSApp.requestUserAttention(.informationalRequest)
    }

    /// Retire un panneau sans décision — demande expirée côté daemon.
    ///
    /// Sans ça, l'utilisateur verrait des boutons qui ne feraient plus rien et
    /// croirait avoir décidé quelque chose.
    func dismiss(_ promptID: UInt64) {
        guard let panel = panels.removeValue(forKey: promptID) else { return }
        panel.orderOut(nil)
        panel.close()
    }

    func dismissAll() {
        for id in panels.keys { dismiss(id) }
    }

    /// Empile les panneaux depuis le coin haut-droit, sous la barre de menus.
    private func position(_ panel: NSPanel, index: Int) {
        guard let screen = NSScreen.main else { return }
        let visible = screen.visibleFrame
        let size = panel.frame.size
        let offset = CGFloat(index) * 24

        panel.setFrameOrigin(NSPoint(
            x: visible.maxX - size.width - 20,
            y: visible.maxY - size.height - 20 - offset
        ))
    }
}

/// Contenu du panneau.
private struct DecisionView: View {
    let prompt: Prompt
    let onDecide: (Bool, Until) -> Void

    @State private var remaining: Int

    init(prompt: Prompt, onDecide: @escaping (Bool, Until) -> Void) {
        self.prompt = prompt
        self.onDecide = onDecide
        _remaining = State(initialValue: Int(prompt.timeoutSeconds))
    }

    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            Divider()
            details
            if !prompt.findings.isEmpty { findings }
            Divider()
            buttons
        }
        .padding(18)
        .frame(width: 460)
        .onReceive(ticker) { _ in
            if remaining > 0 { remaining -= 1 }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: severityIcon)
                .font(.title2)
                .foregroundStyle(severityColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(prompt.message)
                    .font(.headline)
                Text(prompt.title)
                    .font(.system(.subheadline, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            // Le compte à rebours est une information, pas une pression :
            // l'expiration refuse, elle n'autorise jamais.
            Text("\(remaining)s")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .help("À l'expiration, l'appel est refusé.")
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            row("Serveur", prompt.server ?? "inconnu")
            row("Projet", projectLabel)
            if let rule = prompt.rule { row("Règle", rule) }

            Text("Arguments")
                .font(.caption)
                .foregroundStyle(.secondary)
            ScrollView {
                Text(prompt.preview)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 80)
            .padding(8)
            .background(Color.secondary.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
    }

    private var findings: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(prompt.findings, id: \.self) { finding in
                Label(finding, systemImage: "key.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    private var buttons: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Button("Bloquer") { onDecide(false, .once) }
                    .keyboardShortcut(.cancelAction)
                Button("Autoriser une fois") { onDecide(true, .once) }
                Button("Autoriser cette session") { onDecide(true, .session) }
                    .keyboardShortcut(.defaultAction)
            }

            if prompt.foreverAllowed {
                Button("Toujours autoriser pour ce projet") { onDecide(true, .forever) }
                    .buttonStyle(.link)
                    .font(.caption)
            } else {
                // On n'offre pas un bouton dont l'effet ne serait pas celui
                // annoncé : le daemon rétrograderait la décision, parce que la
                // provenance du projet n'est pas assez sûre pour qu'une
                // permission permanente ne fuie pas ailleurs.
                Text("« Toujours » indisponible : le projet n'a pas pu être identifié de façon fiable.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .trailing)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 60, alignment: .leading)
            Text(value)
                .font(.caption)
                .textSelection(.enabled)
                .lineLimit(2)
        }
    }

    private var projectLabel: String {
        let name = prompt.scopeKey.hasPrefix("project:")
            ? String(prompt.scopeKey.dropFirst("project:".count))
            : "inconnu"
        return "\(name)  (\(prompt.scopeSource))"
    }

    private var severityIcon: String {
        switch prompt.severity {
        case "critical": return "exclamationmark.octagon.fill"
        case "high": return "exclamationmark.triangle.fill"
        default: return "questionmark.circle.fill"
        }
    }

    private var severityColor: Color {
        switch prompt.severity {
        case "critical": return .red
        case "high": return .orange
        default: return .accentColor
        }
    }
}
