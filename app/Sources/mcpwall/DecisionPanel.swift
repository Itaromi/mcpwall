import AppKit
import SwiftUI

/// The decision panel.
///
/// **Not an `NSPopover`.** A popover closes when it loses focus and does not
/// show above a full-screen terminal — which is exactly the situation the user
/// is in while their agent runs. The panel must appear over whatever they are
/// doing, without stealing keyboard focus.
final class DecisionPanelController {
    private var panels: [UInt64: NSPanel] = [:]
    private let onDecision: (UInt64, Bool, Until) -> Void

    init(onDecision: @escaping (UInt64, Bool, Until) -> Void) {
        self.onDecision = onDecision
    }

    func present(_ prompt: Prompt) {
        // One window per prompt, even if the daemon re-sends the prompt.
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

        // Above the terminal, full screen included, and on every desktop: the
        // user must not have to go looking for the window.
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .transient]

        // The panel only takes the keyboard if the user goes to it. Stealing
        // focus while someone is typing in their terminal would be an assault.
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

    /// Removes a panel with no decision — the prompt expired daemon-side.
    ///
    /// Without this, the user would see buttons that no longer do anything and
    /// would believe they had decided something.
    func dismiss(_ promptID: UInt64) {
        guard let panel = panels.removeValue(forKey: promptID) else { return }
        panel.orderOut(nil)
        panel.close()
    }

    func dismissAll() {
        for id in panels.keys { dismiss(id) }
    }

    /// Stacks the panels from the top-right corner, under the menu bar.
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

/// Panel contents.
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
            // The countdown is information, not pressure: expiry refuses, it
            // never allows.
            Text("\(remaining)s")
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .help("On expiry, the call is denied.")
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            row("Server", prompt.server ?? "unknown")
            row("Project", projectLabel)
            if let rule = prompt.rule { row("Rule", rule) }

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
                Button("Block") { onDecide(false, .once) }
                    .keyboardShortcut(.cancelAction)
                Button("Allow once") { onDecide(true, .once) }
                Button("Allow this session") { onDecide(true, .session) }
                    .keyboardShortcut(.defaultAction)
            }

            if prompt.foreverAllowed {
                Button("Always allow for this project") { onDecide(true, .forever) }
                    .buttonStyle(.link)
                    .font(.caption)
            } else {
                // We do not offer a button whose effect would not be the one
                // advertised: the daemon would downgrade the decision, because
                // the project's provenance is not certain enough to keep a
                // permanent permission from leaking elsewhere.
                Text("\"Always\" unavailable: the project could not be identified reliably.")
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
            : "unknown"
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
