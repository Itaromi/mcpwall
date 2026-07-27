import AppKit
import SwiftUI

/// Locations shared with the core. Must stay in step with `ipc.rs`.
enum Paths {
    static var home: URL {
        FileManager.default.homeDirectoryForCurrentUser
    }
    static var root: URL { home.appendingPathComponent(".mcpwall") }
    static var socket: URL { root.appendingPathComponent("daemon.sock") }
    static var policy: URL { root.appendingPathComponent("policy.yaml") }
    static var journal: URL { root.appendingPathComponent("journal.db") }

    /// Stable symlink to the binary.
    ///
    /// MCP configurations point at **this link**, never at the bundle path:
    /// otherwise moving the app from the Finder would break every one of the
    /// user's MCP servers.
    static var shimLink: URL { root.appendingPathComponent("bin/mcpwall") }
}

@main
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var connection: DaemonConnection!
    private var supervisor: DaemonSupervisor!
    private var panels: DecisionPanelController!
    private var journalWindow: NSWindow?
    private var onboardingWindow: NSWindow?

    private let model = AppModel()

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        // `LSUIElement` in the Info.plist already keeps the app out of the
        // Dock; we set it here too so `swift run` behaves like the bundle.
        app.setActivationPolicy(.accessory)
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installShimLink()
        setUpStatusItem()

        let binary = embeddedBinary()
        supervisor = DaemonSupervisor(binary: binary)
        supervisor.start()

        panels = DecisionPanelController { [weak self] id, allow, until in
            self?.connection.answer(promptID: id, allow: allow, until: until)
        }

        connection = DaemonConnection(socketPath: Paths.socket.path)
        connection.onMessage = { [weak self] message in self?.handle(message) }
        connection.onConnectionChange = { [weak self] connected in
            self?.model.daemonConnected = connected
            if !connected { self?.panels.dismissAll() }
            self?.refreshIcon()
        }
        connection.start()

        // Refresh the popover counters.
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.connection.requestStatus()
        }

        if !hasCompletedOnboarding {
            showOnboarding()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        connection?.stop()
        // The daemon is a child of this app: leaving it behind would be exactly
        // the orphan we criticise others for.
        supervisor?.stop()
    }

    // MARK: - Menu bar

    private func setUpStatusItem() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        refreshIcon()

        statusItem.button?.action = #selector(togglePopover)
        statusItem.button?.target = self

        popover = NSPopover()
        popover.behavior = .transient
        popover.contentSize = NSSize(width: 320, height: 420)
        popover.contentViewController = NSHostingController(
            rootView: PopoverView(model: model, actions: PopoverActions(
                openJournal: { [weak self] in self?.showJournal() },
                openPolicy: { NSWorkspace.shared.open(Paths.policy) },
                runOnboarding: { [weak self] in self?.showOnboarding() },
                quit: { NSApp.terminate(nil) }
            ))
        )
    }

    /// Template image icon: macOS inverts it automatically for light and dark
    /// themes, and we do not have two image sets to keep in sync.
    private func refreshIcon() {
        guard let button = statusItem?.button else { return }

        let name = model.daemonConnected ? "shield.lefthalf.filled" : "shield.slash"
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "mcpwall")
        image?.isTemplate = true
        button.image = image

        // A numbered badge only when there have been blocks: at rest, the menu
        // bar must stay silent.
        button.title = model.status.blockedToday > 0 ? " \(model.status.blockedToday)" : ""
    }

    @objc private func togglePopover() {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(nil)
        } else {
            connection.requestStatus()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    // MARK: - Daemon messages

    private func handle(_ message: ServerMessage) {
        switch message {
        case .prompt(let prompt):
            model.recent.insert(prompt, at: 0)
            model.recent = Array(model.recent.prefix(10))
            panels.present(prompt)

        case .withdraw(let id):
            panels.dismiss(id)

        case .status(let status):
            model.status = status
            refreshIcon()
        }
    }

    // MARK: - Windows

    private func showJournal() {
        popover.performClose(nil)

        if let window = journalWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 560),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "mcpwall Journal"
        window.center()
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(rootView: JournalView())
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        journalWindow = window
    }

    private func showOnboarding() {
        popover.performClose(nil)

        if let window = onboardingWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 620, height: 520),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "Install mcpwall"
        window.center()
        window.isReleasedWhenClosed = false
        window.contentView = NSHostingView(
            rootView: OnboardingView(binary: embeddedBinary()) { [weak self] in
                self?.hasCompletedOnboarding = true
                self?.onboardingWindow?.close()
                self?.onboardingWindow = nil
            }
        )
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        onboardingWindow = window
    }

    // MARK: - Embedded binary

    /// The core binary, embedded in the bundle.
    ///
    /// In development (`swift run`) we fall back to the Cargo target so the app
    /// is usable without assembling a bundle every time.
    private func embeddedBinary() -> URL {
        if let path = Bundle.main.path(forResource: "mcpwall", ofType: nil) {
            return URL(fileURLWithPath: path)
        }
        let candidates = [
            "target/release/mcpwall",
            "target/debug/mcpwall",
            "../target/release/mcpwall",
            "../target/debug/mcpwall",
        ]
        let cwd = FileManager.default.currentDirectoryPath
        for candidate in candidates {
            let url = URL(fileURLWithPath: cwd).appendingPathComponent(candidate)
            if FileManager.default.isExecutableFile(atPath: url.path) { return url }
        }
        return URL(fileURLWithPath: "/usr/local/bin/mcpwall")
    }

    /// (Re)creates the stable symlink to the embedded binary.
    ///
    /// Remade on every launch: that is what lets the app be moved or updated
    /// without the MCP configurations ceasing to work.
    private func installShimLink() {
        let fm = FileManager.default
        let link = Paths.shimLink
        do {
            try fm.createDirectory(
                at: link.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            if (try? fm.destinationOfSymbolicLink(atPath: link.path)) != nil
                || fm.fileExists(atPath: link.path) {
                try fm.removeItem(at: link)
            }
            try fm.createSymbolicLink(at: link, withDestinationURL: embeddedBinary())
        } catch {
            NSLog("mcpwall: shim link not created: \(error)")
        }
    }

    private var hasCompletedOnboarding: Bool {
        get { UserDefaults.standard.bool(forKey: "onboardingDone") }
        set { UserDefaults.standard.set(newValue, forKey: "onboardingDone") }
    }
}

/// State shared with the views.
final class AppModel: ObservableObject {
    @Published var status = Status()
    @Published var daemonConnected = false
    @Published var recent: [Prompt] = []
}

struct PopoverActions {
    let openJournal: () -> Void
    let openPolicy: () -> Void
    let runOnboarding: () -> Void
    let quit: () -> Void
}
