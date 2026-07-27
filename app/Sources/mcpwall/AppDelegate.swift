import AppKit
import SwiftUI

/// Emplacements partagés avec le core. Doivent rester alignés sur `ipc.rs`.
enum Paths {
    static var home: URL {
        FileManager.default.homeDirectoryForCurrentUser
    }
    static var root: URL { home.appendingPathComponent(".mcpwall") }
    static var socket: URL { root.appendingPathComponent("daemon.sock") }
    static var policy: URL { root.appendingPathComponent("policy.yaml") }
    static var journal: URL { root.appendingPathComponent("journal.db") }

    /// Lien symbolique stable vers le binaire.
    ///
    /// Les configurations MCP pointent vers **ce lien**, jamais vers le chemin
    /// du bundle : sinon déplacer l'app depuis le Finder casserait tous les
    /// serveurs MCP de l'utilisateur.
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
        // `LSUIElement` dans l'Info.plist met déjà l'app hors du Dock ; on le
        // pose aussi ici pour que `swift run` se comporte comme le bundle.
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

        // Rafraîchissement des compteurs du popover.
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            self?.connection.requestStatus()
        }

        if !hasCompletedOnboarding {
            showOnboarding()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        connection?.stop()
        // Le daemon est un enfant de cette app : le laisser derrière soi serait
        // exactement l'orphelin qu'on reproche aux autres.
        supervisor?.stop()
    }

    // MARK: - Barre de menus

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

    /// Icône en image template : macOS l'inverse automatiquement en thème clair
    /// et sombre, et on n'a pas deux jeux d'images à tenir synchronisés.
    private func refreshIcon() {
        guard let button = statusItem?.button else { return }

        let name = model.daemonConnected ? "shield.lefthalf.filled" : "shield.slash"
        let image = NSImage(systemSymbolName: name, accessibilityDescription: "mcpwall")
        image?.isTemplate = true
        button.image = image

        // Badge chiffré uniquement s'il y a eu des blocages : au repos, la
        // barre de menus doit rester silencieuse.
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

    // MARK: - Messages du daemon

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

    // MARK: - Fenêtres

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
        window.title = "Journal mcpwall"
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
        window.title = "Installer mcpwall"
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

    // MARK: - Binaire embarqué

    /// Le binaire du core, embarqué dans le bundle.
    ///
    /// En développement (`swift run`), on retombe sur la cible Cargo pour que
    /// l'app soit utilisable sans avoir à assembler un bundle à chaque fois.
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

    /// (Re)crée le lien symbolique stable vers le binaire embarqué.
    ///
    /// Refait à chaque lancement : c'est ce qui permet de déplacer l'app ou de
    /// la mettre à jour sans que les configurations MCP cessent de fonctionner.
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
            NSLog("mcpwall: lien du shim non créé : \(error)")
        }
    }

    private var hasCompletedOnboarding: Bool {
        get { UserDefaults.standard.bool(forKey: "onboardingDone") }
        set { UserDefaults.standard.set(newValue, forKey: "onboardingDone") }
    }
}

/// État partagé avec les vues.
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
