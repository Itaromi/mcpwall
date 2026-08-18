import Foundation

/// Starts and supervises one long-lived `mcpwall` subcommand.
///
/// The app **does not reimplement** anything it hosts: the daemon and the HTTP
/// proxy are child processes. One source of truth for the policy and the
/// decisions, and the core stays portable beyond macOS.
///
/// Two of these run. The daemon can be absent without breaking a session — the
/// shims fail open. The proxy cannot: MCP clients have been pointed at its URL,
/// so while it is down the servers routed through it are unreachable. Same
/// supervision either way; the difference is what it costs when it fails, and
/// it is why the proxy is supervised at all rather than started on demand.
final class DaemonSupervisor: @unchecked Sendable {
    private let binary: URL
    private let subcommand: String
    private var process: Process?
    private let queue = DispatchQueue(label: "mcpwall.supervisor")
    private var stopping = false
    private var restarts = 0
    private var lastStart = Date.distantPast

    init(binary: URL, subcommand: String = "daemon") {
        self.binary = binary
        self.subcommand = subcommand
    }

    var isRunning: Bool { process?.isRunning ?? false }

    func start() {
        queue.async { [weak self] in self?.launch() }
    }

    /// Stops the child cleanly.
    ///
    /// Called when the app closes. Without this, the daemon would outlive the
    /// application meant to host it and its socket would stay behind, which
    /// would prevent the next start.
    func stop() {
        queue.sync {
            stopping = true
            guard let process, process.isRunning else { return }
            process.terminate()

            // Allow time for the socket to be removed before insisting.
            let deadline = Date().addingTimeInterval(3)
            while process.isRunning && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.05)
            }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
            }
        }
    }

    private func launch() {
        guard !stopping else { return }

        let process = Process()
        process.executableURL = binary
        process.arguments = [subcommand]
        // Diagnostics go to stderr; we let them reach the system log rather
        // than buffering them inside the app.
        process.standardOutput = FileHandle.nullDevice

        process.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.queue.async {
                guard !self.stopping else { return }
                NSLog("mcpwall: \(self.subcommand) exited (code \(proc.terminationStatus)), restarting")
                self.scheduleRestart()
            }
        }

        do {
            lastStart = Date()
            try process.run()
            self.process = process
            NSLog("mcpwall: \(subcommand) started (pid \(process.processIdentifier))")
        } catch {
            NSLog("mcpwall: could not start \(subcommand): \(error)")
            scheduleRestart()
        }
    }

    /// Restarts with exponential backoff.
    ///
    /// A child that fails at startup — socket taken, port taken, policy
    /// unreadable — must not be restarted in a tight loop: that would burn the
    /// machine without ever succeeding, and drown the real cause in the logs.
    private func scheduleRestart() {
        // A child that ran for a long time starts from zero again: that is an
        // isolated incident, not a failure loop.
        if Date().timeIntervalSince(lastStart) > 60 {
            restarts = 0
        }
        restarts += 1

        guard restarts <= 10 else {
            NSLog("mcpwall: \(subcommand) keeps failing, giving up on restarting")
            return
        }

        let delay = min(pow(2.0, Double(restarts - 1)), 30.0)
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.launch()
        }
    }
}
