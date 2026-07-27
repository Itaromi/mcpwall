import Foundation

/// Starts and supervises `mcpwall daemon`.
///
/// The app **does not reimplement** the daemon: it hosts it as a child process.
/// One source of truth for the policy and the decisions, and the core stays
/// portable beyond macOS.
final class DaemonSupervisor: @unchecked Sendable {
    private let binary: URL
    private var process: Process?
    private let queue = DispatchQueue(label: "mcpwall.supervisor")
    private var stopping = false
    private var restarts = 0
    private var lastStart = Date.distantPast

    init(binary: URL) {
        self.binary = binary
    }

    var isRunning: Bool { process?.isRunning ?? false }

    func start() {
        queue.async { [weak self] in self?.launch() }
    }

    /// Stops the daemon cleanly.
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
        process.arguments = ["daemon"]
        // The daemon writes its diagnostics to stderr; we let them go to the
        // system log rather than buffering them inside the app.
        process.standardOutput = FileHandle.nullDevice

        process.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.queue.async {
                guard !self.stopping else { return }
                NSLog("mcpwall: daemon exited (code \(proc.terminationStatus)), restarting")
                self.scheduleRestart()
            }
        }

        do {
            lastStart = Date()
            try process.run()
            self.process = process
            NSLog("mcpwall: daemon started (pid \(process.processIdentifier))")
        } catch {
            NSLog("mcpwall: could not start the daemon: \(error)")
            scheduleRestart()
        }
    }

    /// Restarts with exponential backoff.
    ///
    /// A daemon that fails at startup — socket taken, policy unreadable — must
    /// not be restarted in a tight loop: that would burn the machine without
    /// ever succeeding, and drown the real cause in the logs.
    private func scheduleRestart() {
        // A daemon that ran for a long time starts from zero again: that is an
        // isolated incident, not a failure loop.
        if Date().timeIntervalSince(lastStart) > 60 {
            restarts = 0
        }
        restarts += 1

        guard restarts <= 10 else {
            NSLog("mcpwall: the daemon keeps failing, giving up on restarting")
            return
        }

        let delay = min(pow(2.0, Double(restarts - 1)), 30.0)
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.launch()
        }
    }
}
