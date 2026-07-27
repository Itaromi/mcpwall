import Foundation

/// Lance et surveille `mcpwall daemon`.
///
/// L'app **ne réimplémente pas** le daemon : elle l'héberge comme processus
/// enfant. Une seule source de vérité pour la politique et les décisions, et le
/// core reste portable ailleurs que sur macOS.
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

    /// Arrête le daemon proprement.
    ///
    /// Appelé à la fermeture de l'app. Sans ça, le daemon survivrait à
    /// l'application censée l'héberger et son socket resterait en place, ce qui
    /// empêcherait le prochain démarrage.
    func stop() {
        queue.sync {
            stopping = true
            guard let process, process.isRunning else { return }
            process.terminate()

            // Laisser le temps du retrait du socket avant d'insister.
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
        // Le daemon écrit ses diagnostics sur stderr ; on les laisse aller au
        // journal système plutôt que de les mettre en tampon dans l'app.
        process.standardOutput = FileHandle.nullDevice

        process.terminationHandler = { [weak self] proc in
            guard let self else { return }
            self.queue.async {
                guard !self.stopping else { return }
                NSLog("mcpwall: daemon terminé (code \(proc.terminationStatus)), relance")
                self.scheduleRestart()
            }
        }

        do {
            lastStart = Date()
            try process.run()
            self.process = process
            NSLog("mcpwall: daemon démarré (pid \(process.processIdentifier))")
        } catch {
            NSLog("mcpwall: lancement du daemon impossible : \(error)")
            scheduleRestart()
        }
    }

    /// Relance avec un recul croissant.
    ///
    /// Un daemon qui échoue au démarrage — socket occupé, politique illisible —
    /// ne doit pas être relancé en boucle serrée : ça consommerait la machine
    /// sans jamais réussir, et noierait la cause réelle dans les journaux.
    private func scheduleRestart() {
        // Un daemon qui a tourné longtemps repart de zéro : c'est un incident
        // isolé, pas une boucle d'échec.
        if Date().timeIntervalSince(lastStart) > 60 {
            restarts = 0
        }
        restarts += 1

        guard restarts <= 10 else {
            NSLog("mcpwall: le daemon échoue en boucle, relance abandonnée")
            return
        }

        let delay = min(pow(2.0, Double(restarts - 1)), 30.0)
        queue.asyncAfter(deadline: .now() + delay) { [weak self] in
            self?.launch()
        }
    }
}
