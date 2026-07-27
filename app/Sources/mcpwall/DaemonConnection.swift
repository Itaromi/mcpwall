import Foundation

/// Messages reçus du daemon.
enum ServerMessage {
    case prompt(Prompt)
    case withdraw(promptID: UInt64)
    case status(Status)
}

struct Prompt: Identifiable, Equatable {
    let promptID: UInt64
    let method: String
    let tool: String?
    let server: String?
    let preview: String
    let rule: String?
    let severity: String
    let message: String
    let findings: [String]
    let scopeKey: String
    let scopeSource: String
    /// Si faux, l'interface **ne doit pas** proposer « Toujours autoriser ».
    /// Le daemon rétrograderait de toute façon la décision, mais offrir un
    /// bouton dont l'effet n'est pas celui annoncé est pire qu'un bouton absent.
    let foreverAllowed: Bool
    let timeoutSeconds: UInt64

    var id: UInt64 { promptID }

    /// Ce qui est demandé, en une ligne.
    var title: String {
        if let tool { return tool }
        return method
    }
}

struct Status: Equatable {
    var callsToday: Int = 0
    var blockedToday: Int = 0
    var activeSessions: Int = 0
    var pendingPrompts: Int = 0
    var droppedEntries: Int = 0
    var policyPath: String = ""
    var uiConnected: Bool = false
}

enum Until: String {
    case once, session, forever
}

/// Connexion au daemon, en I/O bloquante sur un thread dédié.
///
/// Le protocole est du JSON délimité par retour ligne ; une boucle de lecture
/// suffit et évite d'avoir à raisonner sur des lectures partielles dans le code
/// d'interface.
///
/// La connexion se rétablit toute seule : le daemon peut être redémarré, mis à
/// jour, ou simplement plus lent à démarrer que l'app qui l'a lancé.
final class DaemonConnection: @unchecked Sendable {
    /// Doit correspondre à `IPC_VERSION` côté Rust.
    static let ipcVersion: UInt32 = 2

    private let socketPath: String

    /// Boucle de lecture. Elle **bloque** pour toute la durée de la connexion.
    private let readQueue = DispatchQueue(label: "mcpwall.ipc.read")

    /// Écritures. Une file distincte, et ce n'est pas un détail : poster les
    /// envois sur la file de lecture les mettait en attente derrière une
    /// lecture bloquante qui ne rend jamais la main. `subscribe` n'était donc
    /// jamais envoyé, et les boutons du panneau n'auraient rien fait.
    private let writeQueue = DispatchQueue(label: "mcpwall.ipc.write")

    /// Protège `fd`, partagé entre les deux files.
    private let lock = NSLock()
    private var fd: Int32 = -1

    /// N'est touché que depuis `readQueue`.
    private var readBuffer = Data()

    private let runFlag = NSLock()
    private var _shouldRun = true
    private var shouldRun: Bool {
        get { runFlag.lock(); defer { runFlag.unlock() }; return _shouldRun }
        set { runFlag.lock(); _shouldRun = newValue; runFlag.unlock() }
    }

    /// Appelés sur la file principale.
    var onMessage: ((ServerMessage) -> Void)?
    var onConnectionChange: ((Bool) -> Void)?

    private(set) var isConnected = false {
        didSet {
            guard isConnected != oldValue else { return }
            let value = isConnected
            DispatchQueue.main.async { [weak self] in self?.onConnectionChange?(value) }
        }
    }

    init(socketPath: String) {
        self.socketPath = socketPath
    }

    func start() {
        readQueue.async { [weak self] in self?.runLoop() }
    }

    func stop() {
        // Pas de saut de file : `readQueue` est occupée par une lecture
        // bloquante, y poster l'arrêt ne servirait à rien. On ferme le
        // descripteur, ce qui fait rendre la lecture.
        shouldRun = false
        closeConnection()
    }

    // MARK: - Envoi

    func answer(promptID: UInt64, allow: Bool, until: Until) {
        send([
            "type": "answer",
            "prompt_id": Int(promptID),
            "allow": allow,
            "until": until.rawValue,
        ])
    }

    func requestStatus() {
        send(["type": "status"])
    }

    private func send(_ object: [String: Any]) {
        writeQueue.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let fd = self.fd
            self.lock.unlock()
            guard fd >= 0, !Self.write(object, to: fd) else { return }
            // Le daemon est parti. La boucle de lecture s'en apercevra et
            // relancera la connexion ; inutile de le traiter deux fois.
            self.closeConnection()
        }
    }

    // MARK: - Boucle

    private func runLoop() {
        while shouldRun {
            guard connect() else {
                // Attente avant nouvelle tentative. Assez court pour que
                // l'utilisateur ne voie pas l'app « déconnectée » longtemps
                // après avoir relancé le daemon, assez long pour ne pas
                // marteler le système de fichiers.
                Thread.sleep(forTimeInterval: 1.0)
                continue
            }
            readUntilClosed()
            closeConnection()
            if shouldRun { Thread.sleep(forTimeInterval: 1.0) }
        }
    }

    /// Dernier échec journalisé.
    ///
    /// On tait les **répétitions** — une boucle de reconnexion qui écrit une
    /// ligne par seconde noie le journal — mais jamais un motif d'échec
    /// différent : c'est exactement celui-là qui explique l'incident.
    private var lastFailure: String?

    private func connect() -> Bool {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            logFailure("socket() : \(String(cString: strerror(errno)))")
            return false
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = Array(socketPath.utf8)
        // `sun_path` fait 104 octets sur macOS. Un dépassement silencieux
        // produirait une connexion vers un chemin tronqué, donc vers rien.
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            logFailure("chemin de socket trop long : \(socketPath)")
            close(sock)
            return false
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(sock, sa, size)
            }
        }
        guard result == 0 else {
            logFailure("connect(\(socketPath)) : \(String(cString: strerror(errno)))")
            close(sock)
            return false
        }

        lock.lock()
        fd = sock
        lock.unlock()
        readBuffer.removeAll(keepingCapacity: true)

        // Handshake, puis abonnement. Les deux sont écrits ici, sur le même
        // chemin : ils font partie de l'établissement de la connexion, pas du
        // trafic courant.
        //
        // Faire passer `subscribe` par `writeQueue` le perdait — la file n'est
        // pas encore en service à cet instant. L'app tournait alors sans jamais
        // recevoir de demande, et le daemon refusait chaque `ask` en expliquant
        // qu'aucune interface n'était là pour confirmer.
        let hello: [String: Any] = [
            "mcpwall_ipc": Int(Self.ipcVersion),
            "build": Bundle.main.shortVersion,
        ]
        guard Self.write(hello, to: sock) else {
            logFailure("envoi du hello impossible")
            closeConnection()
            return false
        }
        guard readHello() else {
            closeConnection()
            return false
        }
        guard Self.write(["type": "subscribe"], to: sock) else {
            logFailure("abonnement impossible")
            closeConnection()
            return false
        }
        Self.write(["type": "status"], to: sock)

        lastFailure = nil
        NSLog("mcpwall: connecté au daemon")
        isConnected = true
        return true
    }

    private func readHello() -> Bool {
        guard let line = readLine() else {
            logFailure("aucune réponse au hello")
            return false
        }
        // `as? UInt32` échouerait : le pont NSNumber ne convertit que vers les
        // types larges. On passe par `Int`, seule forme garantie.
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)),
              let dict = object as? [String: Any],
              let version = dict["mcpwall_ipc"] as? Int
        else {
            logFailure("hello du daemon illisible : \(line)")
            return false
        }

        guard version == Int(Self.ipcVersion) else {
            // Le daemon n'est pas celui qu'on croit — typiquement un daemon
            // resté en place après une mise à jour de l'app. On refuse plutôt
            // que d'interpréter au mieux des messages qu'on ne comprend pas.
            logFailure("version IPC incompatible (daemon \(version), app \(Self.ipcVersion))")
            return false
        }
        return true
    }

    private func readUntilClosed() {
        while shouldRun, let line = readLine() {
            guard let message = Self.decode(line) else { continue }
            DispatchQueue.main.async { [weak self] in self?.onMessage?(message) }
        }
    }

    // MARK: - Entrées/sorties

    /// Écrit un objet suivi d'un retour ligne.
    ///
    /// Appels système directs plutôt que `FileHandle` : ce dernier est conçu
    /// pour les fichiers et les tubes, et son écriture bloquait indéfiniment
    /// sur un socket Unix — quarante octets qui ne partaient jamais, sans
    /// erreur ni trace.
    @discardableResult
    private static func write(_ object: [String: Any], to fd: Int32) -> Bool {
        guard var data = try? JSONSerialization.data(withJSONObject: object) else { return false }
        data.append(0x0A)

        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var sent = 0
            while sent < raw.count {
                // `send` avec MSG_NOSIGNAL n'existe pas sur Darwin ; SIGPIPE est
                // désactivé à l'ouverture du socket par SO_NOSIGPIPE.
                let n = Darwin.write(fd, base.advanced(by: sent), raw.count - sent)
                if n > 0 {
                    sent += n
                } else if n < 0 && errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }

    /// Lit une ligne, en accumulant les lectures partielles.
    private func readLine() -> String? {
        while true {
            if let index = readBuffer.firstIndex(of: 0x0A) {
                let lineData = readBuffer[readBuffer.startIndex..<index]
                readBuffer.removeSubrange(readBuffer.startIndex...index)
                return String(data: lineData, encoding: .utf8)
            }

            lock.lock()
            let fd = self.fd
            lock.unlock()
            guard fd >= 0 else { return nil }

            var chunk = [UInt8](repeating: 0, count: 64 * 1024)
            let n = chunk.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return Darwin.read(fd, base, raw.count)
            }
            if n > 0 {
                readBuffer.append(contentsOf: chunk[0..<n])
            } else if n < 0 && errno == EINTR {
                continue
            } else {
                return nil
            }
        }
    }

    private func logFailure(_ message: String) {
        guard lastFailure != message else { return }
        lastFailure = message
        NSLog("mcpwall: \(message)")
    }

    private func closeConnection() {
        isConnected = false
        lock.lock()
        let old = fd
        fd = -1
        lock.unlock()
        if old >= 0 { close(old) }
    }

    // MARK: - Décodage

    static func decode(_ line: String) -> ServerMessage? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)),
              let dict = object as? [String: Any],
              let type = dict["type"] as? String
        else { return nil }

        switch type {
        case "prompt":
            guard let id = dict["prompt_id"] as? UInt64 else { return nil }
            return .prompt(Prompt(
                promptID: id,
                method: dict["method"] as? String ?? "",
                tool: dict["tool"] as? String,
                server: dict["server"] as? String,
                preview: dict["preview"] as? String ?? "",
                rule: dict["rule"] as? String,
                severity: dict["severity"] as? String ?? "info",
                message: dict["message"] as? String ?? "",
                findings: dict["findings"] as? [String] ?? [],
                scopeKey: dict["scope_key"] as? String ?? "",
                scopeSource: dict["scope_source"] as? String ?? "unknown",
                foreverAllowed: dict["forever_allowed"] as? Bool ?? false,
                timeoutSeconds: dict["timeout_seconds"] as? UInt64 ?? 60
            ))

        case "withdraw":
            guard let id = dict["prompt_id"] as? UInt64 else { return nil }
            return .withdraw(promptID: id)

        case "status":
            return .status(Status(
                callsToday: dict["calls_today"] as? Int ?? 0,
                blockedToday: dict["blocked_today"] as? Int ?? 0,
                activeSessions: dict["active_sessions"] as? Int ?? 0,
                pendingPrompts: dict["pending_prompts"] as? Int ?? 0,
                droppedEntries: dict["dropped_entries"] as? Int ?? 0,
                policyPath: dict["policy_path"] as? String ?? "",
                uiConnected: dict["ui_connected"] as? Bool ?? false
            ))

        // `verdict` circule sur les connexions de shim, jamais ici. On l'ignore
        // sans bruit plutôt que de le traiter comme une anomalie.
        default:
            return nil
        }
    }
}

extension Bundle {
    var shortVersion: String {
        (infoDictionary?["CFBundleShortVersionString"] as? String) ?? "dev"
    }
}
