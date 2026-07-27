import Foundation

/// Messages received from the daemon.
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
    /// If false, the interface **must not** offer "Always allow". The daemon
    /// would downgrade the decision anyway, but offering a button whose effect
    /// is not the one advertised is worse than an absent button.
    let foreverAllowed: Bool
    let timeoutSeconds: UInt64

    var id: UInt64 { promptID }

    /// What is being asked, in one line.
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

/// Connection to the daemon, in blocking I/O on a dedicated thread.
///
/// The protocol is newline-delimited JSON; a single read loop is enough and
/// avoids having to reason about partial reads in the interface code.
///
/// The connection re-establishes itself: the daemon may be restarted, updated,
/// or simply slower to start than the app that launched it.
final class DaemonConnection: @unchecked Sendable {
    /// Must match `IPC_VERSION` on the Rust side.
    static let ipcVersion: UInt32 = 2

    private let socketPath: String

    /// Read loop. It **blocks** for the whole lifetime of the connection.
    private let readQueue = DispatchQueue(label: "mcpwall.ipc.read")

    /// Writes. A separate queue, and that is not a detail: posting sends onto
    /// the read queue left them stuck behind a blocking read that never returns.
    /// `subscribe` was therefore never sent, and the panel's buttons would have
    /// done nothing.
    private let writeQueue = DispatchQueue(label: "mcpwall.ipc.write")

    /// Guards `fd`, shared between the two queues.
    private let lock = NSLock()
    private var fd: Int32 = -1

    /// Only ever touched from `readQueue`.
    private var readBuffer = Data()

    private let runFlag = NSLock()
    private var _shouldRun = true
    private var shouldRun: Bool {
        get { runFlag.lock(); defer { runFlag.unlock() }; return _shouldRun }
        set { runFlag.lock(); _shouldRun = newValue; runFlag.unlock() }
    }

    /// Called on the main queue.
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
        // No queue hopping: `readQueue` is busy on a blocking read, posting the
        // stop there would achieve nothing. We close the descriptor, which makes
        // the read return.
        shouldRun = false
        closeConnection()
    }

    // MARK: - Sending

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
            // The daemon is gone. The read loop will notice and reopen the
            // connection; no need to handle it twice.
            self.closeConnection()
        }
    }

    // MARK: - Loop

    private func runLoop() {
        while shouldRun {
            guard connect() else {
                // Wait before retrying. Short enough that the user does not see
                // the app "disconnected" long after restarting the daemon, long
                // enough not to hammer the filesystem.
                Thread.sleep(forTimeInterval: 1.0)
                continue
            }
            readUntilClosed()
            closeConnection()
            if shouldRun { Thread.sleep(forTimeInterval: 1.0) }
        }
    }

    /// Last failure logged.
    ///
    /// We silence **repeats** — a reconnection loop writing one line per second
    /// drowns the log — but never a different failure reason: that is precisely
    /// the one that explains the incident.
    private var lastFailure: String?

    private func connect() -> Bool {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            logFailure("socket(): \(String(cString: strerror(errno)))")
            return false
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)

        let pathBytes = Array(socketPath.utf8)
        // `sun_path` is 104 bytes on macOS. A silent overflow would produce a
        // connection to a truncated path, and so to nothing.
        guard pathBytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            logFailure("socket path too long: \(socketPath)")
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
            logFailure("connect(\(socketPath)): \(String(cString: strerror(errno)))")
            close(sock)
            return false
        }

        lock.lock()
        fd = sock
        lock.unlock()
        readBuffer.removeAll(keepingCapacity: true)

        // Handshake, then subscription. Both are written here, on the same
        // path: they are part of establishing the connection, not of ordinary
        // traffic.
        //
        // Routing `subscribe` through `writeQueue` lost it — the queue is not
        // yet in service at this point. The app then ran without ever receiving
        // a prompt, and the daemon refused every `ask` explaining that no
        // interface was there to confirm.
        let hello: [String: Any] = [
            "mcpwall_ipc": Int(Self.ipcVersion),
            "build": Bundle.main.shortVersion,
        ]
        guard Self.write(hello, to: sock) else {
            logFailure("could not send the hello")
            closeConnection()
            return false
        }
        guard readHello() else {
            closeConnection()
            return false
        }
        guard Self.write(["type": "subscribe"], to: sock) else {
            logFailure("could not subscribe")
            closeConnection()
            return false
        }
        Self.write(["type": "status"], to: sock)

        lastFailure = nil
        NSLog("mcpwall: connected to the daemon")
        isConnected = true
        return true
    }

    private func readHello() -> Bool {
        guard let line = readLine() else {
            logFailure("no answer to the hello")
            return false
        }
        // `as? UInt32` would fail: the NSNumber bridge only converts to the
        // wide types. We go through `Int`, the only guaranteed form.
        guard let object = try? JSONSerialization.jsonObject(with: Data(line.utf8)),
              let dict = object as? [String: Any],
              let version = dict["mcpwall_ipc"] as? Int
        else {
            logFailure("unreadable daemon hello: \(line)")
            return false
        }

        guard version == Int(Self.ipcVersion) else {
            // The daemon is not the one we think — typically a daemon left in
            // place after an app update. We refuse rather than interpret
            // charitably messages we do not understand.
            logFailure("incompatible IPC version (daemon \(version), app \(Self.ipcVersion))")
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

    // MARK: - I/O

    /// Writes an object followed by a newline.
    ///
    /// Direct system calls rather than `FileHandle`: the latter is designed for
    /// files and pipes, and its write blocked forever on a Unix socket — forty
    /// bytes that never left, with no error and no trace.
    @discardableResult
    private static func write(_ object: [String: Any], to fd: Int32) -> Bool {
        guard var data = try? JSONSerialization.data(withJSONObject: object) else { return false }
        data.append(0x0A)

        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            var sent = 0
            while sent < raw.count {
                // `send` with MSG_NOSIGNAL does not exist on Darwin; SIGPIPE is
                // disabled when the socket is opened, via SO_NOSIGPIPE.
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

    /// Reads one line, accumulating partial reads.
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

    // MARK: - Decoding

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

        // `verdict` travels on shim connections, never here. We ignore it
        // quietly rather than treat it as an anomaly.
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
