import Foundation
import Network

/// WhitelistMonitor runs in the MAIN APP while VPN is disconnected.
///
/// Uses serial ICMP echo probes against a normally blocked control and a
/// domestic allowlisted control. Every completed cycle produces a final UI
/// verdict; ambiguous/offline combinations are surfaced as Error detecting.
///
/// Decision matrix:
///   normal      → free internet      → activeEndpoint = primary after threshold
///   allowlist   → whitelist active   → activeEndpoint = backup after threshold
///   error       → Error detecting    → keep current
@MainActor
final class WhitelistMonitor: ObservableObject {

    private static var cycleInterval: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }

    private var task: Task<Void, Never>?
    private var generation = 0
    private var pathMonitor: NWPathMonitor?
    private let pathMonitorQueue = DispatchQueue(
        label: "com.anarki.samizdat-test.whitelist-main-path",
        qos: .utility
    )

    // Consecutive-result counters — switching happens only after
    // `successesNeeded` consecutive identical decisive verdicts.
    private var whitelistCount = 0
    private var freeCount = 0
    private var lastPathSummary: String?
    private var lastConfigSignature: String?

    /// Begin monitoring. Idempotent; no-op if already running.
    func start() {
        guard task == nil else { return }
        generation += 1
        let gen = generation
        let monitor = NWPathMonitor()
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        // A consecutive sequence cannot span monitor owners or carrier paths.
        // Start clean; the 5 s settling cadence below rebuilds confidence fast.
        whitelistCount = 0
        freeCount = 0
        lastPathSummary = nil
        lastConfigSignature = nil
        WhitelistStatusStore.resetDetectionProgress()
        let build = (Bundle.main.object(forInfoDictionaryKey: "IPAArtifactName") as? String)
            ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
            ?? "unknown"
        AppLog.info("whitelist", "monitor started build=\(build) method=icmp_echo threshold=\(WhitelistProbePreferences.successesNeeded) interval=\(Int(Self.cycleInterval))s blocked=\(WhitelistProbePreferences.testHost) allowed=\(WhitelistProbePreferences.whitelistHost)")
        task = Task { [weak self] in
            while !Task.isCancelled {
                let delay = await self?.runCycle(generation: gen) ?? Self.cycleInterval
                try? await Task.sleep(for: .seconds(delay))
            }
        }
    }

    func stop() {
        generation += 1
        task?.cancel()
        task = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        AppLog.info("whitelist", "monitor stopped")
    }

    // MARK: – cycle

    private func runCycle(generation gen: Int) async -> TimeInterval {
        guard EndpointModeStore.current == .auto else {
            WhitelistStatusStore.current = .unknown
            return Self.cycleInterval
        }
        let threshold = WhitelistProbePreferences.successesNeeded
        let pathSelection = WhitelistProbeEngine.pathSelection(pathMonitor?.currentPath)
        let configSignature = "\(WhitelistProbePreferences.testHost)|\(WhitelistProbePreferences.whitelistHost)|\(threshold)|\(WhitelistProbePreferences.probeInterval)"
        if let previous = lastPathSummary, previous != pathSelection.summary {
            resetProgress(reason: "network path changed: {\(previous)} → {\(pathSelection.summary)}")
        }
        if let previous = lastConfigSignature, previous != configSignature {
            resetProgress(reason: "probe configuration changed")
        }
        lastPathSummary = pathSelection.summary
        lastConfigSignature = configSignature

        AppLog.info("whitelist", "monitor ping start active=\(WhitelistStatusStore.activeEndpoint.rawValue) status=\(WhitelistStatusStore.current.rawValue) whitelistCount=\(whitelistCount)/\(threshold) freeCount=\(freeCount)/\(threshold) path={\(pathSelection.summary)} blocked=\(WhitelistProbePreferences.testHost) allowed=\(WhitelistProbePreferences.whitelistHost)")
        let result = await WhitelistProbeEngine.runAsync(interfaceIndex: pathSelection.interfaceIndex)
        guard gen == generation, !Task.isCancelled else { return Self.cycleInterval }
        for line in WhitelistProbeEngine.detailedLogLines(result) {
            AppLog.info("whitelist", "monitor probe \(line)")
        }

        switch result.classification {
        case .normal:
            // Free internet — domestic + foreign controls reachable.
            whitelistCount = 0
            freeCount += 1
            WhitelistStatusStore.current = .off
            if WhitelistStatusStore.activeEndpoint == .backup
                && freeCount >= threshold {
                WhitelistStatusStore.activeEndpoint = .primary
                freeCount = 0
            }

        case .allowlist:
            // Default-deny allowlist — domestic reachable, foreign controls fail.
            freeCount = 0
            whitelistCount += 1
            WhitelistStatusStore.current = .detected
            if WhitelistStatusStore.activeEndpoint != .backup
                && whitelistCount >= threshold {
                WhitelistStatusStore.activeEndpoint = .backup
                whitelistCount = 0
            }

        case .error:
            freeCount = 0
            whitelistCount = 0
            WhitelistStatusStore.current = .error
        }

        AppLog.info("whitelist", "monitor result=\(result.classification.rawValue) status=\(WhitelistStatusStore.current.rawValue) active=\(WhitelistStatusStore.activeEndpoint.rawValue) whitelistCount=\(whitelistCount)/\(threshold) freeCount=\(freeCount)/\(threshold)")
        let switchPending = (WhitelistStatusStore.activeEndpoint == .primary && whitelistCount > 0)
            || (WhitelistStatusStore.activeEndpoint == .backup && freeCount > 0)
        return switchPending ? 5 : Self.cycleInterval
    }

    private func resetProgress(reason: String) {
        whitelistCount = 0
        freeCount = 0
        WhitelistStatusStore.resetDetectionProgress()
        AppLog.info("whitelist", "monitor progress reset — \(reason)")
    }
}

/// Shared file-logger for the main app. Writes timestamped lines to the
/// same App Group file the extension uses (`extension-log.txt`) so the
/// in-app `LogView` shows app-side events alongside the extension stream.
///
/// Format mirrors the extension's log lines:
///   `HH:mm:ss.SSS <level>: <tag>: <message>`
/// where `<level>` is one of `info`, `warn`, `error`, `crit`.
enum AppLog {
    static let appGroupID = "group.com.anarki.samizdat-test"
    static let fileName = "extension-log.txt"

    // Serializes the whole write path. DateFormatter is NOT
    // thread-safe (concurrent string(from:) can crash), and the
    // open/seek/write sequence is not atomic either — without
    // O_APPEND, two handles that both seeked to EOF overwrite each
    // other's bytes. AppLog is called from the main actor and from
    // URLSession delegate queues concurrently.
    private static let writeLock = NSLock()

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .autoupdatingCurrent
        return f
    }()

    /// Ensure `extension-log.txt` exists in the App Group container,
    /// then return a FileHandle positioned at end-of-file. The handle
    /// is recreated on every write — opening a new fd per line is cheap
    /// (microseconds) and avoids stale-fd issues if iOS reclaims the
    /// container while we hold it.
    private static func handle() -> FileHandle? {
        let fm = FileManager.default
        guard let container = fm.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) else {
            return nil
        }
        let url = container.appendingPathComponent(fileName)
        if !fm.fileExists(atPath: url.path) {
            fm.createFile(atPath: url.path, contents: nil, attributes: nil)
        }
        guard let h = try? FileHandle(forWritingTo: url) else {
            return nil
        }
        // Seek to end for append behaviour without O_APPEND on the fd.
        _ = try? h.seekToEnd()
        return h
    }

    static func info(_ tag: String, _ message: String) {
        write(level: "info", tag: tag, message: message)
    }

    static func warn(_ tag: String, _ message: String) {
        write(level: "warn", tag: tag, message: message)
    }

    static func error(_ tag: String, _ message: String) {
        write(level: "error", tag: tag, message: message)
    }

    private static func write(level: String, tag: String, message: String) {
        writeLock.lock()
        defer { writeLock.unlock() }
        let line = "\(timeFormatter.string(from: Date())) \(level): \(tag): \(message)\n"
        guard let h = handle() else { return }
        defer { try? h.close() }
        _ = try? h.write(contentsOf: Data(line.utf8))
        try? h.synchronize()
    }
}
