import Foundation
import Network

/// WhitelistMonitor runs in the MAIN APP while VPN is disconnected.
///
/// Uses serial ICMP echo probes against a normally blocked control and a
/// domestic allowlisted control. Every completed cycle produces a final UI
/// verdict; ambiguous/offline combinations are surfaced as Error detecting.
///
/// Decision matrix:
///   normal      → free internet      → activeEndpoint = primary
///   allowlist   → whitelist active   → activeEndpoint = backup
///   error       → Error detecting    → keep current
///
/// Timing rules (identical to the extension's WhitelistDetector):
///   1. Bootstrap (start / network path change): probe immediately; the
///      first decisive verdict is applied at once. Inconclusive cycles are
///      retried every `bootstrapRetryInterval` (3 s).
///   2. Stable phase: the opposite endpoint is adopted only after the
///      opposite verdict held continuously for `switchHoldSeconds` (60 s),
///      re-probing every `switchProbeInterval` (10 s). Any agreeing or
///      inconclusive cycle in between restarts the window.
///   3. Steady state (nothing pending): one probe per `probeInterval`.
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

    /// Bootstrap state — true once a decisive verdict has been applied for
    /// the current monitor owner / network path.
    private var bootstrapDone = false
    /// Endpoint we are about to switch to, and since when its verdict has
    /// been holding. Non-nil only while a stable-phase change is pending.
    private var pendingTarget: EndpointMode?
    private var pendingSince: Date?
    private var lastPathSummary: String?
    private var lastConfigSignature: String?

    /// Begin monitoring. Idempotent; no-op if already running.
    func start() {
        guard task == nil else { return }
        generation += 1
        let gen = generation
        resetDecisionState()
        lastPathSummary = nil
        lastConfigSignature = nil
        WhitelistStatusStore.resetDetectionProgress()
        let build = (Bundle.main.object(forInfoDictionaryKey: "IPAArtifactName") as? String)
            ?? (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String)
            ?? "unknown"
        AppLog.info("whitelist", "monitor started build=\(build) method=icmp_echo interval=\(Int(Self.cycleInterval))s bootstrapRetry=\(Int(WhitelistProbePreferences.bootstrapRetryInterval))s hold=\(Int(WhitelistProbePreferences.switchHoldSeconds))s blocked=\(WhitelistProbePreferences.testHost) allowed=\(WhitelistProbePreferences.whitelistHost)")
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let summary = WhitelistProbeEngine.pathSelection(path).summary
            Task { @MainActor in
                self?.handlePathUpdate(summary: summary)
            }
        }
        monitor.start(queue: pathMonitorQueue)
        pathMonitor = monitor
        launchLoop(generation: gen)
    }

    func stop() {
        generation += 1
        task?.cancel()
        task = nil
        pathMonitor?.cancel()
        pathMonitor = nil
        resetDecisionState()
        AppLog.info("whitelist", "monitor stopped")
    }

    private func launchLoop(generation gen: Int) {
        task = Task { [weak self] in
            while !Task.isCancelled {
                let delay = await self?.runCycle(generation: gen) ?? Self.cycleInterval
                try? await Task.sleep(for: .seconds(delay))
                if Task.isCancelled { return }
            }
        }
    }

    /// A new physical path invalidates everything the previous path said.
    /// Rule 1: bootstrap again, starting with an immediate probe.
    private func handlePathUpdate(summary: String) {
        guard task != nil else { return }
        let previous = lastPathSummary
        lastPathSummary = summary
        guard let previous, previous != summary else { return }
        AppLog.info("whitelist", "monitor path changed — bootstrap restarted {\(previous)} → {\(summary)}")
        generation += 1
        let gen = generation
        resetDecisionState()
        task?.cancel()
        task = nil
        WhitelistStatusStore.current = .unknown
        launchLoop(generation: gen)
    }

    private func resetDecisionState() {
        bootstrapDone = false
        pendingTarget = nil
        pendingSince = nil
    }

    // MARK: – cycle

    private func runCycle(generation gen: Int) async -> TimeInterval {
        guard EndpointModeStore.current == .auto else {
            WhitelistStatusStore.current = .unknown
            return Self.cycleInterval
        }
        let configSignature = "\(WhitelistProbePreferences.testHost)|\(WhitelistProbePreferences.whitelistHost)|\(WhitelistProbePreferences.probeInterval)"
        if let previous = lastConfigSignature, previous != configSignature {
            lastConfigSignature = configSignature
            resetProgress(reason: "probe configuration changed")
            return 0
        }
        lastConfigSignature = configSignature

        let pathSelection = WhitelistProbeEngine.pathSelection(pathMonitor?.currentPath)
        AppLog.info("whitelist", "monitor ping start active=\(WhitelistStatusStore.activeEndpoint.rawValue) status=\(WhitelistStatusStore.current.rawValue) bootstrap=\(bootstrapDone) pending=\(pendingTarget?.rawValue ?? "none") path={\(pathSelection.summary)} blocked=\(WhitelistProbePreferences.testHost) allowed=\(WhitelistProbePreferences.whitelistHost)")
        let result = await WhitelistProbeEngine.runAsync(interfaceIndex: pathSelection.interfaceIndex)
        guard gen == generation, !Task.isCancelled else { return Self.cycleInterval }
        for line in WhitelistProbeEngine.detailedLogLines(result) {
            AppLog.info("whitelist", "monitor probe \(line)")
        }
        AppLog.info("whitelist", "monitor result=\(result.classification.rawValue) status=\(WhitelistStatusStore.current.rawValue) active=\(WhitelistStatusStore.activeEndpoint.rawValue)")
        return decide(classification: result.classification)
    }

    /// Applies one completed cycle and returns the delay until the next one.
    private func decide(classification: WhitelistProbeCycleResult.Classification) -> TimeInterval {
        guard bootstrapDone else {
            switch classification {
            case .normal:
                bootstrapDone = true
                WhitelistStatusStore.current = .off
                applyBootstrapVerdict(endpoint: .primary)
                return Self.cycleInterval
            case .allowlist:
                bootstrapDone = true
                WhitelistStatusStore.current = .detected
                applyBootstrapVerdict(endpoint: .backup)
                return Self.cycleInterval
            case .error:
                WhitelistStatusStore.current = .error
                return WhitelistProbePreferences.bootstrapRetryInterval
            }
        }

        let current = WhitelistStatusStore.activeEndpoint
        switch classification {
        case .normal:
            WhitelistStatusStore.current = .off
            return stablePhase(target: .primary, current: current)
        case .allowlist:
            WhitelistStatusStore.current = .detected
            return stablePhase(target: .backup, current: current)
        case .error:
            WhitelistStatusStore.current = .error
            guard pendingTarget != nil else { return Self.cycleInterval }
            pendingSince = Date()
            AppLog.info("whitelist", "monitor pending change restarted (error) target=\(pendingTarget?.rawValue ?? "none")")
            return WhitelistProbePreferences.switchProbeInterval
        }
    }

    private func applyBootstrapVerdict(endpoint: EndpointMode) {
        WhitelistStatusStore.activeEndpoint = endpoint
        AppLog.info("whitelist", "monitor bootstrap verdict=\(endpoint.rawValue) — applied immediately")
    }

    /// Rule 2: a later flip needs `switchHoldSeconds` of continuous
    /// agreement. Any agreeing cycle cancels the pending change.
    private func stablePhase(target: EndpointMode, current: EndpointMode) -> TimeInterval {
        guard target != current else {
            if let pending = pendingTarget {
                AppLog.info("whitelist", "monitor pending change cancelled target=\(pending.rawValue)")
                pendingTarget = nil
                pendingSince = nil
            }
            return Self.cycleInterval
        }
        if pendingTarget != target {
            pendingTarget = target
            pendingSince = Date()
            AppLog.info("whitelist", "monitor pending change started target=\(target.rawValue) hold=\(Int(WhitelistProbePreferences.switchHoldSeconds))s")
            return WhitelistProbePreferences.switchProbeInterval
        }
        let held = Date().timeIntervalSince(pendingSince ?? Date())
        guard held >= WhitelistProbePreferences.switchHoldSeconds else {
            return WhitelistProbePreferences.switchProbeInterval
        }
        WhitelistStatusStore.activeEndpoint = target
        AppLog.info("whitelist", "monitor pending change committed target=\(target.rawValue) held=\(Int(held))s")
        pendingTarget = nil
        pendingSince = nil
        return Self.cycleInterval
    }

    private func resetProgress(reason: String) {
        resetDecisionState()
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
