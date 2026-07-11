import Foundation
import Network

/// WhitelistMonitor runs in the MAIN APP while VPN is disconnected.
///
/// Current detector follows the allowlist research: compare multiple foreign
/// control domains against multiple domestic allowlisted domains using TCP
/// connect + TLS-SNI probes. ICMP is no longer a deciding signal.
///
/// Decision matrix:
///   normal      → free internet      → activeEndpoint = primary after threshold
///   allowlist   → whitelist active   → activeEndpoint = backup after threshold
///   offline     → no usable internet → keep current
///   partial/anomalous/error → uncertain, keep current
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
        TURNLog.info("whitelist", "monitor started build=\(build) method=tcp_tls_sni icmp=not_used threshold=\(WhitelistProbePreferences.successesNeeded) interval=\(Int(Self.cycleInterval))s foreign=\(WhitelistProbePreferences.testHost) domestic=\(WhitelistProbePreferences.whitelistHost)")
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
        TURNLog.info("whitelist", "monitor stopped")
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

        TURNLog.info("whitelist", "monitor cycle start active=\(WhitelistStatusStore.activeEndpoint.rawValue) status=\(WhitelistStatusStore.current.rawValue) whitelistCount=\(whitelistCount)/\(threshold) freeCount=\(freeCount)/\(threshold) path={\(pathSelection.summary)} foreign=\(WhitelistProbePreferences.testHost) domestic=\(WhitelistProbePreferences.whitelistHost)")
        let result = await WhitelistProbeEngine.runAsync(interfaceIndex: pathSelection.interfaceIndex)
        guard gen == generation, !Task.isCancelled else { return Self.cycleInterval }
        for line in WhitelistProbeEngine.detailedLogLines(result) {
            TURNLog.info("whitelist", "monitor probe \(line)")
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

        case .offline:
            freeCount = 0
            whitelistCount = 0
            WhitelistStatusStore.current = .noNetwork

        case .partial, .anomalous, .error:
            // Ordinary excluded list / stale domestic targets / captive weirdness.
            // Do not declare allowlist and do not switch endpoint.
            freeCount = 0
            whitelistCount = 0
            WhitelistStatusStore.current = .unknown
        }

        TURNLog.info("whitelist", "monitor counters classification=\(result.classification.rawValue) status=\(WhitelistStatusStore.current.rawValue) active=\(WhitelistStatusStore.activeEndpoint.rawValue) whitelistCount=\(whitelistCount)/\(threshold) freeCount=\(freeCount)/\(threshold)")
        let switchPending = (WhitelistStatusStore.activeEndpoint == .primary && whitelistCount > 0)
            || (WhitelistStatusStore.activeEndpoint == .backup && freeCount > 0)
        return switchPending ? 5 : Self.cycleInterval
    }

    private func resetProgress(reason: String) {
        whitelistCount = 0
        freeCount = 0
        WhitelistStatusStore.resetDetectionProgress()
        TURNLog.info("whitelist", "monitor progress reset — \(reason)")
    }
}
