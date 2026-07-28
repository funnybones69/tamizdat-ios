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
        guard task != nil || pathMonitor != nil else { return }
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
        let probeStartedAt = Date()
        let result = await WhitelistProbeEngine.runAsync(interfaceIndex: pathSelection.interfaceIndex, pinnedIPs: [:])
        let probeWallTime = Date().timeIntervalSince(probeStartedAt)
        guard gen == generation, !Task.isCancelled else { return Self.cycleInterval }
        // iOS can suspend the main app in the middle of the blocking Go probe.
        // Such a result may arrive minutes later on a different physical path;
        // it is not valid evidence for either endpoint.
        if probeWallTime > 30 {
            resetProgress(reason: "discarded stale probe after \(Int(probeWallTime))s")
            return 1
        }
        for line in WhitelistProbeEngine.detailedLogLines(result) {
            TURNLog.info("whitelist", "monitor probe \(line)")
        }

        switch result.classification {
        case .normal:
            // Free internet — domestic + foreign controls reachable.
            whitelistCount = 0
            if WhitelistStatusStore.activeEndpoint == .backup {
                freeCount += 1
                if freeCount >= threshold {
                    WhitelistStatusStore.activeEndpoint = .primary
                    freeCount = 0
                    WhitelistStatusStore.current = .off
                }
            } else {
                freeCount = 0
                WhitelistStatusStore.current = .off
            }

        case .allowlist:
            // Default-deny allowlist — domestic reachable, foreign controls fail.
            freeCount = 0
            if WhitelistStatusStore.activeEndpoint != .backup {
                whitelistCount += 1
                if whitelistCount >= threshold {
                    WhitelistStatusStore.activeEndpoint = .backup
                    whitelistCount = 0
                    WhitelistStatusStore.current = .detected
                }
            } else {
                whitelistCount = 0
                WhitelistStatusStore.current = .detected
            }

        case .offline:
            freeCount = 0
            whitelistCount = 0
            WhitelistStatusStore.current = .noNetwork

        case .partial, .anomalous, .error:
            // Ordinary excluded list / stale domestic targets / captive weirdness.
            // Do not declare allowlist, switch endpoint, or erase the last
            // decisive verdict. "Uncertain" is not a new network mode.
            freeCount = 0
            whitelistCount = 0
        }

        TURNLog.info("whitelist", "monitor counters classification=\(result.classification.rawValue) status=\(WhitelistStatusStore.current.rawValue) active=\(WhitelistStatusStore.activeEndpoint.rawValue) whitelistCount=\(whitelistCount)/\(threshold) freeCount=\(freeCount)/\(threshold)")
        let switchPending = (WhitelistStatusStore.activeEndpoint == .primary && whitelistCount > 0)
            || (WhitelistStatusStore.activeEndpoint == .backup && freeCount > 0)
        // `probeInterval` is a start-to-start cadence. A blocked foreign TLS
        // probe commonly consumes ~4.75 s; sleeping another full 5 s made a
        // configured 3 × 5 s decision take ~25–30 s instead of ~15 s.
        let desiredStartInterval = switchPending ? 5 : Self.cycleInterval
        return max(0.25, desiredStartInterval - probeWallTime)
    }

    private func resetProgress(reason: String) {
        whitelistCount = 0
        freeCount = 0
        WhitelistStatusStore.resetDetectionProgress()
        TURNLog.info("whitelist", "monitor progress reset — \(reason)")
    }
}
