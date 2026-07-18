import Foundation
import Network
import UserNotifications

/// WhitelistDetector runs inside the PacketTunnelProvider while VPN is up.
///
/// The old D65 detector used two ICMP pings. Current logic follows the
/// allowlist research: compare foreign control domains against domestic
/// allowlisted domains with TCP-connect + TLS-SNI probes. ICMP is not a
/// deciding signal because RU restricted-profile mode can block ICMP independently of
/// web/TLS reachability.
final class WhitelistDetector {

    private static let holdDownSeconds: TimeInterval = 60

    /// Read user-configured cadence; double it when on backup.
    private static var normalCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }
    private static var onBackupCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval) * 2
    }
    private static var failbackSuccessesNeeded: Int {
        WhitelistProbePreferences.successesNeeded
    }

    // Hooks injected by PacketTunnelProvider.
    private let log: (String) -> Void
    private let switchEndpoint: (EndpointMode) -> Void
    private let pathProvider: () -> Network.NWPath?

    private let queue = DispatchQueue(label: "com.anarki.samizdat-test.detector", qos: .utility)
    private var timer: DispatchSourceTimer?

    // Target-list display strings (re-read on applyConfig).
    private var foreignTargets: String = WhitelistProbePreferences.testHost
    private var domesticTargets: String = WhitelistProbePreferences.whitelistHost
    private var configSignature = ""

    // State.
    private var lastSwitchedAt = Date.distantPast
    private var failbackSuccesses = 0
    private var whitelistSuccesses = 0
    private var isPathSatisfied = true
    private var lastPathFingerprint: String?
    private var stopped = false
    private var probeGeneration = 0

    init(log: @escaping (String) -> Void,
         switchEndpoint: @escaping (EndpointMode) -> Void,
         pathProvider: @escaping () -> Network.NWPath?) {
        self.log = log
        self.switchEndpoint = switchEndpoint
        self.pathProvider = pathProvider
    }

    func start() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = false
            self.probeGeneration += 1
            // Consecutive confidence is local to this detector instance. A
            // previous extension/app process may have observed another path.
            self.failbackSuccesses = 0
            self.whitelistSuccesses = 0
            WhitelistStatusStore.failbackSuccesses = 0
            WhitelistStatusStore.whitelistSuccessesExtension = 0
            self.applyConfigLocked()
            self.scheduleNextProbe(after: 2)
            self.log("info: WhitelistDetector started method=tcp_tls_sni icmp=not_used threshold=\(Self.failbackSuccessesNeeded) interval=\(Int(Self.normalCadence))s foreign=\(self.foreignTargets) domestic=\(self.domesticTargets)")
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.stopped = true
            self.probeGeneration += 1
            self.timer?.cancel(); self.timer = nil
            // D59 FIX: do NOT reset WhitelistStatusStore.current here.
            // The last-known detection result should persist so the UI
            // keeps showing "Whitelist active" / "Free internet" across
            // VPN connect/disconnect cycles. The main-app WhitelistMonitor
            // picks up when the extension stops; the 200s stale-check in
            // ContentView.refreshWhitelistStatus() handles truly stale data.
            self.log("info: WhitelistDetector stopped (status preserved)")
        }
    }

    /// Re-reads the user-configured target hosts from App Group
    /// UserDefaults and adopts them for the next cycle. Called by
    /// PacketTunnelProvider on the "refreshWhitelistProbes" provider
    /// message.
    func applyConfig() {
        queue.async { [weak self] in
            self?.applyConfigLocked()
        }
    }

    private func applyConfigLocked() {
        let f = WhitelistProbePreferences.testHost
        let d = WhitelistProbePreferences.whitelistHost
        let signature = "\(f)|\(d)|\(WhitelistProbePreferences.successesNeeded)|\(WhitelistProbePreferences.probeInterval)"
        let changed = !configSignature.isEmpty && signature != configSignature
        if f != foreignTargets || d != domesticTargets {
            log("info: detector targets updated: foreign=\(f) domestic=\(d)")
        }
        foreignTargets = f
        domesticTargets = d
        configSignature = signature
        if changed {
            probeGeneration += 1
            resetProgressLocked(reason: "probe configuration changed")
            scheduleNextProbe(after: 1)
        }
    }

    /// Notify the detector about every physical-path update. Consecutive
    /// confidence cannot cross Wi-Fi/cellular/SIM changes even when both old
    /// and new NWPath values are `.satisfied`.
    func notePathChange(satisfied: Bool, fingerprint: String) {
        queue.async { [weak self] in
            guard let self, !self.stopped else { return }
            let statusChanged = self.isPathSatisfied != satisfied
            let pathChanged = self.lastPathFingerprint != nil
                && self.lastPathFingerprint != fingerprint
            self.isPathSatisfied = satisfied
            self.lastPathFingerprint = fingerprint
            guard statusChanged || pathChanged else { return }

            self.probeGeneration += 1
            self.resetProgressLocked(reason: "network path changed → \(fingerprint)")
            if !satisfied {
                WhitelistStatusStore.current = .noNetwork
                self.log("info: detector paused (path unsatisfied)")
            } else {
                WhitelistStatusStore.current = .unknown
                self.log("info: detector resumed on fresh path")
                self.scheduleNextProbe(after: 1)
            }
        }
    }

    private func resetProgressLocked(reason: String) {
        failbackSuccesses = 0
        whitelistSuccesses = 0
        WhitelistStatusStore.resetDetectionProgress()
        log("info: detector progress reset — \(reason)")
    }

    // MARK: – cycle

    private func scheduleNextProbe(after delay: TimeInterval) {
        guard !stopped else { return }
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + delay)
        t.setEventHandler { [weak self] in
            self?.runCycle()
        }
        t.resume()
        timer = t
    }

    private func runCycle() {
        guard !stopped else { return }

        guard EndpointModeStore.current == .auto else {
            log("info: detector cycle skip (mode=\(EndpointModeStore.current.rawValue))")
            scheduleNextProbe(after: Self.normalCadence)
            return
        }
        if !isPathSatisfied {
            log("info: detector cycle skip (path unsatisfied)")
            scheduleNextProbe(after: Self.normalCadence)
            return
        }
        let pathSelection = WhitelistProbeEngine.pathSelection(pathProvider())
        let iface = pathSelection.interfaceIndex
        let pinned = WhitelistProbePinnedStore.current()
        let onBackup = (WhitelistStatusStore.activeEndpoint == .backup)
        let baseCadence = onBackup ? Self.onBackupCadence : Self.normalCadence
        let cadence = ProcessInfo.processInfo.isLowPowerModeEnabled ? baseCadence * 3 : baseCadence
        log("info: detector cycle start method=tcp_tls_sni icmp=not_used active=\(WhitelistStatusStore.activeEndpoint.rawValue) status=\(WhitelistStatusStore.current.rawValue) whitelistCount=\(whitelistSuccesses)/\(Self.failbackSuccessesNeeded) freeCount=\(failbackSuccesses)/\(Self.failbackSuccessesNeeded) path={\(pathSelection.summary)} foreign=\(foreignTargets) domestic=\(domesticTargets)")
        if iface == nil {
            log("info: detector probe uses NECP/default route (no unambiguous physical interface)")
        }
        if pinned.isEmpty {
            log("info: detector probe: no pinned IPs (targets unresolved) — probe resolves on physical path")
        } else {
            log("info: detector probe pinned=\(pinned.count) targets")
        }

        probeGeneration += 1
        let gen = probeGeneration
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = WhitelistProbeEngine.run(interfaceIndex: iface, pinnedIPs: pinned)
            self?.queue.async { [weak self] in
                guard let self else { return }
                guard !self.stopped, gen == self.probeGeneration else { return }
                for line in WhitelistProbeEngine.detailedLogLines(result) {
                    self.log("info: detector probe \(line)")
                }
                self.handleOutcome(Self.outcome(from: result))
                let switchPending = (WhitelistStatusStore.activeEndpoint == .primary && self.whitelistSuccesses > 0)
                    || (WhitelistStatusStore.activeEndpoint == .backup && self.failbackSuccesses > 0)
                self.scheduleNextProbe(after: switchPending ? 5 : cadence)
            }
        }
    }

    private enum Outcome: String {
        case clearAll
        case whitelistOn
        case uncertain
        case noNetwork
    }

    private static func outcome(from result: WhitelistProbeCycleResult) -> Outcome {
        switch result.classification {
        case .normal:
            return .clearAll
        case .allowlist:
            return .whitelistOn
        case .offline:
            return .noNetwork
        case .partial, .anomalous, .error:
            return .uncertain
        }
    }

    // MARK: – decisions

    private func handleOutcome(_ outcome: Outcome) {
        let now = Date()
        let inHoldDown = now.timeIntervalSince(lastSwitchedAt) < Self.holdDownSeconds
        log("info: detector cycle outcome=\(outcome.rawValue) holdDown=\(inHoldDown)")

        switch outcome {
        case .clearAll:
            whitelistSuccesses = 0
            failbackSuccesses += 1
            if WhitelistStatusStore.activeEndpoint == .backup
                && failbackSuccesses >= Self.failbackSuccessesNeeded
                && !inHoldDown {
                log("info: detector: failback → primary (whitelist gone)")
                applySwitch(to: .primary)
                failbackSuccesses = 0
            }
            WhitelistStatusStore.current = .off

        case .whitelistOn:
            failbackSuccesses = 0
            whitelistSuccesses += 1
            if WhitelistStatusStore.activeEndpoint != .backup
                && whitelistSuccesses >= Self.failbackSuccessesNeeded
                && !inHoldDown {
                log("warn: detector: WHITELIST ACTIVE — switching to backup")
                applySwitch(to: .backup)
                whitelistSuccesses = 0
            }
            WhitelistStatusStore.current = .detected

        case .uncertain:
            failbackSuccesses = 0
            whitelistSuccesses = 0
            WhitelistStatusStore.current = .unknown
            log("warn: detector: uncertain comparative probe result — keeping current endpoint")

        case .noNetwork:
            failbackSuccesses = 0
            whitelistSuccesses = 0
            WhitelistStatusStore.current = .noNetwork
        }

        // Keep counters process-local; only the current verdict/endpoint cross
        // the App Group boundary. Persisting partial confidence made a fresh
        // detector inherit results from another network.
        log("info: detector counters status=\(WhitelistStatusStore.current.rawValue) active=\(WhitelistStatusStore.activeEndpoint.rawValue) whitelistCount=\(whitelistSuccesses)/\(Self.failbackSuccessesNeeded) freeCount=\(failbackSuccesses)/\(Self.failbackSuccessesNeeded)")
    }

    private func applySwitch(to endpoint: EndpointMode) {
        lastSwitchedAt = Date()
        WhitelistStatusStore.activeEndpoint = endpoint
        switchEndpoint(endpoint)
        postSwitchNotification(to: endpoint)
    }

    private func postSwitchNotification(to endpoint: EndpointMode) {
        guard NotificationPreferences.enabled else { return }
        let content = UNMutableNotificationContent()
        switch endpoint {
        case .backup:
            content.title = "Whitelist mode detected"
            content.body  = "Switched to whitelist server to keep traffic flowing."
        case .primary, .auto:
            content.title = "Whitelist lifted"
            content.body  = "Switched back to main server."
        }
        content.sound = .default
        content.categoryIdentifier = NotificationIDs.categoryIdentifier
        let id = (endpoint == .backup) ? NotificationIDs.detectedID : NotificationIDs.recoveredID
        let req = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { [weak self] err in
            if let err = err {
                self?.log("warn: notification post failed: \(err)")
            } else {
                self?.log("info: notification posted (\(endpoint.rawValue))")
            }
        }
    }
}
