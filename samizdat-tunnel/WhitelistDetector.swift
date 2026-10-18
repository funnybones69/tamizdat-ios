import Foundation
import Network
import UserNotifications

/// WhitelistDetector runs inside the PacketTunnelProvider while VPN is up.
///
/// Runs serial ICMP echo probes against blocked and allowlisted controls.
/// The UI receives a final verdict after every cycle: «Обычный»,
/// «Белые списки» or «Ошибка определения». TCP/TLS/HTTP are not part of
/// detection.
///
/// Timing rules (identical to the app-side WhitelistMonitor):
///   1. Bootstrap (detector start / network path change): probe
///      immediately; the first decisive verdict is applied at once.
///      Inconclusive cycles retry every `bootstrapRetryInterval` (3 s).
///   2. Stable phase: the opposite endpoint is adopted only after the
///      opposite verdict held continuously for `switchHoldSeconds` (60 s),
///      re-probing every `switchProbeInterval` (10 s). Any agreeing or
///      inconclusive cycle in between restarts the window.
///   3. Steady state (nothing pending): one probe per `probeInterval`,
///      doubled on backup and tripled in Low Power Mode.
final class WhitelistDetector {

    /// Read user-configured cadence; double it when on backup.
    private static var normalCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval)
    }
    private static var onBackupCadence: TimeInterval {
        TimeInterval(WhitelistProbePreferences.probeInterval) * 2
    }
    /// Cadence for the next steady-state cycle, recomputed after every
    /// decision so an endpoint switch takes effect immediately.
    private static var steadyCadence: TimeInterval {
        let base = WhitelistStatusStore.activeEndpoint == .backup
            ? onBackupCadence
            : normalCadence
        return ProcessInfo.processInfo.isLowPowerModeEnabled ? base * 3 : base
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
    private var bootstrapDone = false
    private var pendingTarget: EndpointMode?
    private var pendingSince: Date?
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
            // Decision state is local to this detector instance. A previous
            // extension/app process may have observed another path.
            self.resetDecisionStateLocked()
            self.applyConfigLocked()
            self.scheduleNextProbe(after: 0)
            self.log("info: WhitelistDetector started method=icmp_echo interval=\(Int(Self.normalCadence))s bootstrapRetry=\(Int(WhitelistProbePreferences.bootstrapRetryInterval))s hold=\(Int(WhitelistProbePreferences.switchHoldSeconds))s blocked=\(self.foreignTargets) allowed=\(self.domesticTargets)")
        }
    }

    func stop() {
        // Strong self on purpose: the provider calls stop() and then
        // immediately drops its only strong reference (whitelistDetector = nil
        // in stopTunnel / startWhitelistDetectorIfNeeded). With a weak capture
        // this block would find self == nil, never cancel the resumed
        // DispatchSourceTimer, and the detector would deallocate while its
        // timer source is still active (libdispatch UAF). Capturing strongly
        // keeps the instance alive until the timer is cancelled on its own
        // queue; the block does not outlive its execution, so no cycle.
        queue.async {
            // Implicit strong self capture (no [weak self]) — see comment above.
            self.stopped = true
            self.probeGeneration += 1
            self.timer?.cancel(); self.timer = nil
            // D59 FIX: do NOT reset WhitelistStatusStore.current here.
            // The last-known detection result should persist so the UI
            // keeps showing «Белые списки» / «Свободный интернет» across
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
        let signature = "\(f)|\(d)|\(WhitelistProbePreferences.probeInterval)"
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
            scheduleNextProbe(after: 0)
        }
    }

    /// Notify the detector about every physical-path update. The verdict
    /// belongs to one physical path: a Wi-Fi/cellular/SIM change even when
    /// both old and new NWPath values are `.satisfied` re-enters bootstrap.
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
                WhitelistStatusStore.current = .error
                self.log("info: detector paused (path unsatisfied)")
            } else {
                WhitelistStatusStore.current = .unknown
                self.log("info: detector resumed on fresh path — bootstrap")
                self.scheduleNextProbe(after: 0)
            }
        }
    }

    private func resetDecisionStateLocked() {
        bootstrapDone = false
        pendingTarget = nil
        pendingSince = nil
    }

    private func resetProgressLocked(reason: String) {
        resetDecisionStateLocked()
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
            scheduleNextProbe(after: Self.steadyCadence)
            return
        }
        if !isPathSatisfied {
            log("info: detector cycle skip (path unsatisfied)")
            scheduleNextProbe(after: Self.steadyCadence)
            return
        }
        let pathSelection = WhitelistProbeEngine.pathSelection(pathProvider())
        let iface = pathSelection.interfaceIndex
        log("info: detector ping start active=\(WhitelistStatusStore.activeEndpoint.rawValue) status=\(WhitelistStatusStore.current.rawValue) bootstrap=\(bootstrapDone) pending=\(pendingTarget?.rawValue ?? "none") path={\(pathSelection.summary)} blocked=\(foreignTargets) allowed=\(domesticTargets)")
        if iface == nil {
            log("info: detector probe uses NECP/default route (no unambiguous physical interface)")
        }

        probeGeneration += 1
        let gen = probeGeneration
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = WhitelistProbeEngine.run(interfaceIndex: iface)
            self?.queue.async { [weak self] in
                guard let self else { return }
                guard !self.stopped, gen == self.probeGeneration else { return }
                for line in WhitelistProbeEngine.detailedLogLines(result) {
                    self.log("info: detector probe \(line)")
                }
                let next = self.decide(outcome: Self.outcome(from: result))
                self.scheduleNextProbe(after: next)
            }
        }
    }

    private enum Outcome: String {
        case clearAll
        case whitelistOn
        case error
    }

    private static func outcome(from result: WhitelistProbeCycleResult) -> Outcome {
        switch result.classification {
        case .normal:
            return .clearAll
        case .allowlist:
            return .whitelistOn
        case .error:
            return .error
        }
    }

    // MARK: – decisions

    /// Applies one completed cycle and returns the delay until the next.
    private func decide(outcome: Outcome) -> TimeInterval {
        log("info: detector cycle outcome=\(outcome.rawValue)")

        guard bootstrapDone else {
            switch outcome {
            case .clearAll:
                bootstrapDone = true
                WhitelistStatusStore.current = .off
                applyBootstrapVerdict(.primary)
                return Self.steadyCadence
            case .whitelistOn:
                bootstrapDone = true
                WhitelistStatusStore.current = .detected
                applyBootstrapVerdict(.backup)
                return Self.steadyCadence
            case .error:
                WhitelistStatusStore.current = .error
                log("info: detector bootstrap inconclusive — retry in \(Int(WhitelistProbePreferences.bootstrapRetryInterval))s")
                return WhitelistProbePreferences.bootstrapRetryInterval
            }
        }

        let current = WhitelistStatusStore.activeEndpoint
        switch outcome {
        case .clearAll:
            WhitelistStatusStore.current = .off
            return stablePhase(target: .primary, current: current)
        case .whitelistOn:
            WhitelistStatusStore.current = .detected
            return stablePhase(target: .backup, current: current)
        case .error:
            WhitelistStatusStore.current = .error
            log("warn: detector: ERROR DETECTING — ping matrix is not decisive; keeping current endpoint")
            guard pendingTarget != nil else { return Self.steadyCadence }
            pendingSince = Date()
            log("info: detector pending change restarted (error) target=\(pendingTarget?.rawValue ?? "none")")
            return WhitelistProbePreferences.switchProbeInterval
        }
    }

    private func applyBootstrapVerdict(_ endpoint: EndpointMode) {
        let previous = WhitelistStatusStore.activeEndpoint
        WhitelistStatusStore.activeEndpoint = endpoint
        log("info: detector bootstrap verdict=\(endpoint.rawValue) — applied immediately (previous=\(previous.rawValue))")
        guard endpoint != previous else { return }
        switchEndpoint(endpoint)
        postSwitchNotification(to: endpoint)
    }

    /// Rule 2: a later flip needs `switchHoldSeconds` of continuous
    /// agreement. Any agreeing cycle cancels the pending change.
    private func stablePhase(target: EndpointMode, current: EndpointMode) -> TimeInterval {
        guard target != current else {
            if let pending = pendingTarget {
                log("info: detector pending change cancelled target=\(pending.rawValue)")
                pendingTarget = nil
                pendingSince = nil
            }
            return Self.steadyCadence
        }
        if pendingTarget != target {
            pendingTarget = target
            pendingSince = Date()
            log("info: detector pending change started target=\(target.rawValue) hold=\(Int(WhitelistProbePreferences.switchHoldSeconds))s")
            return WhitelistProbePreferences.switchProbeInterval
        }
        let held = Date().timeIntervalSince(pendingSince ?? Date())
        guard held >= WhitelistProbePreferences.switchHoldSeconds else {
            return WhitelistProbePreferences.switchProbeInterval
        }
        WhitelistStatusStore.activeEndpoint = target
        log("warn: detector pending change committed target=\(target.rawValue) held=\(Int(held))s")
        switchEndpoint(target)
        postSwitchNotification(to: target)
        pendingTarget = nil
        pendingSince = nil
        return Self.steadyCadence
    }

    private func postSwitchNotification(to endpoint: EndpointMode) {
        guard NotificationPreferences.enabled else { return }
        let content = UNMutableNotificationContent()
        switch endpoint {
        case .backup:
            content.title = "Белые списки"
            content.body  = "Переключились на белые списки, чтобы связь не пропала."
        case .primary, .auto:
            content.title = "Обычный режим"
            content.body  = "Вернулись на обычный сервер."
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
