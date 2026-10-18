import Foundation

/// Live whitelist-detection state surfaced by WhitelistDetector. Persisted
/// in App Group UserDefaults so the main-app UI can poll it (Darwin
/// cross-process notifications would be cleaner but UserDefaults polling
/// at 2 Hz is plenty responsive for a status badge).
enum WhitelistStatus: String {
    case unknown    // grey  — not monitoring (auto off) OR no decisive cascade yet
    case off        // green — internet reachable, primary endpoint OK
    case detected   // red   — whitelist active, switched to backup
    case error      // red   — ping cycle completed without a valid verdict
    case frozen     // yellow — captive portal detected, decisions frozen
    case noNetwork  // grey  — path unsatisfied (lift/forest), probes paused

    var isMonitoring: Bool {
        self != .unknown
    }
}

enum WhitelistStatusStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let statusKey = "whitelistStatus"
    private static let updatedAtKey = "whitelistStatusUpdatedAt"
    private static let activeEndpointKey = "whitelistActiveEndpoint"

    /// The extension's slowest normal cadence is backup × Low Power Mode
    /// (2 × 3). Keep one extra interval of slack before treating a verdict as
    /// stale, while retaining the historical 200 s minimum.
    private static var autoDecisionMaxAge: TimeInterval {
        max(200, TimeInterval(WhitelistProbePreferences.probeInterval * 7))
    }

    // Legacy consecutive-result keys. Nothing reads them any more — the
    // 60 s hold replaced the consecutive-count threshold — but older
    // builds left them in the App Group, so `resetDetectionProgress`
    // still clears them.
    private static let legacyCounterKeys = [
        "whitelistConsecutiveCount",
        "freeConsecutiveCount",
        "whitelistFailbackSuccesses",
        "whitelistWhitelistSuccesses",
    ]

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// The current detector verdict.
    static var current: WhitelistStatus {
        get {
            guard let raw = defaults?.string(forKey: statusKey),
                  let s = WhitelistStatus(rawValue: raw)
            else { return .unknown }
            return s
        }
        set {
            defaults?.set(newValue.rawValue, forKey: statusKey)
            defaults?.set(Date().timeIntervalSince1970, forKey: updatedAtKey)
        }
    }

    /// Wall-clock seconds since the last status write. UI uses this to
    /// stale-out the badge if the extension stops reporting.
    static var ageSeconds: TimeInterval {
        let then = defaults?.double(forKey: updatedAtKey) ?? 0
        guard then > 0 else { return .infinity }
        return Date().timeIntervalSince1970 - then
    }

    /// Auto mode must not bootstrap a new tunnel from an arbitrarily old App
    /// Group endpoint. A decisive, recently-written status is required; the
    /// detector then refreshes that timestamp on every completed cycle.
    static var trustedAutoEndpoint: EndpointMode {
        guard ageSeconds <= autoDecisionMaxAge else { return .primary }
        switch current {
        case .detected, .off:
            return activeEndpoint == .backup ? .backup : .primary
        case .unknown, .error, .frozen, .noNetwork:
            return .primary
        }
    }

    /// Which endpoint the detector is currently routing through. Mirrors
    /// EndpointMode but tracks the *effective* choice (auto-mode picks
    /// primary or backup at runtime).
    static var activeEndpoint: EndpointMode {
        get {
            guard let raw = defaults?.string(forKey: activeEndpointKey),
                  let m = EndpointMode(rawValue: raw)
            else { return .primary }
            return m
        }
        set {
            defaults?.set(newValue.rawValue, forKey: activeEndpointKey)
        }
    }

    /// Probe results are process/path local: nothing about them crosses the
    /// App Group boundary. Cleared whenever the network, target set, or
    /// detector owner changes.
    static func resetDetectionProgress(preserveActiveEndpoint: Bool = true) {
        defaults?.removeObject(forKey: statusKey)
        defaults?.removeObject(forKey: updatedAtKey)
        for key in legacyCounterKeys {
            defaults?.removeObject(forKey: key)
        }
        if !preserveActiveEndpoint {
            defaults?.removeObject(forKey: activeEndpointKey)
        }
    }

    static func reset() {
        resetDetectionProgress(preserveActiveEndpoint: false)
    }
}
