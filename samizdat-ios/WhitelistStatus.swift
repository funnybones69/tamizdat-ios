import Foundation

/// Live whitelist-detection state surfaced by WhitelistDetector. Persisted
/// in App Group UserDefaults so the main-app UI can poll it (Darwin
/// cross-process notifications would be cleaner but UserDefaults polling
/// at 2 Hz is plenty responsive for a status badge).
enum WhitelistStatus: String {
    case unknown    // grey  — not monitoring (auto off) OR no decisive cascade yet
    case off        // green — internet reachable, primary endpoint OK
    case detected   // red   — whitelist active, switched to backup
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

    // Main-app WhitelistMonitor consecutive-result counters
    private static let whitelistCountKey = "whitelistConsecutiveCount"
    private static let freeCountKey = "freeConsecutiveCount"

    // Extension WhitelistDetector consecutive-result counters
    private static let failbackSuccessesKey = "whitelistFailbackSuccesses"
    private static let whitelistSuccessesKey = "whitelistWhitelistSuccesses"

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

    /// The effective auto endpoint is a latched routing decision. Detector
    /// owners (main app while disconnected, extension while connected) may
    /// come and go, and probes may temporarily be unavailable, but neither
    /// event is evidence that the network became free. Only a thresholded
    /// probe decision changes `activeEndpoint`.
    ///
    /// Falling back to Main because `current` was transiently unknown or its
    /// timestamp aged out made a persisted Whitelist decision bootstrap H2.
    /// On a first install `activeEndpoint` naturally defaults to Main.
    static var trustedAutoEndpoint: EndpointMode {
        activeEndpoint == .backup ? .backup : .primary
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

    // -- Main-app monitor counters (WhitelistMonitor) --

    static var whitelistConsecutiveCount: Int {
        get { defaults?.integer(forKey: whitelistCountKey) ?? 0 }
        set { defaults?.set(newValue, forKey: whitelistCountKey) }
    }

    static var freeConsecutiveCount: Int {
        get { defaults?.integer(forKey: freeCountKey) ?? 0 }
        set { defaults?.set(newValue, forKey: freeCountKey) }
    }

    // -- Extension detector counters (WhitelistDetector) --

    static var failbackSuccesses: Int {
        get { defaults?.integer(forKey: failbackSuccessesKey) ?? 0 }
        set { defaults?.set(newValue, forKey: failbackSuccessesKey) }
    }

    static var whitelistSuccessesExtension: Int {
        get { defaults?.integer(forKey: whitelistSuccessesKey) ?? 0 }
        set { defaults?.set(newValue, forKey: whitelistSuccessesKey) }
    }

    /// Consecutive probe results are process/path local. Clear them whenever
    /// the network, target set, threshold, or detector owner changes; carrying
    /// 2/3 successes from another carrier path makes identical phones diverge.
    ///
    /// The last verdict and latched endpoint are deliberately preserved by
    /// default. Lifecycle/configuration changes are not probe results and must
    /// not make the UI return to "Monitoring…" or make Auto bootstrap Main.
    static func resetDetectionProgress(
        preserveActiveEndpoint: Bool = true,
        preserveVerdict: Bool = true
    ) {
        if !preserveVerdict {
            defaults?.removeObject(forKey: statusKey)
            defaults?.removeObject(forKey: updatedAtKey)
        }
        defaults?.removeObject(forKey: whitelistCountKey)
        defaults?.removeObject(forKey: freeCountKey)
        defaults?.removeObject(forKey: failbackSuccessesKey)
        defaults?.removeObject(forKey: whitelistSuccessesKey)
        if !preserveActiveEndpoint {
            defaults?.removeObject(forKey: activeEndpointKey)
        }
    }

    static func reset() {
        resetDetectionProgress(
            preserveActiveEndpoint: false,
            preserveVerdict: false
        )
    }
}
