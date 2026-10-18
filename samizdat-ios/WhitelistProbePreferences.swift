import Foundation

/// User-facing settings for carrier allowlist detection.
///
/// The detector sends ICMP echo requests to normally blocked controls and
/// domestic allowlisted controls. There are no TCP/TLS/HTTP probes here.
///
/// Persisted in App Group UserDefaults under the historical keys
/// `tamizdat.whitelistTestHost` and `tamizdat.whitelistWhitelistHost` so older
/// installs migrate naturally. Detection deliberately uses one target per
/// side; if an old value contains a list, only its first target is used.
enum WhitelistProbePreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let testHostKey = "tamizdat.whitelistTestHost"
    private static let whitelistHostKey = "tamizdat.whitelistWhitelistHost"
    private static let intervalKey = "tamizdat.whitelistProbeInterval"

    static let defaultTestHost = "8.8.8.8"
    static let defaultWhitelistHost = "77.88.8.8"
    static let defaultProbeInterval = 30

    /// Detection timing shared by the app-side WhitelistMonitor and the
    /// extension-side WhitelistDetector, so both obey the same rules.
    ///
    /// Bootstrap (monitor/detector start, network path change): probe
    /// immediately and apply the first decisive verdict at once. An
    /// inconclusive cycle is retried at this cadence.
    static let bootstrapRetryInterval: TimeInterval = 3

    /// Stable phase: the opposite endpoint is adopted only after the
    /// opposite verdict has held continuously for this long.
    static let switchHoldSeconds: TimeInterval = 60

    /// Re-probe cadence while a switch is pending.
    static let switchProbeInterval: TimeInterval = 10

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Foreign controls — expected to fail together under RU mobile default-deny
    /// allowlist mode, but to pass under normal internet.
    static var testHost: String {
        get {
            let stored = defaults?.string(forKey: testHostKey) ?? ""
            return stored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? defaultTestHost : stored
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: testHostKey)
            } else {
                defaults?.set(trimmed, forKey: testHostKey)
            }
        }
    }

    /// Domestic allowlisted controls — expected to stay reachable in default-
    /// deny allowlist mode and used as the online baseline.
    static var whitelistHost: String {
        get {
            let stored = defaults?.string(forKey: whitelistHostKey) ?? ""
            return stored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? defaultWhitelistHost : stored
        }
        set {
            let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                defaults?.removeObject(forKey: whitelistHostKey)
            } else {
                defaults?.set(trimmed, forKey: whitelistHostKey)
            }
        }
    }

    static var foreignControlTargets: [String] {
        Array(splitTargets(testHost, fallback: defaultTestHost).prefix(1))
    }

    static var domesticAllowlistedTargets: [String] {
        Array(splitTargets(whitelistHost, fallback: defaultWhitelistHost).prefix(1))
    }

    /// Seconds between foreground probe cycles in the steady state.
    /// Default 30. Range 5…120.
    static var probeInterval: Int {
        get {
            let v = defaults?.integer(forKey: intervalKey) ?? 0
            return v >= 5 && v <= 120 ? v : defaultProbeInterval
        }
        set {
            let clamped = max(5, min(120, newValue))
            defaults?.set(clamped, forKey: intervalKey)
        }
    }

    /// Restore all settings to their compiled-in defaults.
    static func reset() {
        defaults?.removeObject(forKey: testHostKey)
        defaults?.removeObject(forKey: whitelistHostKey)
        defaults?.removeObject(forKey: intervalKey)
    }

    private static func splitTargets(_ raw: String, fallback: String) -> [String] {
        let source = raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? fallback : raw
        let separators = CharacterSet(charactersIn: ",;\n\r\t")
        var seen = Set<String>()
        var out: [String] = []
        for part in source.components(separatedBy: separators) {
            let trimmed = part.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            let key = trimmed.lowercased()
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            out.append(trimmed)
        }
        return out
    }
}
