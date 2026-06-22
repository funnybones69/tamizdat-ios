import Foundation

/// User-facing settings for carrier allowlist detection.
///
/// The old D65 detector used two ICMP targets. The current detector follows
/// the allowlist research: compare multiple foreign control domains against
/// multiple domestic allowlisted domains using TCP-connect + TLS-SNI probes.
/// ICMP remains available as a low-level helper file, but it is not a deciding
/// censorship signal.
///
/// Persisted in App Group UserDefaults under the historical keys
/// `tamizdat.whitelistTestHost` and `tamizdat.whitelistWhitelistHost` so older
/// installs migrate naturally. The values are now comma/semicolon/newline-
/// separated target lists, not single ping IPs.
enum WhitelistProbePreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let testHostKey = "tamizdat.whitelistTestHost"
    private static let whitelistHostKey = "tamizdat.whitelistWhitelistHost"
    private static let successesKey = "tamizdat.whitelistSuccessesNeeded"
    private static let intervalKey = "tamizdat.whitelistProbeInterval"

    static let defaultTestHost = "google.com, cloudflare.com"
    static let defaultWhitelistHost = "ya.ru, ozon.ru, gosuslugi.ru"
    static let defaultSuccessesNeeded = 3
    static let defaultProbeInterval = 30

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
        splitTargets(testHost, fallback: defaultTestHost)
    }

    static var domesticAllowlistedTargets: [String] {
        splitTargets(whitelistHost, fallback: defaultWhitelistHost)
    }

    /// Consecutive agreeing classifications before endpoint flips. Default 3.
    /// Range 1…10.
    static var successesNeeded: Int {
        get {
            let v = defaults?.integer(forKey: successesKey) ?? 0
            return v >= 1 && v <= 10 ? v : defaultSuccessesNeeded
        }
        set {
            let clamped = max(1, min(10, newValue))
            defaults?.set(clamped, forKey: successesKey)
        }
    }

    /// Seconds between foreground probe cycles. Default 30. Range 5…120.
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
        defaults?.removeObject(forKey: successesKey)
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
