import Foundation

/// VKS room-transport settings (tamizdat VKS upstream).
///
/// The ladder runs inside the PacketTunnel extension — the same process
/// as the socksstub SOCKS5 bridge — so `dialUpstream` can chain TCP
/// flows through its loopback listener. The main app owns this UI and
/// writes the values into the App Group; the extension reads them at
/// `startTunnel`, so changes apply on the next VPN connect.
///
/// Room shapes per provider (matching `vks.ParseSpecs`):
///   - telemost: full room URL (`https://telemost.yandex.ru/j/…`)
///   - wbstream: room id (guests join; an owner server creates the room)
///   - jazz:     `roomId:password`
///   - mts:      full room link (`https://my.mts-link.ru/j/…`)
///
/// Ladder order is fixed — telemost → wbstream → jazz → mts: the first
/// configured provider goes first and failover walks the rest.
enum VKSPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"

    private static let enabledKey = "tamizdat.vks.enabled"
    private static let telemostKey = "tamizdat.vks.telemostRoom"
    private static let wbstreamKey = "tamizdat.vks.wbstreamRoom"
    private static let jazzKey = "tamizdat.vks.jazzRoom"
    private static let mtsKey = "tamizdat.vks.mtsRoom"
    private static let keyHexKey = "tamizdat.vks.keyHex"
    private static let shortIDKey = "tamizdat.vks.shortIDHex"
    private static let wakeDNSKey = "tamizdat.vks.wakeDNS"
    private static let wakeZoneKey = "tamizdat.vks.wakeZone"
    private static let portKey = "tamizdat.vks.listenPort"
    private static let serverKey = "tamizdat.vks.server"
    private static let telemostEnabledKey = "tamizdat.vks.telemostEnabled"
    private static let wbstreamEnabledKey = "tamizdat.vks.wbstreamEnabled"
    private static let jazzEnabledKey = "tamizdat.vks.jazzEnabled"
    private static let mtsEnabledKey = "tamizdat.vks.mtsEnabled"

    static let defaultListenPort = 11080

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    // -- TEST-BUILD DEFAULTS (2026-09-20) --------------------------------
    // Baked-in values so the on-device VKS test needs zero manual input:
    // the card shows them pre-filled and the ladder starts on connect.
    // Remove once server-side provisioning of rooms/key lands.
    static let testDefaultWbstreamRoom = "stab_gw"
    static let testDefaultKeyHex = "REDACTED-VKS-KEY"
    static let testDefaultShortIDHex = "REDACTED-SHORTID"
    // On-demand wake beacon: Yandex DNS (whitelisted) → wake.example.com NS (ru2).
    static let testDefaultWakeDNS = "77.88.8.8:53"
    static let testDefaultWakeZone = "wake.example.com"

    static var enabled: Bool {
        get {
            if defaults?.object(forKey: enabledKey) == nil { return true }
            return defaults?.bool(forKey: enabledKey) ?? false
        }
        set { defaults?.set(newValue, forKey: enabledKey) }
    }

    /// Per-provider switches: a disabled provider is left out of the
    /// ladder even when its room is filled, so a single provider can be
    /// exercised in isolation.
    static var telemostEnabled: Bool {
        get {
            guard let d = defaults, d.object(forKey: telemostEnabledKey) != nil else { return true }
            return d.bool(forKey: telemostEnabledKey)
        }
        set { defaults?.set(newValue, forKey: telemostEnabledKey) }
    }

    static var wbstreamEnabled: Bool {
        get {
            guard let d = defaults, d.object(forKey: wbstreamEnabledKey) != nil else { return true }
            return d.bool(forKey: wbstreamEnabledKey)
        }
        set { defaults?.set(newValue, forKey: wbstreamEnabledKey) }
    }

    static var jazzEnabled: Bool {
        get {
            guard let d = defaults, d.object(forKey: jazzEnabledKey) != nil else { return true }
            return d.bool(forKey: jazzEnabledKey)
        }
        set { defaults?.set(newValue, forKey: jazzEnabledKey) }
    }

    static var mtsEnabled: Bool {
        get {
            guard let d = defaults, d.object(forKey: mtsEnabledKey) != nil else { return true }
            return d.bool(forKey: mtsEnabledKey)
        }
        set { defaults?.set(newValue, forKey: mtsEnabledKey) }
    }

    static var telemostRoom: String {
        get { defaults?.string(forKey: telemostKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: telemostKey) }
    }

    static var wbstreamRoom: String {
        get { defaults?.string(forKey: wbstreamKey) ?? testDefaultWbstreamRoom }
        set { defaults?.set(trim(newValue), forKey: wbstreamKey) }
    }

    static var jazzRoom: String {
        get { defaults?.string(forKey: jazzKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: jazzKey) }
    }

    static var mtsRoom: String {
        get { defaults?.string(forKey: mtsKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: mtsKey) }
    }

    static var keyHex: String {
        get { defaults?.string(forKey: keyHexKey) ?? testDefaultKeyHex }
        set { defaults?.set(trim(newValue).lowercased(), forKey: keyHexKey) }
    }

    /// The VKS beacon MUST carry the caller's real user shortid: the server
    /// shortid-proofs provider beacons and REJECTS any shortid that is not a
    /// valid user. An unset field therefore must not fall back to a
    /// placeholder — derive it from the Main profile URI (the same identity
    /// the H2 tunnel authenticates with) so the beacon is accepted.
    static var shortIDHex: String {
        get {
            if let stored = defaults?.string(forKey: shortIDKey), !trim(stored).isEmpty {
                return trim(stored).lowercased()
            }
            // Unset: fall back to the identity the app mirrors into the App
            // Group (derived from the Main profile URI — the same one the H2
            // tunnel authenticates with). Never a placeholder: the server
            // shortid-proofs provider beacons and rejects unknown shortids.
            // This file is compiled into the extension target too, where
            // ConfigStore is unavailable — the App Group mirror is the shared
            // source both targets can read.
            let mirrored = trim(VKCredsPreferences.connectPassword)
            if !mirrored.isEmpty {
                return mirrored.lowercased()
            }
            return testDefaultShortIDHex
        }
        set { defaults?.set(trim(newValue).lowercased(), forKey: shortIDKey) }
    }

    /// The shortid the VKS provider beacon must carry. Prefers an explicit
    /// operator override, then the identity from the active profile blob —
    /// the extension already holds it, so this works even when the App Group
    /// mirror was never written. The server shortid-proofs provider beacons
    /// and REJECTS any shortid that is not a valid user, so this must never
    /// silently resolve to a placeholder.
    static func beaconShortIDHex(profileBlob: String?) -> String {
        if let stored = defaults?.string(forKey: shortIDKey), !trim(stored).isEmpty {
            return trim(stored).lowercased()
        }
        if let blob = profileBlob, let peer = SamizdatURLCodec.h2PeerConfig(from: blob) {
            let s = trim(peer.shortID).lowercased()
            if !s.isEmpty { return s }
        }
        let mirrored = trim(VKCredsPreferences.connectPassword).lowercased()
        if !mirrored.isEmpty { return mirrored }
        return testDefaultShortIDHex
    }

    /// Explicit server for the VKS carrier (host:port). Empty = no value
    /// (deliberately no default).
    static var server: String {
        get { defaults?.string(forKey: serverKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: serverKey) }
    }

    static var listenPort: Int {
        get {
            let value = defaults?.integer(forKey: portKey) ?? 0
            return value > 0 ? value : defaultListenPort
        }
        set { defaults?.set(newValue, forKey: portKey) }
    }

    /// On-demand wake beacon: the DNS server to send the wake query
    /// through (a whitelisted resolver, e.g. "77.88.8.8:53"). Empty
    /// disables the beacon (the server must then already be in the room).
    static var wakeDNS: String {
        get { defaults?.string(forKey: wakeDNSKey) ?? testDefaultWakeDNS }
        set { defaults?.set(trim(newValue), forKey: wakeDNSKey) }
    }

    /// On-demand wake beacon: the zone the server's NS is authoritative
    /// for (e.g. "wake.example.com").
    static var wakeZone: String {
        get { defaults?.string(forKey: wakeZoneKey) ?? testDefaultWakeZone }
        set { defaults?.set(trim(newValue), forKey: wakeZoneKey) }
    }
    /// Assembled `provider:room,` ladder spec in failover order. A provider
    /// is included when its switch is on. Beacon-assignment: the client
    /// stores only the provider — the server creates/assigns the room via
    /// the TXT answer; an explicit room is an optional override/fallback
    /// (used when the provider beacon fails). An empty room emits a "stub"
    /// placeholder the server's assignment replaces.
    static var ladderSpec: String {
        var parts: [String] = []
        if telemostEnabled { parts.append("telemost:\(telemostRoom.isEmpty ? "stub" : telemostRoom)") }
        if wbstreamEnabled { parts.append("wbstream:\(wbstreamRoom.isEmpty ? "stub" : wbstreamRoom)") }
        if jazzEnabled { parts.append("jazz:\(jazzRoom.isEmpty ? "stub" : jazzRoom)") }
        if mtsEnabled { parts.append("mts:\(mtsRoom.isEmpty ? "stub" : mtsRoom)") }
        return parts.joined(separator: ",")
    }

    static var providerCount: Int {
        var count = 0
        if telemostEnabled { count += 1 }
        if wbstreamEnabled { count += 1 }
        if jazzEnabled { count += 1 }
        if mtsEnabled { count += 1 }
        return count
    }

    static var isConfigured: Bool {
        !ladderSpec.isEmpty && keyLooksValid && !shortIDHex.isEmpty
    }

    /// 64 hex characters — the olcRTC wire-key shape.
    static var keyLooksValid: Bool {
        keyHex.count == 64 && keyHex.allSatisfy { $0.isHexDigit }
    }

    /// Restore all VKS settings to their defaults.
    static func reset() {
        enabled = false
        telemostEnabled = true
        wbstreamEnabled = true
        jazzEnabled = true
        mtsEnabled = true
        telemostRoom = ""
        wbstreamRoom = ""
        jazzRoom = ""
        mtsRoom = ""
        keyHex = ""
        shortIDHex = ""
        listenPort = defaultListenPort
    }

    private static func trim(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
