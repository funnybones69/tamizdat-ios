import Foundation

/// VKS room-transport settings (tamizdat VKS upstream).
///
/// The ladder runs inside the PacketTunnel extension — the same process
/// as the socksstub SOCKS5 bridge — so `dialUpstream` can chain TCP
/// flows through its loopback listener. The main app owns this UI and
/// writes the values into the App Group; the extension reads them at
/// `startTunnel`, so changes apply on the next VPN connect.
///
/// Values resolve in this order:
///   1. an explicit operator override saved from Settings → Дополнительно
///      (empty field = "use the link");
///   2. the `wakedns` / `wakezone` query params of the active
///      tamizdat:// profile link (see `SamizdatURLCodec.vksParams`);
///   3. `defaultWakeDNS` when neither the override nor the link carries a
///      wake DNS server, and a derived wake zone — `w.` + the primary
///      profile host's registrable domain (see `derivedWakeZone`) — when
///      the link carries no `wakezone`. IP-literal hosts and hosts with
///      fewer than two labels derive no zone, so the beacon stays off.
///
/// The room credential is the profile's shortid — the same identity the H2
/// tunnel authenticates with. There is no separate VKS wire key: beacon
/// selectors and the TXT answer are derived from the shortid.
///
/// The room itself is NOT chosen here: the client stores only the
/// providers — the server creates/assigns the room via the beacon TXT
/// answer. Provider ORDER (the ladder) is user-controlled: the first
/// entry is the primary the native transport dials, the rest are
/// failover candidates.
///
/// VKS always uses the H2 profile's server (the native path already
/// derives pubkey/SNI from the active profile blob), so there is no
/// server field here.
enum VKSPreferences {
    private static let appGroupID = "group.com.anarki.samizdat-test"

    private static let shortIDKey = "tamizdat.vks.shortIDHex"
    private static let wakeDNSKey = "tamizdat.vks.wakeDNS"
    private static let wakeZoneKey = "tamizdat.vks.wakeZone"
    private static let orderKey = "tamizdat.vks.order"

    /// Fixed local SOCKS5 listen port for the VKS ladder listener.
    /// Not user-configurable any more; must stay clear of the
    /// in-process socksstub port (18443).
    static let listenPort = 11080

    /// Default wake DNS server when neither the operator override nor
    /// the profile link carries one.
    static let defaultWakeDNS = "77.88.8.8:53"

    /// All providers the ladder understands, in canonical order.
    static let allProviders = ["telemost", "jazz", "mts"]

    /// Operator-facing name of a provider id ("telemost" → "Telemost").
    /// Unknown ids fall back to the raw id.
    static func providerDisplayName(_ provider: String) -> String {
        switch provider {
        case "telemost": return "Telemost"
        case "jazz":     return "Jazz"
        case "mts":      return "MTS"
        default:         return provider
        }
    }

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    // -- TEST-BUILD DEFAULTS ---------------------------------------------
    // Nothing deployment-specific is baked into this repository: the
    // master shortid is the per-user identity, and the wake zone
    // identifies the operator's own infrastructure. Fill them in from
    // Settings → Дополнительно → Параметры VKS (they live in the App
    // Group defaults) or pass them via the profile link.
    static let testDefaultShortIDHex = ""

    /// Ladder order — provider ids from `allProviders`. Unknown ids read
    /// from storage are dropped; missing ones are appended in canonical
    /// order so every provider always has a slot.
    static var providerOrder: [String] {
        get {
            let stored = defaults?.stringArray(forKey: orderKey) ?? []
            let known = stored.filter { allProviders.contains($0) }
            var out = known
            for p in allProviders where !out.contains(p) {
                out.append(p)
            }
            return out
        }
        set {
            let known = newValue.filter { allProviders.contains($0) }
            var out = known
            for p in allProviders where !out.contains(p) {
                out.append(p)
            }
            defaults?.set(out, forKey: orderKey)
        }
    }

    /// Per-provider enabled flag. A disabled provider is left out of the
    /// ladder even when it is first in the order, so a single provider
    /// can be exercised in isolation.
    static func providerEnabled(_ provider: String) -> Bool {
        let key = "tamizdat.vks.\(provider)Enabled"
        guard let d = defaults, d.object(forKey: key) != nil else { return true }
        return d.bool(forKey: key)
    }

    static func setProviderEnabled(_ provider: String, _ value: Bool) {
        let key = "tamizdat.vks.\(provider)Enabled"
        defaults?.set(value, forKey: key)
    }

    /// The stored override, ignoring empty AND the shipped test placeholder:
    /// a saved placeholder is not an operator choice (the server rejects it
    /// as "bad shortid"), so it must behave exactly like "unset". Without this,
    /// merely opening Settings once persists the placeholder over the profile
    /// identity and every provider beacon is rejected.
    private static func explicitShortID() -> String {
        guard let stored = defaults?.string(forKey: shortIDKey) else { return "" }
        let s = trim(stored).lowercased()
        return s == testDefaultShortIDHex ? "" : s
    }

    /// First entry of a comma-separated rotation pool, else the value as-is.
    private static func firstShortID(_ raw: String) -> String {
        let s = trim(raw).lowercased()
        guard let comma = s.firstIndex(of: ",") else { return s }
        return String(s[..<comma])
    }

    /// The VKS beacon MUST carry the caller's real user shortid: the server
    /// shortid-proofs provider beacons and REJECTS any shortid that is not a
    /// valid user. Never resolve to the placeholder — derive from the active
    /// profile link (the identity the H2 tunnel authenticates with).
    static var shortIDHex: String {
        get {
            let explicit = explicitShortID()
            if !explicit.isEmpty { return explicit }
            // Unset: fall back to the identity the app mirrors into the App
            // Group. This file is compiled into the extension target too,
            // where ConfigStore is unavailable — the mirror is the shared
            // source both targets can read.
            let mirrored = firstShortID(VKSPreferences.connectPasswordMirror)
            if !mirrored.isEmpty { return mirrored }
            return testDefaultShortIDHex
        }
        set { defaults?.set(trim(newValue).lowercased(), forKey: shortIDKey) }
    }

    /// The shortid the VKS provider beacon must carry. Prefers an explicit
    /// operator override (never the placeholder), then the identity from the
    /// active profile blob — the extension already holds it, so this works
    /// even when the App Group mirror was never written.
    static func beaconShortIDHex(profileBlob: String?) -> String {
        let explicit = explicitShortID()
        if !explicit.isEmpty { return explicit }
        if let blob = profileBlob, let peer = SamizdatURLCodec.h2PeerConfig(from: blob) {
            let s = firstShortID(peer.shortID)
            if !s.isEmpty { return s }
        }
        let mirrored = firstShortID(connectPasswordMirror)
        if !mirrored.isEmpty { return mirrored }
        return testDefaultShortIDHex
    }

    /// Explicit operator override for the wake DNS server. Writing an
    /// empty string clears the override (falls back to the link param /
    /// default). The resolved value comes from `wakeDNS(profileBlob:)`.
    static var wakeDNSOverride: String {
        get { defaults?.string(forKey: wakeDNSKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: wakeDNSKey) }
    }

    /// Explicit operator override for the wake zone. Writing an empty
    /// string clears the override. The resolved value comes from
    /// `wakeZone(profileBlob:)`.
    static var wakeZoneOverride: String {
        get { defaults?.string(forKey: wakeZoneKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: wakeZoneKey) }
    }

    /// On-demand wake beacon: the DNS server to send the wake query
    /// through (a whitelisted resolver, e.g. "77.88.8.8:53"). Resolution:
    /// explicit override → link's `wakedns` param → `defaultWakeDNS`.
    static func wakeDNS(profileBlob: String?) -> String {
        let explicit = defaults?.string(forKey: wakeDNSKey) ?? ""
        if !explicit.isEmpty { return explicit }
        if let blob = profileBlob, let params = SamizdatURLCodec.vksParams(from: blob),
           !params.wakeDNS.isEmpty {
            return params.wakeDNS
        }
        return defaultWakeDNS
    }

    /// On-demand wake beacon: the zone the server's NS is authoritative
    /// for (e.g. "wake.example.com"). Resolution: explicit override →
    /// link's `wakezone` param → derived zone (`derivedWakeZone`), so a
    /// profile link alone enables the beacon.
    static func wakeZone(profileBlob: String?) -> String {
        let explicit = defaults?.string(forKey: wakeZoneKey) ?? ""
        if !explicit.isEmpty { return explicit }
        if let blob = profileBlob, let params = SamizdatURLCodec.vksParams(from: blob),
           !params.wakeZone.isEmpty {
            return params.wakeZone
        }
        return derivedWakeZone(profileBlob: profileBlob)
    }

    /// Wake zone implied by the active profile link: the wake server is
    /// expected under `w.<registrable domain>` of the primary tamizdat://
    /// host, so the operator never has to type a zone. Registrable domain
    /// is the last two DNS labels, lowercased, trailing dot stripped
    /// (`sync.ai-archive.ru` → `ai-archive.ru` → zone `w.ai-archive.ru`).
    /// IP-literal hosts and hosts with fewer than two labels yield "" —
    /// no zone, so the beacon stays disabled exactly as before.
    static func derivedWakeZone(profileBlob: String?) -> String {
        guard let blob = profileBlob else { return "" }
        let primary = SamizdatURLCodec.split(blob).primary
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: primary),
              let scheme = components.scheme?.lowercased(),
              scheme == "tamizdat" || scheme == "samizdat",
              var host = components.host?.lowercased() else {
            return ""
        }
        // `components.host` carries no port and normally drops the
        // brackets of an IPv6 literal; tolerate both spellings anyway.
        if host.hasPrefix("[") {
            guard let close = host.firstIndex(of: "]") else { return "" }
            host = String(host[host.index(after: host.startIndex)..<close])
        }
        if host.hasSuffix(".") { host.removeLast() }
        if host.isEmpty { return "" }
        // IPv6 literal.
        if host.contains(":") { return "" }
        // IPv4 literal.
        let octets = host.split(separator: ".", omittingEmptySubsequences: false)
        if octets.count == 4,
           octets.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isNumber } && (Int($0) ?? 256) <= 255 }) {
            return ""
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: true)
        guard labels.count >= 2 else { return "" }
        return "w." + labels.suffix(2).joined(separator: ".")
    }

    /// Assembled `provider:room,` ladder spec over the user's order. A
    /// disabled provider is left out. Beacon-assignment: the client stores
    /// only the provider — the server creates/assigns the room via the TXT
    /// answer, so every room slot is the "stub" placeholder the server's
    /// assignment replaces.
    static func ladderSpec(profileBlob: String?) -> String {
        var parts: [String] = []
        for p in providerOrder where providerEnabled(p) {
            parts.append("\(p):stub")
        }
        return parts.joined(separator: ",")
    }

    static var providerCount: Int {
        providerOrder.filter { providerEnabled($0) }.count
    }

    /// True when the VKS ladder can be raised: at least one enabled
    /// provider and a usable user identity. The shortid is the only
    /// credential; it comes from the profile link (or an explicit
    /// override), never from a separate shared key.
    static func isConfigured(profileBlob: String?) -> Bool {
        !ladderSpec(profileBlob: profileBlob).isEmpty && shortIDLooksValid(profileBlob: profileBlob)
    }

    /// 16 hex characters — the master-shortid shape the native transport
    /// and the beacon derivation require.
    static func shortIDLooksValid(profileBlob: String?) -> Bool {
        let sid = beaconShortIDHex(profileBlob: profileBlob)
        return sid.count == 16 && sid.allSatisfy { $0.isHexDigit }
    }

    /// Mirror of the active profile's shortid, written by the main app so
    /// the extension (which cannot reach Keychain) can read the identity.
    /// Kept here (in VKSPreferences) because it is VKS that consumes it.
    private static let connectPasswordMirrorKey = "tamizdat.vkConnectPassword"
    private static var connectPasswordMirror: String {
        defaults?.string(forKey: connectPasswordMirrorKey) ?? ""
    }

    /// Written by the main app after every profile change so the extension
    /// sees the H2 identity without Keychain access. Passing nil clears
    /// the mirror so stale values cannot survive after the profile is
    /// removed.
    @discardableResult
    static func applyDerivedH2PeerConfig(_ config: SamizdatURLCodec.H2PeerConfig?) -> Bool {
        guard let config else {
            defaults?.set("", forKey: connectPasswordMirrorKey)
            return false
        }
        defaults?.set(config.shortID, forKey: connectPasswordMirrorKey)
        return true
    }

    private static func trim(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
