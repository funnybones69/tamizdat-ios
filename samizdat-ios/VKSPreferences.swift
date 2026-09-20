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
    private static let portKey = "tamizdat.vks.listenPort"

    static let defaultListenPort = 11080

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static var enabled: Bool {
        get { defaults?.bool(forKey: enabledKey) ?? false }
        set { defaults?.set(newValue, forKey: enabledKey) }
    }

    static var telemostRoom: String {
        get { defaults?.string(forKey: telemostKey) ?? "" }
        set { defaults?.set(trim(newValue), forKey: telemostKey) }
    }

    static var wbstreamRoom: String {
        get { defaults?.string(forKey: wbstreamKey) ?? "" }
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
        get { defaults?.string(forKey: keyHexKey) ?? "" }
        set { defaults?.set(trim(newValue).lowercased(), forKey: keyHexKey) }
    }

    static var shortIDHex: String {
        get { defaults?.string(forKey: shortIDKey) ?? "" }
        set { defaults?.set(trim(newValue).lowercased(), forKey: shortIDKey) }
    }

    static var listenPort: Int {
        get {
            let value = defaults?.integer(forKey: portKey) ?? 0
            return value > 0 ? value : defaultListenPort
        }
        set { defaults?.set(newValue, forKey: portKey) }
    }

    /// Assembled `provider:room,…` ladder spec in failover order.
    static var ladderSpec: String {
        var parts: [String] = []
        if !telemostRoom.isEmpty { parts.append("telemost:\(telemostRoom)") }
        if !wbstreamRoom.isEmpty { parts.append("wbstream:\(wbstreamRoom)") }
        if !jazzRoom.isEmpty { parts.append("jazz:\(jazzRoom)") }
        if !mtsRoom.isEmpty { parts.append("mts:\(mtsRoom)") }
        return parts.joined(separator: ",")
    }

    static var providerCount: Int {
        [telemostRoom, wbstreamRoom, jazzRoom, mtsRoom].filter { !$0.isEmpty }.count
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
