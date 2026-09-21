import Foundation

/// When the restricted-profile detector flips the tunnel onto the "whitelist"
/// endpoint, this enum decides WHAT that endpoint actually is.
///
///   - `.vks`      — VKS room carriers: the tamizdat VKS ladder runs in
///                   the extension (provider toggles live in the Whitelist
///                   card). The backup URI is unused.
///   - `.vkTurn`   — new (Phase 2G): route the same traffic through
///                   VK TURN instead. The backup URI is unused (but
///                   NOT deleted — the operator may flip back).
///
/// Stored in App Group UserDefaults so the Network Extension and the
/// main app see the same value through a shared suite.
enum WhitelistMode: String, CaseIterable, Identifiable {
    case vks
    case vkTurn

    var id: String { rawValue }

    /// Russian label for SwiftUI pickers (operator-facing). Keep the
    /// strings short — they live inside a segmented control.
    var label: String {
        switch self {
        case .vks:      return "VKS"
        case .vkTurn:   return "TURN"
        }
    }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let storeKey = "tamizdat.whitelistMode"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Current selection. Default is `.vks` (H2 no longer works under
    /// the whitelist, so the carrier picker only offers VKS / TURN).
    static var current: WhitelistMode {
        get {
            guard let raw = defaults?.string(forKey: storeKey),
                  let mode = WhitelistMode(rawValue: raw) else {
                return .vks
            }
            return mode
        }
        set {
            defaults?.set(newValue.rawValue, forKey: storeKey)
        }
    }
}
