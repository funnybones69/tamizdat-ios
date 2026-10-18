import Foundation

/// Saved H2 profiles for the Proxies screen. The ACTIVE profile lives in
/// ConfigStore (Keychain) — that is the blob the extension reads — while
/// this store keeps the inactive ones the operator can flip to.
enum ProfileStore {
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let profilesKey = "tamizdat.profiles.v1"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    static func all() -> [String] {
        defaults?.stringArray(forKey: profilesKey) ?? []
    }

    /// Adds a profile (trimmed, deduped). No-op for empties/duplicates.
    static func add(_ url: String) {
        let value = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }
        var list = all()
        guard !list.contains(value) else { return }
        list.append(value)
        defaults?.set(list, forKey: profilesKey)
    }

    static func remove(_ url: String) {
        let list = all().filter { $0 != url }
        defaults?.set(list, forKey: profilesKey)
    }

    /// Replaces one saved profile in place, keeping its list position.
    /// No-op if `original` is not stored or `replacement` is empty. A
    /// pre-existing duplicate of `replacement` is dropped first so the list
    /// never holds the same URL twice.
    static func replace(_ original: String, with replacement: String) {
        let value = replacement.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value != original else { return }
        var list = all()
        guard list.contains(original) else { return }
        if let duplicate = list.firstIndex(of: value) {
            list.remove(at: duplicate)
        }
        guard let index = list.firstIndex(of: original) else { return }
        list[index] = value
        defaults?.set(list, forKey: profilesKey)
    }
}
