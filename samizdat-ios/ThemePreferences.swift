import Foundation
import SwiftUI

/// Persistence for the appearance picker in Settings → Оформление.
/// Options: Системная (follows iOS), Светлая (cream), Тёмная (dark).
///
/// We store the choice in standard UserDefaults rather than the App
/// Group container because the theme is a main-app-only concern — the
/// extension doesn't render any UI.
enum AppTheme: String, CaseIterable, Identifiable {
    case cream
    case dark

    var id: String { rawValue }

    /// Title shown in segmented controls.
    var label: String {
        switch self {
        case .cream: return "Светлая"
        case .dark:  return "Тёмная"
        }
    }

    /// Maps the user pick to a SwiftUI `ColorScheme`. We always force a
    /// scheme — the design relies on theme tokens, not system colours,
    /// so the iOS system Dark/Light switch must NOT auto-flip the UI
    /// except through the explicit "Системная" option, which resolves
    /// via UITraitCollection at render time.
    var colorScheme: ColorScheme {
        switch self {
        case .cream: return .light
        case .dark:  return .dark
        }
    }

    /// Matching ThemeTokens.
    var tokens: ThemeTokens {
        switch self {
        case .cream: return .cream
        case .dark:  return .dark
        }
    }
}

enum ThemePreferences {
    private static let key = "tamizdat.theme"

    /// The option the user picked (system / cream / dark). The value
    /// "system" is new; legacy installs store "cream"/"dark" and keep
    /// working.
    static var option: String {
        get {
            UserDefaults.standard.string(forKey: key)
                ?? AppTheme.cream.rawValue
        }
        set {
            UserDefaults.standard.set(newValue, forKey: key)
        }
    }

    /// The theme the UI should render with RIGHT NOW: resolves
    /// "system" against the current iOS interface style.
    static var current: AppTheme {
        let raw = option
        if raw == "system" {
            let style = UITraitCollection.current.userInterfaceStyle
            return style == .dark ? .dark : .cream
        }
        return AppTheme(rawValue: raw) ?? .cream
    }
}
