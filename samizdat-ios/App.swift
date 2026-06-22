import SwiftUI
import BackgroundTasks

@main
struct SamizdatTestApp: App {
    /// IPA-D22: theme is held at the App level so any sheet/child gets
    /// the right tokens via `@Environment(\.themeTokens)`. SettingsView's
    /// Appearance segmented control posts `Notification.Name
    /// .tamizdatThemeChanged` when the user picks a new theme; the root
    /// listens and re-reads `ThemePreferences.current` to update.
    @State private var theme: AppTheme = ThemePreferences.current

    /// IPA-D65b: scenePhase listener. The VK TURN refresher kicks off
    /// in the background when the app becomes active and the cached
    /// creds are within `TURNCredsStore.refreshCushion` (15 min) of
    /// expiry. We deliberately do NOT block startup — the refresh is
    /// a `Task { ... }` fire-and-forget. If creds are still fresh, the
    /// refresher returns immediately.
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Register Geist fonts as a safety net (Info.plist's UIAppFonts
        // should already have done this but xcodegen has historically
        // dropped the entry, and the fallback to SF Pro is loud — best
        // to also register at launch).
        GeistFont.register()

        // VK TURN credentials are now refreshed on demand. We still register
        // the BG task so iOS can wake us while Whitelist+TURN is active, but
        // all maintenance paths are policy-gated: Main/H2 or inactive TURN
        // must not burn VK captcha sessions.
        // The BG identifier MUST match
        //   - `Info.plist::BGTaskSchedulerPermittedIdentifiers`
        //   - `TURNCredsRefresher.backgroundTaskIdentifier`
        // …or the register call throws at runtime.
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: TURNCredsRefresher.backgroundTaskIdentifier,
            using: nil // any queue iOS hands us
        ) { task in
            guard let refreshTask = task as? BGAppRefreshTask else {
                task.setTaskCompleted(success: false)
                return
            }
            TURNCredsRefresher.runBackgroundRefresh(task: refreshTask)
        }
        // Only keep a BG request on the books while VK TURN is the effective
        // path. Otherwise iOS may wake the app just to hit VK and trigger a
        // captcha the user did not ask for.
        if TURNCredsRefresher.shouldMaintainTurnCredentialsNow() {
            TURNCredsRefresher.scheduleBackgroundRefresh()
        } else {
            TURNLog.info("turncreds", "initial BG refresh not scheduled — VK TURN not active/effective")
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.themeTokens, theme.tokens)
                .preferredColorScheme(theme.colorScheme)
                .onReceive(NotificationCenter.default.publisher(for: .tamizdatThemeChanged)) { _ in
                    theme = ThemePreferences.current
                }
        }
        .onChange(of: scenePhase) { _, newPhase in
            if newPhase == .active {
                // Fire-and-forget; the refresher is single-flight and
                // cheap when not needed (one App Group UserDefaults
                // read).
                Task { @MainActor in
                    TURNCredsRefresher.shared.handleForegroundActivation()
                }
            }
        }
    }
}
