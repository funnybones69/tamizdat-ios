import Foundation
import SwiftUI
import BackgroundTasks
import UserNotifications

/// Drives VK TURN session parameter acquisition + caching on the main-app side.
///
/// WHY this file is main-app-only: it owns the WebKit verification manager
/// (WKWebView) and the SwiftUI plumbing for the manual fallback
/// (the manual verification sheet). The Network Extension cannot import WebKit
/// — Apple disallows WKWebView in app extensions, and the build
/// would fail. The pure-read side (`TURNSession paramsStore`,
/// `VKTURNSession parameters`, `VKSession paramsPreferences`) lives in
/// `TURNSession paramsStore.swift` and IS shared with the extension target.
///
/// Lifetimes:
///   - Single shared instance per process; survives scene transitions.
///   - Builds a fresh `VKSession paramsClient` per refresh so each attempt owns
///     its own URLSession/cookie state.
///   - The slider-fallback flow is surfaced via `manualChallenge`,
///     which `ContentView` binds to a the manual verification sheet. When the
///     sheet finishes, the coordinator resumes its waiting
///     continuation with the user-supplied success_token.
private enum TURNCredsRefreshWaitError: LocalizedError {
    case notConfigured
    case timedOut
    case stillStale(String?)

    var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "VK TURN не настроен: нет call hash/device settings"
        case .timedOut:
            return "Не дождались свежих VK TURN credentials"
        case .stillStale(let lastError):
            if let lastError, !lastError.isEmpty {
                return "VK TURN credentials всё ещё устарели: \(lastError)"
            }
            return "VK TURN credentials всё ещё устарели"
        }
    }
}

@MainActor
final class TURNCredsRefresher: ObservableObject {
    static let shared = TURNCredsRefresher()

    /// True while a refresh is in flight. Drives the "Resolving
    /// verification challenge..." status indicator + dedupes concurrent triggers.
    @Published private(set) var isRefreshing: Bool = false

    /// Last refresh outcome — nil until the first attempt lands.
    /// Surfaced for UI / log display.
    @Published private(set) var lastError: String?

    /// Short, non-error progress message for the home screen. This is
    /// intentionally separate from `lastError`: trying the primary
    /// accountless flow and switching to CAPTCHA fallback are expected
    /// compatibility states, not red error states.
    @Published private(set) var turnInfo: String?

    /// Auto-dismisses transient method-selection/status messages from the
    /// home screen. They are informational, not persistent errors.
    private var turnInfoDismissTask: Task<Void, Never>?

    /// When non-nil, a the manual verification sheet should be presented so
    /// the user can solve the slider. The sheet calls `resolveManual`
    /// / `cancelManual` to drive the refresh forward.
    @Published var manualChallenge: ManualChallenge?

    /// Active single-flight task; we cancel + replace rather than
    /// stacking refreshes when multiple scene-active events fire in
    /// quick succession.
    private var inFlight: Task<Void, Never>?

    /// Last successful App Group session parameters write in this process.
    /// Used to debounce accidental immediate `forceRefresh` replays.
    private var lastSaveAt: Date?

    /// Start time/generation for the current refresh singleflight.
    /// Used to recover from verification/WebKit hangs where the app remains
    /// `isRefreshing=true` and every explicit Save/Refresh gets skipped.
    private var refreshStartedAt: Date?
    private var refreshGeneration: Int = 0

    deinit {
        turnInfoDismissTask?.cancel()
    }

    func publishTurnInfo(_ message: String) {
        turnInfoDismissTask?.cancel()
        turnInfo = message
        turnInfoDismissTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            guard !Task.isCancelled else { return }
            self?.turnInfo = nil
            self?.turnInfoDismissTask = nil
        }
    }

    /// Manual-fallback handoff: when the auto handler throws
    /// `.sliderRequired`, we open the sheet and `await` this
    /// continuation. The sheet calls `resolveManual(token:)` to
    /// resume with the token or `cancelManual()` to throw.
    private var manualContinuation: CheckedContinuation<String, Error>?

    /// 5-minute foreground heartbeat. It is intentionally policy-gated:
    /// the timer calls `refreshIfNeeded(reason:)`, which returns before
    /// touching VK unless Restricted+Relay is the effective path.
    private var heartbeatTimer: Timer?

    /// Number of refresh attempts that have failed in a row. Reset on
    /// success. When it hits `failureNotificationThreshold` we
    /// schedule a local notification so the user knows to open the
    /// app and solve a verification manually.
    private var consecutiveFailures: Int = 0

    /// BG task identifier — MUST match the one registered in
    /// `BGTaskScheduler.shared.register(...)` (called from App.swift)
    /// and the `BGTaskSchedulerPermittedIdentifiers` array in
    /// `Info.plist`. Keep all three in sync.
    ///
    /// `nonisolated` so the BG-task register closure in App.swift can
    /// read it from off-MainActor without an `await`.
    nonisolated static let backgroundTaskIdentifier = "com.anarki.samizdat-test.creds-refresh"

    private init() {
        startHeartbeat()
    }

    /// Identifies a pending manual challenge for the SwiftUI sheet.
    struct ManualChallenge: Identifiable, Equatable {
        let id = UUID()
        let redirectURI: URL
        let sessionToken: String
    }

    /// True when maintaining VK TURN session parameters is useful right now.
    /// We do NOT rotate session params just because VK TURN is configured: VK verification challenge
    /// sessions are expensive and noisy. Keep session params fresh only while the
    /// effective endpoint is Restricted+Relay.
    nonisolated static func shouldMaintainTurnCredentialsNow() -> Bool {
        guard WhitelistMode.current == .vkTurn else { return false }
        switch EndpointModeStore.current {
        case .backup:
            return true
        case .auto:
            return WhitelistStatusStore.trustedAutoEndpoint == .backup
        case .primary:
            return false
        }
    }

    /// Called when the app becomes active. Handles notification-tap recovery
    /// first, otherwise does a policy-gated maintenance refresh.
    func handleForegroundActivation() {
        if CredsRefreshNotification.consumePendingOpenRequest() {
            TURNLog.warn("turncreds", "foreground after captcha-needed notification — retrying refresh to present captcha UI")
            forceRefresh(reason: "captchaNotification")
            return
        }

        if TURNCredsStore.shared.needsRefresh {
            forceRefresh(reason: "foregroundNearExpiry", requireActiveTURN: true)
        } else {
            refreshIfNeeded(reason: "foreground")
        }
    }

    /// Fire-and-forget maintenance refresh. Idempotent and policy-gated: if
    /// the user is not currently using Restricted+Relay, this returns without
    /// touching VK. Exception: `forceRefresh(reason:)` is still available for
    /// user-visible on-demand actions such as Connect or notification-open.
    func refreshIfNeeded(reason: String = "auto") {
        TURNLog.info("turncreds", "refreshIfNeeded called reason=\(reason)")
        guard Self.shouldMaintainTurnCredentialsNow() else {
            TURNLog.info("turncreds", "refreshIfNeeded: skipped — VK TURN not active/effective")
            return
        }
        guard !isRefreshing else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — isRefreshing is true")
            return
        }
        guard VKCredsPreferences.isConfigured else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — isConfigured is false")
            return
        }
        guard TURNCredsStore.shared.needsRefresh else {
            TURNLog.warn("turncreds", "refreshIfNeeded: skipped — needsRefresh is false")
            return
        }
        startRefresh()
    }

    /// Manually trigger a refresh regardless of staleness. Intended
    /// for "Refresh now" UI affordances; currently unused but kept
    /// public so a future Settings row can call it.
    func forceRefresh(reason: String = "manual", requireActiveTURN: Bool = false) {
        if requireActiveTURN && !Self.shouldMaintainTurnCredentialsNow() {
            TURNLog.info("turncreds", "forceRefresh skipped reason=\(reason) — VK TURN not active/effective")
            return
        }
        if let elapsedMs = millisecondsSinceLastSave,
           elapsedMs < Int(Self.forceRefreshDebounceAfterSave * 1000) {
            TURNLog.warn("turncreds", "forceRefresh debounced (\(elapsedMs) ms since last save)")
            return
        }
        TURNLog.info("turncreds", "forceRefresh called reason=\(reason)")
        if isRefreshing {
            let age = refreshStartedAt.map { Date().timeIntervalSince($0) } ?? 0
            guard age >= Self.forceRestartStaleRefreshAfter else {
                TURNLog.warn("turncreds", "forceRefresh: skipped — isRefreshing is true (age=\(Int(age))s)")
                return
            }
            TURNLog.warn("turncreds", "forceRefresh: stale in-flight refresh age=\(Int(age))s — cancelling and restarting")
            cancelInFlightForRestart(error: CaptchaError.cancelled)
        }
        guard VKCredsPreferences.isConfigured else {
            TURNLog.warn("turncreds", "forceRefresh: skipped — isConfigured is false")
            return
        }
        startRefresh()
    }

    /// Connect-time gate: if Restricted+Relay is about to start and cached
    /// session params are stale/missing, do not bring up the PacketTunnel with known-
    /// bad session params. Start/reuse the refresh flow, let SwiftUI present manual
    /// verification challenge if VK asks for it, and return only once App Group session params are
    /// fresh enough for the extension to attach TURN.
    func ensureFreshForConnect(reason: String = "connectVKTurn",
                               timeout: TimeInterval = 780) async throws {
        guard TURNCredsStore.shared.needsRefreshForConnect else {
            TURNLog.info("turncreds", "connect preflight: cached VK TURN creds are fresh")
            return
        }
        guard VKCredsPreferences.isConfigured else {
            TURNLog.warn("turncreds", "connect preflight failed — VK creds preferences not configured")
            throw TURNCredsRefreshWaitError.notConfigured
        }

        TURNLog.warn("turncreds", "connect preflight: stale/missing VK TURN creds — refreshing before tunnel attach")
        forceRefresh(reason: reason)

        let deadline = Date().addingTimeInterval(timeout)
        var loggedManualWait = false
        while isRefreshing {
            if manualChallenge != nil && !loggedManualWait {
                TURNLog.warn("turncreds", "connect preflight waiting for manual captcha")
                loggedManualWait = true
            }
            if Date() >= deadline {
                TURNLog.error("turncreds", "connect preflight timed out after \(Int(timeout))s")
                throw TURNCredsRefreshWaitError.timedOut
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }

        guard !TURNCredsStore.shared.needsRefreshForConnect else {
            TURNLog.error("turncreds", "connect preflight failed — creds still stale after refresh: \(lastError ?? "<no error>")")
            throw TURNCredsRefreshWaitError.stillStale(lastError)
        }
        TURNLog.info("turncreds", "connect preflight ok — fresh VK TURN creds ready")
    }

    /// Called by `manual verification sheet.onSuccess` — hands the user-
    /// solved token back to the in-flight refresh task.
    func resolveManual(token: String) {
        TURNLog.info("turncreds", "manual token resolved (length=\(token.count))")
        manualChallenge = nil
        CaptchaNotification.cancel()
        manualContinuation?.resume(returning: token)
        manualContinuation = nil
    }

    /// Called by `manual verification sheet.onCancel` — aborts the refresh.
    func cancelManual() {
        TURNLog.warn("turncreds", "manual captcha cancelled by user")
        manualChallenge = nil
        CaptchaNotification.cancel()
        manualContinuation?.resume(throwing: CaptchaError.cancelled)
        manualContinuation = nil
    }

    // MARK: – Private

    /// Overall watchdog: if the refresh hasn't completed in this many
    /// seconds, the Task is cancelled so `isRefreshing` flips back to
    /// false and the next Save attempt isn't dead in the water.
    /// Sized generously: per-request timeout is 20s, max 5 retries +
    /// up to 45s verification step = ~145s worst case. 180s gives slack.
    private static let watchdogTimeout: TimeInterval = 180

    /// Human-initiated force refresh may replace a wedged in-flight
    /// attempt after this age. Shorter active attempts remain deduped so
    /// repeated Settings saves do not burn VK verification sessions.
    private static let forceRestartStaleRefreshAfter: TimeInterval = 60

    /// Belt-and-suspenders guard: after a successful save, any
    /// `forceRefresh` replay within this window is programmatic noise
    /// (not a human tap) and would burn another VK verification challenge session.
    private static let forceRefreshDebounceAfterSave: TimeInterval = 2

    private var millisecondsSinceLastSave: Int? {
        guard let lastSaveAt else { return nil }
        return Int(Date().timeIntervalSince(lastSaveAt) * 1000)
    }

    private func startRefresh() {
        inFlight?.cancel()
        refreshGeneration += 1
        let generation = refreshGeneration
        refreshStartedAt = Date()
        isRefreshing = true
        lastError = nil
        turnInfoDismissTask?.cancel()
        turnInfo = nil
        TURNLog.info("turncreds", "starting refresh task gen=\(generation)")

        inFlight = Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                if self.refreshGeneration == generation {
                    self.isRefreshing = false
                    self.inFlight = nil
                    self.refreshStartedAt = nil
                }
            }
            do {
                let hashes = VKCredsPreferences.roomHashes
                guard !hashes.isEmpty else { throw TURNCredsRefreshWaitError.notConfigured }
                var roomCredentials: [VKTURNRoomCredentials] = []
                roomCredentials.reserveCapacity(hashes.count)

                // Deliberately sequential: the CAPTCHA fallback owns one
                // WKWebView/manual challenge. Parallel room refreshes would race
                // that single UI. Accountless rooms normally finish quickly.
                for (index, hash) in hashes.enumerated() {
                    self.publishTurnInfo("TURN: комната \(index + 1)/\(hashes.count) — пробую без капчи…")
                    let config = VKCredsConfig(
                        callHash: hash,
                        secondaryHash: nil,
                        deviceID: VKCredsPreferences.deviceID
                    )
                    TURNLog.info("turncreds", "fetching room \(index + 1)/\(hashes.count)")
                    let client = VKCredsClient(
                        config: config,
                        captchaSolver: ChainedCaptchaSolver(refresher: self),
                        progress: { [weak self] message in
                            Task { @MainActor in
                                self?.publishTurnInfo("Комната \(index + 1)/\(hashes.count): \(message)")
                            }
                        }
                    )
                    let creds = try await withThrowingTaskGroup(of: VKTURNCredentials.self) { group in
                        group.addTask { try await client.fetchCredentials() }
                        group.addTask {
                            try await Task.sleep(nanoseconds: UInt64(Self.watchdogTimeout * 1_000_000_000))
                            throw VKCredsError.transport(step: "watchdog", underlying: CancellationError())
                        }
                        guard let first = try await group.next() else { throw CancellationError() }
                        group.cancelAll()
                        return first
                    }
                    guard creds.expiresAt.timeIntervalSinceNow > TURNCredsStore.refreshCushion else {
                        throw TURNCredsRefreshWaitError.stillStale(
                            "комната \(index + 1): недостаточный TTL"
                        )
                    }
                    roomCredentials.append(VKTURNRoomCredentials(roomHash: hash, credentials: creds))
                }

                guard self.refreshGeneration == generation else {
                    TURNLog.warn("turncreds", "stale multi-room refresh finished after replacement; discarding")
                    return
                }
                guard TURNCredsStore.shared.saveRooms(roomCredentials) else {
                    throw TURNCredsRefreshWaitError.stillStale("не удалось сохранить multi-room credential bundle")
                }
                guard TURNCredsStore.shared.roomsAreFresh else {
                    throw TURNCredsRefreshWaitError.stillStale("неполный multi-room credential bundle")
                }
                TURNCredsStore.shared.clearQuotaStormMarker()
                self.publishTurnInfo("TURN: \(roomCredentials.count) комнат готовы, \(roomCredentials.count * 20) workers.")

                let bundleJSON = vkRoomCredsAsJSON(roomCredentials)
                let updateErr = SamizdatBridge.updateVKTurnRoomCreds(bundleJSON)
                if updateErr.isEmpty {
                    TURNLog.info("turncreds", "multi-room runner creds updated in-process")
                } else if updateErr == "not running" {
                    TURNLog.info("turncreds", "multi-room runner not running in app process")
                } else {
                    TURNLog.warn("turncreds", "multi-room creds update returned: \(updateErr)")
                }
                let extUpdate = await VPNProfileStore.shared.refreshVKTurnCreds()
                if extUpdate == "ok" || extUpdate.isEmpty || extUpdate == "not running" {
                    TURNLog.info("turncreds", "extension multi-room refresh result=\(extUpdate.isEmpty ? "not-running" : extUpdate)")
                } else {
                    TURNLog.warn("turncreds", "extension multi-room refresh returned: \(extUpdate)")
                }
                self.lastSaveAt = Date()
                self.lastError = nil
                self.consecutiveFailures = 0
                CredsRefreshNotification.cancel()
                // After every successful refresh, queue the next BG
                // task so iOS has a fresh request to satisfy ~45 min
                // from now. iOS will only fire it when it has budget,
                // but at least the request is on the books.
                if Self.shouldMaintainTurnCredentialsNow() {
                    Self.scheduleBackgroundRefresh()
                } else {
                    TURNLog.info("turncreds", "BG refresh not scheduled after save — VK TURN not active/effective")
                }
            } catch {
                guard self.refreshGeneration == generation else {
                    TURNLog.warn("turncreds", "stale refresh gen=\(generation) failed after replacement; ignoring")
                    return
                }
                let msg: String
                if let e = error as? VKCredsError {
                    msg = e.localizedDescription
                } else if let e = error as? CaptchaError {
                    msg = e.localizedDescription
                } else {
                    msg = error.localizedDescription
                }
                TURNLog.error("turncreds", "refresh failed: \(msg)")
                self.lastError = msg
                self.consecutiveFailures += 1
                TURNLog.warn("turncreds", "consecutive failures = \(self.consecutiveFailures)")
                if self.consecutiveFailures >= Self.failureNotificationThreshold {
                    TURNLog.warn("turncreds",
                        "failure threshold reached — scheduling captcha-needed notification")
                    CredsRefreshNotification.scheduleCaptchaNeeded()
                }
            }
        }
    }

    private func cancelInFlightForRestart(error: Error) {
        refreshGeneration += 1
        inFlight?.cancel()
        inFlight = nil
        manualContinuation?.resume(throwing: error)
        manualContinuation = nil
        manualChallenge = nil
        CaptchaNotification.cancel()
        isRefreshing = false
        refreshStartedAt = nil
    }

    /// 3 in a row triggers the user-facing "капча требуется" local
    /// notification. We let the first couple slip silently because
    /// transient network blips are common and would otherwise spam
    /// the user every time they get on the bus.
    private static let failureNotificationThreshold = 3

    /// 5-minute foreground heartbeat cadence. Drives `refreshIfNeeded`,
    /// which itself is a no-op when session params are fresh.
    private static let heartbeatInterval: TimeInterval = 300

    /// Target spacing between BG refreshes — iOS treats this as a
    /// lower bound, not a contract. Real fire latency varies with
    /// device usage; the iOS scheduler aims to coalesce app refreshes
    /// roughly hourly, but on quiet devices we frequently see 45-60
    /// min cadences in practice.
    private static let backgroundRefreshTargetInterval: TimeInterval = 45 * 60

    /// Arm the 5-minute Timer. Idempotent — re-firing this swaps the
    /// timer cleanly rather than stacking multiple fires.
    private func startHeartbeat() {
        heartbeatTimer?.invalidate()
        let timer = Timer.scheduledTimer(
            withTimeInterval: Self.heartbeatInterval,
            repeats: true
        ) { [weak self] _ in
            guard let self else { return }
            Task { @MainActor in
                TURNLog.info("turncreds", "heartbeat tick → refreshIfNeeded(reason=heartbeat)")
                self.refreshIfNeeded(reason: "heartbeat")
            }
        }
        // Tolerance lets iOS coalesce the fire with other timers,
        // saving battery — a few seconds of skew on a 5-min beat is
        // fine.
        timer.tolerance = 30
        // Common run-loop mode so the timer keeps firing while we're
        // in a sheet / scrolling. Without this we miss ticks while
        // SwiftUI presents Settings.
        RunLoop.main.add(timer, forMode: .common)
        heartbeatTimer = timer
        TURNLog.info("turncreds", "heartbeat armed (\(Int(Self.heartbeatInterval))s interval)")
    }

    /// Schedule the next BG App Refresh request. Called after every
    /// successful refresh AND from App.swift on launch (so the very
    /// first request is on the books before any session params exist).
    /// Failure (no entitlement, simulator) is logged and swallowed —
    /// we never want to crash the launch path because of BG plumbing.
    ///
    /// `nonisolated` because callers include the BGTaskScheduler
    /// register-handler closure (unspecified queue) and the post-
    /// refresh path which is already on MainActor — we touch no
    /// instance state, just the `BGTaskScheduler` singleton.
    nonisolated static func scheduleBackgroundRefresh() {
        let req = BGAppRefreshTaskRequest(identifier: Self.backgroundTaskIdentifier)
        req.earliestBeginDate = Date(timeIntervalSinceNow: Self.backgroundRefreshTargetInterval)
        do {
            try BGTaskScheduler.shared.submit(req)
            TURNLog.info("turncreds",
                "BG refresh scheduled for ~\(Int(Self.backgroundRefreshTargetInterval / 60))min from now")
        } catch {
            TURNLog.warn("turncreds",
                "BG refresh schedule failed: \(error.localizedDescription) (simulator / missing entitlement / debugger attached are normal)")
        }
    }

    /// Drive a BG-task-bounded refresh. Called from App.swift's
    /// `BGTaskScheduler.register` handler. We give the work 25 s of
    /// wallclock — iOS budgets BG App Refresh at ~30 s, so 25 leaves
    /// room for the framework to wind us down cleanly via
    /// `setTaskCompleted(success:)`.
    ///
    /// The captured `BGTask` is held by the caller; we just kick the
    /// work and tell them when to finish. iOS may interrupt us
    /// earlier via `expirationHandler` — we honour the cancel by
    /// resolving the continuation.
    ///
    /// `nonisolated` because iOS calls register-handlers on an
    /// unspecified queue. All MainActor work happens inside the
    /// `Task { @MainActor in ... }` blocks below.
    nonisolated static func runBackgroundRefresh(task: BGAppRefreshTask) {
        TURNLog.info("turncreds", "BG refresh fired by iOS")
        // Always queue the next request — even on failure path. iOS
        // will not auto-renew; if we skip the resubmit, the app loses
        // its only autonomous refresh slot until next foreground.
        if shouldMaintainTurnCredentialsNow() {
            scheduleBackgroundRefresh()
        } else {
            TURNLog.info("turncreds", "BG refresh reschedule skipped — VK TURN not active/effective")
        }

        // 25-s budget watchdog. Fires the success/failure callback so
        // iOS marks us complete before it would have killed us.
        let budget: TimeInterval = 25
        let deadline = Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(budget * 1_000_000_000))
            TURNLog.warn("turncreds", "BG refresh budget exhausted (\(Int(budget))s) — marking complete")
            task.setTaskCompleted(success: false)
        }
        task.expirationHandler = {
            TURNLog.warn("turncreds", "BG refresh expired by iOS")
            deadline.cancel()
        }
        Task { @MainActor in
            TURNCredsRefresher.shared.refreshIfNeeded(reason: "background")
            // Give the in-flight Task time to finish before reporting
            // complete. Poll the isRefreshing flag with a 1-s interval
            // for up to 22 s (leaving 3 s slack against the 25 s
            // budget watchdog above).
            for _ in 0..<22 {
                if !TURNCredsRefresher.shared.isRefreshing { break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            deadline.cancel()
            let ok = (TURNCredsRefresher.shared.lastError == nil)
            TURNLog.info("turncreds", "BG refresh completing success=\(ok)")
            task.setTaskCompleted(success: ok)
        }
    }

    /// Emergency reset for the "stuck refresh" state. Cancels the
    /// in-flight Task (if any), drops the manual continuation, and
    /// flips `isRefreshing` back to false so a subsequent forceRefresh
    /// can start fresh. Exposed via Settings → VK TURN → Reset.
    func resetRefreshState() {
        TURNLog.warn("turncreds", "resetRefreshState called — cancelling in-flight task")
        cancelInFlightForRestart(error: CaptchaError.cancelled)
        lastError = "Сброшено вручную"
    }

    /// Spawn a manual challenge and suspend until the user resolves
    /// (or cancels). Called by `ChainedVerification challengeHandler` below when the
    /// auto handler bails with `.sliderRequired`.
    fileprivate func awaitManual(redirectURI: URL, sessionToken: String) async throws -> String {
        TURNLog.info("turncreds", "manual captcha requested (host=\(redirectURI.host ?? "<unknown>"))")
        // Fire the iOS notification so the user knows to open the app
        // even if it's in the background. Operator requirement: this
        // must be unconditional (alternate path NotificationPreferences.enabled)
        // because the VPN silently dies otherwise.
        CaptchaNotification.post()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            self.manualContinuation = cont
            self.manualChallenge = ManualChallenge(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        }
    }
}

/// Notification helper for the "auto-refresh ran out of options"
/// state: 3 consecutive failures (couldn't auto-solve, network timeout,
/// VK threw a slider) raise a local notification so the user opens
/// the app and resolves the manual verification sheet.
///
/// Separate from `Verification challengeNotification` (which fires for the
/// already-in-flight slider challenge) because we may want to coalesce
/// or differentiate the two later. Same App Group, same UN center,
/// different identifier.
enum CredsRefreshNotification {
    /// UN identifier. Kept stable so consecutive schedules collapse
    /// onto each other (iOS dedupes by identifier).
    static let identifier = "tamizdat.captcha-needed"
    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let pendingOpenKey = "tamizdat.captchaNeeded.pendingOpen"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroupID)
    }

    /// Body kept short so it fits the lockscreen / banner. Russian
    /// per project i18n convention.
    private static let title = "Tamizdat"
    private static let body = "Капча требуется — откройте приложение"

    /// Coalesce: cancel any pending instance before scheduling a
    /// fresh one. Without the cancel, iOS just keeps the existing
    /// pending request (identifier-deduped) but doesn't surface a new
    /// banner — the user sees the same stale alert.
    @MainActor
    static func scheduleCaptchaNeeded() {
        let center = UNUserNotificationCenter.current()
        defaults?.set(true, forKey: pendingOpenKey)
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized
                    || settings.authorizationStatus == .provisional
            else {
                TURNLog.warn("turncreds",
                    "captcha-needed notification not authorized — skip")
                return
            }
            center.removePendingNotificationRequests(withIdentifiers: [identifier])
            center.removeDeliveredNotifications(withIdentifiers: [identifier])
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.sound = .default
            let req = UNNotificationRequest(
                identifier: identifier,
                content: content,
                trigger: nil
            )
            center.add(req, withCompletionHandler: nil)
            TURNLog.warn("turncreds",
                "captcha-needed notification scheduled (auto-refresh failed 3+ times)")
        }
    }

    /// Consume the "user opened app because verification notification fired" flag.
    /// The notification itself cannot carry a live WKWebView challenge; opening
    /// the app must kick a fresh refresh attempt so `manualChallenge` can be
    /// published and SwiftUI can present the sheet.
    @MainActor
    static func consumePendingOpenRequest() -> Bool {
        let pending = defaults?.bool(forKey: pendingOpenKey) ?? false
        if pending {
            defaults?.removeObject(forKey: pendingOpenKey)
            let center = UNUserNotificationCenter.current()
            center.removePendingNotificationRequests(withIdentifiers: [identifier])
            center.removeDeliveredNotifications(withIdentifiers: [identifier])
        }
        return pending
    }

    /// Drop a pending / delivered verification-needed banner — called when
    /// a refresh finally succeeds so the user doesn't see a stale
    /// "verification challenge needed" notification after the app already healed.
    @MainActor
    static func cancel() {
        defaults?.removeObject(forKey: pendingOpenKey)
        let center = UNUserNotificationCenter.current()
        center.removePendingNotificationRequests(withIdentifiers: [identifier])
        center.removeDeliveredNotifications(withIdentifiers: [identifier])
    }
}

/// Pluggable handler that tries the hidden WKWebView first, then
/// escalates to a manual SwiftUI sheet (the manual verification sheet) on
/// `.sliderRequired`. The escalation is asynchronous — the refresh
/// task suspends until the user solves the slider or cancels.
///
/// `@unchecked Sendable` is safe here: the wrapped reference is only
/// touched on `@MainActor` (the protocol awaits on `awaitManual`,
/// which hops back to MainActor automatically).
private struct ChainedCaptchaSolver: VKCaptchaSolver, @unchecked Sendable {
    weak var refresher: TURNCredsRefresher?

    func solve(redirectURI: URL, sessionToken: String) async throws -> String {
        do {
            return try await CaptchaWebViewManager.shared.solveCaptcha(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        } catch CaptchaError.sliderRequired {
            guard let r = refresher else {
                throw CaptchaError.cancelled
            }
            // `awaitManual` is @MainActor-isolated; the await hops the
            // current task onto MainActor automatically.
            return try await r.awaitManual(
                redirectURI: redirectURI,
                sessionToken: sessionToken
            )
        }
    }
}
