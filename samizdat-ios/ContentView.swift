import Foundation
import SwiftUI

/// Home screen.
///
/// Top bar (SZ-mark + Tamizdat wordmark + Logs/Settings buttons),
/// large 220px ShieldMark hero, status label + mint Ping chip,
/// 3 stat tiles (Mode/Uptime/Data), big 60pt Connect/Disconnect
/// button, mono caption.
///
/// The endpoint mode picker (Авто / Обычный / Белые списки) lives in
/// Settings; the home screen shows the current mode as a status line
/// under the hero («Белые списки · Telemost» while the VKS carrier is up).
///
/// State machine: 6 states `off / connecting / connected /
/// reconnecting / failed / error`. Phase C iOS-notify observer
/// preserved from D20 — server alerts still render via `.alert(...)`.
struct ContentView: View {
    @Environment(\.themeTokens) private var theme

    @StateObject private var bridge = SamizdatBridge()
    @StateObject private var lampStore = TamizdatStatusStore()
    @StateObject private var serverNotif = ServerNotificationObserver()
    @StateObject private var exitIP = ExitIPStore()
    // Main-app WhitelistMonitor — runs while VPN is OFF + auto mode +
    // foreground, so WhitelistStatusStore.activeEndpoint is already
    // correct by the time the user taps Connect.
    @StateObject private var whitelistMonitor = WhitelistMonitor()

    @State private var showSettings = false
    @State private var showLogs = false
    @State private var hasConfig = ConfigStore.shared.load() != nil

    @State private var whitelistStatus: WhitelistStatus = .unknown
    @State private var whitelistActiveEndpoint: EndpointMode = .primary
    /// Зеркало EndpointModeStore для отрисовки: сам стор не наблюдаемый,
    /// поэтому без @State смена режима не перерисовывала экран.
    @State private var currentMode: EndpointMode = EndpointModeStore.current
    @State private var statusPollTimer: Timer?

    @State private var isPreparingVPN = false
    @State private var vpnProfileError: String?

    /// Optimistic "we just asked for a switch" flag. Set immediately
    /// when the user flips the mode in Settings, so the shield flips to
    /// amber "Reconnecting…" without waiting for the 500 ms status-poll
    /// cycle to pick up the extension's isRewiring flag. Auto-clears
    /// after 3 s (long enough for the real rewire to complete on most
    /// networks; the status poll then takes over).
    @State private var pendingSwitch: Bool = false
    @State private var pendingSwitchClearTask: Task<Void, Never>?

    private static func activeProfileBlob() -> String {
        ConfigStore.shared.load() ?? ""
    }

    // MARK: – Derived state

    /// 6-state derivation. Order of precedence:
    ///   1. `.error`         (bridge.state == .error)
    ///   2. `.reconnecting`  (lampStore.isReconnecting && was connected)
    ///   3. `.connecting`    (bridge.state == .connecting)
    ///   4. `.failed`        (connected but ping prober says failed)
    ///   5. `.connected`     (bridge.state == .connected)
    ///   6. `.off`           (otherwise)
    private enum HomeState {
        case off, connecting, connected, reconnecting, failed, error

        var statusLabel: String {
            switch self {
            case .off:          return "Выключен"
            case .connecting:   return "Подключение…"
            case .connected:    return "Подключено"
            case .reconnecting: return "Переподключение…"
            case .failed:       return "Нет связи"
            case .error:        return "Ошибка"
            }
        }

        func accent(theme: ThemeTokens) -> Color {
            switch self {
            case .off:          return theme.red
            case .connecting:   return theme.amber
            case .connected:    return theme.mint
            case .reconnecting: return theme.amber
            case .failed:       return theme.amber
            case .error:        return theme.red
            }
        }

        var connectButtonLabel: String {
            switch self {
            case .connected:    return "Отключить"
            case .reconnecting: return "Отключить"
            case .failed:       return "Отключить"
            case .connecting:   return "Подключение…"
            default:            return "Подключить"
            }
        }

        var isConnectButtonRed: Bool {
            switch self {
            case .connected, .reconnecting, .failed: return true
            default: return false
            }
        }

        var showsPingChip: Bool {
            self == .connected || self == .failed
        }
    }

    private var homeState: HomeState {
        switch bridge.state {
        case .error:
            return .error
        case .connecting:
            return .connecting
        case .connected:
            // Optimistic flip first — gives instant feedback on a tap
            // while the extension's rewire is still in-flight.
            if pendingSwitch { return .reconnecting }
            if lampStore.isReconnecting { return .reconnecting }
            if lampStore.snapshot.pingFailed { return .failed }
            if lampStore.snapshot.pingMs < 0 {
                // Green "Подключено" waits for a successful real-internet
                // ping — except under the VKS carrier, where the room
                // transport may legitimately take longer to warm up than
                // the first probe. Once the native VKS client owns the
                // upstream, user traffic can already flow.
                if lampStore.snapshot.vksRunning != 0 {
                    return .connected
                }
                return .connecting
            }
            return .connected
        case .disconnected:
            return .off
        }
    }

    // MARK: – Body

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                topBar
                    .padding(.horizontal, 20)
                    .padding(.top, 8)
                    .padding(.bottom, 6)

                hero
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                statTiles
                    .padding(.horizontal, 16)
                    .padding(.top, 4)

                modeStatusRow
                    .padding(.horizontal, 16)
                    .padding(.top, 12)

                connectButton
                    .padding(.horizontal, 16)
                    .padding(.top, 14)

                buildCaption
                    .padding(.top, 10)
                    .padding(.bottom, 18)
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .sheet(isPresented: $showSettings, onDismiss: refreshConfigDerivedState) {
            SettingsView(onConfigChanged: { _ in
                refreshConfigDerivedState()
                // A mode change in Settings rewires the live tunnel;
            // mirror the optimistic pendingSwitch flip here.
            noteSwitchPendingIfConnected()
            })
            .environment(\.themeTokens, theme)
        }
        .sheet(isPresented: $showLogs) {
            LogView(injectedBridge: bridge)
                .environment(\.themeTokens, theme)
        }
        .onAppear {
            startStatusPolling()
            lampStore.start()
            exitIP.start(isConnected: bridge.state == .connected)
            // Only run the main-app monitor while VPN is off
            // and auto-mode is selected. Once the extension is up,
            // its own WhitelistDetector takes over (it has actual
            // physical-iface binding + ICMP probes; we'd just be
            // writing conflicting values).
            updateWhitelistMonitorState()
        }
        .onDisappear {
            stopStatusPolling()
            lampStore.stop()
            exitIP.stop()
            whitelistMonitor.stop()
        }
        .onChange(of: bridge.state) { _, newState in
            // Refetch exit IP immediately on connect/disconnect so the
            // surface flips without waiting up to 60s for the next tick.
            let isUp = (newState == .connected)
            exitIP.refreshSoon(isConnected: isUp)
            // Stop monitor when extension takes over; resume when
            // tunnel drops back to disconnected.
            updateWhitelistMonitorState()
        }
        .onChange(of: currentMode) { _, _ in
            // The mode picker lives in Settings, so this view never sees
            // the tap directly. Without this, switching to Auto left the
            // status line on «Мониторинг…» until the next VPN state flip.
            updateWhitelistMonitorState()
        }
        // Phase C iOS-notify (preserved from D20): server-pushed alert.
        .alert(
            serverNotif.latest?.title.isEmpty == false
                ? (serverNotif.latest?.title ?? "Сообщение")
                : "Сообщение",
            isPresented: Binding(
                get: { serverNotif.latest != nil },
                set: { if !$0 { serverNotif.dismiss() } }
            ),
            presenting: serverNotif.latest
        ) { _ in
            Button("OK", role: .cancel) { serverNotif.dismiss() }
        } message: { payload in
            Text(payload.body)
        }
    }

    // MARK: – Top bar

    private var topBar: some View {
        HStack {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 7)
                        .fill(theme.mintDim)
                        .frame(width: 28, height: 28)
                    Text("SZ")
                        .font(.geist(.bold, size: 13))
                        .tracking(-0.52)
                        .foregroundStyle(theme.mint)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text("Tamizdat")
                        .font(.geist(.semibold, size: 15))
                        .tracking(-0.15)
                        .foregroundStyle(theme.text)
                    // Bundle version + build is baked by the CI Archive step
                    // (MARKETING_VERSION=0.3.<run>-<sha>, CURRENT_PROJECT_VERSION=<run>).
                    // Showing it right under the logo lets us answer "what's
                    // installed?" at a glance without diving into Settings →
                    // О приложении.
                    Text(Self.shortVersionLabel)
                        .font(.geistMono(.regular, size: 10))
                        .foregroundStyle(theme.textDim)
                }
            }
            Spacer()
            HStack(spacing: 8) {
                circleIconButton(systemName: "doc.text") { showLogs = true }
                circleIconButton(systemName: "gearshape") { showSettings = true }
            }
        }
    }

    /// Read CFBundleShortVersionString lazily once and cache; we only
    /// want to format this string, never to recompute on every redraw.
    private static let shortVersionLabel: String = {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "v\(marketing) (\(build))"
    }()

    private func circleIconButton(systemName: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            ZStack {
                Circle().fill(theme.chip).frame(width: 34, height: 34)
                Image(systemName: systemName)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(theme.textDim)
            }
        }
        .buttonStyle(.plain)
    }

    // MARK: – Hero

    private var hero: some View {
        VStack(spacing: 18) {
            ShieldMark(
                size: 220,
                color: homeState.accent(theme: theme),
                dim: theme.isDark ? theme.mintInk : Color.black.opacity(0.18)
            )

            VStack(spacing: 12) {
                Text(homeState.statusLabel)
                    .font(.geist(.bold, size: 38))
                    .tracking(-1.14)
                    .foregroundStyle(theme.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)

                if homeState.showsPingChip {
                    PingChip(
                        pingMs: lampStore.snapshot.pingMs >= 0 ? lampStore.snapshot.pingMs : nil
                    )
                }

                // Exit IP under the Ping chip. URLSession.shared
                // follows the system default route — through the tunnel
                // when on, real ISP when off. Quiet failure: line hides.
                if let ip = exitIP.ip {
                    HStack(spacing: 4) {
                        Text(exitIP.isFromTunnel ? "Выход" : "Сеть")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textMuted)
                        Text("·")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textMuted)
                        Text(ip)
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    .padding(.top, 2)
                }

                if !bridge.lastError.isEmpty && bridge.state == .error {
                    Text(bridge.lastError)
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.textDim)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                if let vpnProfileError {
                    Text(vpnProfileError)
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                if !hasConfig {
                    Text("Добавьте ссылку tamizdat:// в «Профиле».")
                        .font(.geist(.regular, size: 13))
                        .foregroundStyle(theme.textDim)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
            }
        }
    }

    // MARK: – Stat tiles

    private var statTiles: some View {
        HStack(spacing: 8) {
            StatTile(label: "Режим",
                     value: modeTileValue,
                     unit: nil)
            StatTile(label: "Аптайм",
                     value: lampStore.uptimeText,
                     unit: lampStore.uptimeUnit.isEmpty ? nil : lampStore.uptimeUnit)
            StatTile(label: "Трафик",
                     value: lampStore.dataText.value,
                     unit: lampStore.dataText.unit)
        }
    }

    /// Mode tile uses extension status ground truth while the tunnel is
    /// online. Local EndpointMode/UserDefaults are only a fallback before
    /// the Network Extension has replied.
    private var modeTileValue: String {
        let snap = lampStore.snapshot
        if !snap.realShape.isEmpty {
            let active: EndpointMode = snap.effectiveEndpoint == EndpointMode.backup.rawValue
                ? .backup
                : .primary
            return TamizdatStatusStore.modeLabel(active: active)
        }
        return TamizdatStatusStore.modeLabel(active: effectiveEndpoint)
    }

    /// "Effective" endpoint for label purposes:
    ///   - manual primary/backup → the picked one
    ///   - auto                 → WhitelistStatusStore.activeEndpoint
    private var effectiveEndpoint: EndpointMode {
        if currentMode == .auto {
            return WhitelistStatusStore.trustedAutoEndpoint
        }
        return currentMode
    }

    // MARK: – Mode status row (home keeps only the status line)

    private var modeStatusRow: some View {
        CardContainer(padding: 0) {
            HStack(spacing: 14) {
                IconCard(systemName: "dot.radiowaves.up.forward",
                         bg: theme.blueDim,
                         fg: theme.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text(modeLineTitle)
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Text(whitelistSub)
                        .font(.geist(.regular, size: 12.5))
                        .foregroundStyle(theme.textDim)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(theme.textMuted)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
        }
        .contentShape(Rectangle())
        .onTapGesture { showSettings = true }
    }

    /// «Авто» / «Обычный» / «Белые списки» — текущий режим.
    private var modeLineTitle: String {
        switch currentMode {
        case .auto:    return "Авто"
        case .primary: return "Обычный"
        case .backup:  return "Белые списки"
        }
    }

    private var whitelistSub: String {
        // Под именем «Белые списки» показываем канал: первый включённый
        // провайдер в порядке списка. Если ключа VKS нет — прямо говорим
        // об этом, а не притворяемся, что режим переключился.
        let blob = Self.activeProfileBlob()
        let configured = VKSPreferences.isConfigured(profileBlob: blob)
        let carrier: String? = {
            guard configured,
                  let first = VKSPreferences.providerOrder
                    .first(where: { VKSPreferences.providerEnabled($0) })
            else { return nil }
            return VKSPreferences.providerDisplayName(first)
        }()
        let whitelistLine = carrier.map { "Белые списки · \($0)" } ?? "Белые списки"

        switch currentMode {
        case .primary:
            return "Выбрано вручную"
        case .backup:
            guard configured else {
                return "Белые списки · не настроены (нет ключа VKS)"
            }
            switch whitelistStatus {
            case .error, .noNetwork, .frozen:
                return "Ошибка определения"
            default:
                return whitelistLine
            }
        case .auto:
            switch whitelistStatus {
            case .error, .noNetwork, .frozen:
                return "Ошибка определения"
            case .detected:
                return whitelistLine
            case .off:
                return "Свободный интернет"
            case .unknown:
                return "Мониторинг…"
            }
        }
    }

    /// Start/stop the main-app WhitelistMonitor based on the current VPN
    /// state + auto-mode. Runs ONLY when
    ///   - bridge.state == .disconnected (extension's own detector
    ///     would conflict otherwise)
    ///   - currentMode == .auto (no point monitoring if
    ///     the user picked a manual endpoint)
    private func updateWhitelistMonitorState() {
        let shouldRun = bridge.state == .disconnected
            && currentMode == .auto
        if shouldRun {
            whitelistMonitor.start()
        } else {
            whitelistMonitor.stop()
        }
    }

    /// Re-derives config-dependent state (hasConfig + the mode mirror).
    /// Called from the settings sheet's callbacks AND its onDismiss.
    /// Never touches the user's mode: a missing VKS key is a state the
    /// status line reports, not a reason to silently pick another mode.
    private func refreshConfigDerivedState() {
        hasConfig = ConfigStore.shared.load() != nil
        currentMode = EndpointModeStore.current
    }

    /// Flip the optimistic "reconnecting" flag instantly when Settings
    /// changed the mode while connected, so the shield turns amber the
    /// moment the sheet's change lands. The flag auto-clears after 3 s —
    /// by then the extension's isRewiring has propagated via the 500 ms
    /// status poll.
    private func noteSwitchPendingIfConnected() {
        guard bridge.state == .connected else { return }
        noteSwitchPending()
    }

    /// Optimistic "we just asked for a switch" flip: the shield turns
    /// amber immediately; the 500 ms status poll takes over once the
    /// extension's isRewiring propagates. Also kick the ExitIP store to
    /// refetch soon after the rewire completes.
    private func noteSwitchPending() {
        pendingSwitchClearTask?.cancel()
        pendingSwitch = true
        exitIP.refreshSoon(isConnected: bridge.state == .connected)
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            exitIP.refreshSoon(isConnected: bridge.state == .connected)
        }
        pendingSwitchClearTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(3))
            if !Task.isCancelled {
                pendingSwitch = false
            }
        }
    }

    // MARK: – Connect button

    private var connectButton: some View {
        Button(action: toggleConnection) {
            HStack(spacing: 10) {
                Circle()
                    .fill(homeState.isConnectButtonRed ? Color.white : theme.mintInk)
                    .frame(width: 8, height: 8)
                Text(homeState.connectButtonLabel)
                    .font(.geist(.bold, size: 18))
                    .tracking(-0.18)
            }
            .frame(maxWidth: .infinity)
            .frame(minHeight: 60)
            .background(homeState.isConnectButtonRed ? theme.red : theme.mint)
            .foregroundStyle(homeState.isConnectButtonRed ? Color.white : theme.mintInk)
            .clipShape(RoundedRectangle(cornerRadius: 20))
            .shadow(
                color: homeState.isConnectButtonRed
                    ? Color.red.opacity(0.32)
                    : theme.mint.opacity(0.28),
                radius: 12, x: 0, y: 6
            )
        }
        .buttonStyle(.plain)
        .disabled(bridge.state == .connecting || isPreparingVPN || !hasConfig)
        .opacity((bridge.state == .connecting || isPreparingVPN || !hasConfig) ? 0.6 : 1.0)
    }

    // MARK: – Build caption

    private var buildCaption: some View {
        Text(buildLabel)
            .font(.geistMono(.semibold, size: 10.5))
            .tracking(0.42)
            .foregroundStyle(theme.textMuted)
    }

    private var buildLabel: String {
        let info = Bundle.main.infoDictionary
        if let ipaName = info?["IPAArtifactName"] as? String,
           !ipaName.isEmpty,
           !ipaName.contains("$(") {
            return ipaName
        }
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "Tamizdat-\(marketing)-build-\(build).ipa"
    }

    // MARK: – Actions

    private func toggleConnection() {
        if bridge.state == .connected {
            bridge.disconnect()
            return
        }
        guard let blob = ConfigStore.shared.load() else { return }
        isPreparingVPN = true
        vpnProfileError = nil
        Task { @MainActor in
            defer { isPreparingVPN = false }
            do {
                try await bridge.connect(blob)
            } catch {
                vpnProfileError = error.localizedDescription
            }
        }
    }

    // MARK: – Status polling

    private func refreshWhitelistStatus() {
        currentMode = EndpointModeStore.current
        whitelistStatus = WhitelistStatusStore.current
        whitelistActiveEndpoint = WhitelistStatusStore.activeEndpoint
        // Mirror WhitelistStatusStore.autoDecisionMaxAge (≥200 s, widened
        // by probeInterval×7 at long intervals) instead of a fixed window —
        // with a 120 s probe interval the detector legitimately goes
        // silent for >200 s while still healthy, and this poll then
        // mis-rendered "Error detecting" over a live verdict.
        if currentMode == .auto && bridge.state == .connected
            && WhitelistStatusStore.ageSeconds > max(200, TimeInterval(WhitelistProbePreferences.probeInterval * 7)) {
            whitelistStatus = .error
        }
    }

    private func startStatusPolling() {
        statusPollTimer?.invalidate()
        let timer = Timer(timeInterval: 2.0, repeats: true) { _ in
            refreshWhitelistStatus()
        }
        RunLoop.main.add(timer, forMode: .common)
        statusPollTimer = timer
        refreshWhitelistStatus()
    }

    private func stopStatusPolling() {
        statusPollTimer?.invalidate()
        statusPollTimer = nil
    }
}

// MARK: – Phase C iOS-notify server-message observer (preserved verbatim from D20)
//
// Sits on the app side; listens for a Darwin notification posted by the
// NE-side `NotificationBridge` whenever a server-pushed
// `CoverConfigBundle.Notification` has been persisted into App Group
// UserDefaults.
final class ServerNotificationObserver: ObservableObject {
    @Published var latest: NotificationPayload?

    init() {
        readFromGroup()
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterAddObserver(
            center, observer,
            { _, observerPtr, _, _, _ in
                guard let observerPtr = observerPtr else { return }
                let me = Unmanaged<ServerNotificationObserver>
                    .fromOpaque(observerPtr).takeUnretainedValue()
                DispatchQueue.main.async { me.readFromGroup() }
            },
            ServerNotificationConstants.darwinNotificationName,
            nil, .deliverImmediately
        )
    }

    deinit {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = UnsafeRawPointer(Unmanaged.passUnretained(self).toOpaque())
        CFNotificationCenterRemoveEveryObserver(center, observer)
    }

    private func readFromGroup() {
        guard
            let defaults = UserDefaults(suiteName: ServerNotificationConstants.appGroupID),
            let data = defaults.data(forKey: ServerNotificationConstants.userDefaultsKey),
            let payload = try? JSONDecoder().decode(NotificationPayload.self, from: data)
        else { return }
        if payload != latest {
            latest = payload
        }
    }

    func dismiss() {
        UserDefaults(suiteName: ServerNotificationConstants.appGroupID)?
            .removeObject(forKey: ServerNotificationConstants.userDefaultsKey)
        latest = nil
    }
}

#Preview {
    ContentView()
        .environment(\.themeTokens, ThemeTokens.cream)
}
