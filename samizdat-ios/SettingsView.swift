import SwiftUI
import Foundation
import SamizdatClient
import UserNotifications

/// Настройки — единый минимальный экран. Все пользовательские строки —
/// русские; оформление — дизайн-токены (Geist, ThemeTokens, mint).
///
/// Структура:
///   Подключение      → Профиль (список профилей), Режим (Авто/Обычный/Белые списки)
///   Каналы VKS       → порядок провайдеров (drag) + тумблер на строку
///   Уведомления      → «Переключение режима» + строка про заблокированные
///   Оформление       → Системная / Светлая / Тёмная
///   Дополнительно ›  → push-экран: Параметры VKS, Детектор белых списков,
///                      Проверка связи, Логи ›, Telegram для логов ›
///   О приложении     → версия, GitHub
///
/// Навигация внутри шита — NavigationStack (push, не sheets).
/// Сохранение кнопкой — только там, где значение нужно провалидировать
/// (профиль, параметры VKS); остальное применяется сразу при изменении.
struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Called whenever the user changes endpoints. The parent uses this
    /// to refresh `hasConfig` and re-derive whitelist state.
    var onConfigChanged: (Bool) -> Void = { _ in }

    /// Theme picker is rendered here but the *root* view (App.swift /
    /// ContentView) reads `ThemePreferences.current` to compute the
    /// environment value. To make the picker change propagate live, we
    /// post a Notification on change; the root listens and re-renders.
    @State private var selectedTheme: SettingsThemeOption = SettingsThemeOption.current

    @State private var notificationsEnabled: Bool = NotificationPreferences.enabled
    @State private var permissionStatus: UNAuthorizationStatus = .notDetermined
    @State private var permissionDeniedAlert: Bool = false

    /// VKS channel list: local mirror of VKSPreferences.providerOrder
    /// + per-provider enabled flags. Edits (drag/toggle) persist
    /// immediately and apply on the next connect (or live via the
    /// refreshVKSLadder provider message while connected).
    @State private var providerOrder: [String] = VKSPreferences.providerOrder

    /// Зеркала сторов. EndpointModeStore и VKSPreferences — обычные
    /// UserDefaults-обёртки без наблюдения: читать их прямо в Binding
    /// getter'ах нельзя, иначе после тапа ничего не перерисовывается и
    /// подсветка «отстаёт».
    @State private var mode: EndpointMode = EndpointModeStore.current
    /// Provider row currently highlighted as a drop target during a
    /// drag-reorder of the VKS ladder.
    @State private var targetProvider: String?
    @State private var providerEnabled: [String: Bool] = Dictionary(
        uniqueKeysWithValues: VKSPreferences.allProviders.map {
            ($0, VKSPreferences.providerEnabled($0))
        }
    )

    /// Providers the server reported as needing a fresh login (from the
    /// extension status). Empty while disconnected.
    @State private var loginRequired: Set<String> = []
    @State private var loginTarget: LoginTarget?

    private struct LoginTarget: Identifiable {
        let provider: String
        var id: String { provider }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                ThemeBackground(theme: theme)

                ScrollView {
                    VStack(spacing: 0) {
                        // ── Подключение ──────────────────────────
                        SectionLabel(text: "Подключение")
                        connectionCard
                            .padding(.horizontal, 16)

                        // ── Каналы VKS ────────────────────────────
                        SectionLabel(text: "Каналы VKS")
                            .padding(.top, 22)
                        channelsCard
                            .padding(.horizontal, 16)

                        // ── Уведомления ───────────────────────────
                        SectionLabel(text: "Уведомления")
                            .padding(.top, 22)
                        notificationsCard
                            .padding(.horizontal, 16)

                        // ── Оформление ────────────────────────────
                        SectionLabel(text: "Оформление")
                            .padding(.top, 22)
                        appearanceCard
                            .padding(.horizontal, 16)

                        // ── Дополнительно ─────────────────────────
                        SectionLabel(text: "Дополнительно")
                            .padding(.top, 22)
                        advancedCard
                            .padding(.horizontal, 16)

                        // ── О приложении ──────────────────────────
                        SectionLabel(text: "О приложении")
                            .padding(.top, 22)
                        aboutCard
                            .padding(.horizontal, 16)

                        Color.clear.frame(height: 28)
                    }
                }
            }
            .preferredColorScheme(theme.isDark ? .dark : .light)
            .navigationTitle("Настройки")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Chip(label: "Готово") { dismiss() }
                }
            }
            .task {
                permissionStatus = await NotificationPreferences.currentSystemAuthorization()
            }
            .task {
                while !Task.isCancelled {
                    let snap = await VPNProfileStore.shared.fetchTamizdatStatus()
                    let set = Set(snap.loginRequired.split(separator: ",").map {
                        $0.trimmingCharacters(in: .whitespaces)
                    }.filter { !$0.isEmpty })
                    if set != loginRequired { loginRequired = set }
                    try? await Task.sleep(for: .seconds(3))
                }
            }
            .sheet(item: $loginTarget) { target in
                ProviderLoginSheet(provider: target.provider) {
                    loginRequired.remove(target.provider)
                    pushLadderUpdate()
                }
                .environment(\.themeTokens, theme)
            }
            .alert("Уведомления не выданы", isPresented: $permissionDeniedAlert) {
                Button("Открыть настройки") { openSystemSettings() }
                Button("Отмена", role: .cancel) { }
            } message: {
                Text("Включите уведомления для Tamizdat в настройках iOS.")
            }
        }
    }

    // MARK: – Подключение

    private var connectionCard: some View {
        CardContainer(padding: 0) {
            NavigationLink {
                EndpointsView { saved in
                    onConfigChanged(saved)
                }
                .environment(\.themeTokens, theme)
            } label: {
                DesignRow(
                    icon: IconCard(systemName: "key.fill", bg: theme.mintDim, fg: theme.mint),
                    title: "Профиль",
                    sub: profileSubtitle,
                    isLast: false
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
            }
            .buttonStyle(.plain)

            modeRow
        }
    }

    private var profileSubtitle: String {
        let blob = ConfigStore.shared.load() ?? ""
        guard !blob.isEmpty else { return "Не настроен" }
        let primary = SamizdatURLCodec.split(blob).primary
        if let host = Self.endpointHost(primary) { return host }
        return "tamizdat://"
    }

    /// Режим: [ Авто | Обычный | Белые списки ]. Смена применяется сразу —
    /// запись EndpointModeStore (единственный writer) + живой rewire
    /// через switchEndpoint.
    private var modeRow: some View {
        VStack(spacing: 10) {
            HStack(spacing: 14) {
                IconCard(systemName: "arrow.triangle.branch",
                         bg: theme.blueDim, fg: theme.blue)
                Text("Режим")
                    .font(.geist(.medium, size: 16))
                    .tracking(-0.16)
                    .foregroundStyle(theme.text)
                Spacer(minLength: 8)
            }
            segmentedControl(
                options: EndpointMode.allCases,
                selection: Binding(
                    get: { mode },
                    set: { newValue in
                        guard newValue != mode else { return }
                        mode = newValue
                        EndpointModeStore.current = newValue
                        // Report immediately so the parent re-derives
                        // `currentMode` and starts/stops WhitelistMonitor
                        // without waiting for the 2 s status poll.
                        onConfigChanged(ConfigStore.shared.load() != nil)
                        Task {
                            _ = await VPNProfileStore.shared.switchEndpoint(to: newValue)
                        }
                    }
                ),
                label: { $0.modeSegmentLabel }
            )
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
    }

    // MARK: – Каналы VKS

    /// Переупорядочиваемый список провайдеров VKS: тумблер справа, порядок
    /// меняется долгим нажатием + перетаскиванием. Первая включённая
    /// строка — основной канал, остальные — failover. Изменения
    /// применяются при следующем подключении (или живьём, если туннель
    /// поднят).
    private var channelsCard: some View {
        CardContainer(padding: 0) {
            VStack(spacing: 0) {
                ForEach(providerOrder, id: \.self) { provider in
                    channelProviderRow(provider)
                }
            }
        }
    }

    /// Строка одного провайдера: имя + тумблер.
    ///
    /// Порядок меняется системным drag & drop: вся строка — источник
    /// перетаскивания (`.draggable` стартует по долгому нажатию, поэтому
    /// обычный скролл и тап по тумблеру не ломаются), `.dropDestination`
    /// на строке-цели переносит провайдера на её позицию (remove + insert,
    /// не swap).
    private func channelProviderRow(_ provider: String) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(VKSPreferences.providerDisplayName(provider))
                    .font(.geist(.medium, size: 15))
                    .tracking(-0.16)
                    .foregroundStyle(theme.text)
                if loginRequired.contains(provider) {
                    Text("Нужен вход")
                        .font(.geist(.regular, size: 12.5))
                        .foregroundStyle(theme.red)
                }
            }
            Spacer(minLength: 8)
            if loginRequired.contains(provider) {
                Chip(label: "Войти", isActive: true) {
                    loginTarget = LoginTarget(provider: provider)
                }
            }
            Toggle("", isOn: Binding(
                get: { providerEnabled[provider] ?? true },
                set: { newValue in
                    providerEnabled[provider] = newValue
                    VKSPreferences.setProviderEnabled(provider, newValue)
                    pushLadderUpdate()
                }
            ))
            .labelsHidden()
            .tint(theme.mint)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(providerRowBackground(provider: provider))
        .overlay(alignment: .top) {
            if targetProvider == provider {
                Rectangle()
                    .fill(theme.mint)
                    .frame(height: 2)
            }
        }
        .contentShape(Rectangle())
        .draggable(provider) {
            Text(VKSPreferences.providerDisplayName(provider))
                .font(.geist(.semibold, size: 13))
                .foregroundStyle(theme.text)
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(Capsule().fill(theme.chip))
        }
        .dropDestination(for: String.self) { items, _ in
            guard let dragged = items.first else { return false }
            let moved = moveProvider(dragged, before: provider)
            targetProvider = nil
            return moved
        } isTargeted: { targeted in
            if targeted {
                targetProvider = provider
            } else if targetProvider == provider {
                targetProvider = nil
            }
        }
    }

    /// Переносит `dragged` на позицию `destination` (remove + insert).
    /// Возвращает false, если строка не найдена или порядок не изменился.
    private func moveProvider(_ dragged: String, before destination: String) -> Bool {
        guard dragged != destination,
              let from = providerOrder.firstIndex(of: dragged),
              let to = providerOrder.firstIndex(of: destination) else { return false }
        var updated = providerOrder
        updated.remove(at: from)
        let insertAt = min(to, updated.count)
        updated.insert(dragged, at: insertAt)
        guard updated != providerOrder else { return false }
        withAnimation(.easeInOut(duration: 0.18)) {
            providerOrder = updated
        }
        VKSPreferences.providerOrder = updated
        pushLadderUpdate()
        return true
    }

    @ViewBuilder
    private func providerRowBackground(provider: String) -> some View {
        // Отключённый провайдер визуально гаснет.
        let on = providerEnabled[provider] ?? true
        Rectangle()
            .fill(on ? Color.clear : theme.chip)
            .opacity(on ? 0 : 0.5)
    }

    /// Живое применение лестницы в работающий туннель (no-op при
    /// отключённом VPN — следующий connect читает те же ключи).
    private func pushLadderUpdate() {
        Task { await VPNProfileStore.shared.refreshVKSLadder() }
    }

    // MARK: – Уведомления

    private var notificationsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "bell.badge", bg: theme.blueDim, fg: theme.blue),
                title: "Переключение режима",
                isLast: permissionStatus != .denied || !notificationsEnabled
            ) {
                Toggle("", isOn: $notificationsEnabled)
                    .labelsHidden()
                    .tint(theme.mint)
                    .onChange(of: notificationsEnabled) { _, newValue in
                        if newValue {
                            // onChange's action closure is nonisolated, so a
                            // bare Task{} runs handleEnableNotifications on the
                            // global executor — mutating @State permissionStatus /
                            // notificationsEnabled / permissionDeniedAlert off main.
                            Task { @MainActor in
                                await handleEnableNotifications()
                            }
                        } else {
                            NotificationPreferences.enabled = false
                        }
                    }
            }
            if permissionStatus == .denied && notificationsEnabled {
                DesignRow(
                    icon: IconCard(systemName: "exclamationmark.triangle.fill",
                                   bg: theme.amberDim, fg: theme.amber),
                    title: "Уведомления заблокированы",
                    isLast: true
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
                .contentShape(Rectangle())
                .onTapGesture { openSystemSettings() }
            }
        }
    }

    // MARK: – Оформление

    /// [ Системная | Светлая | Тёмная ]. Светлая = cream-токены, Тёмная =
    /// dark-токены, Системная следует за iOS.
    private var appearanceCard: some View {
        CardContainer(padding: 0) {
            VStack(spacing: 10) {
                HStack(spacing: 14) {
                    IconCard(systemName: "paintpalette.fill",
                             bg: theme.chip, fg: theme.text)
                    Text("Тема")
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Spacer(minLength: 8)
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)

                segmentedControl(
                    options: SettingsThemeOption.allCases,
                    selection: Binding(
                        get: { selectedTheme },
                        set: { newValue in
                            selectedTheme = newValue
                            SettingsThemeOption.current = newValue
                            // Propagate to root immediately
                            NotificationCenter.default.post(name: .tamizdatThemeChanged, object: nil)
                        }
                    ),
                    label: { $0.label }
                )
                .padding(.horizontal, 16)
                .padding(.bottom, 14)
            }
        }
    }

    // MARK: – Дополнительно

    private var advancedCard: some View {
        CardContainer(padding: 0) {
            NavigationLink {
                AdvancedView()
                    .environment(\.themeTokens, theme)
            } label: {
                DesignRow(
                    icon: IconCard(systemName: "slider.horizontal.3",
                                   bg: theme.chip, fg: theme.textDim),
                    title: "Дополнительно",
                    isLast: true
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
            }
            .buttonStyle(.plain)
        }
    }

    // MARK: – О приложении

    private var aboutCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "info.circle",
                               bg: theme.chip, fg: theme.textDim),
                title: "Версия",
                sub: versionLabel,
                isLast: false
            ) {
                EmptyView()
            }
            DesignRow(
                icon: IconCard(systemName: "arrow.up.right.square",
                               bg: theme.chip, fg: theme.textDim),
                title: "Проект на GitHub",
                sub: "github.com/funnybones69/tamizdat",
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                if let url = URL(string: "https://github.com/funnybones69/tamizdat") {
                    UIApplication.shared.open(url)
                }
            }
        }
    }

    // MARK: – Единый сегмент-контрол

    /// Один и тот же стиль сегментов для Режима и Темы: чип-фон, активная
    /// плашка chipActive, текст semibold 13.
    private func segmentedControl<Option: Identifiable & Equatable>(
        options: [Option],
        selection: Binding<Option>,
        label: @escaping (Option) -> String
    ) -> some View {
        HStack(spacing: 2) {
            ForEach(options) { option in
                let active = selection.wrappedValue == option
                Button {
                    selection.wrappedValue = option
                } label: {
                    Text(label(option))
                        .font(.geist(.semibold, size: 13))
                        .tracking(-0.13)
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                        .padding(.horizontal, 4)
                        .background(active ? theme.chipActive : Color.clear)
                        .foregroundStyle(active ? theme.chipActiveText : theme.text)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(theme.chip)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }

    // MARK: – Helpers

    private var versionLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(marketing) (\(build))"
    }

    private func openSystemSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }

    private func handleEnableNotifications() async {
        let granted = await NotificationPreferences.requestPermission()
        permissionStatus = await NotificationPreferences.currentSystemAuthorization()
        if granted {
            NotificationPreferences.enabled = true
        } else {
            NotificationPreferences.enabled = false
            notificationsEnabled = false
            permissionDeniedAlert = true
        }
    }

    /// Best-effort host:port parse for a tamizdat:// URL (row subtitle).
    static func endpointHost(_ s: String) -> String? {
        guard !s.isEmpty else { return nil }
        let probe = s
            .replacingOccurrences(of: "tamizdat://", with: "https://")
            .replacingOccurrences(of: "samizdat://", with: "https://")
        guard let u = URL(string: probe), let host = u.host else { return nil }
        if let port = u.port { return "\(host):\(port)" }
        return host
    }
}

// MARK: – Тема: Системная / Светлая / Тёмная

/// Расширенная опция темы: «Системная» следует за iOS, «Светлая» = cream,
/// «Тёмная» = dark. Хранится в UserDefaults.standard под тем же ключом,
/// что и раньше (`tamizdat.theme`); значение "system" — новое, резолвится
/// через `ThemePreferences.current`.
enum SettingsThemeOption: String, CaseIterable, Identifiable {
    case system
    case cream
    case dark

    var id: String { rawValue }

    var label: String {
        switch self {
        case .system: return "Системная"
        case .cream:  return "Светлая"
        case .dark:   return "Тёмная"
        }
    }

    static var current: SettingsThemeOption {
        get {
            let raw = UserDefaults.standard.string(forKey: "tamizdat.theme")
                ?? AppTheme.cream.rawValue
            return SettingsThemeOption(rawValue: raw) ?? .cream
        }
        set {
            UserDefaults.standard.set(newValue.rawValue, forKey: "tamizdat.theme")
        }
    }
}

// MARK: – EndpointMode: подписи сегментов

extension EndpointMode {
    /// Подпись в сегмент-контроле «Режим».
    var modeSegmentLabel: String {
        switch self {
        case .primary: return "Обычный"
        case .backup:  return "Белые списки"
        case .auto:    return "Авто"
        }
    }
}

// MARK: – Дополнительно (push-экран)

/// Дополнительно: параметры VKS (override'ы с плейсхолдерами из ссылки),
/// детектор белых списков, проверка связи, логи, Telegram для логов.
private struct AdvancedView: View {
    @Environment(\.themeTokens) private var theme

    // Параметры VKS — черновики; применяются кнопкой «Сохранить»
    // (shortid нужно валидировать).
    @State private var vksShortIDDraft: String = ""
    @State private var vksWakeDNSDraft: String = ""
    @State private var vksWakeZoneDraft: String = ""
    @State private var vksFeedback: String = ""

    // Детектор белых списков.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost
    @State private var wlIntervalDraft: Int = WhitelistProbePreferences.probeInterval

    // Проверка связи.
    @State private var pingURLDraft: String = PingURLPreferences.url

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            ScrollView {
                VStack(spacing: 0) {
                    SectionLabel(text: "Параметры VKS")
                    vksParamsCard
                        .padding(.horizontal, 16)

                    SectionLabel(text: "Детектор белых списков")
                        .padding(.top, 22)
                    detectorCard
                        .padding(.horizontal, 16)

                    SectionLabel(text: "Проверка связи")
                        .padding(.top, 22)
                    probeURLCard
                        .padding(.horizontal, 16)

                    SectionLabel(text: "Диагностика")
                        .padding(.top, 22)
                    diagnosticsCard
                        .padding(.horizontal, 16)

                    Color.clear.frame(height: 28)
                }
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .navigationTitle("Дополнительно")
        .navigationBarTitleDisplayMode(.inline)
    }

    // MARK: Параметры VKS

    private var activeProfileBlob: String {
        ConfigStore.shared.load() ?? ""
    }

    /// Что придёт из ссылки, если поле оставить пустым.
    private var linkParams: SamizdatURLCodec.VKSParams? {
        let blob = activeProfileBlob
        return blob.isEmpty ? nil : SamizdatURLCodec.vksParams(from: blob)
    }

    private var vksParamsCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "network",
                             bg: theme.mintDim, fg: theme.mint)
                    Text("Параметры VKS")
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Spacer()
                }

                vksField("shortid",
                         placeholder: linkShortIDPlaceholder,
                         text: $vksShortIDDraft)
                vksField("Wake DNS",
                         placeholder: linkWakeDNSPlaceholder,
                         text: $vksWakeDNSDraft)
                vksField("Зона",
                         placeholder: linkWakeZonePlaceholder,
                         text: $vksWakeZoneDraft)

                if !vksFeedback.isEmpty {
                    Text(vksFeedback)
                        .font(.geistMono(.regular, size: 11))
                        .foregroundStyle(theme.textDim)
                }

                Button(action: saveVKSParams) {
                    Text("Сохранить")
                        .font(.geist(.semibold, size: 13))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.mint)
                        .foregroundStyle(theme.mintInk)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var linkShortIDPlaceholder: String {
        if linkParams != nil {
            let peer = SamizdatURLCodec.h2PeerConfig(from: activeProfileBlob)
            if let s = peer?.shortID, !s.isEmpty { return "из ссылки: \(s)" }
        }
        return "hex из ссылки"
    }

    private var linkWakeDNSPlaceholder: String {
        if let dns = linkParams?.wakeDNS, !dns.isEmpty {
            return "из ссылки: \(dns)"
        }
        return "по умолчанию: \(VKSPreferences.defaultWakeDNS)"
    }

    private var linkWakeZonePlaceholder: String {
        if let zone = linkParams?.wakeZone, !zone.isEmpty {
            return "из ссылки: \(zone)"
        }
        let derived = VKSPreferences.derivedWakeZone(profileBlob: activeProfileBlob)
        if !derived.isEmpty { return "по умолчанию: \(derived)" }
        return "из ссылки (нет)"
    }

    private func vksField(_ label: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.geist(.medium, size: 12))
                .foregroundStyle(theme.textMuted)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .font(.geistMono(.regular, size: 12.5))
                .foregroundStyle(theme.text)
                .padding(.horizontal, 8)
                .padding(.vertical, 7)
                .background(theme.chip)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
    }

    private func saveVKSParams() {
        let shortIDDraft = vksShortIDDraft.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !shortIDDraft.isEmpty && !(shortIDDraft.count == 16 && shortIDDraft.allSatisfy({ $0.isHexDigit })) {
            vksFeedback = "Нужно 16 hex-символов shortid."
            return
        }
        VKSPreferences.shortIDHex = vksShortIDDraft
        VKSPreferences.wakeDNSOverride = vksWakeDNSDraft
        VKSPreferences.wakeZoneOverride = vksWakeZoneDraft
        // Re-sync drafts with the normalized persisted values.
        vksShortIDDraft = ""
        vksWakeDNSDraft = ""
        vksWakeZoneDraft = ""

        let blob = activeProfileBlob
        if !VKSPreferences.isConfigured(profileBlob: blob) {
            vksFeedback = "Сохранено. Нет shortid в профиле — белые списки не заработают."
        } else {
            vksFeedback = "Сохранено. Каналов: \(VKSPreferences.providerCount)."
        }
        Task { await VPNProfileStore.shared.refreshVKSLadder() }
    }

    // MARK: Детектор белых списков

    private var detectorCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "shield.lefthalf.filled",
                             bg: theme.amberDim, fg: theme.amber)
                    Text("Детектор белых списков")
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Spacer()
                }

                detectorField("Заблокированный хост", placeholder: "8.8.8.8", text: $testHostDraft)
                detectorField("Разрешённый хост", placeholder: "77.88.8.8", text: $whitelistHostDraft)

                Text("Интервал опроса (секунды)")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Stepper(value: $wlIntervalDraft, in: 5...120) {
                    Text("\(wlIntervalDraft) с")
                        .font(.geistMono(.regular, size: 14))
                        .foregroundStyle(theme.text)
                }
                .tint(theme.mint)
                .onChange(of: wlIntervalDraft) { _, newValue in
                    WhitelistProbePreferences.probeInterval = newValue
                    WhitelistStatusStore.resetDetectionProgress()
                    Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
                }

                Button(action: saveDetector) {
                    Text("Сохранить")
                        .font(.geist(.semibold, size: 13))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                        .background(theme.mint)
                        .foregroundStyle(theme.mintInk)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func detectorField(_ label: String, placeholder: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.geist(.medium, size: 12))
                .foregroundStyle(theme.textMuted)
            TextField(placeholder, text: text)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
                .keyboardType(.URL)
                .font(.geistMono(.regular, size: 12.5))
                .foregroundStyle(theme.text)
                .padding(.horizontal, 12)
                .padding(.vertical, 11)
                .background(theme.chip)
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .onSubmit { saveDetector() }
        }
    }

    private func saveDetector() {
        WhitelistProbePreferences.testHost = testHostDraft
        WhitelistProbePreferences.whitelistHost = whitelistHostDraft
        WhitelistProbePreferences.probeInterval = wlIntervalDraft
        WhitelistStatusStore.resetDetectionProgress()
        // Re-sync drafts so blank-saves snap back to the resolved default.
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        wlIntervalDraft = WhitelistProbePreferences.probeInterval
        Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
    }

    // MARK: Проверка связи

    private var probeURLCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "waveform.path.ecg",
                             bg: theme.mintDim, fg: theme.mint)
                    Text("Проверка связи")
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Spacer()
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("Адрес проверки")
                        .font(.geist(.medium, size: 12))
                        .foregroundStyle(theme.textMuted)
                    TextField("https://ya.ru", text: $pingURLDraft)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .keyboardType(.URL)
                        .font(.geistMono(.regular, size: 12.5))
                        .foregroundStyle(theme.text)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 11)
                        .background(theme.chip)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .onSubmit { saveProbeURL() }
                }

                HStack(spacing: 8) {
                    Button(action: saveProbeURL) {
                        Text("Сохранить")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetProbeURL) {
                        Text("Сбросить")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func saveProbeURL() {
        let trimmed = pingURLDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        PingURLPreferences.url = trimmed
        pingURLDraft = PingURLPreferences.url
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }

    private func resetProbeURL() {
        PingURLPreferences.resetToDefault()
        pingURLDraft = PingURLPreferences.url
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }

    // MARK: Диагностика

    private var diagnosticsCard: some View {
        CardContainer(padding: 0) {
            NavigationLink {
                LogView()
                    .environment(\.themeTokens, theme)
            } label: {
                DesignRow(
                    icon: IconCard(systemName: "doc.text",
                                   bg: theme.chip, fg: theme.textDim),
                    title: "Логи",
                    isLast: false
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
            }
            .buttonStyle(.plain)

            NavigationLink {
                TelegramSettingsView()
                    .environment(\.themeTokens, theme)
            } label: {
                DesignRow(
                    icon: IconCard(systemName: "paperplane.fill",
                                   bg: theme.chip, fg: theme.textDim),
                    title: "Telegram для логов",
                    isLast: true
                ) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(theme.textMuted)
                }
            }
            .buttonStyle(.plain)
        }
    }
}

/// Notification name used to flip the theme live without dismissing the
/// Settings sheet. App.swift / ContentView listens and re-reads the
/// theme to update the environment.
extension Notification.Name {
    static let tamizdatThemeChanged = Notification.Name("tamizdat.themeChanged")
}
