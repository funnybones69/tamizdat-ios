import SwiftUI
import Foundation
import SamizdatClient
import UserNotifications

/// Настройки — единый минимальный экран. Все пользовательские строки —
/// русские; оформление — дизайн-токены (Geist, ThemeTokens, mint).
///
/// Структура:
///   Подключение      → Профиль (список профилей), Режим (Авто/Обычный/Whitelist)
///   Каналы whitelist → порядок провайдеров (drag) + тумблер на строку
///   Уведомления      → «Переключение режима» + строка про заблокированные
///   Оформление       → Системная / Светлая / Тёмная
///   Дополнительно ›  → push-экран: Параметры VKS, Детектор whitelist,
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

    /// Whitelist channel list: local mirror of VKSPreferences.providerOrder
    /// + per-provider enabled flags. Edits (drag/toggle) persist
    /// immediately and apply on the next connect (or live via the
    /// refreshVKSLadder provider message while connected).
    @State private var providerOrder: [String] = VKSPreferences.providerOrder

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

                        // ── Каналы whitelist ──────────────────────
                        SectionLabel(text: "Каналы whitelist")
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
            .alert("Уведомления не выданы", isPresented: $permissionDeniedAlert) {
                Button("Открыть настройки") { openSystemSettings() }
                Button("Отмена", role: .cancel) { }
            } message: {
                Text("Разрешите уведомления для Tamizdat в настройках iOS, чтобы получать оповещения о смене режима.")
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

    /// Режим: [ Авто | Обычный | Whititelist ]. Смена применяется сразу —
    /// перезапись EndpointModeStore + живой rewire через switchEndpoint.
    private var modeRow: some View {
        VStack(spacing: 10) {
            HStack(spacing: 14) {
                IconCard(systemName: "arrow.triangle.branch",
                         bg: theme.blueDim, fg: theme.blue)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Режим")
                        .font(.geist(.medium, size: 16))
                        .tracking(-0.16)
                        .foregroundStyle(theme.text)
                    Text("Whitelist гоняет трафик через комнаты VKS")
                        .font(.geist(.regular, size: 12.5))
                        .foregroundStyle(theme.textDim)
                }
                Spacer(minLength: 8)
            }
            segmentedControl(
                options: EndpointMode.allCases,
                selection: Binding(
                    get: { EndpointModeStore.current },
                    set: { newValue in
                        EndpointModeStore.current = newValue
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

    // MARK: – Каналы whitelist

    /// Переупорядочиваемый список провайдеров VKS: drag-хэндл слева,
    /// тумблер справа. Первая включённая строка — основной канал, остальные
    /// — failover. Изменения применяются при следующем подключении (или
    /// живьём, если туннель поднят).
    private var channelsCard: some View {
        CardContainer(padding: 0) {
            VStack(spacing: 0) {
                HStack(spacing: 14) {
                    IconCard(systemName: "network",
                             bg: theme.blueDim, fg: theme.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Каналы")
                            .font(.geist(.medium, size: 16))
                            .tracking(-0.16)
                            .foregroundStyle(theme.text)
                        Text("Порядок = приоритет. Первый активный — основной.")
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer(minLength: 8)
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 6)

                // Тумблер VKS общий (мастер-выключатель лестницы).
                channelToggleRow(
                    title: "VKS",
                    icon: "shield.lefthalf.filled",
                    isOn: Binding(
                        get: { VKSPreferences.enabled },
                        set: { VKSPreferences.enabled = $0 }
                    ),
                    isLast: false
                )

                ForEach(Array(providerOrder.enumerated()), id: \.element) { index, provider in
                    channelProviderRow(provider, orderIndex: index)
                }
            }
        }
    }

    /// Строка одного провайдера: drag-хэндл + имя + тумблер.
    /// Резерв под будущую строку статуса/действия («Нужен вход — Войти»)
    /// — место под заголовком строки, пока пустое.
    private func channelProviderRow(_ provider: String, orderIndex: Int) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "line.3.horizontal")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(theme.textMuted)
                .opacity(0.6)
            VStack(alignment: .leading, spacing: 2) {
                Text(VKSPreferences.providerDisplayName(provider))
                    .font(.geist(.medium, size: 15))
                    .tracking(-0.16)
                    .foregroundStyle(theme.text)
                // Слот статуса/действия провайдера (заполняется из
                // статуса расширения; сейчас пуст — см. follow-up).
                Color.clear.frame(height: 0)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: Binding(
                get: { VKSPreferences.providerEnabled(provider) },
                set: { newValue in
                    VKSPreferences.setProviderEnabled(provider, newValue)
                    pushLadderUpdate()
                }
            ))
            .labelsHidden()
            .tint(theme.mint)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(providerRowBackground(orderIndex: orderIndex))
        .contentShape(Rectangle())
        .gesture(channelDragGesture(provider: provider))
    }

    @ViewBuilder
    private func providerRowBackground(orderIndex: Int) -> some View {
        // Отключённый провайдер визуально гаснет.
        let on = VKSPreferences.providerEnabled(providerOrder[orderIndex])
        Rectangle()
            .fill(on ? Color.clear : theme.chip)
            .opacity(on ? 0 : 0.5)
    }

    /// Drag-reorder: перекидываем строку внутри providerOrder и
    /// персистим новый порядок.
    private func channelDragGesture(provider: String) -> some Gesture {
        DragGesture(minimumDistance: 12)
            .onEnded { value in
                // Простая эвристика: вертикальный drag > 40pt двигает
                // строку на одну позицию вверх/вниз. Полноценный
                // List-based reorder здесь не используется — карточный
                // дизайн держит строки в CardContainer.
                guard abs(value.translation.height) > 40 else { return }
                guard let index = providerOrder.firstIndex(of: provider) else { return }
                let direction = value.translation.height > 0 ? 1 : -1
                let target = index + direction
                guard providerOrder.indices.contains(target) else { return }
                providerOrder.swapAt(index, target)
                VKSPreferences.providerOrder = providerOrder
                pushLadderUpdate()
            }
    }

    /// Живое применение лестницы в работающий туннель (no-op при
    /// отключённом VPN — следующий connect читает те же ключи).
    private func pushLadderUpdate() {
        Task { await VPNProfileStore.shared.refreshVKSLadder() }
    }

    @ViewBuilder
    private func channelToggleRow(title: String, icon: String, isOn: Binding<Bool>, isLast: Bool) -> some View {
        HStack(spacing: 14) {
            IconCard(systemName: icon, bg: theme.chip, fg: theme.textDim)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.geist(.medium, size: 16))
                    .tracking(-0.16)
                    .foregroundStyle(theme.text)
            }
            Spacer(minLength: 8)
            Toggle("", isOn: isOn)
                .labelsHidden()
                .tint(theme.mint)
                .onChange(of: isOn.wrappedValue) { _, _ in
                    pushLadderUpdate()
                }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        if !isLast {
            Rectangle()
                .fill(theme.rowBorder)
                .frame(height: 0.5)
                .padding(.leading, 16)
        }
    }

    // MARK: – Уведомления

    private var notificationsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "bell.badge", bg: theme.blueDim, fg: theme.blue),
                title: "Переключение режима",
                sub: "Локальный push, когда детектор переключает Обычный ↔ Whitelist.",
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
                    sub: "Нажмите, чтобы открыть настройки iOS и включить.",
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
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Тема")
                            .font(.geist(.medium, size: 16))
                            .tracking(-0.16)
                            .foregroundStyle(theme.text)
                        Text("Светлая — по умолчанию, тёмная экономит OLED.")
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                    }
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
                    sub: "Параметры VKS, детектор, проверка связи, логи",
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
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
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
        case .backup:  return "Whitelist"
        case .auto:    return "Авто"
        }
    }
}

// MARK: – Дополнительно (push-экран)

/// Дополнительно: параметры VKS (ovverride'ы с плейсхолдерами из ссылки),
/// детектор whitelist, проверка связи, логи, Telegram для логов.
private struct AdvancedView: View {
    @Environment(\.themeTokens) private var theme

    // Параметры VKS — черновики; применяются кнопкой «Сохранить»
    // (ключ и shortid нужно валидировать).
    @State private var vksShortIDDraft: String = ""
    @State private var vksKeyDraft: String = ""
    @State private var vksWakeDNSDraft: String = ""
    @State private var vksWakeZoneDraft: String = ""
    @State private var vksFeedback: String = ""

    // Детектор whitelist.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost
    @State private var wlSuccessesDraft: Int = WhitelistProbePreferences.successesNeeded
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

                    SectionLabel(text: "Детектор whitelist")
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
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Параметры VKS")
                            .font(.geist(.medium, size: 16))
                            .tracking(-0.16)
                            .foregroundStyle(theme.text)
                        Text("Пустое поле = значение из ссылки профиля.")
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                vksField("shortid",
                         placeholder: linkShortIDPlaceholder,
                         text: $vksShortIDDraft)
                vksField("Ключ (64 hex)",
                         placeholder: linkKeyPlaceholder,
                         text: $vksKeyDraft)
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

                Text("Провайдер и комната выбираются автоматически: клиент шлёт бикон, сервер создаёт комнату и отвечает TXT. Применится при следующем подключении.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private var linkShortIDPlaceholder: String {
        if let params = linkParams {
            let peer = SamizdatURLCodec.h2PeerConfig(from: activeProfileBlob)
            if let s = peer?.shortID, !s.isEmpty { return "из ссылки: \(s)" }
        }
        return "hex из ссылки"
    }

    private var linkKeyPlaceholder: String {
        if let key = linkParams?.vksKeyHex, !key.isEmpty {
            let head = key.prefix(8)
            return "из ссылки: \(head)…"
        }
        return "64 hex из ссылки"
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
        let keyDraft = vksKeyDraft.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !keyDraft.isEmpty && !(keyDraft.count == 64 && keyDraft.allSatisfy({ $0.isHexDigit })) {
            vksFeedback = "Ключ отклонён: нужно 64 hex-символа."
            return
        }
        VKSPreferences.shortIDHex = vksShortIDDraft
        VKSPreferences.keyHex = keyDraft
        VKSPreferences.wakeDNSOverride = vksWakeDNSDraft
        VKSPreferences.wakeZoneOverride = vksWakeZoneDraft
        // Re-sync drafts with the normalized persisted values.
        vksShortIDDraft = ""
        vksKeyDraft = ""
        vksWakeDNSDraft = ""
        vksWakeZoneDraft = ""

        let blob = activeProfileBlob
        if !VKSPreferences.enabled {
            vksFeedback = "Сохранено: VKS выключен (лестница доживёт до переподключения)"
        } else if !VKSPreferences.isConfigured(profileBlob: blob) {
            vksFeedback = "Сохранено, но лестница не собрана: нужен валидный ключ (64 hex) — из ссылки или поля выше"
        } else {
            vksFeedback = "Сохранено: \(VKSPreferences.providerCount) провайдер(а); применится при следующем подключении"
        }
        Task { await VPNProfileStore.shared.refreshVKSLadder() }
    }

    // MARK: Детектор whitelist

    private var detectorCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "shield.lefthalf.filled",
                             bg: theme.amberDim, fg: theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Детектор whitelist")
                            .font(.geist(.medium, size: 16))
                            .tracking(-0.16)
                            .foregroundStyle(theme.text)
                        Text("ICMP-пинг вне туннеля")
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                detectorField("Заблокированный хост", placeholder: "8.8.8.8", text: $testHostDraft)
                detectorField("Разрешённый хост", placeholder: "77.88.8.8", text: $whitelistHostDraft)

                Text("Подтверждённых циклов до переключения")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Stepper(value: $wlSuccessesDraft, in: 1...10) {
                    Text("\(wlSuccessesDraft)")
                        .font(.geistMono(.regular, size: 14))
                        .foregroundStyle(theme.text)
                }
                .tint(theme.mint)
                .onChange(of: wlSuccessesDraft) { _, newValue in
                    WhitelistProbePreferences.successesNeeded = newValue
                    WhitelistStatusStore.resetDetectionProgress()
                    Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
                }

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

                Text("Только ICMP echo. Отвечают оба — свободный интернет. Молчит заблокированный при живом разрешённом — whitelist. Остальное — ошибка определения.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)
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
        WhitelistProbePreferences.successesNeeded = wlSuccessesDraft
        WhitelistProbePreferences.probeInterval = wlIntervalDraft
        WhitelistStatusStore.resetDetectionProgress()
        // Re-sync drafts so blank-saves snap back to the resolved default.
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        wlSuccessesDraft = WhitelistProbePreferences.successesNeeded
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
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Проверка связи")
                            .font(.geist(.medium, size: 16))
                            .tracking(-0.16)
                            .foregroundStyle(theme.text)
                        // Реальное поведение: HTTP HEAD через туннель,
                        // 3 c на пробу на переднем плане / 30 c в фоне,
                        // провал = 2 промаха подряд. Дефолт — ya.ru.
                        Text("HTTP HEAD через туннель, каждые 3 с на экране / 30 с в фоне")
                            .font(.geist(.regular, size: 12.5))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("URL пробы")
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
                    sub: "Живая лента + фильтры",
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
                    sub: "Токен бота + chat id",
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
