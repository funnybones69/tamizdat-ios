import SwiftUI
import Foundation
import SamizdatClient
import UserNotifications

/// IPA-D22: redesigned Settings sheet — grouped inset cards over the
/// theme background gradient. Sections (top → bottom):
///   1. Notifications  (Whitelist alerts toggle)
///   2. Configuration  (Endpoints → push to EndpointsView)
///   3. Ping probe     (URL code-block + Save / Reset)
///   4. Appearance     (Cream / Dark segmented control)
///   5. Diagnostics    (View logs + About)
///
/// Pool variant section deleted in D22 (V1 hardcoded in Go). Telegram
/// uploader stays reachable but as a row in Diagnostics rather than
/// its own section — it's a debug aid, not a primary config knob.
struct SettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    /// Called whenever the user changes endpoints. The parent uses this
    /// to refresh `hasConfig` and `hasBackupConfigured`.
    var onConfigChanged: (Bool) -> Void = { _ in }

    /// Theme picker is rendered here but the *root* view (App.swift /
    /// ContentView) reads `ThemePreferences.current` to compute the
    /// environment value. To make the picker change propagate live, we
    /// post a Notification on change; the root listens and re-renders.
    @State private var selectedTheme: AppTheme = ThemePreferences.current

    @State private var notificationsEnabled: Bool = NotificationPreferences.enabled
    @State private var permissionStatus: UNAuthorizationStatus = .notDetermined
    @State private var permissionDeniedAlert: Bool = false

    @State private var pingURL: String = PingURLPreferences.url
    @State private var pingURLDraft: String = PingURLPreferences.url

    // One VK invite per line, up to four rooms. Each room automatically gets
    // the verified pool size of 20 workers; peer/password still derive from Main.
    @State private var vkRoomsDraft: String = VKCredsPreferences.roomHashes.joined(separator: "\n")
    @State private var vkCallHashFeedback: String = ""
    @State private var turnServerDraft: String = VKCredsPreferences.turnServer

    // VKS room transports (whitelist carrier ladder). Drafts only — they
    // persist via VKSPreferences on Save; the extension applies them on
    // the next connect.
    @State private var vksEnabledDraft: Bool = VKSPreferences.enabled
    @State private var vksShortIDDraft: String = VKSPreferences.shortIDHex
    @State private var vksPortDraft: String = String(VKSPreferences.listenPort)
    @State private var vksServerDraft: String = VKSPreferences.server
    @State private var vksTelemostOnDraft: Bool = VKSPreferences.telemostEnabled
    @State private var vksWbstreamOnDraft: Bool = VKSPreferences.wbstreamEnabled
    @State private var vksJazzOnDraft: Bool = VKSPreferences.jazzEnabled
    @State private var vksMtsOnDraft: Bool = VKSPreferences.mtsEnabled
    @State private var vksFeedback: String = ""

    // Whitelist-detection ICMP echo target lists.
    @State private var testHostDraft: String = WhitelistProbePreferences.testHost
    @State private var whitelistHostDraft: String = WhitelistProbePreferences.whitelistHost
    // Expanded whitelist tunables.
    @State private var wlSuccessesDraft: Int = WhitelistProbePreferences.successesNeeded
    @State private var wlIntervalDraft: Int = WhitelistProbePreferences.probeInterval

    // Phase 2G: what does the whitelist endpoint actually do?
    // Either dial the backup tamizdat URI (legacy), or route through
    // VK TURN. The backup URI is preserved in either case so the
    // operator can flip back without re-pasting it.
    @State private var whitelistMode: WhitelistMode = WhitelistMode.current

    @State private var showEndpoints = false
    @State private var showLogs = false
    @State private var showTelegram = false

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            VStack(spacing: 0) {
                // ── Header ───────────────────────────────────────
                HStack {
                    Chip(label: "Done") { dismiss() }
                    Spacer()
                    Text("Settings")
                        .font(.geist(.semibold, size: 16))
                        .foregroundStyle(theme.text)
                    Spacer()
                    Color.clear.frame(width: 56, height: 1)
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)
                .padding(.bottom, 6)

                // ── Large title ──────────────────────────────────
                Text("Settings")
                    .font(.geist(.bold, size: 32))
                    .tracking(-0.96)
                    .foregroundStyle(theme.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 20)
                    .padding(.bottom, 14)

                ScrollView {
                    VStack(spacing: 0) {
                        // ── Notifications ────────────────────────
                        SectionLabel(text: "Notifications")
                        notificationsCard
                            .padding(.horizontal, 16)

                        // ── Configuration ────────────────────────
                        SectionLabel(text: "Configuration")
                            .padding(.top, 22)
                        configurationCard
                            .padding(.horizontal, 16)

                        // ── Whitelist carrier ────────────────────
                        SectionLabel(text: "Whitelist carrier")
                            .padding(.top, 22)
                        whitelistCarrierCard
                            .padding(.horizontal, 16)

                        // ── Ping probe ───────────────────────────
                        SectionLabel(text: "Ping probe")
                            .padding(.top, 22)
                        pingProbeCard
                            .padding(.horizontal, 16)

                        // ── Whitelist detection ──────────────────
                        SectionLabel(text: "Whitelist detection")
                            .padding(.top, 22)
                        whitelistProbeCard
                            .padding(.horizontal, 16)

                        // ── Appearance ───────────────────────────
                        SectionLabel(text: "Appearance")
                            .padding(.top, 22)
                        appearanceCard
                            .padding(.horizontal, 16)

                        // ── Diagnostics ──────────────────────────
                        SectionLabel(text: "Diagnostics")
                            .padding(.top, 22)
                        diagnosticsCard
                            .padding(.horizontal, 16)

                        // ── About ────────────────────────────────
                        SectionLabel(text: "About")
                            .padding(.top, 22)
                        aboutCard
                            .padding(.horizontal, 16)

                        Color.clear.frame(height: 28)
                    }
                }
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .task {
            permissionStatus = await NotificationPreferences.currentSystemAuthorization()
            syncVKDerivedH2Config()
        }
        .alert("Notifications were not granted", isPresented: $permissionDeniedAlert) {
            Button("Open iOS Settings") { openSystemSettings() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Enable notifications for Tamizdat in iOS Settings to receive whitelist-detection alerts.")
        }
        .sheet(isPresented: $showEndpoints) {
            EndpointsView { saved in
                onConfigChanged(saved)
                syncVKDerivedH2Config()
            }
            .environment(\.themeTokens, theme)
        }
        .sheet(isPresented: $showTelegram) {
            TelegramSettingsView()
        }
    }

    // MARK: – Section cards

    private var notificationsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "bell.badge", bg: theme.blueDim, fg: theme.blue),
                title: "Whitelist alerts",
                sub: "Local push when auto-detector flips between Main and Whitelist.",
                isLast: permissionStatus != .denied || !notificationsEnabled
            ) {
                Toggle("", isOn: $notificationsEnabled)
                    .labelsHidden()
                    .tint(theme.mint)
                    .onChange(of: notificationsEnabled) { _, newValue in
                        if newValue {
                            Task { await handleEnableNotifications() }
                        } else {
                            NotificationPreferences.enabled = false
                        }
                    }
            }
            if permissionStatus == .denied && notificationsEnabled {
                DesignRow(
                    icon: IconCard(systemName: "exclamationmark.triangle.fill",
                                   bg: theme.amberDim, fg: theme.amber),
                    title: "Notifications are blocked",
                    sub: "Tap to open iOS Settings and re-enable.",
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

    /// Unified whitelist block: picks the carrier used when the detector
    /// flips to the whitelist endpoint — VKS rooms, legacy H2 backup, or
    /// VK TURN (in that order; TURN last). The carrier-specific settings
    /// show inline below the picker.
    private var whitelistCarrierCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "shield.lefthalf.filled",
                             bg: theme.amberDim, fg: theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Whitelist carrier")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("What carries traffic under the whitelist")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Text("Whitelist mode")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Picker("", selection: $whitelistMode) {
                    ForEach(WhitelistMode.allCases) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .onChange(of: whitelistMode) { _, newValue in
                    WhitelistMode.current = newValue
                    // Re-evaluate the currently effective endpoint immediately.
                    // Without this RPC, H2↔VKS↔TURN only changed persisted prefs
                    // and the live extension kept the old upstream until reconnect.
                    Task {
                        _ = await VPNProfileStore.shared.switchEndpoint(to: EndpointModeStore.current)
                    }
                }

                switch whitelistMode {
                case .vks:
                    vksCarrierContent
                case .vkTurn:
                    vkTurnCarrierContent
                }
            }
        }
    }

    // VK TURN card: lets the operator paste a VK call-invite hash. The
    // hash is required by VKSession paramsClient / TURNSession paramsRefresher to begin
    // the 5-step VK API flow; if it is empty, refresh silently no-ops.
    //
    // To obtain a hash: open VK in a browser or app, create a group call,
    // copy the invitation link (https://vk.ru/call/join/<HASH>) and paste
    // either the full URL or just the slug here.
    //
    // Donor caveat (amurcanov/network adapter-turn-vk-android README): when leaving
    // the call, choose "just leave" — not "end for everyone" — otherwise
    // the hash dies and refresh starts failing with VKSession paramsError.deadHash.
    /// VK TURN carrier sub-config — shown inside the Whitelist card when
    /// Whitelist mode = TURN.
    private var vkTurnCarrierContent: some View {
        VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "phone.connection",
                             bg: theme.mintDim, fg: theme.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("VK TURN rooms")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Paste 1–4 invite links, one per line")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                TextEditor(text: $vkRoomsDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .scrollContentBackground(.hidden)
                    .frame(minHeight: 104)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 7)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                let roomCount = Self.roomHashes(from: vkRoomsDraft).count
                HStack {
                    Text("Rooms")
                        .font(.geist(.medium, size: 12))
                        .foregroundStyle(theme.textMuted)
                    Spacer()
                    Text("\(roomCount)/4 · \(roomCount * VKCredsPreferences.workersPerRoom) workers")
                        .font(.geistMono(.semibold, size: 12))
                        .foregroundStyle(theme.text)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(theme.chip)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }

                Text("Rooms cannot be discovered automatically: VK does not expose the required private calls. Add each invite once; links are normalized and duplicates removed. Every room uses 20 workers automatically.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)

                Text("Server: host:port для TURN-плеча (пусто = берётся из Main URI). Пароль подключения — shortid пользователя. VK TURN включается при Whitelist mode = TURN.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)
                    .padding(.top, 4)
                TextField("Server (host:port)", text: $turnServerDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 7)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 10))

                if !vkCallHashFeedback.isEmpty {
                    Text(vkCallHashFeedback)
                        .font(.geistMono(.regular, size: 11))
                        .foregroundStyle(theme.textDim)
                }

                Button(action: saveVKTurnSettings) {
                    Text("Save")
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

    private static func roomHashes(from draft: String) -> [String] {
        VKCredsPreferences.normalizeRoomHashes(
            draft.components(separatedBy: .newlines)
        )
    }

    private func syncVKDerivedH2Config() -> SamizdatURLCodec.H2PeerConfig? {
        let blob = ConfigStore.shared.load() ?? ""
        let derived = SamizdatURLCodec.h2PeerConfig(from: blob)
        VKCredsPreferences.applyDerivedH2PeerConfig(derived)
        return derived
    }

    private func saveVKTurnSettings() {
        let oldRooms = VKCredsPreferences.roomHashes
        VKCredsPreferences.turnServer = turnServerDraft
        let derived = syncVKDerivedH2Config()
        let rooms = Self.roomHashes(from: vkRoomsDraft)
        guard rooms.count <= VKCredsPreferences.maxRooms else {
            vkCallHashFeedback = "Можно сохранить максимум 4 уникальные комнаты"
            return
        }
        VKCredsPreferences.roomHashes = rooms
        VKCredsPreferences.workers = VKCredsPreferences.workersPerRoom
        vkRoomsDraft = rooms.joined(separator: "\n")

        if rooms != oldRooms {
            TURNCredsStore.shared.clear()
        }

        guard !rooms.isEmpty else {
            TURNCredsStore.shared.clear()
            vkCallHashFeedback = "Сохранено: комнаты очищены"
            return
        }
        guard derived != nil else {
            vkCallHashFeedback = "Нет Main URI или shortid в Proxies; \(rooms.count) комнат сохранено"
            return
        }

        let totalWorkers = rooms.count * VKCredsPreferences.workersPerRoom
        let needsRefresh = (rooms != oldRooms) || TURNCredsStore.shared.needsRefresh
        let turnActive = TURNCredsRefresher.shouldMaintainTurnCredentialsNow()
        if needsRefresh && turnActive {
            vkCallHashFeedback = "Сохранено: \(rooms.count) комнат, \(totalWorkers) workers; получаю credentials…"
            TURNCredsRefresher.shared.forceRefresh(reason: "settingsSave", requireActiveTURN: true)
        } else if needsRefresh {
            vkCallHashFeedback = "Сохранено: \(rooms.count) комнат, \(totalWorkers) workers; credentials обновятся при TURN"
        } else {
            vkCallHashFeedback = "Сохранено: \(rooms.count) комнат, \(totalWorkers) workers"
        }

        Task { @MainActor in
            let result = await VPNProfileStore.shared.restartVKTurnUpstream()
            switch result {
            case "attachStarted":
                vkCallHashFeedback = "TURN перезапущен: \(rooms.count)×20"
            case let value where value.hasPrefix("turnDisabled"):
                vkCallHashFeedback = "Сохранено: \(rooms.count)×20 применится при Whitelist+TURN"
            case "noCreds":
                vkCallHashFeedback = "Сохранено: жду credentials для всех \(rooms.count) комнат"
            case "sendError":
                vkCallHashFeedback = "Сохранено: применится при следующем connect"
            default:
                break
            }
        }
    }

    /// VKS carrier sub-config — shown inside the Whitelist card when
    /// Whitelist mode = VKS: master toggle + one toggle per provider.
    /// The ladder itself runs in the PacketTunnel extension; saving only
    /// persists the values — they are applied on the next VPN connect.
    private var vksCarrierContent: some View {
        VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "network",
                             bg: theme.blueDim, fg: theme.blue)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("VKS rooms")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("Master switch; per-provider toggles below")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                    Toggle("", isOn: $vksEnabledDraft)
                        .labelsHidden()
                        .tint(theme.mint)
                }

                vksProviderRow("Telemost", on: $vksTelemostOnDraft)
                vksProviderRow("WB Stream", on: $vksWbstreamOnDraft)
                vksProviderRow("Jazz", on: $vksJazzOnDraft)
                vksProviderRow("MTS", on: $vksMtsOnDraft)
                vksField("shortid", "hex из users", $vksShortIDDraft)
            vksField("Server", "host:port (без дефолта)", $vksServerDraft)
                vksField("Listen port", String(VKSPreferences.defaultListenPort), $vksPortDraft)

                Text("Мастер-тумблер (сверху): VKS активен — в whitelist-режиме перехватывает у VK TURN (тот остаётся резервом). У каждого провайдера свой тумблер — клиент хранит ТОЛЬКО провайдеров: при подключении шлёт бикон, сервер создаёт/назначает комнату и отвечает TXT. Рандомный выбор из активных + failover.")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)

                if !vksFeedback.isEmpty {
                    Text(vksFeedback)
                        .font(.geistMono(.regular, size: 11))
                        .foregroundStyle(theme.textDim)
                }

                Button(action: saveVKSSettings) {
                    Text("Save")
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

    private func vksField(_ label: String, _ placeholder: String, _ text: Binding<String>) -> some View {
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

    /// Provider row: just a switch. The client stores only the provider —
    /// the room is created/assigned by the server via the beacon (TXT
    /// answer), so there is nothing to type here.
    private func vksProviderRow(_ title: String, on: Binding<Bool>) -> some View {
        HStack {
            Text(title)
                .font(.geist(.medium, size: 12))
                .foregroundStyle(theme.textMuted)
            Spacer()
            Toggle("", isOn: on)
                .labelsHidden()
                .tint(theme.mint)
        }
    }

    private func saveVKSSettings() {
        VKSPreferences.enabled = vksEnabledDraft
        VKSPreferences.telemostEnabled = vksTelemostOnDraft
        VKSPreferences.wbstreamEnabled = vksWbstreamOnDraft
        VKSPreferences.jazzEnabled = vksJazzOnDraft
        VKSPreferences.mtsEnabled = vksMtsOnDraft
        VKSPreferences.shortIDHex = vksShortIDDraft
        VKSPreferences.server = vksServerDraft
        let portText = vksPortDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        var portNote = ""
        if let port = Int(portText), (1024...65535).contains(port), port != 9000, port != 18443 {
            VKSPreferences.listenPort = port
        } else {
            portNote = " Порт отклонён: нужен 1024–65535, кроме 9000/18443."
        }

        // Re-sync the drafts with the normalized persisted values.
        vksTelemostOnDraft = VKSPreferences.telemostEnabled
        vksWbstreamOnDraft = VKSPreferences.wbstreamEnabled
        vksJazzOnDraft = VKSPreferences.jazzEnabled
        vksMtsOnDraft = VKSPreferences.mtsEnabled
        vksShortIDDraft = VKSPreferences.shortIDHex
        vksServerDraft = VKSPreferences.server
        vksPortDraft = String(VKSPreferences.listenPort)

        if !VKSPreferences.enabled {
            vksFeedback = "Сохранено: VKS выключен (текущая лестница доживёт до переподключения)"
        } else if !VKSPreferences.isConfigured {
            vksFeedback = "Сохранено, но лестница не собрана: нужна комната + валидный key (64 hex) + shortid"
        } else {
            vksFeedback = "Сохранено: \(VKSPreferences.providerCount) провайдер(а); применится при следующем connect"
        }
        vksFeedback += portNote
    }

    private var configurationCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "key.fill", bg: theme.mintDim, fg: theme.mint),
                title: "Proxies",
                sub: configSubtitle,
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showEndpoints = true }
        }
    }

    private var pingProbeCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "waveform.path.ecg",
                             bg: theme.mintDim, fg: theme.mint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Probe URL")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("HEAD every 10s through the tunnel")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                // Inline TextField for editing
                TextField("https://example.com/probe", text: $pingURLDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveURL() }

                HStack(spacing: 8) {
                    Button(action: saveURL) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetURL) {
                        Text("Reset to default")
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

    private var whitelistProbeCard: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    IconCard(systemName: "shield.lefthalf.filled",
                             bg: theme.amberDim, fg: theme.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Probe targets")
                            .font(.geist(.medium, size: 16))
                            .foregroundStyle(theme.text)
                        Text("ICMP ping outside the tunnel")
                            .font(.geistMono(.regular, size: 11))
                            .foregroundStyle(theme.textDim)
                    }
                    Spacer()
                }

                Text("Normally blocked ping target")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                TextField("8.8.8.8", text: $testHostDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveWhitelistProbes() }

                Text("Allowed ping target")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                TextField("77.88.8.8", text: $whitelistHostDraft)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .keyboardType(.URL)
                    .font(.geistMono(.regular, size: 12.5))
                    .foregroundStyle(theme.text)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 11)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .onSubmit { saveWhitelistProbes() }

                // D45: successes needed before switching back to primary
                Text("Matching ping cycles before switch")
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

                // D45: probe interval (seconds)
                Text("Probe interval (seconds)")
                    .font(.geist(.medium, size: 12))
                    .foregroundStyle(theme.textMuted)
                Stepper(value: $wlIntervalDraft, in: 5...120) {
                    Text("\(wlIntervalDraft) s")
                        .font(.geistMono(.regular, size: 14))
                        .foregroundStyle(theme.text)
                }
                .tint(theme.mint)
                .onChange(of: wlIntervalDraft) { _, newValue in
                    WhitelistProbePreferences.probeInterval = newValue
                    WhitelistStatusStore.resetDetectionProgress()
                    Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
                }

                HStack(spacing: 8) {
                    Button(action: saveWhitelistProbes) {
                        Text("Save")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    Button(action: resetWhitelistProbes) {
                        Text("Reset")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(theme.chip)
                            .foregroundStyle(theme.text)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                }

                Text("ICMP echo only. If both targets reply: Free internet. If the blocked target times out while the allowed target replies: Whitelist active. Any other result is Error detecting.")
                    .font(.geist(.regular, size: 11))
                    .foregroundStyle(theme.textDim)
            }
        }
    }

    private var appearanceCard: some View {
        CardContainer(padding: 16) {
            HStack(spacing: 12) {
                IconCard(systemName: "paintpalette.fill",
                         bg: theme.chip, fg: theme.text)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Theme")
                        .font(.geist(.medium, size: 16))
                        .foregroundStyle(theme.text)
                    Text("Cream is the default. Dark suits OLED.")
                        .font(.geist(.regular, size: 12.5))
                        .foregroundStyle(theme.textDim)
                }
                Spacer()
                // Custom segmented control matching the chip design
                HStack(spacing: 2) {
                    themeSegment(.cream)
                    themeSegment(.dark)
                }
                .padding(3)
                .background(theme.chip)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }

    private func themeSegment(_ option: AppTheme) -> some View {
        let active = selectedTheme == option
        return Button {
            selectedTheme = option
            ThemePreferences.current = option
            // Propagate to root immediately
            NotificationCenter.default.post(name: .tamizdatThemeChanged, object: nil)
        } label: {
            Text(option.label)
                .font(.geist(.semibold, size: 13))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(active ? theme.chipActive : Color.clear)
                .foregroundStyle(active ? theme.chipActiveText : theme.textDim)
                .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private var diagnosticsCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "doc.text",
                               bg: theme.chip, fg: theme.textDim),
                title: "View logs",
                sub: "Live stream + filters",
                isLast: false
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showLogs = true }

            DesignRow(
                icon: IconCard(systemName: "paperplane.fill",
                               bg: theme.chip, fg: theme.textDim),
                title: "Telegram log uploader",
                sub: "Bot token + chat id for debugging",
                isLast: true
            ) {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(theme.textMuted)
            }
            .contentShape(Rectangle())
            .onTapGesture { showTelegram = true }
        }
        .sheet(isPresented: $showLogs) {
            // Pull bridge from environment-free reach — Logs reads from
            // App Group log file directly, no shared SamizdatBridge needed.
            LogView()
                .environment(\.themeTokens, theme)
        }
    }

    private var aboutCard: some View {
        CardContainer(padding: 0) {
            DesignRow(
                icon: IconCard(systemName: "info.circle",
                               bg: theme.chip, fg: theme.textDim),
                title: "Version",
                sub: versionLabel,
                isLast: false
            ) {
                EmptyView()
            }
            DesignRow(
                icon: IconCard(systemName: "arrow.up.right.square",
                               bg: theme.chip, fg: theme.textDim),
                title: "Project on GitHub",
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

    // MARK: – Helpers

    private var versionLabel: String {
        let info = Bundle.main.infoDictionary
        let marketing = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(marketing) (\(build)) · IPA-D57"
    }

    private var configSubtitle: String {
        let blob = ConfigStore.shared.load() ?? ""
        if blob.isEmpty { return "Not configured" }
        let split = SamizdatURLCodec.split(blob)
        let mainConfigured = !split.primary.isEmpty
        let backupConfigured = (split.backup != nil)
        switch (mainConfigured, backupConfigured) {
        case (true, true):   return "Main + Whitelist · 2 configured"
        case (true, false):  return "Main only"
        case (false, true):  return "Whitelist only (Main missing)"
        case (false, false): return "Not configured"
        }
    }

    private func saveURL() {
        let trimmed = pingURLDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        PingURLPreferences.url = trimmed
        pingURL = PingURLPreferences.url
        pingURLDraft = pingURL
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }

    private func resetURL() {
        PingURLPreferences.resetToDefault()
        pingURL = PingURLPreferences.url
        pingURLDraft = pingURL
        Task { await VPNProfileStore.shared.refreshPingURL() }
    }

    // MARK: – Restricted-profile probes

    private func saveWhitelistProbes() {
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

    private func resetWhitelistProbes() {
        WhitelistProbePreferences.reset()
        WhitelistStatusStore.resetDetectionProgress()
        testHostDraft = WhitelistProbePreferences.testHost
        whitelistHostDraft = WhitelistProbePreferences.whitelistHost
        wlSuccessesDraft = WhitelistProbePreferences.successesNeeded
        wlIntervalDraft = WhitelistProbePreferences.probeInterval
        Task { await VPNProfileStore.shared.refreshWhitelistProbes() }
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

    private func openSystemSettings() {
        guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
        UIApplication.shared.open(url)
    }
}

/// Notification name used to flip the theme live without dismissing the
/// Settings sheet. App.swift / ContentView listens and re-reads
/// `ThemePreferences.current` to update the environment.
extension Notification.Name {
    static let tamizdatThemeChanged = Notification.Name("tamizdat.themeChanged")
}
