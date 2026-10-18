import SwiftUI

/// Telegram для логов — экран в стиле дизайн-токенов (Geist, ThemeTokens).
/// Токен бота + chat id используются кнопкой «Telegram» на экране логов.
/// Хранится в UserDefaults (это отладочные креды, не секреты профиля —
/// и их можно мгновенно очистить).
struct TelegramSettingsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    @State private var botToken: String = TelegramReporter.botToken
    @State private var chatID:   String = TelegramReporter.chatID
    @State private var testStatus: TestStatus = .idle

    enum TestStatus: Equatable {
        case idle, sending, ok, failed(String)

        var label: String {
            switch self {
            case .idle:    return "Отправить тест"
            case .sending: return "Отправка…"
            case .ok:      return "Отправлено ✓"
            case .failed:  return "Ошибка"
            }
        }
    }

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            ScrollView {
                VStack(spacing: 0) {
                    CardContainer(padding: 16) {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack(spacing: 12) {
                                IconCard(systemName: "paperplane.fill",
                                         bg: theme.blueDim, fg: theme.blue)
                                Text("Telegram для логов")
                                    .font(.geist(.medium, size: 16))
                                    .tracking(-0.16)
                                    .foregroundStyle(theme.text)
                                Spacer()
                            }

                            telegramField("Токен бота", placeholder: "123456:ABC-DEF…", text: $botToken, secure: true)
                            telegramField("Chat ID", placeholder: "-1001234567890", text: $chatID, secure: false)

                            if let status = footerStatus {
                                Text(status)
                                    .font(.geistMono(.regular, size: 11))
                                    .foregroundStyle(testStatus == .ok ? theme.mint : theme.red)
                            }

                            Button(action: sendTest) {
                                Text(testStatus.label)
                                    .font(.geist(.semibold, size: 13))
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(theme.mint)
                                    .foregroundStyle(theme.mintInk)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                            .buttonStyle(.plain)
                            .disabled(testStatus == .sending || !looksValid)

                            Button(action: clear) {
                                Text("Очистить")
                                    .font(.geist(.semibold, size: 13))
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 10)
                                    .background(theme.chip)
                                    .foregroundStyle(theme.red)
                                    .clipShape(RoundedRectangle(cornerRadius: 10))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.horizontal, 16)
                    .padding(.top, 12)

                    Button(action: save) {
                        Text("Сохранить")
                            .font(.geist(.semibold, size: 13))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .background(looksValid ? theme.mint : theme.chip)
                            .foregroundStyle(looksValid ? theme.mintInk : theme.textMuted)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    .buttonStyle(.plain)
                    .disabled(!looksValid)
                    .padding(.horizontal, 16)
                    .padding(.top, 8)

                    Color.clear.frame(height: 24)
                }
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .navigationTitle("Telegram")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func telegramField(_ label: String, placeholder: String, text: Binding<String>, secure: Bool) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.geist(.medium, size: 12))
                .foregroundStyle(theme.textMuted)
            Group {
                if secure {
                    SecureField(placeholder, text: text)
                } else {
                    TextField(placeholder, text: text)
                }
            }
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

    private var looksValid: Bool {
        let t = botToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let c = chatID.trimmingCharacters(in: .whitespacesAndNewlines)
        // Telegram tokens look like "<digits>:<35-ish chars>".
        let tokenOK = t.contains(":") && t.count >= 30
        let chatOK  = !c.isEmpty
        return tokenOK && chatOK
    }

    private var footerStatus: String? {
        if case .failed(let msg) = testStatus { return msg }
        if case .ok = testStatus { return "Отправлено." }
        return nil
    }

    private func sendTest() {
        // Persist before testing so TelegramReporter picks them up.
        TelegramReporter.botToken = botToken
        TelegramReporter.chatID   = chatID
        testStatus = .sending
        let caption = TelegramReporter.defaultCaption(extra: "test message")
        TelegramReporter.sendLog(text: "Tamizdat Telegram test \(Date())\n",
                                 caption: caption) { result in
            switch result {
            case .success:
                testStatus = .ok
            case .failure(let err):
                testStatus = .failed(err.errorDescription ?? "?")
            }
        }
    }

    private func clear() {
        TelegramReporter.botToken = ""
        TelegramReporter.chatID = ""
        botToken = ""
        chatID = ""
        testStatus = .idle
    }

    private func save() {
        TelegramReporter.botToken = botToken
        TelegramReporter.chatID   = chatID
        dismiss()
    }
}
