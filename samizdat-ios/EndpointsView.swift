import SwiftUI
import UIKit
import CoreImage

/// IPA-D22: Endpoints management screen. Replaces the legacy
/// `ConfigPasteView` 2-TextEditor sheet.
///
/// Card 1: the ACTIVE H2 profile (mint accent). Below it, the saved
/// profiles section (blue accent) — add H2 profiles, activate one to
/// swap it into the active slot (live-applied), delete with inline
/// confirmation.
/// Each renders the URL as a parsed code-block and offers
/// Paste / Scan (QR camera) / Clear chip actions. Clear opens an
/// inline confirmation strip (no native alert) so the surrounding
/// context stays visible.
///
/// Persistence: still goes through `ConfigStore` (Keychain) +
/// `SamizdatURLCodec.compose / split` so the Network Extension reads
/// the same blob shape it already understands.
struct EndpointsView: View {
    @Environment(\.themeTokens) private var theme

    /// Called after every persist with `true` if a profile is stored.
    /// Parent (SettingsView) refreshes its derived config state.
    var onClose: (Bool) -> Void

    @State private var primaryURL: String
    @State private var profiles: [String] = []
    @State private var scanning: ScanTarget? = nil
    @State private var pasteError: String?

    // Inline edit state for the new-profile row: `addingProfile` /
    // `editBufferNewProfile` drive the saved-profiles section;
    // `deletingProfile` drives the inline delete confirmation.
    @State private var addingProfile: Bool = false
    @State private var editBufferNewProfile: String = ""
    @State private var deletingProfile: String? = nil

    // Inline edit of an EXISTING saved profile: `editingProfile` holds the
    // original URL, `editBufferProfile` the draft.
    @State private var editingProfile: String? = nil
    @State private var editBufferProfile: String = ""

    /// Profile URL shown in the QR / share sheet.
    @State private var sharingProfile: SharingProfile? = nil

    private struct SharingProfile: Identifiable {
        let url: String
        var id: String { url }
    }

    private enum ScanTarget: Identifiable {
        case newProfile
        var id: String { "new-profile" }
    }

    init(onClose: @escaping (Bool) -> Void) {
        self.onClose = onClose
        let stored = ConfigStore.shared.load() ?? ""
        let split = SamizdatURLCodec.split(stored)
        // Migration: the legacy "Whitelist" URI (H2 whitelist mode is gone)
        // becomes a saved profile instead of the obsolete backup slot.
        if let legacy = split.backup, !legacy.isEmpty {
            ProfileStore.add(legacy)
        }
        // The active profile lives IN the list (marked inline) — no separate
        // Active card. Seed it into the list if it's not there yet.
        let primary = split.primary
        if !primary.isEmpty {
            ProfileStore.add(primary)
        }
        _primaryURL = State(initialValue: primary)
        _profiles = State(initialValue: ProfileStore.all())
    }

    var body: some View {
        ZStack {
            ThemeBackground(theme: theme)

            ScrollView {
                VStack(spacing: 12) {
                    profilesSection

                    if let err = pasteError {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(theme.red)
                            Text(err)
                                .font(.geist(.medium, size: 13))
                                .foregroundStyle(theme.text)
                            Spacer()
                        }
                        .padding(12)
                        .background(theme.redDim)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 12)
                .padding(.bottom, 24)
            }
        }
        .preferredColorScheme(theme.isDark ? .dark : .light)
        .navigationTitle("Профиль")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $scanning) { target in
            QRScannerSheet { code in
                addProfile(from: code)
            }
            .environment(\.themeTokens, theme)
        }
        .sheet(item: $sharingProfile) { profile in
            ProfileQRSheet(url: profile.url)
                .environment(\.themeTokens, theme)
        }
    }

    // MARK: – Actions

    private func pasteNewProfile() {
        guard let pasted = UIPasteboard.general.string?
            .trimmingCharacters(in: .whitespacesAndNewlines), !pasted.isEmpty else { return }
        addProfile(from: pasted)
    }

    /// Validates and appends a URL to the saved profiles.
    private func addProfile(from s: String) {
        if let err = SamizdatBridge.validate(s) {
            pasteError = "Ошибка: \(err)"
            return
        }
        ProfileStore.add(s)
        profiles = ProfileStore.all()
        pasteError = nil
    }


    /// Commit the inline-entered new profile.
    private func saveNewProfile() {
        let s = editBufferNewProfile.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else {
            addingProfile = false
            return
        }
        if let err = SamizdatBridge.validate(s) {
            pasteError = "Ошибка: \(err)"
            return
        }
        ProfileStore.add(s)
        profiles = ProfileStore.all()
        addingProfile = false
        editBufferNewProfile = ""
        pasteError = nil
    }

    /// Marks a saved profile as the active one (it stays in the list, shown
    /// with the active accent). Live-applied into the running tunnel by
    /// persistImmediately's setConfigBlob push.
    private func activateProfile(_ url: String) {
        primaryURL = url
        pasteError = nil
        persistImmediately()
    }

    private func deleteProfile(_ url: String) {
        ProfileStore.remove(url)
        if primaryURL == url {
            // The deleted profile was active — clear the active selection.
            primaryURL = ""
            persistImmediately()
        }
        profiles = ProfileStore.all()
        deletingProfile = nil
    }


    /// IPA-D22: design says "changes apply immediately" (no Save
    /// button). The ACTIVE profile is written to Keychain on every
    /// successful change; saved profiles live in ProfileStore.
    private func persistImmediately() {
        let p = primaryURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if p.isEmpty {
            ConfigStore.shared.delete()
            VKSPreferences.applyDerivedH2PeerConfig(nil)
            onClose(false)
            return
        }
        let combined = SamizdatURLCodec.compose(primary: p, backup: nil)
        ConfigStore.shared.save(combined)
        VKSPreferences.applyDerivedH2PeerConfig(SamizdatURLCodec.h2PeerConfig(from: combined))
        // Live-apply into the running tunnel (no-op while disconnected —
        // the next connect reads ConfigStore anyway). The derived VKS
        // identity mirror is already in the App Group, so the extension's
        // rewire picks it up.
        Task { await VPNProfileStore.shared.applyActiveConfigBlob(combined) }
        onClose(true)
    }

    // MARK: – Profiles section

    private var profilesSection: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("ПРОФИЛИ")
                        .font(.geist(.bold, size: 10.5))
                        .tracking(0.84)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(theme.blueDim))
                        .foregroundStyle(theme.blue)
                    Spacer()
                    Text("Профилей: \(profiles.count)")
                        .font(.geistMono(.regular, size: 12))
                        .foregroundStyle(theme.textMuted)
                }

                if addingProfile {
                    TextEditor(text: $editBufferNewProfile)
                        .font(.geistMono(.regular, size: 12))
                        .foregroundStyle(theme.text)
                        .scrollContentBackground(.hidden)
                        .frame(minHeight: 88, maxHeight: 160)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                        .background(theme.chip)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                    HStack(spacing: 6) {
                        ActionChip(systemName: "xmark",
                                   label: "Отмена",
                                   tint: theme.textDim) {
                            addingProfile = false
                            editBufferNewProfile = ""
                        }
                        ActionChip(systemName: "checkmark",
                                   label: "Добавить",
                                   tint: theme.mint,
                                   labelColor: theme.mint,
                                   action: saveNewProfile)
                    }
                } else {
                    HStack(spacing: 6) {
                        ActionChip(systemName: "doc.on.clipboard",
                                   label: "Вставить",
                                   tint: theme.blue,
                                   action: pasteNewProfile)
                        ActionChip(systemName: "qrcode.viewfinder",
                                   label: "QR",
                                   tint: theme.blue) {
                            scanning = .newProfile
                        }
                        ActionChip(systemName: "pencil",
                                   label: "Ввод",
                                   tint: theme.blue) {
                            editBufferNewProfile = ""
                            addingProfile = true
                        }
                    }
                }

                if profiles.isEmpty {
                    CodeBlock {
                        Text("Нет профилей.")
                            .foregroundStyle(theme.textMuted)
                    }
                } else {
                    ForEach(profiles, id: \.self) { url in
                        profileRow(url)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func profileRow(_ url: String) -> some View {
        let isActive = url == primaryURL
        if editingProfile == url {
            VStack(alignment: .leading, spacing: 8) {
                TextEditor(text: $editBufferProfile)
                    .font(.geistMono(.regular, size: 12))
                    .foregroundStyle(theme.text)
                    .scrollContentBackground(.hidden)
                    .frame(minHeight: 88, maxHeight: 160)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(theme.chip)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .keyboardType(.URL)
                HStack(spacing: 6) {
                    ActionChip(systemName: "xmark",
                               label: "Отмена",
                               tint: theme.textDim) {
                        editingProfile = nil
                        editBufferProfile = ""
                    }
                    ActionChip(systemName: "checkmark",
                               label: "Сохранить",
                               tint: theme.mint,
                               labelColor: theme.mint) {
                        saveEditedProfile(original: url)
                    }
                }
            }
            .padding(10)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        } else {
            HStack(spacing: 8) {
                Button {
                    guard !isActive else { return }
                    activateProfile(url)
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: isActive ? "checkmark.circle.fill" : "doc.text")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(isActive ? theme.mint : theme.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(endpointHost(url) ?? "tamizdat://")
                                .font(.geist(.medium, size: 13))
                                .foregroundStyle(theme.text)
                            Text(url)
                                .font(.geistMono(.regular, size: 10))
                                .foregroundStyle(theme.textDim)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                Spacer(minLength: 8)
                if deletingProfile == url {
                    Button {
                        deletingProfile = nil
                    } label: {
                        Text("Отмена")
                            .font(.geist(.semibold, size: 12))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Capsule().fill(theme.chip))
                            .foregroundStyle(theme.text)
                    }
                    .buttonStyle(.plain)
                    Button {
                        deleteProfile(url)
                    } label: {
                        Text("Удалить")
                            .font(.geist(.bold, size: 12))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Capsule().fill(theme.red))
                            .foregroundStyle(Color.white)
                    }
                    .buttonStyle(.plain)
                } else {
                    if isActive {
                        Text("Активен")
                            .font(.geist(.bold, size: 12))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Capsule().fill(theme.mintDim))
                            .foregroundStyle(theme.mint)
                    } else {
                        Button {
                            activateProfile(url)
                        } label: {
                            Text("Выбрать")
                                .font(.geist(.semibold, size: 12))
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(Capsule().fill(theme.mintDim))
                                .foregroundStyle(theme.mint)
                        }
                        .buttonStyle(.plain)
                    }
                    Menu {
                        Button {
                            beginEditing(url)
                        } label: {
                            Label("Изменить", systemImage: "pencil")
                        }
                        Button {
                            sharingProfile = SharingProfile(url: url)
                        } label: {
                            Label("QR", systemImage: "qrcode")
                        }
                        Button(role: .destructive) {
                            deletingProfile = url
                        } label: {
                            Label("Удалить", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .font(.system(size: 17, weight: .semibold))
                            .foregroundStyle(theme.textDim)
                            .frame(minWidth: 44, minHeight: 44)
                            .contentShape(Rectangle())
                    }
                }
            }
            .padding(10)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
    }

    private func beginEditing(_ url: String) {
        deletingProfile = nil
        editBufferProfile = url
        editingProfile = url
    }

    /// Validates and persists an inline edit of a saved profile. Keeps the
    /// row's position; if this profile is the active one, re-applies it to
    /// the running tunnel.
    private func saveEditedProfile(original: String) {
        let value = editBufferProfile.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty else { return }
        if let err = SamizdatBridge.validate(value) {
            pasteError = "Ошибка: \(err)"
            return
        }
        pasteError = nil
        if value != original {
            ProfileStore.replace(original, with: value)
            if primaryURL == original {
                primaryURL = value
                persistImmediately()
            }
        }
        profiles = ProfileStore.all()
        editingProfile = nil
        editBufferProfile = ""
    }

    /// Called by SettingsView when it needs a hasConfig refresh after
    /// this pushed page's edits. The parent refreshes on pop anyway
    /// (onConfigChanged is invoked on every persistImmediately), so the
    /// page itself no longer owns a Done button.
}

/// Best-effort host:port parse for a tamizdat:// URL. Shared by the
/// endpoint card and the saved-profiles rows.
private func endpointHost(_ s: String) -> String? {
    guard !s.isEmpty else { return nil }
    // Replace scheme so URLComponents can parse — `tamizdat://` is
    // unknown to URLComponents and may produce nil host on iOS 17.
    let probe = s
        .replacingOccurrences(of: "tamizdat://", with: "https://")
        .replacingOccurrences(of: "samizdat://", with: "https://")
    guard let u = URL(string: probe), let host = u.host else { return nil }
    if let port = u.port { return "\(host):\(port)" }
    return host
}

/// QR / share sheet for a saved profile link.
///
/// The QR carries the full tamizdat:// URL, secrets included — that is the
/// point of the screen (hand the profile to another device). The link is
/// never logged.
private struct ProfileQRSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    let url: String
    @State private var qrImage: UIImage?

    init(url: String) {
        self.url = url
        _qrImage = State(initialValue: QRCodeRenderer.image(for: url))
    }

    var body: some View {
        NavigationStack {
            ZStack {
                ThemeBackground(theme: theme)

                ScrollView {
                    VStack(spacing: 20) {
                        if let qrImage {
                            Image(uiImage: qrImage)
                                .interpolation(.none)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: 280, maxHeight: 280)
                                .padding(14)
                                .background(Color.white)
                                .clipShape(RoundedRectangle(cornerRadius: 16))
                        }

                        ShareLink(item: url) {
                            HStack(spacing: 8) {
                                Image(systemName: "square.and.arrow.up")
                                    .font(.system(size: 14, weight: .semibold))
                                Text("Поделиться")
                                    .font(.geist(.semibold, size: 15))
                            }
                            .frame(maxWidth: .infinity)
                            .frame(minHeight: 46)
                            .background(theme.mint)
                            .foregroundStyle(theme.mintInk)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 24)
                    .padding(.top, 16)
                    .padding(.bottom, 24)
                }
            }
            .preferredColorScheme(theme.isDark ? .dark : .light)
            .navigationTitle("Поделиться")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Chip(label: "Готово") { dismiss() }
                }
            }
        }
    }
}

private enum QRCodeRenderer {
    /// CoreImage QR code scaled with nearest-neighbour-friendly integer
    /// scaling. The white padding around the image in `ProfileQRSheet`
    /// supplies the quiet zone (CIQRCodeGenerator does not guarantee one).
    static func image(for text: String, scale: CGFloat = 12) -> UIImage? {
        guard !text.isEmpty,
              let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let context = CIContext(options: nil)
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else {
            return nil
        }
        return UIImage(cgImage: cgImage)
    }
}

private struct ActionChip: View {
    @Environment(\.themeTokens) private var theme
    let systemName: String
    let label: String
    let tint: Color
    var labelColor: Color? = nil
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                Image(systemName: systemName)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(tint)
                Text(label)
                    .font(.geist(.semibold, size: 13))
                    .foregroundStyle(labelColor ?? theme.text)
            }
            .frame(maxWidth: .infinity)
            .frame(minHeight: 38)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}

