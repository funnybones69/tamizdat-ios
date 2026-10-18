import SwiftUI

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
            pasteError = "Profile: \(err)"
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
            pasteError = "Profile: \(err)"
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
    }

    // MARK: – Profiles section

    private var profilesSection: some View {
        CardContainer(padding: 16) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("PROFILES")
                        .font(.geist(.bold, size: 10.5))
                        .tracking(0.84)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(theme.blueDim))
                        .foregroundStyle(theme.blue)
                    Spacer()
                    Text("\(profiles.count) saved")
                        .font(.geistMono(.regular, size: 12))
                        .foregroundStyle(theme.textMuted)
                }

                Text("Сохранённые H2-профили. Activate делает профиль активным — он сразу начинает использоваться (текущий останется в списке).")
                    .font(.geistMono(.regular, size: 10))
                    .foregroundStyle(theme.textDim)

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
                                   label: "Cancel",
                                   tint: theme.textDim) {
                            addingProfile = false
                            editBufferNewProfile = ""
                        }
                        ActionChip(systemName: "checkmark",
                                   label: "Add",
                                   tint: theme.mint,
                                   labelColor: theme.mint,
                                   action: saveNewProfile)
                    }
                } else {
                    HStack(spacing: 6) {
                        ActionChip(systemName: "doc.on.clipboard",
                                   label: "Paste",
                                   tint: theme.blue,
                                   action: pasteNewProfile)
                        ActionChip(systemName: "qrcode.viewfinder",
                                   label: "Scan",
                                   tint: theme.blue) {
                            scanning = .newProfile
                        }
                        ActionChip(systemName: "pencil",
                                   label: "Enter",
                                   tint: theme.blue) {
                            editBufferNewProfile = ""
                            addingProfile = true
                        }
                    }
                }

                if profiles.isEmpty {
                    CodeBlock {
                        Text("No saved profiles yet — paste, scan or enter a tamizdat:// link to add one.")
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

    private func profileRow(_ url: String) -> some View {
        let isActive = url == primaryURL
        return HStack(spacing: 8) {
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
            Spacer()
            if deletingProfile == url {
                Button {
                    deletingProfile = nil
                } label: {
                    Text("Cancel")
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
                    Text("Delete")
                        .font(.geist(.bold, size: 12))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Capsule().fill(theme.red))
                        .foregroundStyle(Color.white)
                }
                .buttonStyle(.plain)
            } else {
                if isActive {
                    Text("Active")
                        .font(.geist(.bold, size: 12))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Capsule().fill(theme.mintDim))
                        .foregroundStyle(theme.mint)
                } else {
                    Button {
                        activateProfile(url)
                    } label: {
                        Text("Activate")
                            .font(.geist(.semibold, size: 12))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(Capsule().fill(theme.mintDim))
                            .foregroundStyle(theme.mint)
                    }
                    .buttonStyle(.plain)
                }
                Button {
                    deletingProfile = url
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(theme.red)
                        .padding(6)
                        .background(Circle().fill(theme.redDim))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(10)
        .background(theme.chip)
        .clipShape(RoundedRectangle(cornerRadius: 12))
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
            .frame(height: 38)
            .background(theme.chip)
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}

