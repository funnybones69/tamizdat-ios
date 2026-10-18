import SwiftUI
import WebKit

/// In-app login for a VKS provider whose server-side session died.
///
/// The user signs in inside a throwaway (non-persistent) web view; once the
/// session cookies appear they are sent to the server through the tunnel and
/// the web view's storage is dropped with the sheet. Cookies are never logged
/// or kept on the phone.
struct ProviderLoginSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.themeTokens) private var theme

    let provider: String
    /// Called after the server accepted the new session.
    var onSuccess: () -> Void = {}

    @State private var phase: Phase = .browsing
    @State private var uploadStarted = false

    enum Phase: Equatable {
        case browsing
        case uploading
        case failed(String)
    }

    var body: some View {
        NavigationStack {
            ZStack(alignment: .bottom) {
                LoginWebView(
                    startURL: ProviderLogin.startURL(for: provider),
                    isSessionReady: { ProviderLogin.isSessionReady($0, provider: provider) },
                    onSession: { cookies in handleSession(cookies) }
                )
                .ignoresSafeArea(edges: .bottom)

                if phase != .browsing {
                    statusBanner
                        .padding(16)
                }
            }
            .preferredColorScheme(theme.isDark ? .dark : .light)
            .navigationTitle("Вход в \(VKSPreferences.providerDisplayName(provider))")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Chip(label: "Отмена") { dismiss() }
                }
            }
        }
    }

    @ViewBuilder
    private var statusBanner: some View {
        HStack(spacing: 10) {
            switch phase {
            case .uploading:
                ProgressView()
                Text("Отправляю на сервер…")
                    .font(.geist(.medium, size: 14))
                    .foregroundStyle(theme.text)
            case .failed(let message):
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(theme.red)
                Text(message)
                    .font(.geist(.medium, size: 14))
                    .foregroundStyle(theme.text)
                Spacer(minLength: 8)
                Chip(label: "Ещё раз") {
                    uploadStarted = false
                    phase = .browsing
                }
            case .browsing:
                EmptyView()
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(theme.cardSolid)
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private func handleSession(_ cookies: [HTTPCookie]) {
        guard !uploadStarted else { return }
        uploadStarted = true
        phase = .uploading
        let header = ProviderLogin.cookieHeader(cookies, provider: provider)
        Task {
            let error = await VPNProfileStore.shared.uploadVKSCredentials(
                provider: provider, cookieHeader: header)
            if let error {
                phase = .failed("Сервер не принял вход: \(error)")
            } else {
                onSuccess()
                dismiss()
            }
        }
    }
}

/// Per-provider login rules: where to start, which cookies form the session,
/// and how to tell that the user finished signing in.
enum ProviderLogin {
    static func startURL(for provider: String) -> URL {
        switch provider {
        case "mts":
            return URL(string: "https://my.mts-link.ru/")!
        default:
            return URL(string: "https://passport.yandex.ru/auth?retpath=https%3A%2F%2Ftelemost.yandex.ru%2F")!
        }
    }

    private static func domainSuffix(for provider: String) -> String {
        provider == "mts" ? "mts-link.ru" : "yandex.ru"
    }

    private static func belongs(_ cookie: HTTPCookie, provider: String) -> Bool {
        let domain = cookie.domain.hasPrefix(".") ? String(cookie.domain.dropFirst()) : cookie.domain
        let suffix = domainSuffix(for: provider)
        return domain == suffix || domain.hasSuffix("." + suffix)
    }

    /// Telemost: a logged-in Session_id carries the uid after "|".
    /// MTS: the refresh cookie appears only after a completed login.
    static func isSessionReady(_ cookies: [HTTPCookie], provider: String) -> Bool {
        let own = cookies.filter { belongs($0, provider: provider) }
        switch provider {
        case "mts":
            return own.contains { $0.name == "refresh" && !$0.value.isEmpty }
        default:
            return own.contains { $0.name == "Session_id" && $0.value.contains("|") }
        }
    }

    /// `name=value; name=value` over the provider's cookies, de-duplicated
    /// by name (the most specific domain wins).
    static func cookieHeader(_ cookies: [HTTPCookie], provider: String) -> String {
        var byName: [String: HTTPCookie] = [:]
        for cookie in cookies where belongs(cookie, provider: provider) {
            if let existing = byName[cookie.name], existing.domain.count >= cookie.domain.count {
                continue
            }
            byName[cookie.name] = cookie
        }
        return byName.values
            .sorted { $0.name < $1.name }
            .map { "\($0.name)=\($0.value)" }
            .joined(separator: "; ")
    }
}

/// WKWebView on a non-persistent data store: nothing survives the sheet.
private struct LoginWebView: UIViewRepresentable {
    let startURL: URL
    let isSessionReady: ([HTTPCookie]) -> Bool
    let onSession: ([HTTPCookie]) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(isSessionReady: isSessionReady, onSession: onSession)
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        context.coordinator.attach(webView)
        webView.load(URLRequest(url: startURL))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        coordinator.detach()
        webView.stopLoading()
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        private let isSessionReady: ([HTTPCookie]) -> Bool
        private let onSession: ([HTTPCookie]) -> Void
        private weak var webView: WKWebView?
        private var timer: Timer?
        private var delivered = false

        init(isSessionReady: @escaping ([HTTPCookie]) -> Bool,
             onSession: @escaping ([HTTPCookie]) -> Void) {
            self.isSessionReady = isSessionReady
            self.onSession = onSession
        }

        func attach(_ webView: WKWebView) {
            self.webView = webView
            // Some logins finish via XHR without a navigation; poll as well.
            timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
                self?.checkCookies()
            }
        }

        func detach() {
            timer?.invalidate()
            timer = nil
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            checkCookies()
        }

        private func checkCookies() {
            guard !delivered, let store = webView?.configuration.websiteDataStore.httpCookieStore else { return }
            store.getAllCookies { [weak self] cookies in
                guard let self, !self.delivered, self.isSessionReady(cookies) else { return }
                self.delivered = true
                self.detach()
                DispatchQueue.main.async { self.onSession(cookies) }
            }
        }
    }
}
