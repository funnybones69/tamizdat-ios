import Foundation

/// Foundation-only VK Calls credential path shared by the app and the packet
/// tunnel extension. The extension uses this accountless flow as a bootstrap
/// escape hatch when a TURN quota storm makes the fail-closed tunnel unable to
/// carry the main app's own credential refresh requests.
///
/// There is deliberately no CAPTCHA/WebKit fallback here. If the accountless
/// endpoints reject a request, the main-app `VKCredsClient` remains responsible
/// for the user-visible fallback while the extension retries this bounded path.
struct TURNAnonymousCredsFetcher {
    enum FetchError: Error, LocalizedError {
        case invalidRoom
        case timedOut
        case transport(step: String, underlying: Error)
        case httpStatus(step: String, status: Int)
        case malformed(step: String, reason: String)

        var errorDescription: String? {
            switch self {
            case .invalidRoom:
                return "anonymous TURN room is empty"
            case .timedOut:
                return "anonymous TURN refresh timed out"
            case let .transport(step, underlying):
                return "anonymous TURN transport failed at \(step): \(underlying.localizedDescription)"
            case let .httpStatus(step, status):
                return "anonymous TURN HTTP \(status) at \(step)"
            case let .malformed(step, reason):
                return "anonymous TURN malformed response at \(step): \(reason)"
            }
        }
    }

    static let defaultUserAgent =
        "Mozilla/5.0 (Linux; Android 13; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) " +
        "Chrome/120.0.0.0 Mobile Safari/537.36"

    private let session: URLSession
    private let userAgent: String

    init(session: URLSession, userAgent: String = Self.defaultUserAgent) {
        self.session = session
        self.userAgent = userAgent
    }

    /// Fetch a complete room bundle under one wall-clock watchdog. Rooms stay
    /// sequential to avoid turning one recovery into a 15-request burst.
    static func fetchRooms(
        _ roomHashes: [String],
        perRequestTimeout: TimeInterval = 5,
        overallTimeout: TimeInterval = 15
    ) async throws -> [VKTURNRoomCredentials] {
        guard !roomHashes.isEmpty else { throw FetchError.invalidRoom }

        return try await withThrowingTaskGroup(of: [VKTURNRoomCredentials].self) { group in
            group.addTask {
                let configuration = URLSessionConfiguration.ephemeral
                configuration.timeoutIntervalForRequest = perRequestTimeout
                configuration.timeoutIntervalForResource = perRequestTimeout
                configuration.urlCache = nil
                configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
                configuration.httpMaximumConnectionsPerHost = 1
                let session = URLSession(configuration: configuration)
                defer { session.invalidateAndCancel() }

                let fetcher = TURNAnonymousCredsFetcher(session: session)
                var rooms: [VKTURNRoomCredentials] = []
                rooms.reserveCapacity(roomHashes.count)
                for hash in roomHashes {
                    try Task.checkCancellation()
                    let credentials = try await fetcher.fetch(roomHash: hash)
                    rooms.append(VKTURNRoomCredentials(roomHash: hash, credentials: credentials))
                }
                return rooms
            }
            group.addTask {
                let nanoseconds = UInt64(max(1, overallTimeout) * 1_000_000_000)
                try await Task.sleep(nanoseconds: nanoseconds)
                throw FetchError.timedOut
            }

            guard let first = try await group.next() else {
                throw FetchError.malformed(step: "bundle", reason: "no result")
            }
            group.cancelAll()
            return first
        }
    }

    func fetch(roomHash rawHash: String) async throws -> VKTURNCredentials {
        let hash = Self.normalizeCallHash(rawHash)
        guard !hash.isEmpty else { throw FetchError.invalidRoom }

        let deviceID = UUID().uuidString.lowercased()
        let joinURL = "https://vk.com/call/join/\(hash)"
        let names = ["Alex", "Anna", "Ivan", "Maria", "Maxim", "Olga", "Pavel", "Sergey"]
        let nameIndex = deviceID.unicodeScalars.reduce(0) { partial, scalar in
            partial + Int(scalar.value)
        } % names.count
        let guestName = names[nameIndex]
        let api = "https://api.vk.me"
        let version = "5.276"
        let clientID = "8093730"

        let step1 = try await postJSON(
            "v=\(version)&client_id=\(clientID)&link=\(Self.urlEncoded(joinURL))&device_id=\(deviceID)&anonymName=\(Self.urlEncoded(guestName))&lang=en",
            to: "\(api)/method/auth.getAnonymToken",
            step: "anonymous.1"
        )
        try Self.assertResponseOK(step1, step: "anonymous.1")
        let anonymousToken = try Self.requireString(step1, path: ["response", "token"], step: "anonymous.1")

        let step2 = try await postJSON(
            "v=\(version)&anonymous_token=\(Self.urlEncoded(anonymousToken))&device_id=\(deviceID)&extended=1&fields=first_name%2Clast_name%2Cphoto_200&lang=en&link=\(Self.urlEncoded(joinURL))",
            to: "\(api)/method/messages.getCallPreview",
            step: "anonymous.2"
        )
        try Self.assertResponseOK(step2, step: "anonymous.2")
        let userID = try Self.requireNumberString(step2, path: ["response", "user_id"], step: "anonymous.2")
        let secret = try Self.requireString(step2, path: ["response", "secret"], step: "anonymous.2")

        let step3 = try await postJSON(
            "v=\(version)&anonymous_token=\(Self.urlEncoded(anonymousToken))&device_id=\(deviceID)&link=\(Self.urlEncoded(joinURL))&name=\(Self.urlEncoded(guestName))&user_id=\(Self.urlEncoded(userID))&secret=\(Self.urlEncoded(secret))&lang=en",
            to: "\(api)/method/messages.getAnonymCallToken",
            step: "anonymous.3"
        )
        try Self.assertResponseOK(step3, step: "anonymous.3")
        let callToken = try Self.requireString(step3, path: ["response", "token"], step: "anonymous.3")

        let okDeviceID = UUID().uuidString.lowercased()
        let sessionData = "{\"version\":2,\"device_id\":\"\(okDeviceID)\",\"client_version\":\"1.0.1\"}"
        let step4 = try await postJSON(
            "session_data=\(Self.urlEncoded(sessionData))&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
            to: "https://calls.okcdn.ru/fb.do",
            step: "anonymous.4"
        )
        try Self.assertResponseOK(step4, step: "anonymous.4")
        let sessionKey = try Self.requireString(step4, path: ["session_key"], step: "anonymous.4")

        let step5 = try await postJSON(
            "joinLink=\(Self.urlEncoded(hash))&isVideo=false&protocolVersion=5&anonymToken=\(Self.urlEncoded(callToken))&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key=\(Self.urlEncoded(sessionKey))",
            to: "https://calls.okcdn.ru/fb.do",
            step: "anonymous.5"
        )
        try Self.assertResponseOK(step5, step: "anonymous.5")
        guard let turnBlock = step5["turn_server"] as? [String: Any] else {
            throw FetchError.malformed(step: "anonymous.5", reason: "TURN block missing")
        }
        return try Self.parseTurnBlock(turnBlock)
    }

    private func postJSON(_ formBody: String, to urlString: String, step: String) async throws -> [String: Any] {
        guard let url = URL(string: urlString) else {
            throw FetchError.malformed(step: step, reason: "bad endpoint URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = formBody.data(using: .utf8)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("\"Android\"", forHTTPHeaderField: "sec-ch-ua-platform")
        request.setValue("\"Not(A:Brand\";v=\"99\", \"Android WebView\";v=\"133\", \"Chromium\";v=\"133\"", forHTTPHeaderField: "sec-ch-ua")
        request.setValue("?1", forHTTPHeaderField: "sec-ch-ua-mobile")
        request.setValue("cross-site", forHTTPHeaderField: "Sec-Fetch-Site")
        request.setValue("cors", forHTTPHeaderField: "Sec-Fetch-Mode")
        request.setValue("empty", forHTTPHeaderField: "Sec-Fetch-Dest")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("https://login.vk.ru", forHTTPHeaderField: "Origin")
        request.setValue("https://login.vk.ru/", forHTTPHeaderField: "Referer")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw FetchError.transport(step: step, underlying: error)
        }
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw FetchError.httpStatus(step: step, status: http.statusCode)
        }
        guard data.count <= 1_048_576 else {
            throw FetchError.malformed(step: step, reason: "response too large")
        }
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw FetchError.malformed(step: step, reason: "JSON root is not an object")
            }
            return object
        } catch let error as FetchError {
            throw error
        } catch {
            throw FetchError.malformed(step: step, reason: "invalid JSON")
        }
    }

    private static func assertResponseOK(_ payload: [String: Any], step: String) throws {
        if let code = payload["error_code"] as? NSNumber, code.intValue != 0 {
            throw FetchError.malformed(step: step, reason: "VK error \(code.intValue)")
        }
        guard let error = payload["error"] as? [String: Any] else { return }
        let code = (error["error_code"] as? NSNumber)?.intValue ?? -1
        throw FetchError.malformed(step: step, reason: "VK error \(code)")
    }

    private static func requireString(_ payload: [String: Any], path: [String], step: String) throws -> String {
        var current: Any = payload
        for key in path {
            guard let object = current as? [String: Any], let next = object[key] else {
                throw FetchError.malformed(step: step, reason: "missing field")
            }
            current = next
        }
        guard let value = current as? String, !value.isEmpty else {
            throw FetchError.malformed(step: step, reason: "invalid string field")
        }
        return value
    }

    private static func requireNumberString(_ payload: [String: Any], path: [String], step: String) throws -> String {
        var current: Any = payload
        for key in path {
            guard let object = current as? [String: Any], let next = object[key] else {
                throw FetchError.malformed(step: step, reason: "missing numeric field")
            }
            current = next
        }
        if let value = current as? String, !value.isEmpty { return value }
        if let value = current as? NSNumber { return value.stringValue }
        throw FetchError.malformed(step: step, reason: "invalid numeric field")
    }

    private static func parseTurnBlock(_ block: [String: Any]) throws -> VKTURNCredentials {
        guard let username = block["username"] as? String, !username.isEmpty,
              let password = block["credential"] as? String, !password.isEmpty else {
            throw FetchError.malformed(step: "anonymous.5", reason: "missing TURN authentication")
        }
        let rawURLs = block["urls"] as? [String] ?? []
        let servers: [TurnServer] = rawURLs.compactMap { raw in
            var value = raw
            var scheme = "turn"
            if value.hasPrefix("turns:") {
                scheme = "turns"
                value.removeFirst("turns:".count)
            } else if value.hasPrefix("turn:") {
                value.removeFirst("turn:".count)
            }
            let hostPort: String
            let query: String?
            if let separator = value.firstIndex(of: "?") {
                hostPort = String(value[..<separator])
                query = String(value[value.index(after: separator)...])
            } else {
                hostPort = value
                query = nil
            }
            guard let separator = hostPort.lastIndex(of: ":"),
                  let port = Int(hostPort[hostPort.index(after: separator)...]),
                  port > 0, port <= 65_535 else { return nil }
            var host = String(hostPort[..<separator])
            if host.hasPrefix("[") && host.hasSuffix("]") {
                host.removeFirst()
                host.removeLast()
            }
            guard !host.isEmpty else { return nil }

            var transport = scheme == "turns" ? "tcp" : "udp"
            if let query {
                for component in query.split(separator: "&") {
                    let pair = component.split(separator: "=", maxSplits: 1).map(String.init)
                    if pair.count == 2, pair[0].lowercased() == "transport" {
                        let candidate = pair[1].lowercased()
                        if candidate == "tcp" || candidate == "udp" { transport = candidate }
                    }
                }
            }
            return TurnServer(host: host, port: port, scheme: scheme, transport: transport)
        }
        guard !servers.isEmpty else {
            throw FetchError.malformed(step: "anonymous.5", reason: "no TURN servers")
        }

        let lifetime: TimeInterval
        if let value = block["lifetime"] as? NSNumber, value.doubleValue > 0 {
            lifetime = value.doubleValue
        } else if let value = block["ttl"] as? NSNumber, value.doubleValue > 0 {
            lifetime = value.doubleValue
        } else {
            lifetime = 3_600
        }
        return VKTURNCredentials(
            username: username,
            password: password,
            turnServers: servers,
            lifetime: lifetime,
            acquiredAt: Date()
        )
    }

    private static func normalizeCallHash(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: value), url.host != nil {
            value = url.path.split(separator: "/").last.map(String.init) ?? value
        }
        if let slash = value.lastIndex(of: "/") {
            value = String(value[value.index(after: slash)...])
        }
        if let cut = value.firstIndex(where: { $0 == "?" || $0 == "#" }) {
            value = String(value[..<cut])
        }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func urlEncoded(_ value: String) -> String {
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "+&=")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}
