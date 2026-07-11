import Foundation
import Network
import SamizdatClient

struct WhitelistProbePathSelection {
    let interfaceIndex: UInt32?
    let summary: String
}

struct WhitelistProbeCycleConfig: Encodable {
    let foreign: [String]
    let domestic: [String]
    let timeoutMs: Int
    let port: Int
    let interfaceIndex: Int

    enum CodingKeys: String, CodingKey {
        case foreign
        case domestic
        case timeoutMs = "timeout_ms"
        case port
        case interfaceIndex = "interface_index"
    }
}

struct WhitelistProbeCycleResult: Decodable {
    enum Classification: String, Decodable {
        case normal
        case allowlist
        case offline
        case partial
        case anomalous
        case error
    }

    struct Target: Decodable {
        let group: String
        let host: String
        let port: Int
        let tcpOK: Bool
        let tlsOK: Bool
        let pass: Bool
        let errorClass: String?
        let error: String?
        let remoteAddress: String?
        let durationMs: Int64

        enum CodingKeys: String, CodingKey {
            case group, host, port, pass, error
            case tcpOK = "tcp_ok"
            case tlsOK = "tls_ok"
            case errorClass = "error_class"
            case remoteAddress = "remote_address"
            case durationMs = "duration_ms"
        }
    }

    let ok: Bool
    let classification: Classification
    let summary: String
    let domesticPass: Int
    let domesticTotal: Int
    let foreignPass: Int
    let foreignTotal: Int
    let targets: [Target]
    let error: String?

    enum CodingKeys: String, CodingKey {
        case ok, classification, summary, targets, error
        case domesticPass = "domestic_pass"
        case domesticTotal = "domestic_total"
        case foreignPass = "foreign_pass"
        case foreignTotal = "foreign_total"
    }

    static let errorResult = WhitelistProbeCycleResult(
        ok: false,
        classification: .error,
        summary: "probe failed before producing JSON",
        domesticPass: 0,
        domesticTotal: 0,
        foreignPass: 0,
        foreignTotal: 0,
        targets: [],
        error: "decode_error"
    )
}

enum WhitelistProbeEngine {
    static let defaultTimeoutMs = 4_000
    static let defaultPort = 443

    /// Select an explicit physical interface only when NWPath says that type
    /// is in use and there is exactly one matching candidate. `availableInterfaces`
    /// may contain Wi-Fi plus multiple cellular interfaces (dual SIM/eSIM); binding
    /// to the first entry can send probes over the wrong or inactive data line.
    /// In ambiguous cases interfaceIndex stays nil and NECP/default routing chooses
    /// the actual underlying path for the provider process.
    static func pathSelection(_ path: NWPath?) -> WhitelistProbePathSelection {
        guard let path else {
            return WhitelistProbePathSelection(interfaceIndex: nil, summary: "status=missing bind=default")
        }

        let status: String
        switch path.status {
        case .satisfied: status = "satisfied"
        case .unsatisfied: status = "unsatisfied"
        case .requiresConnection: status = "requiresConnection"
        @unknown default: status = "unknown"
        }

        let physicalTypes: [(NWInterface.InterfaceType, String)] = [
            (.wifi, "wifi"),
            (.cellular, "cellular"),
            (.wiredEthernet, "wired")
        ]
        let usedKinds = physicalTypes.filter { path.usesInterfaceType($0.0) }
        let usedNames = usedKinds.map { $0.1 }
        let candidates = path.availableInterfaces.filter { iface in
            usedKinds.contains { $0.0 == iface.type } && !iface.name.hasPrefix("utun")
        }
        let candidateText = candidates
            .map { "\($0.name)#\($0.index)" }
            .sorted()
            .joined(separator: ",")
        let bindIndex: UInt32? = path.status == .satisfied && candidates.count == 1
            ? UInt32(candidates[0].index)
            : nil
        let bindText = bindIndex.map(String.init) ?? "default"
        let summary = [
            "status=\(status)",
            "used=\(usedNames.isEmpty ? "other" : usedNames.joined(separator: "+"))",
            "candidates=\(candidateText.isEmpty ? "none" : candidateText)",
            "bind=\(bindText)",
            "expensive=\(path.isExpensive)",
            "constrained=\(path.isConstrained)",
            "ipv4=\(path.supportsIPv4)",
            "ipv6=\(path.supportsIPv6)",
            "dns=\(path.supportsDNS)"
        ].joined(separator: " ")
        return WhitelistProbePathSelection(interfaceIndex: bindIndex, summary: summary)
    }

    static func run(interfaceIndex: UInt32? = nil) -> WhitelistProbeCycleResult {
        let cfg = WhitelistProbeCycleConfig(
            foreign: WhitelistProbePreferences.foreignControlTargets,
            domestic: WhitelistProbePreferences.domesticAllowlistedTargets,
            timeoutMs: defaultTimeoutMs,
            port: defaultPort,
            interfaceIndex: Int(interfaceIndex ?? 0)
        )
        let data: Data
        do {
            data = try JSONEncoder().encode(cfg)
        } catch {
            return WhitelistProbeCycleResult.errorResult
        }
        let json = String(data: data, encoding: .utf8) ?? "{}"
        let out = SocksstubRunWhitelistProbeCycleJSON(json)
        guard let outData = out.data(using: .utf8) else {
            return WhitelistProbeCycleResult.errorResult
        }
        do {
            return try JSONDecoder().decode(WhitelistProbeCycleResult.self, from: outData)
        } catch {
            return WhitelistProbeCycleResult.errorResult
        }
    }

    static func runAsync(interfaceIndex: UInt32? = nil) async -> WhitelistProbeCycleResult {
        await Task.detached(priority: .utility) {
            run(interfaceIndex: interfaceIndex)
        }.value
    }

    static func shortLog(_ result: WhitelistProbeCycleResult) -> String {
        "method=tcp_tls_sni icmp=not_used classification=\(result.classification.rawValue) domestic=\(result.domesticPass)/\(result.domesticTotal) foreign=\(result.foreignPass)/\(result.foreignTotal) summary=\"\(sanitize(result.summary))\""
    }

    static func detailedLogLines(_ result: WhitelistProbeCycleResult) -> [String] {
        var lines: [String] = [shortLog(result)]
        let ordered = result.targets.sorted { lhs, rhs in
            if lhs.group != rhs.group {
                return lhs.group == "foreign"
            }
            return lhs.host.localizedCaseInsensitiveCompare(rhs.host) == .orderedAscending
        }
        for target in ordered {
            let tcp = target.tcpOK ? "ok" : "fail"
            let tls = target.tlsOK ? "ok" : "fail"
            let pass = target.pass ? "yes" : "no"
            let errClass = sanitize(target.errorClass ?? "")
            let err = sanitize(target.error ?? "")
            let remote = sanitize(target.remoteAddress ?? "")
            lines.append("target group=\(target.group) host=\(target.host):\(target.port) remote=\(remote.isEmpty ? "none" : remote) tcp=\(tcp) tls=\(tls) pass=\(pass) dur=\(target.durationMs)ms errorClass=\(errClass.isEmpty ? "none" : errClass) error=\(err.isEmpty ? "none" : err)")
        }
        if let error = result.error, !error.isEmpty {
            lines.append("engineError=\(sanitize(error))")
        }
        return lines
    }

    private static func sanitize(_ text: String) -> String {
        let oneLine = text
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
        if oneLine.count <= 180 { return oneLine }
        return String(oneLine.prefix(180)) + "…"
    }
}
