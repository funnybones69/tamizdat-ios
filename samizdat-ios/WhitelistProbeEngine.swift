import Foundation
import Network

struct WhitelistProbePathSelection {
    let interfaceIndex: UInt32?
    let summary: String
}

struct WhitelistProbeCycleResult {
    enum Classification: String {
        case normal
        case allowlist
        case error
    }

    struct Target {
        let group: String
        let host: String
        let pass: Bool
        let durationMs: Int64
    }

    let classification: Classification
    let domesticPass: Int
    let domesticTotal: Int
    let foreignPass: Int
    let foreignTotal: Int
    let targets: [Target]
    let error: String?
}

enum WhitelistProbeEngine {
    /// A pair of serial pings stays bounded and avoids Darwin ICMP socket
    /// identifier reuse races between the blocked and allowed controls.
    static let pingTimeout: TimeInterval = 3

    /// Select an explicit physical interface only when NWPath says that type
    /// is active and there is exactly one distinct non-utun candidate. Some
    /// iOS versions expose the same en0/index more than once; dedupe by index
    /// before deciding that the path is ambiguous.
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

        var seenIndexes = Set<Int>()
        let candidates = path.availableInterfaces.filter { iface in
            guard usedKinds.contains(where: { $0.0 == iface.type }),
                  !iface.name.hasPrefix("utun"),
                  seenIndexes.insert(iface.index).inserted else {
                return false
            }
            return true
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

    /// Run only ICMP echo probes. There is intentionally no TCP, TLS, HTTP,
    /// or gomobile probe in the whitelist detector.
    static func run(interfaceIndex: UInt32? = nil) -> WhitelistProbeCycleResult {
        let foreign = WhitelistProbePreferences.foreignControlTargets
        let domestic = WhitelistProbePreferences.domesticAllowlistedTargets
        guard !foreign.isEmpty, !domestic.isEmpty else {
            return WhitelistProbeCycleResult(
                classification: .error,
                domesticPass: 0,
                domesticTotal: domestic.count,
                foreignPass: 0,
                foreignTotal: foreign.count,
                targets: [],
                error: "missing ping target"
            )
        }

        // Keep probes serial. Besides making the log easy to read, this avoids
        // stale ICMP datagrams crossing immediately reused Darwin ping sockets.
        var targets: [WhitelistProbeCycleResult.Target] = []
        for host in foreign {
            targets.append(ping(group: "blocked", host: host, interfaceIndex: interfaceIndex))
        }
        for host in domestic {
            targets.append(ping(group: "allowed", host: host, interfaceIndex: interfaceIndex))
        }

        let foreignPass = targets.filter { $0.group == "blocked" && $0.pass }.count
        let domesticPass = targets.filter { $0.group == "allowed" && $0.pass }.count
        let classification: WhitelistProbeCycleResult.Classification
        if domesticPass > 0 && foreignPass > 0 {
            classification = .normal
        } else if domesticPass > 0 && foreignPass == 0 {
            classification = .allowlist
        } else {
            classification = .error
        }

        return WhitelistProbeCycleResult(
            classification: classification,
            domesticPass: domesticPass,
            domesticTotal: domestic.count,
            foreignPass: foreignPass,
            foreignTotal: foreign.count,
            targets: targets,
            error: classification == .error ? "ping matrix is not decisive" : nil
        )
    }

    static func runAsync(interfaceIndex: UInt32? = nil) async -> WhitelistProbeCycleResult {
        await Task.detached(priority: .utility) {
            run(interfaceIndex: interfaceIndex)
        }.value
    }

    static func shortLog(_ result: WhitelistProbeCycleResult) -> String {
        let verdict: String
        switch result.classification {
        case .normal: verdict = "free_internet"
        case .allowlist: verdict = "whitelist_active"
        case .error: verdict = "error_detecting"
        }
        return "method=icmp_echo verdict=\(verdict) blocked=\(result.foreignPass)/\(result.foreignTotal) allowed=\(result.domesticPass)/\(result.domesticTotal)"
    }

    static func detailedLogLines(_ result: WhitelistProbeCycleResult) -> [String] {
        var lines = [shortLog(result)]
        for target in result.targets {
            let outcome = target.pass ? "reply" : "timeout"
            lines.append("ping group=\(target.group) target=\(sanitize(target.host)) result=\(outcome) rtt=\(target.durationMs)ms")
        }
        if let error = result.error {
            lines.append("error=\(sanitize(error))")
        }
        return lines
    }

    private static func ping(
        group: String,
        host: String,
        interfaceIndex: UInt32?
    ) -> WhitelistProbeCycleResult.Target {
        let pinger = ICMPPinger(target: .hostname(host), interfaceIndex: interfaceIndex)
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var success = false
        var elapsed = pingTimeout

        pinger.ping(timeout: pingTimeout) { ok, duration in
            lock.lock()
            success = ok
            elapsed = duration
            lock.unlock()
            semaphore.signal()
        }

        if semaphore.wait(timeout: .now() + pingTimeout + 1) == .timedOut {
            pinger.cancel()
        }
        lock.lock()
        let result = WhitelistProbeCycleResult.Target(
            group: group,
            host: host,
            pass: success,
            durationMs: Int64((elapsed * 1_000).rounded())
        )
        lock.unlock()
        return result
    }

    private static func sanitize(_ text: String) -> String {
        let oneLine = text
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
        if oneLine.count <= 120 { return oneLine }
        return String(oneLine.prefix(120)) + "…"
    }
}
