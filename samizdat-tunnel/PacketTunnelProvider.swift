import Foundation
import Network
import NetworkExtension
import OSLog
import os
import Darwin
import HevSocks5Tunnel
import SamizdatClient

/// Path 3 PacketTunnelProvider — pure C/lwIP via hev-socks5-tunnel, no Go
/// runtime in the extension. The heavy lifting (Go SOCKS5 listener,
/// optional samizdat network adapter) lives in the main-app process where there is
/// no jetsam memory cap. The extension's job in this design is reduced to
/// just three things:
///
///   1. install NEPacketTunnelNetworkSettings;
///   2. find the utun file descriptor that NEPacketTunnelProvider just
///      opened for us (Apple does not pass it through the public API; we
///      enumerate fds and match the "com.apple.net.utun_control" socket
///      pattern — same trick every shipping iOS network adapter app uses);
///   3. call hev_socks5_tunnel_main_from_str(config, len, fd), which
///      blocks until hev_socks5_tunnel_quit().
///
/// Memory profile observed on production iOS network adapter clients (V2Box, FoXray,
/// Hiddify variants) running this exact pattern: 5-15 MB RSS sustained
/// even at 100 Mbps, vs. our ~30-40 MB Go/gVisor stack that hit jetsam at
/// 50 s. The savings come from: no Go runtime, no gVisor packet pools, no
/// gomobile cgo bridging, no per-flow Go goroutines.
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private struct MemoryPressureState {
        var lastNuclearCloseAt = Date.distantPast
        // Every delivered critical event, including ones swallowed by the
        // nuclear-close rate limit, re-arms the recovery cooldown via this
        // timestamp. lastNuclearCloseAt alone would let a critical at t+59
        // pass unseen and recovery attach at t+60 — one second after live
        // pressure.
        var lastCriticalEventAt = Date.distantPast
        var didDumpHeap = false
        var recoveryScheduled = false
        var recoveryAttempted = false
    }

    private let log = Logger(subsystem: "com.anarki.samizdat-test.tunnel", category: "extension")
    private let runningState = OSAllocatedUnfairLock<Bool>(initialState: false)
    private var isRunning: Bool {
        get { runningState.withLock { $0 } }
        set { runningState.withLock { $0 = newValue } }
    }

    private static let appGroupID = "group.com.anarki.samizdat-test"
    private static let logFileName = "extension-log.txt"

    /// TCP port the main-app's SocksStubStart binds to on 127.0.0.1. Hev
    /// connects here for every flow it forwards. Hardcoded so extension
    /// and app agree without an extra rendezvous; collision-unlikely in
    /// the iOS sandbox.
    private static let socksPort: UInt16 = 18443

    private var swiftHeartbeatTimer: DispatchSourceTimer?
    // IPA-D18: emit heartbeat log line only every 5 ticks (every ~150 s
    // at the new 30 s cadence) to drop file-write rate from 3600/hour
    // to ~24/hour. Pressure events are still logged immediately.
    private var hbTick: Int = 0
    private var swiftLogHandle: FileHandle?
    private var memPressureSrc: DispatchSourceMemoryPressure?
    private let memoryPressureState = OSAllocatedUnfairLock<MemoryPressureState>(initialState: .init())
    private let pressureRecoveryTask = OSAllocatedUnfairLock<Task<Void, Never>?>(initialState: nil)
    private static let memoryPressureCooldown: TimeInterval = 60
    private static let turnPressureRecoveryHeadroomBytes: UInt64 = 20 * 1024 * 1024
    private static let turnPressureRecoveryStableSamples = 2
    private static let turnPressureRecoveryPollNanoseconds: UInt64 = 2_000_000_000
    private static let turnPressureRecoveryMaxPolls = 150
    private var hevQueue = DispatchQueue(label: "com.anarki.samizdat-test.hev", qos: .userInitiated)

    // IPA-O: auto-reconnect on network change (Wi-Fi ↔ cellular flip).
    // Mirrors what V2Box / FoXray / Hiddify do: when the OS default interface
    // changes, the in-flight TLS+H2 transports to the upstream samizdat
    // server are tied to old socket fds and won't recover on their own;
    // we re-call SocksstubSetSamizdatConfig with the same blob, which
    // closes the old samizdat.Client and rebuilds a fresh one over the
    // current default interface.
    private let pathMonitor = NWPathMonitor()
    private let pathMonitorQueue = DispatchQueue(label: "com.anarki.samizdat-test.path", qos: .utility)
    private var lastPathInterfaceID: String? // sortable key from path.availableInterfaces
    private var lastReconnectAt = Date.distantPast

    // IPA-D22: timestamp when startTunnel completed (the SOCKS5 listener
    // is up and we handed packets to hev). Surfaced in the "status" RPC
    // as uptimeSec so the main-app Uptime stat tile can render m:ss /
    // h:mm without keeping its own anchor.
    private let tunnelStartedAtLock = OSAllocatedUnfairLock<Date?>(initialState: nil)
    private var tunnelStartedAt: Date? {
        get { tunnelStartedAtLock.withLock { $0 } }
        set { tunnelStartedAtLock.withLock { $0 = newValue } }
    }

    // IPA-D22: 1 while rewireUpstream is mid-flight (SetSamizdatConfig
    // call running on a background queue). Surfaced as `isRewiring` in
    // the status RPC so the main-app shield can flip to amber
    // "Reconnecting…" instantly without waiting for path-monitor
    // settling. Read+written under runningState's same unfair lock for
    // cheapness — concurrency model: one rewire at a time.
    private let rewiringFlag = OSAllocatedUnfairLock<Bool>(initialState: false)
    private var isRewiring: Bool {
        get { rewiringFlag.withLock { $0 } }
        set { rewiringFlag.withLock { $0 = newValue } }
    }

    // IPA-P: dual-endpoint storage. The combined blob arrives in
    // providerConfiguration; we split it into primary + optional backup
    // and pick which one to dial based on EndpointModeStore.current
    // (read from App Group UserDefaults — the main app writes when the
    // user taps the picker, then sends a "switchEndpoint" provider
    // message so we re-read live without disconnect).
    private var combinedConfigBlob: String = ""
    private var primaryBlob: String = ""
    private var backupBlob: String?
    private struct ResolvedPeer {
        let host: String
        let ip: String
    }
    private let resolvedPeerLock = OSAllocatedUnfairLock<ResolvedPeer?>(initialState: nil)
    private var resolvedPeer: ResolvedPeer? {
        get { resolvedPeerLock.withLock { $0 } }
        set { resolvedPeerLock.withLock { $0 = newValue } }
    }

    private enum EffectiveUpstream: String {
        case h2
        case turn
    }

    private struct UpstreamPolicy {
        let endpointMode: EndpointMode
        let effectiveEndpoint: EndpointMode
        let whitelistModeRaw: String
        let upstream: EffectiveUpstream

        var usesTURN: Bool { upstream == .turn }
    }

    private let rewireQueue = DispatchQueue(label: "com.anarki.samizdat-test.rewire", qos: .userInitiated)
    private let rewireGenerationLock = OSAllocatedUnfairLock<Int>(initialState: 0)
    private static let turnTunnelGenerationLock = OSAllocatedUnfairLock<Int>(initialState: 0)
    // nil = no retry; otherwise the generation that currently owns the slot.
    // A newer tunnel may replace a stale retry without waiting for its Task to
    // observe cancellation, and stale defer blocks cannot clear the new owner.
    private static let turnAttachRetryGenerationLock = OSAllocatedUnfairLock<Int?>(initialState: nil)
    private var rewireGeneration: Int {
        get { rewireGenerationLock.withLock { $0 } }
        set { rewireGenerationLock.withLock { $0 = newValue } }
    }

    // IPA-Q: WhitelistDetector — periodic out-of-tunnel cascade probe
    // that flips to backup when TSPU restricted-profile mode is detected and
    // back to primary when it lifts.
    private var whitelistDetector: WhitelistDetector?
    private var lastPathSatisfied: Bool = true

    // IPA-D26: bridge object retained while the tunnel is up so the
    // Go-side rewire requester atomic.Value holds a valid pointer.
    private var autoRewireBridge: AutoRewireBridge?

    // IPA-A1: PacketBridge removed. We're back on the original
    // "Path 3" architecture (Pattern 1 in the iOS network adapter taxonomy):
    // hev gets the raw utun file descriptor via KVO and reads/writes
    // packets directly in C. No Swift in the data path. Same setup
    // Shadowrocket / Surge / Tun2SocksKit use. Loss: per-flow
    // NEFlowMetaData (app bundle-id) — the Tamizdat-App-Hint header
    // (Tier 3 server classifier signal) is no longer sent. Server's
    // Tier 1 (port whitelist for Roblox/AnyDesk/Discord/IANA-dynamic)
    // and Tier 2 (cadence/jitter for RTP/opus) handle real workload
    // without it.

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // Start writing into App Group log file immediately so we have a
        // timeline even if hev fails to launch.
        openLogSink()
        Self.turnTunnelGenerationLock.withLock { $0 += 1 }
        appendExtLog("info: PacketTunnelProvider startTunnel (Path 3 / hev)")

        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let configBlob = proto.providerConfiguration?["configBlob"] as? String else {
            appendExtLog("error: missing configBlob in providerConfiguration")
            completionHandler(makeError("missing samizdat config"))
            return
        }
        let serverIP = proto.providerConfiguration?["serverIP"] as? String
        let serverHost = URLComponents(string: configBlob)?.host
        let resolvedPeer = serverIP.flatMap { ip in
            serverHost.map { ResolvedPeer(host: $0, ip: ip) }
        }
        self.resolvedPeer = resolvedPeer

        // IPA-P: split the combined blob (which carries an optional
        // &backup=base64url(...) query param) into per-endpoint URLs.
        // The currently selected endpoint feeds SocksStubSetSamizdatConfig.
        let split = SamizdatURLCodec.split(configBlob)
        self.combinedConfigBlob = configBlob
        self.primaryBlob = split.primary
        self.backupBlob = split.backup
        let mode = EndpointModeStore.current
        let activeBlob = Self.pick(mode: mode, primary: split.primary, backup: split.backup)
        let policy = Self.upstreamPolicy(mode: mode, backup: split.backup)
        appendExtLog("info: endpoint mode = \(mode.rawValue) effective=\(policy.effectiveEndpoint.rawValue) upstream=\(policy.upstream.rawValue) (backup configured: \(split.backup != nil))")

        // Bring the in-process SOCKS5 listener up FIRST. Both endpoints
        // of the loopback bridge live in this extension, so there is no
        // cross-process sandbox issue and the listener can never get
        // host-app-suspended out from under us.
        appendExtLog("info: starting in-process SocksStub on 127.0.0.1:\(Self.socksPort)")
        if !Self.startInProcessSocks(configBlob: activeBlob, policy: policy, resolvedPeer: resolvedPeer, log: appendExtLog) {
            completionHandler(makeError("SocksStub failed to start"))
            return
        }

        // IPA-D26: register the auto-rewire bridge so the Go-side ping
        // prober can request a fresh client when it sees consecutive
        // misses. Catches the case where wifi is dying but iOS hasn't
        // yet failed over to LTE — system NWPath stays satisfied (or
        // takes 15-30 s to flip), but the prober knows the upstream
        // is unreachable RIGHT NOW. Throttled in Go to once per 15 s.
        let rewireBridge = AutoRewireBridge { [weak self] in
            guard let self else { return }
            if self.shouldSuppressPingRewireForTURN() {
                return
            }
            self.appendExtLog("info: auto-rewire fired by ping prober (consecutive fails)")
            self.rewireUpstream()
        }
        // Stash a strong ref so the bridge isn't deallocated while Go
        // holds it via atomic.Value.
        self.autoRewireBridge = rewireBridge
        SocksstubSetRewireRequester(rewireBridge)

        let settings = makeNetworkSettings(serverIP: serverIP)
        appendExtLog("info: applying packet tunnel network settings")
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                self.appendExtLog("error: setTunnelNetworkSettings: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            self.startHev(configBlob: configBlob, completionHandler: completionHandler)
        }
    }

    /// Starts the Go SOCKS5 listener and primes the samizdat client. Both
    /// run inside this extension process. Returns true on success.
    private static func startInProcessSocks(configBlob: String, policy: UpstreamPolicy, resolvedPeer: ResolvedPeer?, log: @escaping (String) -> Void) -> Bool {
        // Mirror Go-shim logs to the App Group file so the bridge sees them
        // alongside extension logs.
        if let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupID
        ) {
            let logURL = containerURL.appendingPathComponent(logFileName)
            SocksstubSetLogSink(logURL.path)
        }
        var startErr: NSError?
        SocksstubStart("127.0.0.1:\(socksPort)", &startErr)
        if let startErr {
            // "already listening" is fine on a hot-restart of the tunnel
            // — surface but don't fail.
            let msg = startErr.localizedDescription
            if msg.contains("already listening") {
                log("info: SocksStub: already listening, reusing")
            } else {
                log("error: SocksstubStart: \(msg)")
                return false
            }
        }
        // IPA-D22: pool variant picker deleted from the UI. V1 is the
        // hardcoded shipping choice (matches what mobile/socksstub
        // ships with). Setter is still called so the Go bridge has a
        // consistent value if anything reads it back; semantically a
        // no-op against the default.
        SocksstubSetPoolVariant("v1")
        // IPA-D21: push the configured real-internet ping probe URL into
        // Go-side before the first client is built, so the prober's first
        // tick fires against the user's chosen target. App-side updates
        // (via SettingsView) are pushed live through the
        // "refreshPingURL" provider message handled below.
        SocksstubSetPingProbeURL(PingURLPreferences.url)
        // Phase C iOS-notify (2026-05-10): register the bridge BEFORE the
        // first samizdat client is built. The first bundle fetch happens
        // immediately after SetSamizdatConfig, so a user who is already
        // over-quota at connect time still gets the notification.
        SocksstubSetNotificationCallback(NotificationBridge.shared)
        // Policy must be visible to the Go dial path before the H2 client is
        // built. In TURN mode this suppresses H2 ping/warm-up and makes every
        // TCP/UDP flow fail closed until the TURN/WG netstack is ready.
        if policy.usesTURN {
            SocksstubSetVKTurnRequired(true)
        } else {
            // Clear any stale TURN netstack before permitting H2 again. The
            // synchronous stop waits for an already-owned drain to finish.
            SocksstubStopVKTurnUpstream()
            SocksstubSetVKTurnRequired(false)
        }
        var cfgErr: NSError?
        SocksstubSetSamizdatConfig(configBlob, &cfgErr)
        if let cfgErr {
            log("error: SocksstubSetSamizdatConfig: \(cfgErr.localizedDescription)")
            return false
        }

        // TURN/H2 policy is derived from the effective endpoint, not from
        // WhitelistMode alone. WhitelistMode.vkTurn only applies when the
        // effective endpoint is the backup/Whitelist endpoint; Main always
        // uses H2 and must clear any stale VK TURN netstack before flows
        // reconnect.
        log("info: [vkturn] upstream policy mode=\(policy.endpointMode.rawValue) effective=\(policy.effectiveEndpoint.rawValue) whitelistMode=\(policy.whitelistModeRaw) desired=\(policy.upstream.rawValue)")
        ExtLog.info("[vkturn] upstream policy mode=\(policy.endpointMode.rawValue) effective=\(policy.effectiveEndpoint.rawValue) whitelistMode=\(policy.whitelistModeRaw) desired=\(policy.upstream.rawValue)")
        if policy.usesTURN {
            log("info: [vkturn] effective Whitelist + WhitelistMode=vkTurn → calling attachVKTurnUpstream")
            ExtLog.info("[vkturn] effective Whitelist + WhitelistMode=vkTurn → calling attachVKTurnUpstream")
            Self.attachVKTurnUpstream(resolvedPeer: resolvedPeer)
            log("info: [vkturn] attachVKTurnUpstream returned (sync part finished)")
            ExtLog.info("[vkturn] attachVKTurnUpstream returned (sync part finished)")
        } else {
            log("info: [vkturn] VK TURN disabled by policy — H2 active (effective=\(policy.effectiveEndpoint.rawValue), whitelistMode=\(policy.whitelistModeRaw))")
            ExtLog.info("[vkturn] VK TURN disabled by policy — H2 active (effective=\(policy.effectiveEndpoint.rawValue), whitelistMode=\(policy.whitelistModeRaw))")
        }
        return true
    }

    /// Build a numeric peer from the IPv4 resolved by the main app before
    /// startVPNTunnel(). This avoids a cold DNS lookup inside the fail-closed
    /// extension bootstrap. If the pre-resolved value is absent or malformed,
    /// Go retains a short context-bounded hostname fallback.
    private static func numericPeerAddress(_ configuredPeer: String, resolvedPeer: ResolvedPeer?) -> String {
        guard let resolvedPeer,
              !resolvedPeer.ip.isEmpty,
              let separator = configuredPeer.lastIndex(of: ":")
        else { return configuredPeer }
        let portText = configuredPeer[configuredPeer.index(after: separator)...]
        guard let port = UInt16(portText), port > 0 else { return configuredPeer }
        guard let configuredHost = URLComponents(string: "udp://\(configuredPeer)")?.host,
              configuredHost.caseInsensitiveCompare(resolvedPeer.host) == .orderedSame
        else { return configuredPeer }
        var parsed = in_addr()
        guard inet_pton(AF_INET, resolvedPeer.ip, &parsed) == 1 else { return configuredPeer }
        return "\(resolvedPeer.ip):\(port)"
    }

    private static func roomCount(inBundleJSON json: String?) -> Int {
        guard let json, !json.isEmpty,
              let data = json.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let rooms = object["rooms"] as? [Any]
        else { return 0 }
        return rooms.count
    }

    /// Spin up the VK TURN runner if the operator selected it.
    /// All inputs come from App Group UserDefaults — the user fills
    /// them in Settings → VK TURN before flipping the picker on.
    /// Traffic still flows over the existing hev path; this only logs
    /// the WireGuard config it receives so the operator can verify
    /// reachability. WireGuardKit attach is Phase 2D-followup.
    ///
    /// Logging changed from a captured `(String) -> Void` closure to
    /// direct `ExtLog.*` calls. The closure path (which fans out to
    /// `FileHandle.write` + `synchronize`) was eating every line we
    /// emitted around `SocksstubStartVKTurnUpstream`. That gomobile
    /// call used to block while VK Allocate / DTLS / GETCONF ran, and
    /// Foundation's buffered handle silently dropped post-block lines.
    /// `ExtLog` open/write/fsync/close every call, so the timeline
    /// survives the block.
    @discardableResult
    private static func attachVKTurnUpstream(resolvedPeer: ResolvedPeer? = nil, scheduleDrainRetry: Bool = true) -> String {
        ExtLog.info("[vkturn] attach: entering helper")

        // Read runtime values from App Group UserDefaults — these keys
        // are written by the main app. VKSession paramsPreferences/TURNSession paramsStore
        // are included in the extension target for read-side helpers, but
        // the WKWebView refresh writer remains main-app-only.
        let groupID = "group.com.anarki.samizdat-test"
        let defaults = UserDefaults(suiteName: groupID)
        let configuredPeer = defaults?.string(forKey: "tamizdat.vkPeerAddr") ?? ""
        let peer = numericPeerAddress(configuredPeer, resolvedPeer: resolvedPeer)
        let password = defaults?.string(forKey: "tamizdat.vkConnectPassword") ?? ""
        let deviceID = defaults?.string(forKey: "tamizdat.vkDeviceID") ?? "no-device-id"
        let workers = VKCredsPreferences.workers
        let roomCount = VKCredsPreferences.roomHashes.count
        ExtLog.info("[vkturn] attach: peerNumeric=\(peer != configuredPeer) passwordLen=\(password.count) deviceIDLen=\(deviceID.count) rooms=\(roomCount) workersPerRoom=20")

        guard !peer.isEmpty else {
            ExtLog.warn("[vkturn] attach SKIPPED — Main tamizdat:// server not mirrored yet. Open Settings → Proxies and save Main URI.")
            return "missingPeer"
        }
        guard !password.isEmpty else {
            ExtLog.warn("[vkturn] attach SKIPPED — Main tamizdat:// shortid not mirrored yet. Re-save Main URI in Settings → Proxies.")
            return "missingPassword"
        }
        if SocksstubTURNUpstreamRunning() {
            let ready = !SocksstubTURNUpstreamWGConfig().isEmpty
            ExtLog.info("[vkturn] attach deduplicated — runner already \(ready ? "ready" : "waiting for GETCONF") generation=\(SocksstubTURNUpstreamGeneration())")
            return "already running"
        }

        // Prefer the atomic multi-room bundle. Legacy JSON is a migration path
        // for a true single-room install only. A configured multi-room tunnel
        // must fail closed if its complete bundle is missing: silently falling
        // back to one legacy room during pressure recovery would make 4×20
        // appear recovered while actually running only 20 workers.
        let roomBundleJSON = TURNCredsStore.shared.validatedRoomBundleJSON()
        let legacyCredsJSON = defaults?.string(forKey: "tamizdat.vkTURNCredsJSON")
        let bundleRoomCount = Self.roomCount(inBundleJSON: roomBundleJSON)
        if roomCount > 1 && bundleRoomCount != roomCount {
            ExtLog.warn("[vkturn] attach SKIPPED — incomplete multi-room bundle bundleRooms=\(bundleRoomCount) configured=\(roomCount)")
            return "noCreds"
        }
        guard (roomBundleJSON?.isEmpty == false) || (legacyCredsJSON?.isEmpty == false) else {
            ExtLog.warn("[vkturn] attach SKIPPED — no complete credential bundle in App Group")
            return "noCreds"
        }
        let credsJSON = legacyCredsJSON ?? ""
        ExtLog.info("[vkturn] attach: credential payload present mode=\(roomBundleJSON?.isEmpty == false ? "multi-room" : "legacy")")

        // Safety margin gate. The pre-fix code hard-coded 3480 s
        // (lifetime 3600 minus 120 s cushion), but VK has shipped
        // shorter-lived session params in the past — and a future TTL change
        // would have silently let us call `SocksstubStartVKTurnUpstream`
        // against session params that were already past expiry. That gomobile
        // function does a synchronous VK Allocate against the TURN
        // server, which can sleep up to 15 s before failing 401, so
        // we want to bail clean here and let the foreground/BG
        // refresher grab fresh session params instead.
        //
        // Now: parse `lifetime_sec` out of the session paramsJSON we already
        // loaded above (wire shape `{username, password, turn_servers,
        // lifetime_sec}` from TURNSession paramsStore.vkSession paramsAsJSON) and gate
        // on `age >= lifetime - 120 s`. lifetime_sec <= 0 falls back
        // to the historic 3480 s value so older entries (pre-refresh
        // schema) still age-check cleanly.
        if roomBundleJSON?.isEmpty != false {
            let cushionSec: TimeInterval = 120
            let lifetimeSec: TimeInterval = {
            guard let data = credsJSON.data(using: .utf8) else { return 0 }
            struct LifetimeShape: Decodable { let lifetime_sec: Int? }
            guard let parsed = try? JSONDecoder().decode(LifetimeShape.self, from: data),
                  let life = parsed.lifetime_sec, life > 0 else {
                return 0
            }
            return TimeInterval(life)
        }()
        let safeBound: TimeInterval = lifetimeSec > 0 ? (lifetimeSec - cushionSec) : 3480

        // Key written by `TURNSession paramsStore.save(_:)` alongside the JSON
        // payload — see step C of feat/turn-autonomous-refresh.
        if let acquiredAt = defaults?.object(forKey: "tamizdat.vkTURNCredsAcquiredAt") as? Date {
            let age = Date().timeIntervalSince(acquiredAt)
            ExtLog.info("[vkturn] attach: creds age=\(Int(age))s (lifetime=\(Int(lifetimeSec))s, cushion=\(Int(cushionSec))s)")
            if age >= safeBound {
                ExtLog.warn("[vkturn] attach SKIPPED — creds стары (age=\(Int(age))s ≥ \(Int(safeBound))s). Wait for refresh, then reconnect.")
                return "staleCreds"
            }
        } else {
            ExtLog.warn("[vkturn] attach: no vkTURNCredsAcquiredAt stamp — proceeding without age check (legacy creds?)")
        }

        }

        ExtLog.info("[vkturn] attach: BEFORE runner start peerNumeric=\(peer != configuredPeer), listenPort=9000, rooms=\(roomCount)")
        let beforeMs = Date()
        let err: String
        if let bundle = roomBundleJSON, !bundle.isEmpty {
            err = SocksstubStartVKTurnMultiRoomUpstream(bundle, peer, password, deviceID, 9000, VKCredsPreferences.workersPerRoom)
        } else {
            err = SocksstubStartVKTurnUpstream(credsJSON, peer, password, deviceID, 9000, workers)
        }
        let durMs = Int(Date().timeIntervalSince(beforeMs) * 1000)
        ExtLog.info("[vkturn] attach: AFTER runner start dur=\(durMs)ms err=\"\(err)\"")
        if err == "already running" {
            ExtLog.info("[vkturn] attach deduplicated by Go singleton")
            return err
        }
        if err == "previous runner still draining" {
            ExtLog.info("[vkturn] attach pending — previous runner still draining")
            if scheduleDrainRetry {
                scheduleVKTurnAttachAfterDrain(resolvedPeer: resolvedPeer)
            }
            return err
        }
        if !err.isEmpty {
            ExtLog.error("[vkturn] runner start returned: \"\(err)\"")
            return err
        }
        let generation = SocksstubTURNUpstreamGeneration()
        ExtLog.info("[vkturn] runner OK generation=\(generation), polling for WG config + netstack (up to 60 s)")

        Task.detached(priority: .utility) {
            ExtLog.info("[vkturn] async polling task started generation=\(generation)")
            struct TurnStatsShape: Decodable { let error: String? }
            var attempts = 0
            for _ in 0..<240 { // 240 * 250 ms = 60 s
                attempts += 1
                let currentGeneration = SocksstubTURNUpstreamGeneration()
                if currentGeneration != generation {
                    ExtLog.info("[vkturn] polling stopped — stale generation=\(generation) current=\(currentGeneration)")
                    return
                }
                let wg = SocksstubTURNUpstreamWGConfig()
                let running = SocksstubTURNUpstreamRunning()
                if !wg.isEmpty {
                    ExtLog.info("[vkturn] WG config received after \(attempts*250)ms (\(wg.count) chars; content redacted)")
                    ExtLog.info("[vkturn] SocksstubTURNUpstreamRunning = \(running). Traffic should now flow via netstack.")
                    return
                }
                let stats = SocksstubTURNUpstreamStatsJSON()
                if let data = stats.data(using: .utf8),
                   let shape = try? JSONDecoder().decode(TurnStatsShape.self, from: data),
                   let error = shape.error,
                   !error.isEmpty {
                    ExtLog.error("[vkturn] async attach failed generation=\(generation): \(error)")
                    return
                }
                if !running {
                    ExtLog.warn("[vkturn] polling stopped — runner exited before GETCONF generation=\(generation)")
                    return
                }
                if attempts % 8 == 0 { // every 2 sec
                    ExtLog.info("[vkturn] still waiting for WG config (running=\(running), \(attempts*250)ms)")
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            ExtLog.warn("[vkturn] WG config NOT received within 60 s. running=\(SocksstubTURNUpstreamRunning()) stats=\(SocksstubTURNUpstreamStatsJSON())")
        }
        return ""
    }

    private static func scheduleVKTurnAttachAfterDrain(resolvedPeer: ResolvedPeer?) {
        let capturedTunnelGeneration = turnTunnelGenerationLock.withLock { $0 }
        let shouldSchedule = turnAttachRetryGenerationLock.withLock { owner -> Bool in
            if owner == capturedTunnelGeneration { return false }
            owner = capturedTunnelGeneration
            return true
        }
        guard shouldSchedule else {
            ExtLog.info("[vkturn] drain retry already scheduled generation=\(capturedTunnelGeneration)")
            return
        }

        Task.detached(priority: .utility) {
            defer {
                turnAttachRetryGenerationLock.withLock { owner in
                    if owner == capturedTunnelGeneration {
                        owner = nil
                    }
                }
            }
            for attempt in 1...120 { // up to 60 s; never blocks NE stop watchdog
                guard turnTunnelGenerationLock.withLock({ $0 }) == capturedTunnelGeneration else {
                    ExtLog.info("[vkturn] drain retry cancelled — tunnel generation changed")
                    return
                }
                let policy = upstreamPolicy(mode: EndpointModeStore.current, backup: nil)
                guard policy.usesTURN else {
                    ExtLog.info("[vkturn] drain retry cancelled — current policy no longer uses TURN")
                    return
                }
                if !SocksstubTURNUpstreamDraining() {
                    let result = attachVKTurnUpstream(resolvedPeer: resolvedPeer, scheduleDrainRetry: false)
                    ExtLog.info("[vkturn] drain retry attempt=\(attempt) result=\(result.isEmpty ? "started" : result)")
                    if result == "previous runner still draining" {
                        try? await Task.sleep(nanoseconds: 500_000_000)
                        continue
                    }
                    return
                }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
            ExtLog.error("[vkturn] drain retry timed out after 60 s")
        }
    }

    private static func refreshVKTurnCredsFromAppGroup() -> String {
        let groupID = "group.com.anarki.samizdat-test"
        let defaults = UserDefaults(suiteName: groupID)
        let roomBundle = TURNCredsStore.shared.validatedRoomBundleJSON()
        let legacyJSON = defaults?.string(forKey: "tamizdat.vkTURNCredsJSON")
        let configuredRoomCount = VKCredsPreferences.roomHashes.count
        let bundleRoomCount = Self.roomCount(inBundleJSON: roomBundle)

        if configuredRoomCount > 1 && bundleRoomCount != configuredRoomCount {
            ExtLog.warn("[vkturn] refresh creds SKIPPED — incomplete multi-room bundle bundleRooms=\(bundleRoomCount) configured=\(configuredRoomCount)")
            return "noCreds"
        }

        let beforeMs = Date()
        let err: String
        let mode: String
        if let roomBundle, !roomBundle.isEmpty {
            mode = "multi-room"
            err = SocksstubUpdateVKTurnRoomCreds(roomBundle)
        } else if let legacyJSON, !legacyJSON.isEmpty {
            mode = "legacy"
            err = SocksstubUpdateVKTurnCreds(legacyJSON)
        } else {
            ExtLog.warn("[vkturn] refresh creds SKIPPED — no credential payload in App Group")
            return "noCreds"
        }

        let durMs = Int(Date().timeIntervalSince(beforeMs) * 1000)
        if err.isEmpty {
            ExtLog.info("[vkturn] refresh creds OK mode=\(mode) dur=\(durMs)ms")
            return "ok"
        }
        if err == "not running" {
            ExtLog.info("[vkturn] refresh creds: runner not running mode=\(mode) dur=\(durMs)ms")
            return err
        }
        ExtLog.warn("[vkturn] refresh creds failed mode=\(mode) err=\"\(err)\" dur=\(durMs)ms")
        return err
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        isRunning = false
        // IPA-D22: clear so the main-app Uptime tile flips to "—".
        tunnelStartedAt = nil
        isRewiring = false
        appendExtLog("info: PacketTunnelProvider stopTunnel reason=\(reason.rawValue)")
        // IPA-D26: drop the auto-rewire bridge so it doesn't keep a
        // strong reference to self after the tunnel is torn down.
        autoRewireBridge = nil
        whitelistDetector?.stop()
        whitelistDetector = nil
        WhitelistProbePinnedStore.clear()
        // D61 FIX: do NOT call WhitelistStatusStore.reset() here.
        // reset() wipes activeEndpoint → defaults to .primary → Mode
        // tile flips from "Whitelist" to "Main" on every disconnect,
        // even though the network is still whitelist-filtered. The
        // main-app WhitelistMonitor resumes on disconnect and writes
        // fresh values; the 200s stale-check handles truly stale data.
        pathMonitor.cancel()
        // NE stop must return promptly: cancel/reset synchronously, but drain
        // TURN workers/allocations in Go background. Replacement starts remain
        // gated until that drain completes.
        Self.turnTunnelGenerationLock.withLock { $0 += 1 }
        pressureRecoveryTask.withLock {
            $0?.cancel()
            $0 = nil
        }
        SocksstubStopVKTurnUpstreamAsync()
        hev_socks5_tunnel_quit()
        // Go Stop closes the listener, waits for the accept handoff, closes all
        // registered flows and bounds the drain to two seconds.
        SocksstubStop()
        appendExtLog("info: stopTunnel stopped SOCKS listener and drained registered flows")
        swiftHeartbeatTimer?.cancel()
        swiftHeartbeatTimer = nil
        stopBurstProtection()  // IPA-D2
        try? swiftLogHandle?.close()
        swiftLogHandle = nil
        completionHandler()
    }

    // MARK: – auto-reconnect on network change

    /// Subscribes to NWPath updates so we can detect Wi-Fi ↔ cellular
    /// flips and other interface changes. When the underlying default
    /// interface changes, the OS sockets the samizdat client opened on
    /// the old interface are stale (may RST or just hang); rebuilding
    /// the upstream-facing pool from scratch is the cheapest correct
    /// fix and matches what every other production iOS network adapter client
    /// does.
    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.onPathUpdate(path)
        }
        pathMonitor.start(queue: pathMonitorQueue)
        appendExtLog("info: path monitor started")
    }

    private func onPathUpdate(_ path: Network.NWPath) {
        // Compose a stable interface fingerprint first so the detector can
        // reset confidence on satisfied→satisfied Wi-Fi/cellular/SIM changes.
        let satisfied = (path.status == .satisfied)
        let kind = describePath(path)
        let detectorPath = WhitelistProbeEngine.pathSelection(path)
        whitelistDetector?.notePathChange(
            satisfied: satisfied,
            fingerprint: detectorPath.summary
        )
        lastPathSatisfied = satisfied

        let prev = lastPathInterfaceID
        lastPathInterfaceID = kind

        // First update right after start — record baseline, do nothing.
        if prev == nil {
            appendExtLog("info: path baseline = \(kind)")
            return
        }
        if prev == kind {
            return
        }

        // IPA-D17: removed 3-second blanket debounce. sing-box-for-apple
        // (ExtensionPlatformInterface.swift:260-271) calls onUpdate
        // DefaultInterface synchronously from the path callback with no
        // debounce; the same-kind early return above already coalesces
        // satisfied→satisfied churn for free. The 3-s blanket was the
        // reason users felt the WiFi-off → cellular-on switch hang for
        // ~30-60 seconds: dead flows kept running until their per-stream
        // read-timeout while we sat on the debounce.
        //
        // Skip rewire on .unsatisfied transitions — there is no upstream
        // to dial through, and rebuilding a samizdat.Client now would
        // just fail and waste the warm-up TLS handshake. The next
        // .satisfied callback with a fresh interface kind fires a real
        // rewire.
        if !satisfied {
            appendExtLog("info: path change \(prev ?? "?") → \(kind) — unsatisfied, deferring rewire to next satisfied path")
            return
        }
        lastReconnectAt = Date()

        appendExtLog("info: path change \(prev ?? "?") → \(kind) — rewiring upstream + force-closing stale flows")
        rewireUpstream()
    }

    private func describePath(_ path: Network.NWPath) -> String {
        if path.status != Network.NWPath.Status.satisfied {
            return "unsatisfied"
        }
        let activeType: NWInterface.InterfaceType?
        let typeName: String
        if path.usesInterfaceType(.wifi) {
            activeType = .wifi
            typeName = "wifi"
        } else if path.usesInterfaceType(.cellular) {
            activeType = .cellular
            typeName = "cellular"
        } else if path.usesInterfaceType(.wiredEthernet) {
            activeType = .wiredEthernet
            typeName = "wired"
        } else if path.usesInterfaceType(.loopback) {
            activeType = .loopback
            typeName = "loopback"
        } else {
            activeType = nil
            typeName = "other"
        }
        let names = path.availableInterfaces.compactMap { iface -> String? in
            guard !iface.name.hasPrefix("utun") else { return nil }
            if let activeType, iface.type != activeType { return nil }
            return iface.name
        }
        .sorted()
        .joined(separator: ",")
        return "\(typeName)[\(names)]"
    }

    /// A ping miss in TURN mode must not rebuild the dormant H2 client and
    /// close all live SOCKS flows. That old behavior reset TCP every ~11–15 s,
    /// reducing throughput; while GETCONF was pending it also spawned duplicate
    /// attach pollers and eventually caused rapid runner restart/quota churn.
    /// Physical NWPath changes and explicit user reconnects remain separate,
    /// authoritative lifecycle triggers.
    private func shouldSuppressPingRewireForTURN() -> Bool {
        let policy = Self.upstreamPolicy(mode: EndpointModeStore.current, backup: backupBlob)
        guard policy.usesTURN else { return false }

        let running = SocksstubTURNUpstreamRunning()
        let ready = !SocksstubTURNUpstreamWGConfig().isEmpty
        if ready {
            appendExtLog("info: auto-rewire ignored — TURN data plane owns upstream; preserving live flows")
        } else if running {
            appendExtLog("info: auto-rewire ignored — TURN runner is waiting for GETCONF; preserving attach generation")
        } else {
            let freshness = Self.vkTurnCredsFreshness()
            appendExtLog("warn: auto-rewire ignored — TURN runner is stopped (\(freshness.reason)); waiting for explicit refresh/reconnect")
        }
        return true
    }

    private static func vkTurnCredsFreshness() -> (isFresh: Bool, reason: String) {
        if TURNCredsStore.shared.roomsAreFresh {
            let rooms = VKCredsPreferences.roomHashes.count
            return (true, "multi-room credentials fresh rooms=\(rooms)")
        }
        return (false, "multi-room credentials missing, incomplete, or stale")
    }

    /// Rebuilds the samizdat client by re-calling SocksstubSetSamizdatConfig
    /// with the stored config blob. This closes the old client (which closes
    /// TLS+H2 transports tied to the previous interface) and constructs a new
    /// one whose first connect goes via the current default interface.
    private func rewireUpstream() {
        let generation = nextRewireGeneration()
        isRewiring = true
        // Close the policy race before the serialized rewire queue runs.
        // A user switch to TURN must block new H2/direct flows immediately.
        let requestedPolicy = Self.upstreamPolicy(mode: EndpointModeStore.current, backup: backupBlob)
        if requestedPolicy.usesTURN {
            SocksstubSetVKTurnRequired(true)
        }
        appendExtLog("info: rewire gen=\(generation) queued")

        rewireQueue.async { [weak self] in
            guard let self else { return }
            guard self.rewireGeneration == generation else {
                self.appendExtLog("info: rewire gen=\(generation) skipped — superseded before start")
                return
            }
            let mode = EndpointModeStore.current
            let policy = Self.upstreamPolicy(mode: mode, backup: self.backupBlob)
            let blob = Self.pick(mode: mode, primary: self.primaryBlob, backup: self.backupBlob)
            guard !blob.isEmpty else {
                self.appendExtLog("warn: rewire gen=\(generation) skipped — empty config blob")
                self.finishRewireGeneration(generation)
                return
            }

            self.appendExtLog("info: rewire gen=\(generation) start mode=\(mode.rawValue) effective=\(policy.effectiveEndpoint.rawValue) upstream=\(policy.upstream.rawValue)")

            // TURN closes its fallback gate before detach. H2 opens the gate
            // only after stale TURN is detached, so neither transition has a
            // window on the wrong data plane.
            if policy.usesTURN {
                SocksstubSetVKTurnRequired(true)
            }

            // Every authoritative rewire owns the current data-plane lifecycle.
            // H2 must clear a stale TURN netstack; TURN must drain and recreate
            // its relay sockets on the new NWPath instead of "rewiring" only
            // the dormant H2 client. Ping-prober callbacks never reach here in
            // TURN mode, so this cannot create the old 11-second restart loop.
            SocksstubStopVKTurnUpstream()
            if !policy.usesTURN {
                SocksstubSetVKTurnRequired(false)
            }
            guard self.rewireGeneration == generation else {
                self.appendExtLog("info: rewire gen=\(generation) stopped after TURN drain — superseded")
                return
            }

            var err: NSError?
            SocksstubSetSamizdatConfig(blob, &err)
            if let err {
                self.appendExtLog("error: rewire gen=\(generation) SetSamizdatConfig: \(err.localizedDescription)")
                self.finishRewireGeneration(generation)
                return
            }
            guard self.rewireGeneration == generation else {
                self.appendExtLog("info: rewire gen=\(generation) skipped after config — superseded before attach")
                return
            }

            if policy.usesTURN {
                Self.attachVKTurnUpstream(resolvedPeer: self.resolvedPeer)
            }

            self.appendExtLog("info: rewire gen=\(generation) ok — fresh samizdat client warmed")

            // IPA-D17: after the new upstream policy is in place,
            // force-close every loopback SOCKS5 flow that hev opened over
            // the OLD path. Apps see RST → reconnect immediately on the
            // fresh H2 or TURN path instead of hanging on dead streams.
            let closed = SocksstubCloseAllFlows()
            self.appendExtLog("info: rewire gen=\(generation) force-closed \(closed) stale flows")
            self.finishRewireGeneration(generation)
        }
    }

    private func nextRewireGeneration() -> Int {
        rewireGenerationLock.withLock {
            $0 += 1
            return $0
        }
    }

    private func finishRewireGeneration(_ generation: Int) {
        if rewireGeneration == generation {
            isRewiring = false
        }
    }

    private static func whitelistModeRaw() -> String {
        UserDefaults(suiteName: appGroupID)?
            .string(forKey: "tamizdat.whitelistMode") ?? "h2Backup"
    }

    private static func whitelistTargetConfigured(backup: String?, whitelistModeRaw: String) -> Bool {
        // H2 whitelist needs an explicit backup tamizdat:// URI. VK TURN does
        // not: peer host + password are derived from the Main URI and TURN
        // session params live in App Group storage. Treating nil backup as "primary"
        // here made manual Restricted+Relay silently run H2/Main.
        backup != nil || whitelistModeRaw == "vkTurn"
    }

    private static func effectiveEndpoint(mode: EndpointMode, backup: String?, whitelistModeRaw: String) -> EndpointMode {
        let hasWhitelistTarget = whitelistTargetConfigured(backup: backup, whitelistModeRaw: whitelistModeRaw)
        switch mode {
        case .primary:
            return .primary
        case .backup:
            return hasWhitelistTarget ? .backup : .primary
        case .auto:
            guard hasWhitelistTarget else { return .primary }
            return WhitelistStatusStore.trustedAutoEndpoint
        }
    }

    private static func upstreamPolicy(mode: EndpointMode, backup: String?) -> UpstreamPolicy {
        let whitelist = whitelistModeRaw()
        let effective = effectiveEndpoint(mode: mode, backup: backup, whitelistModeRaw: whitelist)
        let upstream: EffectiveUpstream = (effective == .backup && whitelist == "vkTurn") ? .turn : .h2
        return UpstreamPolicy(endpointMode: mode, effectiveEndpoint: effective, whitelistModeRaw: whitelist, upstream: upstream)
    }

    /// Picks the appropriate blob for a given mode. In manual modes
    /// (.primary/.backup) it follows the user's pick. In .auto mode it
    /// honours WhitelistStatusStore.activeEndpoint — which the
    /// WhitelistDetector flips between .primary and .backup based on
    /// the cascade probe verdict.
    private static func pick(mode: EndpointMode, primary: String, backup: String?) -> String {
        switch mode {
        case .primary:
            return primary
        case .backup:
            return backup ?? primary
        case .auto:
            return WhitelistStatusStore.trustedAutoEndpoint == .backup
                ? (backup ?? primary)
                : primary
        }
    }

    // MARK: – WhitelistDetector lifecycle

    /// Starts the detector iff EndpointModeStore.current == .auto AND a
    /// whitelist target is configured: H2 backup URI or VK TURN via Main URI.
    /// Idempotent — calling again while the detector is already running is a no-op.
    private func startWhitelistDetectorIfNeeded() {
        let mode = EndpointModeStore.current
        let whitelistRaw = Self.whitelistModeRaw()
        let hasWhitelistTarget = Self.whitelistTargetConfigured(backup: backupBlob, whitelistModeRaw: whitelistRaw)
        appendExtLog("info: detector lifecycle check: mode=\(mode.rawValue) hasBackup=\(backupBlob != nil) whitelistMode=\(whitelistRaw) hasWhitelistTarget=\(hasWhitelistTarget) running=\(whitelistDetector != nil)")
        guard mode == .auto else {
            // Mode is not auto → stop if it was running, paint badge as unknown
            // so the UI doesn't keep showing a stale verdict.
            if whitelistDetector != nil {
                appendExtLog("info: detector stopping (mode is \(mode.rawValue), not auto)")
                whitelistDetector?.stop()
                whitelistDetector = nil
            }
            WhitelistStatusStore.current = .unknown
            return
        }
        guard hasWhitelistTarget else {
            // Auto requested but there is no target to fail over TO.
            // H2 mode needs a saved backup URI; TURN mode is valid without
            // one because it derives peer/password from the Main URI.
            appendExtLog("warn: detector NOT started — auto mode requested but no whitelist target configured (set Whitelist mode=TURN or save backup URL)")
            if whitelistDetector != nil {
                whitelistDetector?.stop()
                whitelistDetector = nil
            }
            WhitelistStatusStore.current = .unknown
            return
        }
        if whitelistDetector != nil {
            appendExtLog("info: detector already running")
            return
        }
        let detector = WhitelistDetector(
            log: { [weak self] line in self?.appendExtLog(line) },
            switchEndpoint: { [weak self] target in
                guard let self else { return }
                // The detector already wrote WhitelistStatusStore.activeEndpoint
                // before calling us; just trigger the rewire to apply it.
                self.appendExtLog("info: detector requested switch → \(target.rawValue)")
                self.rewireUpstream()
            },
            pathProvider: { [weak self] in self?.pathMonitor.currentPath }
        )
        // Seed with current path status/fingerprint so first-cycle decisions
        // cannot inherit confidence from another physical path.
        detector.notePathChange(
            satisfied: lastPathSatisfied,
            fingerprint: lastPathInterfaceID ?? "uninitialized"
        )
        whitelistDetector = detector
        detector.start()
    }

    override func handleAppMessage(_ messageData: Data,
                                   completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? "ping"
        switch cmd {
        case "ping":
            completionHandler?("pong".data(using: .utf8))
        case "switchEndpoint":
            // IPA-P: main app updated EndpointModeStore in App Group
            // UserDefaults; we re-read and rewire to the new endpoint.
            let mode = EndpointModeStore.current
            appendExtLog("info: app requested endpoint switch → \(mode.rawValue)")
            // IPA-Q: also start/stop the WhitelistDetector based on
            // whether auto mode is now selected.
            startWhitelistDetectorIfNeeded()
            rewireUpstream()
            completionHandler?("switched:\(mode.rawValue)".data(using: .utf8))
        case "refreshSamizdatClient":
            // IPA-D22: pool-variant UI deleted. Path retained for
            // future cases where the app wants to force a samizdat
            // client rebuild; pool variant is now hardcoded V1 in the
            // setInProcessSocks bootstrap.
            appendExtLog("info: app requested samizdat refresh")
            SocksstubSetPoolVariant("v1")
            rewireUpstream()
            completionHandler?("refreshed".data(using: .utf8))
        case "refreshPingURL":
            // IPA-D21: SettingsView's ping-probe URL field changed in the
            // main app. Re-read from App Group UserDefaults and push into
            // Go-side. Prober picks it up on the next tick — no need to
            // rebuild the samizdat client.
            let url = PingURLPreferences.url
            appendExtLog("info: app requested ping URL refresh → \(url)")
            SocksstubSetPingProbeURL(url)
            completionHandler?("pingURLRefreshed".data(using: .utf8))
        case "refreshWhitelistProbes":
            // IPA-D23: SettingsView's restricted-profile probe targets changed.
            // Re-read prefs and tell the detector to adopt them. The
            // excludedRoutes change requires a tunnel reconnect to take
            // effect (we don't currently rebuild network settings live);
            // the UI shows a disclaimer about that.
            appendExtLog("info: app requested whitelist probes refresh → foreign=\(WhitelistProbePreferences.testHost) domestic=\(WhitelistProbePreferences.whitelistHost)")
            whitelistDetector?.applyConfig()
            completionHandler?("whitelistProbesRefreshed".data(using: .utf8))
        case "refreshVKTurnCreds":
            // Main app fetched fresh VK TURN session params and wrote them to the
            // App Group. The active runner lives in THIS extension
            // process, so update it here; calling the gomobile bridge
            // in the main app only touches that process' idle Go runtime.
            appendExtLog("info: app requested VK TURN creds refresh")
            let policy = Self.upstreamPolicy(mode: EndpointModeStore.current, backup: backupBlob)
            guard policy.usesTURN else {
                SocksstubStopVKTurnUpstream()
                SocksstubSetVKTurnRequired(false)
                appendExtLog("info: VK TURN creds refresh ignored by policy — effective=\(policy.effectiveEndpoint.rawValue) whitelistMode=\(policy.whitelistModeRaw), H2 active")
                completionHandler?("turnDisabled:\(policy.effectiveEndpoint.rawValue)".data(using: .utf8))
                return
            }
            SocksstubSetVKTurnRequired(true)

            let result = Self.refreshVKTurnCredsFromAppGroup()
            if result == "not running" {
                // If the tunnel started before VK session params existed,
                // attachVKTurnUpstream() skipped. A later successful
                // refresh should start the runner immediately, but only
                // while the effective endpoint is Restricted+Relay.
                appendExtLog("info: VK TURN creds refreshed while runner was stopped; starting attach path")
                let attachResult = Self.attachVKTurnUpstream(resolvedPeer: resolvedPeer)
                let response = attachResult == "previous runner still draining" ? "attachPendingDrain" : (attachResult.isEmpty ? "attachStarted" : attachResult)
                completionHandler?(response.data(using: .utf8))
            } else {
                completionHandler?(result.data(using: .utf8))
            }
        case "restartVKTurnUpstream":
            // Settings → VK TURN workers changed. Workers are only read
            // at runner construction, so apply them by stopping the
            // current TURN runner and starting a fresh attach if TURN is
            // the active policy. H2/Main users just keep the saved value
            // for the next Restricted+Relay connect.
            let policy = Self.upstreamPolicy(mode: EndpointModeStore.current, backup: backupBlob)
            appendExtLog("info: app requested VK TURN restart → rooms=\(VKCredsPreferences.roomHashes.count) workersPerRoom=20 effective=\(policy.effectiveEndpoint.rawValue) whitelistMode=\(policy.whitelistModeRaw)")
            guard policy.usesTURN else {
                SocksstubStopVKTurnUpstream()
                SocksstubSetVKTurnRequired(false)
                completionHandler?("turnDisabled:\(policy.effectiveEndpoint.rawValue)".data(using: .utf8))
                return
            }
            SocksstubSetVKTurnRequired(true)
            SocksstubStopVKTurnUpstream()
            let defaults = UserDefaults(suiteName: "group.com.anarki.samizdat-test")
            let roomBundleJSON = TURNCredsStore.shared.validatedRoomBundleJSON()
            let hasBundle = roomBundleJSON?.isEmpty == false
            let hasLegacy = defaults?.string(forKey: "tamizdat.vkTURNCredsJSON")?.isEmpty == false
            let configuredRoomCount = VKCredsPreferences.roomHashes.count
            let bundleRoomCount = Self.roomCount(inBundleJSON: roomBundleJSON)
            if configuredRoomCount > 1 && bundleRoomCount != configuredRoomCount {
                appendExtLog("warn: VK TURN restart skipped — incomplete multi-room bundle bundleRooms=\(bundleRoomCount) configured=\(configuredRoomCount)")
                completionHandler?("noCreds".data(using: .utf8))
                return
            }
            let hasRequiredCredentials = configuredRoomCount > 1 ? hasBundle : (hasBundle || hasLegacy)
            guard hasRequiredCredentials else {
                appendExtLog("warn: VK TURN restart skipped — no credential payload in App Group")
                completionHandler?("noCreds".data(using: .utf8))
                return
            }
            let attachResult = Self.attachVKTurnUpstream(resolvedPeer: resolvedPeer)
            let response = attachResult == "previous runner still draining" ? "attachPendingDrain" : (attachResult.isEmpty ? "attachStarted" : attachResult)
            completionHandler?(response.data(using: .utf8))
        case "status":
            // IPA-Z (D21 update): main-screen lamp polls this every 500 ms.
            // Snapshot is built from in-process Socksstub*() getters which
            // read tamizdat.Client + ping-prober atomic state — no locks,
            // no I/O. Field names must stay in sync with
            // TamizdatStatusSnapshot in TamizdatStatusStore.swift.
            //
            // D21: rttBulk/rttLite/liteAlive/lockedFlows kept in the JSON
            // (no harm) but no longer read on the Swift side — the lamp
            // now uses the ping snapshot fields. Old fields will be
            // dropped in a future cleanup commit once the v0.2.D21 IPA is
            // rolled out and no skewed clients remain in the wild.
            SocksstubNoteForegroundPoll()
            let pingSnap = SocksstubPingProbeSnapshot()
            // IPA-D22: include hev cumulative byte counters + uptime so
            // the main-app Data + Uptime stat tiles can render without
            // any extra RPC. `hev_socks5_tunnel_stats` semantics on the
            // iOS side: tx = packets/bytes from utun (app→remote), rx
            // = packets/bytes back. We expose both as "rxBytes" and
            // "txBytes"; the main app sums them for the Data tile and
            // diffs them for the rate readout.
            var tx_pkts = 0, tx_bytes = 0, rx_pkts = 0, rx_bytes = 0
            hev_socks5_tunnel_stats(&tx_pkts, &tx_bytes, &rx_pkts, &rx_bytes)
            let uptime: Int64
            if let started = self.tunnelStartedAt {
                uptime = Int64(Date().timeIntervalSince(started))
            } else {
                uptime = 0
            }
            // Runtime status must be tunnel-authoritative (Go `vkturnRequired`);
            // App Group prefs are published separately as the requested/next policy.
            // Otherwise changing prefs while a TURN tunnel is live hides the UI amber
            // `active < expected` gate (build-326 review blocker).
            let turnRequiredNow = SocksstubVKTurnRequired()
            let mode = EndpointModeStore.current
            let policy = Self.upstreamPolicy(mode: mode, backup: backupBlob)
            let turnRunning = SocksstubTURNUpstreamRunning()
            let turnNetstackReady = !SocksstubTURNUpstreamWGConfig().isEmpty
            let actualUpstream = turnRequiredNow
                ? (turnNetstackReady ? "turn" : "turn-pending")
                : "h2"
            let turnStats: (active: Int, expected: Int, quotaStorm: Bool) = {
                let fallbackExpected = VKCredsPreferences.roomHashes.count * VKCredsPreferences.workersPerRoom
                let raw = SocksstubTURNUpstreamStatsJSON()
                guard let data = raw.data(using: .utf8),
                      let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
                else { return (0, fallbackExpected, false) }
                let active = object["active"] as? Int ?? 0
                let reportedExpected = object["expected"] as? Int ?? 0
                let expected = reportedExpected > 0 ? reportedExpected : fallbackExpected
                let quotaStorm = object["quota_storm"] as? Bool ?? false
                return (max(0, active), max(0, expected), quotaStorm)
            }()
            // H2 ping state is irrelevant in TURN-only mode and can be stale
            // from a previous policy. Keep it neutral instead of letting an
            // old H2 failure paint the TURN connection as failed.
            let pingMs = turnRequiredNow ? -1 : Int(pingSnap?.lastMs ?? -1)
            let pingOK = turnRequiredNow ? false : (pingSnap?.ok ?? false)
            let pingFailed = turnRequiredNow ? false : (pingSnap?.failed ?? false)
            let payload: [String: Any] = [
                "realShape":   turnRequiredNow ? "turn" : SocksstubRealShapeMode(),
                "lockedFlows": Int(SocksstubLockedRealtimeFlows()),
                "liteAlive":   Int(SocksstubLiteAlive()),
                "rttLiteMs":   Int(SocksstubRTTLiteP50Ms()),
                "rttBulkMs":   Int(SocksstubRTTBulkP50Ms()),
                // IPA-D21 ping-prober fields.
                "pingMs":      pingMs,
                "pingOK":      pingOK,
                "pingFailed":  pingFailed,
                "pingURL":     pingSnap?.url ?? "",
                // IPA-D22 stat-tile + reconnecting fields.
                "rxBytes":     Int64(rx_bytes),
                "txBytes":     Int64(tx_bytes),
                "uptimeSec":   uptime,
                "isRewiring":  self.isRewiring ? 1 : 0,
                "rewireGeneration": self.rewireGeneration,
                "endpointMode": mode.rawValue,
                "effectiveEndpoint": policy.effectiveEndpoint.rawValue,
                "requestedUpstream": policy.upstream.rawValue,
                "desiredUpstream": turnRequiredNow ? "turn" : "h2",
                "upstreamKind": actualUpstream,
                "turnRunning": turnRunning ? 1 : 0,
                "turnNetstackReady": turnNetstackReady ? 1 : 0,
                "turnActiveWorkers": turnStats.active,
                "turnExpectedWorkers": turnStats.expected,
                "turnWorkers": turnStats.expected,
                "turnQuotaStorm": turnStats.quotaStorm,
                // VK TURN relay session parameter status. IPA-D65b: the main
                // app now acquires session params itself via WKWebView verification challenge
                // solving and writes them to App Group UserDefaults
                // (`TURNSession paramsStore`). The extension only READS the
                // cache here — no VK API touch from inside the NE.
                // The legacy `SocksstubTURNSession paramsSnapshot()` is kept on
                // the Go side as a no-op fallback for now but is no
                // longer the source of truth.
                "hasTURNCreds": TURNCredsStore.shared.isFresh,
            ]
            let json = (try? JSONSerialization.data(withJSONObject: payload)) ?? Data()
            completionHandler?(json)
        default:
            completionHandler?(Data())
        }
    }

    // MARK: – hev invocation

    private func startHev(configBlob: String, completionHandler: @escaping (Error?) -> Void) {
        // hev's YAML config. iOS knobs from heiher's published memory-tuning
        // recommendations (issue #109): tiny task stacks, small TCP buffer,
        // bounded session count. socks5 endpoint = our main-app SOCKS5
        // listener on localhost. UDP-over-TCP keeps memory bounded for
        // QUIC-heavy traffic.
        // Notes from the Path 3 audit:
        //   - lwIP needs an explicit ipv4 in the tunnel block on some
        //     code paths, otherwise it silently drops packets.
        //   - connect-timeout 2 s (down from 5) — first DNS query
        //     should not stall 5 s on a brief startup race.
        // IPA-A7: revert A4's hev YAML caps. The 2nd analyst's review
        // identified A4's `tcp-buffer-size: 16 KiB` as the smoking gun
        // for Go heap explosion in the A4 log: lwIP outbound buffer
        // (16 KiB) was too small relative to Go h2 stream window
        // (64 KiB), producing backpressure pile-up that pinned 200
        // streams × ~100 KB = 20+ MiB of "released-but-stuck" Go state.
        // A5 added pcs eviction but kept the YAML, so heap explosions
        // continued under load.
        //
        // Back to defaults — let lwIP run with its standard 64 KiB
        // tcp-buffer matched against Go's 64 KiB stream window. The
        // pcs-map leak (the original A3 9-min YouTube cause) is still
        // bounded by Phase A in IPA-A5.
        //
        // Only retained: task-stack-size 24 KiB (default 84 KiB,
        // historic iOS budget choice — out of scope to revisit).
        // Key the cap on TURN *capability*, not the instantaneous effective
        // policy: HEV reads this YAML once at tunnel start, while the endpoint
        // can live-switch H2<->TURN later without a tunnel restart. A
        // TURN-capable tunnel always gets the room-based cap so a switch into
        // 3-4-room TURN can never leave HEV holding an H2-sized session
        // backlog under memory pressure.
        let policy = Self.upstreamPolicy(mode: EndpointModeStore.current, backup: backupBlob)
        let turnCapable = policy.usesTURN || policy.whitelistModeRaw == "vkTurn"
        let configuredRoomCount = VKCredsPreferences.roomHashes.count
        let maxSessionCount: Int
        if turnCapable {
            if configuredRoomCount <= 1 {
                maxSessionCount = 160
            } else if configuredRoomCount == 2 {
                maxSessionCount = 128
            } else {
                maxSessionCount = 96
            }
        } else {
            maxSessionCount = 500
        }
        appendExtLog("info: hev max-session-count=\(maxSessionCount) turnCapable=\(turnCapable) upstream=\(policy.upstream.rawValue) configuredRooms=\(configuredRoomCount)")
        let yaml = """
tunnel:
  mtu: 1280
  ipv4: '198.18.0.1'

socks5:
  port: \(Self.socksPort)
  address: '127.0.0.1'
  udp: 'tcp'

misc:
  task-stack-size: 24576
  # HEV 2.14.4 conf/main.yml defines this key; align it with Go socksFlowLimit.
  max-session-count: \(maxSessionCount)
  # IPA-R1: clamp HEV native buffers (defaults: tcp-buffer-size 65536,
  # udp-recv-buffer-size 524288). This memory is lwIP/kernel side and NOT
  # governed by the Go SetMemoryLimit; at the session caps above the old
  # defaults alone could pin 6-18 MB during a speed test. hev's lwIP leg
  # terminates on-device (microsecond RTT), so 32 KiB windows do not cap
  # end-to-end throughput — backpressure lives on the TURN/netstack side.
  tcp-buffer-size: 32768
  udp-recv-buffer-size: 131072
  log-level: 'info'
  connect-timeout: 2000
  # HEV 2.14.4 exposes protocol-specific timeout keys in conf/main.yml. Keep
  # idle TCP control channels (for example AnyDesk HID) alive for five minutes
  # while retaining HEV's 60s UDP idle reclamation.
  tcp-read-write-timeout: 300000
  udp-read-write-timeout: 60000
"""
        appendExtLog("info: hev config built (\(yaml.utf8.count) bytes)")

        // IPA-A1: direct utun fd handoff to hev. Same pattern as
        // Tun2SocksKit, Shadowrocket, sing-box-with-hev configs etc.
        // KVO `socket.fileDescriptor` is the well-known private API
        // every shipping iOS network adapter app uses — wireguard-apple,
        // sing-box-for-apple, Tun2SocksKit. Apple has not deprecated it.
        // Fallback fd-scanner kept as diagnostic for the rare case KVO
        // returns nil (typically when iCloud Private Relay's utun
        // shadows ours).
        let kvoFD = (self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32) ?? -1
        let scanFD = Self.findTunnelFileDescriptor(log: { line in self.appendExtLog(line) }) ?? -1
        appendExtLog("info: utun fd kvo=\(kvoFD) scan=\(scanFD)")
        let fd: Int32
        if kvoFD >= 0 {
            fd = kvoFD
        } else if scanFD >= 0 {
            appendExtLog("warn: KVO fd unavailable, falling back to scan")
            fd = scanFD
        } else {
            appendExtLog("error: could not locate utun fd (KVO + scan both failed)")
            completionHandler(makeError("utun fd not found"))
            return
        }
        appendExtLog("info: utun fd selected = \(fd)")

        // Verify main app's SOCKS5 listener is reachable before handing
        // packets to hev. If the app hasn't started SocksStubStart yet,
        // fail fast with a clear error so the user sees "open the app".
        if !Self.probeSocks5(port: Self.socksPort, timeout: 1.0) {
            appendExtLog("error: SOCKS5 listener not reachable on 127.0.0.1:\(Self.socksPort) — open the main app first")
            completionHandler(makeError("Open the Samizdat app first to start the SOCKS5 listener."))
            return
        }
        appendExtLog("info: SOCKS5 reachable; handing packets to hev")

        startSwiftHeartbeat()
        startBurstProtection()  // IPA-D2
        startPathMonitor()
        startWhitelistDetectorIfNeeded()
        isRunning = true
        // IPA-D22: anchor uptime for the main-app Uptime stat tile.
        tunnelStartedAt = Date()

        // hev_socks5_tunnel_main_from_str blocks until quit. Run it on a
        // dedicated background queue.
        let yamlCopy = yaml
        hevQueue.async { [weak self] in
            let rc = yamlCopy.withCString { cstr -> Int32 in
                hev_socks5_tunnel_main_from_str(cstr, UInt32(yamlCopy.utf8.count), fd)
            }
            self?.appendExtLog("info: hev returned rc=\(rc)")
            self?.runningState.withLock { $0 = false }
        }

        // hev itself does not have a "ready" callback — it starts
        // accepting packets immediately on the fd. Synchronous return.
        completionHandler(nil)
    }

    // MARK: – utun fd discovery

    /// Enumerates open file descriptors and returns the highest-numbered
    /// utun fd, logging every candidate it finds along the way (with
    /// the utun unit number from `sc_unit`). On iOS 17+ with iCloud
    /// Private Relay this routinely returns the wrong fd because
    /// Apple's relay utun has a higher fd than ours. KVO is the
    /// preferred path; this scanner survives only as a diagnostic
    /// fallback.
    private static func findTunnelFileDescriptor(log: (String) -> Void) -> Int32? {
        var ctlInfo = ctl_info()
        withUnsafeMutablePointer(to: &ctlInfo.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        var best: Int32 = -1
        var found: [String] = []
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var ret: Int32 = -1
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    ret = getpeername(fd, $0, &len)
                }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM {
                continue
            }
            if ctlInfo.ctl_id == 0 {
                ret = ioctl(fd, CTLIOCGINFO, &ctlInfo)
                if ret != 0 {
                    continue
                }
            }
            if addr.sc_id == ctlInfo.ctl_id {
                // sc_unit is 1-based: utun(N-1).
                let unit = Int(addr.sc_unit) - 1
                found.append("fd=\(fd)→utun\(unit)")
                if fd > best {
                    best = fd
                }
            }
        }
        log("info: utun candidates: [\(found.joined(separator: ", "))]")
        return best >= 0 ? best : nil
    }

    /// Resolve every current IPv4 answer for a probe target so DNS answer
    /// ordering cannot make the Go dialer select an address that was not
    /// excluded when tunnel settings were installed.
    private static func resolveProbeTargetIPv4(_ target: String, log: (String) -> Void) -> [String] {
        let trimmed = target.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return [] }
        var v4 = in_addr()
        if inet_pton(AF_INET, trimmed, &v4) == 1 {
            return [trimmed]
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, trimmed, &v6) == 1 {
            log("info: probe target \(trimmed) is IPv6 literal — skipping v4 exclusion")
            return []
        }

        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        let sem = DispatchSemaphore(value: 0)
        var found: [String] = []
        DispatchQueue.global(qos: .utility).async {
            var res: UnsafeMutablePointer<addrinfo>?
            defer { if let res = res { freeaddrinfo(res) } }
            guard getaddrinfo(trimmed, nil, &hints, &res) == 0 else {
                sem.signal()
                return
            }
            var cursor = res
            var seen = Set<String>()
            while let item = cursor {
                if item.pointee.ai_family == AF_INET, let raw = item.pointee.ai_addr {
                    var addr = raw.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                        $0.pointee.sin_addr
                    }
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                        let ip = String(cString: buf)
                        if seen.insert(ip).inserted { found.append(ip) }
                    }
                }
                cursor = item.pointee.ai_next
            }
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 2.0)
        return found
    }

    /// Best-effort TCP probe to see if the main app's SOCKS5 listener is up
    /// before we hand packets to hev. Avoids a 60-second hev timeout for
    /// each early flow when the app isn't running.
    private static func probeSocks5(port: UInt16, timeout: TimeInterval) -> Bool {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard s >= 0 else { return false }
        defer { close(s) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        // Non-blocking connect with timeout.
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)

        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc == 0 { return true }
        if errno != EINPROGRESS { return false }

        // Wait for write-ready or timeout.
        var fdSet = fd_set()
        __darwin_fd_set(s, &fdSet)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: __darwin_suseconds_t((timeout - floor(timeout)) * 1_000_000))
        let sel = select(s + 1, nil, &fdSet, nil, &tv)
        if sel <= 0 { return false }

        // Check SO_ERROR.
        var err: Int32 = 0
        var elen = socklen_t(MemoryLayout<Int32>.size)
        if getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &elen) != 0 { return false }
        return err == 0
    }

    // MARK: – Network settings

    private func makeNetworkSettings(serverIP: String?) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = serverIP ?? "127.0.0.1"
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        settings.mtu = 1280

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        if let serverIP {
            ipv4.excludedRoutes = [NEIPv4Route(destinationAddress: serverIP, subnetMask: "255.255.255.255")]
        }
        // Critically: exclude 127.0.0.1/8 from the tunnel so hev's SOCKS5
        // dial to the main app's listener does NOT loop back through us.
        // (iOS may special-case loopback here but explicit is safer.)
        var excluded: [NEIPv4Route] = (ipv4.excludedRoutes ?? []) + [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]
        // IPA-D23: dynamic WhitelistDetector probe-target exclusions.
        // Comparative detector settings are comma/semicolon/newline-separated
        // target lists; exclude each individual resolved IPv4. If one hostname
        // fails to resolve, skip only that host.
        var probeTargets: [String] = []
        probeTargets.append(contentsOf: WhitelistProbePreferences.foreignControlTargets)
        probeTargets.append(contentsOf: WhitelistProbePreferences.domesticAllowlistedTargets)
        var addedProbeIPs = Set<String>()
        var pinnedProbeIPs: [String: String] = [:]
        for target in probeTargets {
            let host = target.trimmingCharacters(in: .whitespacesAndNewlines)
            let key = host.lowercased()
            let ips = Self.resolveProbeTargetIPv4(host, log: appendExtLog)
            if ips.isEmpty {
                appendExtLog("warn: probe target \(host) — could not resolve to IPv4, route skipped")
                continue
            }
            pinnedProbeIPs[key] = ips[0]
            for ip in ips {
                if addedProbeIPs.contains(ip) {
                    appendExtLog("info: probe target \(host) → \(ip) already excluded (deduped)")
                    continue
                }
                addedProbeIPs.insert(ip)
                appendExtLog("info: probe target \(host) → excludedRoute \(ip)/32")
                excluded.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
            }
        }
        // INVARIANT: the pinned map and excludedRoutes above are built from
        // the SAME resolve pass in this loop. The detector dials exactly these
        // IPs, so its traffic provably egresses the physical carrier path. If
        // route exclusion and pinning are ever split apart, the probe can fall
        // back onto tunnel DNS/routing and the allowlist verdict goes blind.
        WhitelistProbePinnedStore.set(pinnedProbeIPs)
        appendExtLog("info: whitelist probe pinned \(pinnedProbeIPs.count) target IPs to physical path")
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4

        // No IPv6 — see Phase 2.5 rationale; v4-only tunnel is unambiguous.
        settings.ipv6Settings = nil

        // IPA-J: force DNS through the tunnel.
        //
        // Earlier (IPA-F) we set dnsSettings = nil on the theory that iOS
        // mDNSResponder would scope DNS queries to the underlying Wi-Fi
        // interface (IP_BOUND_IF) and alternate path the tunnel. On iOS 17/18 with
        // a default-route VPN, this is not what happens: with no
        // dnsSettings installed, iOS treats name resolution as broken
        // ("iPhone не подключен к интернету"), the captive-portal probe
        // to captive.apple.com fails, and Safari refuses to load even
        // direct-IP URLs.
        //
        // Now that IPA-I added cmd=0x05 / FWD_UDP support in SocksStub
        // backed by samizdat.Client.DialUDP, we can safely force DNS
        // (UDP/53) through the tunnel: hev wraps it as cmd=0x05, our
        // SocksStub opens a samizdat UDP tunnel to the configured
        // rehandler, and the response comes back the same way.
        //
        // IPA-D22 fix3 (DNS leak): the rehandler IPs were 1.1.1.1 + 8.8.8.8
        // — the SAME IPs we exclude above for WhitelistDetector canary.
        // Result: iOS sent DNS queries to 1.1.1.1, routing matched
        // excludedRoutes, packets went OUT VIA PHYSICAL Wi-Fi/cellular
        // (RU ISP), Cloudflare anycast saw RU client and returned
        // RU-close CDN edges. App then opened TCP to that RU-close IP
        // via tunnel → exit Finland → server saw Finland IP for an
        // RU-edge destination → mismatch → ChatGPT/CDN refusals.
        //
        // Use Cloudflare/Google SECONDARY IPs (1.0.0.1, 8.8.4.4) for
        // DNS-via-tunnel. They are anycast and unrelated to canary IPs
        // in excludedRoutes, so they resolve cleanly through the tunnel
        // and the upstream-server (Finland exit) is the query source.
        // GeoDNS therefore returns Finland-close edges; subsequent TCP
        // is consistent with the tunnel exit IP.
        //
        // IPA-DNS-LEAK-FIX (2026-05-11): the previous fix3 set
        // `matchDomains = [""]` but did NOT set `matchDomainsNoSearch =
        // true`. On iOS 17/18 with split-DNS semantics this is the
        // documented difference between "every query goes to our DNS"
        // vs "iOS still consults the system rehandler in parallel /
        // first for FQDNs". Production iOS network adapter clients (sing-box-
        // for-apple ExtensionProvider.swift, Hiddify, Streisand) all
        // set BOTH flags together — empty matchDomain alone is not a
        // reliable catch-all on iOS. The leak manifested as ChatGPT
        // and Roblox refusing the iPhone: app got a Russia-biased CDN
        // IP from the leaked system DNS query (RU ISP rehandler
        // returning RU-edge), then opened TCP to that RU-edge IP via
        // tunnel → exit IP Finland but destination is RU-edge of CDN
        // → CDN sees geo-mismatch → block. Setting
        // matchDomainsNoSearch=true forces ALL DNS through the tunnel
        // so the IPs the app receives are Finland-edge from the start.
        //
        // Refs:
        //   https://sing-box.sagernet.org/configuration/dns/  (catch-all pattern)
        //   sing-box-for-apple/ExtensionProvider/include/ExtensionProvider.swift
        //   Apple NEDNSSettings docs:
        //     matchDomainsNoSearch=true means "treat matchDomains as a
        //     pure rehandler-selection filter, do NOT also add them to
        //     the system search list" — which is exactly what we want
        //     for [""] catch-all (otherwise iOS treats "" as a search
        //     suffix and alternate path FQDNs).
        let dns = NEDNSSettings(servers: ["1.0.0.1", "8.8.4.4"])
        dns.matchDomains = [""]
        dns.matchDomainsNoSearch = true
        settings.dnsSettings = dns

        return settings
    }

    // MARK: – Logging (App Group file)

    private func openLogSink() {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupID
        ) else { return }
        let logURL = containerURL.appendingPathComponent(Self.logFileName)
        // Truncate per-session — the app reads the file from offset 0 on
        // bridge start, so a fresh file per tunnel is what we want.
        try? Data().write(to: logURL, options: .atomic)
        if let h = try? FileHandle(forWritingTo: logURL) {
            try? h.seekToEnd()
            swiftLogHandle = h
        }
    }

    private func startBurstProtection() {
        // IPA-D7: nuclear close pattern from sing-box-for-apple.
        // IPA-D9: dump one heap profile per pressure episode. iOS may
        // repeatedly deliver `.critical`; the shared cooldown below prevents
        // a GC/profile/flow-close feedback loop.
        pressureRecoveryTask.withLock {
            $0?.cancel()
            $0 = nil
        }
        memoryPressureState.withLock { $0 = MemoryPressureState() }
        let q = DispatchQueue(label: "com.anarki.samizdat-test.burst", qos: .userInitiated)
        let src = DispatchSource.makeMemoryPressureSource(eventMask: [.critical], queue: q)
        src.setEventHandler { [weak self] in
            _ = self?.handleCriticalMemoryPressure(reason: "kernel-critical")
        }
        src.activate()
        self.memPressureSrc = src
    }

    private func handleCriticalMemoryPressure(reason: String) -> Bool {
        let now = Date()
        // Capture ownership before any side effect: a handler delivered just
        // before Disconnect must not stop TURN/flows of the next tunnel.
        let handlerTunnelGeneration = Self.turnTunnelGenerationLock.withLock { $0 }
        let decision = memoryPressureState.withLock { state -> (run: Bool, dump: Bool, scheduleRecovery: Bool, manualRecovery: Bool) in
            state.lastCriticalEventAt = now
            guard now.timeIntervalSince(state.lastNuclearCloseAt) >= Self.memoryPressureCooldown else {
                return (false, false, false, false)
            }
            state.lastNuclearCloseAt = now
            let shouldDump = !state.didDumpHeap
            state.didDumpHeap = true
            if state.recoveryScheduled {
                return (true, shouldDump, false, false)
            }
            if state.recoveryAttempted {
                return (true, shouldDump, false, true)
            }
            state.recoveryScheduled = true
            return (true, shouldDump, true, false)
        }
        guard decision.run else { return false }

        // Re-check after the decision: stopTunnel may have advanced the
        // generation while this handler was queued or dumping. The side
        // effects below (stop TURN, close flows, schedule recovery) must
        // never land on the next tunnel's runtime.
        guard Self.turnTunnelGenerationLock.withLock({ $0 }) == handlerTunnelGeneration else {
            appendExtLog("warn: memorypressure CRITICAL reason=\(reason) ignored — tunnel generation changed mid-handler")
            return false
        }

        let availKB = os_proc_available_memory() / 1024
        appendExtLog("error: memorypressure CRITICAL reason=\(reason) avail=\(availKB)KB — entering fail-closed pressure recovery")
        // Preserve the triggering state in the one diagnostic heap before any
        // worker/flow teardown changes it.
        if decision.dump {
            dumpProfileBeforeNuclear(reason: reason)
        }
        // The dump above can stall for hundreds of milliseconds; re-check
        // ownership once more so a Disconnect/Connect completed meanwhile
        // keeps its fresh runtime. (A microsecond race remains between this
        // check and the calls below; its worst case is the pre-recovery
        // behavior — TURN stopped, manual reconnect.)
        guard Self.turnTunnelGenerationLock.withLock({ $0 }) == handlerTunnelGeneration else {
            appendExtLog("warn: memorypressure CRITICAL reason=\(reason) ignored after dump — tunnel generation changed")
            return false
        }
        // Stop is idempotent and also clears a stale netstack whose runner has
        // already exited. Desired TURN policy remains required throughout.
        SocksstubStopVKTurnUpstreamAsync()
        let closed = SocksstubCloseAllFlows()
        appendExtLog("warn: memorypressure CRITICAL reason=\(reason) — stopped TURN and closed \(closed) flows; cooldown=60s")

        if decision.scheduleRecovery {
            scheduleTURNPressureRecovery(pressureAt: now)
        } else if decision.manualRecovery {
            appendExtLog("error: memorypressure repeated after automatic recovery — circuit breaker open; manual reconnect required")
        } else {
            appendExtLog("warn: memorypressure recovery already scheduled; keeping TURN fail-closed")
        }
        return true
    }

    /// One bounded automatic recovery is allowed per Network Extension tunnel
    /// generation. It waits for the old runner's drain/release barrier, the
    /// full 60-second pressure cooldown, and two stable >=20 MiB headroom
    /// samples. A second critical episode opens the circuit breaker instead of
    /// creating a stop/start pressure loop. Room preferences are never reduced.
    /// Pressure state is owned per tunnel generation: startBurstProtection
    /// resets it on every tunnel start. Rewire changes within one tunnel
    /// intentionally do NOT block these writes — an exiting recovery task must
    /// still reset the shared per-tunnel state (e.g. after a rewire or policy
    /// change) or recoveryScheduled would stay latched and both auto-recovery
    /// and the circuit breaker would be dead for the rest of the tunnel.
    private func mutatePressureStateIfOwned(
        tunnelGeneration: Int,
        _ mutate: (inout MemoryPressureState) -> Void
    ) -> Bool {
        Self.turnTunnelGenerationLock.withLock { currentTunnelGeneration -> Bool in
            guard currentTunnelGeneration == tunnelGeneration else { return false }
            memoryPressureState.withLock { state in
                mutate(&state)
            }
            return true
        }
    }

    private func scheduleTURNPressureRecovery(pressureAt: Date) {
        // Tunnel-authoritative gate: recover only what this tunnel actually
        // runs (the Go-side TURN-required flag), never live App Group prefs.
        // The 2026-07-17 field hang (0/80 zombie on the reverted v1) came
        // from recovery consulting instantaneous prefs the user had already
        // flipped for the NEXT connect while the running tunnel was still
        // TURN-required fail-closed.
        guard SocksstubVKTurnRequired() else {
            memoryPressureState.withLock { $0.recoveryScheduled = false }
            appendExtLog("info: memorypressure recovery not scheduled — tunnel is not TURN-required")
            return
        }
        let capturedTunnelGeneration = Self.turnTunnelGenerationLock.withLock { $0 }
        let capturedRewireGeneration = rewireGeneration
        appendExtLog("info: memorypressure auto-recovery scheduled tunnelGeneration=\(capturedTunnelGeneration) rewireGeneration=\(capturedRewireGeneration) rooms=\(VKCredsPreferences.roomHashes.count) cooldown=60s headroom=20MiB")

        let task = Task.detached(priority: .utility) { [weak self] in
            guard let self else { return }
            var stableHeadroomSamples = 0
            var requestedCompaction = false
            var previousLastPressure = pressureAt

            for poll in 1...Self.turnPressureRecoveryMaxPolls {
                if Task.isCancelled { return }
                guard Self.turnTunnelGenerationLock.withLock({ $0 }) == capturedTunnelGeneration,
                      self.isRunning else {
                    // Do not mutate recovery state here: the same provider
                    // object may already have reset it for a newer generation.
                    self.appendExtLog("info: memorypressure auto-recovery cancelled — tunnel generation stopped or changed")
                    return
                }
                guard self.rewireGeneration == capturedRewireGeneration else {
                    let didMutate = self.mutatePressureStateIfOwned(
                        tunnelGeneration: capturedTunnelGeneration
                    ) {
                        $0.recoveryScheduled = false
                        $0.recoveryAttempted = false
                    }
                    guard didMutate else {
                        self.appendExtLog("info: memorypressure auto-recovery state reset skipped, ownership changed")
                        return
                    }
                    self.appendExtLog("info: memorypressure auto-recovery cancelled — authoritative rewire generation changed")
                    return
                }

                // Tunnel-authoritative: the Go TURN-required flag flips only
                // through this tunnel's own wiring (attach/rewire), unlike
                // App Group prefs which describe the NEXT connect.
                guard SocksstubVKTurnRequired() else {
                    let didMutate = self.mutatePressureStateIfOwned(
                        tunnelGeneration: capturedTunnelGeneration
                    ) {
                        $0.recoveryScheduled = false
                        $0.recoveryAttempted = false
                    }
                    guard didMutate else {
                        self.appendExtLog("info: memorypressure auto-recovery state reset skipped, ownership changed")
                        return
                    }
                    self.appendExtLog("info: memorypressure auto-recovery cancelled — tunnel no longer TURN-required (rewired)")
                    return
                }

                let lastPressure = self.memoryPressureState.withLock { max($0.lastNuclearCloseAt, $0.lastCriticalEventAt) }
                if lastPressure > previousLastPressure {
                    previousLastPressure = lastPressure
                    stableHeadroomSamples = 0
                    self.appendExtLog("info: memorypressure auto-recovery cooldown re-armed by repeated pressure")
                }
                let cooldownComplete = Date().timeIntervalSince(lastPressure) >= Self.memoryPressureCooldown
                if !cooldownComplete || SocksstubTURNUpstreamDraining() {
                    do {
                        try await Task.sleep(nanoseconds: Self.turnPressureRecoveryPollNanoseconds)
                    } catch {
                        return
                    }
                    continue
                }

                let availableBeforeCompaction = os_proc_available_memory()
                if availableBeforeCompaction < Self.turnPressureRecoveryHeadroomBytes,
                   !requestedCompaction {
                    // Limit this recovery poller to one post-drain compaction;
                    // never repeat it every two seconds as the reverted loop did.
                    // The 30 s heartbeat backstop and nuclear-close compaction
                    // remain independent pressure-safety mechanisms.
                    requestedCompaction = true
                    SocksstubFreeOSMemory()
                    self.appendExtLog("info: memorypressure auto-recovery requested one post-drain memory compaction")
                    do {
                        try await Task.sleep(nanoseconds: Self.turnPressureRecoveryPollNanoseconds)
                    } catch {
                        return
                    }
                    continue
                }

                let available = os_proc_available_memory()
                if available >= Self.turnPressureRecoveryHeadroomBytes {
                    stableHeadroomSamples += 1
                } else {
                    stableHeadroomSamples = 0
                }

                if stableHeadroomSamples < Self.turnPressureRecoveryStableSamples {
                    if poll % 15 == 0 {
                        self.appendExtLog("info: memorypressure auto-recovery waiting headroom=\(available / 1024)KB stable=\(stableHeadroomSamples)/\(Self.turnPressureRecoveryStableSamples)")
                    }
                    do {
                        try await Task.sleep(nanoseconds: Self.turnPressureRecoveryPollNanoseconds)
                    } catch {
                        return
                    }
                    continue
                }

                // Re-check ownership immediately before consuming the one-shot
                // attempt. A rewire may have started while headroom was sampled.
                guard Self.turnTunnelGenerationLock.withLock({ $0 }) == capturedTunnelGeneration,
                      self.isRunning else {
                    self.appendExtLog("info: memorypressure auto-recovery cancelled before attach — tunnel generation changed")
                    return
                }
                guard self.rewireGeneration == capturedRewireGeneration,
                      SocksstubVKTurnRequired() else {
                    let didMutate = self.mutatePressureStateIfOwned(
                        tunnelGeneration: capturedTunnelGeneration
                    ) {
                        $0.recoveryScheduled = false
                        $0.recoveryAttempted = false
                    }
                    guard didMutate else {
                        self.appendExtLog("info: memorypressure auto-recovery state reset before attach skipped, ownership changed")
                        return
                    }
                    self.appendExtLog("info: memorypressure auto-recovery cancelled before attach — rewire/policy ownership changed")
                    return
                }

                var ownsAttempt = false
                let didMutate = self.mutatePressureStateIfOwned(
                    tunnelGeneration: capturedTunnelGeneration
                ) { state in
                    guard state.recoveryScheduled, !state.recoveryAttempted else { return }
                    state.recoveryScheduled = false
                    state.recoveryAttempted = true
                    ownsAttempt = true
                }
                guard didMutate else {
                    self.appendExtLog("info: memorypressure auto-recovery attempt consume skipped, ownership changed")
                    return
                }
                guard ownsAttempt else {
                    self.appendExtLog("info: memorypressure auto-recovery skipped — recovery ownership changed")
                    return
                }

                // Desired TURN remains fail-closed before, during and after
                // attach. attachVKTurnUpstream re-reads the same complete App
                // Group room bundle; it does not silently truncate 4 rooms.
                // Holding both generation locks across attach closes the
                // check-to-attach race with stopTunnel/rewire. This is only
                // legal with scheduleDrainRetry:false — the drain-retry path
                // (scheduleVKTurnAttachAfterDrain) takes the same non-recursive
                // turnTunnelGenerationLock and would deadlock here.
                let ownedResult = Self.turnTunnelGenerationLock.withLock { currentTunnelGeneration -> String? in
                    guard currentTunnelGeneration == capturedTunnelGeneration,
                          !Task.isCancelled,
                          self.isRunning
                    else { return nil }
                    return self.rewireGenerationLock.withLock { currentRewireGeneration -> String? in
                        guard currentRewireGeneration == capturedRewireGeneration,
                              !Task.isCancelled,
                              self.isRunning,
                              SocksstubVKTurnRequired()
                        else { return nil }
                        SocksstubSetVKTurnRequired(true)
                        return Self.attachVKTurnUpstream(resolvedPeer: self.resolvedPeer, scheduleDrainRetry: false)
                    }
                }
                guard let result = ownedResult else {
                    // The consumed one-shot never attached. Hand the allowance
                    // back (tunnel-guarded) so a later critical in this tunnel
                    // schedules a fresh recovery instead of instantly opening
                    // the breaker for an attach that never ran.
                    _ = self.mutatePressureStateIfOwned(
                        tunnelGeneration: capturedTunnelGeneration
                    ) {
                        $0.recoveryScheduled = false
                        $0.recoveryAttempted = false
                    }
                    self.appendExtLog("info: memorypressure auto-recovery attach skipped, ownership changed; attempt returned")
                    return
                }
                self.appendExtLog("info: memorypressure auto-recovery attach result=\(result.isEmpty ? "started" : result) headroom=\(available / 1024)KB")

                if result == "previous runner still draining" {
                    let didMutate = self.mutatePressureStateIfOwned(
                        tunnelGeneration: capturedTunnelGeneration
                    ) {
                        $0.recoveryScheduled = true
                        $0.recoveryAttempted = false
                    }
                    guard didMutate else {
                        self.appendExtLog("info: memorypressure auto-recovery drain retry state skipped, ownership changed")
                        return
                    }
                    stableHeadroomSamples = 0
                    do {
                        try await Task.sleep(nanoseconds: Self.turnPressureRecoveryPollNanoseconds)
                    } catch {
                        return
                    }
                    continue
                }
                guard result.isEmpty || result == "already running" else {
                    self.appendExtLog("error: memorypressure auto-recovery failed before runner readiness; manual reconnect required")
                    return
                }

                for _ in 0..<120 { // 60 s bound for runner + GETCONF + WG attach
                    if Task.isCancelled { return }
                    guard Self.turnTunnelGenerationLock.withLock({ $0 }) == capturedTunnelGeneration,
                          self.rewireGeneration == capturedRewireGeneration,
                          self.isRunning else {
                        self.appendExtLog("info: memorypressure auto-recovery readiness poll cancelled — lifecycle generation changed")
                        return
                    }
                    if !SocksstubTURNUpstreamWGConfig().isEmpty {
                        self.appendExtLog("info: memorypressure auto-recovery READY workers=\(SocksstubTURNUpstreamActiveWorkers())/\(SocksstubTURNUpstreamExpectedWorkers()) rooms=\(VKCredsPreferences.roomHashes.count)")
                        return
                    }
                    if !SocksstubTURNUpstreamRunning() {
                        self.appendExtLog("error: memorypressure auto-recovery runner exited before ready; manual reconnect required")
                        return
                    }
                    do {
                        try await Task.sleep(nanoseconds: 500_000_000)
                    } catch {
                        return
                    }
                }
                let didMutateAfterReadinessTimeout = self.mutatePressureStateIfOwned(
                    tunnelGeneration: capturedTunnelGeneration
                ) {
                    $0.recoveryScheduled = false
                    $0.recoveryAttempted = true
                }
                guard didMutateAfterReadinessTimeout else {
                    self.appendExtLog("info: memorypressure auto-recovery readiness timeout state skipped, ownership changed")
                    return
                }
                self.appendExtLog("error: memorypressure auto-recovery timed out waiting for WG netstack; manual reconnect required")
                return
            }

            if Task.isCancelled { return }
            let didMutate = self.mutatePressureStateIfOwned(
                tunnelGeneration: capturedTunnelGeneration
            ) {
                $0.recoveryScheduled = false
                $0.recoveryAttempted = true
            }
            guard didMutate else {
                self.appendExtLog("info: memorypressure auto-recovery drain/headroom timeout state skipped, ownership changed")
                return
            }
            self.appendExtLog("error: memorypressure auto-recovery timed out waiting for drain/headroom; manual reconnect required")
        }
        pressureRecoveryTask.withLock {
            $0?.cancel()
            $0 = task
        }
    }

    private func dumpProfileBeforeNuclear(reason: String) {
        guard let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: Self.appGroupID
        ) else {
            appendExtLog("warn: heap-dump: appGroup container not available")
            return
        }
        let stamp = Int(Date().timeIntervalSince1970)
        let heapURL = containerURL.appendingPathComponent("heap-\(reason)-\(stamp).pb.gz")
        let heapErr = SocksstubWriteHeapProfile(heapURL.path)
        if heapErr.isEmpty {
            appendExtLog("info: heap-dump → \(heapURL.lastPathComponent)")
        } else {
            appendExtLog("warn: heap-dump failed: \(heapErr)")
        }
    }

    private func stopBurstProtection() {
        self.memPressureSrc?.cancel()
        self.memPressureSrc = nil
    }

    private func startSwiftHeartbeat() {
        let queue = DispatchQueue(label: "com.anarki.samizdat-test.swift-hb", qos: .userInitiated)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        // IPA-D18: 1 s → 30 s. The 1 Hz cadence kept the extension CPU
        // pinned awake and ran runtime.GC() 3600x/hour — both major
        // battery leaks per gpt-5.5 analyst. Memory leak from D12 is
        // fixed; we no longer need fast crash-correlation. Pressure
        // detection still fires via DispatchSource.makeMemoryPressure
        // Source(.critical) which kernel-pushes (zero-cost when idle).
        // sing-box-for-apple has no comparable extension heartbeat at
        // all — we keep one for diagnostics but at human cadence.
        timer.schedule(deadline: .now() + .seconds(1), repeating: .seconds(30))
        timer.setEventHandler { [weak self] in
            guard let self, self.isRunning else { return }
            // iOS's apple-supplied "available before jetsam" gauge.
            let availKB = os_proc_available_memory() / 1024

            // IPA-D7/D9: per-process memory backstop with heap dump.
            let availBytes = os_proc_available_memory()
            var nuclearFired = false
            if availBytes > 0 && availBytes < 8 * 1024 * 1024 {
                nuclearFired = self.handleCriticalMemoryPressure(reason: "avail8mib")
            }

            // Go heap detail — disambiguates "Go is bloating" from
            // "non-Go is bloating" on a crash.
            //   inUse: working set of allocated objects RIGHT NOW.
            //   sys: heap committed from OS (>= inUse).
            //   released: returned to OS via madvise.
            //   numGC: cycles completed since process start (rate)
            let goInUseKB = SocksstubMemHeapInUseKB()
            let goSysKB   = SocksstubMemHeapSysKB()
            let goRelKB   = SocksstubMemHeapReleasedKB()
            let numGC     = SocksstubMemNumGC()

            // IPA-D18: only force GC when actually approaching the
            // jetsam ceiling. The unconditional 1 Hz call was running
            // runtime.GC() 3600 times/hour, pinning CPU and burning
            // battery. Go's pacer + GOGC handles the normal case;
            // we only step in when avail-memory is genuinely tight
            // (< 12 MiB headroom before iOS reaps us).
            if availBytes > 0 && availBytes < 12 * 1024 * 1024 {
                SocksstubFreeOSMemory()
            }

            // IPA-A1: pps comes from hev's own tunnel-stats counters
            // (it now owns the data path again — no bridge counters
            // to consult). Compute delta since last heartbeat.
            var tx_pkts = 0, tx_bytes = 0, rx_pkts = 0, rx_bytes = 0
            hev_socks5_tunnel_stats(&tx_pkts, &tx_bytes, &rx_pkts, &rx_bytes)
            let inboundPPS  = Int64(tx_pkts) - self.lastHevTxPkts
            let outboundPPS = Int64(rx_pkts) - self.lastHevRxPkts
            self.lastHevTxPkts = Int64(tx_pkts)
            self.lastHevRxPkts = Int64(rx_pkts)

            // IPA-D18: log only every 5 ticks (~150 s) for periodic
            // health snapshot, OR immediately when nuclear close
            // fired. Drops appendExtLog() rate from 3600/hour to
            // ~24/hour, removing the per-tick file-write that pulled
            // iOS out of idle state.
            self.hbTick += 1
            if nuclearFired || (self.hbTick % 5) == 0 {
                self.appendExtLog(String(
                    format: "info: hb avail=%dKB go.inuse=%lldKB go.sys=%lldKB go.rel=%lldKB gc=%lld pps in=%lld out=%lld",
                    availKB,
                    goInUseKB, goSysKB, goRelKB,
                    numGC,
                    inboundPPS, outboundPPS
                ))
            }
        }
        timer.resume()
        swiftHeartbeatTimer = timer
    }

    // IPA-A1 bookkeeping for pps delta in heartbeat (from hev's own counters).
    private var lastHevTxPkts: Int64 = 0
    private var lastHevRxPkts: Int64 = 0

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .autoupdatingCurrent
        return f
    }()

    private func appendExtLog(_ message: String) {
        let stamp = Self.timeFormatter.string(from: Date())
        let line = "\(stamp) \(message)\n"
        log.info("\(message, privacy: .public)")
        guard let h = swiftLogHandle else { return }
        do {
            try h.write(contentsOf: Data(line.utf8))
            try h.synchronize()
        } catch {
            // best-effort
        }
    }

    private func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.anarki.samizdat-test.tunnel",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}

/// IPA-D26: gomobile-bound bridge for the ping prober's auto-rewire
/// signal. Go calls `requestRewire()` when it has detected 2+
/// consecutive HTTP HEAD failures through the tunnel — likely the
/// upstream is unreachable on the current path (wifi dying without
/// NWPath having flipped yet, or upstream node blip). We respond by
/// rebuilding the samizdat client over the current default route.
/// Throttled in Go to once per 15 s.
final class AutoRewireBridge: NSObject, SocksstubRewireRequesterProtocol {
    private let onRequest: () -> Void

    init(onRequest: @escaping () -> Void) {
        self.onRequest = onRequest
        super.init()
    }

    /// Called from a Go goroutine — bounce off Go's stack before
    /// touching extension state.
    func requestRewire() {
        DispatchQueue.global(qos: .userInitiated).async { [onRequest] in
            onRequest()
        }
    }
}
