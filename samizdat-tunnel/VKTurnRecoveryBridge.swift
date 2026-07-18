import Foundation
import SamizdatClient

/// Go emits this callback once when a live TURN runner enters a 0/N quota
/// storm. The packet-tunnel process owns the recovery because its own sockets
/// egress on the physical NetworkExtension path even while user traffic remains
/// fail-closed inside the broken tunnel.
final class VKTurnRecoveryBridge: NSObject, SocksstubVKTurnRecoveryCallbackProtocol {
    private let handler: () -> Void

    init(handler: @escaping () -> Void) {
        self.handler = handler
    }

    func onQuotaStorm() {
        // gomobile enters Swift on a Go-owned thread. Bounce before touching
        // NetworkExtension state, matching the established rewire bridge.
        DispatchQueue.global(qos: .userInitiated).async { [handler] in
            handler()
        }
    }
}
