import Foundation

enum TURNPressureLadderAction: Equatable {
    case none
    case shedFlows
    case downshift(workersPerRoom: Int)
    case failClosed
    case upshift(workersPerRoom: Int)
}

/// Immutable input for the TURN memory-pressure ladder. All clocks and samples
/// are supplied by the caller, which keeps `nextLadderAction` deterministic and
/// unit-testable without timers or process state.
struct TURNPressureLadderDecisionState: Equatable {
    var now: TimeInterval
    var pressureEvent: Bool
    var pressureEpisodeCount: Int
    var lastPressureAt: TimeInterval?
    var currentWorkersPerRoom: Int
    var stepEnteredAt: TimeInterval
    var headroomStableSince: TimeInterval?
    var recentUpshiftAt: [TimeInterval]
    var turnRequired: Bool
    var runnerAlive: Bool
}

private let turnPressureEpisodeWindow: TimeInterval = 10 * 60
private let turnUpshiftStableDuration: TimeInterval = 3 * 60
private let turnUpshiftWindow: TimeInterval = 60 * 60
private let turnUpshiftHourlyLimit = 4

func nextPressureEpisode(state: TURNPressureLadderDecisionState) -> Int {
    guard state.pressureEvent else { return state.pressureEpisodeCount }
    guard let last = state.lastPressureAt,
          state.now - last < turnPressureEpisodeWindow else {
        return 1
    }
    return state.pressureEpisodeCount + 1
}

func nextLadderAction(state: TURNPressureLadderDecisionState) -> TURNPressureLadderAction {
    guard state.turnRequired else { return .none }

    if state.pressureEvent {
        switch nextPressureEpisode(state: state) {
        case 1:
            return .shedFlows
        case 2:
            let target = min(state.currentWorkersPerRoom, 8)
            return target < state.currentWorkersPerRoom
                ? .downshift(workersPerRoom: target)
                : .shedFlows
        case 3:
            let target = min(state.currentWorkersPerRoom, 6)
            return target < state.currentWorkersPerRoom
                ? .downshift(workersPerRoom: target)
                : .shedFlows
        default:
            return .failClosed
        }
    }

    guard state.runnerAlive,
          state.currentWorkersPerRoom == 6 || state.currentWorkersPerRoom == 8,
          state.now - state.stepEnteredAt >= turnUpshiftStableDuration,
          state.lastPressureAt.map({ state.now - $0 >= turnUpshiftStableDuration }) ?? true,
          let stableSince = state.headroomStableSince,
          state.now - stableSince >= turnUpshiftStableDuration else {
        return .none
    }

    let recentUpshifts = state.recentUpshiftAt.filter {
        state.now - $0 < turnUpshiftWindow
    }
    guard recentUpshifts.count < turnUpshiftHourlyLimit else { return .none }

    return .upshift(workersPerRoom: state.currentWorkersPerRoom == 6 ? 8 : 12)
}
