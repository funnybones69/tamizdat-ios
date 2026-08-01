import Foundation
import XCTest

final class TURNMemoryPressureLadderTests: XCTestCase {
    private func state(
        now: TimeInterval = 1_000,
        pressureEvent: Bool = true,
        episodes: Int = 0,
        lastPressureAt: TimeInterval? = nil,
        workers: Int = 12,
        stepEnteredAt: TimeInterval = 0,
        headroomStableSince: TimeInterval? = nil,
        upshifts: [TimeInterval] = [],
        required: Bool = true,
        runnerAlive: Bool = true
    ) -> TURNPressureLadderDecisionState {
        TURNPressureLadderDecisionState(
            now: now,
            pressureEvent: pressureEvent,
            pressureEpisodeCount: episodes,
            lastPressureAt: lastPressureAt,
            currentWorkersPerRoom: workers,
            stepEnteredAt: stepEnteredAt,
            headroomStableSince: headroomStableSince,
            recentUpshiftAt: upshifts,
            turnRequired: required,
            runnerAlive: runnerAlive
        )
    }

    func testPressureEpisodesFollowShedDownshiftDownshiftFailClosedLadder() {
        XCTAssertEqual(nextLadderAction(state: state()), .shedFlows)
        XCTAssertEqual(
            nextLadderAction(state: state(episodes: 1, lastPressureAt: 900)),
            .downshift(workersPerRoom: 8)
        )
        XCTAssertEqual(
            nextLadderAction(state: state(episodes: 2, lastPressureAt: 900, workers: 8)),
            .downshift(workersPerRoom: 6)
        )
        XCTAssertEqual(
            nextLadderAction(state: state(episodes: 3, lastPressureAt: 900, workers: 6)),
            .failClosed
        )
    }

    func testTenMinuteQuietWindowResetsEpisodeCounter() {
        let quiet = state(episodes: 9, lastPressureAt: 400)
        XCTAssertEqual(nextPressureEpisode(state: quiet), 1)
        XCTAssertEqual(nextLadderAction(state: quiet), .shedFlows)

        let insideWindow = state(episodes: 1, lastPressureAt: 401)
        XCTAssertEqual(nextPressureEpisode(state: insideWindow), 2)
    }

    func testPressureNeverUpshiftsAlreadyDegradedRunner() {
        XCTAssertEqual(
            nextLadderAction(state: state(episodes: 1, lastPressureAt: 900, workers: 6)),
            .shedFlows
        )
    }

    func testUpshiftRequiresThreeMinutesOfHeadroomNoPressureAndDwell() {
        let notStable = state(
            now: 1_000,
            pressureEvent: false,
            episodes: 3,
            lastPressureAt: 700,
            workers: 6,
            stepEnteredAt: 700,
            headroomStableSince: 821
        )
        XCTAssertEqual(nextLadderAction(state: notStable), .none)

        var ready = notStable
        ready.headroomStableSince = 820
        XCTAssertEqual(nextLadderAction(state: ready), .upshift(workersPerRoom: 8))

        ready.currentWorkersPerRoom = 8
        XCTAssertEqual(nextLadderAction(state: ready), .upshift(workersPerRoom: 12))
    }

    func testUpshiftHysteresisBlocksRecentPressureAndShortDwell() {
        XCTAssertEqual(
            nextLadderAction(state: state(
                now: 1_000,
                pressureEvent: false,
                episodes: 3,
                lastPressureAt: 900,
                workers: 6,
                stepEnteredAt: 700,
                headroomStableSince: 700
            )),
            .none
        )
        XCTAssertEqual(
            nextLadderAction(state: state(
                now: 1_000,
                pressureEvent: false,
                episodes: 3,
                lastPressureAt: 700,
                workers: 6,
                stepEnteredAt: 900,
                headroomStableSince: 700
            )),
            .none
        )
    }

    func testUpshiftHourlyLimitAndRunnerGuards() {
        let fourRecent = [100.0, 300.0, 500.0, 700.0]
        XCTAssertEqual(
            nextLadderAction(state: state(
                now: 1_000,
                pressureEvent: false,
                episodes: 3,
                lastPressureAt: 700,
                workers: 6,
                stepEnteredAt: 700,
                headroomStableSince: 700,
                upshifts: fourRecent
            )),
            .none
        )
        XCTAssertEqual(
            nextLadderAction(state: state(
                now: 5_000,
                pressureEvent: false,
                episodes: 3,
                lastPressureAt: 4_700,
                workers: 6,
                stepEnteredAt: 4_700,
                headroomStableSince: 4_700,
                upshifts: fourRecent
            )),
            .upshift(workersPerRoom: 8)
        )
        XCTAssertEqual(
            nextLadderAction(state: state(
                now: 1_000,
                pressureEvent: false,
                episodes: 3,
                lastPressureAt: 700,
                workers: 6,
                stepEnteredAt: 700,
                headroomStableSince: 700,
                runnerAlive: false
            )),
            .none
        )
        XCTAssertEqual(nextLadderAction(state: state(required: false)), .none)
    }
}
