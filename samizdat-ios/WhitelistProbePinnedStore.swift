import Foundation
import os

enum WhitelistProbePinnedStore {
    private static let lock = OSAllocatedUnfairLock<[String: String]>(initialState: [:])

    static func set(_ map: [String: String]) {
        lock.withLock { $0 = map }
    }

    static func current() -> [String: String] {
        lock.withLock { $0 }
    }

    static func clear() {
        lock.withLock { $0 = [:] }
    }
}
