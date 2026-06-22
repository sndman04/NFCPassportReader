//
//  PassportDataGroupReadReport.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportDataGroupReadStatus: Sendable, Equatable {
    case requested
    case advertised
    case read
    case skippedByProfile
    case blockedByPolicy
    case unsupported
    case failed

    func replaces(_ previous: PassportDataGroupReadStatus) -> Bool {
        switch (self, previous) {
        case (.read, .failed),
             (.read, .unsupported),
             (.read, .skippedByProfile),
             (.read, .blockedByPolicy),
             (.unsupported, .failed),
             (.unsupported, .skippedByProfile),
             (.unsupported, .blockedByPolicy),
             (.failed, .skippedByProfile),
             (.failed, .blockedByPolicy),
             (.skippedByProfile, .failed),
             (.blockedByPolicy, .failed):
            return true
        default:
            return false
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public struct PassportDataGroupReadReport: Sendable, Equatable {
    public let dataGroup: DataGroupId
    public let status: PassportDataGroupReadStatus

    public init(dataGroup: DataGroupId, status: PassportDataGroupReadStatus) {
        self.dataGroup = dataGroup
        self.status = status
    }
}
