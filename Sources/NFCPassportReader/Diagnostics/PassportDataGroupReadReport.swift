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
