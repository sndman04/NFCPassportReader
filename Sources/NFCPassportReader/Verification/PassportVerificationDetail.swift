//
//  PassportVerificationDetail.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportVerificationDetailReason: Sendable, Equatable {
    case notRequested
    case notSupported
    case skipped
    case missingSOD
    case missingMasterList
    case signerUntrusted
    case signatureInvalid
    case hashMismatch
    case malformedSOD
    case unsupportedAlgorithm
    case attemptedFailed
    case passed
}

@available(iOS 13, macOS 10.15, *)
public struct PassportVerificationCheck: Sendable, Equatable {
    public let status: PassportVerificationStatus
    public let reason: PassportVerificationDetailReason

    public init(status: PassportVerificationStatus, reason: PassportVerificationDetailReason) {
        self.status = status
        self.reason = reason
    }

    public var privacySafeExplanation: String {
        switch reason {
        case .notRequested:
            return "This verification check was not requested."
        case .notSupported:
            return "The passport did not advertise this verification mechanism."
        case .skipped:
            return "This verification check was skipped by the scan configuration."
        case .missingSOD:
            return "The document security object was not read."
        case .missingMasterList:
            return "Signer trust was not checked because no master list was provided."
        case .signerUntrusted:
            return "Signer trust could not be established with the configured master list."
        case .signatureInvalid:
            return "The document security object signature could not be verified."
        case .hashMismatch:
            return "One or more read data groups did not match the document security object."
        case .malformedSOD:
            return "The document security object could not be parsed."
        case .unsupportedAlgorithm:
            return "The passport used an unsupported verification algorithm."
        case .attemptedFailed:
            return "The verification check was attempted and failed."
        case .passed:
            return "The verification check passed."
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public enum PassportDataGroupCoverageStatus: Sendable, Equatable {
    case notApplicable
    case coveredAndMatched
    case coveredButMismatched
    case readButNotCovered
    case coveredButNotRead
}

@available(iOS 13, macOS 10.15, *)
public struct PassportDataGroupVerificationCoverage: Sendable, Equatable {
    public let dataGroup: DataGroupId
    public let status: PassportDataGroupCoverageStatus

    public init(dataGroup: DataGroupId, status: PassportDataGroupCoverageStatus) {
        self.dataGroup = dataGroup
        self.status = status
    }
}
