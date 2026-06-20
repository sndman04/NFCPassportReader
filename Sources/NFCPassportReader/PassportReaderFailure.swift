//
//  PassportReaderFailure.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Privacy-safe app-facing failure information for a passport NFC scan.
///
/// This type is intended for user messaging and retry decisions. It does not
/// expose status words, low-level command bytes, access-key material,
/// cryptographic material, data-group bytes, certificate details, or image data.
@available(iOS 13, macOS 10.15, *)
public struct PassportReaderFailure: Sendable, Equatable {
    public let reason: PassportReaderFailureReason
    public let stage: PassportReaderScanStage
    public let isRetryLikelyToHelp: Bool
    public let recoverySuggestion: String

    public init(reason: PassportReaderFailureReason, stage: PassportReaderScanStage = .unknown) {
        self.reason = reason
        self.stage = stage
        self.isRetryLikelyToHelp = reason.isRetryLikelyToHelp(at: stage)
        self.recoverySuggestion = reason.recoverySuggestion(at: stage)
    }
}

@available(iOS 13, macOS 10.15, *)
public extension PassportReaderFailureReason {
    var isRetryLikelyToHelp: Bool {
        isRetryLikelyToHelp(at: .unknown)
    }

    func isRetryLikelyToHelp(at stage: PassportReaderScanStage) -> Bool {
        switch self {
        case .verificationFailed:
            switch stage {
            case .passiveAuthentication, .securityPolicyValidation:
                return false
            default:
                return false
            }
        case .timeout, .connectionLost, .unexpectedReadFailure:
            return true
        case .userCanceled, .nfcNotSupported, .accessKeyRejected, .unsupportedPassport:
            return false
        }
    }

    var recoverySuggestion: String {
        recoverySuggestion(at: .unknown)
    }

    func recoverySuggestion(at stage: PassportReaderScanStage) -> String {
        switch self {
        case .userCanceled:
            return "Scan canceled."
        case .nfcNotSupported:
            return "Use a device that supports NFC passport reading."
        case .timeout:
            return "Move your phone back to the passport and try again."
        case .connectionLost:
            if case .readingDataGroup = stage {
                return "Hold the phone steady on the passport chip and try again."
            }
            return "Hold the phone steady against the passport chip and try again."
        case .accessKeyRejected:
            return "Check the passport number, date of birth, and expiration date, then try again."
        case .unsupportedPassport:
            return "This passport feature is not supported by the reader."
        case .verificationFailed:
            return "The passport chip data could not be verified."
        case .unexpectedReadFailure:
            switch stage {
            case .pace:
                return "Try scanning again, or use a BAC-compatible flow if PACE is unavailable."
            case .readingDataGroup:
                return "Try scanning again while keeping the phone steady on the passport."
            default:
                break
            }
            return "Try scanning the passport again."
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public extension NFCPassportReaderError {
    var privacySafeFailure: PassportReaderFailure {
        PassportReaderFailure(reason: privacySafeFailureReason)
    }

    func privacySafeFailure(at stage: PassportReaderScanStage) -> PassportReaderFailure {
        PassportReaderFailure(reason: privacySafeFailureReason, stage: stage)
    }
}
