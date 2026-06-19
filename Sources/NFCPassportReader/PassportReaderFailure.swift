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
    public let isRetryLikelyToHelp: Bool
    public let recoverySuggestion: String

    public init(reason: PassportReaderFailureReason) {
        self.reason = reason
        self.isRetryLikelyToHelp = reason.isRetryLikelyToHelp
        self.recoverySuggestion = reason.recoverySuggestion
    }
}

@available(iOS 13, macOS 10.15, *)
public extension PassportReaderFailureReason {
    var isRetryLikelyToHelp: Bool {
        switch self {
        case .timeout, .connectionLost, .unexpectedReadFailure:
            return true
        case .userCanceled, .nfcNotSupported, .accessKeyRejected, .unsupportedPassport, .verificationFailed:
            return false
        }
    }

    var recoverySuggestion: String {
        switch self {
        case .userCanceled:
            return "Scan canceled."
        case .nfcNotSupported:
            return "Use a device that supports NFC passport reading."
        case .timeout:
            return "Move your phone back to the passport and try again."
        case .connectionLost:
            return "Hold the phone steady against the passport chip and try again."
        case .accessKeyRejected:
            return "Check the passport number, date of birth, and expiration date, then try again."
        case .unsupportedPassport:
            return "This passport feature is not supported by the reader."
        case .verificationFailed:
            return "The passport chip data could not be verified."
        case .unexpectedReadFailure:
            return "Try scanning the passport again."
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public extension NFCPassportReaderError {
    var privacySafeFailure: PassportReaderFailure {
        PassportReaderFailure(reason: privacySafeFailureReason)
    }
}
