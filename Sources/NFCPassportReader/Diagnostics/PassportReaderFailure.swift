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
    public let verificationReason: PassportVerificationDetailReason?
    public let isRetryLikelyToHelp: Bool
    public let userMessage: String
    public let recoverySuggestion: String

    public init(
        reason: PassportReaderFailureReason,
        stage: PassportReaderScanStage = .unknown,
        verificationReason: PassportVerificationDetailReason? = nil,
        userMessage: String? = nil
    ) {
        self.reason = reason
        self.stage = stage
        self.verificationReason = verificationReason
        self.isRetryLikelyToHelp = reason.isRetryLikelyToHelp(at: stage)
        self.userMessage = userMessage
            ?? reason.userMessage(at: stage, verificationReason: verificationReason)
        self.recoverySuggestion = reason.recoverySuggestion(at: stage)
    }
}

@available(iOS 13, macOS 10.15, *)
public extension PassportReaderFailureReason {
    func userMessage(
        at stage: PassportReaderScanStage,
        verificationReason: PassportVerificationDetailReason? = nil
    ) -> String {
        switch self {
        case .userCanceled:
            return "Passport chip scan canceled."
        case .nfcNotSupported:
            return "This device does not support NFC passport scanning."
        case .timeout:
            return "The passport chip did not respond before the scan timed out\(stage.userMessageSuffix)."
        case .connectionLost:
            return "The phone lost contact with the passport chip\(stage.userMessageSuffix)."
        case .accessKeyRejected:
            return "The passport chip rejected the passport number, date of birth, or expiration date used to unlock it."
        case .unsupportedPassport:
            return "The passport uses a chip feature this reader does not support\(stage.userMessageSuffix)."
        case .verificationFailed:
            return verificationReason?.userMessage
                ?? "The passport chip was read, but its signed data could not be verified."
        case .unexpectedReadFailure:
            return "The passport chip could not be read\(stage.userMessageSuffix)."
        }
    }

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
            return "Place the top of the phone against the passport's rear cover, move it slowly until it connects, then hold it still and try again."
        case .connectionLost:
            if case .readingDataGroup = stage {
                return "Keep the top of the phone pressed steadily against the passport cover and try again."
            }
            return "Move the top of the phone slowly across the passport cover until it reconnects, then hold it still and try again."
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
private extension PassportReaderScanStage {
    var userMessageSuffix: String {
        switch self {
        case .unknown:
            return ""
        case .waitingForPassport:
            return " while waiting for the passport"
        case .connecting:
            return " while connecting"
        case .pace:
            return " during secure access setup"
        case .bac:
            return " while checking the passport access details"
        case .readingDataGroup(let dataGroup):
            return " while reading \(dataGroup.userFacingName)"
        case .chipAuthentication:
            return " during chip authentication"
        case .activeAuthentication:
            return " during anti-cloning authentication"
        case .passiveAuthentication:
            return " while checking the passport's digital signature"
        case .securityPolicyValidation:
            return " during final security validation"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
private extension DataGroupId {
    var userFacingName: String {
        switch self {
        case .COM:
            return "the chip directory"
        case .SOD:
            return "the passport's digital signature"
        case .DG1:
            return "identity details"
        case .DG2:
            return "the passport photo"
        case .DG7:
            return "the signature image"
        case .DG11:
            return "additional identity details"
        case .DG12:
            return "document details"
        case .DG14:
            return "chip security information"
        case .DG15:
            return "anti-cloning information"
        default:
            return "optional passport data"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
private extension PassportVerificationDetailReason {
    var userMessage: String {
        switch self {
        case .missingSOD:
            return "The passport chip was read, but the digital security object needed for verification was missing."
        case .missingMasterList:
            return "The passport chip was read, but the issuing-country certificate list needed to establish trust was unavailable."
        case .signerUntrusted:
            return "The passport chip was read, but its signer could not be trusted with the configured country certificate list."
        case .signatureInvalid:
            return "The passport chip was read, but its digital signature could not be verified."
        case .hashMismatch:
            return "The passport chip was read, but one or more fields did not match the passport's signed data."
        case .malformedSOD:
            return "The passport chip was read, but its digital security object was malformed or unsupported."
        case .unsupportedAlgorithm:
            return "The passport chip was read, but it uses a verification algorithm this reader does not support."
        case .attemptedFailed:
            return "The passport chip was read, but the required authenticity check failed."
        case .notRequested, .notSupported, .skipped, .passed:
            return "The passport chip was read, but the configured security requirements were not satisfied."
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public extension NFCPassportReaderError {
    var privacySafeFailure: PassportReaderFailure {
        privacySafeFailure(at: .unknown)
    }

    func privacySafeFailure(at stage: PassportReaderScanStage) -> PassportReaderFailure {
        PassportReaderFailure(
            reason: privacySafeFailureReason,
            stage: stage,
            userMessage: privacySafeUserMessage(at: stage)
        )
    }

    private func privacySafeUserMessage(at stage: PassportReaderScanStage) -> String {
        switch self {
        case .ResponseError, .UnexpectedError, .Unknown:
            return "The passport chip could not be read\(stage.userMessageSuffix)."
        case .InvalidResponse(let dataGroupId, _, _):
            return "The passport chip returned unexpected data while reading \(dataGroupId.userFacingName)."
        case .NFCNotSupported:
            return "This device does not support NFC passport scanning."
        case .NoConnectedTag:
            return "No passport chip was connected."
        case .D087Malformed, .InvalidResponseChecksum, .UnableToUnprotectAPDU:
            return "The secure response from the passport chip could not be verified\(stage.userMessageSuffix)."
        case .MissingMandatoryFields, .CannotDecodeASN1Length, .InvalidASN1Value, .InvalidASN1Structure:
            return "The passport chip returned data the reader could not understand\(stage.userMessageSuffix)."
        case .UnableToProtectAPDU:
            return "The reader could not prepare a secure command for the passport chip\(stage.userMessageSuffix)."
        case .UnsupportedDataGroup, .DataGroupNotRead, .NotImplemented, .NotYetSupported,
             .UnsupportedCipherAlgorithm, .UnsupportedMappingType:
            return "The passport uses a chip feature this reader does not support\(stage.userMessageSuffix)."
        case .UnknownTag, .TagNotValid:
            return "The NFC tag was not a compatible passport chip."
        case .UnknownImageFormat:
            return "The passport photo uses an image format this reader does not support."
        case .ConnectionError:
            return PassportReaderFailureReason.connectionLost.userMessage(at: stage)
        case .TimeOutError:
            return PassportReaderFailureReason.timeout.userMessage(at: stage)
        case .UserCanceled:
            return PassportReaderFailureReason.userCanceled.userMessage(at: stage)
        case .ScanAlreadyInProgress:
            return "A passport chip scan is already in progress."
        case .SecurityPolicyViolation:
            return PassportReaderFailureReason.verificationFailed.userMessage(at: stage)
        case .RawDataExportNotAllowed:
            return "Raw passport data is unavailable because the configured privacy policy does not allow it."
        case .InvalidMRZKey:
            return PassportReaderFailureReason.accessKeyRejected.userMessage(at: stage)
        case .MoreThanOneTagFound:
            return "More than one NFC tag was detected. Move other NFC items away and present only one passport."
        case .InvalidHashAlgorithmSpecified:
            return "The passport uses a signature verification method this reader does not support."
        case .PACEError:
            return "Secure access setup with the passport chip failed."
        case .ChipAuthenticationFailed:
            return "The passport chip was read, but chip authentication failed."
        case .ActiveAuthenticationFailed:
            return "The passport chip was read, but its anti-cloning check failed."
        case .InvalidDataPassed:
            return "The scan could not start because required passport details were invalid."
        }
    }
}
