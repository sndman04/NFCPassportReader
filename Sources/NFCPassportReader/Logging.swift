//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

/// Controls privacy-safe logging emitted by `PassportReader`.
///
/// Logging is off by default. Even at `debugRedacted`, events are typed and do
/// not include MRZ values, APDUs, cryptographic keys, data-group bytes, images,
/// certificates, random challenges, or low-level secure messaging material.
public enum PassportReaderLogLevel: Int, Sendable {
    case off = 0
    case error
    case info
    case debugRedacted
}

/// A redacted, high-level event emitted by `PassportReader`.
public enum PassportReaderLogEvent: Sendable, CustomStringConvertible {
    case sessionStarted
    case sessionInvalidated(PassportReaderSessionInvalidationReason)
    case tagDetected
    case multipleTagsDetected
    case invalidTagDetected
    case tagConnected
    case paceStarted
    case paceSucceeded
    case paceFailedFallbackToBAC
    case bacStarted
    case bacSucceeded
    case bacFailed
    case chipAuthenticationStarted
    case chipAuthenticationSucceeded
    case chipAuthenticationFailedFallbackToBAC
    case activeAuthenticationStarted
    case activeAuthenticationSucceeded
    case readingDataGroup(DataGroupId)
    case unsupportedDataGroup(DataGroupId)
    case dataGroupReadFailed(DataGroupId)
    case verificationStarted
    case readSucceeded
    case readFailed(PassportReaderFailureReason)

    public var description: String {
        switch self {
        case .sessionStarted:
            return "NFC session started"
        case .sessionInvalidated(let reason):
            return "NFC session invalidated: \(reason.description)"
        case .tagDetected:
            return "NFC tag detected"
        case .multipleTagsDetected:
            return "Multiple NFC tags detected"
        case .invalidTagDetected:
            return "Invalid NFC tag detected"
        case .tagConnected:
            return "NFC tag connected"
        case .paceStarted:
            return "PACE started"
        case .paceSucceeded:
            return "PACE succeeded"
        case .paceFailedFallbackToBAC:
            return "PACE failed; falling back to BAC"
        case .bacStarted:
            return "BAC started"
        case .bacSucceeded:
            return "BAC succeeded"
        case .bacFailed:
            return "BAC failed"
        case .chipAuthenticationStarted:
            return "Chip authentication started"
        case .chipAuthenticationSucceeded:
            return "Chip authentication succeeded"
        case .chipAuthenticationFailedFallbackToBAC:
            return "Chip authentication failed; falling back to BAC"
        case .activeAuthenticationStarted:
            return "Active authentication started"
        case .activeAuthenticationSucceeded:
            return "Active authentication succeeded"
        case .readingDataGroup(let dataGroup):
            return "Reading \(dataGroup.getName())"
        case .unsupportedDataGroup(let dataGroup):
            return "Unsupported data group skipped: \(dataGroup.getName())"
        case .dataGroupReadFailed(let dataGroup):
            return "Data group read failed: \(dataGroup.getName())"
        case .verificationStarted:
            return "Passport verification started"
        case .readSucceeded:
            return "Passport chip read succeeded"
        case .readFailed(let reason):
            return "Passport chip read failed: \(reason.description)"
        }
    }
}

/// Privacy-safe reason for an NFC session invalidation.
public enum PassportReaderSessionInvalidationReason: Sendable, Equatable, CustomStringConvertible {
    case userCanceled
    case timeout
    case connectionLost
    case system
    case unknown

    public var description: String {
        switch self {
        case .userCanceled: return "user canceled"
        case .timeout: return "timeout"
        case .connectionLost: return "connection lost"
        case .system: return "system"
        case .unknown: return "unknown"
        }
    }
}

/// Privacy-safe high-level failure reason.
public enum PassportReaderFailureReason: Sendable, Equatable, CustomStringConvertible {
    case userCanceled
    case nfcNotSupported
    case timeout
    case connectionLost
    case accessKeyRejected
    case unsupportedPassport
    case verificationFailed
    case unexpectedReadFailure

    public var description: String {
        switch self {
        case .userCanceled: return "user canceled"
        case .nfcNotSupported: return "NFC not supported"
        case .timeout: return "timeout"
        case .connectionLost: return "connection lost"
        case .accessKeyRejected: return "access key rejected"
        case .unsupportedPassport: return "unsupported passport"
        case .verificationFailed: return "verification failed"
        case .unexpectedReadFailure: return "unexpected read failure"
        }
    }
}

/// Sink for receiving privacy-safe passport reader events.
public protocol PassportReaderLogging: AnyObject {
    func log(_ event: PassportReaderLogEvent)
}

final class PassportReaderOSLogger: PassportReaderLogging {
    private let logger: Logger

    init() {
        let subsystem = Bundle.main.bundleIdentifier ?? "com.nfcpassportreader"
        self.logger = Logger(subsystem: subsystem, category: "passportReader")
    }

    func log(_ event: PassportReaderLogEvent) {
        logger.info("\(event.description, privacy: .public)")
    }
}

final class PassportReaderEventLogger {
    private let level: PassportReaderLogLevel
    private weak var sink: PassportReaderLogging?
    private let defaultSink: PassportReaderLogging?

    init(level: PassportReaderLogLevel, sink: PassportReaderLogging?) {
        self.level = level
        self.sink = sink
        self.defaultSink = sink == nil && level != .off ? PassportReaderOSLogger() : nil
    }

    func log(_ event: PassportReaderLogEvent) {
        guard level != .off else { return }

        switch event {
        case .readFailed, .sessionInvalidated:
            break
        default:
            guard level.rawValue >= PassportReaderLogLevel.info.rawValue else { return }
        }

        (sink ?? defaultSink)?.log(event)
    }
}

@available(iOS 13, macOS 10.15, *)
extension NFCPassportReaderError {
    var privacySafeFailureReason: PassportReaderFailureReason {
        switch self {
        case .UserCanceled:
            return .userCanceled
        case .NFCNotSupported:
            return .nfcNotSupported
        case .TimeOutError:
            return .timeout
        case .ConnectionError:
            return .connectionLost
        case .ScanAlreadyInProgress:
            return .unexpectedReadFailure
        case .InvalidMRZKey:
            return .accessKeyRejected
        case .UnsupportedDataGroup, .NotImplemented, .NotYetSupported, .UnsupportedCipherAlgorithm, .UnsupportedMappingType:
            return .unsupportedPassport
        case .InvalidResponseChecksum, .InvalidHashAlgorithmSpecified:
            return .verificationFailed
        default:
            return .unexpectedReadFailure
        }
    }

    var shouldRetryDataGroupReadAfterChipAuthentication: Bool {
        switch self {
        case .ConnectionError:
            return true
        case .ResponseError(let message, let sw1, let sw2):
            return (sw1, sw2) == (0x6E, 0x00)
                || message == "Session invalidated"
                || message == "Class not supported"
                || message == "Tag connection lost"
                || message == "Tag response error / no response"
        default:
            return false
        }
    }

    var shouldSkipDataGroupAndRedoBAC: Bool {
        switch self {
        case .ResponseError(_, 0x69, 0x82), .ResponseError(_, 0x6A, 0x82):
            return true
        default:
            return false
        }
    }

    var shouldRedoBACForDataGroupRead: Bool {
        switch self {
        case .ResponseError(_, 0x69, 0x88), .ResponseError(_, 0x6E, 0x00):
            return true
        default:
            return false
        }
    }

    var shouldReduceReadAmountAndRedoBAC: Bool {
        switch self {
        case .ResponseError(_, 0x62, 0x82), .ResponseError(_, 0x67, 0x00), .ResponseError(_, 0x6C, _):
            return true
        default:
            return false
        }
    }

    var isUnsupportedDataGroupRead: Bool {
        switch self {
        case .UnsupportedDataGroup:
            return true
        default:
            return false
        }
    }
}
