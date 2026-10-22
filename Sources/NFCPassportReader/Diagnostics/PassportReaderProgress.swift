//
//  PassportReaderProgress.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// A structured, privacy-safe progress update for a passport NFC scan.
///
/// These events are intended for app UI state. They never include MRZ values,
/// APDUs, cryptographic keys, random challenges, decrypted data groups,
/// certificates, or image bytes.
@available(iOS 13, macOS 10.15, *)
public enum PassportReaderProgressEvent: Sendable, Equatable, CustomStringConvertible {
    case waitingForPassport
    case tagDetected
    case authenticating(progress: Double?)
    case paceStarted
    case paceSucceeded
    /// Fallback was chosen; application/session preparation is in progress.
    /// BAC authentication starts only at `bacStarted`.
    case paceFailedFallbackToBAC
    case bacFallbackRestartingPolling
    case bacFallbackSelectingApplication
    case bacStarted
    case bacSucceeded
    case chipAuthenticationStarted
    case chipAuthenticationSucceeded
    case chipAuthenticationFailedFallbackToBAC
    case activeAuthenticationStarted
    case activeAuthenticationSucceeded
    case activeAuthenticationFailed
    case readingDataGroup(DataGroupId, progress: Double?)
    case verifyingSOD
    case verifyingDataGroups
    case complete
    /// Terminal failure, delivered once after cleanup, with no underlying error payload.
    case failed(reason: PassportReaderFailureReason, stage: PassportReaderScanStage)

    public var description: String {
        switch self {
        case .waitingForPassport:
            return "Waiting for passport"
        case .tagDetected:
            return "Passport NFC tag detected"
        case .authenticating:
            return "Authenticating with passport"
        case .paceStarted:
            return "PACE started"
        case .paceSucceeded:
            return "PACE succeeded"
        case .paceFailedFallbackToBAC:
            return "PACE failed; falling back to BAC"
        case .bacFallbackRestartingPolling:
            return "BAC fallback: waiting for a fresh NFC connection"
        case .bacFallbackSelectingApplication:
            return "BAC fallback: selecting passport application"
        case .bacStarted:
            return "BAC started"
        case .bacSucceeded:
            return "BAC succeeded"
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
        case .activeAuthenticationFailed:
            return "Active authentication failed"
        case .readingDataGroup(let dataGroup, _):
            return "Reading \(dataGroup.getName())"
        case .verifyingSOD:
            return "Verifying SOD"
        case .verifyingDataGroups:
            return "Verifying data groups"
        case .complete:
            return "Passport chip read complete"
        case .failed(let reason, let stage):
            return "Passport chip read failed during \(stage.description): \(reason.description)"
        }
    }

    /// Privacy-safe scan stage corresponding to this progress event.
    public var scanStage: PassportReaderScanStage {
        switch self {
        case .waitingForPassport:
            return .waitingForPassport
        case .tagDetected, .authenticating:
            return .connecting
        case .paceStarted, .paceSucceeded:
            return .pace
        case .paceFailedFallbackToBAC, .bacFallbackRestartingPolling, .bacFallbackSelectingApplication:
            return .bacFallbackPreparation
        case .bacStarted, .bacSucceeded:
            return .bac
        case .chipAuthenticationStarted,
             .chipAuthenticationSucceeded,
             .chipAuthenticationFailedFallbackToBAC:
            return .chipAuthentication
        case .activeAuthenticationStarted, .activeAuthenticationSucceeded, .activeAuthenticationFailed:
            return .activeAuthentication
        case .readingDataGroup(let dataGroup, _):
            return .readingDataGroup(dataGroup)
        case .verifyingSOD, .verifyingDataGroups:
            return .passiveAuthentication
        case .complete:
            return .unknown
        case .failed(_, let stage):
            return stage
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public typealias PassportReaderProgressHandler = @Sendable (PassportReaderProgressEvent) -> Void
