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
    case paceFailedFallbackToBAC
    case bacStarted
    case bacSucceeded
    case chipAuthenticationStarted
    case chipAuthenticationSucceeded
    case chipAuthenticationFailedFallbackToBAC
    case activeAuthenticationStarted
    case activeAuthenticationSucceeded
    case readingDataGroup(DataGroupId, progress: Double?)
    case verifyingSOD
    case verifyingDataGroups
    case complete

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
        case .readingDataGroup(let dataGroup, _):
            return "Reading \(dataGroup.getName())"
        case .verifyingSOD:
            return "Verifying SOD"
        case .verifyingDataGroups:
            return "Verifying data groups"
        case .complete:
            return "Passport chip read complete"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public typealias PassportReaderProgressHandler = @Sendable (PassportReaderProgressEvent) -> Void

