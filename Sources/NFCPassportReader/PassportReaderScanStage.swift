//
//  PassportReaderScanStage.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportReaderScanStage: Sendable, Equatable, CustomStringConvertible {
    case unknown
    case waitingForPassport
    case connecting
    case pace
    case bac
    case readingDataGroup(DataGroupId)
    case chipAuthentication
    case activeAuthentication
    case passiveAuthentication
    case securityPolicyValidation

    public var description: String {
        switch self {
        case .unknown:
            return "unknown"
        case .waitingForPassport:
            return "waiting for passport"
        case .connecting:
            return "connecting"
        case .pace:
            return "PACE"
        case .bac:
            return "BAC"
        case .readingDataGroup(let dataGroup):
            return "reading \(dataGroup.getName())"
        case .chipAuthentication:
            return "chip authentication"
        case .activeAuthentication:
            return "active authentication"
        case .passiveAuthentication:
            return "passive authentication"
        case .securityPolicyValidation:
            return "security policy validation"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public enum PassportReaderPACEPolicy: Sendable, Equatable {
    /// Attempt PACE when enabled, but allow the existing BAC fallback behavior.
    case allowBACFallback

    /// If PACE is advertised and attempted, fail the scan instead of falling back to BAC.
    case requirePACEWhenAdvertised

    /// Require the caller to provide a non-MRZ PACE credential for PACE-capable flows.
    case requireExplicitCredential(PassportPACEKeyReference)
}
