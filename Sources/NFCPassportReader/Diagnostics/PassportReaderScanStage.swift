//
//  PassportReaderScanStage.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportReaderScanStage: Sendable, Equatable, Encodable, CustomStringConvertible {
    case unknown
    case waitingForPassport
    case connecting
    case pace
    /// Restoring the application after failed/unavailable PACE; BAC has not started.
    case bacFallbackPreparation
    case bac
    case readingDataGroup(DataGroupId)
    case chipAuthentication
    case activeAuthentication
    case passiveAuthentication
    case securityPolicyValidation

    private enum CodingKeys: String, CodingKey { case name, dataGroup }

    /// Stable structural encoding used by diagnostic schema version 1.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let name: String
        switch self {
        case .unknown: name = "unknown"
        case .waitingForPassport: name = "waitingForPassport"
        case .connecting: name = "connecting"
        case .pace: name = "pace"
        case .bacFallbackPreparation: name = "bacFallbackPreparation"
        case .bac: name = "bac"
        case .readingDataGroup(let group):
            name = "readingDataGroup"
            try container.encode(group, forKey: .dataGroup)
        case .chipAuthentication: name = "chipAuthentication"
        case .activeAuthentication: name = "activeAuthentication"
        case .passiveAuthentication: name = "passiveAuthentication"
        case .securityPolicyValidation: name = "securityPolicyValidation"
        }
        try container.encode(name, forKey: .name)
    }

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
        case .bacFallbackPreparation:
            return "preparing BAC fallback"
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
