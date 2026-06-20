//
//  PassportTrustLevel.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportTrustLevel: Sendable, Equatable, CustomStringConvertible {
    case chipReadOnly
    case dataIntegrityVerified
    case documentSignerTrusted
    case chipAuthenticated
    case verificationFailed
    case inconclusive

    public init(passport: NFCPassportModel) {
        let verification = passport.verificationResult

        if verification.overallStatus == .failed {
            self = .verificationFailed
        } else if verification.chipAuthenticationStatus == .passed {
            self = .chipAuthenticated
        } else if verification.countrySigningCertificateStatus == .passed
            && verification.documentSignerCertificateStatus == .passed {
            self = .documentSignerTrusted
        } else if verification.sodSignatureStatus == .passed
            && verification.dataGroupHashStatus == .passed {
            self = .dataIntegrityVerified
        } else if !passport.dataGroupsRead.isEmpty {
            self = .chipReadOnly
        } else {
            self = .inconclusive
        }
    }

    public var description: String {
        switch self {
        case .chipReadOnly:
            return "chip data read without completed verification"
        case .dataIntegrityVerified:
            return "passport data integrity verified"
        case .documentSignerTrusted:
            return "document signer trusted"
        case .chipAuthenticated:
            return "chip authenticated"
        case .verificationFailed:
            return "verification failed"
        case .inconclusive:
            return "verification inconclusive"
        }
    }

    public var privacySafeExplanation: String {
        switch self {
        case .chipReadOnly:
            return "Passport chip data was read, but verification did not complete."
        case .dataIntegrityVerified:
            return "The read passport chip data groups matched the signed document security object."
        case .documentSignerTrusted:
            return "The read passport chip data groups matched the signed document security object, and signer trust was verified."
        case .chipAuthenticated:
            return "The read passport chip data groups and chip authentication were verified."
        case .verificationFailed:
            return "Passport chip verification failed."
        case .inconclusive:
            return "Passport chip verification was inconclusive."
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public struct PassportCertificateTrustMetadata: Sendable, Equatable {
    public let verificationAttempted: Bool
    public let masterListProvided: Bool
    public let documentSigningCertificatePresent: Bool
    public let countrySigningCertificatePresent: Bool
    public let signerTrustEstablished: Bool

    public init(passport: NFCPassportModel) {
        self.verificationAttempted = passport.passportVerificationAttempted
        self.masterListProvided = passport.masterListWasProvided
        self.documentSigningCertificatePresent = passport.documentSigningCertificate != nil
        self.countrySigningCertificatePresent = passport.countrySigningCertificate != nil
        self.signerTrustEstablished = passport.verificationResult.documentSignerCertificateStatus == .passed
            && passport.verificationResult.countrySigningCertificateStatus == .passed
    }
}
