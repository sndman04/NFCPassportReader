//
//  PassportReaderSecurityPolicy.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Controls privacy and verification decisions that should be deliberate at the host-app boundary.
@available(iOS 13, macOS 10.15, *)
public struct PassportReaderSecurityPolicy: Sendable, Equatable {
    /// Permissive default. Allows requested photo reads and does not fail a read solely because
    /// verification is incomplete.
    public static let `default` = PassportReaderSecurityPolicy()

    /// Conservative policy for apps that only need normalized identity fields.
    public static let identityOnly = PassportReaderSecurityPolicy(
        allowsPassportPhoto: false,
        verificationRequirement: .none
    )

    /// Recommended starting point for Notary Journal: allow photo review and require
    /// passive-authentication integrity checks to pass when verification is attempted.
    public static let notaryRecommended = PassportReaderSecurityPolicy(
        allowsPassportPhoto: true,
        verificationRequirement: .passiveAuthentication
    )

    public let allowsPassportPhoto: Bool
    public let verificationRequirement: PassportVerificationRequirement
    /// Require trusted passive authentication and a successful current offline CRL check.
    /// Defaults to false for compatibility; configure the reader with a local CRL bundle.
    public let requiresRevocationCheck: Bool

    public init(
        allowsPassportPhoto: Bool = true,
        verificationRequirement: PassportVerificationRequirement = .none,
        requiresRevocationCheck: Bool = false
    ) {
        self.allowsPassportPhoto = allowsPassportPhoto
        self.verificationRequirement = verificationRequirement
        self.requiresRevocationCheck = requiresRevocationCheck
    }

    func apply(to photoPolicy: PassportPhotoPolicy) -> PassportPhotoPolicy {
        allowsPassportPhoto ? photoPolicy : .skip
    }

    func validate(_ passport: NFCPassportModel) throws {
        guard verificationRequirement.isSatisfied(by: passport),
              !requiresRevocationCheck || (PassportVerificationRequirement.trustedPassiveAuthentication.isSatisfied(by: passport)
                && passport.diagnosticEvidence.revocation.status == .succeeded) else {
            throw NFCPassportReaderError.SecurityPolicyViolation
        }
    }

    var requiresChipAuthenticationWhenSupported: Bool {
        verificationRequirement == .chipAuthenticationWhenSupported
            || verificationRequirement == .fullVerificationWhenSupported
    }

    var requiresActiveAuthenticationWhenSupported: Bool {
        verificationRequirement == .activeAuthenticationWhenSupported
            || verificationRequirement == .fullVerificationWhenSupported
    }
}

/// Verification strictness for `PassportReaderSecurityPolicy`.
@available(iOS 13, macOS 10.15, *)
public enum PassportVerificationRequirement: Sendable, Equatable {
    /// Do not fail the scan because verification was not attempted or did not pass.
    case none

    /// Require SOD signature and data-group hash verification to pass.
    case passiveAuthentication

    /// Require passive authentication and trusted signer-chain verification to pass.
    case trustedPassiveAuthentication

    /// Require chip authentication to pass when the passport advertises chip authentication support.
    /// Missing advertised authentication data or unknown availability fails this requirement.
    case chipAuthenticationWhenSupported

    /// Require active authentication to pass when the passport advertises active authentication support.
    /// Missing advertised authentication data or unknown availability fails this requirement.
    case activeAuthenticationWhenSupported

    /// Require passive authentication, trusted signer-chain verification, and chip/active authentication
    /// when those mechanisms are advertised by the passport.
    case fullVerificationWhenSupported

    func isSatisfied(by passport: NFCPassportModel) -> Bool {
        let verification = passport.verificationResult

        switch self {
        case .none:
            return true
        case .passiveAuthentication:
            return verification.sodSignatureStatus == .passed
                && verification.dataGroupHashStatus == .passed
        case .trustedPassiveAuthentication:
            return verification.sodSignatureStatus == .passed
                && verification.dataGroupHashStatus == .passed
                && verification.documentSignerCertificateStatus == .passed
                && verification.countrySigningCertificateStatus == .passed
        case .chipAuthenticationWhenSupported:
            return verification.chipAuthenticationStatus == .passed
                || verification.chipAuthenticationDetail.reason == .notSupported
        case .activeAuthenticationWhenSupported:
            return verification.activeAuthenticationStatus == .passed
                || verification.activeAuthenticationDetail.reason == .notSupported
        case .fullVerificationWhenSupported:
            return PassportVerificationRequirement.trustedPassiveAuthentication.isSatisfied(by: passport)
                && PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: passport)
                && PassportVerificationRequirement.activeAuthenticationWhenSupported.isSatisfied(by: passport)
        }
    }
}
