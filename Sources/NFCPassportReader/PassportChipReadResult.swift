//
//  PassportChipReadResult.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Privacy-preserving chip scan result for host-app integration.
///
/// This type intentionally omits raw data groups, MRZ text, APDUs, certificates, keys,
/// active-authentication challenge/signature bytes, and passport image bytes. It also
/// intentionally does not conform to `Codable`; host apps should make explicit retention
/// decisions before storing or uploading identity-document data.
@available(iOS 13, macOS 10.15, *)
public struct PassportChipReadResult: Sendable, Equatable {
    public let identity: PassportIdentityResult
    public let verificationResult: PassportVerificationResult
    public let trustLevel: PassportTrustLevel
    public let certificateTrustMetadata: PassportCertificateTrustMetadata
    public let diagnosticsSummary: PassportReaderDiagnosticsSummary

    public init(passport: NFCPassportModel) {
        self.identity = passport.identityResult
        self.verificationResult = passport.verificationResult
        self.trustLevel = PassportTrustLevel(passport: passport)
        self.certificateTrustMetadata = PassportCertificateTrustMetadata(passport: passport)
        self.diagnosticsSummary = PassportReaderDiagnosticsSummary(passport: passport)
    }
}
