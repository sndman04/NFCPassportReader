//
//  PassportIdentityResult.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Normalized app-facing passport fields and verification summary.
///
/// This type intentionally does not conform to `Codable`. Host apps should make explicit,
/// privacy-reviewed decisions before persisting, uploading, copying, or logging identity data.
@available(iOS 13, macOS 10.15, *)
public struct PassportIdentityResult: Sendable, Equatable {
    public let documentType: String
    public let documentSubType: String
    public let documentNumber: String
    public let issuingAuthority: String
    public let documentExpiryDate: String
    public let dateOfBirth: String
    public let gender: String
    public let nationality: String
    public let lastName: String
    public let firstName: String
    public let personalNumber: String?
    public let placeOfBirth: String?
    public let residenceAddress: String?
    public let phoneNumber: String?
    public let hasFaceImage: Bool
    public let hasSignatureImage: Bool
    public let dataGroupsRead: [DataGroupId]
    public let verificationResult: PassportVerificationResult
    public let trustLevel: PassportTrustLevel
    public let certificateTrustMetadata: PassportCertificateTrustMetadata

    public init(passport: NFCPassportModel) {
        self.documentType = passport.documentType
        self.documentSubType = passport.documentSubType
        self.documentNumber = passport.documentNumber
        self.issuingAuthority = passport.issuingAuthority
        self.documentExpiryDate = passport.documentExpiryDate
        self.dateOfBirth = passport.dateOfBirth
        self.gender = passport.gender
        self.nationality = passport.nationality
        self.lastName = passport.lastName
        self.firstName = passport.firstName
        self.personalNumber = passport.personalNumber
        self.placeOfBirth = passport.placeOfBirth
        self.residenceAddress = passport.residenceAddress
        self.phoneNumber = passport.phoneNumber
        self.hasFaceImage = passport.getDataGroup(.DG2) != nil
        self.hasSignatureImage = passport.getDataGroup(.DG7) != nil
        self.dataGroupsRead = passport.dataGroupsAvailable
        self.verificationResult = passport.verificationResult
        self.trustLevel = PassportTrustLevel(passport: passport)
        self.certificateTrustMetadata = PassportCertificateTrustMetadata(passport: passport)
    }
}

@available(iOS 13, macOS 10.15, *)
public extension NFCPassportModel {
    /// Returns normalized fields and safe verification metadata for app integration.
    ///
    /// The returned value still contains personal identity data. It intentionally omits MRZ text,
    /// raw data-group bytes, APDU data, certificates, cryptographic material, and image bytes.
    var identityResult: PassportIdentityResult {
        PassportIdentityResult(passport: self)
    }
}
