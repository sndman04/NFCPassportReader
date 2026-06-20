//
//  PassportReaderDiagnosticsSummary.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Privacy-safe support metadata for a passport scan.
///
/// This summary intentionally excludes MRZ values, identity fields, APDUs, certificates,
/// data-group bytes, cryptographic material, and image bytes.
@available(iOS 13, macOS 10.15, *)
public struct PassportReaderDiagnosticsSummary: Sendable, Equatable {
    public let scanProfile: PassportScanProfile
    public let photoPolicy: PassportPhotoPolicy
    public let securityPolicy: PassportReaderSecurityPolicy
    public let failure: PassportReaderFailure?
    public let verificationResult: PassportVerificationResult?
    public let trustLevel: PassportTrustLevel?
    public let dataGroupsRead: [DataGroupId]
    public let dataGroupReadReports: [PassportDataGroupReadReport]

    public init(
        scanProfile: PassportScanProfile,
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy = .default,
        failure: PassportReaderFailure
    ) {
        self.scanProfile = scanProfile
        self.photoPolicy = photoPolicy
        self.securityPolicy = securityPolicy
        self.failure = failure
        self.verificationResult = nil
        self.trustLevel = nil
        self.dataGroupsRead = []
        self.dataGroupReadReports = []
    }

    init(
        scanProfile: PassportScanProfile,
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy = .default,
        passport: NFCPassportModel
    ) {
        self.scanProfile = scanProfile
        self.photoPolicy = photoPolicy
        self.securityPolicy = securityPolicy
        self.failure = nil
        self.verificationResult = passport.verificationResult
        self.trustLevel = PassportTrustLevel(passport: passport)
        self.dataGroupsRead = passport.dataGroupsAvailable
        self.dataGroupReadReports = passport.dataGroupReadReports
    }

    init(passport: NFCPassportModel) {
        self.scanProfile = .custom(passport.dataGroupsAvailable)
        self.photoPolicy = passport.getDataGroup(.DG2) == nil ? .skip : .read
        self.securityPolicy = .default
        self.failure = nil
        self.verificationResult = passport.verificationResult
        self.trustLevel = PassportTrustLevel(passport: passport)
        self.dataGroupsRead = passport.dataGroupsAvailable
        self.dataGroupReadReports = passport.dataGroupReadReports
    }
}
