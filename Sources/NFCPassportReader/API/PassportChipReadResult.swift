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
/// and active-authentication challenge/signature bytes. Face-image bytes are included only
/// when the effective `PassportPhotoPolicy` is `.read`. It also intentionally does not
/// conform to `Codable`; host apps should make explicit retention decisions before storing
/// or uploading identity-document data.
@available(iOS 13, macOS 10.15, *)
public struct PassportChipReadResult: Sendable, Equatable {
    public let identity: PassportIdentityResult
    /// Sensitive DG2 face-image bytes, present only when the scan's effective photo policy is `.read`.
    public let faceImageData: PassportChipImageResult?
    public let verificationResult: PassportVerificationResult
    public let trustLevel: PassportTrustLevel
    public let certificateTrustMetadata: PassportCertificateTrustMetadata
    public let diagnosticsSummary: PassportReaderDiagnosticsSummary

    init(passport: NFCPassportModel, photoPolicy: PassportPhotoPolicy = .read) {
        self.identity = passport.identityResult
        if let dg2 = passport.getDataGroup(.DG2) as? DataGroup2 {
            self.faceImageData = PassportChipImageResult(dataGroup: dg2, photoPolicy: photoPolicy)
        } else {
            self.faceImageData = nil
        }
        self.verificationResult = passport.verificationResult
        self.trustLevel = PassportTrustLevel(passport: passport)
        self.certificateTrustMetadata = PassportCertificateTrustMetadata(passport: passport)
        self.diagnosticsSummary = PassportReaderDiagnosticsSummary(passport: passport)
    }
}
