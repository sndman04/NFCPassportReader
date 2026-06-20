//
//  UnsafePassportRawDataExporter.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Explicit raw passport-data export surface for rare, privacy-reviewed workflows.
///
/// The exported values can contain sensitive identity-document data, image bytes, and optional
/// active-authentication material. Normal app integrations should use `PassportIdentityResult`
/// and `PassportVerificationResult` instead.
@available(iOS 13, macOS 10.15, *)
public struct UnsafePassportRawDataExporter {
    private let securityPolicy: PassportReaderSecurityPolicy

    public init(securityPolicy: PassportReaderSecurityPolicy) {
        self.securityPolicy = securityPolicy
    }

    public func unsafeExportRawPassportData(
        from passport: NFCPassportModel,
        selectedDataGroups: [DataGroupId],
        includeActiveAuthenticationData: Bool = false
    ) throws -> [String: String] {
        guard securityPolicy.allowsUnsafeRawDataExport else {
            throw NFCPassportReaderError.RawDataExportNotAllowed
        }

        return passport.unsafeDumpPassportData(
            selectedDataGroups: selectedDataGroups,
            includeActiveAuthenticationData: includeActiveAuthenticationData
        )
    }
}
