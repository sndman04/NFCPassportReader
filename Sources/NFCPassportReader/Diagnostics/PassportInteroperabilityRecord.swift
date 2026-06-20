//
//  PassportInteroperabilityRecord.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Synthetic, non-identifying metadata for private real-device compatibility tracking.
///
/// Do not add MRZ text, passport numbers, names, dates, certificate details, APDUs,
/// images, or raw data-group values to interoperability records.
@available(iOS 13, macOS 10.15, *)
public struct PassportInteroperabilityRecord: Sendable, Equatable {
    public let issuingRegionCode: String?
    public let chipFeatureClass: String
    public let scanOptions: PassportScanOptions
    public let verificationResult: PassportVerificationResult?
    public let trustLevel: PassportTrustLevel?
    public let notes: String?

    public init(
        issuingRegionCode: String?,
        chipFeatureClass: String,
        scanOptions: PassportScanOptions,
        verificationResult: PassportVerificationResult?,
        trustLevel: PassportTrustLevel?,
        notes: String? = nil
    ) {
        self.issuingRegionCode = issuingRegionCode?.uppercased()
        self.chipFeatureClass = chipFeatureClass
        self.scanOptions = scanOptions
        self.verificationResult = verificationResult
        self.trustLevel = trustLevel
        self.notes = notes
    }

    public var containsOnlyNonIdentifyingFields: Bool {
        let text = [issuingRegionCode, chipFeatureClass, notes].compactMap { $0 }.joined(separator: " ")
        return text.range(of: #"[A-Z0-9<]{30,}"#, options: .regularExpression) == nil
            && text.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression) == nil
    }
}
