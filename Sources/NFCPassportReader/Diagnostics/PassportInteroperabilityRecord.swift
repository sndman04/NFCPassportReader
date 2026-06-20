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
        let sensitivePatterns = [
            #"[A-Z0-9<]{30,}"#,
            #"(?i)(?:[0-9a-f]{2}[\s:.-]?){8,}"#,
            #"(?i)\b(?:mrz|passport\s*(?:no|number)|document\s*(?:no|number)|date\s*of\s*birth|dob|birth\s*date|expiry|expiration|surname|given\s*name|full\s*name|photo|image|face\s*image)\b"#,
            #"(?i)\b(?:apdu|rapdu|kseed|ksenc|ksmac|rnd\.ifd|rnd\.icc|bac\s*key|pace\s*key|session\s*key|certificate\s*(?:dump|serial|fingerprint|thumbprint)|fingerprint|thumbprint)\b"#
        ]

        return sensitivePatterns.allSatisfy { pattern in
            text.range(of: pattern, options: .regularExpression) == nil
        }
    }
}
