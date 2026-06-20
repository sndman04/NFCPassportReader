//
//  PassportReaderPrivacyCopy.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Suggested privacy-safe copy for host apps.
@available(iOS 13, macOS 10.15, *)
public enum PassportReaderPrivacyCopy {
    public static let nfcConsent = "This scan reads identity data from the passport chip and may read the passport photo if required for review."
    public static let noRawDiagnostics = "Support diagnostics should include scan status and verification summary only, not passport numbers, MRZ text, photos, certificates, or chip data."
    public static let verificationInconclusive = "Passport chip data was read, but authenticity verification was inconclusive."
}
