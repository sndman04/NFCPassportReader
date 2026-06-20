//
//  PassportScanOptions.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Coherent scan configuration for privacy and verification-sensitive apps.
///
/// Prefer these presets when the host app wants a reviewed combination of profile,
/// authentication behavior, timeout, photo handling, and verification policy.
@available(iOS 13, macOS 10.15, *)
public struct PassportScanOptions: Sendable, Equatable {
    public static let defaultCompatibility = PassportScanOptions()

    public static let notaryStrict = PassportScanOptions(
        scanProfile: .fullVerification,
        skipSecureElements: false,
        skipCA: false,
        skipPACE: false,
        useExtendedMode: true,
        operationTimeout: 60,
        photoPolicy: .read,
        securityPolicy: .notaryRecommended
    )

    public static let identityOnly = PassportScanOptions(
        scanProfile: .identityOnly,
        skipSecureElements: true,
        skipCA: true,
        skipPACE: false,
        useExtendedMode: false,
        operationTimeout: 45,
        photoPolicy: .skip,
        securityPolicy: .identityOnly
    )

    public let scanProfile: PassportScanProfile
    public let skipSecureElements: Bool
    public let skipCA: Bool
    public let skipPACE: Bool
    public let useExtendedMode: Bool
    public let operationTimeout: TimeInterval?
    public let photoPolicy: PassportPhotoPolicy
    public let securityPolicy: PassportReaderSecurityPolicy

    public init(
        scanProfile: PassportScanProfile = .custom([]),
        skipSecureElements: Bool = true,
        skipCA: Bool = false,
        skipPACE: Bool = false,
        useExtendedMode: Bool = false,
        operationTimeout: TimeInterval? = nil,
        photoPolicy: PassportPhotoPolicy = .read,
        securityPolicy: PassportReaderSecurityPolicy = .default
    ) {
        self.scanProfile = scanProfile
        self.skipSecureElements = skipSecureElements
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        self.operationTimeout = operationTimeout
        self.photoPolicy = photoPolicy
        self.securityPolicy = securityPolicy
    }
}
