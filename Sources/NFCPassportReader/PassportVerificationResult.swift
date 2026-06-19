//
//  PassportVerificationResult.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportVerificationStatus: Sendable, Equatable {
    case notChecked
    case passed
    case failed
}

@available(iOS 13, macOS 10.15, *)
public struct PassportVerificationResult: Sendable, Equatable {
    public let sodSignatureStatus: PassportVerificationStatus
    public let dataGroupHashStatus: PassportVerificationStatus
    public let documentSignerCertificateStatus: PassportVerificationStatus
    public let countrySigningCertificateStatus: PassportVerificationStatus
    public let activeAuthenticationStatus: PassportVerificationStatus
    public let chipAuthenticationStatus: PassportVerificationStatus

    public var overallStatus: PassportVerificationStatus {
        let statuses = [
            sodSignatureStatus,
            dataGroupHashStatus,
            documentSignerCertificateStatus,
            countrySigningCertificateStatus,
            activeAuthenticationStatus,
            chipAuthenticationStatus
        ]

        if statuses.contains(.failed) {
            return .failed
        }

        if statuses.contains(.passed) {
            return .passed
        }

        return .notChecked
    }
}

