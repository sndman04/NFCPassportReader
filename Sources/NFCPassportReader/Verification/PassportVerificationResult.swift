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
    public let sodSignatureDetail: PassportVerificationCheck
    public let dataGroupHashDetail: PassportVerificationCheck
    public let documentSignerCertificateDetail: PassportVerificationCheck
    public let countrySigningCertificateDetail: PassportVerificationCheck
    public let activeAuthenticationDetail: PassportVerificationCheck
    public let chipAuthenticationDetail: PassportVerificationCheck
    public let dataGroupCoverage: [PassportDataGroupVerificationCoverage]

    public init(
        sodSignatureStatus: PassportVerificationStatus,
        dataGroupHashStatus: PassportVerificationStatus,
        documentSignerCertificateStatus: PassportVerificationStatus,
        countrySigningCertificateStatus: PassportVerificationStatus,
        activeAuthenticationStatus: PassportVerificationStatus,
        chipAuthenticationStatus: PassportVerificationStatus,
        sodSignatureDetail: PassportVerificationCheck? = nil,
        dataGroupHashDetail: PassportVerificationCheck? = nil,
        documentSignerCertificateDetail: PassportVerificationCheck? = nil,
        countrySigningCertificateDetail: PassportVerificationCheck? = nil,
        activeAuthenticationDetail: PassportVerificationCheck? = nil,
        chipAuthenticationDetail: PassportVerificationCheck? = nil,
        dataGroupCoverage: [PassportDataGroupVerificationCoverage] = []
    ) {
        self.sodSignatureStatus = sodSignatureStatus
        self.dataGroupHashStatus = dataGroupHashStatus
        self.documentSignerCertificateStatus = documentSignerCertificateStatus
        self.countrySigningCertificateStatus = countrySigningCertificateStatus
        self.activeAuthenticationStatus = activeAuthenticationStatus
        self.chipAuthenticationStatus = chipAuthenticationStatus
        self.sodSignatureDetail = sodSignatureDetail ?? PassportVerificationCheck(
            status: sodSignatureStatus,
            reason: sodSignatureStatus.defaultDetailReason
        )
        self.dataGroupHashDetail = dataGroupHashDetail ?? PassportVerificationCheck(
            status: dataGroupHashStatus,
            reason: dataGroupHashStatus.defaultDetailReason
        )
        self.documentSignerCertificateDetail = documentSignerCertificateDetail ?? PassportVerificationCheck(
            status: documentSignerCertificateStatus,
            reason: documentSignerCertificateStatus.defaultDetailReason
        )
        self.countrySigningCertificateDetail = countrySigningCertificateDetail ?? PassportVerificationCheck(
            status: countrySigningCertificateStatus,
            reason: countrySigningCertificateStatus.defaultDetailReason
        )
        self.activeAuthenticationDetail = activeAuthenticationDetail ?? PassportVerificationCheck(
            status: activeAuthenticationStatus,
            reason: activeAuthenticationStatus.defaultDetailReason
        )
        self.chipAuthenticationDetail = chipAuthenticationDetail ?? PassportVerificationCheck(
            status: chipAuthenticationStatus,
            reason: chipAuthenticationStatus.defaultDetailReason
        )
        self.dataGroupCoverage = dataGroupCoverage
    }

    public var overallStatus: PassportVerificationStatus {
        if sodSignatureStatus == .failed
            || dataGroupHashStatus == .failed
            || documentSignerCertificateStatus == .failed
            || countrySigningCertificateStatus == .failed
            || activeAuthenticationStatus == .failed
            || chipAuthenticationStatus == .failed {
            return .failed
        }

        if sodSignatureStatus == .passed
            || dataGroupHashStatus == .passed
            || documentSignerCertificateStatus == .passed
            || countrySigningCertificateStatus == .passed
            || activeAuthenticationStatus == .passed
            || chipAuthenticationStatus == .passed {
            return .passed
        }

        return .notChecked
    }
}

@available(iOS 13, macOS 10.15, *)
private extension PassportVerificationStatus {
    var defaultDetailReason: PassportVerificationDetailReason {
        switch self {
        case .notChecked:
            return .notRequested
        case .passed:
            return .passed
        case .failed:
            return .attemptedFailed
        }
    }
}
