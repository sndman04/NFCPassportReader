//
//  PassportChipReading.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 15, *)
public protocol PassportChipReading {
    func readPassportIdentity(
        mrzKey: String,
        options: PassportScanOptions,
        aaChallenge: [UInt8]?,
        progressHandler: PassportReaderProgressHandler?,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)?
    ) async throws -> PassportChipReadResult
}

@available(iOS 15, *)
extension PassportChipReading {
    public func readPassportIdentity(
        mrzKey: String,
        scanProfile: PassportScanProfile,
        aaChallenge: [UInt8]? = nil,
        skipSecureElements: Bool = true,
        skipCA: Bool = false,
        skipPACE: Bool = false,
        useExtendedMode: Bool = false,
        operationTimeout: TimeInterval? = nil,
        photoPolicy: PassportPhotoPolicy = .read,
        securityPolicy: PassportReaderSecurityPolicy = .default,
        pacePolicy: PassportReaderPACEPolicy = .allowBACFallback,
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> PassportChipReadResult {
        try await readPassportIdentity(
            mrzKey: mrzKey,
            options: PassportScanOptions(
                scanProfile: scanProfile,
                skipSecureElements: skipSecureElements,
                skipCA: skipCA,
                skipPACE: skipPACE,
                useExtendedMode: useExtendedMode,
                operationTimeout: operationTimeout,
                photoPolicy: photoPolicy,
                securityPolicy: securityPolicy,
                pacePolicy: pacePolicy
            ),
            aaChallenge: aaChallenge,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }
}

@available(iOS 15, *)
extension PassportReader: PassportChipReading {}

@available(iOS 15, *)
public struct PassportReaderFixture: PassportChipReading {
    public let result: Result<PassportChipReadResult, NFCPassportReaderError>

    public init(result: Result<PassportChipReadResult, NFCPassportReaderError>) {
        self.result = result
    }

    public func readPassportIdentity(
        mrzKey: String,
        options: PassportScanOptions,
        aaChallenge: [UInt8]? = nil,
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> PassportChipReadResult {
        progressHandler?(.waitingForPassport)

        switch result {
        case .success(let result):
            progressHandler?(.complete)
            return result
        case .failure(let error):
            throw error
        }
    }
}
