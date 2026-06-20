//
//  PassportChipReading.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 15, *)
public protocol PassportChipReading {
    func readPassport(
        mrzKey: String,
        scanProfile: PassportScanProfile,
        aaChallenge: [UInt8]?,
        skipSecureElements: Bool,
        skipCA: Bool,
        skipPACE: Bool,
        useExtendedMode: Bool,
        operationTimeout: TimeInterval?,
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy,
        progressHandler: PassportReaderProgressHandler?,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)?
    ) async throws -> NFCPassportModel
}

@available(iOS 15, *)
extension PassportChipReading {
    public func readPassport(
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
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> NFCPassportModel {
        try await readPassport(
            mrzKey: mrzKey,
            scanProfile: scanProfile,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }
}

@available(iOS 15, *)
extension PassportReader: PassportChipReading {}

@available(iOS 15, *)
public struct PassportReaderFixture: PassportChipReading {
    public let result: Result<NFCPassportModel, NFCPassportReaderError>

    public init(result: Result<NFCPassportModel, NFCPassportReaderError>) {
        self.result = result
    }

    public func readPassport(
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
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> NFCPassportModel {
        progressHandler?(.waitingForPassport)

        switch result {
        case .success(let model):
            try securityPolicy.validate(model)
            progressHandler?(.complete)
            return model
        case .failure(let error):
            throw error
        }
    }
}
