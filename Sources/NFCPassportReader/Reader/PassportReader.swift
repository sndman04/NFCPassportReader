//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

#if !os(macOS)
@preconcurrency import UIKit
@preconcurrency import CoreNFC

@available(iOS 15, *)
protocol PassportReaderTrackingDelegate: AnyObject {
    func nfcTagDetected()
    func readCardAccess(cardAccess: CardAccess)
    func paceStarted()
    func paceSucceeded()
    func paceFailed()
    func bacStarted()
    func bacSucceeded()
    func bacFailed()
}

@available(iOS 15, *)
extension PassportReaderTrackingDelegate {
    func nfcTagDetected() { /* default implementation */ }
    func readCardAccess(cardAccess: CardAccess) { /* default implementation */ }
    func paceStarted() { /* default implementation */ }
    func paceSucceeded() { /* default implementation */ }
    func paceFailed() { /* default implementation */ }
    func bacStarted() { /* default implementation */ }
    func bacSucceeded() { /* default implementation */ }
    func bacFailed() { /* default implementation */ }
}

@available(iOS 15, *)
@MainActor
public class PassportReader : NSObject {
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    private static let nanosecondsPerSecond: UInt64 = 1_000_000_000
    private var nfcContinuation: NFCCheckedContinuation?
    private let scanStateLock = NSLock()
    private var scanInProgress = false
    private var activeScanID: UInt64 = 0
    private let eventLogger: PassportReaderEventLogger
    private var progressHandler: PassportReaderProgressHandler?
    private var scanTimeoutTask: Task<Void, Never>?
    private var securityPolicy: PassportReaderSecurityPolicy = .default

    weak var trackingDelegate: PassportReaderTrackingDelegate?
    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var currentlyReadingDataGroup : DataGroupId?
    private var progressRenderGeneration = 0
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    private var pacePolicy: PassportReaderPACEPolicy = .allowBACFallback
    private var effectivePhotoPolicy: PassportPhotoPolicy = .read
    
    // Extended mode is used for reading eMRTD's that support extended length APDUs
    private var useExtendedMode = false

    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var paceKey : String?
    private var paceKeyReference: PassportPACEKeyReference = .mrz
    private var pendingPACECredential: (key: String, reference: PassportPACEKeyReference)?
    private var aaChallenge: [UInt8]?
    private var dataAmountToReadOverride : Int? = nil
    
    private var nfcViewDisplayMessageHandler: PassportReaderDisplayMessageHandler?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false

    // By default, Passive Authentication uses the new RFS5652 method to verify the SOD, but can be switched to use
    // the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL : Bool = false

    public init(
        masterListURL: URL? = nil,
        logLevel: PassportReaderLogLevel = .off,
        logger: PassportReaderLogging? = nil
    ) {
        self.eventLogger = PassportReaderEventLogger(level: logLevel, sink: logger)
        super.init()
        
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL( _ masterListURL : URL ) {
        self.masterListURL = masterListURL
    }
    
    // This function allows you to override the amount of data the TagReader tries to read from the NFC
    // chip. NOTE - this really shouldn't be used for production but is useful for testing as different
    // passports support different data amounts.
    // It appears that the most reliable is 0xA0 (160 chars) but some will support arbitary reads (0xFF or 256)
    func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
    
    func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, operationTimeout: TimeInterval? = nil, photoPolicy: PassportPhotoPolicy = .read, securityPolicy: PassportReaderSecurityPolicy = .default, pacePolicy: PassportReaderPACEPolicy = .allowBACFallback, progressHandler: PassportReaderProgressHandler? = nil, customDisplayMessage : PassportReaderDisplayMessageHandler? = nil) async throws -> NFCPassportModel {
        guard NFCNDEFReaderSession.readingAvailable else {
            pendingPACECredential = nil
            eventLogger.log(.readFailed(.nfcNotSupported))
            throw NFCPassportReaderError.NFCNotSupported
        }

        self.pacePolicy = pacePolicy
        try validatePACEPolicyBeforeSession(skipPACE: skipPACE)
        try validateActiveAuthenticationChallengeBeforeSession(aaChallenge)

        guard let scanID = beginScanIfPossible() else {
            pendingPACECredential = nil
            eventLogger.log(.readFailed(.unexpectedReadFailure))
            throw NFCPassportReaderError.ScanAlreadyInProgress
        }

        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        let paceCredential = pendingPACECredential
        pendingPACECredential = nil
        self.paceKey = paceCredential?.key ?? mrzKey
        self.paceKeyReference = paceCredential?.reference ?? .mrz
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.pacePolicy = pacePolicy
        self.useExtendedMode = useExtendedMode
        self.securityPolicy = securityPolicy
        
        self.effectivePhotoPolicy = securityPolicy.apply(to: photoPolicy)
        let initialRequest = Self.initialDataGroupReadRequest(
            tags: tags,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy
        )
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append(contentsOf: initialRequest.dataGroups)
        self.dataGroupsToRead.forEach { self.passport.recordDataGroupReadStatus(.requested, for: $0) }
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.progressHandler = progressHandler
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        self.readAllDatagroups = initialRequest.readAllDataGroups

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
                guard self.storeActiveScanContinuation(continuation, scanID: scanID) else {
                    continuation.resume(throwing: NFCPassportReaderError.UserCanceled)
                    return
                }

                guard NFCTagReaderSession.readingAvailable else {
                    self.failActiveScan(error: .NFCNotSupported, scanID: scanID)
                    return
                }

                guard let readerSession = PassportNFCSessionFactory.makeTagReaderSession(delegate: self) else {
                    self.failActiveScan(error: .UnexpectedError, scanID: scanID)
                    return
                }

                self.readerSession = readerSession
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
                self.emitProgress(.waitingForPassport)
                self.startTimeoutTask(operationTimeout, scanID: scanID)
                readerSession.begin()
            })
        } onCancel: {
            Task { @MainActor in
                self.cancelRead(scanID: scanID)
            }
        }
    }

    func readPassport(
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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> NFCPassportModel {
        try await readPassport(
            mrzKey: mrzKey,
            tags: scanProfile.dataGroups,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }

    func readPassport(
        mrzKey: String,
        tags: [DataGroupId] = [],
        paceKey: String,
        paceKeyReference: PassportPACEKeyReference,
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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> NFCPassportModel {
        self.pendingPACECredential = (paceKey, paceKeyReference)
        return try await readPassport(
            mrzKey: mrzKey,
            tags: tags,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }

    func readPassport(
        mrzKey: String,
        scanProfile: PassportScanProfile,
        paceKey: String,
        paceKeyReference: PassportPACEKeyReference,
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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> NFCPassportModel {
        try await readPassport(
            mrzKey: mrzKey,
            tags: scanProfile.dataGroups,
            paceKey: paceKey,
            paceKeyReference: paceKeyReference,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }

    func readPassport(
        mrzKey: String,
        options: PassportScanOptions,
        aaChallenge: [UInt8]? = nil,
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> NFCPassportModel {
        try await readPassport(
            mrzKey: mrzKey,
            scanProfile: options.scanProfile,
            aaChallenge: aaChallenge,
            skipSecureElements: options.skipSecureElements,
            skipCA: options.skipCA,
            skipPACE: options.skipPACE,
            useExtendedMode: options.useExtendedMode,
            operationTimeout: options.operationTimeout,
            photoPolicy: options.photoPolicy,
            securityPolicy: options.securityPolicy,
            pacePolicy: options.pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }

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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> PassportChipReadResult {
        let passport = try await readPassport(
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
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
        return makeIdentityResultAndScrubPassport(
            passport,
            photoPolicy: securityPolicy.apply(to: photoPolicy),
            securityPolicy: securityPolicy
        )
    }

    public func readPassportIdentity(
        mrzKey: String,
        scanProfile: PassportScanProfile,
        paceKey: String,
        paceKeyReference: PassportPACEKeyReference,
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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> PassportChipReadResult {
        let passport = try await readPassport(
            mrzKey: mrzKey,
            scanProfile: scanProfile,
            paceKey: paceKey,
            paceKeyReference: paceKeyReference,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
        return makeIdentityResultAndScrubPassport(
            passport,
            photoPolicy: securityPolicy.apply(to: photoPolicy),
            securityPolicy: securityPolicy
        )
    }

    func readPassportIdentity(
        mrzKey: String,
        tags: [DataGroupId] = [],
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
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> PassportChipReadResult {
        let passport = try await readPassport(
            mrzKey: mrzKey,
            tags: tags,
            aaChallenge: aaChallenge,
            skipSecureElements: skipSecureElements,
            skipCA: skipCA,
            skipPACE: skipPACE,
            useExtendedMode: useExtendedMode,
            operationTimeout: operationTimeout,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy,
            pacePolicy: pacePolicy,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
        return makeIdentityResultAndScrubPassport(
            passport,
            photoPolicy: securityPolicy.apply(to: photoPolicy),
            securityPolicy: securityPolicy
        )
    }

    public func readPassportIdentity(
        mrzKey: String,
        options: PassportScanOptions,
        aaChallenge: [UInt8]? = nil,
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: PassportReaderDisplayMessageHandler? = nil
    ) async throws -> PassportChipReadResult {
        let passport = try await readPassport(
            mrzKey: mrzKey,
            options: options,
            aaChallenge: aaChallenge,
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
        return makeIdentityResultAndScrubPassport(
            passport,
            photoPolicy: options.securityPolicy.apply(to: options.photoPolicy),
            securityPolicy: options.securityPolicy
        )
    }

    public func cancelRead() {
        failActiveScan(error: .UserCanceled, invalidationReason: .userCanceled, scanID: currentScanID())
    }

    private func cancelRead(scanID: UInt64) {
        failActiveScan(error: .UserCanceled, invalidationReason: .userCanceled, scanID: scanID)
    }
}

@available(iOS 15, *)
extension PassportReader : @preconcurrency NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        guard currentScanID(for: session) != nil else { return }
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        eventLogger.log(.sessionStarted)
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        guard let scanID = currentScanID(for: session) else { return }

        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        self.readerSession = nil

        if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError = NFCPassportReaderError.UnexpectedError
            if let readerError = error as? NFCReaderError {
                switch (readerError.code) {
                case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                    eventLogger.log(.sessionInvalidated(.userCanceled))
                    userError = NFCPassportReaderError.UserCanceled
                case NFCReaderError.readerSessionInvalidationErrorSessionTimeout:
                    eventLogger.log(.sessionInvalidated(.timeout))
                    userError = NFCPassportReaderError.TimeOutError
                default:
                    eventLogger.log(.sessionInvalidated(.system))
                    userError = NFCPassportReaderError.UnexpectedError
                }
            } else {
                eventLogger.log(.sessionInvalidated(.unknown))
            }
            failActiveScan(error: userError, scanID: scanID)
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let scanID = currentScanID(for: session) else { return }

        eventLogger.log(.tagDetected)
        emitProgress(.tagDetected)
        if tags.count > 1 {
            eventLogger.log(.multipleTagsDetected)

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.MoreThanOneTagFound, scanID: scanID)
            return
        }

        var passportTag: NFCISO7816Tag
        guard let tag = tags.first else {
            eventLogger.log(.invalidTagDetected)

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.TagNotValid, scanID: scanID)
            return
        }

        switch tag {
        case let .iso7816(tag):
            passportTag = tag
        default:
            eventLogger.log(.invalidTagDetected)

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid, scanID: scanID)
            return
        }

        Task { [passportTag, scanID] in
            do {
                // CoreNFC's async connect API is not fully Sendable-annotated in the SDK.
                // Keep the unsafe boundary at the external transport call, then return to
                // main-actor-isolated reader state for all scan bookkeeping.
                nonisolated(unsafe) let sessionToConnect = session
                nonisolated(unsafe) let tagToConnect = tag
                try await sessionToConnect.connect(to: tagToConnect)
                guard self.isActiveScan(scanID, session: session) else { return }
                self.eventLogger.log(.tagConnected)
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )
                self.emitProgress(.authenticating(progress: 0))
                
                let tagReader = TagReader(tag:passportTag)
                
                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                } else if self.useExtendedMode {
                    tagReader.preferExtendedReadAmount()
                }
                
                tagReader.progress = self.makeTagReaderProgressHandler(scanID: scanID)
                
                let passportModel = try await self.startReading(tagReader: tagReader, scanID: scanID)
                self.completeActiveScan(returning: passportModel, scanID: scanID)

                
            } catch let error as NFCPassportReaderError {
                let errorMessage = NFCViewDisplayMessage.error(error)
                self.invalidateSession(errorMessage: errorMessage, error: error, scanID: scanID)
            } catch {

                // .readerTransceiveErrorTagResponseError is thrown when a "connection lost" scenario is forced by moving the phone away from the NFC chip
                // .readerTransceiveErrorTagConnectionLost is never thrown for this scenario, but added for the sake of completeness
                if let nfcError = error as? NFCReaderError,
                   nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue {
                    self.eventLogger.log(.sessionInvalidated(.connectionLost))
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError, scanID: scanID)
                } else {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.Unknown(error))
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.Unknown(error), scanID: scanID)
                }
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }

    func emitProgress(_ event: PassportReaderProgressEvent) {
        progressHandler?(event)
    }

    func makeTagReaderProgressHandler(scanID: UInt64) -> (Int) -> Void {
        var lastRenderedProgress: Int?
        var lastRenderedDataGroup: DataGroupId?
        var lastRenderedGeneration = progressRenderGeneration

        return { [weak self] progress in
            guard let self, self.isActiveScan(scanID) else { return }

            let clampedProgress = min(max(progress, 0), 100)
            let currentDataGroup = self.currentlyReadingDataGroup
            let currentGeneration = self.progressRenderGeneration
            let shouldRenderProgress = currentGeneration != lastRenderedGeneration
                || currentDataGroup != lastRenderedDataGroup
                || lastRenderedProgress == nil
                || clampedProgress == 100
                || clampedProgress - (lastRenderedProgress ?? 0) >= 5
            guard shouldRenderProgress else { return }

            lastRenderedGeneration = currentGeneration
            lastRenderedProgress = clampedProgress
            lastRenderedDataGroup = currentDataGroup
            let normalizedProgress = Double(clampedProgress) / 100.0
            if let dgId = self.currentlyReadingDataGroup {
                self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, clampedProgress))
                self.emitProgress(.readingDataGroup(dgId, progress: normalizedProgress))
            } else {
                self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(clampedProgress))
                self.emitProgress(.authenticating(progress: normalizedProgress))
            }
        }
    }

    private func makeIdentityResultAndScrubPassport(
        _ passport: NFCPassportModel,
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy
    ) -> PassportChipReadResult {
        let result = PassportChipReadResult(
            passport: passport,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy
        )
        passport.removeSensitiveDataForPrivacy()
        return result
    }

    func startTimeoutTask(_ operationTimeout: TimeInterval?, scanID: UInt64) {
        scanTimeoutTask?.cancel()
        guard let nanoseconds = Self.safeTimeoutNanoseconds(for: operationTimeout) else {
            scanTimeoutTask = nil
            return
        }

        scanTimeoutTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else { return }
            self?.failActiveScan(error: .TimeOutError, invalidationReason: .timeout, scanID: scanID)
        }
    }

    static func safeTimeoutNanoseconds(for operationTimeout: TimeInterval?) -> UInt64? {
        guard let operationTimeout, operationTimeout.isFinite, operationTimeout > 0 else {
            return nil
        }

        let maxWholeSeconds = TimeInterval(UInt64.max / nanosecondsPerSecond)
        let clampedSeconds = min(operationTimeout, maxWholeSeconds)
        let wholeSeconds = UInt64(clampedSeconds.rounded(.down))
        let fractionalSeconds = clampedSeconds - TimeInterval(wholeSeconds)
        let fractionalNanoseconds = UInt64(
            (fractionalSeconds * TimeInterval(nanosecondsPerSecond)).rounded(.down)
        )
        let wholeNanoseconds = wholeSeconds * nanosecondsPerSecond

        guard UInt64.max - wholeNanoseconds >= fractionalNanoseconds else {
            return UInt64.max
        }
        return wholeNanoseconds + fractionalNanoseconds
    }

    static func initialDataGroupReadRequest(
        tags: [DataGroupId],
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy
    ) -> (dataGroups: [DataGroupId], readAllDataGroups: Bool) {
        let requestedDataGroups = PassportDataGroupReadPolicy.requestedDataGroups(
            tags: tags,
            photoPolicy: photoPolicy,
            securityPolicy: securityPolicy
        )

        guard requestedDataGroups.isEmpty else {
            return (requestedDataGroups, false)
        }

        // Legacy empty-tag reads expand from COM after the mandatory startup groups are read.
        return ([.COM, .SOD], true)
    }

    func cancelTimeoutTask() {
        scanTimeoutTask?.cancel()
        scanTimeoutTask = nil
    }

    func beginScanIfPossible() -> UInt64? {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard !scanInProgress else { return nil }
        scanInProgress = true
        shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        activeScanID &+= 1
        if activeScanID == 0 {
            activeScanID = 1
        }
        return activeScanID
    }

    private func storeActiveScanContinuation(_ continuation: NFCCheckedContinuation, scanID: UInt64) -> Bool {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard scanInProgress, activeScanID == scanID else { return false }
        nfcContinuation = continuation
        return true
    }

    private func takeActiveScanState(scanID: UInt64) -> (matched: Bool, continuation: NFCCheckedContinuation?) {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard scanInProgress, activeScanID == scanID else { return (false, nil) }
        scanInProgress = false
        shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        let continuation = nfcContinuation
        nfcContinuation = nil
        return (true, continuation)
    }

    func currentScanID() -> UInt64 {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        return activeScanID
    }

    private func currentScanID(for session: NFCTagReaderSession) -> UInt64? {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard scanInProgress, readerSession === session else { return nil }
        return activeScanID
    }

    func isActiveScan(_ scanID: UInt64, session: NFCTagReaderSession? = nil) -> Bool {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard scanInProgress, activeScanID == scanID else { return false }
        if let session {
            return readerSession === session
        }
        return true
    }

    func ensureActiveScan(_ scanID: UInt64) throws {
        guard isActiveScan(scanID) else {
            throw NFCPassportReaderError.UserCanceled
        }
    }

    func completeActiveScan(returning passportModel: NFCPassportModel, scanID: UInt64) {
        let activeScan = takeActiveScanState(scanID: scanID)
        guard activeScan.matched else { return }
        cancelTimeoutTask()
        progressHandler = nil
        discardSensitiveAuthenticationState()
        activeScan.continuation?.resume(returning: passportModel)
    }

    func failActiveScan(error: NFCPassportReaderError, invalidationReason: PassportReaderSessionInvalidationReason? = nil, scanID: UInt64) {
        let activeScan = takeActiveScanState(scanID: scanID)
        guard activeScan.matched else { return }
        if let invalidationReason {
            eventLogger.log(.sessionInvalidated(invalidationReason))
        }
        cancelTimeoutTask()
        self.readerSession?.invalidate()
        self.readerSession = nil
        discardSensitiveScanStateAfterFailure()
        progressHandler = nil
        eventLogger.log(.readFailed(error.privacySafeFailureReason))
        activeScan.continuation?.resume(throwing: error)
    }

    func discardSensitiveScanStateAfterFailure() {
        passport.removeSensitiveDataForPrivacy()
        passport = NFCPassportModel()
        discardSensitiveAuthenticationState()
    }

    func discardSensitiveAuthenticationState() {
        bacHandler?.removeSensitiveData()
        caHandler?.removeSensitiveData()
        paceHandler?.removeSensitiveData()
        dataGroupsToRead.removeAll(keepingCapacity: false)
        currentlyReadingDataGroup = nil
        bacHandler = nil
        caHandler = nil
        paceHandler = nil
        mrzKey.removeAll(keepingCapacity: false)
        paceKey = nil
        pendingPACECredential = nil
        aaChallenge?.removeAll(keepingCapacity: false)
        aaChallenge = nil
        nfcViewDisplayMessageHandler = nil
    }

    #if DEBUG
    func suppressNextReaderSessionUserCancelForTesting() {
        shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
    }

    var isNextReaderSessionUserCancelSuppressedForTesting: Bool {
        shouldNotReportNextReaderSessionInvalidationErrorUserCanceled
    }
    #endif
}

@available(iOS 15, *)
extension PassportReader {
    
    func startReading(tagReader: TagReader, scanID: UInt64) async throws -> NFCPassportModel {
        try ensureActiveScan(scanID)
        trackingDelegate?.nfcTagDetected()

        if !skipPACE {
            do {
                try ensureActiveScan(scanID)
                trackingDelegate?.paceStarted()
                eventLogger.log(.paceStarted)
                emitProgress(.paceStarted)

                let data = try await tagReader.readCardAccess()
                try ensureActiveScan(scanID)
                let cardAccess = try CardAccess(data)
                passport.cardAccess = cardAccess

                trackingDelegate?.readCardAccess(cardAccess: cardAccess)

                let cardSecurityData = try? await tagReader.readCardSecurity()
                try ensureActiveScan(scanID)
                if let cardSecurityData {
                    try storeCardSecurity(from: cardSecurityData)
                }
                 
                guard let paceInfo = cardAccess.preferredPACEInfo else {
                    throw NFCPassportReaderError.NotYetSupported("PACE not supported")
                }

                try validatePACEPolicyBeforeAttempt()

                let paceHandler = PACEHandler(paceInfo: paceInfo, tagReader: tagReader)
                self.paceHandler = paceHandler
                defer {
                    paceHandler.removeSensitiveData()
                    if self.paceHandler === paceHandler {
                        self.paceHandler = nil
                    }
                }
                try await paceHandler.doPACE(accessKey: paceKey ?? mrzKey, keyReference: paceKeyReference)
                try ensureActiveScan(scanID)
                passport.paceChipAuthenticationMappingResult = paceHandler.chipAuthenticationMappingResult

                passport.PACEStatus = .success
                verifyTrustedCardSecurityCAMIfPossible()
                eventLogger.log(.paceSucceeded)
                emitProgress(.paceSucceeded)

                trackingDelegate?.paceSucceeded()
            } catch {
                try ensureActiveScan(scanID)
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
                if shouldFailInsteadOfFallingBackFromPACE(error: error) {
                    throw error
                }
                eventLogger.log(.paceFailedFallbackToBAC)
                emitProgress(.paceFailedFallbackToBAC)
            }
            
            _ = try await tagReader.selectPassportApplication()
            try ensureActiveScan(scanID)
        }
        
        // If either PACE isn't supported, we failed whilst doing PACE or we didn't even attempt it, then fall back to BAC
        if passport.PACEStatus != .success {
            do {
                try ensureActiveScan(scanID)
                trackingDelegate?.bacStarted()
                try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                try ensureActiveScan(scanID)
                trackingDelegate?.bacSucceeded()
            } catch {
                try ensureActiveScan(scanID)
                trackingDelegate?.bacFailed()
                eventLogger.log(.bacFailed)
                throw error
            }
        }
        
        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader, scanID: scanID)

        try await doActiveAuthenticationIfNeccessary(tagReader: tagReader, scanID: scanID)

        try ensureActiveScan(scanID)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()
        self.readerSession = nil

        // If we have a masterlist url set then use that and verify the passport now
        try ensureActiveScan(scanID)
        eventLogger.log(.verificationStarted)
        emitProgress(.verifyingSOD)
        emitProgress(.verifyingDataGroups)
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)
        try self.securityPolicy.validate(self.passport)
        eventLogger.log(.readSucceeded)
        emitProgress(.complete)

        return self.passport
    }

    func validatePACEPolicyBeforeSession(skipPACE: Bool) throws {
        if skipPACE, pacePolicy != .allowBACFallback {
            pendingPACECredential = nil
            throw NFCPassportReaderError.PACEError(
                "Credential policy",
                "PACE cannot be disabled for the requested policy"
            )
        }

        if case .requireExplicitCredential(let requiredReference) = pacePolicy {
            guard let credential = pendingPACECredential,
                  credential.reference == requiredReference else {
                pendingPACECredential = nil
                throw NFCPassportReaderError.PACEError(
                    "Credential policy",
                    "Explicit PACE credential required"
                )
            }
        }
    }

    func validateActiveAuthenticationChallengeBeforeSession(_ challenge: [UInt8]?) throws {
        guard let challenge else { return }
        guard NFCPassportModel.isValidActiveAuthenticationChallenge(challenge) else {
            pendingPACECredential = nil
            throw NFCPassportReaderError.MissingMandatoryFields
        }
    }

    func validatePACEPolicyBeforeAttempt() throws {
        switch pacePolicy {
        case .allowBACFallback, .requirePACEWhenAdvertised:
            return
        case .requireExplicitCredential(let requiredReference):
            guard paceKeyReference == requiredReference,
                  paceKey != nil,
                  paceKey != mrzKey else {
                throw NFCPassportReaderError.PACEError(
                    "Credential policy",
                    "Explicit PACE credential required"
                )
            }
        }
    }

    func shouldFailInsteadOfFallingBackFromPACE(error: Error) -> Bool {
        switch pacePolicy {
        case .allowBACFallback:
            return false
        case .requirePACEWhenAdvertised, .requireExplicitCredential:
            return true
        }
    }

    #if DEBUG
    func configurePACEPolicyForTesting(
        _ policy: PassportReaderPACEPolicy,
        paceKey: String? = nil,
        paceKeyReference: PassportPACEKeyReference = .mrz,
        pendingPACEKey: String? = nil,
        pendingPACEKeyReference: PassportPACEKeyReference = .mrz
    ) {
        self.pacePolicy = policy
        self.paceKey = paceKey
        self.paceKeyReference = paceKeyReference
        if let pendingPACEKey {
            self.pendingPACECredential = (pendingPACEKey, pendingPACEKeyReference)
        } else {
            self.pendingPACECredential = nil
        }
    }
    #endif

    func storeCardSecurity(from data: [UInt8]) throws {
        passport.cardSecurity = try makeCardSecurity(from: data)
    }

    private func makeCardSecurity(from data: [UInt8]) throws -> CardSecurity {
        let cardSecurity = try CardSecurity(data)
        if let masterListURL {
            try? cardSecurity.verifySignature(trustedCertificatesURL: masterListURL)
        } else {
            try? cardSecurity.verifySignature(trustedCertificatesURL: nil)
        }
        return cardSecurity
    }

    private func verifyTrustedCardSecurityCAMIfPossible() {
        guard let camResult = passport.paceChipAuthenticationMappingResult,
              let cardSecurity = passport.cardSecurity,
              cardSecurity.signerTrusted else {
            return
        }

        let publicKeyInfos = cardSecurity.securityInfos.compactMap { $0 as? ChipAuthenticationPublicKeyInfo }
        passport.paceChipAuthenticationMappingResult = nil
        if camResult.verifies(using: publicKeyInfos) {
            passport.chipAuthenticationStatus = .success
        } else {
            passport.chipAuthenticationStatus = .failed
        }
    }
    
    
    func doActiveAuthenticationIfNeccessary(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        guard self.passport.activeAuthenticationSupported else {
            return
        }
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        eventLogger.log(.activeAuthenticationStarted)
        emitProgress(.activeAuthenticationStarted)

        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        try ensureActiveScan(scanID)
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
        if self.passport.activeAuthenticationPassed {
            eventLogger.log(.activeAuthenticationSucceeded)
            emitProgress(.activeAuthenticationSucceeded)
        }
    }
    

    func doBACAuthentication(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        self.currentlyReadingDataGroup = nil

        eventLogger.log(.bacStarted)
        emitProgress(.bacStarted)
        
        self.passport.BACStatus = .failed

        self.bacHandler = BACHandler( tagReader: tagReader )
        try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey )
        try ensureActiveScan(scanID)
        eventLogger.log(.bacSucceeded)
        emitProgress(.bacSucceeded)

        self.passport.BACStatus = .success
    }

    func readDataGroups(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        
        // Read COM
        var DGsToRead = [DataGroupId]()

        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(tagReader: tagReader, dgId: .COM, scanID: scanID) as? COM {
            try ensureActiveScan(scanID)
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        try ensureActiveScan(scanID)
        DGsToRead.forEach { self.passport.recordDataGroupReadStatus(.advertised, for: $0) }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader: tagReader, dgId: .DG14, scanID: scanID) as? DataGroup14 {
                    try ensureActiveScan(scanID)
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    if let camResult = passport.paceChipAuthenticationMappingResult {
                        let publicKeyInfos = dg14.securityInfos.compactMap { $0 as? ChipAuthenticationPublicKeyInfo }
                        self.passport.paceChipAuthenticationMappingResult = nil
                        if camResult.verifies(using: publicKeyInfos) {
                            self.passport.chipAuthenticationStatus = .success
                        } else {
                            self.passport.chipAuthenticationStatus = .failed
                        }
                    }

                    do {
                        let caHandler = try ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                        self.caHandler = caHandler

                        if caHandler.isChipAuthenticationSupported && self.passport.chipAuthenticationStatus != .success {
                            eventLogger.log(.chipAuthenticationStarted)
                            emitProgress(.chipAuthenticationStarted)
                            do {
                                // Do Chip authentication and then continue reading datagroups
                                try await caHandler.doChipAuthentication()
                                try ensureActiveScan(scanID)
                                self.passport.chipAuthenticationStatus = .success
                                eventLogger.log(.chipAuthenticationSucceeded)
                                emitProgress(.chipAuthenticationSucceeded)
                            } catch {
                                try ensureActiveScan(scanID)
                                eventLogger.log(.chipAuthenticationFailedFallbackToBAC)
                                emitProgress(.chipAuthenticationFailedFallbackToBAC)
                                self.passport.chipAuthenticationStatus = .failed

                                caHandler.removeSensitiveData()
                                if self.caHandler === caHandler {
                                    self.caHandler = nil
                                }

                                // Failed Chip Auth, need to re-establish BAC
                                try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                            }
                        }
                    } catch {
                        try ensureActiveScan(scanID)
                        eventLogger.log(.chipAuthenticationFailedFallbackToBAC)
                        emitProgress(.chipAuthenticationFailedFallbackToBAC)
                        self.passport.chipAuthenticationStatus = .failed
                    }
                }
            }
        }

        let advertisedDataGroups = DGsToRead
        DGsToRead = PassportDataGroupReadPolicy(
            requestedDataGroups: dataGroupsToRead,
            readAllDataGroups: readAllDatagroups,
            skipSecureElements: skipSecureElements,
            photoPolicy: effectivePhotoPolicy
        ).apply(to: DGsToRead)
        try ensureActiveScan(scanID)
        recordSkippedDataGroups(advertised: advertisedDataGroups, selected: DGsToRead)
        for dgId in DGsToRead {
            if let dg = try await readDataGroup(tagReader: tagReader, dgId: dgId, scanID: scanID) {
                try ensureActiveScan(scanID)
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    func readDataGroup(tagReader: TagReader, dgId: DataGroupId, scanID: UInt64) async throws -> DataGroup? {

        try ensureActiveScan(scanID)
        self.currentlyReadingDataGroup = dgId
        progressRenderGeneration += 1
        eventLogger.log(.readingDataGroup(dgId))
        emitProgress(.readingDataGroup(dgId, progress: 0))
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            do {
                let response = try await tagReader.readDataGroup(dataGroup:dgId)
                try ensureActiveScan(scanID)
                let dg = try DataGroupParser().parseDG(data: response)
                try ensureActiveScan(scanID)
                self.passport.recordDataGroupReadStatus(.read, for: dgId)
                return dg
            } catch let error as NFCPassportReaderError {
                try ensureActiveScan(scanID)
                eventLogger.log(.dataGroupReadFailed(dgId))
                self.passport.recordDataGroupReadStatus(.failed, for: dgId)
                nfcPassportReaderError = error

                var redoBAC = false
                if error.shouldRetryDataGroupReadAfterChipAuthentication {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if let caHandler = self.caHandler {
                        caHandler.removeSensitiveData()
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if error.shouldSkipDataGroupAndRedoBAC {
                    // The chip reported this group as unavailable for the current session. Reset BAC so
                    // following groups keep their best chance of succeeding, but do not retry this one.
                    Self.removeDataGroup(dgId, from: &self.dataGroupsToRead)
                    eventLogger.log(.unsupportedDataGroup(dgId))
                    self.passport.recordDataGroupReadStatus(.unsupported, for: dgId)
                    try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                    return nil
                } else if error.shouldRedoBACForDataGroupRead {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if error.shouldReduceReadAmountAndRedoBAC {
                    // OK passport can't handle max length so drop it down
                    tagReader.reduceDataReadingAmount()
                    redoBAC = true
                } else if error.isUnsupportedDataGroupRead {
                    // OK, this DataGroup is not supported, lets skip it
                    eventLogger.log(.unsupportedDataGroup(dgId))
                    self.passport.recordDataGroupReadStatus(.unsupported, for: dgId)
                    return nil
                }
                
                if redoBAC {
                    // Redo BAC and try again
                    try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError, scanID: UInt64) {
        guard isActiveScan(scanID) else { return }
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        failActiveScan(error: error, scanID: scanID)
    }
    
    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
    }

    internal static func removeDataGroup(_ dataGroup: DataGroupId, from dataGroups: inout [DataGroupId]) {
        dataGroups.removeAll { $0 == dataGroup }
    }

    private func recordSkippedDataGroups(advertised: [DataGroupId], selected: [DataGroupId]) {
        let selectedSet = Set(selected)
        for dataGroup in advertised where !selectedSet.contains(dataGroup) {
            if (dataGroup == .DG2 && effectivePhotoPolicy == .skip)
                || (skipSecureElements && (dataGroup == .DG3 || dataGroup == .DG4)) {
                passport.recordDataGroupReadStatus(.blockedByPolicy, for: dataGroup)
            } else {
                passport.recordDataGroupReadStatus(.skippedByProfile, for: dataGroup)
            }
        }
    }
}
#endif
