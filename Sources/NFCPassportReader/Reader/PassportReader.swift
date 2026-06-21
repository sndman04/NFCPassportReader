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
    private var nfcContinuation: NFCCheckedContinuation?
    private let scanStateLock = NSLock()
    private var scanInProgress = false
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

        guard beginScanIfPossible() else {
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
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append(
            contentsOf: PassportDataGroupReadPolicy.requestedDataGroups(
                tags: tags,
                photoPolicy: photoPolicy,
                securityPolicy: securityPolicy
            )
        )
        self.dataGroupsToRead.forEach { self.passport.recordDataGroupReadStatus(.requested, for: $0) }
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.progressHandler = progressHandler
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
                guard self.storeActiveScanContinuation(continuation) else {
                    continuation.resume(throwing: NFCPassportReaderError.UserCanceled)
                    return
                }

                guard NFCTagReaderSession.readingAvailable else {
                    self.failActiveScan(error: .NFCNotSupported)
                    return
                }

                self.readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: .main)
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
                self.emitProgress(.waitingForPassport)
                self.startTimeoutTask(operationTimeout)
                self.readerSession?.begin()
            })
        } onCancel: {
            Task { @MainActor in
                self.cancelRead()
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
        return makeIdentityResultAndScrubPassport(passport, photoPolicy: securityPolicy.apply(to: photoPolicy))
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
        return makeIdentityResultAndScrubPassport(passport, photoPolicy: securityPolicy.apply(to: photoPolicy))
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
        return makeIdentityResultAndScrubPassport(passport, photoPolicy: securityPolicy.apply(to: photoPolicy))
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
            photoPolicy: options.securityPolicy.apply(to: options.photoPolicy)
        )
    }

    public func cancelRead() {
        failActiveScan(error: .UserCanceled, invalidationReason: .userCanceled)
    }
}

@available(iOS 15, *)
extension PassportReader : @preconcurrency NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        eventLogger.log(.sessionStarted)
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        self.readerSession?.invalidate()
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
            failActiveScan(error: userError)
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        eventLogger.log(.tagDetected)
        emitProgress(.tagDetected)
        if tags.count > 1 {
            eventLogger.log(.multipleTagsDetected)

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.MoreThanOneTagFound)
            return
        }

        var passportTag: NFCISO7816Tag
        guard let tag = tags.first else {
            eventLogger.log(.invalidTagDetected)

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }

        switch tag {
        case let .iso7816(tag):
            passportTag = tag
        default:
            eventLogger.log(.invalidTagDetected)

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }
        
        Task { [passportTag] in
            do {
                // CoreNFC's async connect API is not fully Sendable-annotated in the SDK.
                // Keep the unsafe boundary at the external transport call, then return to
                // main-actor-isolated reader state for all scan bookkeeping.
                nonisolated(unsafe) let sessionToConnect = session
                nonisolated(unsafe) let tagToConnect = tag
                try await sessionToConnect.connect(to: tagToConnect)
                self.eventLogger.log(.tagConnected)
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )
                self.emitProgress(.authenticating(progress: 0))
                
                let tagReader = TagReader(tag:passportTag)
                
                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                } else if self.useExtendedMode {
                    tagReader.preferExtendedReadAmount()
                }
                
                var lastRenderedProgress: Int?
                var lastRenderedDataGroup: DataGroupId?
                var lastRenderedGeneration = self.progressRenderGeneration
                tagReader.progress = { [unowned self] (progress) in
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
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, clampedProgress) )
                        self.emitProgress(.readingDataGroup(dgId, progress: normalizedProgress))
                    } else {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(clampedProgress) )
                        self.emitProgress(.authenticating(progress: normalizedProgress))
                    }
                }
                
                let passportModel = try await self.startReading( tagReader : tagReader)
                self.completeActiveScan(returning: passportModel)

                
            } catch let error as NFCPassportReaderError {
                let errorMessage = NFCViewDisplayMessage.error(error)
                self.invalidateSession(errorMessage: errorMessage, error: error)
            } catch {

                // .readerTransceiveErrorTagResponseError is thrown when a "connection lost" scenario is forced by moving the phone away from the NFC chip
                // .readerTransceiveErrorTagConnectionLost is never thrown for this scenario, but added for the sake of completeness
                if let nfcError = error as? NFCReaderError,
                   nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue {
                    self.eventLogger.log(.sessionInvalidated(.connectionLost))
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError)
                } else {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.Unknown(error))
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.Unknown(error))
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

    private func makeIdentityResultAndScrubPassport(
        _ passport: NFCPassportModel,
        photoPolicy: PassportPhotoPolicy
    ) -> PassportChipReadResult {
        let result = PassportChipReadResult(passport: passport, photoPolicy: photoPolicy)
        passport.removeSensitiveDataForPrivacy()
        return result
    }

    func startTimeoutTask(_ operationTimeout: TimeInterval?) {
        scanTimeoutTask?.cancel()
        guard let operationTimeout, operationTimeout.isFinite, operationTimeout > 0 else {
            scanTimeoutTask = nil
            return
        }

        let maxSafeSeconds = TimeInterval(UInt64.max / 1_000_000_000)
        let timeoutSeconds = min(operationTimeout, maxSafeSeconds)

        scanTimeoutTask = Task { [weak self] in
            let nanoseconds = UInt64(timeoutSeconds * 1_000_000_000)
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else { return }
            self?.failActiveScan(error: .TimeOutError, invalidationReason: .timeout)
        }
    }

    func cancelTimeoutTask() {
        scanTimeoutTask?.cancel()
        scanTimeoutTask = nil
    }

    private func beginScanIfPossible() -> Bool {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard !scanInProgress else { return false }
        scanInProgress = true
        return true
    }

    private func storeActiveScanContinuation(_ continuation: NFCCheckedContinuation) -> Bool {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        guard scanInProgress else { return false }
        nfcContinuation = continuation
        return true
    }

    private func takeActiveScanContinuation() -> NFCCheckedContinuation? {
        scanStateLock.lock()
        defer { scanStateLock.unlock() }

        scanInProgress = false
        let continuation = nfcContinuation
        nfcContinuation = nil
        return continuation
    }

    func completeActiveScan(returning passportModel: NFCPassportModel) {
        guard let continuation = takeActiveScanContinuation() else { return }
        cancelTimeoutTask()
        progressHandler = nil
        discardSensitiveAuthenticationState()
        continuation.resume(returning: passportModel)
    }

    func failActiveScan(error: NFCPassportReaderError, invalidationReason: PassportReaderSessionInvalidationReason? = nil) {
        if let invalidationReason {
            eventLogger.log(.sessionInvalidated(invalidationReason))
        }
        cancelTimeoutTask()
        self.readerSession?.invalidate()
        self.readerSession = nil
        discardSensitiveScanStateAfterFailure()
        guard let continuation = takeActiveScanContinuation() else { return }
        progressHandler = nil
        eventLogger.log(.readFailed(error.privacySafeFailureReason))
        continuation.resume(throwing: error)
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
}

@available(iOS 15, *)
extension PassportReader {
    
    func startReading(tagReader : TagReader) async throws -> NFCPassportModel {
        trackingDelegate?.nfcTagDetected()

        if !skipPACE {
            do {
                trackingDelegate?.paceStarted()
                eventLogger.log(.paceStarted)
                emitProgress(.paceStarted)

                let data = try await tagReader.readCardAccess()
                let cardAccess = try CardAccess(data)
                passport.cardAccess = cardAccess

                trackingDelegate?.readCardAccess(cardAccess: cardAccess)

                if let cardSecurityData = try? await tagReader.readCardSecurity() {
                    passport.cardSecurity = try? makeCardSecurity(from: cardSecurityData)
                }
                 
                let paceInfos = cardAccess.paceInfos
                let implementedPACEInfos = paceInfos.filter { $0.isImplementedForReading }
                let orderedPACEInfos = implementedPACEInfos.isEmpty ? paceInfos : implementedPACEInfos
                guard !orderedPACEInfos.isEmpty else {
                    throw NFCPassportReaderError.NotYetSupported("PACE not supported")
                }

                try validatePACEPolicyBeforeAttempt()

                var lastPACEError: Error?
                var didPACE = false
                for paceInfo in orderedPACEInfos {
                    do {
                        let paceHandler = PACEHandler(paceInfo: paceInfo, tagReader: tagReader)
                        try await paceHandler.doPACE(accessKey: paceKey ?? mrzKey, keyReference: paceKeyReference)
                        passport.paceChipAuthenticationMappingResult = paceHandler.chipAuthenticationMappingResult
                        didPACE = true
                        break
                    } catch {
                        lastPACEError = error
                    }
                }

                if let lastPACEError, !didPACE {
                    throw lastPACEError
                }

                passport.PACEStatus = .success
                verifyTrustedCardSecurityCAMIfPossible()
                eventLogger.log(.paceSucceeded)
                emitProgress(.paceSucceeded)

                trackingDelegate?.paceSucceeded()
            } catch {
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
                if shouldFailInsteadOfFallingBackFromPACE(error: error) {
                    throw error
                }
                eventLogger.log(.paceFailedFallbackToBAC)
                emitProgress(.paceFailedFallbackToBAC)
            }
            
            _ = try await tagReader.selectPassportApplication()
        }
        
        // If either PACE isn't supported, we failed whilst doing PACE or we didn't even attempt it, then fall back to BAC
        if passport.PACEStatus != .success {
            do {
                trackingDelegate?.bacStarted()
                try await doBACAuthentication(tagReader : tagReader)
                trackingDelegate?.bacSucceeded()
            } catch {
                trackingDelegate?.bacFailed()
                eventLogger.log(.bacFailed)
                throw error
            }
        }
        
        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader)

        try await doActiveAuthenticationIfNeccessary(tagReader : tagReader)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()
        self.readerSession = nil

        // If we have a masterlist url set then use that and verify the passport now
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
        if camResult.verifies(using: publicKeyInfos) {
            passport.chipAuthenticationStatus = .success
            passport.paceChipAuthenticationMappingResult = nil
        }
    }
    
    
    func doActiveAuthenticationIfNeccessary( tagReader : TagReader) async throws {
        guard self.passport.activeAuthenticationSupported else {
            return
        }
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        eventLogger.log(.activeAuthenticationStarted)
        emitProgress(.activeAuthenticationStarted)

        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
        if self.passport.activeAuthenticationPassed {
            eventLogger.log(.activeAuthenticationSucceeded)
            emitProgress(.activeAuthenticationSucceeded)
        }
    }
    

    func doBACAuthentication(tagReader : TagReader) async throws {
        self.currentlyReadingDataGroup = nil

        eventLogger.log(.bacStarted)
        emitProgress(.bacStarted)
        
        self.passport.BACStatus = .failed

        self.bacHandler = BACHandler( tagReader: tagReader )
        try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey )
        eventLogger.log(.bacSucceeded)
        emitProgress(.bacSucceeded)

        self.passport.BACStatus = .success
    }

    func readDataGroups( tagReader: TagReader ) async throws {
        
        // Read COM
        var DGsToRead = [DataGroupId]()

        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(tagReader:tagReader, dgId:.COM) as? COM {
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        DGsToRead.forEach { self.passport.recordDataGroupReadStatus(.advertised, for: $0) }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader:tagReader, dgId:.DG14) as? DataGroup14 {
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

                    let caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                    self.caHandler = caHandler
                     
                    if caHandler.isChipAuthenticationSupported && self.passport.chipAuthenticationStatus != .success {
                        eventLogger.log(.chipAuthenticationStarted)
                        emitProgress(.chipAuthenticationStarted)
                        do {
                            // Do Chip authentication and then continue reading datagroups
                            try await caHandler.doChipAuthentication()
                            self.passport.chipAuthenticationStatus = .success
                            eventLogger.log(.chipAuthenticationSucceeded)
                            emitProgress(.chipAuthenticationSucceeded)
                        } catch {
                            eventLogger.log(.chipAuthenticationFailedFallbackToBAC)
                            emitProgress(.chipAuthenticationFailedFallbackToBAC)
                            self.passport.chipAuthenticationStatus = .failed
                            
                            // Failed Chip Auth, need to re-establish BAC
                            try await doBACAuthentication(tagReader: tagReader)
                        }
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
        recordSkippedDataGroups(advertised: advertisedDataGroups, selected: DGsToRead)
        for dgId in DGsToRead {
            if let dg = try await readDataGroup(tagReader:tagReader, dgId:dgId) {
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    func readDataGroup( tagReader : TagReader, dgId : DataGroupId ) async throws -> DataGroup?  {

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
                let dg = try DataGroupParser().parseDG(data: response)
                self.passport.recordDataGroupReadStatus(.read, for: dgId)
                return dg
            } catch let error as NFCPassportReaderError {
                eventLogger.log(.dataGroupReadFailed(dgId))
                self.passport.recordDataGroupReadStatus(.failed, for: dgId)
                nfcPassportReaderError = error

                var redoBAC = false
                if error.shouldRetryDataGroupReadAfterChipAuthentication {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if error.shouldSkipDataGroupAndRedoBAC {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    if !self.dataGroupsToRead.isEmpty {
                        self.dataGroupsToRead.removeFirst()
                    }
                    redoBAC = true
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
                    try await doBACAuthentication(tagReader : tagReader)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError) {
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        failActiveScan(error: error)
    }
    
    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
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
