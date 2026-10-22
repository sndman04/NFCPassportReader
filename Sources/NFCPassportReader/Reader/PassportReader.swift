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
    private var scanDeadline: ContinuousClock.Instant?
    private var securityPolicy: PassportReaderSecurityPolicy = .default
    private var currentScanStage: PassportReaderScanStage = .unknown
    private var mostRecentFailure: PassportReaderFailure?
    private var mostRecentFailureDescription: String?

    weak var trackingDelegate: PassportReaderTrackingDelegate?
    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var activeTagReader: TagReader?
    private var currentlyReadingDataGroup : DataGroupId?
    private var progressRenderGeneration = 0
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    private var preparingBACFallback = false
    private var retriedBACApplicationSelection = false
    private var tagConnectionInProgress = false
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

    /// Returns the most specific privacy-safe failure captured for the latest scan.
    ///
    /// The returned value contains only a typed high-level reason, scan stage, and
    /// verification category. It never includes MRZ values, status words, APDUs,
    /// keys, certificates, data-group bytes, or image data.
    public func privacySafeFailure(for error: NFCPassportReaderError) -> PassportReaderFailure {
        if mostRecentFailureDescription == error.safeDescription,
           let mostRecentFailure {
            return mostRecentFailure
        }
        return error.privacySafeFailure(at: currentScanStage)
    }
    
    // This function allows you to override the amount of data the TagReader tries to read from the NFC
    // chip. NOTE - this really shouldn't be used for production but is useful for testing as different
    // passports support different data amounts.
    // It appears that the most reliable is 0xA0 (160 chars) but some will support arbitary reads (0xFF or 256)
    func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
    
    func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, operationTimeout: TimeInterval? = nil, photoPolicy: PassportPhotoPolicy = .read, securityPolicy: PassportReaderSecurityPolicy = .default, pacePolicy: PassportReaderPACEPolicy = .allowBACFallback, progressHandler: PassportReaderProgressHandler? = nil, customDisplayMessage : PassportReaderDisplayMessageHandler? = nil) async throws -> NFCPassportModel {
        // Reject overlap before touching any credential, policy, or diagnostics.
        guard !isActiveScan(currentScanID()) else { throw NFCPassportReaderError.ScanAlreadyInProgress }
        currentScanStage = .unknown
        mostRecentFailure = nil
        mostRecentFailureDescription = nil
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

        self.currentScanStage = .waitingForPassport
        self.mostRecentFailure = nil
        self.mostRecentFailureDescription = nil
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

                guard !Task.isCancelled else {
                    self.failActiveScan(error: .UserCanceled, scanID: scanID)
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
                guard self.isActiveScan(scanID) else { return }
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
        guard !isActiveScan(currentScanID()) else { throw NFCPassportReaderError.ScanAlreadyInProgress }
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

    func performPACE(_ handler: PACEHandler) async throws {
        try await handler.doPACE(accessKey: paceKey ?? mrzKey, keyReference: paceKeyReference)
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
            let userError = PassportAccessRecovery.interruption(from: error) ?? .UnexpectedError
            let reason: PassportReaderSessionInvalidationReason
            switch userError {
            case .UserCanceled: reason = .userCanceled
            case .TimeOutError: reason = .timeout
            case .ConnectionError: reason = .connectionLost
            default: reason = error is NFCReaderError ? .system : .unknown
            }
            failActiveScan(error: userError, invalidationReason: reason, scanID: scanID)
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let scanID = currentScanID(for: session), !tagConnectionInProgress else { return }

        eventLogger.log(.tagDetected)
        if !preparingBACFallback { emitProgress(.tagDetected) }
        guard isActiveScan(scanID, session: session) else { return }
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

        tagConnectionInProgress = true
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
                if !self.preparingBACFallback { self.emitProgress(.authenticating(progress: 0)) }
                
                let tagReader = TagReader(tag:passportTag)
                
                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                } else if self.useExtendedMode {
                    tagReader.preferExtendedReadAmount()
                }
                
                tagReader.progress = self.makeTagReaderProgressHandler(scanID: scanID)
                
                let passportModel = try await self.startReading(tagReader: tagReader, scanID: scanID)
                self.completeActiveScan(returning: passportModel, scanID: scanID)

                
            } catch PassportAccessRecovery.restartPolling {
                // Run after this task unwinds so its old NFCTag references are
                // released before CoreNFC invalidates all previously detected tags.
                Task { @MainActor in
                    guard self.isActiveScan(scanID, session: session) else { return }
                    self.tagConnectionInProgress = false
                    session.restartPolling()
                }
            } catch let error as NFCPassportReaderError {
                let errorMessage = NFCViewDisplayMessage.error(error)
                self.invalidateSession(errorMessage: errorMessage, error: error, scanID: scanID)
            } catch {

                let failure = PassportAccessRecovery.interruption(from: error)
                    ?? (self.currentScanStage == .bacFallbackPreparation ? .BACFallbackPreparationFailed : .UnexpectedError)
                self.invalidateSession(errorMessage: .error(failure), error: failure, scanID: scanID)
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }

    func emitProgress(_ event: PassportReaderProgressEvent) {
        // File reads during PACE may report generic authentication progress.
        // Keep the specific stage until a real stage transition is emitted.
        if case .authenticating = event {
            if currentScanStage == .unknown || currentScanStage == .waitingForPassport {
                currentScanStage = .connecting
            }
        } else {
            currentScanStage = event.scanStage
        }
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
        scanDeadline = nil
        guard let nanoseconds = Self.safeTimeoutNanoseconds(for: operationTimeout) else {
            scanTimeoutTask = nil
            return
        }

        scanDeadline = ContinuousClock.now.advanced(by: .seconds(nanoseconds / Self.nanosecondsPerSecond)
            + .nanoseconds(Int64(nanoseconds % Self.nanosecondsPerSecond)))
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
        scanDeadline = nil
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
        guard isActiveScan(scanID), !Task.isCancelled else {
            throw NFCPassportReaderError.UserCanceled
        }
        if let scanDeadline, ContinuousClock.now >= scanDeadline {
            throw NFCPassportReaderError.TimeOutError
        }
    }

    func completeActiveScan(returning passportModel: NFCPassportModel, scanID: UInt64) {
        let activeScan = takeActiveScanState(scanID: scanID)
        guard activeScan.matched else { return }
        let completion = progressHandler
        cancelTimeoutTask()
        readerSession?.invalidate()
        readerSession = nil
        currentScanStage = .unknown
        progressHandler = nil
        discardSensitiveAuthenticationState()
        // Terminal callbacks run only after all old scan state is detached.
        eventLogger.log(.readSucceeded)
        completion?(.complete)
        activeScan.continuation?.resume(returning: passportModel)
    }

    func failActiveScan(error: NFCPassportReaderError, invalidationReason: PassportReaderSessionInvalidationReason? = nil, scanID: UInt64) {
        let activeScan = takeActiveScanState(scanID: scanID)
        guard activeScan.matched else { return }
        let failure = makePrivacySafeFailure(for: error)
        let completion = progressHandler
        mostRecentFailure = failure
        mostRecentFailureDescription = error.safeDescription
        cancelTimeoutTask()
        readerSession?.invalidate()
        readerSession = nil
        discardSensitiveScanStateAfterFailure()
        progressHandler = nil
        currentScanStage = .unknown
        if let invalidationReason { eventLogger.log(.sessionInvalidated(invalidationReason)) }
        eventLogger.log(.readFailed(failure.reason))
        eventLogger.log(.readFailedAtStage(failure.reason, failure.stage))
        completion?(.failed(reason: failure.reason, stage: failure.stage))
        activeScan.continuation?.resume(throwing: error)
    }

    private func makePrivacySafeFailure(for error: NFCPassportReaderError) -> PassportReaderFailure {
        switch error {
        case .SecurityPolicyViolation:
            return PassportReaderFailure(
                reason: .verificationFailed,
                stage: .securityPolicyValidation,
                verificationReason: securityPolicyFailureReason()
            )
        case .ActiveAuthenticationFailed:
            return PassportReaderFailure(
                reason: .verificationFailed,
                stage: .activeAuthentication,
                verificationReason: .attemptedFailed
            )
        case .ChipAuthenticationFailed:
            return PassportReaderFailure(
                reason: .verificationFailed,
                stage: .chipAuthentication,
                verificationReason: .attemptedFailed
            )
        default:
            return error.privacySafeFailure(at: currentScanStage)
        }
    }

    private func securityPolicyFailureReason() -> PassportVerificationDetailReason {
        let verification = passport.verificationResult
        let checks: [PassportVerificationCheck]

        switch securityPolicy.verificationRequirement {
        case .none:
            checks = []
        case .passiveAuthentication:
            checks = [verification.sodSignatureDetail, verification.dataGroupHashDetail]
        case .trustedPassiveAuthentication:
            checks = [
                verification.sodSignatureDetail,
                verification.dataGroupHashDetail,
                verification.documentSignerCertificateDetail,
                verification.countrySigningCertificateDetail,
            ]
        case .chipAuthenticationWhenSupported:
            checks = [verification.chipAuthenticationDetail]
        case .activeAuthenticationWhenSupported:
            checks = [verification.activeAuthenticationDetail]
        case .fullVerificationWhenSupported:
            checks = [
                verification.sodSignatureDetail,
                verification.dataGroupHashDetail,
                verification.documentSignerCertificateDetail,
                verification.countrySigningCertificateDetail,
                verification.chipAuthenticationDetail,
                verification.activeAuthenticationDetail,
            ]
        }

        return checks.first(where: { $0.status != .passed })?.reason ?? .attemptedFailed
    }

    func discardSensitiveScanStateAfterFailure() {
        passport.removeSensitiveDataForPrivacy()
        passport = NFCPassportModel()
        discardSensitiveAuthenticationState()
    }

    func discardSensitiveAuthenticationState() {
        activeTagReader?.disconnect()
        activeTagReader = nil
        preparingBACFallback = false
        retriedBACApplicationSelection = false
        tagConnectionInProgress = false
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
    func configureLifecycleForTesting(
        passport: NFCPassportModel = NFCPassportModel(),
        tagReader: TagReader? = nil,
        groups: [DataGroupId] = [.COM, .SOD, .DG1],
        securityPolicy: PassportReaderSecurityPolicy = .default,
        useExtendedMode: Bool = false
    ) {
        self.passport = passport
        self.activeTagReader = tagReader
        self.dataGroupsToRead = groups
        self.securityPolicy = securityPolicy
        self.useExtendedMode = useExtendedMode
    }

    func configureAccessForTesting(
        skipPACE: Bool = false,
        mrzKey: String,
        progress: PassportReaderProgressHandler? = nil
    ) {
        self.skipPACE = skipPACE
        self.mrzKey = mrzKey
        self.progressHandler = progress
    }
    #endif

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

        try await establishAccess(tagReader: tagReader, scanID: scanID)

        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader, scanID: scanID)

        try await doActiveAuthenticationIfNeccessary(tagReader: tagReader, scanID: scanID)

        try ensureActiveScan(scanID)

        // Verify the passport before presenting a successful read. This prevents
        // the NFC sheet from reporting success when the configured security policy
        // will reject the result immediately afterward.
        try ensureActiveScan(scanID)
        eventLogger.log(.verificationStarted)
        emitProgress(.verifyingSOD)
        emitProgress(.verifyingDataGroups)
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)
        try ensureActiveScan(scanID)
        self.currentScanStage = .securityPolicyValidation
        try self.securityPolicy.validate(self.passport)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()
        self.readerSession = nil
        try ensureActiveScan(scanID)
        return self.passport
    }

    /// Authentication boundary shared by startReading and scripted transport tests.
    func establishAccess(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        if activeTagReader !== tagReader {
            activeTagReader?.disconnect()
            activeTagReader = tagReader
        }
        if !skipPACE, !preparingBACFallback {
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

                let cardSecurityData: [UInt8]?
                do {
                    cardSecurityData = try await tagReader.readCardSecurity()
                } catch {
                    if let interruption = PassportAccessRecovery.interruption(from: error) {
                        throw interruption
                    }
                    cardSecurityData = nil // Optional file/format support.
                }
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
                try await performPACE(paceHandler)
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
                tagReader.clearAuthenticationState()
                paceKey = nil
                passport.paceChipAuthenticationMappingResult = nil
                passport.cardSecurity?.removeSensitiveDataForPrivacy()
                passport.cardSecurity = nil
                passport.cardAccess?.removeSensitiveDataForPrivacy()
                passport.cardAccess = nil
                if let interruption = PassportAccessRecovery.interruption(from: error) {
                    throw interruption
                }
                if shouldFailInsteadOfFallingBackFromPACE(error: error) {
                    if !tagReader.paceAuthenticationAttempted,
                       let readerError = error as? NFCPassportReaderError,
                       readerError.shouldSkipUnavailableDataGroupWithoutReauthentication {
                        throw NFCPassportReaderError.NotYetSupported("PACE access information unavailable")
                    }
                    throw error
                }
                preparingBACFallback = true
                eventLogger.log(.paceFailedFallbackToBAC)
                emitProgress(.paceFailedFallbackToBAC)
                if tagReader.paceAuthenticationAttempted {
                    // No guessed GA terminator: re-polling terminates this
                    // connection, then a newly discovered tag is activated.
                    tagReader.disconnect()
                    activeTagReader = nil
                    eventLogger.log(.bacFallbackRestartingPolling)
                    emitProgress(.bacFallbackRestartingPolling)
                    throw PassportAccessRecovery.restartPolling
                }
            }

            if !preparingBACFallback {
                _ = try await tagReader.selectPassportApplication()
                try ensureActiveScan(scanID)
            }
        }

        if preparingBACFallback {
            try await prepareBACFallback(tagReader: tagReader, scanID: scanID)
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
                throw error
            }
        }
        
    }

    func prepareBACFallback(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        tagReader.clearAuthenticationState()
        eventLogger.log(.bacFallbackSelectingApplication)
        emitProgress(.bacFallbackSelectingApplication)
        do {
            _ = try await tagReader.selectPassportApplication()
            try ensureActiveScan(scanID)
        } catch {
            try ensureActiveScan(scanID)
            if let interruption = PassportAccessRecovery.interruption(from: error) {
                throw interruption
            }
            // One additional fresh activation for a rejected application SELECT.
            // Including the initial PACE reset, there are at most two re-polls.
            guard !retriedBACApplicationSelection else {
                throw NFCPassportReaderError.BACFallbackPreparationFailed
            }
            retriedBACApplicationSelection = true
            tagReader.disconnect()
            activeTagReader = nil
            eventLogger.log(.bacFallbackRestartingPolling)
            emitProgress(.bacFallbackRestartingPolling)
            throw PassportAccessRecovery.restartPolling
        }
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
        try await authenticateActively(tagReader: tagReader, scanID: scanID)
    }

    /// Executes AA and its bounded short-response recovery once support is established.
    func authenticateActively(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        eventLogger.log(.activeAuthenticationStarted)
        emitProgress(.activeAuthenticationStarted)

        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        let response: ResponseAPDU
        do {
            response = try await tagReader.doInternalAuthentication(
                challenge: challenge,
                useExtendedMode: useExtendedMode
            )
        } catch {
            try ensureActiveScan(scanID)

            if useExtendedMode, pacePolicy == .allowBACFallback,
               Self.shouldRetryActiveAuthenticationWithoutExtendedMode(after: error) {
                // A failed BAC recovery is a terminal BAC failure, even when AA is optional.
                try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                eventLogger.log(.activeAuthenticationStarted)
                emitProgress(.activeAuthenticationStarted)
                do {
                    response = try await tagReader.doInternalAuthentication(
                        challenge: challenge,
                        useExtendedMode: false
                    )
                } catch {
                    try handleActiveAuthenticationFailure(error, scanID: scanID)
                    return
                }
            } else {
                try handleActiveAuthenticationFailure(error, scanID: scanID)
                return
            }
        }
        try ensureActiveScan(scanID)
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
        if self.passport.activeAuthenticationPassed {
            eventLogger.log(.activeAuthenticationSucceeded)
            emitProgress(.activeAuthenticationSucceeded)
        } else {
            try handleActiveAuthenticationFailure(
                NFCPassportReaderError.ActiveAuthenticationFailed,
                scanID: scanID
            )
        }
    }

    private func handleActiveAuthenticationFailure(_ error: Error, scanID: UInt64) throws {
        try ensureActiveScan(scanID)
        if let interruption = PassportAccessRecovery.interruption(from: error) { throw interruption }
        if let readerError = error as? NFCPassportReaderError, readerError.isSecureMessagingFailure { throw readerError }
        guard let readerError = error as? NFCPassportReaderError else { throw NFCPassportReaderError.UnexpectedError }
        switch readerError {
        case .ResponseError, .ActiveAuthenticationFailed: break
        default: throw readerError
        }
        passport.recordActiveAuthenticationFailure()
        eventLogger.log(.activeAuthenticationFailed)
        emitProgress(.activeAuthenticationFailed)

        if securityPolicy.requiresActiveAuthenticationWhenSupported {
            throw NFCPassportReaderError.ActiveAuthenticationFailed
        }
    }

    static func shouldRetryActiveAuthenticationWithoutExtendedMode(after error: Error) -> Bool {
        guard let readerError = error as? NFCPassportReaderError else { return false }

        switch readerError {
        case .ResponseError(_, 0x67, 0x00),
             .ResponseError(_, 0x6A, 0x81),
             .ResponseError(_, 0x6C, _),
             .ResponseError(_, 0x6D, 0x00),
             .ResponseError(_, 0x6E, 0x00):
            return true
        default:
            return false
        }
    }
    

    func doBACAuthentication(tagReader: TagReader, scanID: UInt64) async throws {
        try ensureActiveScan(scanID)
        guard pacePolicy == .allowBACFallback else {
            throw NFCPassportReaderError.PACEError("Policy", "BAC downgrade is not permitted")
        }
        self.currentlyReadingDataGroup = nil

        eventLogger.log(.bacStarted)
        emitProgress(.bacStarted)
        
        self.passport.BACStatus = .failed

        try ensureActiveScan(scanID)
        let handler = BACHandler(tagReader: tagReader)
        self.bacHandler = handler
        do {
            try await handler.performBACAndGetSessionKeys(mrzKey: mrzKey)
        } catch {
            try ensureActiveScan(scanID)
            eventLogger.log(.bacFailed)
            throw error
        }
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
        
        guard let com = try await readDataGroup(tagReader: tagReader, dgId: .COM, scanID: scanID) as? COM else {
            throw NFCPassportReaderError.DataGroupNotRead
        }
        do {
            try ensureActiveScan(scanID)
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        try ensureActiveScan(scanID)
        DGsToRead.forEach { self.passport.recordDataGroupReadStatus(.advertised, for: $0) }
        
        // Read an explicitly requested mandatory identity group even if a malformed
        // COM omits it. Custom profiles that deliberately omit it stay supported.
        if (readAllDatagroups || dataGroupsToRead.contains(.DG1)), !DGsToRead.contains(.DG1) {
            DGsToRead.append(.DG1)
        }
        if DGsToRead.contains(.DG14), readAllDatagroups || dataGroupsToRead.contains(.DG14) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                let dg14: DataGroup14?
                do {
                    dg14 = try await readDataGroup(
                        tagReader: tagReader,
                        dgId: .DG14,
                        scanID: scanID
                    ) as? DataGroup14
                } catch let error as NFCPassportReaderError {
                    try ensureActiveScan(scanID)
                    guard shouldContinueAfterOptionalDataGroupFailure(error, dataGroup: .DG14) else {
                        throw error
                    }
                    dg14 = nil
                }

                // Do Chip Authentication
                if let dg14 {
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

                    let handler = try ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                    if handler.isChipAuthenticationSupported && passport.chipAuthenticationStatus != .success {
                        self.caHandler = handler
                        try await authenticateChip(tagReader: tagReader, scanID: scanID) {
                            try await handler.doChipAuthentication()
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
        try ensureActiveScan(scanID)
        recordSkippedDataGroups(advertised: advertisedDataGroups, selected: DGsToRead)
        for dgId in DGsToRead {
            do {
                if let dg = try await readDataGroup(tagReader: tagReader, dgId: dgId, scanID: scanID) {
                    try ensureActiveScan(scanID)
                    self.passport.addDataGroup( dgId, dataGroup:dg )
                }
            } catch let error as NFCPassportReaderError {
                try ensureActiveScan(scanID)
                guard shouldContinueAfterOptionalDataGroupFailure(error, dataGroup: dgId) else {
                    throw error
                }
            }
        }
    }

    /// Recovery errors propagate from this boundary; they cannot be swallowed by an optional CA catch.
    func authenticateChip(tagReader: TagReader, scanID: UInt64, attempt: () async throws -> Void) async throws {
        try ensureActiveScan(scanID)
        eventLogger.log(.chipAuthenticationStarted)
        emitProgress(.chipAuthenticationStarted)
        do {
            try await attempt()
            try ensureActiveScan(scanID)
            guard tagReader.secureMessaging != nil,
                  let commonFile = DataGroupId.COM.getFileIDTag() else {
                throw NFCPassportReaderError.ChipAuthenticationFailed
            }
            // CA v1 confirms the shared secret through the new secure-messaging
            // channel. A protected SELECT of the already-read COM confirms it
            // even when no further data groups were requested.
            _ = try await tagReader.selectFile(tag: commonFile)
            try ensureActiveScan(scanID)
        } catch {
            try ensureActiveScan(scanID)
            passport.chipAuthenticationStatus = .failed
            caHandler?.removeSensitiveData()
            caHandler = nil
            tagReader.clearAuthenticationState()
            if let interruption = PassportAccessRecovery.interruption(from: error) { throw interruption }
            if let readerError = error as? NFCPassportReaderError, readerError.isSecureMessagingFailure { throw readerError }
            // Re-polling after reading document data could mix two documents. A
            // failed open CA chain therefore requires a wholly new scan.
            guard !tagReader.generalAuthenticationChainOpen,
                  pacePolicy == .allowBACFallback,
                  !securityPolicy.requiresChipAuthenticationWhenSupported else {
                throw NFCPassportReaderError.ChipAuthenticationFailed
            }
            eventLogger.log(.chipAuthenticationFailedFallbackToBAC)
            emitProgress(.chipAuthenticationFailedFallbackToBAC)
            try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
            return
        }
        passport.chipAuthenticationStatus = .success
        eventLogger.log(.chipAuthenticationSucceeded)
        emitProgress(.chipAuthenticationSucceeded)
    }

    func shouldContinueAfterOptionalDataGroupFailure(
        _ error: NFCPassportReaderError,
        dataGroup: DataGroupId
    ) -> Bool {
        guard !isRequiredDataGroup(dataGroup) else { return false }

        switch error {
        case .InvalidResponse,
             .MissingMandatoryFields,
             .CannotDecodeASN1Length,
             .InvalidASN1Value,
             .InvalidASN1Structure,
             .UnsupportedDataGroup,
             .DataGroupNotRead,
             .UnknownTag,
             .UnknownImageFormat,
             .NotImplemented,
             .UnsupportedCipherAlgorithm,
             .UnsupportedMappingType,
             .InvalidDataPassed,
             .NotYetSupported:
            return true
        default:
            return false
        }
    }

    private func isRequiredDataGroup(_ dataGroup: DataGroupId) -> Bool {
        switch dataGroup {
        case .COM, .SOD, .DG1:
            return true
        case .DG14:
            return securityPolicy.requiresChipAuthenticationWhenSupported
        case .DG15:
            return securityPolicy.requiresActiveAuthenticationWhenSupported
        default:
            return false
        }
    }
    
    func readDataGroup(tagReader: TagReader, dgId: DataGroupId, scanID: UInt64) async throws -> DataGroup? {

        for attempt in 0..<2 {
            try ensureActiveScan(scanID)
            self.currentlyReadingDataGroup = dgId
            progressRenderGeneration &+= 1
            eventLogger.log(.readingDataGroup(dgId))
            emitProgress(.readingDataGroup(dgId, progress: 0))
            updateReaderSessionMessage(alertMessage: .readingDataGroupProgress(dgId, 0))
            do {
                let response = try await tagReader.readDataGroup(dataGroup: dgId)
                try ensureActiveScan(scanID)
                let dg = try DataGroupParser().parseDG(data: response)
                guard dg.datagroupType == dgId else { throw NFCPassportReaderError.InvalidASN1Structure }
                passport.recordDataGroupReadStatus(.read, for: dgId)
                return dg
            } catch {
                try ensureActiveScan(scanID)
                eventLogger.log(.dataGroupReadFailed(dgId))
                passport.recordDataGroupReadStatus(.failed, for: dgId)
                if let interruption = PassportAccessRecovery.interruption(from: error) { throw interruption }
                guard let error = error as? NFCPassportReaderError else { throw NFCPassportReaderError.UnexpectedError }
                if error.isDeterministicDataGroupReadFailure || error.isSecureMessagingFailure { throw error }
                if error.shouldSkipUnavailableDataGroupWithoutReauthentication || error.isUnsupportedDataGroupRead {
                    guard !isRequiredDataGroup(dgId) else { throw NFCPassportReaderError.DataGroupNotRead }
                    Self.removeDataGroup(dgId, from: &dataGroupsToRead)
                    eventLogger.log(.unsupportedDataGroup(dgId))
                    passport.recordDataGroupReadStatus(.unsupported, for: dgId)
                    return nil
                }
                if error.shouldSkipDataGroupAndRedoBAC {
                    guard !isRequiredDataGroup(dgId) else { throw NFCPassportReaderError.DataGroupNotRead }
                    Self.removeDataGroup(dgId, from: &dataGroupsToRead)
                    eventLogger.log(.unsupportedDataGroup(dgId))
                    passport.recordDataGroupReadStatus(.unsupported, for: dgId)
                    try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
                    return nil
                }
                // Retry only a known recoverable status, once, while there is an
                // actual read attempt left. Integrity errors never reach this path.
                guard attempt == 0,
                      error.shouldRedoBACForDataGroupRead || error.shouldReduceReadAmountAndRedoBAC else { throw error }
                if error.shouldReduceReadAmountAndRedoBAC { tagReader.reduceDataReadingAmount() }
                caHandler?.removeSensitiveData()
                caHandler = nil
                try await doBACAuthentication(tagReader: tagReader, scanID: scanID)
            }
        }
        throw NFCPassportReaderError.DataGroupNotRead
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError, scanID: UInt64) {
        guard isActiveScan(scanID) else { return }
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        let failure = makePrivacySafeFailure(for: error)
        let defaultMessage: String
        if case .MoreThanOneTagFound = error {
            defaultMessage = errorMessage.description
        } else {
            defaultMessage = "\(failure.userMessage) \(failure.recoverySuggestion)"
        }
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? defaultMessage)
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
