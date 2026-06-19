//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

#if !os(macOS)
import UIKit
import CoreNFC

@available(iOS 15, *)
public protocol PassportReaderTrackingDelegate: AnyObject {
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
public class PassportReader : NSObject {
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    private var nfcContinuation: NFCCheckedContinuation?
    private let eventLogger: PassportReaderEventLogger
    private var progressHandler: PassportReaderProgressHandler?
    private var scanTimeoutTask: Task<Void, Never>?

    public weak var trackingDelegate: PassportReaderTrackingDelegate?
    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var currentlyReadingDataGroup : DataGroupId?
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    
    // Extended mode is used for reading eMRTD's that support extended length APDUs
    private var useExtendedMode = false

    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var aaChallenge: [UInt8]?
    private var dataAmountToReadOverride : Int? = nil
    
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
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
    public func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
    
    public func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, operationTimeout: TimeInterval? = nil, photoPolicy: PassportPhotoPolicy = .read, progressHandler: PassportReaderProgressHandler? = nil, customDisplayMessage : ((NFCViewDisplayMessage) -> String?)? = nil) async throws -> NFCPassportModel {
        
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf: photoPolicy.apply(to: tags))
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
        
        guard NFCNDEFReaderSession.readingAvailable else {
            eventLogger.log(.readFailed(.nfcNotSupported))
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
                self.nfcContinuation = continuation

                guard NFCTagReaderSession.readingAvailable else {
                    self.failActiveScan(error: .NFCNotSupported)
                    return
                }

                self.readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
                self.emitProgress(.waitingForPassport)
                self.eventLogger.log(.sessionStarted)
                self.startTimeoutTask(operationTimeout)
                self.readerSession?.begin()
            })
        } onCancel: {
            self.cancelRead()
        }
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
        progressHandler: PassportReaderProgressHandler? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
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
            progressHandler: progressHandler,
            customDisplayMessage: customDisplayMessage
        )
    }

    public func cancelRead() {
        failActiveScan(error: .UserCanceled, invalidationReason: .userCanceled)
    }
}

@available(iOS 15, *)
extension PassportReader : NFCTagReaderSessionDelegate {
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

        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
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
                try await session.connect(to: tag)
                self.eventLogger.log(.tagConnected)
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )
                self.emitProgress(.authenticating(progress: 0))
                
                let tagReader = TagReader(tag:passportTag)
                
                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                }
                
                tagReader.progress = { [unowned self] (progress) in
                    let normalizedProgress = Double(progress) / 100.0
                    if let dgId = self.currentlyReadingDataGroup {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                        self.emitProgress(.readingDataGroup(dgId, progress: normalizedProgress))
                    } else {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
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

    func startTimeoutTask(_ operationTimeout: TimeInterval?) {
        scanTimeoutTask?.cancel()
        guard let operationTimeout, operationTimeout > 0 else {
            scanTimeoutTask = nil
            return
        }

        scanTimeoutTask = Task { [weak self] in
            let nanoseconds = UInt64(operationTimeout * 1_000_000_000)
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else { return }
            self?.failActiveScan(error: .TimeOutError, invalidationReason: .timeout)
        }
    }

    func cancelTimeoutTask() {
        scanTimeoutTask?.cancel()
        scanTimeoutTask = nil
    }

    func completeActiveScan(returning passportModel: NFCPassportModel) {
        guard let continuation = nfcContinuation else { return }
        cancelTimeoutTask()
        nfcContinuation = nil
        progressHandler = nil
        continuation.resume(returning: passportModel)
    }

    func failActiveScan(error: NFCPassportReaderError, invalidationReason: PassportReaderSessionInvalidationReason? = nil) {
        if let invalidationReason {
            eventLogger.log(.sessionInvalidated(invalidationReason))
        }
        cancelTimeoutTask()
        self.readerSession?.invalidate()
        self.readerSession = nil
        guard let continuation = nfcContinuation else { return }
        nfcContinuation = nil
        progressHandler = nil
        eventLogger.log(.readFailed(error.privacySafeFailureReason))
        continuation.resume(throwing: error)
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
                 
                let paceHandler = try PACEHandler( cardAccess: cardAccess, tagReader: tagReader )
                try await paceHandler.doPACE(mrzKey: mrzKey )
                passport.PACEStatus = .success
                eventLogger.log(.paceSucceeded)
                emitProgress(.paceSucceeded)

                trackingDelegate?.paceSucceeded()
            } catch {
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
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
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)
        eventLogger.log(.readSucceeded)
        emitProgress(.verifyingDataGroups)
        emitProgress(.complete)

        return self.passport
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
        eventLogger.log(.activeAuthenticationSucceeded)
        emitProgress(.activeAuthenticationSucceeded)
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
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader:tagReader, dgId:.DG14) as? DataGroup14 {
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                     
                    if caHandler.isChipAuthenticationSupported {
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

        // If we are skipping secure elements then remove .DG3 and .DG4
        if self.skipSecureElements {
            DGsToRead = DGsToRead.filter { $0 != .DG3 && $0 != .DG4 }
        }

        if self.readAllDatagroups != true {
            DGsToRead = DGsToRead.filter { dataGroupsToRead.contains($0) }
        }
        for dgId in DGsToRead {
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
            if let dg = try await readDataGroup(tagReader:tagReader, dgId:dgId) {
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    func readDataGroup( tagReader : TagReader, dgId : DataGroupId ) async throws -> DataGroup?  {

        self.currentlyReadingDataGroup = dgId
        eventLogger.log(.readingDataGroup(dgId))
        emitProgress(.readingDataGroup(dgId, progress: 0))
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            do {
                let response = try await tagReader.readDataGroup(dataGroup:dgId)
                let dg = try DataGroupParser().parseDG(data: response)
                return dg
            } catch let error as NFCPassportReaderError {
                eventLogger.log(.dataGroupReadFailed(dgId))
                nfcPassportReaderError = error

                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = error.value
                var redoBAC = false
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "Tag response error / no response" {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    redoBAC = true
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    tagReader.reduceDataReadingAmount()
                    redoBAC = true
                } else if errMsg == "UnsupportedDataGroup" {
                    // OK, this DataGroup is not supported, lets skip it
                    eventLogger.log(.unsupportedDataGroup(dgId))
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
}
#endif
