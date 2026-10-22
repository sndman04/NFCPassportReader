import XCTest
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class PACEFallbackTests: XCTestCase {
    private let key = "synthetic-access-credential"

    private func makeReader(skipPACE: Bool = false) throws -> (PassportReader, UInt64, AccessEvents) {
        let reader = PassportReader()
        let events = AccessEvents()
        reader.configureAccessForTesting(skipPACE: skipPACE, mrzKey: key, progress: { events.append($0) })
        return (reader, try XCTUnwrap(reader.beginScanIfPossible()), events)
    }

    private func expectRestart(_ reader: PassportReader, _ tag: TagReader, _ scan: UInt64) async {
        do {
            try await reader.establishAccess(tagReader: tag, scanID: scan)
            XCTFail("Expected a fresh tag activation")
        } catch PassportAccessRecovery.restartPolling {
            XCTAssertNil(tag.secureMessaging)
            do {
                _ = try await tag.getChallenge()
                XCTFail("An obsolete tag must not be reused")
            } catch NFCPassportReaderError.NoConnectedTag { /* expected */ }
            catch { XCTFail("Unexpected obsolete-tag failure") }
        } catch { XCTFail("Expected bounded recovery") }
    }

    func testSuccessfulPACEDoesNotStartBAC() async throws {
        let reader = SuccessfulPACEReader()
        let events = AccessEvents()
        reader.configureAccessForTesting(mrzKey: key, progress: { events.append($0) })
        let scan = try XCTUnwrap(reader.beginScanIfPossible())
        let transport = ScriptedPassportTransport(.pace)
        try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
        XCTAssertEqual(reader.paceCalls, 1)
        XCTAssertTrue(events.values.contains(.paceSucceeded))
        XCTAssertFalse(events.values.contains(.bacStarted))
        XCTAssertEqual(transport.commands.last, "select application")
        XCTAssertFalse(transport.commands.contains("BAC challenge"))
    }

    func testMissingCardAccessRestoresApplicationAndCompletesRealBAC() async throws {
        try await assertUnsupportedPACE(.missingCardAccess)
    }

    func testCardAccessWithoutPACEInfoRestoresApplicationAndCompletesRealBAC() async throws {
        try await assertUnsupportedPACE(.noPACE)
    }

    private func assertUnsupportedPACE(_ mode: ScriptedPassportTransport.Mode) async throws {
        let (reader, scan, events) = try makeReader()
        let transport = ScriptedPassportTransport(mode)
        let tag = TagReader(transport: transport)
        try await reader.establishAccess(tagReader: tag, scanID: scan)
        XCTAssertEqual(Array(transport.commands.suffix(3)), ["select application", "BAC challenge", "BAC mutual authentication"])
        XCTAssertNotNil(tag.secureMessaging)
        XCTAssertEqual(events.values.filter { [.paceFailedFallbackToBAC, .bacStarted, .bacSucceeded].contains($0) },
                       [.paceFailedFallbackToBAC, .bacStarted, .bacSucceeded])
    }

    func testIntermediateGeneralAuthenticateFailureDiscardsConnectionBeforeSelection() async throws {
        let (reader, scan, events) = try makeReader()
        let oldTransport = ScriptedPassportTransport(.pace)
        let oldTag = TagReader(transport: oldTransport)
        await expectRestart(reader, oldTag, scan)
        XCTAssertEqual(Array(oldTransport.commands.suffix(3)), ["MSE", "GA nonce", "GA mapping rejected"])
        XCTAssertFalse(oldTransport.commands.contains("select application"))
        XCTAssertFalse(events.values.contains(.bacStarted))
        let fresh = ScriptedPassportTransport(.fresh)
        let freshTag = TagReader(transport: fresh)
        try await reader.establishAccess(tagReader: freshTag, scanID: scan)
        XCTAssertEqual(fresh.commands, ["select application", "BAC challenge", "BAC mutual authentication"])
        XCTAssertNotNil(freshTag.secureMessaging)
        XCTAssertEqual(events.values.filter { $0 == .paceFailedFallbackToBAC }.count, 1)
    }

    func testRejectedApplicationSelectGetsOneFreshConnectionRetry() async throws {
        let (reader, scan, _) = try makeReader()
        let first = ScriptedPassportTransport(.missingCardAccess, rejectSelection: true)
        await expectRestart(reader, TagReader(transport: first), scan)
        let fresh = ScriptedPassportTransport(.fresh)
        try await reader.establishAccess(tagReader: TagReader(transport: fresh), scanID: scan)
        XCTAssertEqual(first.commands.filter { $0 == "select application" }.count, 1)
        XCTAssertEqual(fresh.commands, ["select application", "BAC challenge", "BAC mutual authentication"])
    }

    func testSelectionAfterInterruptedPACEAlsoGetsBoundedRecovery() async throws {
        let (reader, scan, _) = try makeReader()
        await expectRestart(reader, TagReader(transport: ScriptedPassportTransport(.pace)), scan)
        await expectRestart(reader, TagReader(transport: ScriptedPassportTransport(.fresh, rejectSelection: true)), scan)
        let fresh = ScriptedPassportTransport(.fresh)
        try await reader.establishAccess(tagReader: TagReader(transport: fresh), scanID: scan)
        XCTAssertEqual(fresh.commands.last, "BAC mutual authentication")
    }

    func testExhaustedRecoveryHasSpecificSafeFailureAndNoBACStarted() async throws {
        let (reader, scan, events) = try makeReader()
        await expectRestart(reader, TagReader(transport: ScriptedPassportTransport(.pace)), scan)
        await expectRestart(reader, TagReader(transport: ScriptedPassportTransport(.fresh, rejectSelection: true)), scan)
        let final = ScriptedPassportTransport(.fresh, rejectSelection: true)
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: final), scanID: scan)
            XCTFail("Expected preparation failure")
        } catch let error as NFCPassportReaderError {
            guard case .BACFallbackPreparationFailed = error else { return XCTFail("Incorrect failure category") }
            reader.failActiveScan(error: error, scanID: scan)
            let failure = reader.privacySafeFailure(for: error)
            XCTAssertEqual(failure.reason, .bacFallbackPreparationFailed)
            XCTAssertEqual(failure.stage, .bacFallbackPreparation)
            XCTAssertTrue(failure.userMessage.contains("did not start"))
        }
        XCTAssertFalse(events.values.contains(.bacStarted))
        XCTAssertEqual(final.commands, ["select application"])
    }

    func testWrongMRZRejectedByRealBACRemainsAccessKeyRejected() async throws {
        let (reader, scan, events) = try makeReader()
        let transport = ScriptedPassportTransport(.missingCardAccess, rejectBAC: true)
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
            XCTFail("Expected access-key rejection")
        } catch let error as NFCPassportReaderError {
            reader.failActiveScan(error: error, scanID: scan)
            XCTAssertEqual(reader.privacySafeFailure(for: error).reason, .accessKeyRejected)
            XCTAssertEqual(reader.privacySafeFailure(for: error).stage, .bac)
        }
        XCTAssertTrue(events.values.contains(.bacStarted))
        XCTAssertFalse(events.values.contains(.bacSucceeded))
    }

    func testRequiredPoliciesNeverDowngrade() async throws {
        for policy: PassportReaderPACEPolicy in [.requirePACEWhenAdvertised, .requireExplicitCredential(.can)] {
            let (reader, scan, events) = try makeReader()
            reader.configurePACEPolicyForTesting(policy, paceKey: "synthetic-can", paceKeyReference: .can)
            let transport = ScriptedPassportTransport(.pace)
            do {
                try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
                XCTFail("Expected required PACE failure")
            } catch PassportAccessRecovery.restartPolling { XCTFail("Required PACE must not recover into BAC") }
            catch { /* PACE failed without downgrade */ }
            XCTAssertFalse(events.values.contains(.paceFailedFallbackToBAC))
            XCTAssertFalse(events.values.contains(.bacStarted))
            XCTAssertFalse(transport.commands.contains("BAC challenge"))
            // Also reject later data-group/AA/CA reauthentication downgrades.
            do {
                try await reader.doBACAuthentication(tagReader: TagReader(transport: transport), scanID: scan)
                XCTFail("PACE policy must apply to reauthentication")
            } catch { /* expected */ }
            XCTAssertFalse(events.values.contains(.bacStarted))
        }
    }

    func testSkipPACEStartsBACDirectly() async throws {
        let (reader, scan, events) = try makeReader(skipPACE: true)
        let transport = ScriptedPassportTransport(.fresh)
        try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
        XCTAssertEqual(transport.commands, ["BAC challenge", "BAC mutual authentication"])
        XCTAssertEqual(events.values, [.bacStarted, .bacSucceeded])
    }

    func testTransportLossDuringPreparationIsNotCredentialOrPreparationRejection() async throws {
        let (reader, scan, events) = try makeReader()
        let transport = ScriptedPassportTransport(.missingCardAccess)
        transport.selectionError = NFCReaderError(.readerTransceiveErrorTagConnectionLost)
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
            XCTFail("Expected transport failure")
        } catch let error as NFCPassportReaderError {
            reader.failActiveScan(error: error, scanID: scan)
            XCTAssertEqual(reader.privacySafeFailure(for: error).reason, .connectionLost)
            XCTAssertEqual(reader.privacySafeFailure(for: error).stage, .bacFallbackPreparation)
        }
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testCanceledScanCannotResumeFallbackOnFreshTag() async throws {
        let (reader, scan, events) = try makeReader()
        await expectRestart(reader, TagReader(transport: ScriptedPassportTransport(.pace)), scan)
        reader.cancelRead()
        let fresh = ScriptedPassportTransport(.fresh)
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: fresh), scanID: scan)
            XCTFail("Canceled scans cannot resume")
        } catch NFCPassportReaderError.UserCanceled { /* expected */ }
        XCTAssertTrue(fresh.commands.isEmpty)
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testFallbackClearsUnusableSecureMessagingBeforeSelect() async throws {
        let (reader, scan, _) = try makeReader()
        let transport = ScriptedPassportTransport(.missingCardAccess)
        let tag = TagReader(transport: transport)
        // A corrupted response while trying PACE must not protect fallback SELECT.
        tag.secureMessaging = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
        try await reader.establishAccess(tagReader: tag, scanID: scan)
        XCTAssertTrue(transport.selectedWithoutSecureMessaging)
        XCTAssertNotNil(tag.secureMessaging) // freshly established BAC
    }

    func testPACETransportInterruptionsDoNotTriggerFallback() async throws {
        let interruptions: [Error] = [NFCPassportReaderError.ConnectionError, NFCPassportReaderError.TimeOutError, CancellationError()]
        let reasons: [PassportReaderFailureReason] = [.connectionLost, .timeout, .userCanceled]
        for (error, reason) in zip(interruptions, reasons) {
            let (reader, scan, events) = try makeReader()
            let transport = ScriptedPassportTransport(.pace)
            transport.accessError = error
            do {
                try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
                XCTFail("Expected interruption")
            } catch let failure as NFCPassportReaderError {
                XCTAssertEqual(reader.privacySafeFailure(for: failure).reason, reason)
                XCTAssertEqual(reader.privacySafeFailure(for: failure).stage, .pace)
            }
            XCTAssertFalse(events.values.contains(.paceFailedFallbackToBAC))
            XCTAssertFalse(events.values.contains(.bacStarted))
        }
    }

    func testOptionalCardSecurityDoesNotSwallowConnectionLoss() async throws {
        let (reader, scan, events) = try makeReader()
        let transport = ScriptedPassportTransport(.pace)
        transport.cardSecurityError = NFCPassportReaderError.ConnectionError
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: transport), scanID: scan)
            XCTFail("Expected connection loss")
        } catch NFCPassportReaderError.ConnectionError { /* expected */ }
        XCTAssertFalse(events.values.contains(.paceFailedFallbackToBAC))
        XCTAssertFalse(transport.commands.contains("MSE"))
    }

    func testSelectCredentialStatusIsPreparationFailureAndRedactsUnderlyingError() async throws {
        let (reader, scan, events) = try makeReader()
        let first = ScriptedPassportTransport(.missingCardAccess)
        first.selectionError = NFCPassportReaderError.InvalidMRZKey
        await expectRestart(reader, TagReader(transport: first), scan)
        let final = ScriptedPassportTransport(.fresh)
        final.selectionError = NFCPassportReaderError.ResponseError(
            "P<UTO Kseed KSenc KSmac RND.IFD RND.ICC FFD8FFE0 00A40400 synthetic-access-credential", 0x69, 0x85)
        do {
            try await reader.establishAccess(tagReader: TagReader(transport: final), scanID: scan)
            XCTFail("Expected preparation failure")
        } catch let error as NFCPassportReaderError {
            let failure = reader.privacySafeFailure(for: error)
            XCTAssertEqual(failure.reason, .bacFallbackPreparationFailed)
            XCTAssertEqual(failure.stage, .bacFallbackPreparation)
            XCTAssertFalse(failure.userMessage.contains("Kseed"))
            XCTAssertFalse(error.description.contains("synthetic"))
        }
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testOnlyTransportAndSessionErrorsAreClassifiedAsInterruptions() {
        XCTAssertNil(PassportAccessRecovery.interruption(from: NFCReaderError(.readerErrorInvalidParameter)))
        XCTAssertNil(PassportAccessRecovery.interruption(from: NFCPassportReaderError.InvalidMRZKey))
        XCTAssertEqual(PassportAccessRecovery.interruption(from: NFCReaderError(.readerTransceiveErrorTagNotConnected))?.privacySafeFailureReason, .connectionLost)
        XCTAssertEqual(PassportAccessRecovery.interruption(from: NFCReaderError(.readerSessionInvalidationErrorSessionTimeout))?.privacySafeFailureReason, .timeout)
    }

    func testGenericAuthenticationProgressPreservesSpecificStage() throws {
        let (reader, _, _) = try makeReader()
        for event: PassportReaderProgressEvent in [.paceStarted, .paceFailedFallbackToBAC, .bacStarted] {
            reader.emitProgress(event)
            reader.emitProgress(.authenticating(progress: 0.5))
            XCTAssertEqual(reader.privacySafeFailure(for: .TimeOutError).stage, event.scanStage)
        }
    }

    func testFallbackFailureDescriptionsContainNoUnderlyingSensitiveText() {
        let error = NFCPassportReaderError.BACFallbackPreparationFailed
        let failure = error.privacySafeFailure(at: .bacFallbackPreparation)
        let descriptions = [error.description, error.localizedDescription, failure.userMessage, failure.recoverySuggestion,
                            PassportReaderLogEvent.readFailed(failure.reason).description].joined(separator: " ")
        for forbidden in ["Kseed", "KSenc", "KSmac", "RND.IFD", "RND.ICC", "FFD8FFE0", "P<UTO", "00A40400", key] {
            XCTAssertFalse(descriptions.contains(forbidden))
        }
        XCTAssertEqual(PassportReaderProgressEvent.paceFailedFallbackToBAC.scanStage, .bacFallbackPreparation)
    }
}

@MainActor
private final class SuccessfulPACEReader: PassportReader {
    var paceCalls = 0
    override func performPACE(_ handler: PACEHandler) async throws {
        // Control-flow seam only. Crypto/token/secure-messaging tests separately
        // cover PACE internals; all failure paths above execute the real handler.
        paceCalls += 1
    }
}

private final class AccessEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [PassportReaderProgressEvent] = []
    func append(_ event: PassportReaderProgressEvent) { lock.withLock { storage.append(event) } }
    var values: [PassportReaderProgressEvent] { lock.withLock { storage } }
}
