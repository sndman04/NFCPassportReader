import XCTest
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class ScanLifecycleTests: XCTestCase {
    private let key = "synthetic-access-credential"

    private func scan(tag: TagReader? = nil, extended: Bool = false,
                      policy: PassportReaderSecurityPolicy = .default) throws -> (PassportReader, UInt64, LifecycleEvents) {
        let reader = PassportReader()
        let events = LifecycleEvents()
        reader.configureAccessForTesting(mrzKey: key, progress: events.append)
        reader.configureLifecycleForTesting(tagReader: tag, securityPolicy: policy, useExtendedMode: extended)
        return (reader, try XCTUnwrap(reader.beginScanIfPossible()), events)
    }

    func testSynchronousWorkCannotCompleteBeyondOperationDeadline() throws {
        let (reader, id, _) = try scan()
        reader.startTimeoutTask(0.001, scanID: id)
        // Hold the actor briefly so the timer task cannot run; the boundary check must still expire.
        Thread.sleep(forTimeInterval: 0.005)
        XCTAssertThrowsError(try reader.ensureActiveScan(id)) { error in
            guard case NFCPassportReaderError.TimeOutError = error else { return XCTFail("Expected expired deadline") }
        }
        reader.cancelRead()
    }

    func testRequiredPACEWithMissingAccessFileReportsUnsupportedAtPACEStage() async throws {
        let transport = ScriptedPassportTransport(.missingCardAccess)
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised)
        do { try await reader.establishAccess(tagReader: tag, scanID: id); XCTFail("Expected unavailable PACE") }
        catch let error as NFCPassportReaderError {
            XCTAssertEqual(error.privacySafeFailureReason, .unsupportedPassport)
            reader.failActiveScan(error: error, scanID: id)
            XCTAssertEqual(reader.privacySafeFailure(for: error).stage, .pace)
        }
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testOverlappingReadCannotDowngradeActivePACEPolicy() async throws {
        let (reader, id, _) = try scan()
        reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised)
        do {
            _ = try await reader.readPassport(mrzKey: key, pacePolicy: .allowBACFallback)
            XCTFail("Expected overlap rejection")
        } catch NFCPassportReaderError.ScanAlreadyInProgress { } catch { XCTFail("Wrong overlap failure") }
        XCTAssertTrue(reader.isActiveScan(id))
        XCTAssertTrue(reader.shouldFailInsteadOfFallingBackFromPACE(error: NFCPassportReaderError.UnexpectedError))
    }

    func testOverlappingExplicitCredentialCannotReplaceActiveCredentialPolicy() async throws {
        let (reader, _, _) = try scan()
        reader.configurePACEPolicyForTesting(.requireExplicitCredential(.can), pendingPACEKey: "123456", pendingPACEKeyReference: .can)
        do {
            _ = try await reader.readPassport(mrzKey: key, paceKey: "654321", paceKeyReference: .mrz)
            XCTFail("Expected overlap rejection")
        } catch NFCPassportReaderError.ScanAlreadyInProgress { } catch { XCTFail("Wrong overlap failure") }
        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeSession(skipPACE: false))
    }

    func testRevokedTransportCannotFollowLateResponseWithGetResponse() async throws {
        let transport = DeferredLifecycleTransport()
        let tag = TagReader(transport: transport)
        let task = Task { try await tag.getChallenge() }
        await transport.waitForCommand()
        tag.disconnect()
        transport.respond((Data([1]), 0x61, 1))
        do { _ = try await task.value; XCTFail("Expected revocation") }
        catch NFCPassportReaderError.ConnectionError { } catch { XCTFail("Wrong revocation failure") }
        XCTAssertEqual(transport.commands, [0x84])
        XCTAssertNil(tag.secureMessaging)
    }

    func testCancellationDuringBACPreventsMutualAuthenticationAndLateStateChanges() async throws {
        let transport = DeferredLifecycleTransport()
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        let task = Task { try await reader.doBACAuthentication(tagReader: tag, scanID: id) }
        await transport.waitForCommand()
        reader.cancelRead()
        let next = try XCTUnwrap(reader.beginScanIfPossible())
        transport.respond((Data(repeating: 1, count: 8), 0x90, 0))
        do { try await task.value; XCTFail("Expected cancellation") }
        catch NFCPassportReaderError.UserCanceled { } catch { XCTFail("Wrong cancellation failure") }
        XCTAssertTrue(reader.isActiveScan(next))
        XCTAssertEqual(transport.commands, [0x84])
        XCTAssertFalse(events.values.contains(.bacSucceeded))
        XCTAssertEqual(events.values.filter { if case .failed = $0 { return true }; return false }.count, 1)
        XCTAssertNil(tag.secureMessaging)
    }

    func testTimeoutDuringTransportKeepsTimeoutStageAndStopsCommands() async throws {
        let transport = DeferredLifecycleTransport()
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        let task = Task { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG1, scanID: id) }
        await transport.waitForCommand()
        reader.failActiveScan(error: .TimeOutError, scanID: id)
        transport.respond((Data(), 0x90, 0))
        _ = await task.result
        XCTAssertEqual(transport.commands.count, 1)
        XCTAssertEqual(reader.privacySafeFailure(for: .TimeOutError).stage, .readingDataGroup(.DG1))
        XCTAssertTrue(events.values.contains(.failed(reason: .timeout, stage: .readingDataGroup(.DG1))))
    }

    func testCleanupRevokesSuccessfulSessionAndScrubsMessaging() async throws {
        let transport = ScriptedPassportTransport(.fresh)
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        try await reader.doBACAuthentication(tagReader: tag, scanID: id)
        let sm = try XCTUnwrap(tag.secureMessaging)
        reader.completeActiveScan(returning: NFCPassportModel(), scanID: id)
        reader.completeActiveScan(returning: NFCPassportModel(), scanID: id)
        XCTAssertNil(tag.secureMessaging)
        XCTAssertTrue(sm.sequenceCounter.isEmpty)
        XCTAssertEqual(events.values.filter { $0 == .complete }.count, 1)
        do { _ = try await tag.getChallenge(); XCTFail("Expected revoked connection") }
        catch NFCPassportReaderError.NoConnectedTag { } catch { XCTFail("Wrong cleanup failure") }
    }

    func testChipAuthenticationCannotSucceedWithoutNewSessionKeyConfirmation() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x90, 0) }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        do {
            try await reader.authenticateChip(tagReader: tag, scanID: id) {
                tag.secureMessaging = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
            }
            XCTFail("Expected rejected key confirmation")
        } catch NFCPassportReaderError.UnableToUnprotectAPDU { } catch { XCTFail("Wrong confirmation failure") }
        XCTAssertEqual(transport.commands, [0xA4])
        XCTAssertFalse(events.values.contains(.chipAuthenticationSucceeded))
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testChipAuthenticationSucceedsOnlyAfterAuthenticatedConfirmation() async throws {
        let macKey = Array(repeating: UInt8(2), count: 16)
        let transport = LifecycleTransport { command, _ in
            XCTAssertEqual(command.instructionCode, 0xA4)
            XCTAssertEqual(command.instructionClass, 0x0C)
            let counter: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 2]
            let status: [UInt8] = [0x99, 2, 0x90, 0]
            let checksum = Array(mac(algoName: .DES, key: macKey, msg: pad(counter + status, blockSize: 8)).prefix(8))
            return (Data(status + wrapDO(b: 0x8E, arr: checksum)), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        try await reader.authenticateChip(tagReader: tag, scanID: id) {
            tag.secureMessaging = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: macKey, ssc: Array(repeating: 0, count: 8))
        }
        XCTAssertEqual(transport.commands, [0xA4])
        XCTAssertEqual(events.values.last, .chipAuthenticationSucceeded)
        XCTAssertFalse(events.values.contains(.bacStarted))
        reader.failActiveScan(error: .UserCanceled, scanID: id)
        XCTAssertEqual(reader.lastDiagnosticSnapshot?.verification.chipAuthentication.status, .succeeded)
        XCTAssertEqual(reader.lastDiagnosticSnapshot?.verification.chipAuthentication.attempted, true)
    }

    func testChipAuthenticationRecoveryPreservesBACKeyRejection() async throws {
        let transport = ScriptedPassportTransport(.fresh, rejectBAC: true)
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        do {
            try await reader.authenticateChip(tagReader: tag, scanID: id) { throw NFCPassportReaderError.ChipAuthenticationFailed }
            XCTFail("Expected BAC rejection")
        } catch NFCPassportReaderError.InvalidMRZKey {
            reader.failActiveScan(error: .InvalidMRZKey, scanID: id)
        } catch { XCTFail("Wrong recovery failure") }
        XCTAssertTrue(events.values.contains(.chipAuthenticationFailedFallbackToBAC))
        XCTAssertEqual(reader.privacySafeFailure(for: .InvalidMRZKey).stage, .bac)
        XCTAssertFalse(events.values.contains(.complete))
        XCTAssertEqual(reader.lastDiagnosticSnapshot?.verification.chipAuthentication.status, .failed)
        XCTAssertEqual(reader.lastDiagnosticSnapshot?.verification.chipAuthentication.attempted, true)
    }

    func testChipAuthenticationInterruptionAndIntegrityNeverStartBAC() async throws {
        for error in [NFCPassportReaderError.ConnectionError, .TimeOutError, .InvalidResponseChecksum] {
            let transport = ScriptedPassportTransport(.fresh)
            let tag = TagReader(transport: transport)
            let (reader, id, events) = try scan(tag: tag)
            do { try await reader.authenticateChip(tagReader: tag, scanID: id) { throw error }; XCTFail("Expected failure") }
            catch let actual as NFCPassportReaderError { XCTAssertEqual(actual.safeDescription, error.safeDescription) }
            XCTAssertTrue(transport.commands.isEmpty)
            XCTAssertFalse(events.values.contains(.bacStarted))
        }
    }

    func testFailedOpenChipAuthenticationChainRequiresNewScan() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x6A, 0x80) }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        do {
            try await reader.authenticateChip(tagReader: tag, scanID: id) {
                _ = try await tag.sendGeneralAuthenticate(data: [], isLast: false)
            }
            XCTFail("Expected failed chain")
        } catch NFCPassportReaderError.ChipAuthenticationFailed { } catch { XCTFail("Wrong chain failure") }
        XCTAssertTrue(tag.generalAuthenticationChainOpen)
        XCTAssertEqual(transport.commands, [0x86])
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testRequiredChipAuthenticationAndRequiredPACEPreventCAFallback() async throws {
        for requirePACE in [false, true] {
            let transport = ScriptedPassportTransport(.fresh)
            let tag = TagReader(transport: transport)
            let policy = PassportReaderSecurityPolicy(verificationRequirement: requirePACE ? .none : .chipAuthenticationWhenSupported)
            let (reader, id, events) = try scan(tag: tag, policy: policy)
            if requirePACE { reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised) }
            do { try await reader.authenticateChip(tagReader: tag, scanID: id) { throw NFCPassportReaderError.ChipAuthenticationFailed }; XCTFail("Expected required verification failure") }
            catch NFCPassportReaderError.ChipAuthenticationFailed { } catch { XCTFail("Wrong policy failure") }
            XCTAssertTrue(transport.commands.isEmpty)
            XCTAssertFalse(events.values.contains(.chipAuthenticationFailedFallbackToBAC))
        }
    }

    func testOptionalActiveAuthenticationDoesNotSwallowInterruptionsOrIntegrityErrors() async throws {
        for error in [NFCPassportReaderError.ConnectionError, .TimeOutError, .InvalidResponseChecksum, .UnexpectedError] {
            let transport = LifecycleTransport { _, _ in throw error }
            let tag = TagReader(transport: transport)
            let (reader, id, _) = try scan(tag: tag)
            do { try await reader.authenticateActively(tagReader: tag, scanID: id); XCTFail("Expected fatal AA failure") }
            catch let actual as NFCPassportReaderError { XCTAssertEqual(actual.safeDescription, error.safeDescription) }
            XCTAssertEqual(transport.commands, [0x88])
        }
    }

    func testActiveAuthenticationShortRetryPropagatesFailedBAC() async throws {
        let bac = ScriptedPassportTransport(.fresh, rejectBAC: true)
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0x88 { return (Data(), 0x67, 0) }
            return try await bac.sendCommand(apdu: command)
        }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag, extended: true)
        do { try await reader.authenticateActively(tagReader: tag, scanID: id); XCTFail("Expected failed BAC") }
        catch NFCPassportReaderError.InvalidMRZKey { reader.failActiveScan(error: .InvalidMRZKey, scanID: id) }
        catch { XCTFail("Wrong BAC failure") }
        XCTAssertEqual(transport.commands, [0x88, 0x84, 0x82])
        XCTAssertEqual(reader.privacySafeFailure(for: .InvalidMRZKey).stage, .bac)
        XCTAssertFalse(events.values.contains(.activeAuthenticationFailed))
    }

    func testActiveAuthenticationShortRetryRestoresAAStage() async throws {
        let bac = ScriptedPassportTransport(.fresh)
        var attempts = 0
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0x88 {
                attempts += 1
                if attempts == 1 { return (Data(), 0x67, 0) }
                throw NFCPassportReaderError.ConnectionError
            }
            return try await bac.sendCommand(apdu: command)
        }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag, extended: true)
        do { try await reader.authenticateActively(tagReader: tag, scanID: id); XCTFail("Expected interrupted retry") }
        catch NFCPassportReaderError.ConnectionError { reader.failActiveScan(error: .ConnectionError, scanID: id) }
        catch { XCTFail("Wrong interruption") }
        XCTAssertEqual(reader.privacySafeFailure(for: .ConnectionError).stage, .activeAuthentication)
        XCTAssertEqual(events.values.filter { $0 == .activeAuthenticationStarted }.count, 2)
    }

    func testRequiredPACEOptionalAACannotDowngrade() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x67, 0) }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag, extended: true)
        reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised)
        try await reader.authenticateActively(tagReader: tag, scanID: id)
        XCTAssertEqual(transport.commands, [0x88])
        XCTAssertTrue(events.values.contains(.activeAuthenticationFailed))
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testMissingMandatoryFilesNeverBecomeSuccessfulSkippedReads() async throws {
        for group in [DataGroupId.COM, .SOD, .DG1] {
            for status: (UInt8, UInt8) in [(0x6A, 0x82), (0x69, 0x82)] {
                let transport = LifecycleTransport { _, _ in (Data(), status.0, status.1) }
                let tag = TagReader(transport: transport)
                let (reader, id, events) = try scan(tag: tag)
                do { _ = try await reader.readDataGroup(tagReader: tag, dgId: group, scanID: id); XCTFail("Expected required file failure") }
                catch NFCPassportReaderError.DataGroupNotRead { } catch { XCTFail("Wrong required file failure") }
                XCTAssertEqual(transport.commands.count, 1)
                XCTAssertFalse(events.values.contains(.bacStarted))
            }
        }
    }

    func testMissingOptionalFileDoesNotDisturbAuthentication() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x6A, 0x82) }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        let result = try await reader.readDataGroup(tagReader: tag, dgId: .DG11, scanID: id)
        XCTAssertNil(result)
        XCTAssertEqual(transport.commands.count, 1)
        XCTAssertFalse(events.values.contains(.bacStarted))
    }

    func testMismatchedDataGroupIsRejectedBeforeStorage() async throws {
        let transport = fileTransport(lifecycleCOM([]))
        let tag = TagReader(transport: transport)
        let (reader, id, _) = try scan(tag: tag)
        do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG1, scanID: id); XCTFail("Expected wrong group rejection") }
        catch NFCPassportReaderError.InvalidASN1Structure { } catch { XCTFail("Wrong group failure") }
        XCTAssertFalse(transport.commands.contains(0x84))
    }

    func testUnadvertisedRequestedIdentityStillGetsRead() async throws {
        let file = lifecycleCOM([])
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 {
                if command.data == Data(DataGroupId.DG1.getFileIDTag()!) { return (Data(), 0x6A, 0x82) }
                return (Data(), 0x90, 0)
            }
            let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
            return (Data(file.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        reader.configureLifecycleForTesting(tagReader: tag, groups: [.COM, .DG1])
        do { try await reader.readDataGroups(tagReader: tag, scanID: id); XCTFail("Expected missing identity failure") }
        catch NFCPassportReaderError.DataGroupNotRead { } catch { XCTFail("Wrong identity failure") }
        XCTAssertTrue(events.values.contains(.readingDataGroup(.DG1, progress: 0)))
    }

    func testProfileExclusionDoesNotReadChipAuthenticationFile() async throws {
        let tag = TagReader(transport: fileTransport(lifecycleCOM([0x6E])))
        let (reader, id, events) = try scan(tag: tag)
        reader.configureLifecycleForTesting(tagReader: tag, groups: [.COM])
        try await reader.readDataGroups(tagReader: tag, scanID: id)
        XCTAssertFalse(events.values.contains(.readingDataGroup(.DG14, progress: 0)))
        XCTAssertFalse(events.values.contains(.chipAuthenticationStarted))
    }

    func testRetryRestoresGroupStageAndDoesNotAuthenticateAfterFinalReadFailure() async throws {
        let bac = ScriptedPassportTransport(.fresh)
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 { return (Data(), 0x69, 0x88) }
            return try await bac.sendCommand(apdu: command)
        }
        let tag = TagReader(transport: transport)
        let (reader, id, events) = try scan(tag: tag)
        do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG1, scanID: id); XCTFail("Expected bounded failure") }
        catch let error as NFCPassportReaderError { reader.failActiveScan(error: error, scanID: id) }
        XCTAssertEqual(transport.commands, [0xA4, 0x84, 0x82, 0xA4])
        XCTAssertEqual(events.values.filter { $0 == .readingDataGroup(.DG1, progress: 0) }.count, 2)
        XCTAssertTrue(events.values.contains(.failed(reason: .unexpectedReadFailure, stage: .readingDataGroup(.DG1))))
    }

    func testDataGroupIntegrityFailureNeverRetries() async throws {
        let transport = LifecycleTransport { _, _ in throw NFCPassportReaderError.InvalidResponseChecksum }
        let tag = TagReader(transport: transport)
        let (reader, id, _) = try scan(tag: tag)
        do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG2, scanID: id); XCTFail("Expected integrity failure") }
        catch NFCPassportReaderError.InvalidResponseChecksum { } catch { XCTFail("Wrong integrity failure") }
        XCTAssertEqual(transport.commands, [0xA4])
    }

    func testNonAuthenticationRejectionIsNotMisreportedAsWrongAccessKey() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x63, 0) }
        let tag = TagReader(transport: transport)
        do { _ = try await tag.selectPassportApplication(); XCTFail("Expected selection failure") }
        catch let error as NFCPassportReaderError { XCTAssertNotEqual(error.privacySafeFailureReason, .accessKeyRejected) }
    }

    func testMalformedProtectedResponseFailsClosedAndClearsMessaging() async throws {
        let transport = LifecycleTransport { _, _ in (Data([0]), 0x90, 0) }
        let tag = TagReader(transport: transport)
        tag.secureMessaging = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
        do { _ = try await tag.selectPassportApplication(); XCTFail("Expected secure response failure") }
        catch NFCPassportReaderError.UnableToUnprotectAPDU { } catch { XCTFail("Wrong secure response failure") }
        XCTAssertNil(tag.secureMessaging)
        XCTAssertEqual(transport.commands.count, 1)
    }

    private func fileTransport(_ file: [UInt8]) -> LifecycleTransport {
        LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
            let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
            return (Data(file.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
        }
    }
}

@MainActor
final class LifecycleTransport: PassportTagTransport {
    private let response: @MainActor (NFCISO7816APDU, Int) async throws -> (Data, UInt8, UInt8)
    private(set) var commands: [UInt8] = []
    init(_ response: @escaping @MainActor (NFCISO7816APDU, Int) async throws -> (Data, UInt8, UInt8)) { self.response = response }
    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        commands.append(apdu.instructionCode)
        return try await response(apdu, commands.count)
    }
}

@MainActor
final class DeferredLifecycleTransport: PassportTagTransport {
    private var pending: CheckedContinuation<(Data, UInt8, UInt8), Error>?
    private var waiter: CheckedContinuation<Void, Never>?
    private(set) var commands: [UInt8] = []
    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        commands.append(apdu.instructionCode)
        return try await withCheckedThrowingContinuation { continuation in
            pending = continuation
            waiter?.resume()
            waiter = nil
        }
    }
    func waitForCommand() async {
        if pending != nil { return }
        await withCheckedContinuation { waiter = $0 }
    }
    func respond(_ response: (Data, UInt8, UInt8)) {
        pending?.resume(returning: response)
        pending = nil
    }
}

final class LifecycleEvents: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [PassportReaderProgressEvent] = []
    func append(_ event: PassportReaderProgressEvent) { lock.withLock { storage.append(event) } }
    var values: [PassportReaderProgressEvent] { lock.withLock { storage } }
}

func lifecycleCOM(_ groups: [UInt8]) -> [UInt8] {
    let body: [UInt8] = [0x5F, 1, 4] + Array("0107".utf8) + [0x5F, 0x36, 6] + Array("040000".utf8) + [0x5C, UInt8(groups.count)] + groups
    return wrapDO(b: 0x60, arr: body)
}
