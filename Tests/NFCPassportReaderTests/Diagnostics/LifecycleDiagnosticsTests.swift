import XCTest
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class LifecycleDiagnosticsTests: XCTestCase {
    func testCompleteReadEmitsSuccessOnlyAfterVerificationAndCleanup() async throws {
        let (reader, tag, id, events) = try makeScan()
        let model = try await reader.startReading(tagReader: tag, scanID: id)
        XCTAssertFalse(events.values.contains(.complete))
        XCTAssertTrue(events.values.contains(.verifyingDataGroups))
        reader.completeActiveScan(returning: model, scanID: id)
        XCTAssertEqual(events.values.last, .complete)
        XCTAssertFalse(reader.isActiveScan(id))
        XCTAssertFalse(events.values.contains(.bacStarted))
        do { _ = try await tag.getChallenge(); XCTFail("Expected revoked transport") }
        catch NFCPassportReaderError.NoConnectedTag { } catch { XCTFail("Wrong cleanup result") }
    }

    func testSecurityPolicyFailureNeverReportsComplete() async throws {
        let (reader, tag, id, events) = try makeScan(policy: .notaryRecommended)
        do { _ = try await reader.startReading(tagReader: tag, scanID: id); XCTFail("Expected incomplete verification failure") }
        catch NFCPassportReaderError.SecurityPolicyViolation { reader.failActiveScan(error: .SecurityPolicyViolation, scanID: id) }
        catch { XCTFail("Wrong policy failure") }
        XCTAssertFalse(events.values.contains(.complete))
        XCTAssertEqual(events.values.last, .failed(reason: .verificationFailed, stage: .securityPolicyValidation))
        XCTAssertEqual(reader.privacySafeFailure(for: .SecurityPolicyViolation).stage, .securityPolicyValidation)
    }

    func testTerminalCallbackCanStartAnotherScanWithoutOldCleanupClobberingIt() throws {
        let sink = LifecycleLog()
        let reader = PassportReader(logLevel: .info, logger: sink)
        let old = try XCTUnwrap(reader.beginScanIfPossible())
        var next: UInt64?
        sink.callback = { event in
            if case .readSucceeded = event { next = reader.beginScanIfPossible() }
        }
        reader.completeActiveScan(returning: NFCPassportModel(), scanID: old)
        XCTAssertTrue(reader.isActiveScan(try XCTUnwrap(next)))
        reader.failActiveScan(error: .ConnectionError, scanID: old)
        XCTAssertTrue(reader.isActiveScan(try XCTUnwrap(next)))
        sink.callback = nil
    }

    func testErrorLoggerIncludesTerminalReasonAndStageAndRetainsSink() throws {
        var sink: LifecycleLog? = LifecycleLog()
        weak var retained = sink
        let reader = PassportReader(logLevel: .error, logger: sink)
        sink = nil
        XCTAssertNotNil(retained)
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        reader.emitProgress(.readingDataGroup(.DG1, progress: 0))
        reader.failActiveScan(error: .InvalidResponseChecksum, scanID: id)
        XCTAssertEqual(retained?.events.map(\.description), [
            "Passport chip read failed: verification failed",
            "Passport chip read failed during reading DG1: verification failed"
        ])
        retained = nil
    }

    func testNewDiagnosticsAndLegacyFormatterRedactUnderlyingSensitivePayloads() {
        let marker = "P<UTO SYNTHETIC Kseed KSenc KSmac RND.IFD RND.ICC FFD8FFE0 00A40400 " + String(repeating: "AB", count: 40)
        let error = NFCPassportReaderError.Unknown(NSError(domain: marker, code: 1, userInfo: [NSLocalizedDescriptionKey: marker]))
        let text = [error.value, error.safeDescription, error.localizedDescription,
                    PassportReaderLogEvent.readFailedAtStage(.verificationFailed, .bac).description,
                    PassportReaderLogEvent.bacFallbackRestartingPolling.description,
                    PassportReaderLogEvent.bacFallbackSelectingApplication.description,
                    PassportReaderProgressEvent.failed(reason: .verificationFailed, stage: .bac).description,
                    PassportReaderProgressEvent.bacFallbackRestartingPolling.description,
                    PassportReaderProgressEvent.bacFallbackSelectingApplication.description,
                    PassportReaderFailure(reason: .verificationFailed, stage: .bac).userMessage].joined(separator: " ")
        for forbidden in marker.split(separator: " ") { XCTAssertFalse(text.contains(forbidden)) }
        XCTAssertNil(text.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
        XCTAssertFalse(text.contains("signed data"))
    }

    func testUnrecognizedTransportErrorDoesNotEscapeWithRawMetadata() async throws {
        let marker = "synthetic-sensitive-detail"
        let transport = LifecycleTransport { _, _ in throw NSError(domain: marker, code: 1, userInfo: [NSLocalizedDescriptionKey: marker]) }
        do { _ = try await TagReader(transport: transport).getChallenge(); XCTFail("Expected transport failure") }
        catch NFCPassportReaderError.UnexpectedError { } catch { XCTFail("Raw error escaped transport boundary") }
    }

    func testDisplayProgressClampsArbitraryClientInput() {
        for progress in [Int.min, -1, 0, 100, 101, Int.max] {
            let text = NFCViewDisplayMessage.authenticatingWithPassport(progress).description
            XCTAssertLessThan(text.count, 100)
            XCTAssertEqual(text.filter { $0 == "🟢" || $0 == "⚪️" }.count, 5)
        }
    }

    func testUnusedCAHandlerCannotDestroyEstablishedMessaging() throws {
        let tag = TagReader(transport: LifecycleTransport { _, _ in (Data(), 0x90, 0) })
        let sm = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
        tag.secureMessaging = sm
        var handler: ChipAuthenticationHandler? = try ChipAuthenticationHandler(dg14: DataGroup14([0x6E, 2, 0x31, 0]), tagReader: tag)
        XCTAssertFalse(try XCTUnwrap(handler).isChipAuthenticationSupported)
        handler = nil
        XCTAssertTrue(tag.secureMessaging === sm)
        XCTAssertFalse(sm.sequenceCounter.isEmpty)
        tag.disconnect()
    }

    private func makeScan(policy: PassportReaderSecurityPolicy = .default) throws -> (PassportReader, TagReader, UInt64, LifecycleEvents) {
        let reader = LifecyclePACEReader()
        let events = LifecycleEvents()
        reader.configureAccessForTesting(mrzKey: "synthetic-access-credential", progress: events.append)
        let paceTransport = ScriptedPassportTransport(.pace)
        let file = lifecycleCOM([])
        var applicationSelected = false
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4, command.p1Parameter == 4 {
                applicationSelected = true
                return (Data(), 0x90, 0)
            }
            if !applicationSelected { return try await paceTransport.sendCommand(apdu: command) }
            if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
            let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
            return (Data(file.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        // Deliberate custom COM-only profile isolates orchestration from identity fixtures.
        reader.configureLifecycleForTesting(tagReader: tag, groups: [.COM], securityPolicy: policy)
        return (reader, tag, try XCTUnwrap(reader.beginScanIfPossible()), events)
    }
}

@MainActor
private final class LifecyclePACEReader: PassportReader {
    override func performPACE(_ handler: PACEHandler) async throws { }
}

@MainActor
private final class LifecycleLog: @preconcurrency PassportReaderLogging {
    var events: [PassportReaderLogEvent] = []
    var callback: ((PassportReaderLogEvent) -> Void)?
    func log(_ event: PassportReaderLogEvent) { events.append(event); callback?(event) }
}
