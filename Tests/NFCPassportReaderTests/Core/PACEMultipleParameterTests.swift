import XCTest
import CryptoTokenKit
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class PACEMultipleParameterTests: XCTestCase {
    func testMultipleDHParametersExplicitlySelectsChosenSetIncludingZero() async throws {
        try await check(parameters: [0, 1], isDH: true, includesReference: true)
    }
    func testMultipleECDHParametersExplicitlySelectsChosenSet() async throws {
        try await check(parameters: [12, 13], includesReference: true)
    }
    func testSingleParameterPreservesPublishedCommandShape() async throws {
        try await check(parameters: [13], includesReference: false)
    }
    func testMultipleCipherOptionsWithSameParametersNeedsNoReference() async throws {
        try await check(parameters: [13, 13], includesReference: false)
    }

    func testReaderSelectsMultipleDHParametersIncludingZero() async throws {
        try await check(parameters: [0, 1], isDH: true, includesReference: true, viaReader: true)
    }
    func testReaderSelectsMultipleECDHParameters() async throws {
        try await check(parameters: [12, 13], includesReference: true, viaReader: true)
    }
    func testReaderPreservesSingleParameterCommand() async throws {
        try await check(parameters: [13], includesReference: false, viaReader: true)
    }
    func testReaderPreservesSharedParameterCommand() async throws {
        try await check(parameters: [13, 13], includesReference: false, viaReader: true)
    }

    private func check(parameters: [Int], isDH: Bool = false, includesReference: Bool, viaReader: Bool = false) async throws {
        let primary = isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128
        let secondary = isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256
        let infos = parameters.enumerated().flatMap { index, parameter in
            wrapDO(b: 0x30, arr: oidToBytes(oid: index == 0 ? primary : secondary, replaceTag: false) + [2, 1, 2, 2, 1, UInt8(parameter)])
        }
        let accessData = wrapDO(b: 0x31, arr: infos)
        let access = try CardAccess(accessData)
        let selected = try XCTUnwrap(access.preferredPACEInfo)
        let transport = LifecycleTransport { command, _ in
            if viaReader {
                switch command.instructionCode {
                case 0xA4:
                    // CardAccess is available; optional CardSecurity is absent.
                    XCTAssertEqual(command.instructionClass, 0)
                    if command.data == Data([1, 0x1D]) { return (Data(), 0x6A, 0x82) }
                    XCTAssertTrue(command.data == Data([0x3F, 0]) || command.data == Data([1, 0x1C]))
                    return (Data(), 0x90, 0)
                case 0xB0:
                    let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
                    return (Data(accessData.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
                default:
                    break
                }
            }
            XCTAssertEqual(command.instructionCode, 0x22)
            XCTAssertEqual(command.expectedResponseLength, -1)
            let records = try XCTUnwrap(TKBERTLVRecord.sequenceOfRecords(from: command.data ?? Data()))
            let references = records.filter { $0.tag == 0x84 }
            XCTAssertEqual(references.count, includesReference ? 1 : 0)
            if includesReference {
                XCTAssertTrue(references.first?.value == Data([UInt8(try XCTUnwrap(selected.parameterId))]), "MSE must identify the selected parameters")
            }
            // Stop at the command boundary so no key exchange/fixture nonce is needed.
            throw NFCPassportReaderError.UserCanceled
        }
        let tag = TagReader(transport: transport)
        defer { tag.disconnect() }
        if viaReader {
            let reader = PassportReader()
            let events = LifecycleEvents()
            reader.configureAccessForTesting(mrzKey: "synthetic-access-credential", progress: { events.append($0) })
            let scan = try XCTUnwrap(reader.beginScanIfPossible())
            defer { reader.cancelRead() }
            do { try await reader.establishAccess(tagReader: tag, scanID: scan); XCTFail("Expected scripted stop") }
            catch NFCPassportReaderError.UserCanceled { } catch { XCTFail("Unexpected reader selection failure") }
            XCTAssertEqual(transport.commands.filter { $0 == 0x22 }.count, 1)
            XCTAssertEqual(transport.commands.last, 0x22)
            XCTAssertFalse(events.values.contains(.paceFailedFallbackToBAC))
            XCTAssertFalse(events.values.contains(.bacStarted))
        } else {
            let handler = try PACEHandler(cardAccess: access, tagReader: tag)
            do { try await handler.doPACE(mrzKey: "synthetic-access-credential"); XCTFail("Expected scripted stop") }
            catch NFCPassportReaderError.UserCanceled { } catch { XCTFail("Unexpected selection failure") }
            XCTAssertEqual(transport.commands, [0x22])
        }
        XCTAssertNil(tag.secureMessaging)
    }
}
