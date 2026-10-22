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

    private func check(parameters: [Int], isDH: Bool = false, includesReference: Bool) async throws {
        let primary = isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128
        let secondary = isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256
        let infos = parameters.enumerated().flatMap { index, parameter in
            wrapDO(b: 0x30, arr: oidToBytes(oid: index == 0 ? primary : secondary, replaceTag: false) + [2, 1, 2, 2, 1, UInt8(parameter)])
        }
        let access = try CardAccess(wrapDO(b: 0x31, arr: infos))
        let selected = try XCTUnwrap(access.preferredPACEInfo)
        let transport = LifecycleTransport { command, _ in
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
        let handler = try PACEHandler(cardAccess: access, tagReader: tag)
        do { try await handler.doPACE(mrzKey: "synthetic-access-credential"); XCTFail("Expected scripted stop") }
        catch NFCPassportReaderError.UserCanceled { } catch { XCTFail("Unexpected selection failure") }
        XCTAssertEqual(transport.commands, [0x22])
        XCTAssertNil(tag.secureMessaging)
        tag.disconnect()
    }
}
