import XCTest
@testable import NFCPassportReader

final class PACEPasswordAndResponseTests: XCTestCase {
    func testNonMRZPasswordEncodingUsesUnhashedCharacterString() throws {
        // ICAO 9303-11 §9.7.3 Table 14 / BSI TR-03110-3 A.2.3 Table 5.
        // Expected digests independently calculated with Python hashlib.
        let v = try ICAOVector("password")
        for reference in [PassportPACEKeyReference.can, .pin, .puk] {
            for bits in [128, 192, 256] {
                let key = try PACEHandler.createPaceKey(from: "123456", keyReference: reference, cipherAlg: "AES", keyLength: bits)
                XCTAssertTrue(key == (try v.bytes(String(bits))), "Non-MRZ KDF mismatch; credential and key suppressed")
            }
        }
    }

    func testNonMRZPasswordRejectsCharactersOutsideSpecifiedEncoding() {
        XCTAssertThrowsError(try PACEHandler.createPaceKey(from: "\u{1F600}", keyReference: .can, cipherAlg: "AES", keyLength: 128))
    }

    func testNonMRZCredentialControlsFailWithRedactedDiagnostics() {
        for credential in ["123\u{00}456", "123\n456", "123\u{7F}456", "123\u{85}456"] {
            do {
                _ = try PACEHandler.createPaceKey(from: credential, keyReference: .pin, cipherAlg: "AES", keyLength: 128)
                XCTFail("Expected invalid encoding")
            } catch let error as NFCPassportReaderError {
                XCTAssertFalse(error.localizedDescription.contains(credential))
                XCTAssertFalse(error.localizedDescription.contains("123"))
                XCTAssertEqual(error.localizedDescription, "PACE authentication failed")
            } catch { XCTFail("Expected a typed privacy-safe failure") }
        }
    }

    func testPACEAcceptsBothOptionalAuthorityReferencesWithoutExposingThem() throws {
        let token = Array(repeating: UInt8(1), count: 8)
        let response = wrapDO(b: 0x87, arr: Array("TESTAUTHORITY01".utf8)) + wrapDO(b: 0x86, arr: token) + wrapDO(b: 0x88, arr: Array("TESTAUTHORITY00".utf8))
        let result = try PACEHandler.authenticationTokenAndCAMData(from: response)
        XCTAssertTrue(result.authenticationToken == token)
        XCTAssertNil(result.encryptedCAMData)
    }

    func testPACERejectsDuplicateEmptyOversizedAndOrphanAuthorityReferences() {
        let token = wrapDO(b: 0x86, arr: Array(repeating: 1, count: 8))
        let reference = wrapDO(b: 0x87, arr: Array("TESTAUTHORITY01".utf8))
        for suffix in [reference + reference, wrapDO(b: 0x87, arr: []), wrapDO(b: 0x87, arr: Array(repeating: 1, count: 17)), wrapDO(b: 0x88, arr: [1]), wrapDO(b: 0x87, arr: [0x7F])] {
            XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: token + suffix))
        }
    }
}
