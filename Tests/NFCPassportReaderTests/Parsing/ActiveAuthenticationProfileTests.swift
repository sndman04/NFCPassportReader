import XCTest
import OpenSSL
@testable import NFCPassportReader

final class ActiveAuthenticationProfileTests: XCTestCase {
    struct Profile: Decodable {
        let dg14: String, dg15: String, challenge: String, signature: String
        let valid: Bool
    }
    func testAARejectsCompressedECPointAndTrailingSPKIBytes() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "active-authentication-profiles", withExtension: "json", subdirectory: "Fixtures"))
        let profiles = try JSONDecoder().decode([String: Profile].self, from: Data(contentsOf: url))
        let dg = try SimpleASN1Node.parse(hexRepToBin(try XCTUnwrap(profiles["ec_sha256"]).dg15))
        let spki = try SimpleASN1Node.parse(dg.value)
        let point = spki.children[1].value
        XCTAssertEqual(point.count, 66)
        let compressed = [UInt8(0), UInt8(2) | (point.last! & 1)] + Array(point[2..<34])
        let invalid = wrapDO(b: 0x30, arr: spki.children[0].encodedBytes + wrapDO(b: 0x03, arr: compressed))
        XCTAssertThrowsError(try DataGroup15(wrapDO(b: 0x6F, arr: invalid)))
        XCTAssertThrowsError(try DataGroup15(wrapDO(b: 0x6F, arr: dg.value + [0])))
        let binaryKey = try OpenSSLUtils.generateECKeyPair(curveNID: NID_sect233r1)
        defer { EVP_PKEY_free(binaryKey) }
        var binarySPKI = [UInt8](repeating: 0, count: Int(i2d_PUBKEY(binaryKey, nil)))
        _ = binarySPKI.withUnsafeMutableBufferPointer { buffer in
            var cursor = buffer.baseAddress
            return i2d_PUBKEY(binaryKey, &cursor)
        }
        XCTAssertThrowsError(try DataGroup15(wrapDO(b: 0x6F, arr: binarySPKI)))
    }

    func testIndependentRSARecoveryAndECDSAAlgorithmsRejectMalformedAndCorruptedResponses() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "active-authentication-profiles", withExtension: "json", subdirectory: "Fixtures"))
        let profiles = try JSONDecoder().decode([String: Profile].self, from: Data(contentsOf: url))
        XCTAssertEqual(profiles.count, 44)
        for (name, fixture) in profiles {
            let model = NFCPassportModel()
            model.addDataGroup(.DG15, dataGroup: try DataGroup15(hexRepToBin(fixture.dg15)))
            if !fixture.dg14.isEmpty { model.addDataGroup(.DG14, dataGroup: try DataGroup14(hexRepToBin(fixture.dg14))) }
            model.verifyActiveAuthentication(challenge: hexRepToBin(fixture.challenge), signature: hexRepToBin(fixture.signature))
            XCTAssertEqual(model.activeAuthenticationPassed, fixture.valid, name)
            let policy = PassportReaderSecurityPolicy(verificationRequirement: .activeAuthenticationWhenSupported)
            if fixture.valid { XCTAssertNoThrow(try policy.validate(model), name) }
            else { XCTAssertThrowsError(try policy.validate(model), name) }
            let snapshot = model.makeDiagnosticSnapshot(attemptID: 1, outcome: fixture.valid ? .succeeded : .failed)
            XCTAssertEqual(snapshot.verification.activeAuthentication.status == .succeeded, fixture.valid, name)
            model.removeSensitiveDataForPrivacy()
            XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
            XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
            let text = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self).uppercased()
            for secret in [fixture.challenge, fixture.signature, fixture.dg15] { XCTAssertFalse(text.contains(secret.uppercased()), name) }
        }
    }
}
