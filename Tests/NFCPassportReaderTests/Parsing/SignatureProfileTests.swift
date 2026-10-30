import XCTest
@testable import NFCPassportReader

final class SignatureProfileTests: XCTestCase {
    struct Profile: Decodable {
        let com: String, dg1: String, dg11: String, sod: String, content: String
        let valid: Bool, trusted: Bool, cms: Bool
    }

    func testIndependentPSSAndSignerProfilesThroughBothVerifiersAndPolicies() throws {
        let profiles = try load()
        XCTAssertEqual(profiles.keys.filter { $0.hasPrefix("pss_sha") }.count, 100)
        for (name, fixture) in profiles.sorted(by: { $0.key < $1.key }) {
            let sod = try SOD(hexRepToBin(fixture.sod))
            let expected = Data(hexRepToBin(fixture.content))
            if fixture.valid {
                XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod) == expected, name)
            } else {
                XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod), name)
            }
            if fixture.cms {
                XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod) == expected, name)
            } else {
                XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod), name)
            }
            for preferCMS in [false, true] {
                let model = try makeModel(fixture)
                model.verifyPassport(masterListURL: try root(), useCMSVerification: preferCMS)
                XCTAssertEqual(model.verificationResult.sodSignatureStatus, fixture.valid ? .passed : .failed, name)
                XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed, name)
                if fixture.valid {
                    XCTAssertNoThrow(try PassportScanOptions.notaryStrict.securityPolicy.validate(model), name)
                } else {
                    XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model), name)
                }
                let trusted = PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication)
                if fixture.trusted { XCTAssertNoThrow(try trusted.validate(model), name) }
                else { XCTAssertThrowsError(try trusted.validate(model), name) }
                if name.contains("untrusted") {
                    XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .failed, name)
                }
                let snapshot = model.makeDiagnosticSnapshot(attemptID: 1, outcome: fixture.valid ? .succeeded : .failed)
                let encoder = JSONEncoder()
                encoder.outputFormatting = .sortedKeys
                let encoded = try encoder.encode(snapshot)
                model.removeSensitiveDataForPrivacy()
                XCTAssertTrue(model.dataGroupsRead.isEmpty)
                XCTAssertTrue(try encoder.encode(snapshot) == encoded)
                let text = String(decoding: encoded, as: UTF8.self).uppercased()
                for secret in [fixture.sod, fixture.dg1, fixture.content, "SYNTHETIC CMS", "BEGIN CERTIFICATE",
                               "KSENC", "KSMAC", "RND.IFD", "RND.ICC", "FFD8FFE0", "TEST00001"] {
                    XCTAssertFalse(text.contains(secret.uppercased()), name)
                }
            }
        }
    }

    func testCMSFirstFallbackForDifferentPSSContentDigestRecordsBothOutcomes() throws {
        let fixture = try XCTUnwrap(load()["pss_different_content_hash"])
        let model = try makeModel(fixture)
        model.verifyPassport(masterListURL: try root(), useCMSVerification: true)
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .succeeded)
        XCTAssertTrue(value.sod.fallbackAttempted)
        XCTAssertEqual(value.sod.cmsVerifier.status, .failed)
        XCTAssertEqual(value.sod.manualVerifier.status, .succeeded)
        XCTAssertEqual(value.sod.successfulVerifier, .manual)
        XCTAssertNoThrow(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
    }

    private func load() throws -> [String: Profile] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "signature-profiles", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode([String: Profile].self, from: Data(contentsOf: url))
    }
    private func root() throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: "signature-profile-csca", withExtension: "pem", subdirectory: "Fixtures"))
    }
    private func makeModel(_ fixture: Profile) throws -> NFCPassportModel {
        let model = NFCPassportModel()
        model.addDataGroup(.COM, dataGroup: try COM(hexRepToBin(fixture.com)))
        model.addDataGroup(.DG1, dataGroup: try DataGroup1(hexRepToBin(fixture.dg1)))
        model.addDataGroup(.DG11, dataGroup: try DataGroup11(hexRepToBin(fixture.dg11)))
        model.addDataGroup(.SOD, dataGroup: try SOD(hexRepToBin(fixture.sod)))
        return model
    }
}
