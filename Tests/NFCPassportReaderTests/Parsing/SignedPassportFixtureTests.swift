import XCTest
@testable import NFCPassportReader

final class SignedPassportFixtureTests: XCTestCase {
    private let validProfiles = ["rsa_sha256", "ec_sha384", "rsa_pss_sha256", "rsa_sha512_dg"]

    func testIndependentSignedProfilesPassBothSignatureImplementations() throws {
        for profile in validProfiles {
            let fixture = try load(profile)
            let sod = try SOD(bytes(fixture, "sod"))
            let expected = Data(try bytes(fixture, "content"))
            XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod) == expected, "Manual SOD verification failed for synthetic profile")
            XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod) == expected, "CMS verification failed for synthetic profile")
        }
    }

    func testIndependentSignedProfilesPassTrustedPassiveAuthentication() throws {
        for profile in validProfiles {
            let model = try makeModel(load(profile))
            defer { model.removeSensitiveDataForPrivacy() }
            model.verifyPassport(masterListURL: try root())
            let result = model.verificationResult
            XCTAssertEqual(result.sodSignatureStatus, .passed)
            XCTAssertEqual(result.dataGroupHashStatus, .passed)
            XCTAssertEqual(result.documentSignerCertificateStatus, .passed)
            XCTAssertEqual(result.countrySigningCertificateStatus, .passed)
            XCTAssertNoThrow(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model))
        }
    }

    func testAuthenticDocumentWithoutTrustStoreCannotClaimTrustedVerification() throws {
        let model = try makeModel(load(validProfiles[0]))
        model.verifyPassport(masterListURL: nil)
        XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed)
        XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .notChecked)
        XCTAssertNoThrow(try PassportReaderSecurityPolicy.notaryRecommended.validate(model))
        XCTAssertThrowsError(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model))
    }

    func testUnrelatedRootRejectsTrustWhilePreservingSignatureAndHashResults() throws {
        let model = try makeModel(load(validProfiles[0]))
        model.verifyPassport(masterListURL: try root("unrelated-csca"))
        XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed)
        XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .failed)
        XCTAssertThrowsError(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model))
    }

    func testExpiredSignerCannotPassTrustedAuthentication() throws {
        let model = try makeModel(load("expired_signer"))
        model.verifyPassport(masterListURL: try root())
        XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .failed)
        XCTAssertThrowsError(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model))
    }

    func testTamperedDataGroupFailsHashCheckWithAuthenticSignature() throws {
        var fixture = try load(validProfiles[0])
        var group = try bytes(fixture, "dg11")
        group[group.count - 1] ^= 1
        fixture["dg11"] = binToHexRep(group)
        let model = try makeModel(fixture)
        model.verifyPassport(masterListURL: try root())
        XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed)
        XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .failed)
        XCTAssertThrowsError(try PassportReaderSecurityPolicy.notaryRecommended.validate(model))
    }

    func testTamperedSignatureFailsBothVerifiersAndPolicyEvenWhenHashesMatch() throws {
        for profile in validProfiles {
            var fixture = try load(profile)
            var wire = try bytes(fixture, "sod")
            wire[wire.count - 1] ^= 1
            fixture["sod"] = binToHexRep(wire)
            let sod = try SOD(wire)
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod))
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod))
            let model = try makeModel(fixture)
            model.verifyPassport(masterListURL: try root())
            XCTAssertEqual(model.verificationResult.sodSignatureStatus, .failed)
            XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed)
            XCTAssertThrowsError(try PassportReaderSecurityPolicy.notaryRecommended.validate(model))
        }
    }

    func testTamperedSignedContentFailsBothVerifiers() throws {
        let fixture = try load(validProfiles[0])
        var wire = try bytes(fixture, "sod")
        let content = try bytes(fixture, "content")
        let index = try XCTUnwrap(wire.indices.first { i in i + content.count <= wire.count && Array(wire[i..<i + content.count]) == content })
        wire[index + content.count - 1] ^= 1
        let sod = try SOD(wire)
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod))
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod))
    }

    func testTruncatedSignedCorpusFailsWithoutReturningTrustedContent() throws {
        for profile in validProfiles {
            let fixture = try load(profile)
            let wire = try bytes(fixture, "sod")
            for length in [0, 1, 2, 4, wire.count / 2, wire.count - 1] {
                XCTAssertThrowsError(try SOD(Array(wire.prefix(length))))
            }
        }
    }

    private func root(_ name: String = "synthetic-csca") throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
    }
    private func load(_ name: String) throws -> [String: String] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "signed-passports", withExtension: "json", subdirectory: "Fixtures"))
        let all = try JSONDecoder().decode([String: [String: String]].self, from: Data(contentsOf: url))
        return try XCTUnwrap(all[name])
    }
    private func bytes(_ fixture: [String: String], _ name: String) throws -> [UInt8] {
        hexRepToBin(try XCTUnwrap(fixture[name]))
    }
    private func makeModel(_ fixture: [String: String]) throws -> NFCPassportModel {
        let model = NFCPassportModel()
        for (id, name) in [(DataGroupId.COM, "com"), (.DG1, "dg1"), (.DG11, "dg11"), (.SOD, "sod")] {
            model.addDataGroup(id, dataGroup: try DataGroupParser().parseDG(data: bytes(fixture, name)))
        }
        return model
    }
}
