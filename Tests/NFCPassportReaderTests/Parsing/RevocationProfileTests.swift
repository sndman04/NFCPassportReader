import XCTest
@testable import NFCPassportReader

final class RevocationProfileTests: XCTestCase {
    struct Profile: Decodable { let data: String, reason: String }
    struct Corpus: Decodable { let passport: [String: String]; let profiles: [String: Profile]; let linkedMasterList: String; let unauthorizedMasterList: String }
    func testOfflineCRLsAreAuthenticatedCurrentAndBoundToActualSigner() throws {
        let fixtureURL = try XCTUnwrap(Bundle.module.url(forResource: "revocation-profiles", withExtension: "json", subdirectory: "Fixtures"))
        let corpus = try JSONDecoder().decode(Corpus.self, from: Data(contentsOf: fixtureURL))
        let root = try XCTUnwrap(Bundle.module.url(forResource: "revocation-profile-csca", withExtension: "pem", subdirectory: "Fixtures"))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: file) }
        for (name, profile) in corpus.profiles {
            try Data(hexRepToBin(profile.data)).write(to: file)
            for cms in [false, true] {
                let model = try makeModel(corpus.passport)
                model.verifyPassport(masterListURL: root, useCMSVerification: cms, revocationListURL: file)
                let passed = profile.reason == "passed"
                let revoked = profile.reason == "revoked"
                XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed, name)
                XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed, name)
                XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, passed ? .passed : .failed, name)
                XCTAssertEqual(model.revocationCheckPerformed, passed || revoked, name)
                let check = PassportCertificateRevocationCheck(passport: model)
                XCTAssertEqual(String(describing: check.reason), profile.reason, name)
                XCTAssertEqual(check.status, passed ? .notRevoked : (revoked ? .revoked : .failed), name)
                let policy = PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication, requiresRevocationCheck: true)
                if passed { XCTAssertNoThrow(try policy.validate(model), name) }
                else { XCTAssertThrowsError(try policy.validate(model), name) }
                let snapshot = model.makeDiagnosticSnapshot(attemptID: 1, outcome: passed ? .succeeded : .failed)
                XCTAssertEqual(snapshot.verification.revocation.status, passed ? .succeeded : .failed, name)
                model.removeSensitiveDataForPrivacy()
                XCTAssertFalse(model.revocationCheckPerformed)
                XCTAssertEqual(snapshot.verification.revocation.status, passed ? .succeeded : .failed, name)
                let text = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self)
                for secret in ["SYNTHETIC", "TEST00001", "BEGIN X509 CRL", profile.data, corpus.passport["sod"] ?? ""] {
                    XCTAssertFalse(text.contains(secret), name)
                }
            }
        }
        let linkedRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: linkedRoot) }
        try Data(corpus.linkedMasterList.utf8).write(to: linkedRoot)
        try Data(hexRepToBin(try XCTUnwrap(corpus.profiles["clear"]).data)).write(to: file)
        let linked = try makeModel(corpus.passport)
        linked.verifyPassport(masterListURL: linkedRoot, revocationListURL: file)
        XCTAssertEqual(linked.verificationResult.countrySigningCertificateStatus, .passed)
        XCTAssertEqual(linked.diagnosticEvidence.revocation.status, .succeeded)
        try Data(corpus.unauthorizedMasterList.utf8).write(to: linkedRoot)
        let unauthorized = try makeModel(corpus.passport)
        unauthorized.verifyPassport(masterListURL: linkedRoot, revocationListURL: file)
        XCTAssertEqual(unauthorized.diagnosticEvidence.revocation.reason, .revocationListInvalid)
        XCTAssertEqual(unauthorized.verificationResult.countrySigningCertificateStatus, .failed)
        let unconfigured = try makeModel(corpus.passport)
        unconfigured.verifyPassport(masterListURL: root)
        XCTAssertEqual(PassportCertificateRevocationCheck(passport: unconfigured).reason, .notConfigured)
        XCTAssertThrowsError(try PassportReaderSecurityPolicy(requiresRevocationCheck: true).validate(unconfigured))
        let missingRoot = try makeModel(corpus.passport)
        missingRoot.verifyPassport(masterListURL: nil, revocationListURL: file)
        XCTAssertEqual(missingRoot.diagnosticEvidence.revocation.reason, .missingMasterList)
        XCTAssertThrowsError(try PassportReaderSecurityPolicy(requiresRevocationCheck: true).validate(missingRoot))
        let missingList = try makeModel(corpus.passport)
        missingList.verifyPassport(masterListURL: root, revocationListURL: URL(fileURLWithPath: "/nonexistent-synthetic-crl"))
        XCTAssertEqual(missingList.diagnosticEvidence.revocation.reason, .revocationListUnavailable)
    }
    private func makeModel(_ fixture: [String: String]) throws -> NFCPassportModel {
        let model = NFCPassportModel()
        for (id, key) in [(DataGroupId.COM, "com"), (.DG1, "dg1"), (.DG11, "dg11"), (.SOD, "sod")] {
            let bytes = hexRepToBin(try XCTUnwrap(fixture[key]))
            model.addDataGroup(id, dataGroup: try DataGroupParser().parseDG(data: bytes))
        }
        return model
    }
}
