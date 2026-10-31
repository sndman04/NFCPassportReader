import XCTest
import Darwin
@testable import NFCPassportReader

final class EdgeCaseAuditTests: XCTestCase {
    struct CRLProfile: Decodable { let data: String, reason: String }
    struct CardProfile: Decodable { let data: String; let valid: Bool }
    struct Corpus: Decodable {
        let passport: [String: String], hiddenAuth: [String: String], aaOnly: [String: String], root: String
        let crls: [String: CRLProfile], cardSecurity: [String: CardProfile]
    }

    func testIdentifiersDoNotNormalizeMalformedEncodingsIntoKnownAlgorithms() throws {
        let encoded = oidToBytes(oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, replaceTag: false)
        let value = try SimpleASN1Node.parse(encoded).value
        for malformed in [[0x80] + value, value + [0x80], value + [0x80, 0x80]] {
            let oid = wrapDO(b: 6, arr: malformed)
            XCTAssertNil(try SimpleASN1Node.parse(oid).objectIdentifier)
            let info = wrapDO(b: 0x30, arr: oid + [2, 1, 2, 2, 1, 13])
            XCTAssertThrowsError(try CardAccess(wrapDO(b: 0x31, arr: info)))
        }
        XCTAssertNil(try SimpleASN1Node.parse([2, 2, 0, 1]).integerValue)
        XCTAssertEqual(try SimpleASN1Node.parse([2, 2, 0, 0x80]).integerValue, 128)
        XCTAssertEqual(try SimpleASN1Node.parse([6, 3, 0x88, 0x37, 3]).objectIdentifier, "2.999.3")
        XCTAssertThrowsError(try SimpleASN1Node.parse([0x7F, 0x80, 0x61, 0]))
        XCTAssertEqual(try SimpleASN1Node.parse([0x5F, 1, 0]).tag, 0x5F01) // ICAO BER-TLV tag retained.
    }

    func testCRLConflictAndInvalidReplacementCannotDisappearWithBundleOrdering() throws {
        let corpus = try load()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("root.pem"), crl = directory.appendingPathComponent("crls.pem")
        try Data(corpus.root.utf8).write(to: root)
        for (name, profile) in corpus.crls.sorted(by: { $0.key < $1.key }) {
            try Data(hexRepToBin(profile.data)).write(to: crl)
            for preferCMS in [false, true] {
                let model = try model(corpus.passport)
                model.verifyPassport(masterListURL: root, useCMSVerification: preferCMS, revocationListURL: crl)
                let check = PassportCertificateRevocationCheck(passport: model)
                XCTAssertEqual(String(describing: check.reason), profile.reason, name)
                XCTAssertEqual(model.verificationResult.sodSignatureStatus, .passed, name)
                XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed, name)
                let policy = PassportReaderSecurityPolicy(requiresRevocationCheck: true)
                if profile.reason == "passed" { XCTAssertNoThrow(try policy.validate(model), name) }
                else { XCTAssertThrowsError(try policy.validate(model), name) }
                let snapshot = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
                model.removeSensitiveDataForPrivacy()
                let text = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self)
                for sentinel in ["SYNTHETIC", "BEGIN X509 CRL", "TEST00001", profile.data] {
                    XCTAssertFalse(text.contains(sentinel), name)
                }
            }
        }
    }

    func testSignedCardSecurityRequiresItsOwnContentType() throws {
        let corpus = try load()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data(corpus.root.utf8).write(to: root)
        defer { try? FileManager.default.removeItem(at: root) }
        for (name, profile) in corpus.cardSecurity {
            let bytes = hexRepToBin(profile.data)
            // All examples have a valid independent CMS signature, even wrong content types.
            XCTAssertNoThrow(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(bytes), trustedCertificatesURL: root), name)
            if profile.valid {
                let card = try CardSecurity(bytes)
                try card.verifySignature(trustedCertificatesURL: root)
                XCTAssertTrue(card.signatureVerified)
                XCTAssertTrue(card.signerTrusted)
                card.removeSensitiveDataForPrivacy()
                XCTAssertTrue(card.securityInfos.isEmpty)
            } else { XCTAssertThrowsError(try CardSecurity(bytes), name) }
        }
    }

    func testNestedASN1PayloadDoesNotMultiplyRetainedMemoryByDepth() throws {
        var bytes = wrapDO(b: 4, arr: [UInt8](repeating: 0xA5, count: 2 * 1024 * 1024))
        for _ in 0..<60 { bytes = wrapDO(b: 0x30, arr: bytes) }
        let before = try residentBytes()
        let tree = try SimpleASN1Node.parse(bytes)
        try withExtendedLifetime(tree) {
            let after = try residentBytes()
            // Generous process-memory allowance for allocator/toolchain variation;
            // a 2 MiB input must not retain hundreds of MiB of duplicated ancestors.
            XCTAssertLessThan(after, before + 96 * 1024 * 1024)
            var leaf = tree
            for _ in 0..<60 { leaf = try XCTUnwrap(leaf.children.first) }
            XCTAssertEqual(leaf.value.count, 2 * 1024 * 1024)
        }
    }

    func testSignedAuthenticationGroupsCannotBeHiddenByUnsignedCOM() throws {
        let corpus = try load()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data(corpus.root.utf8).write(to: root)
        defer { try? FileManager.default.removeItem(at: root) }
        let required = PassportReaderSecurityPolicy(verificationRequirement: .fullVerificationWhenSupported)
        for preferCMS in [false, true] {
            let absent = try model(corpus.passport)
            absent.verifyPassport(masterListURL: root, useCMSVerification: preferCMS)
            XCTAssertNoThrow(try required.validate(absent)) // Signed inventory really lacks AA/CA groups.
            let hidden = try model(corpus.hiddenAuth)
            hidden.verifyPassport(masterListURL: root, useCMSVerification: preferCMS)
            XCTAssertTrue(PassportVerificationRequirement.trustedPassiveAuthentication.isSatisfied(by: hidden))
            XCTAssertThrowsError(try required.validate(hidden))
            XCTAssertEqual(hidden.verificationResult.activeAuthenticationDetail.reason, .skipped)
            XCTAssertEqual(hidden.verificationResult.chipAuthenticationDetail.reason, .skipped)
            let snapshot = hidden.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
            XCTAssertEqual(snapshot.verification.activeAuthentication.reason, .missingDataGroup)
            XCTAssertEqual(snapshot.verification.chipAuthentication.reason, .missingDataGroup)
            hidden.removeSensitiveDataForPrivacy()
            XCTAssertEqual(snapshot.verification.activeAuthentication.status, .unavailable)
        }
        for requirement in [PassportVerificationRequirement.chipAuthenticationWhenSupported, .activeAuthenticationWhenSupported] {
            XCTAssertFalse(requirement.isSatisfied(by: NFCPassportModel())) // Unknown availability is not success.
        }
    }

    func testNativeCMSRejectsTrailingContent() throws {
        let corpus = try load()
        let bytes = hexRepToBin(try XCTUnwrap(corpus.cardSecurity["security_object"]).data)
        for suffix: [UInt8] in [[0], [5, 0], bytes] {
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(bytes + suffix), trustedCertificatesURL: nil))
        }
    }

    func testCardSecurityCAMOutcomeDoesNotDependOnDG14Presence() throws {
        let corpus = try load()
        let model = try model(corpus.passport) // No DG14; CAM can use trusted MF CardSecurity.
        model.chipAuthenticationStatus = .failed
        XCTAssertEqual(model.verificationResult.chipAuthenticationDetail.reason, .attemptedFailed)
        XCTAssertFalse(PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: model))
        model.chipAuthenticationStatus = .success
        XCTAssertEqual(model.verificationResult.chipAuthenticationStatus, .passed)
        XCTAssertTrue(PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: model))
        model.removeSensitiveDataForPrivacy()
        XCTAssertFalse(PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: model))
    }

    @MainActor
    func testAggregatePolicyFailureNamesUnsatisfiedAuthenticationCheck() throws {
        let corpus = try load()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try Data(corpus.root.utf8).write(to: root)
        defer { try? FileManager.default.removeItem(at: root) }
        for preferCMS in [false, true] {
            let passport = try model(corpus.aaOnly)
            passport.addDataGroup(.DG15, dataGroup: try DataGroup15(hexRepToBin(try XCTUnwrap(corpus.aaOnly["dg15"]))))
            passport.verifyPassport(masterListURL: root, useCMSVerification: preferCMS)
            XCTAssertTrue(PassportVerificationRequirement.trustedPassiveAuthentication.isSatisfied(by: passport))
            XCTAssertEqual(passport.verificationResult.chipAuthenticationDetail.reason, .notSupported)
            XCTAssertEqual(passport.verificationResult.activeAuthenticationDetail.reason, .skipped)
            let reader = PassportReader()
            reader.configureLifecycleForTesting(passport: passport,
                securityPolicy: .init(verificationRequirement: .fullVerificationWhenSupported))
            let id = try XCTUnwrap(reader.beginScanIfPossible())
            reader.failActiveScan(error: .SecurityPolicyViolation, scanID: id)
            XCTAssertEqual(reader.privacySafeFailure(for: .SecurityPolicyViolation).verificationReason, .skipped)
            XCTAssertTrue(passport.dataGroupsRead.isEmpty)
        }
    }

    func testEveryCardSecurityTruncationAndDeterministicMutationsStayBounded() throws {
        let corpus = try load()
        let bytes = hexRepToBin(try XCTUnwrap(corpus.cardSecurity["security_object"]).data)
        for length in 0..<bytes.count {
            let truncated = Array(bytes.prefix(length))
            XCTAssertThrowsError(try SimpleASN1Node.parse(truncated), "Truncation length \(length)")
            XCTAssertThrowsError(try CardSecurity(truncated), "Truncation length \(length)")
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(truncated), trustedCertificatesURL: nil), "Truncation length \(length)")
        }
        var state: UInt64 = 0x534F445631
        func next() -> UInt64 { state = state &* 6364136223846793005 &+ 1; return state }
        for index in 0..<2_048 {
            autoreleasepool {
                var mutation: [UInt8]
                if index % 2 == 0 {
                    mutation = bytes
                    let offset = Int(next() % UInt64(mutation.count))
                    mutation[offset] ^= UInt8(1 << (next() % 8))
                } else {
                    mutation = (0..<Int(next() % 512)).map { _ in UInt8(truncatingIfNeeded: next() >> 32) }
                }
                // Mutations may still be legal. This is bounded crash/ownership coverage,
                // complementary to explicit acceptance/rejection oracles above.
                _ = try? SimpleASN1Node.parse(mutation)
                if let card = try? CardSecurity(mutation) {
                    try? card.verifySignature(trustedCertificatesURL: nil)
                    card.removeSensitiveDataForPrivacy()
                    XCTAssertTrue(card.securityInfos.isEmpty)
                }
                _ = try? OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(mutation), trustedCertificatesURL: nil)
            }
        }
    }

    func testRepeatedVerificationAndMutationDoNotRetainEarlierTrustOrRevocationSuccess() throws {
        let corpus = try load()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("root.pem"), crl = directory.appendingPathComponent("crls.pem")
        try Data(corpus.root.utf8).write(to: root)
        let model = try model(corpus.passport)
        let required = PassportReaderSecurityPolicy(requiresRevocationCheck: true)
        for preferCMS in [false, true] {
            try Data(hexRepToBin(try XCTUnwrap(corpus.crls["clear"]).data)).write(to: crl)
            model.verifyPassport(masterListURL: root, useCMSVerification: preferCMS, revocationListURL: crl)
            XCTAssertNoThrow(try required.validate(model))
            let passed = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .succeeded)
            try Data(hexRepToBin(try XCTUnwrap(corpus.crls["ordinary_reason"]).data)).write(to: crl)
            model.verifyPassport(masterListURL: root, useCMSVerification: preferCMS, revocationListURL: crl)
            XCTAssertThrowsError(try required.validate(model))
            XCTAssertEqual(model.diagnosticEvidence.revocation.reason, .certificateRevoked)
            XCTAssertEqual(passed.verification.revocation.status, .succeeded)
            model.verifyPassport(masterListURL: nil, useCMSVerification: preferCMS)
            XCTAssertThrowsError(try required.validate(model))
            XCTAssertEqual(model.diagnosticEvidence.trust.reason, .missingMasterList)
            XCTAssertEqual(PassportCertificateRevocationCheck(passport: model).reason, .notConfigured)
            model.addDataGroup(.DG11, dataGroup: try DataGroup11(hexRepToBin(try XCTUnwrap(corpus.passport["dg11"]))))
            XCTAssertFalse(model.passportVerificationAttempted)
            XCTAssertFalse(model.revocationCheckPerformed)
            XCTAssertEqual(model.diagnosticEvidence.revocation.status, .notAttempted)
        }
    }

    private func residentBytes() throws -> UInt64 {
        var info = mach_task_basic_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info_data_t>.size / MemoryLayout<integer_t>.size)
        let capacity = Int(count)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: capacity) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        guard result == KERN_SUCCESS else { throw NSError(domain: "SyntheticMemoryMetric", code: Int(result)) }
        return info.resident_size
    }

    private func load() throws -> Corpus {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "edge-case-profiles", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Corpus.self, from: Data(contentsOf: url))
    }
    private func model(_ fixture: [String: String]) throws -> NFCPassportModel {
        let result = NFCPassportModel()
        for (id, name) in [(DataGroupId.COM, "com"), (.DG1, "dg1"), (.DG11, "dg11"), (.SOD, "sod")] {
            result.addDataGroup(id, dataGroup: try DataGroupParser().parseDG(data: hexRepToBin(try XCTUnwrap(fixture[name]))))
        }
        return result
    }
}
