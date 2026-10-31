import XCTest
import OpenSSL
import PassportTestSupport
import UIKit
@testable import NFCPassportReader

/// Opt-in pinned public corpora. Fetch with scripts/fetch_external_corpora.py.
/// Assertions report only public case IDs/outcomes, never buffers or certificate data.
final class ExternalCorpusTests: XCTestCase {
    struct SignatureCase: Decodable { let tcId: Int, msg: String, sig: String, result: String, flags: [String] }
    struct SignatureGroup: Decodable { let id: String, key: String, algorithm: String, digest: String; let tests: [SignatureCase] }
    struct AgreementCase: Decodable {
        let tcId: Int, `public`: String, `private`: String, ownPublic: String, shared: String, result: String, flags: [String]
    }
    struct AgreementGroup: Decodable { let id: String, curve: String; let tests: [AgreementCase] }
    struct MacCase: Decodable { let tcId: Int, key: String, msg: String, tag: String, result: String, flags: [String] }
    struct MacGroup: Decodable { let id: String; let tests: [MacCase] }
    struct TrustCase: Decodable {
        let id: String, expected: String, roots: [String], intermediates: [String], certificate: String, date: String?, crls: [String]
    }
    struct ImageCase: Decodable { let id: String, data: String }
    struct AgreementDifference: Decodable { let id: String, upstreamExpected: String, readerExpected: String }
    struct TrustDifference: Decodable { let id: String, upstreamExpected: String, reason: String; let readerAccepted: Bool }
    struct Mapping: Decodable { let agreementDifferences: [AgreementDifference], trustDifferences: [TrustDifference] }
    struct PublicKeyCase: Decodable { let id: String, `public`: String; let accepted: Bool }
    struct Regressions: Decodable { let publicKeys: [PublicKeyCase], trust: [TrustCase] }

    func testPermanentExternalPublicKeyRegressions() throws {
        let cases = try regressions().publicKeys
        XCTAssertEqual(cases.count, 9)
        for test in cases {
            let key = try? OpenSSLUtils.readPublicKey(data: hexRepToBin(test.public))
            defer { EVP_PKEY_free(key) }
            XCTAssertEqual(key != nil, test.accepted, test.id)
        }
    }

    func testPermanentExternalTrustAndCRLRegressions() throws {
        let cases = try regressions().trust
        XCTAssertEqual(cases.count, 22)
        try verifyTrust(cases)
    }

    func testTrustExceptionsDoNotBypassSignatureOrAnchorChecks() throws {
        let cases = try regressions().trust
        let boundary = try XCTUnwrap(cases.first { $0.id == "rfc5280::validity::notafter-exact" })
        let base64 = boundary.certificate.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
        var der = try XCTUnwrap(Data(base64Encoded: base64))
        der[der.count - 1] ^= 1 // Corrupt only the signature, at the allowed notAfter second.
        let corrupt = "-----BEGIN CERTIFICATE-----\n" + der.base64EncodedString(options: .lineLength64Characters)
            + "\n-----END CERTIFICATE-----\n"
        let badSignature = TrustCase(id: "boundary-with-corrupt-signature", expected: "FAILURE", roots: boundary.roots,
            intermediates: boundary.intermediates, certificate: corrupt, date: boundary.date, crls: [])
        let linked = try XCTUnwrap(cases.first { $0.id == "rfc5280::root-and-intermediate-swapped" })
        let unrelated = try XCTUnwrap(cases.first { $0.id == "crl::structure::crl-empty" })
        let untrustedOnly = TrustCase(id: "link-present-only-as-untrusted", expected: "FAILURE", roots: unrelated.roots,
            intermediates: linked.intermediates + linked.roots, certificate: linked.certificate, date: linked.date, crls: [])
        try verifyTrust([badSignature, untrustedOnly])
    }

    func testWycheproofSignaturesThroughProductionSODPrimitive() throws {
        let groups: [SignatureGroup] = try load("signatures")
        XCTAssertEqual(groups.reduce(0) { $0 + $1.tests.count }, 6_817)
        for group in groups {
            let key = try XCTUnwrap(OpenSSLUtils.readPublicKey(data: hexRepToBin(group.key)), group.id)
            defer { EVP_PKEY_free(key) }
            let algorithm = try SODSignatureAlgorithm(SimpleASN1Node.parse(hexRepToBin(group.algorithm)), contentDigest: group.digest)
            for test in group.tests {
                let accepted = OpenSSLUtils.verifySODSignature(data: Data(hexRepToBin(test.msg)),
                    signature: Data(hexRepToBin(test.sig)), publicKey: key, algorithm: algorithm)
                if test.result != "acceptable" {
                    XCTAssertEqual(accepted, test.result == "valid", "\(group.id)/\(test.tcId)")
                }
            }
        }
    }

    func testWycheproofECDHImportAndSharedSecrets() throws {
        let groups: [AgreementGroup] = try load("agreements")
        let mapping: Mapping = try load("profile-mapping")
        XCTAssertEqual(mapping.agreementDifferences.count, 3)
        var differences = 0
        XCTAssertEqual(groups.reduce(0) { $0 + $1.tests.count }, 2_575)
        for group in groups {
            let nid: Int32 = try XCTUnwrap(["secp256r1": NID_X9_62_prime256v1, "secp384r1": NID_secp384r1, "secp521r1": NID_secp521r1][group.curve])
            let parameters = try OpenSSLUtils.generateECKeyPair(curveNID: nid)
            defer { EVP_PKEY_free(parameters) }
            for test in group.tests {
                let name = "\(group.id)/\(test.tcId)"
                var scalar = hexRepToBin(test.private), ownPublic = hexRepToBin(test.ownPublic)
                let key = try XCTUnwrap(NFCPRTestImportKey(parameters, &scalar, scalar.count, &ownPublic, ownPublic.count, 0), name)
                defer { EVP_PKEY_free(key) }
                var actual: [UInt8]?
                if let peer = try? OpenSSLUtils.readPublicKey(data: hexRepToBin(test.public)) {
                    defer { EVP_PKEY_free(peer) }
                    actual = try? OpenSSLUtils.computeSharedSecret(privateKeyPair: key, publicKey: peer)
                }
                if let difference = mapping.agreementDifferences.first(where: { $0.id == name }) {
                    differences += 1
                    XCTAssertEqual(test.result, difference.upstreamExpected, name)
                    XCTAssertEqual(difference.readerExpected, "valid", name)
                    XCTAssertTrue(actual == hexRepToBin(test.shared), name)
                } else if test.result == "invalid" { XCTAssertTrue(actual == nil, name) }
                else if test.result == "valid" { XCTAssertTrue(actual == hexRepToBin(test.shared), name) }
                else if let actual { XCTAssertTrue(actual == hexRepToBin(test.shared), name) }
            }
        }
        XCTAssertEqual(differences, 3)
    }

    func testWycheproofCMAC() throws {
        let groups: [MacGroup] = try load("macs")
        XCTAssertEqual(groups.reduce(0) { $0 + $1.tests.count }, 311)
        for group in groups {
            for test in group.tests {
                let expected = hexRepToBin(test.tag)
                let actual = OpenSSLUtils.generateAESCMAC(key: hexRepToBin(test.key), message: hexRepToBin(test.msg))
                let matches = !expected.isEmpty && Array(actual.prefix(expected.count)) == expected
                XCTAssertEqual(matches, test.result == "valid", "\(group.id)/\(test.tcId)")
            }
        }
    }

    func testLimboCertificateAndCRLProfiles() throws {
        let cases: [TrustCase] = try load("trust")
        let mapping: Mapping = try load("profile-mapping")
        XCTAssertEqual(cases.count, 119)
        XCTAssertEqual(mapping.trustDifferences.count, 16)
        // Keep upstream verdicts intact. These explicit, documented differentials
        // are not counted as generic X.509 conformance passes.
        let applicable = cases.filter { test in !mapping.trustDifferences.contains { $0.id == test.id } }
        XCTAssertEqual(applicable.count, 103)
        try verifyTrust(applicable)
    }

    func testLimboDocumentedProfileDifferences() throws {
        let cases: [TrustCase] = try load("trust")
        let mapping: Mapping = try load("profile-mapping")
        let differences = cases.filter { test in mapping.trustDifferences.contains { $0.id == test.id } }
        XCTAssertEqual(differences.count, 16)
        try verifyTrust(differences, differences: mapping.trustDifferences)
    }

    private func verifyTrust(_ cases: [TrustCase], differences: [TrustDifference] = []) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("synthetic-roots.pem")
        for test in cases {
            try Data(test.roots.joined(separator: "\n").utf8).write(to: root)
            guard let certificate = certificate(test.certificate) else {
                XCTAssertEqual(test.expected, "FAILURE", test.id)
                continue
            }
            let intermediates = test.intermediates.compactMap { self.certificate($0) }
            XCTAssertEqual(intermediates.count, test.intermediates.count, test.id)
            let fractional = ISO8601DateFormatter()
            fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let date = test.date.flatMap { fractional.date(from: $0) ?? ISO8601DateFormatter().date(from: $0) }
            if test.date != nil { XCTAssertNotNil(date, test.id) }
            var validationCode: Int?
            var diagnostics: [PassportDiagnosticFailure] = []
            let result = OpenSSLUtils.verifyTrustAndGetIssuerCertificate(x509: certificate, CAFile: root,
                untrustedCertificates: intermediates, verificationDate: date) {
                    validationCode = $0.certificateValidationCode
                    diagnostics.append($0)
                }
            var accepted = false
            var revocationFailure: PassportDiagnosticFailure?
            if case .success(let issuer) = result {
                accepted = true
                if !test.crls.isEmpty {
                    let check = CertificateRevocation.check(Data(test.crls.joined(separator: "\n").utf8),
                        signer: certificate, issuer: issuer)
                    accepted = check.status == .succeeded
                    revocationFailure = check.failure
                    if let failure = check.failure { diagnostics.append(failure) }
                }
            }
            if test.id == "crl::structure::crl-duplicate-revoked-serial" {
                XCTAssertEqual(revocationFailure?.reason, .revocationListInvalid, test.id)
            }
            if let difference = differences.first(where: { $0.id == test.id }) {
                XCTAssertEqual(test.expected, difference.upstreamExpected, test.id)
                XCTAssertEqual(accepted, difference.readerAccepted, "\(test.id): \(difference.reason)")
            } else {
                XCTAssertEqual(accepted, test.expected == "SUCCESS", "\(test.id) (validation code \(validationCode ?? 0))")
            }
            let diagnosticText = String(decoding: try JSONEncoder().encode(diagnostics), as: UTF8.self)
            for marker in ["BEGIN CERTIFICATE", "BEGIN X509 CRL", "example.com", test.certificate] {
                XCTAssertFalse(diagnosticText.contains(marker), test.id)
            }
        }
    }

    @MainActor
    func testOpenJPEGSmallMalformedHeaderCorpusThroughDG2() throws {
        let cases: [ImageCase] = try load("images")
        XCTAssertEqual(cases.count, 10)
        var parsed = 0, returnedImages = 0
        for test in cases {
            autoreleasepool {
                let data = hexRepToBin(test.data)
                XCTAssertLessThan(data.count, 1024, test.id) // Header-only inputs, not photographs.
                // Wrap unchanged external bytes in a synthetic ICAO 39794-5 BIT.
                let information = wrapDO(b: 0xA0, arr: [0x80, 1, 3]) + wrapDO(b: 0xA1, arr: wrapDO(b: 0xA1, arr: [0x80, 1, 0]))
                let block = wrapDO(b: 0xA0, arr: wrapDO(b: 0xA0, arr: wrapDO(b: 0x80, arr: data) + wrapDO(b: 0xA1, arr: information)))
                let version = wrapDO(b: 0xA0, arr: [0x80, 1, 3, 0x81, 2, 7, 0xE3])
                let face = wrapDO(b: 0xA1, arr: wrapDO(b: 0x65, arr: version + wrapDO(b: 0xA1, arr: wrapDO(b: 0x30, arr: [0x80, 1, 0] + wrapDO(b: 0xA1, arr: block)))))
                func tlv(_ tag: [UInt8], _ value: [UInt8]) -> [UInt8] {
                    tag + wrapDO(b: 0, arr: value).dropFirst()
                }
                let template = tlv([0x7F, 0x60], [0xA1, 0] + tlv([0x7F, 0x2E], face))
                let wire = wrapDO(b: 0x75, arr: tlv([0x7F, 0x61], [2, 1, 1] + template))
                if let group = try? DataGroup2(wire) {
                    parsed += 1
                    if let image = group.getImage() {
                        returnedImages += 1
                        XCTAssertLessThanOrEqual(image.size.width * image.size.height, 16_000_000, test.id)
                        // Render a small thumbnail only after checking the claimed pixel budget.
                        if image.size.width * image.size.height <= 16_000_000 {
                            _ = UIGraphicsImageRenderer(size: CGSize(width: 32, height: 32)).image { _ in
                                image.draw(in: CGRect(x: 0, y: 0, width: 32, height: 32))
                            }
                        }
                    }
                    group.removeSensitiveDataForPrivacy()
                    XCTAssertTrue(group.imageData.isEmpty, test.id)
                }
            }
        }
        print("External image corpus: \(cases.count) headers, \(parsed) parsed DG2, \(returnedImages) returned UIImage objects")
    }

    private func certificate(_ pem: String) -> X509Wrapper? {
        guard let bio = BIO_new(BIO_s_mem()) else { return nil }
        defer { BIO_free(bio) }
        let data = Data(pem.utf8)
        guard data.withUnsafeBytes({ BIO_write(bio, $0.baseAddress, Int32(data.count)) }) == data.count,
              let value = PEM_read_bio_X509(bio, nil, nil, nil) else { return nil }
        defer { X509_free(value) }
        return X509Wrapper(with: value)
    }
    private func load<T: Decodable>(_ name: String) throws -> T {
        guard let url = Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures/ExternalCorpora") else {
            throw XCTSkip("Fetch the optional pinned public corpus with scripts/fetch_external_corpora.py")
        }
        return try JSONDecoder().decode(T.self, from: Data(contentsOf: url))
    }

    private func regressions() throws -> Regressions {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "external-regressions", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(Regressions.self, from: Data(contentsOf: url))
    }
}
