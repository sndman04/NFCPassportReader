import XCTest
@testable import NFCPassportReader

@MainActor
final class PACEExplicitParameterTests: XCTestCase {
    private let base = "0.4.0.127.0.7.2.2.4.2"
    func testSingleExplicitSetWithoutIdentifierAndStandardReference() throws {
        for algorithm in [try explicitAlgorithm(), wrapDO(b: 0x30, arr: oidToBytes(oid: "0.4.0.127.0.7.1.2", replaceTag: false) + [2, 1, 13])] {
            let access = try CardAccess(wrapDO(b: 0x31, arr: info(nil) + domain(algorithm, nil)))
            XCTAssertEqual(access.preferredPACEInfo?.effectiveStandardParameterId, 13)
            XCTAssertTrue(try XCTUnwrap(access.preferredPACEInfo).isImplementedForReading)
        }
    }
    func testUnsafeExplicitParametersNeverStartAPDUAndSafeAlternativeIsSelected() async throws {
        var algorithm = try explicitAlgorithm()
        algorithm[algorithm.count - 1] ^= 1 // Change the cofactor, keeping well-formed ASN.1.
        let unsafe = try CardAccess(wrapDO(b: 0x31, arr: info(32) + domain(algorithm, 32)))
        XCTAssertFalse(try XCTUnwrap(unsafe.preferredPACEInfo).isImplementedForReading)
        let transport = LifecycleTransport { _, _ in XCTFail("Unsafe parameters reached NFC"); return (Data(), 0x90, 0) }
        let tag = TagReader(transport: transport)
        let handler = try PACEHandler(cardAccess: unsafe, tagReader: tag)
        do { try await handler.doPACE(mrzKey: "synthetic-credential"); XCTFail("Expected untrusted parameters to fail") }
        catch { XCTAssertTrue(error is NFCPassportReaderError) }
        XCTAssertTrue(transport.commands.isEmpty)
        let safe = try CardAccess(wrapDO(b: 0x31, arr: info(32) + domain(algorithm, 32) + info(13)))
        XCTAssertEqual(safe.preferredPACEInfo?.parameterId, 13)
    }
    func testAmbiguousReservedNamedAndMalformedDomainParametersAreRejected() throws {
        let algorithm = try explicitAlgorithm()
        for invalid in [domain(algorithm, 13), domain(algorithm, 0), domain(algorithm, 31),
                        domain(algorithm, 32) + domain(wrapDO(b: 0x30, arr: oidToBytes(oid: "0.4.0.127.0.7.1.2", replaceTag: false) + [2, 1, 12]), 32),
                        domain(algorithm, nil) + domain(algorithm, 32),
                        domain(wrapDO(b: 0x30, arr: oidToBytes(oid: "1.2.840.10045.2.1", replaceTag: false) + oidToBytes(oid: "1.2.840.10045.3.1.7", replaceTag: false)), 32)] {
            XCTAssertThrowsError(try CardAccess(wrapDO(b: 0x31, arr: info(32) + invalid)))
        }
        for count in 0..<algorithm.count {
            // Appending the local identifier can complete a truncated inner INTEGER.
            // Such a syntactically valid splice must still never resolve secure parameters.
            if let access = try? CardAccess(wrapDO(b: 0x31, arr: info(32) + domain(Array(algorithm.prefix(count)), 32))) {
                XCTAssertFalse(try XCTUnwrap(access.preferredPACEInfo).isImplementedForReading)
            }
        }
    }
    func testIntegratedMappingExcludesP224AndProtocolParameterFamiliesMustAgree() {
        XCTAssertFalse(PACEInfo(oid: "0.4.0.127.0.7.2.2.4.4.2", version: 2, parameterId: 10).isImplementedForReading)
        XCTAssertFalse(PACEInfo(oid: base + ".2", version: 2, parameterId: 0).isImplementedForReading)
        XCTAssertFalse(PACEInfo(oid: "0.4.0.127.0.7.2.2.4.1.2", version: 2, parameterId: 13).isImplementedForReading)
    }
    private func info(_ id: UInt8?) -> [UInt8] {
        wrapDO(b: 0x30, arr: oidToBytes(oid: base + ".2", replaceTag: false) + [2, 1, 2] + (id.map { [2, 1, $0] } ?? []))
    }
    private func domain(_ algorithm: [UInt8], _ id: UInt8?) -> [UInt8] {
        wrapDO(b: 0x30, arr: oidToBytes(oid: base, replaceTag: false) + algorithm + (id.map { [2, 1, $0] } ?? []))
    }
    private func explicitAlgorithm() throws -> [UInt8] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "pace-explicit-parameters", withExtension: "json", subdirectory: "Fixtures"))
        let values = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
        return wrapDO(b: 0x30, arr: oidToBytes(oid: "1.2.840.10045.2.1", replaceTag: false) + hexRepToBin(try XCTUnwrap(values["13"])))
    }
}
