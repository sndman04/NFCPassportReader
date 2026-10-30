import XCTest
@testable import NFCPassportReader

@MainActor
final class ISO39794FaceTests: XCTestCase {
    struct Profile: Decodable {
        let com: String, dg1: String, dg2: String, sod: String
        let valid: Bool
        let images: Int
    }
    func testIndependentFaceProfilesThroughReaderVerificationResultAndScrubbing() async throws {
        for (name, fixture) in try load().sorted(by: { $0.key < $1.key }) {
            let wire = hexRepToBin(fixture.dg2)
            for preferCMS in [false, true] {
                let model = NFCPassportModel()
                let transport = LifecycleTransport { command, _ in
                    if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
                    let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
                    return (Data(wire.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
                }
                let tag = TagReader(transport: transport)
                let reader = PassportReader()
                reader.configureLifecycleForTesting(passport: model, tagReader: tag, groups: [.DG2])
                let scan = try XCTUnwrap(reader.beginScanIfPossible())
                if !fixture.valid {
                    do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG2, scanID: scan); XCTFail(name) }
                    catch let error as NFCPassportReaderError { reader.failActiveScan(error: error, scanID: scan) }
                    let snapshot = try XCTUnwrap(reader.lastDiagnosticSnapshot)
                    XCTAssertTrue(snapshot.failures.contains { $0.operation == .parseDataGroup }, name)
                    XCTAssertTrue(model.dataGroupsRead.isEmpty)
                    try assertRedacted(snapshot, wire: wire)
                    continue
                }
                let group = try await reader.readDataGroup(tagReader: tag, dgId: .DG2, scanID: scan)
                let parsed = try XCTUnwrap(group as? DataGroup2)
                XCTAssertEqual(parsed.imageDataItems.count, fixture.images, name)
                XCTAssertNotNil(parsed.getImage(), name)
                model.addDataGroup(.DG2, dataGroup: parsed)
                model.addDataGroup(.COM, dataGroup: try COM(hexRepToBin(fixture.com)))
                model.addDataGroup(.DG1, dataGroup: try DataGroup1(hexRepToBin(fixture.dg1)))
                model.addDataGroup(.SOD, dataGroup: try SOD(hexRepToBin(fixture.sod)))
                model.verifyPassport(masterListURL: try root(), useCMSVerification: preferCMS)
                XCTAssertNoThrow(try PassportScanOptions.notaryStrict.securityPolicy.validate(model), name)
                XCTAssertNoThrow(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model), name)
                XCTAssertEqual(model.verificationResult.dataGroupHashStatus, .passed)
                reader.completeActiveScan(returning: model, scanID: scan)
                let result = PassportChipReadResult(passport: model, photoPolicy: .read)
                XCTAssertNotNil(result.faceImageData, name)
                XCTAssertTrue(result.identity.hasFaceImage, name)
                let snapshot = try XCTUnwrap(reader.lastDiagnosticSnapshot)
                XCTAssertEqual(snapshot.dataGroups.first { $0.dataGroup == .DG2 }?.comparison.status, .succeeded)
                model.removeSensitiveDataForPrivacy()
                XCTAssertTrue(parsed.imageData.isEmpty)
                XCTAssertTrue(parsed.imageDataItems.isEmpty)
                XCTAssertTrue(parsed.body.isEmpty)
                try assertRedacted(snapshot, wire: wire)
            }
        }
    }
    func testEveryTruncatedPrefixAndIncorrectContainerLengthIsRejected() throws {
        let fixture = try XCTUnwrap(load()["jpeg"])
        let wire = hexRepToBin(fixture.dg2)
        for count in 0..<wire.count {
            XCTAssertThrowsError(try DataGroupParser().parseDG(data: Array(wire.prefix(count))))
        }
        let root = try SimpleASN1Node.parse(wire)
        let templateGroup = root.children[0]
        var shortened = wire
        let lengthOffset = templateGroup.offset + 2
        XCTAssertEqual(shortened[lengthOffset] & 0x80, 0x80)
        shortened[lengthOffset + Int(shortened[lengthOffset] & 0x7F)] &-= 1
        XCTAssertThrowsError(try DataGroupParser().parseDG(data: shortened))
    }
    private func assertRedacted(_ snapshot: PassportDiagnosticSnapshot, wire: [UInt8]) throws {
        let text = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self)
        XCTAssertFalse(text.contains(binToHexRep(wire)))
        XCTAssertFalse(text.contains(Data(wire).base64EncodedString()))
        XCTAssertFalse(text.contains("SYNTHETIC"))
        XCTAssertNil(text.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
    }
    private func load() throws -> [String: Profile] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "face-profiles", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode([String: Profile].self, from: Data(contentsOf: url))
    }
    private func root() throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: "face-profile-csca", withExtension: "pem", subdirectory: "Fixtures"))
    }
}
