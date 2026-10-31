import XCTest
@testable import NFCPassportReader

/// Third-party synthetic documents retain their original signed bytes. A valid
/// signature is not an oracle for biometric structure, completeness or issuer trust.
@MainActor
final class ExternalPassportTests: XCTestCase {
    struct Specimen: Decodable { let format: String, lds: [String: String] }
    struct Generated: Decodable { let files: [String: String] }

    func testSignedSpecimenPassesBothVerifiersAndAllFourRawHashes() throws {
        let files = try specimen()
        let sod = try SOD(try bytes(files, "sod"))
        let content = try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
        XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod) == content)
        XCTAssertEqual(try hashMismatches(files, content: content), [])
        XCTAssertEqual(files.count, 5)
        // Hashing opaque bytes above does not bypass the typed parser: both of
        // these signed groups are malformed and must fail the document read.
        XCTAssertThrowsError(try DataGroupParser().parseDG(data: bytes(files, "dg2")))
        XCTAssertThrowsError(try DataGroupParser().parseDG(data: bytes(files, "dg14")))
    }

    func testSignedSpecimenThroughFileReadsAndFailureScrubbing() async throws {
        try await exerciseFileReads(try specimen(), rejected: [.DG2, .DG14])
    }

    func testSignedSpecimenMissingTrustAndTamperingStayRejected() throws {
        let files = try specimen()
        for preferCMS in [false, true] {
            let partial = try partialModel(files)
            partial.verifyPassport(masterListURL: nil, useCMSVerification: preferCMS)
            XCTAssertEqual(partial.verificationResult.sodSignatureStatus, .passed)
            XCTAssertThrowsError(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(partial))
            // A partial component probe is never treated as a complete accepted passport.
            XCTAssertTrue(partial.dataGroupsRead[.DG2] == nil)
            let snapshot = partial.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
            XCTAssertEqual(snapshot.sod.version, .v0)
            XCTAssertEqual(snapshot.sod.preferredVerifier, preferCMS ? .cms : .manual)
            XCTAssertEqual(snapshot.verification.sodSignature.status, .succeeded)
            XCTAssertEqual(snapshot.verification.countrySignerTrust.reason, .missingMasterList)
            XCTAssertEqual(snapshot.dataGroups.first { $0.dataGroup == .DG2 }?.comparison.reason, .missingDataGroup)
            partial.removeSensitiveDataForPrivacy()
            try assertRedacted(snapshot, files: files)

            var corrupt = files
            var signature = try bytes(files, "sod")
            signature[signature.count - 1] ^= 1
            corrupt["sod"] = signature
            let sod = try SOD(signature)
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod))
            XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod))
            let model = try partialModel(corrupt)
            model.verifyPassport(masterListURL: nil, useCMSVerification: preferCMS)
            XCTAssertEqual(model.verificationResult.sodSignatureStatus, .failed)
            XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
            let failed = model.makeDiagnosticSnapshot(attemptID: 2, outcome: .failed)
            model.removeSensitiveDataForPrivacy()
            try assertRedacted(failed, files: corrupt)

            var changedGroup = files
            var personalData = try bytes(files, "dg11")
            personalData[personalData.count - 1] ^= 1 // Preserve TLV shape; change signed bytes.
            changedGroup["dg11"] = personalData
            let mismatched = try partialModel(changedGroup)
            mismatched.verifyPassport(masterListURL: nil, useCMSVerification: preferCMS)
            XCTAssertEqual(mismatched.verificationResult.sodSignatureStatus, .passed)
            XCTAssertEqual(mismatched.verificationResult.dataGroupHashStatus, .failed)
            XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(mismatched))
            let hashFailure = mismatched.makeDiagnosticSnapshot(attemptID: 3, outcome: .failed)
            XCTAssertEqual(hashFailure.verification.dataGroupHashes.reason, .hashMismatch)
            mismatched.removeSensitiveDataForPrivacy()
            try assertRedacted(hashFailure, files: changedGroup)
        }
    }

    func testEveryTruncatedSpecimenFileIsRejectedWithoutContentDiagnostics() throws {
        for (name, wire) in try specimen().sorted(by: { $0.key < $1.key }) {
            for count in 0..<wire.count {
                XCTAssertThrowsError(try DataGroupParser().parseDG(data: Array(wire.prefix(count))), "\(name)/\(count)")
            }
        }
    }

    func testProxmarkFilesThroughReaderAndFailureScrubbing() async throws {
        let samples = try generated()
        XCTAssertEqual(samples.count, 3)
        for (name, files) in samples.sorted(by: { $0.key < $1.key }) {
            try await exerciseFileReads(files, rejected: name == "td1_utopia_idcard" ? [.DG2] : [.DG2, .DG7, .DG14])
        }
    }

    func testProxmarkValidGenericSignaturesCannotAuthorizeWrongSODContentType() throws {
        for (name, files) in try generated().sorted(by: { $0.key < $1.key }) {
            for preferCMS in [false, true] {
                if files["sod"] != nil {
                    let sod = try SOD(try bytes(files, "sod"))
                    // The upstream signature is valid even though its content type is wrong.
                    XCTAssertNoThrow(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(sod.body), trustedCertificatesURL: nil), name)
                    XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod), name)
                    XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod), name)
                }
                let model = try partialModel(files)
                model.verifyPassport(masterListURL: nil, useCMSVerification: preferCMS)
                XCTAssertNotEqual(model.verificationResult.sodSignatureStatus, .passed, name)
                XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model), name)
                XCTAssertThrowsError(try PassportReaderSecurityPolicy(verificationRequirement: .trustedPassiveAuthentication).validate(model), name)
                let snapshot = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
                if files["sod"] == nil {
                    XCTAssertEqual(snapshot.verification.sodSignature.reason, .missingSOD, name)
                    XCTAssertEqual(snapshot.verification.dataGroupHashes.reason, .missingSOD, name)
                } else {
                    XCTAssertEqual(snapshot.sod.stages.first { $0.stage == .encapsulatedContent }?.check.reason, .malformedStructure, name)
                    XCTAssertEqual(snapshot.verification.dataGroupHashes.status, .unavailable, name)
                    XCTAssertEqual(snapshot.sod.stages.first { $0.stage == .ldsSecurityObject }?.check.status, .notAttempted, name)
                }
                model.removeSensitiveDataForPrivacy()
                try assertRedacted(snapshot, files: files)
            }
        }
    }

    func testProxmarkTamperedPortraitIsVisibleToIndependentHashComparison() throws {
        let samples = try generated()
        for name in ["td3_utopia", "td3_utopia_tampered"] {
            let files = try XCTUnwrap(samples[name])
            let sod = try SOD(try bytes(files, "sod"))
            // Component isolation only: the complete SOD path rejects its content
            // type first; this does not override that rejection or repair signed bytes.
            let content = try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(sod.body), trustedCertificatesURL: nil)
            XCTAssertEqual(try hashMismatches(files, content: content), name.hasSuffix("tampered") ? [.DG2] : [], name)
        }
    }

    private func exerciseFileReads(_ files: [String: [UInt8]], rejected: Set<DataGroupId>) async throws {
        for (name, wire) in files.sorted(by: { $0.key < $1.key }) {
            let id = DataGroupId.getIDFromName(name: name.uppercased())
            let model = NFCPassportModel()
            // Previously read synthetic identity must be removed on later parse failure.
            model.addDataGroup(.DG1, dataGroup: try DataGroup1(try bytes(files, "dg1")))
            let transport = LifecycleTransport { command, _ in
                if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
                let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
                return (Data(wire.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
            }
            let tag = TagReader(transport: transport)
            let reader = PassportReader()
            reader.configureLifecycleForTesting(passport: model, tagReader: tag, groups: [id])
            let scan = try XCTUnwrap(reader.beginScanIfPossible())
            if rejected.contains(id) {
                do {
                    _ = try await reader.readDataGroup(tagReader: tag, dgId: id, scanID: scan)
                    XCTFail("Expected structural rejection: \(name)")
                    reader.failActiveScan(error: .InvalidASN1Structure, scanID: scan)
                } catch let error as NFCPassportReaderError {
                    reader.failActiveScan(error: error, scanID: scan)
                }
                let snapshot = try XCTUnwrap(reader.lastDiagnosticSnapshot)
                XCTAssertTrue(snapshot.failures.contains { $0.operation == .parseDataGroup }, name)
                XCTAssertTrue(model.dataGroupsRead.isEmpty, name)
                try assertRedacted(snapshot, files: files)
            } else {
                let read = try await reader.readDataGroup(tagReader: tag, dgId: id, scanID: scan)
                let group = try XCTUnwrap(read)
                XCTAssertEqual(group.datagroupType, id, name)
                XCTAssertTrue(group.data == wire, name)
                group.removeSensitiveDataForPrivacy()
                XCTAssertTrue(group.body.isEmpty && group.data.isEmpty, name)
                reader.failActiveScan(error: .UserCanceled, scanID: scan)
            }
        }
    }

    private func partialModel(_ files: [String: [UInt8]]) throws -> NFCPassportModel {
        let model = NFCPassportModel()
        for name in ["com", "dg1", "dg11", "dg12", "dg15", "sod"] {
            if let wire = files[name] {
                let group = try DataGroupParser().parseDG(data: wire)
                model.addDataGroup(group.datagroupType, dataGroup: group)
            }
        }
        return model
    }

    private func hashMismatches(_ files: [String: [UInt8]], content: Data) throws -> [DataGroupId] {
        let model = NFCPassportModel()
        defer { model.removeSensitiveDataForPrivacy() }
        let (algorithm, hashes) = try model.parseSODSignatureContent(data: content)
        XCTAssertEqual(hashes.count, files.keys.filter { $0.hasPrefix("dg") }.count)
        var mismatches: [DataGroupId] = []
        for (id, expected) in hashes {
            let wire = try bytes(files, id.getName().lowercased())
            // Hash original encoded file bytes without asserting its typed contents are valid.
            let opaque = try DataGroup(wire)
            defer { opaque.removeSensitiveDataForPrivacy() }
            if binToHexRep(opaque.hash(algorithm)) != expected { mismatches.append(id) }
        }
        return mismatches.sorted { $0.rawValue < $1.rawValue }
    }

    private func assertRedacted(_ snapshot: PassportDiagnosticSnapshot, files: [String: [UInt8]]) throws {
        let text = String(decoding: try JSONEncoder().encode(snapshot), as: UTF8.self)
        for wire in files.values {
            XCTAssertFalse(text.contains(Data(wire).base64EncodedString()))
            XCTAssertFalse(text.contains(binToHexRep(wire)))
        }
        for marker in ["JANE", "DOE", "ERIKSSON", "UTOPIA", "BEGIN CERTIFICATE", "Kseed", "KSenc", "KSmac", "RND.IFD", "RND.ICC", "FFD8FFE0"] {
            XCTAssertFalse(text.uppercased().contains(marker.uppercased()))
        }
        XCTAssertNil(text.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
    }

    private func bytes(_ files: [String: [UInt8]], _ name: String) throws -> [UInt8] { try XCTUnwrap(files[name]) }
    private func specimen() throws -> [String: [UInt8]] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "external-passport-specimen", withExtension: "json", subdirectory: "Fixtures"))
        let sample = try JSONDecoder().decode(Specimen.self, from: Data(contentsOf: url))
        XCTAssertEqual(sample.format, "icao-9303-lds1")
        return try sample.lds.mapValues { Array(try XCTUnwrap(Data(base64Encoded: $0))) }
    }
    private func generated() throws -> [String: [String: [UInt8]]] {
        guard let url = Bundle.module.url(forResource: "proxmark-passports", withExtension: "json", subdirectory: "Fixtures/ExternalPassports") else {
            throw XCTSkip("Run scripts/prepare_external_passports.py for pinned synthetic Proxmark3 samples")
        }
        return try JSONDecoder().decode([String: Generated].self, from: Data(contentsOf: url)).mapValues { $0.files.mapValues(hexRepToBin) }
    }
}
