import XCTest
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class DiagnosticSnapshotTests: XCTestCase {
    func testIndependentV0AndV1SignaturesPassBothVerifiersButOnlyV0Parses() throws {
        for profile in ["v0", "v1"] {
            let fixture = try load(profile)
            let sod = try SOD(bytes(fixture, "sod"))
            let expected = Data(try bytes(fixture, "content"))
            XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod) == expected)
            XCTAssertTrue(try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod) == expected)
            for preferCMS in [false, true] {
                let model = try makeModel(fixture)
                model.verifyPassport(masterListURL: try root(), useCMSVerification: preferCMS)
                let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
                XCTAssertEqual(value.verification.sodSignature.status, .succeeded)
                XCTAssertEqual(value.sod.successfulVerifier, preferCMS ? .cms : .manual)
                XCTAssertFalse(value.sod.fallbackAttempted)
                XCTAssertEqual(preferCMS ? value.sod.manualVerifier.status : value.sod.cmsVerifier.status, .notAttempted)
                XCTAssertEqual(value.sod.version, profile == "v0" ? .v0 : .v1)
                XCTAssertEqual(value.sod.ldsVersionInfo, profile == "v0" ? .absent : .present)
                if profile == "v1" {
                    XCTAssertEqual(stage(.ldsSecurityObject, value).reason, .unsupportedVersion)
                    XCTAssertEqual(value.verification.dataGroupHashes.status, .unavailable)
                    XCTAssertFalse(value.verification.dataGroupHashes.attempted)
                    XCTAssertEqual(model.verificationResult.dataGroupHashDetail.reason, .malformedSOD)
                    XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
                } else {
                    XCTAssertEqual(value.verification.dataGroupHashes.status, .succeeded)
                    XCTAssertNoThrow(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
                }
                model.removeSensitiveDataForPrivacy()
            }
        }
    }

    func testRealManualToCMSFallbackKeepsBothOutcomes() throws {
        let model = try makeModel(load("rsa_encryption"))
        model.verifyPassport(masterListURL: try root())
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .succeeded)
        XCTAssertTrue(value.sod.manualVerifier.attempted)
        XCTAssertEqual(value.sod.manualVerifier.status, .unsupported)
        XCTAssertEqual(value.sod.manualVerifier.reason, .unsupportedAlgorithm)
        XCTAssertTrue(value.sod.cmsVerifier.attempted)
        XCTAssertEqual(value.sod.cmsVerifier.status, .succeeded)
        XCTAssertTrue(value.sod.fallbackAttempted)
        XCTAssertEqual(value.sod.successfulVerifier, .cms)
        XCTAssertEqual(value.sod.signatureAlgorithm?.identifier, .rsaEncryption)
        XCTAssertNoThrow(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
    }

    func testSignatureHashAndTrustFailuresAllSurviveWithBothVerifierOrders() throws {
        var fixture = try load("v0")
        var wire = try bytes(fixture, "sod")
        wire[wire.count - 1] ^= 1
        fixture["sod"] = binToHexRep(wire)
        var group = try bytes(fixture, "dg11")
        group[group.count - 1] ^= 1
        fixture["dg11"] = binToHexRep(group)
        for preferCMS in [false, true] {
            let model = try makeModel(fixture)
            model.verifyPassport(masterListURL: try root("unrelated-csca"), useCMSVerification: preferCMS)
            let reader = PassportReader()
            reader.configureLifecycleForTesting(passport: model, securityPolicy: PassportScanOptions.notaryStrict.securityPolicy)
            let id = try XCTUnwrap(reader.beginScanIfPossible())
            reader.failActiveScan(error: .SecurityPolicyViolation, scanID: id)
            let value = try XCTUnwrap(reader.lastDiagnosticSnapshot)
            XCTAssertEqual(value.sod.manualVerifier.status, .failed)
            XCTAssertEqual(value.sod.cmsVerifier.status, .failed)
            XCTAssertEqual(value.sod.manualVerifier.failure?.operation, .manualVerification)
            XCTAssertEqual(value.sod.cmsVerifier.failure?.operation, .cmsVerification)
            XCTAssertNil(value.sod.successfulVerifier)
            XCTAssertEqual(value.verification.dataGroupHashes.reason, .hashMismatch)
            XCTAssertEqual(value.verification.countrySignerTrust.reason, .issuerNotFound)
            XCTAssertNotNil(value.verification.countrySignerTrust.failure?.certificateValidationCode)
            XCTAssertEqual(value.dataGroups.first { $0.dataGroup == .DG11 }?.comparison.status, .failed)
            XCTAssertEqual(value.dataGroups.first { $0.dataGroup == .DG1 }?.comparison.status, .succeeded)
            XCTAssertTrue(model.dataGroupsRead.isEmpty)
            XCTAssertTrue(model.dataGroupHashes.isEmpty)
            XCTAssertTrue(model.verificationErrors.isEmpty)
            reader.cancelRead()
            reader.failActiveScan(error: .UserCanceled, scanID: id)
            XCTAssertEqual(reader.lastDiagnosticSnapshot, value)
        }
    }

    func testUnsupportedAlgorithmsAndMalformedSODStayDistinctFromSignatureFailure() throws {
        for profile in ["unknown_digest", "unknown_signature", "bad_hash_length", "bad_lds_tag"] {
            let model = try makeModel(load(profile))
            model.verifyPassport(masterListURL: try root())
            let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
            XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
            if profile == "unknown_signature" {
                XCTAssertEqual(value.sod.signatureAlgorithm?.identifier, .unrecognized)
                XCTAssertEqual(value.sod.manualVerifier.status, .unsupported)
                XCTAssertEqual(value.sod.cmsVerifier.status, .failed)
                XCTAssertEqual(value.verification.dataGroupHashes.status, .succeeded)
            } else {
                XCTAssertEqual(value.verification.sodSignature.status, .succeeded)
                XCTAssertEqual(value.verification.dataGroupHashes.status, .unavailable)
                if profile == "unknown_digest" {
                    XCTAssertEqual(value.sod.dataGroupDigestAlgorithm?.identifier, .unrecognized)
                    XCTAssertEqual(stage(.ldsSecurityObject, value).reason, .unsupportedAlgorithm)
                } else if profile == "bad_hash_length" {
                    let parser = try XCTUnwrap(stage(.dataGroupHashes, value).failure?.parser)
                    XCTAssertEqual(parser.expectedLength, 32)
                    XCTAssertEqual(parser.actualLength, 31)
                    XCTAssertNotNil(parser.offset)
                } else {
                    XCTAssertEqual(stage(.ldsSecurityObject, value).failure?.parser?.actualTag, 0x31)
                }
            }
        }
    }

    func testPSSParametersAreDeclaredAllowlistedMetadata() throws {
        let fixture = try load("rsa_pss_sha256", file: "signed-passports")
        let model = try makeModel(fixture)
        model.verifyPassport(masterListURL: nil)
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .succeeded)
        let pss = try XCTUnwrap(value.sod.signatureAlgorithm?.rsaPSS)
        XCTAssertEqual(value.sod.signatureAlgorithm?.parameterForm, .rsaPSS)
        XCTAssertEqual(pss.hashAlgorithm, .sha256)
        XCTAssertEqual(pss.maskGenerationAlgorithm, .mgf1)
        XCTAssertEqual(pss.maskGenerationHashAlgorithm, .sha256)
        XCTAssertEqual(pss.saltLength, 32)
        XCTAssertEqual(pss.trailerField, 1)
        XCTAssertEqual(value.sod.contentDigestAlgorithm?.identifier, .sha256)
        XCTAssertEqual(value.sod.signerDigestAlgorithm?.identifier, .sha256)
        XCTAssertEqual(value.verification.countrySignerTrust.status, .unavailable)
        XCTAssertFalse(value.verification.countrySignerTrust.attempted)
        XCTAssertEqual(value.verification.revocation.status, .notAttempted)
    }

    func testExpiredCertificateAndUnavailableTrustStoreHaveSeparateReasons() throws {
        let expired = try makeModel(load("expired_signer", file: "signed-passports"))
        expired.verifyPassport(masterListURL: try root("synthetic-csca"))
        XCTAssertEqual(expired.diagnosticEvidence.trust.reason, .certificateExpired)
        XCTAssertEqual(expired.diagnosticEvidence.trust.failure?.certificateValidationCode, 10)
        let noStore = try makeModel(load("v0"))
        noStore.verifyPassport(masterListURL: URL(fileURLWithPath: "/nonexistent-synthetic-trust-store.pem"))
        XCTAssertEqual(noStore.diagnosticEvidence.trust.reason, .trustStoreUnavailable)
    }

    func testSuccessSnapshotIsCopiedIntoResultAndSurvivesScrubbing() throws {
        let box = DiagnosticBox()
        let reader = PassportReader(diagnosticHandler: { box.snapshots.append($0) })
        let model = try makeModel(load("v0"))
        model.verifyPassport(masterListURL: try root())
        reader.configureLifecycleForTesting(passport: model)
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        reader.completeActiveScan(returning: model, scanID: id)
        let result = PassportChipReadResult(passport: model)
        model.removeSensitiveDataForPrivacy()
        XCTAssertEqual(result.diagnosticSnapshot, reader.lastDiagnosticSnapshot)
        XCTAssertEqual(box.snapshots.count, 1)
        XCTAssertEqual(result.diagnosticSnapshot?.outcome, .succeeded)
        XCTAssertTrue(model.dataGroupsRead.isEmpty)
        XCTAssertEqual(result.diagnosticSnapshot?.verification.sodSignature.status, .succeeded)
    }

    func testEarlyPublicAPIFailureAlwaysPublishesFreshSnapshot() async throws {
        let box = DiagnosticBox()
        let reader = PassportReader(diagnosticHandler: { box.snapshots.append($0) })
        for _ in 0..<2 {
            do {
                _ = try await reader.readPassportIdentity(mrzKey: "SYNTHETIC-SECRET", scanProfile: .identityOnly,
                    aaChallenge: [0], securityPolicy: PassportScanOptions.notaryStrict.securityPolicy)
                XCTFail("Expected unavailable NFC or invalid input")
            } catch { }
        }
        XCTAssertEqual(box.snapshots.count, 2)
        XCTAssertNotEqual(box.snapshots.first?.attemptID, box.snapshots.last?.attemptID)
        XCTAssertEqual(box.snapshots.last?.verification.sodSignature.status, .notAttempted)
        XCTAssertEqual(box.snapshots.last?.sod.manualVerifier.attempted, false)
    }

    func testTimeoutAndCancellationKeepEvidenceAndRejectOldCallbacks() async throws {
        for error in [NFCPassportReaderError.TimeOutError, .UserCanceled] {
            let reader = PassportReader()
            let model = try makeModel(load("v1"))
            model.verifyPassport(masterListURL: try root())
            reader.configureLifecycleForTesting(passport: model)
            let first = try XCTUnwrap(reader.beginScanIfPossible())
            reader.emitProgress(.verifyingDataGroups)
            reader.failActiveScan(error: error, scanID: first)
            let value = try XCTUnwrap(reader.lastDiagnosticSnapshot)
            XCTAssertEqual(value.outcome, error.safeDescription == NFCPassportReaderError.TimeOutError.safeDescription ? .timedOut : .canceled)
            XCTAssertEqual(value.verification.sodSignature.status, .succeeded)
            XCTAssertEqual(stage(.ldsSecurityObject, value).reason, .unsupportedVersion)
            XCTAssertTrue(model.dataGroupsRead.isEmpty)
            let next = try XCTUnwrap(reader.beginScanIfPossible())
            XCTAssertNil(reader.lastDiagnosticSnapshot)
            reader.recordDiagnosticFailure(.init(subsystem: .reader, operation: .scan, reason: .unknownFailure), scanID: first)
            reader.failActiveScan(error: .UserCanceled, scanID: first)
            XCTAssertNil(reader.lastDiagnosticSnapshot)
            reader.configureLifecycleForTesting()
            reader.cancelRead()
            XCTAssertEqual(reader.lastDiagnosticSnapshot?.attemptID, next)
            XCTAssertEqual(reader.lastDiagnosticSnapshot?.failures.count, 0)
            XCTAssertEqual(reader.lastDiagnosticSnapshot?.sod.version, nil)
        }
    }

    func testNativeCodeAndAPDUStatusSurviveTranslation() async throws {
        for native in [true, false] {
            let transport = LifecycleTransport { _, _ in
                if native { throw NFCReaderError(.readerTransceiveErrorTagConnectionLost) }
                return (Data(), 0x6A, 0x82)
            }
            let tag = TagReader(transport: transport)
            let reader = PassportReader()
            reader.configureLifecycleForTesting(tagReader: tag)
            let id = try XCTUnwrap(reader.beginScanIfPossible())
            do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .DG1, scanID: id); XCTFail("Expected failure") }
            catch let error as NFCPassportReaderError { reader.failActiveScan(error: error, scanID: id) }
            let value = try XCTUnwrap(reader.lastDiagnosticSnapshot)
            if native {
                XCTAssertTrue(value.failures.contains { $0.coreNFCCode == NFCReaderError.Code.readerTransceiveErrorTagConnectionLost.rawValue })
            } else {
                XCTAssertTrue(value.failures.contains { $0.statusWord == 0x6A82 })
            }
            XCTAssertTrue(value.failures.contains { $0.stage == .readingDataGroup(.DG1) })
        }
    }

    func testMalformedEnvelopeCapturesParserOffsetWithoutRawBytes() async throws {
        let wire: [UInt8] = [0x77, 3, 0x30, 2, 0x02]
        let tag = TagReader(transport: LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
            let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
            return (Data(wire.dropFirst(offset).prefix(command.expectedResponseLength)), 0x90, 0)
        })
        let reader = PassportReader()
        reader.configureLifecycleForTesting(tagReader: tag)
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        do { _ = try await reader.readDataGroup(tagReader: tag, dgId: .SOD, scanID: id); XCTFail("Expected malformed SOD") }
        catch let error as NFCPassportReaderError { reader.failActiveScan(error: error, scanID: id) }
        let value = try XCTUnwrap(reader.lastDiagnosticSnapshot)
        XCTAssertEqual(stage(.envelope, value).status, .failed)
        XCTAssertEqual(stage(.envelope, value).failure?.parser?.offset, 0)
        XCTAssertFalse(value.sod.manualVerifier.attempted)
        XCTAssertEqual(value.dataGroups.first?.coverage, .unavailable)
    }

    func testBoundedFailuresAndSentinelRedaction() throws {
        let marker = "P<UTO PRIVATE-NAME TEST12345 700101 Kseed KSenc KSmac RND.IFD RND.ICC FFD8FFE0 00A40400 " + String(repeating: "AB", count: 40)
        let box = DiagnosticBox()
        let sink = DiagnosticLog()
        let reader = PassportReader(logLevel: .info, logger: sink, diagnosticHandler: { box.snapshots.append($0) })
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        let errors: [Error] = [NFCPassportReaderError.Unknown(NSError(domain: marker, code: 987654, userInfo: [NSLocalizedDescriptionKey: marker])),
            NFCPassportReaderError.ResponseError(marker, 0x69, 0x82), NFCPassportReaderError.PACEError(marker, marker),
            NFCPassportReaderError.InvalidDataPassed(marker), OpenSSLError.VerifyAndReturnSODEncapsulatedData(marker)]
        for error in errors { reader.recordDiagnosticFailure(.capture(error, stage: .pace), scanID: id) }
        for code in 0..<100 {
            reader.recordDiagnosticFailure(.capture(NFCPassportReaderError.ResponseError(marker, 0x6F, UInt8(code)), stage: .pace), scanID: id)
        }
        reader.failActiveScan(error: .Unknown(NSError(domain: marker, code: 99)), scanID: id)
        let value = try XCTUnwrap(reader.lastDiagnosticSnapshot)
        XCTAssertEqual(value.failures.count, 32)
        XCTAssertGreaterThan(value.droppedFailureCount, 0)
        let text = String(decoding: try JSONEncoder().encode(value), as: UTF8.self) + sink.events.map(\.description).joined()
        for forbidden in marker.split(separator: " ") { XCTAssertFalse(text.contains(forbidden), "Sensitive sentinel escaped") }
        XCTAssertFalse(text.contains("987654"))
        XCTAssertNil(text.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
        XCTAssertEqual(box.snapshots, [value])
    }

    func testAlgorithmAndStructureAllowlistRejectArbitraryValues() throws {
        let metadata = PassportParserDiagnostic(expectedTag: Int.max, actualTag: 0xFFFF,
            expectedLength: -1, actualLength: Int.max, offset: -1)
        XCTAssertNil(metadata.expectedTag)
        XCTAssertNil(metadata.actualTag)
        XCTAssertNil(metadata.expectedLength)
        XCTAssertNil(metadata.actualLength)
        XCTAssertNil(metadata.offset)
        let node = try SimpleASN1Node.parse([0x30, 6, 0x06, 4, 0x2A, 3, 4, 5])
        XCTAssertEqual(PassportAlgorithmDiagnostic.read(node, role: .digest)?.identifier, .unrecognized)
    }

    func testAuthenticationStatusesDoNotClaimUnperformedChecksPassed() throws {
        let model = NFCPassportModel()
        model.activeAuthenticationDiagnostic = .init(.inProgress, .none, attempted: true)
        model.chipAuthenticationDiagnostic = .init(.skipped, .skippedByConfiguration)
        var value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .canceled)
        XCTAssertTrue(value.verification.activeAuthentication.attempted)
        XCTAssertEqual(value.verification.activeAuthentication.status, .inProgress)
        XCTAssertFalse(value.verification.chipAuthentication.attempted)
        model.recordActiveAuthenticationFailure()
        model.chipAuthenticationStatus = .failed
        value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
        XCTAssertEqual(value.verification.activeAuthentication.status, .failed)
        XCTAssertEqual(value.verification.chipAuthentication.status, .failed)
    }

    func testSnapshotCallbackCanBeginNextAttemptWithoutOldStateContamination() throws {
        let box = DiagnosticBox()
        let reader = PassportReader(diagnosticHandler: { snapshot in
            box.snapshots.append(snapshot)
            box.onSnapshot?()
        })
        let first = try XCTUnwrap(reader.beginScanIfPossible())
        box.onSnapshot = { [weak reader] in _ = reader?.beginScanIfPossible() }
        reader.failActiveScan(error: .SecurityPolicyViolation, scanID: first)
        XCTAssertEqual(box.snapshots.count, 1)
        XCTAssertEqual(box.snapshots[0].terminalFailure?.reason, .policyRejected)
        XCTAssertNil(reader.lastDiagnosticSnapshot)
        XCTAssertTrue(reader.isActiveScan(reader.currentScanID()))
        reader.failActiveScan(error: .TimeOutError, scanID: first)
        XCTAssertNil(reader.lastDiagnosticSnapshot)
        box.onSnapshot = nil
        reader.cancelRead()
        XCTAssertEqual(box.snapshots.count, 2)
        XCTAssertTrue(try XCTUnwrap(reader.lastDiagnosticSnapshot).failures.isEmpty)
    }

    func testTimerAndLateTransportResponseCannotContaminateNextAttempt() async throws {
        let transport = DeferredLifecycleTransport()
        let tag = TagReader(transport: transport)
        let reader = PassportReader()
        reader.configureLifecycleForTesting(tagReader: tag)
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        let pending = Task { _ = try await reader.readDataGroup(tagReader: tag, dgId: .SOD, scanID: id) }
        await transport.waitForCommand()
        reader.startTimeoutTask(0.001, scanID: id)
        try await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(reader.lastDiagnosticSnapshot?.outcome, .timedOut)
        let old = reader.lastDiagnosticSnapshot
        let next = try XCTUnwrap(reader.beginScanIfPossible())
        transport.respond((Data(), 0x6F, 0x01))
        _ = await pending.result
        XCTAssertNil(reader.lastDiagnosticSnapshot)
        XCTAssertTrue(reader.isActiveScan(next))
        reader.cancelRead()
        XCTAssertTrue(try XCTUnwrap(reader.lastDiagnosticSnapshot).failures.isEmpty)
        XCTAssertEqual(old?.terminalFailure?.stage, .readingDataGroup(.SOD))
    }

    func testMetadataAvailableBeforeVerificationDoesNotImplyVerificationPassed() throws {
        let model = try makeModel(load("v1"))
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .canceled)
        XCTAssertEqual(value.sod.version, .v1)
        XCTAssertEqual(value.sod.ldsVersionInfo, .present)
        XCTAssertEqual(value.sod.signatureAlgorithm?.identifier, .rsaSHA256)
        XCTAssertEqual(value.verification.sodSignature.status, .notAttempted)
        XCTAssertEqual(value.verification.dataGroupHashes.status, .notAttempted)
        XCTAssertFalse(value.sod.manualVerifier.attempted)
        XCTAssertEqual(stage(.ldsSecurityObject, value).status, .notAttempted)
        XCTAssertEqual(value.dataGroups.first { $0.dataGroup == .DG1 }?.coverage, .unavailable)
    }

    func testPartialParsedHashCoverageDoesNotClaimComparison() throws {
        let model = NFCPassportModel()
        let digest: [UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0]
        let first = wrapDO(b: 0x30, arr: [2, 1, 1] + wrapDO(b: 4, arr: Array(repeating: 0, count: 32)))
        let second = wrapDO(b: 0x30, arr: [2, 1, 2] + wrapDO(b: 4, arr: Array(repeating: 0, count: 31)))
        let content = wrapDO(b: 0x30, arr: [2, 1, 0] + digest + wrapDO(b: 0x30, arr: first + second))
        XCTAssertThrowsError(try model.parseSODSignatureContent(data: Data(content)))
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
        let group = try XCTUnwrap(value.dataGroups.first { $0.dataGroup == .DG1 })
        XCTAssertEqual(group.coverage, .covered)
        XCTAssertFalse(group.comparison.attempted)
        XCTAssertEqual(value.dataGroups.first { $0.dataGroup == .DG2 }?.coverage, .unavailable)
    }

    func testHashCoverageDistinguishesCoveredButUnreadAndReadButUncovered() throws {
        let fixture = try load("v0")
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: try DataGroup1(bytes(fixture, "dg1")))
        model.addDataGroup(.DG13, dataGroup: try DataGroup13([0x6D, 0]))
        model.addDataGroup(.SOD, dataGroup: try SOD(bytes(fixture, "sod")))
        model.verifyPassport(masterListURL: nil)
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
        let unread = try XCTUnwrap(value.dataGroups.first { $0.dataGroup == .DG11 })
        XCTAssertEqual(unread.coverage, .covered)
        XCTAssertFalse(unread.wasRead)
        XCTAssertFalse(unread.comparison.attempted)
        let uncovered = try XCTUnwrap(value.dataGroups.first { $0.dataGroup == .DG13 })
        XCTAssertEqual(uncovered.coverage, .notCovered)
        XCTAssertTrue(uncovered.wasRead)
        XCTAssertEqual(uncovered.comparison.reason, .hashNotCovered)
        XCTAssertThrowsError(try PassportScanOptions.notaryStrict.securityPolicy.validate(model))
    }

    func testAdvertisedAuthenticationWithUnreadMaterialIsUnavailable() throws {
        let model = NFCPassportModel()
        model.addDataGroup(.COM, dataGroup: try COM(lifecycleCOM([0x6E, 0x6F])))
        model.recordDataGroupReadStatus(.failed, for: .DG15)
        let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
        XCTAssertEqual(value.verification.activeAuthentication.status, .unavailable)
        XCTAssertEqual(value.verification.chipAuthentication.status, .unavailable)
        XCTAssertFalse(value.verification.activeAuthentication.attempted)
        model.recordDataGroupReadStatus(.skippedByProfile, for: .DG14)
        XCTAssertEqual(model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed).verification.chipAuthentication.status, .skipped)
    }

    func testDefaultLoggingRemainsOffWhileSnapshotDeliveryWorks() throws {
        let box = DiagnosticBox()
        let sink = DiagnosticLog()
        let reader = PassportReader(logger: sink, diagnosticHandler: { box.snapshots.append($0) })
        let id = try XCTUnwrap(reader.beginScanIfPossible())
        reader.failActiveScan(error: .UserCanceled, scanID: id)
        XCTAssertTrue(sink.events.isEmpty)
        XCTAssertEqual(box.snapshots.count, 1)
    }

    func testSnapshotExcludesSyntheticContentCertificatesAndHashes() throws {
        let fixture = try load("v0")
        let model = try makeModel(fixture)
        model.verifyPassport(masterListURL: try root())
        let encoded = String(decoding: try JSONEncoder().encode(model.makeDiagnosticSnapshot(attemptID: 1, outcome: .succeeded)), as: UTF8.self)
        for name in ["sod", "content", "dg1", "dg11"] {
            let raw = try bytes(fixture, name)
            XCTAssertFalse(encoded.contains(binToHexRep(raw)))
            XCTAssertFalse(encoded.contains(Data(raw).base64EncodedString()))
        }
        for hash in model.dataGroupHashes.values {
            XCTAssertFalse(encoded.contains(hash.sodHash))
            XCTAssertFalse(encoded.contains(hash.computedHash))
        }
        for forbidden in ["SYNTHETIC", "TEST00001", "700101", "300101", "PRIVATE KEY", "CERTIFICATE"] {
            XCTAssertFalse(encoded.contains(forbidden))
        }
        XCTAssertLessThan(encoded.utf8.count, 32_768)
    }

    func testIndependentActiveAuthenticationSuccessAndFailureArePreserved() throws {
        let fixture = try load("active_authentication")
        for tamper in [false, true] {
            let model = NFCPassportModel()
            model.addDataGroup(.DG15, dataGroup: try DataGroup15(bytes(fixture, "dg15")))
            var response = try bytes(fixture, "response")
            if tamper { response[0] ^= 1 }
            model.verifyActiveAuthentication(challenge: try bytes(fixture, "challenge"), signature: response)
            let value = model.makeDiagnosticSnapshot(attemptID: 1, outcome: .failed)
            XCTAssertEqual(value.verification.activeAuthentication.status, tamper ? .failed : .succeeded)
            XCTAssertTrue(value.verification.activeAuthentication.attempted)
            model.removeSensitiveDataForPrivacy()
            XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
            XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
            XCTAssertTrue(model.dataGroupsRead.isEmpty)
        }
    }

    private func stage(_ stage: PassportSODParsingStage, _ value: PassportDiagnosticSnapshot) -> PassportDiagnosticCheck {
        value.sod.stages.first { $0.stage == stage }!.check
    }
    private func root(_ name: String = "diagnostic-csca") throws -> URL {
        try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "pem", subdirectory: "Fixtures"))
    }
    private func load(_ name: String, file: String = "diagnostic-passports") throws -> [String: String] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: file, withExtension: "json", subdirectory: "Fixtures"))
        return try XCTUnwrap(JSONDecoder().decode([String: [String: String]].self, from: Data(contentsOf: url))[name])
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

@MainActor
private final class DiagnosticBox {
    var snapshots: [PassportDiagnosticSnapshot] = []
    var onSnapshot: (() -> Void)?
}

@MainActor
private final class DiagnosticLog: @preconcurrency PassportReaderLogging {
    var events: [PassportReaderLogEvent] = []
    func log(_ event: PassportReaderLogEvent) { events.append(event) }
}
