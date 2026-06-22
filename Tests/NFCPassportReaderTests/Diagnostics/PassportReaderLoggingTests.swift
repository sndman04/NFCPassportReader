import XCTest
import OpenSSL
import OpenSSLCompat

@testable import NFCPassportReader

final class PassportReaderLoggingTests: XCTestCase {
    private final class CapturingLogger: PassportReaderLogging {
        private(set) var events: [PassportReaderLogEvent] = []

        func log(_ event: PassportReaderLogEvent) {
            events.append(event)
        }
    }

    private final class ProgressRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var recordedEvents: [PassportReaderProgressEvent] = []

        var events: [PassportReaderProgressEvent] {
            lock.lock()
            defer { lock.unlock() }
            return recordedEvents
        }

        func record(_ event: PassportReaderProgressEvent) {
            lock.lock()
            defer { lock.unlock() }
            recordedEvents.append(event)
        }
    }

    func testLoggerDefaultsToOff() {
        let sink = CapturingLogger()
        let logger = PassportReaderEventLogger(level: .off, sink: sink)

        logger.log(.paceStarted)
        logger.log(.readFailed(.accessKeyRejected))

        XCTAssertTrue(sink.events.isEmpty)
    }

    func testErrorLevelOnlyEmitsFailuresAndInvalidations() {
        let sink = CapturingLogger()
        let logger = PassportReaderEventLogger(level: .error, sink: sink)

        logger.log(.sessionStarted)
        logger.log(.readingDataGroup(.DG2))
        logger.log(.readFailed(.connectionLost))
        logger.log(.sessionInvalidated(.timeout))

        XCTAssertEqual(sink.events.map(\.description), [
            "Passport chip read failed: connection lost",
            "NFC session invalidated: timeout"
        ])
    }

    func testEventDescriptionsDoNotExposeSensitivePatterns() {
        let descriptions = [
            PassportReaderLogEvent.sessionStarted,
            .tagDetected,
            .paceStarted,
            .paceSucceeded,
            .paceFailedFallbackToBAC,
            .bacStarted,
            .bacSucceeded,
            .chipAuthenticationStarted,
            .chipAuthenticationFailedFallbackToBAC,
            .activeAuthenticationStarted,
            .readingDataGroup(.DG2),
            .unsupportedDataGroup(.DG15),
            .verificationStarted,
            .readFailed(.accessKeyRejected)
        ].map(\.description).joined(separator: "\n")

        let forbiddenFragments = [
            "MRZ",
            "MRZ KEY",
            "Kseed",
            "KSenc",
            "KSmac",
            "RND.IFD",
            "RND.ICC",
            "APDU",
            "RAPDU",
            "FFD8FFE0",
            "A0000002471001",
            "L898902C36UTO7408122F1204159"
        ]

        for fragment in forbiddenFragments {
            XCTAssertFalse(
                descriptions.localizedCaseInsensitiveContains(fragment),
                "Event descriptions must not contain sensitive fragment: \(fragment)"
            )
        }

        XCTAssertNil(
            descriptions.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression),
            "Event descriptions must not contain long hex dumps"
        )
    }

    func testReaderErrorsMapToPrivacySafeFailureReasons() {
        XCTAssertEqual(NFCPassportReaderError.UserCanceled.privacySafeFailureReason.description, "user canceled")
        XCTAssertEqual(NFCPassportReaderError.NFCNotSupported.privacySafeFailureReason.description, "NFC not supported")
        XCTAssertEqual(NFCPassportReaderError.TimeOutError.privacySafeFailureReason.description, "timeout")
        XCTAssertEqual(NFCPassportReaderError.ConnectionError.privacySafeFailureReason.description, "connection lost")
        XCTAssertEqual(NFCPassportReaderError.InvalidMRZKey.privacySafeFailureReason.description, "access key rejected")
        XCTAssertEqual(NFCPassportReaderError.UnsupportedDataGroup.privacySafeFailureReason.description, "unsupported passport")
        XCTAssertEqual(NFCPassportReaderError.InvalidResponseChecksum.privacySafeFailureReason.description, "verification failed")
        XCTAssertEqual(NFCPassportReaderError.ScanAlreadyInProgress.privacySafeFailureReason.description, "read failed")
    }

    func testProgressDescriptionsDoNotExposeSensitivePatterns() {
        let descriptions = [
            PassportReaderProgressEvent.waitingForPassport,
            .tagDetected,
            .authenticating(progress: 0.4),
            .paceStarted,
            .paceFailedFallbackToBAC,
            .bacStarted,
            .bacSucceeded,
            .chipAuthenticationStarted,
            .activeAuthenticationStarted,
            .readingDataGroup(.DG2, progress: 0.7),
            .verifyingSOD,
            .verifyingDataGroups,
            .complete
        ].map(\.description).joined(separator: "\n")

        for fragment in ["MRZ", "Kseed", "KSenc", "KSmac", "RND.IFD", "RND.ICC", "APDU", "RAPDU"] {
            XCTAssertFalse(descriptions.localizedCaseInsensitiveContains(fragment))
        }

        XCTAssertNil(descriptions.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
    }

    func testDisplayMessageDoesNotExposeResponseStatusWords() {
        let message = NFCViewDisplayMessage.error(.ResponseError("Wrong length", 0x6C, 0x20)).description

        XCTAssertFalse(message.contains("Wrong length"))
        XCTAssertFalse(message.contains("0x6C"))
        XCTAssertFalse(message.contains("0x20"))
        XCTAssertEqual(message, "Sorry, there was a problem reading the passport. Please try again.")
    }

    func testASN1DebugDescriptionRedactsParsedValues() throws {
        let item = try SimpleASN1Node.parse([0x04, 0x10] + hexRepToBin("00112233445566778899AABBCCDDEEFF"))
        let description = item.debugDescription

        XCTAssertTrue(description.contains("<redacted>"))
        XCTAssertFalse(description.contains("00112233445566778899AABBCCDDEEFF"))
        XCTAssertNil(description.range(of: #"[0-9A-Fa-f]{16,}"#, options: .regularExpression))
    }

    func testPACEErrorDescriptionDoesNotExposeTokenBytes() {
        let error = NFCPassportReaderError.PACEError("Step3 KeyAgreement", "Passport authentication token mismatch")

        XCTAssertEqual(error.localizedDescription, "PACE authentication failed")
        XCTAssertFalse(error.localizedDescription.contains("["))
        XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("expected"))
        XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("received"))
    }

    func testReaderErrorLocalizedDescriptionsArePrivacySafe() {
        let errors: [NFCPassportReaderError] = [
            .ResponseError("Wrong length Le: SW2 indicates exact length", 0x6C, 0x20),
            .InvalidResponse(dataGroupId: .DG1, expectedTag: 0x61, actualTag: 0x75),
            .PACEError("Step3", "Expected [01, 02], received [03, 04]"),
            .ScanAlreadyInProgress,
            .InvalidDataPassed("Kseed 00112233445566778899AABBCCDDEEFF"),
            .NotYetSupported("APDU A0000002471001"),
            .Unknown(NFCPassportReaderError.ResponseError("RAPDU 9000", 0x90, 0x00))
        ]

        let descriptions = errors.map(\.localizedDescription).joined(separator: "\n")
        for fragment in ["Wrong length", "SW2", "0x6C", "expected", "received", "Kseed", "APDU", "RAPDU", "00112233445566778899AABBCCDDEEFF"] {
            XCTAssertFalse(descriptions.localizedCaseInsensitiveContains(fragment))
        }
        XCTAssertNil(descriptions.range(of: #"[0-9A-Fa-f]{16,}"#, options: .regularExpression))
    }

    func testReaderErrorDefaultStringDescriptionsArePrivacySafe() {
        let errors: [NFCPassportReaderError] = [
            .ResponseError("Wrong length Le: SW2 indicates exact length", 0x6C, 0x20),
            .PACEError("Step3", "Expected [01, 02], received [03, 04]"),
            .InvalidDataPassed("Kseed 00112233445566778899AABBCCDDEEFF"),
            .NotYetSupported("APDU A0000002471001"),
            .Unknown(NFCPassportReaderError.ResponseError("RAPDU 9000", 0x90, 0x00))
        ]

        let descriptions = errors.map { String(describing: $0) }.joined(separator: "\n")
        for fragment in ["Wrong length", "SW2", "0x6C", "expected", "received", "Kseed", "APDU", "RAPDU", "00112233445566778899AABBCCDDEEFF"] {
            XCTAssertFalse(descriptions.localizedCaseInsensitiveContains(fragment))
        }
        XCTAssertNil(descriptions.range(of: #"[0-9A-Fa-f]{16,}"#, options: .regularExpression))
    }

    func testSecondaryErrorLocalizedDescriptionsArePrivacySafe() {
        let errors: [Error] = [
            OpenSSLError.UnableToParseASN1("ASN1 dump 00112233445566778899AABBCCDDEEFF"),
            OpenSSLError.UnableToDecryptRSASignature("OpenSSL error with certificate bytes FFD8FFE000104A464946"),
            PassiveAuthenticationError.InvalidDataGroupHash("DG1 expected 00112233445566778899 actual AABBCCDDEEFF001122"),
            PassiveAuthenticationError.UnableToParseSODHashes("messageDigest A0000002471001")
        ]

        let descriptions = errors.map(\.localizedDescription).joined(separator: "\n")
        for fragment in ["ASN1 dump", "OpenSSL error", "FFD8FFE000104A464946", "expected", "actual", "messageDigest", "A0000002471001"] {
            XCTAssertFalse(descriptions.localizedCaseInsensitiveContains(fragment))
        }
        XCTAssertNil(descriptions.range(of: #"[0-9A-Fa-f]{16,}"#, options: .regularExpression))
    }

    func testPassiveAuthenticationHashMismatchPayloadUsesSummaryOnly() {
        let error = PassiveAuthenticationError.InvalidDataGroupHash("DG1 hash mismatch")
        let description = String(describing: error)

        XCTAssertTrue(description.contains("DG1 hash mismatch"))
        XCTAssertFalse(description.localizedCaseInsensitiveContains("SOD hash"))
        XCTAssertFalse(description.localizedCaseInsensitiveContains("Computed hash"))
        XCTAssertNil(description.range(of: #"[0-9A-Fa-f]{16,}"#, options: .regularExpression))
    }

    func testScanProfilesMapToExpectedDataGroups() {
        XCTAssertEqual(PassportScanProfile.identityOnly.dataGroups, [.COM, .SOD, .DG1])
        XCTAssertEqual(PassportScanProfile.identityWithPhoto.dataGroups, [.COM, .SOD, .DG1, .DG2])
        XCTAssertEqual(PassportScanProfile.fullVerification.dataGroups, [.COM, .SOD, .DG1, .DG2, .DG7, .DG11, .DG12, .DG14, .DG15])
    }

    func testPACEKeyReferencesUseStandardPasswordReferenceValues() {
        XCTAssertEqual(PassportPACEKeyReference.mrz.rawValue, 0x01)
        XCTAssertEqual(PassportPACEKeyReference.can.rawValue, 0x02)
        XCTAssertEqual(PassportPACEKeyReference.pin.rawValue, 0x03)
        XCTAssertEqual(PassportPACEKeyReference.puk.rawValue, 0x04)
    }

    func testPACEMappingClassifierDistinguishesGMIMAndCAM() throws {
        switch try PACEInfo.toMappingType(oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) {
        case .GM:
            break
        default:
            XCTFail("Expected GM mapping")
        }

        switch try PACEInfo.toMappingType(oid: SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128) {
        case .IM:
            break
        default:
            XCTFail("Expected IM mapping")
        }

        switch try PACEInfo.toMappingType(oid: SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) {
        case .CAM:
            break
        default:
            XCTFail("Expected CAM mapping")
        }
    }

    func testPACEProtocolOIDStringsMatchStandardNames() {
        let dhIM = PACEInfo(
            oid: SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_GFP_2048_256
        )
        let ecdhIM3DES = PACEInfo(
            oid: SecurityInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1
        )

        XCTAssertEqual(dhIM.getProtocolOIDString(), "id-PACE-DH-IM-AES-CBC-CMAC-256")
        XCTAssertEqual(ecdhIM3DES.getProtocolOIDString(), "id-PACE-ECDH-IM-3DES-CBC-CBC")
    }

    func testPACEInfoSelectionPreservesImplementedIMBeforeGM() {
        let im = PACEInfo(
            oid: SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1
        )
        let gm = PACEInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1
        )

        XCTAssertTrue(im.isImplementedForReading)
        XCTAssertTrue(gm.isImplementedForReading)

        let infos = [im, gm]
        let ordered = infos.filter { $0.isImplementedForReading } + infos.filter { !$0.isImplementedForReading }

        XCTAssertTrue(ordered.first === im)
    }

    func testCardAccessPreferredPACEInfoUsesFirstImplementedEntry() throws {
        let unsupportedFirst = try securityInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            requiredData: diagnosticASN1Integer([0x02]),
            optionalData: diagnosticASN1Integer([0x7F])
        )
        let implementedSecond = try securityInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            requiredData: diagnosticASN1Integer([0x02]),
            optionalData: diagnosticASN1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
        )

        let cardAccess = try CardAccess(diagnosticASN1Set(unsupportedFirst + implementedSecond))

        XCTAssertEqual(cardAccess.preferredPACEInfo?.getParameterId(), PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
    }

    func testCardAccessPreferredPACEInfoFallsBackToFirstEntryForPreflightFailure() throws {
        let unsupportedFirst = try securityInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            requiredData: diagnosticASN1Integer([0x02]),
            optionalData: diagnosticASN1Integer([0x7F])
        )
        let unsupportedSecond = try securityInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
            requiredData: diagnosticASN1Integer([0x02]),
            optionalData: diagnosticASN1Integer([0x7E])
        )

        let cardAccess = try CardAccess(diagnosticASN1Set(unsupportedFirst + unsupportedSecond))

        XCTAssertEqual(cardAccess.preferredPACEInfo?.getParameterId(), 0x7F)
    }

    func testPACEInfoSelectionTreatsECDHCAMAsReadableMapping() {
        let cam = PACEInfo(
            oid: SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1
        )

        XCTAssertTrue(cam.isImplementedForReading)
    }

    @available(iOS 15, *)
    func testPACEIntegratedMappingFieldMatchesICAOAppendixHECDHVector() throws {
        let field = try PACEHandler.integratedMappingField(
            passportNonce: hexRepToBin("2923BE84E16CD6AE529049F1F1BBE9EB"),
            terminalNonce: hexRepToBin("5DD4CBFC96F5453B130D890A1CDBAE32"),
            cipherAlg: "AES",
            keyLength: 128,
            primeBitLength: 256
        )

        XCTAssertEqual(
            binToHexRep(field),
            "E4447E2DFB3586BAC05DDB00156B57FBB2179A3949294C97254189800C517BAA8DA0FF397ED8C445D3E421E4FEB57322"
        )
    }

    @available(iOS 15, *)
    func testPACEIntegratedMappingRejectsInvalidNonceLengths() {
        XCTAssertThrowsError(try PACEHandler.integratedMappingField(
            passportNonce: [0x01, 0x02],
            terminalNonce: hexRepToBin("5DD4CBFC96F5453B130D890A1CDBAE32"),
            cipherAlg: "AES",
            keyLength: 128,
            primeBitLength: 256
        ))

        XCTAssertThrowsError(try PACEHandler.integratedMappingField(
            passportNonce: hexRepToBin("2923BE84E16CD6AE529049F1F1BBE9EB"),
            terminalNonce: [0x01, 0x02],
            cipherAlg: "AES",
            keyLength: 128,
            primeBitLength: 256
        ))
    }

    @available(iOS 15, *)
    func testPACEIntegratedMappingCreatesExpectedECDHGeneratorFromICAOAppendixHVector() throws {
        let paceInfo = PACEInfo(
            oid: SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1
        )
        let domainKey = try paceInfo.createMappingKey()
        defer { EVP_PKEY_free(domainKey) }

        var field = hexRepToBin(
            "E4447E2DFB3586BAC05DDB00156B57FB" +
            "B2179A3949294C97254189800C517BAA" +
            "8DA0FF397ED8C445D3E421E4FEB57322"
        )
        let mappedParameters = try XCTUnwrap(NFCPRCreateECDHIntegratedMappedParameters(domainKey, &field, field.count))
        defer { EVP_PKEY_free(mappedParameters) }

        var expectedGenerator = hexRepToBin(
            "04" +
            "8E82D31559ED0FDE92A4D0498ADD3C23BABA94FB77691E31E90AEA77FB17D427" +
            "4C1AE14BD0C3DBAC0C871B7F3608169364437CA30AC243A089D3F266C1E60FAD"
        )
        XCTAssertEqual(NFCPRVerifyECGenerator(mappedParameters, &expectedGenerator, expectedGenerator.count), 1)
    }

    @available(iOS 15, *)
    func testPACEIntegratedMappingCreatesExpectedDHGeneratorFromICAOAppendixHVector() throws {
        let paceInfo = PACEInfo(
            oid: SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128,
            version: 2,
            parameterId: PACEInfo.PARAM_ID_GFP_1024_160
        )
        let domainKey = try paceInfo.createMappingKey()
        defer { EVP_PKEY_free(domainKey) }

        var field = hexRepToBin(
            "EAB98D13E09052952AA729907C3C9461" +
            "84DEA0FE74AD2B3AF506F0A83018459C" +
            "38099CD1F7FF4EA0A078DB1FAC136550" +
            "5E3DC85500EF95E20B4EEF2E88489233" +
            "BEE0546B472F994B618D168702406791" +
            "DEEF3CB4810932EC278F3533FDB860EB" +
            "4835C36FA4F1BF3FA0B828A718C96BDE" +
            "88FBA38A3E6C35AAA10959251EB5FC71" +
            "0FC187258995944C0F926E249373F485"
        )
        let mappedParameters = try XCTUnwrap(NFCPRCreateDHIntegratedMappedParameters(domainKey, &field, field.count))
        defer { EVP_PKEY_free(mappedParameters) }

        var expectedGenerator = hexRepToBin(
            "1D7D767F11E333BCD6DBAEF40E799E7A" +
            "926B96973550656FF3C830726D118D61" +
            "C276CDCC61D475CF03A98E0C0E79CAEB" +
            "A5BE25578BD4551D0B10903236F0B0F9" +
            "76852FA78EEA14EA0ACA87D1E91F688F" +
            "E0DFF897BBE35A472621D343564B262F" +
            "34223AE8FC59B664BFEDFA2BFE7516CA" +
            "5510A6BBB633D517EC25D4E0BBAA16C2"
        )
        XCTAssertEqual(NFCPRVerifyDHGenerator(mappedParameters, &expectedGenerator, expectedGenerator.count), 1)
    }

    func testPACECAMVerifierChecksDecryptedChipAuthenticationDataAgainstPublicKey() throws {
        let staticKey = try OpenSSLUtils.generateECKeyPair(curveNID: PACEInfo.getParameterSpec(stdDomainParam: PACEInfo.PARAM_ID_ECP_NIST_P256_R1))
        defer { EVP_PKEY_free(staticKey) }
        let wrongStaticKey = try OpenSSLUtils.generateECKeyPair(curveNID: PACEInfo.getParameterSpec(stdDomainParam: PACEInfo.PARAM_ID_ECP_NIST_P256_R1))
        defer { EVP_PKEY_free(wrongStaticKey) }

        var chipAuthenticationData = [UInt8](repeating: 0x00, count: 32)
        chipAuthenticationData[31] = 0x02

        var mappingPublicKeyLength = 0
        XCTAssertEqual(
            NFCPRCalculateECDHCAMPublicKey(staticKey, &chipAuthenticationData, chipAuthenticationData.count, nil, &mappingPublicKeyLength),
            1
        )
        var mappingPublicKey = [UInt8](repeating: 0x00, count: mappingPublicKeyLength)
        XCTAssertEqual(
            NFCPRCalculateECDHCAMPublicKey(staticKey, &chipAuthenticationData, chipAuthenticationData.count, &mappingPublicKey, &mappingPublicKeyLength),
            1
        )

        let encryptionKey = [UInt8](0x01...0x10)
        let iv = AESEncrypt(key: encryptionKey, message: [UInt8](repeating: 0xFF, count: 16), iv: [UInt8](repeating: 0x00, count: 16))
        let encryptedCAMData = AESEncrypt(key: encryptionKey, message: pad(chipAuthenticationData, blockSize: 16), iv: iv)

        let result = try PACEChipAuthenticationMappingResult(
            mappingPublicKey: mappingPublicKey,
            encryptedChipAuthenticationData: encryptedCAMData,
            encryptionKey: encryptionKey
        )

        XCTAssertTrue(result.verifies(using: [
            ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: staticKey, ownsPublicKey: false)
        ]))
        XCTAssertFalse(result.verifies(using: [
            ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: wrongStaticKey, ownsPublicKey: false)
        ]))

        let malformedPaddedCAMData = [UInt8](repeating: 0xA5, count: 16)
        let encryptedMalformedCAMData = AESEncrypt(key: encryptionKey, message: malformedPaddedCAMData, iv: iv)
        XCTAssertThrowsError(try PACEChipAuthenticationMappingResult(
            mappingPublicKey: mappingPublicKey,
            encryptedChipAuthenticationData: encryptedMalformedCAMData,
            encryptionKey: encryptionKey
        )) { error in
            guard case NFCPassportReaderError.PACEError = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
        }
    }

    func testSupportedPACEIdentifiersHaveCompleteMetadata() throws {
        XCTAssertEqual(PACEInfo.allowedIdentifiers.count, 19)

        for oid in PACEInfo.allowedIdentifiers {
            let info = PACEInfo(oid: oid, version: 2, parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
            XCTAssertNoThrow(try info.getMappingType(), oid)
            XCTAssertNoThrow(try info.getKeyAgreementAlgorithm(), oid)
            XCTAssertNoThrow(try info.getCipherAlgorithm(), oid)
            XCTAssertNoThrow(try info.getDigestAlgorithm(), oid)
            XCTAssertNoThrow(try info.getKeyLength(), oid)
            XCTAssertNotEqual(info.getProtocolOIDString(), oid)
        }
    }

    func testSupportedChipAuthenticationIdentifiersHaveCompleteMetadata() throws {
        let supportedOIDs = [
            SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID,
            SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID,
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID,
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_192_OID,
            SecurityInfo.ID_CA_DH_AES_CBC_CMAC_256_OID,
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_192_OID,
            SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID
        ]

        for oid in supportedOIDs {
            XCTAssertTrue(ChipAuthenticationInfo.checkRequiredIdentifier(oid), oid)
            XCTAssertNoThrow(try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: oid), oid)
            XCTAssertNoThrow(try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid), oid)
            XCTAssertNoThrow(try ChipAuthenticationInfo.toKeyLength(oid: oid), oid)
            XCTAssertNotEqual(ChipAuthenticationInfo(oid: oid, version: 1).getProtocolOIDString(), oid)
        }
    }

    func testSecurityInfoParsesMultiByteOptionalIdentifiers() throws {
        let chipAuthentication = try securityInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID,
            requiredData: diagnosticASN1Integer([0x01]),
            optionalData: diagnosticASN1Integer([0x01, 0x00])
        )
        let chipInfo = try XCTUnwrap(SecurityInfosParser.parse(diagnosticASN1Set(chipAuthentication)).first as? ChipAuthenticationInfo)
        XCTAssertEqual(chipInfo.getKeyId(), 256)

        let pace = try securityInfo(
            oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            requiredData: diagnosticASN1Integer([0x02]),
            optionalData: diagnosticASN1Integer([0x01, 0x00])
        )
        let paceInfo = try XCTUnwrap(SecurityInfosParser.parse(diagnosticASN1Set(pace)).first as? PACEInfo)
        XCTAssertEqual(paceInfo.getParameterId(), 256)
    }

    func testUnknownSecurityInfoIsPreservedAsRedactedObject() throws {
        let sequenceItem = try securityInfo(
            oid: "1.2.3.4",
            requiredData: diagnosticASN1Integer([0x02])
        )
        let info = try XCTUnwrap(SecurityInfosParser.parse(diagnosticASN1Set(sequenceItem)).first)

        XCTAssertFalse(info.isRecognized)
        XCTAssertTrue(info is UnknownSecurityInfo)
        XCTAssertEqual(info.getProtocolOIDString(), "Unknown security info")
    }

    func testSecurityInfoRejectsInvalidPublicKeyWithoutTrapping() throws {
        let malformedPublicKeyInfo = try securityInfo(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            requiredData: diagnosticASN1Integer([0x01])
        )

        XCTAssertThrowsError(try SecurityInfosParser.parse(diagnosticASN1Set(malformedPublicKeyInfo))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testSecurityInfoRejectsOversizedPublicKeyBeforeOpenSSLParsing() throws {
        let malformedPublicKeyInfo = try securityInfo(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            requiredData: diagnosticASN1Integer([0x01])
        )
        let parsedInfo = try XCTUnwrap(try SimpleASN1Node.parse(malformedPublicKeyInfo))
        let requiredData = try XCTUnwrap(parsedInfo.children.dropFirst().first)

        XCTAssertThrowsError(try SecurityInfo.getInstance(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            requiredData: requiredData,
            requiredDataDER: [UInt8](repeating: 0x01, count: 64 * 1024 + 1),
            optionalData: nil
        )) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testCustomScanProfileDeduplicatesWithoutReordering() {
        let profile = PassportScanProfile.custom([.DG1, .DG2, .DG1, .SOD, .DG2])

        XCTAssertEqual(profile.dataGroups, [.DG1, .DG2, .SOD])
    }

    func testFailureMetadataProvidesRetryGuidanceWithoutSensitiveDetails() {
        let connectionFailure = NFCPassportReaderError.ConnectionError.privacySafeFailure
        XCTAssertEqual(connectionFailure.reason, .connectionLost)
        XCTAssertEqual(connectionFailure.stage, .unknown)
        XCTAssertTrue(connectionFailure.isRetryLikelyToHelp)
        XCTAssertFalse(connectionFailure.recoverySuggestion.localizedCaseInsensitiveContains("APDU"))

        let dataGroupFailure = NFCPassportReaderError.ConnectionError.privacySafeFailure(at: .readingDataGroup(.DG2))
        XCTAssertEqual(dataGroupFailure.stage, .readingDataGroup(.DG2))
        XCTAssertTrue(dataGroupFailure.isRetryLikelyToHelp)
        XCTAssertTrue(dataGroupFailure.recoverySuggestion.localizedCaseInsensitiveContains("steady"))

        let accessKeyFailure = NFCPassportReaderError.InvalidMRZKey.privacySafeFailure
        XCTAssertEqual(accessKeyFailure.reason, .accessKeyRejected)
        XCTAssertFalse(accessKeyFailure.isRetryLikelyToHelp)
        XCTAssertFalse(accessKeyFailure.recoverySuggestion.localizedCaseInsensitiveContains("MRZ"))
    }

    func testChipAuthenticationRetryClassificationDoesNotRequirePublicErrorValue() {
        XCTAssertTrue(NFCPassportReaderError.ConnectionError.shouldRetryDataGroupReadAfterChipAuthentication)
        XCTAssertTrue(
            NFCPassportReaderError.ResponseError("Class not supported", 0x6E, 0x00)
                .shouldRetryDataGroupReadAfterChipAuthentication
        )
        XCTAssertFalse(NFCPassportReaderError.InvalidMRZKey.shouldRetryDataGroupReadAfterChipAuthentication)
    }

    func testDataGroupRetryPolicyUsesTypedStatusWords() {
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x69, 0x82).shouldSkipDataGroupAndRedoBAC)
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x6A, 0x82).shouldSkipDataGroupAndRedoBAC)
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x69, 0x88).shouldRedoBACForDataGroupRead)
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x62, 0x82).shouldReduceReadAmountAndRedoBAC)
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x67, 0x00).shouldReduceReadAmountAndRedoBAC)
        XCTAssertTrue(NFCPassportReaderError.ResponseError("redacted", 0x6C, 0x20).shouldReduceReadAmountAndRedoBAC)
        XCTAssertTrue(NFCPassportReaderError.UnsupportedDataGroup.isUnsupportedDataGroupRead)
        XCTAssertFalse(NFCPassportReaderError.InvalidMRZKey.shouldRedoBACForDataGroupRead)
    }

    @MainActor
    func testSkippedDataGroupQueueRemovalTargetsCurrentGroup() {
        var dataGroups: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG11]

        PassportReader.removeDataGroup(.DG2, from: &dataGroups)

        XCTAssertEqual(dataGroups, [.COM, .SOD, .DG1, .DG11])
    }

    @available(iOS 15, *)
    func testStatusWordSuccessRequiresExact9000() {
        XCTAssertTrue(TagReader.isSuccessStatus(sw1: 0x90, sw2: 0x00))
        XCTAssertFalse(TagReader.isSuccessStatus(sw1: 0x90, sw2: 0x01))
        XCTAssertFalse(TagReader.isSuccessStatus(sw1: 0x91, sw2: 0x00))
    }

    @available(iOS 15, *)
    func testUnknownStatusWordMessageDoesNotExposeRawStatusBytes() {
        let message = TagReader.decodeError(sw1: 0x6F, sw2: 0x42)

        XCTAssertEqual(message, "Unknown passport chip response error")
        XCTAssertFalse(message.localizedCaseInsensitiveContains("sw1"))
        XCTAssertFalse(message.localizedCaseInsensitiveContains("sw2"))
        XCTAssertFalse(message.localizedCaseInsensitiveContains("6F"))
        XCTAssertFalse(message.localizedCaseInsensitiveContains("42"))
    }

    func testVerificationResultDefaultsToNotChecked() {
        let model = NFCPassportModel()
        let result = model.verificationResult

        XCTAssertEqual(result.sodSignatureStatus, .notChecked)
        XCTAssertEqual(result.dataGroupHashStatus, .notChecked)
        XCTAssertEqual(result.documentSignerCertificateStatus, .notChecked)
        XCTAssertEqual(result.countrySigningCertificateStatus, .notChecked)
        XCTAssertEqual(result.activeAuthenticationStatus, .notChecked)
        XCTAssertEqual(result.chipAuthenticationStatus, .notChecked)
        XCTAssertEqual(result.overallStatus, .notChecked)
        XCTAssertEqual(result.sodSignatureDetail.reason, .notRequested)
        XCTAssertEqual(result.activeAuthenticationDetail.reason, .notRequested)
        XCTAssertEqual(result.chipAuthenticationDetail.reason, .notRequested)
    }

    func testActiveAuthenticationStatusDistinguishesNotAdvertisedFromNotRequested() throws {
        let model = NFCPassportModel()
        let comWithoutDG15 = hexRepToBin("60185F0104303130375F36063034303030305C066175676B6C6E")
        guard let com = try DataGroupParser().parseDG(data: comWithoutDG15) as? COM else {
            XCTFail("Expected COM")
            return
        }

        model.addDataGroup(.COM, dataGroup: com)

        XCTAssertEqual(model.verificationResult.activeAuthenticationStatus, .notChecked)
        XCTAssertEqual(model.verificationResult.activeAuthenticationDetail.reason, .notSupported)
    }

    func testActiveAuthenticationStatusIsSkippedWhenDG15WasAdvertisedButNotRead() {
        let model = NFCPassportModel()

        model.recordDataGroupReadStatus(.advertised, for: .DG15)
        model.recordDataGroupReadStatus(.skippedByProfile, for: .DG15)

        XCTAssertEqual(model.verificationResult.activeAuthenticationStatus, .notChecked)
        XCTAssertEqual(model.verificationResult.activeAuthenticationDetail.reason, .skipped)
    }

    func testChipAuthenticationStatusIsSkippedWhenDG14WasAdvertisedButNotRead() {
        let model = NFCPassportModel()

        model.recordDataGroupReadStatus(.advertised, for: .DG14)
        model.recordDataGroupReadStatus(.skippedByProfile, for: .DG14)

        XCTAssertEqual(model.verificationResult.chipAuthenticationStatus, .notChecked)
        XCTAssertEqual(model.verificationResult.chipAuthenticationDetail.reason, .skipped)
    }

    func testOptionalAuthenticationStatusReportsFailedDataGroupReadsAsFailed() {
        let activeModel = NFCPassportModel()
        activeModel.recordDataGroupReadStatus(.advertised, for: .DG15)
        activeModel.recordDataGroupReadStatus(.failed, for: .DG15)

        XCTAssertEqual(activeModel.verificationResult.activeAuthenticationStatus, .failed)
        XCTAssertEqual(activeModel.verificationResult.activeAuthenticationDetail.reason, .attemptedFailed)

        let chipModel = NFCPassportModel()
        chipModel.recordDataGroupReadStatus(.advertised, for: .DG14)
        chipModel.recordDataGroupReadStatus(.failed, for: .DG14)

        XCTAssertEqual(chipModel.verificationResult.chipAuthenticationStatus, .failed)
        XCTAssertEqual(chipModel.verificationResult.chipAuthenticationDetail.reason, .attemptedFailed)
    }

    func testOptionalAuthenticationUnsupportedReadTakesPrecedenceOverTransientFailure() {
        let activeModel = NFCPassportModel()
        activeModel.recordDataGroupReadStatus(.advertised, for: .DG15)
        activeModel.recordDataGroupReadStatus(.failed, for: .DG15)
        activeModel.recordDataGroupReadStatus(.unsupported, for: .DG15)

        XCTAssertEqual(activeModel.verificationResult.activeAuthenticationStatus, .notChecked)
        XCTAssertEqual(activeModel.verificationResult.activeAuthenticationDetail.reason, .notSupported)

        let chipModel = NFCPassportModel()
        chipModel.recordDataGroupReadStatus(.advertised, for: .DG14)
        chipModel.recordDataGroupReadStatus(.failed, for: .DG14)
        chipModel.recordDataGroupReadStatus(.unsupported, for: .DG14)

        XCTAssertEqual(chipModel.verificationResult.chipAuthenticationStatus, .notChecked)
        XCTAssertEqual(chipModel.verificationResult.chipAuthenticationDetail.reason, .notSupported)
    }

    func testWhenSupportedPoliciesFailIfAdvertisedMechanismWasSkipped() {
        let activeModel = NFCPassportModel()
        activeModel.recordDataGroupReadStatus(.advertised, for: .DG15)
        activeModel.recordDataGroupReadStatus(.skippedByProfile, for: .DG15)

        XCTAssertFalse(PassportVerificationRequirement.activeAuthenticationWhenSupported.isSatisfied(by: activeModel))

        let chipModel = NFCPassportModel()
        chipModel.recordDataGroupReadStatus(.advertised, for: .DG14)
        chipModel.recordDataGroupReadStatus(.skippedByProfile, for: .DG14)

        XCTAssertFalse(PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: chipModel))
    }

    func testWhenSupportedPoliciesPassWhenMechanismWasNotAdvertised() throws {
        let model = NFCPassportModel()
        let comWithoutDG14OrDG15 = hexRepToBin("60175F0104303130375F36063034303030305C056175676B6C")
        guard let com = try DataGroupParser().parseDG(data: comWithoutDG14OrDG15) as? COM else {
            XCTFail("Expected COM")
            return
        }

        model.addDataGroup(.COM, dataGroup: com)

        XCTAssertTrue(PassportVerificationRequirement.activeAuthenticationWhenSupported.isSatisfied(by: model))
        XCTAssertTrue(PassportVerificationRequirement.chipAuthenticationWhenSupported.isSatisfied(by: model))
    }

    func testCountrySigningCertificateStatusIsNotCheckedWithoutMasterList() {
        let model = NFCPassportModel()

        model.verifyPassport(masterListURL: nil)

        XCTAssertTrue(model.passportVerificationAttempted)
        XCTAssertFalse(model.masterListWasProvided)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .notChecked)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateDetail.reason, .missingMasterList)
        XCTAssertFalse(model.revocationCheckPerformed)
    }

    func testVerifyPassportResetsErrorsBetweenAttempts() {
        let model = NFCPassportModel()

        model.verifyPassport(masterListURL: nil)
        XCTAssertEqual(model.verificationErrors.count, 1)

        model.verifyPassport(masterListURL: nil)
        XCTAssertEqual(model.verificationErrors.count, 1)
    }

    func testPhotoPolicyCanRemoveDG2FromRequestedGroups() {
        let requested: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG12]

        XCTAssertEqual(PassportPhotoPolicy.read.apply(to: requested), requested)
        XCTAssertEqual(PassportPhotoPolicy.skip.apply(to: requested), [.COM, .SOD, .DG1, .DG12])
    }

    func testDataGroupReadPolicyAppliesPrivacyFiltersAfterCOMExpansion() {
        let advertisedByCOM: [DataGroupId] = [.SOD, .DG1, .DG2, .DG3, .DG4, .DG7, .DG11, .DG12]
        let readAllPolicy = PassportDataGroupReadPolicy(
            requestedDataGroups: [.COM, .SOD],
            readAllDataGroups: true,
            skipSecureElements: true,
            photoPolicy: .skip
        )

        XCTAssertEqual(readAllPolicy.apply(to: advertisedByCOM), [.SOD, .DG1, .DG7, .DG11, .DG12])

        let explicitPolicy = PassportDataGroupReadPolicy(
            requestedDataGroups: [.COM, .SOD, .DG1, .DG2, .DG11],
            readAllDataGroups: false,
            skipSecureElements: false,
            photoPolicy: .skip
        )

        XCTAssertEqual(explicitPolicy.apply(to: advertisedByCOM), [.SOD, .DG1, .DG11])
    }

    func testIdentityOnlySecurityPolicyTurnsLegacyEmptyTagsIntoMinimalRead() {
        let requested = PassportDataGroupReadPolicy.requestedDataGroups(
            tags: [],
            photoPolicy: .read,
            securityPolicy: .identityOnly
        )

        XCTAssertEqual(requested, [.COM, .SOD, .DG1])
    }

    @available(iOS 15, *)
    @MainActor
    func testInitialDataGroupReadRequestRecordsLegacyReadAllStartupGroups() {
        let legacyReadAll = PassportReader.initialDataGroupReadRequest(
            tags: [],
            photoPolicy: .read,
            securityPolicy: .default
        )

        XCTAssertEqual(legacyReadAll.dataGroups, [.COM, .SOD])
        XCTAssertTrue(legacyReadAll.readAllDataGroups)

        let identityOnly = PassportReader.initialDataGroupReadRequest(
            tags: [],
            photoPolicy: .read,
            securityPolicy: .identityOnly
        )

        XCTAssertEqual(identityOnly.dataGroups, [.COM, .SOD, .DG1])
        XCTAssertFalse(identityOnly.readAllDataGroups)
    }

    func testSecurityPolicyCanDisallowPassportPhotoReads() {
        let policy = PassportReaderSecurityPolicy.identityOnly

        XCTAssertEqual(policy.apply(to: .read), .skip)
        XCTAssertEqual(policy.apply(to: .skip), .skip)
    }

    func testSecurityPolicyFailureUsesPrivacySafeError() {
        let policy = PassportReaderSecurityPolicy(verificationRequirement: .passiveAuthentication)
        let model = NFCPassportModel()

        XCTAssertThrowsError(try policy.validate(model)) { error in
            guard let readerError = error as? NFCPassportReaderError else {
                return XCTFail("Expected NFCPassportReaderError")
            }

            guard case .SecurityPolicyViolation = readerError else {
                return XCTFail("Expected SecurityPolicyViolation")
            }
            XCTAssertEqual(readerError.privacySafeFailure.reason, .verificationFailed)
            XCTAssertFalse(readerError.localizedDescription.localizedCaseInsensitiveContains("SOD"))
            XCTAssertFalse(readerError.localizedDescription.localizedCaseInsensitiveContains("hash"))
        }
    }

    func testIdentityResultOmitsRawMRZAndDataGroupBytes() {
        let model = NFCPassportModel()
        let result = model.identityResult

        XCTAssertEqual(result.documentNumber, "?")
        XCTAssertEqual(result.trustLevel, .inconclusive)
        XCTAssertEqual(result.certificateTrustMetadata.verificationAttempted, false)
        XCTAssertEqual(result.certificateTrustMetadata.masterListProvided, false)
        XCTAssertEqual(result.certificateTrustMetadata.revocationCheck.status, .notChecked)
        XCTAssertEqual(result.certificateTrustMetadata.revocationCheck.reason, .notRequested)
        XCTAssertEqual(result.verificationResult.overallStatus, .notChecked)
        XCTAssertFalse(Mirror(reflecting: result).children.contains { $0.label == "passportMRZ" })
    }

    func testCertificateTrustMetadataMakesRevocationNotCheckedExplicit() {
        let model = NFCPassportModel()

        model.verifyPassport(masterListURL: nil)

        let metadata = PassportCertificateTrustMetadata(passport: model)
        XCTAssertFalse(metadata.revocationCheckPerformed)
        XCTAssertEqual(metadata.revocationCheck.status, .notChecked)
        XCTAssertEqual(metadata.revocationCheck.reason, .notImplemented)
        XCTAssertFalse(metadata.revocationCheck.privacySafeExplanation.localizedCaseInsensitiveContains("certificate dump"))
        XCTAssertFalse(metadata.revocationCheck.privacySafeExplanation.localizedCaseInsensitiveContains("APDU"))
    }

    func testChipReadResultOmitsRawModelSurfaces() {
        let model = NFCPassportModel()
        let result = PassportChipReadResult(passport: model)

        XCTAssertEqual(result.identity.trustLevel, .inconclusive)
        XCTAssertEqual(result.verificationResult.overallStatus, .notChecked)
        XCTAssertFalse(Mirror(reflecting: result).children.contains { $0.label == "dataGroupsRead" })
        XCTAssertFalse(Mirror(reflecting: result).children.contains { $0.label == "passportImage" })
    }

    func testModelSensitiveCleanupRemovesRawExportMaterial() throws {
        let model = NFCPassportModel()
        let dataGroup = try DataGroup([0x61, 0x00])
        model.addDataGroup(.DG1, dataGroup: dataGroup)
        model.verifyActiveAuthentication(
            challenge: [UInt8](repeating: 0x01, count: 8),
            signature: [0x03, 0x04]
        )
        model.verifyPassport(masterListURL: nil)
        model.BACStatus = .success
        model.PACEStatus = .failed
        model.chipAuthenticationStatus = .success

        XCTAssertNotNil(model.getDataGroup(.DG1))
        XCTAssertFalse(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertFalse(model.activeAuthenticationSignature.isEmpty)
        XCTAssertTrue(model.passportVerificationAttempted)
        XCTAssertFalse(model.verificationErrors.isEmpty)

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG1))
        XCTAssertTrue(model.dataGroupsAvailable.isEmpty)
        XCTAssertTrue(model.dataGroupHashes.isEmpty)
        XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
        XCTAssertFalse(model.passportVerificationAttempted)
        XCTAssertFalse(model.masterListWasProvided)
        XCTAssertNil(model.masterListModifiedDate)
        XCTAssertFalse(model.revocationCheckPerformed)
        XCTAssertFalse(model.passportCorrectlySigned)
        XCTAssertFalse(model.documentSigningCertificateVerified)
        XCTAssertFalse(model.passportDataNotTampered)
        XCTAssertFalse(model.activeAuthenticationPassed)
        XCTAssertFalse(model.activeAuthenticationAttempted)
        XCTAssertEqual(model.BACStatus, .notDone)
        XCTAssertEqual(model.PACEStatus, .notDone)
        XCTAssertEqual(model.chipAuthenticationStatus, .notDone)
        XCTAssertTrue(model.verificationErrors.isEmpty)
        XCTAssertEqual(model.verificationResult.overallStatus, .notChecked)
        XCTAssertEqual(model.verificationResult.sodSignatureDetail.reason, .notRequested)
    }

    func testActiveAuthenticationRejectsMalformedInputsWithoutRetainingBytes() {
        let model = NFCPassportModel()
        let invalidInputs: [([UInt8], [UInt8])] = [
            ([], [0x01]),
            ([UInt8](repeating: 0xAA, count: 7), [0x01]),
            ([UInt8](repeating: 0xAA, count: 9), [0x01]),
            ([UInt8](repeating: 0xAA, count: 8), []),
            ([UInt8](repeating: 0xAA, count: 8), [UInt8](repeating: 0xBB, count: 64 * 1024 + 1))
        ]

        for (challenge, signature) in invalidInputs {
            model.verifyActiveAuthentication(challenge: challenge, signature: signature)

            XCTAssertFalse(model.activeAuthenticationPassed)
            XCTAssertTrue(model.activeAuthenticationAttempted)
            XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
            XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
            XCTAssertEqual(model.verificationResult.activeAuthenticationDetail.reason, .notRequested)
        }

        XCTAssertTrue(NFCPassportModel.isValidActiveAuthenticationInput(
            challenge: [UInt8](repeating: 0xAA, count: 8),
            signature: [0x01]
        ))
        XCTAssertFalse(NFCPassportModel.isValidActiveAuthenticationInput(
            challenge: [UInt8](repeating: 0xAA, count: 8),
            signature: [UInt8](repeating: 0xBB, count: 64 * 1024 + 1)
        ))
    }

    func testAddingAuthenticationDataGroupsInvalidatesDerivedAuthenticationState() throws {
        let model = NFCPassportModel()
        model.verifyActiveAuthentication(
            challenge: [UInt8](repeating: 0x01, count: 8),
            signature: [0x02, 0x03]
        )
        model.chipAuthenticationStatus = .success

        XCTAssertTrue(model.activeAuthenticationAttempted)
        XCTAssertFalse(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertFalse(model.activeAuthenticationSignature.isEmpty)
        XCTAssertEqual(model.chipAuthenticationStatus, .success)

        model.addDataGroup(.DG14, dataGroup: try DataGroup([0x6E, 0x00]))

        XCTAssertFalse(model.activeAuthenticationAttempted)
        XCTAssertFalse(model.activeAuthenticationPassed)
        XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
        XCTAssertEqual(model.chipAuthenticationStatus, .notDone)

        model.verifyActiveAuthentication(
            challenge: [UInt8](repeating: 0x04, count: 8),
            signature: [0x05, 0x06]
        )
        XCTAssertTrue(model.activeAuthenticationAttempted)

        model.addDataGroup(.DG15, dataGroup: try DataGroup([0x6F, 0x00]))

        XCTAssertFalse(model.activeAuthenticationAttempted)
        XCTAssertFalse(model.activeAuthenticationPassed)
        XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
    }

    @available(iOS 15, *)
    @MainActor
    func testReaderRejectsMalformedActiveAuthenticationChallengeBeforeSessionState() throws {
        let reader = PassportReader()

        for challenge in [[UInt8](), [UInt8](repeating: 0xAA, count: 7), [UInt8](repeating: 0xAA, count: 9)] {
            XCTAssertThrowsError(try reader.validateActiveAuthenticationChallengeBeforeSession(challenge)) { error in
                guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                    XCTFail("Expected MissingMandatoryFields, got \(error)")
                    return
                }
            }
        }

        XCTAssertNoThrow(try reader.validateActiveAuthenticationChallengeBeforeSession(nil))
        XCTAssertNoThrow(try reader.validateActiveAuthenticationChallengeBeforeSession([UInt8](repeating: 0xAA, count: 8)))
    }

    @available(iOS 15, *)
    @MainActor
    func testTagReaderProgressHandlerDoesNotRetainReaderAfterCancellation() {
        var reader: PassportReader? = PassportReader()
        weak let weakReader = reader
        let progressHandler = reader?.makeTagReaderProgressHandler(scanID: 1)

        reader = nil

        XCTAssertNil(weakReader)
        progressHandler?(50)
        progressHandler?(100)
    }

    @available(iOS 15, *)
    @MainActor
    func testReaderTimeoutNanosecondsRejectsInvalidValuesAndPreservesPrecision() {
        XCTAssertNil(PassportReader.safeTimeoutNanoseconds(for: nil))
        XCTAssertNil(PassportReader.safeTimeoutNanoseconds(for: 0))
        XCTAssertNil(PassportReader.safeTimeoutNanoseconds(for: -1))
        XCTAssertNil(PassportReader.safeTimeoutNanoseconds(for: .infinity))
        XCTAssertNil(PassportReader.safeTimeoutNanoseconds(for: .nan))

        XCTAssertEqual(PassportReader.safeTimeoutNanoseconds(for: 1.25), 1_250_000_000)
        XCTAssertEqual(PassportReader.safeTimeoutNanoseconds(for: 0.000_000_001), 1)
    }

    @available(iOS 15, *)
    @MainActor
    func testReaderTimeoutNanosecondsClampsExtremeFiniteValuesWithoutOverflow() throws {
        let hugeTimeout = try XCTUnwrap(PassportReader.safeTimeoutNanoseconds(for: .greatestFiniteMagnitude))
        XCTAssertGreaterThan(hugeTimeout, 0)
        XCTAssertLessThanOrEqual(hugeTimeout, UInt64.max)

        let maxWholeSeconds = TimeInterval(UInt64.max / 1_000_000_000)
        XCTAssertEqual(
            PassportReader.safeTimeoutNanoseconds(for: maxWholeSeconds + 60),
            PassportReader.safeTimeoutNanoseconds(for: maxWholeSeconds)
        )
    }

    @available(iOS 15, *)
    @MainActor
    func testStaleScanFailureDoesNotClearActiveScanState() throws {
        let reader = PassportReader()
        let scanID = try XCTUnwrap(reader.beginScanIfPossible())
        let staleScanID = scanID &+ 1

        reader.failActiveScan(error: .UserCanceled, scanID: staleScanID)

        XCTAssertTrue(reader.isActiveScan(scanID))

        reader.failActiveScan(error: .UserCanceled, scanID: scanID)

        XCTAssertFalse(reader.isActiveScan(scanID))
    }

    @available(iOS 15, *)
    @MainActor
    func testStaleScanPhaseCheckpointFailsClosed() throws {
        let reader = PassportReader()
        let scanID = try XCTUnwrap(reader.beginScanIfPossible())

        XCTAssertNoThrow(try reader.ensureActiveScan(scanID))

        reader.failActiveScan(error: .UserCanceled, scanID: scanID)

        XCTAssertThrowsError(try reader.ensureActiveScan(scanID)) { error in
            guard case NFCPassportReaderError.UserCanceled = error else {
                XCTFail("Expected UserCanceled, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testReaderSessionUserCancelSuppressionDoesNotLeakAcrossScans() throws {
        let reader = PassportReader()
        reader.suppressNextReaderSessionUserCancelForTesting()
        XCTAssertTrue(reader.isNextReaderSessionUserCancelSuppressedForTesting)

        let firstScanID = try XCTUnwrap(reader.beginScanIfPossible())
        XCTAssertFalse(reader.isNextReaderSessionUserCancelSuppressedForTesting)

        reader.suppressNextReaderSessionUserCancelForTesting()
        XCTAssertTrue(reader.isNextReaderSessionUserCancelSuppressedForTesting)

        reader.failActiveScan(error: .UserCanceled, scanID: firstScanID)
        XCTAssertFalse(reader.isNextReaderSessionUserCancelSuppressedForTesting)

        reader.suppressNextReaderSessionUserCancelForTesting()
        XCTAssertTrue(reader.isNextReaderSessionUserCancelSuppressedForTesting)

        let secondScanID = try XCTUnwrap(reader.beginScanIfPossible())
        reader.suppressNextReaderSessionUserCancelForTesting()
        reader.completeActiveScan(returning: NFCPassportModel(), scanID: secondScanID)

        XCTAssertFalse(reader.isNextReaderSessionUserCancelSuppressedForTesting)
        XCTAssertFalse(reader.isActiveScan(secondScanID))
    }

    func testModelSensitiveCleanupDoesNotKeepProjectedIdentityCaches() throws {
        let dg1 = try DataGroupParser().parseDG(data: diagnosticDataGroup1Fixture(mrz: diagnosticSyntheticTD3MRZ()))
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: dg1)

        let projected = model.identityResult

        XCTAssertEqual(projected.documentNumber, "ABC123456")
        XCTAssertEqual(projected.lastName, "DOE")
        XCTAssertEqual(projected.firstName, "JANE")
        XCTAssertEqual(model.documentNumber, "ABC123456")

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG1))
        XCTAssertEqual(model.documentNumber, "?")
        XCTAssertEqual(model.lastName, "?")
        XCTAssertEqual(model.firstName, "")
        XCTAssertEqual(model.dateOfBirth, "?")
        XCTAssertEqual(model.documentExpiryDate, "?")
    }

    @available(iOS 15, *)
    @MainActor
    func testReaderFailureCleanupScrubsPartiallyReadWorkingModel() throws {
        let reader = PassportReader()
        let workingModel = try XCTUnwrap(
            Mirror(reflecting: reader).descendant("passport") as? NFCPassportModel
        )
        let dataGroup = try DataGroup([0x61, 0x00])
        workingModel.addDataGroup(.DG1, dataGroup: dataGroup)
        workingModel.verifyActiveAuthentication(
            challenge: [UInt8](repeating: 0x01, count: 8),
            signature: [0x03, 0x04]
        )

        XCTAssertNotNil(workingModel.getDataGroup(.DG1))
        XCTAssertFalse(workingModel.activeAuthenticationChallenge.isEmpty)

        reader.discardSensitiveScanStateAfterFailure()

        XCTAssertNil(workingModel.getDataGroup(.DG1))
        XCTAssertTrue(workingModel.activeAuthenticationChallenge.isEmpty)
        XCTAssertTrue(workingModel.activeAuthenticationSignature.isEmpty)

        let replacementModel = try XCTUnwrap(
            Mirror(reflecting: reader).descendant("passport") as? NFCPassportModel
        )
        XCTAssertFalse(replacementModel === workingModel)
        XCTAssertTrue(replacementModel.dataGroupsAvailable.isEmpty)
        XCTAssertNil(replacementModel.getDataGroup(.DG1))
    }

    func testScanOptionsPresetsBindReviewedPolicyCombinations() {
        let strict = PassportScanOptions.notaryStrict

        XCTAssertEqual(strict.scanProfile, .fullVerification)
        XCTAssertFalse(strict.skipSecureElements)
        XCTAssertFalse(strict.skipCA)
        XCTAssertFalse(strict.skipPACE)
        XCTAssertTrue(strict.useExtendedMode)
        XCTAssertEqual(strict.operationTimeout, 60)
        XCTAssertEqual(strict.photoPolicy, .read)
        XCTAssertEqual(strict.securityPolicy, .notaryRecommended)

        let identityOnly = PassportScanOptions.identityOnly
        XCTAssertEqual(identityOnly.scanProfile, .identityOnly)
        XCTAssertEqual(identityOnly.photoPolicy, .skip)
        XCTAssertEqual(identityOnly.securityPolicy, .identityOnly)
        XCTAssertEqual(identityOnly.pacePolicy, .allowBACFallback)
    }

    @available(iOS 15, *)
    @MainActor
    func testPACEPolicyRequiresExplicitCredentialWithoutLoggingDetails() throws {
        let reader = PassportReader()

        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeAttempt())

        let strictOptions = PassportScanOptions(
            scanProfile: .identityOnly,
            pacePolicy: .requireExplicitCredential(.can)
        )
        XCTAssertEqual(strictOptions.pacePolicy, .requireExplicitCredential(.can))
    }

    @available(iOS 15, *)
    @MainActor
    func testStrictPACEPoliciesDoNotFallBackToBACAfterPACEFailure() {
        let reader = PassportReader()
        let error = NFCPassportReaderError.PACEError("Step1", "Synthetic failure")

        reader.configurePACEPolicyForTesting(.allowBACFallback)
        XCTAssertFalse(reader.shouldFailInsteadOfFallingBackFromPACE(error: error))

        reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised)
        XCTAssertTrue(reader.shouldFailInsteadOfFallingBackFromPACE(error: error))

        reader.configurePACEPolicyForTesting(.requireExplicitCredential(.can))
        XCTAssertTrue(reader.shouldFailInsteadOfFallingBackFromPACE(error: error))
    }

    @available(iOS 15, *)
    @MainActor
    func testStrictPACEPoliciesRejectSkipPACEBeforeSession() {
        let reader = PassportReader()

        reader.configurePACEPolicyForTesting(.allowBACFallback)
        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeSession(skipPACE: true))

        reader.configurePACEPolicyForTesting(.requirePACEWhenAdvertised)
        XCTAssertThrowsError(try reader.validatePACEPolicyBeforeSession(skipPACE: true)) { error in
            guard case NFCPassportReaderError.PACEError = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testExplicitPACECredentialPolicyRequiresMatchingCredentialAtBothGates() {
        let reader = PassportReader()

        reader.configurePACEPolicyForTesting(.requireExplicitCredential(.can))
        XCTAssertThrowsError(try reader.validatePACEPolicyBeforeSession(skipPACE: false)) { error in
            guard case NFCPassportReaderError.PACEError = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
        }

        reader.configurePACEPolicyForTesting(
            .requireExplicitCredential(.can),
            paceKey: "SYNTHETIC-CAN",
            paceKeyReference: .can,
            pendingPACEKey: "SYNTHETIC-CAN",
            pendingPACEKeyReference: .can
        )

        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeSession(skipPACE: false))
        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeAttempt())

        reader.configurePACEPolicyForTesting(
            .requireExplicitCredential(.can),
            paceKey: "SYNTHETIC-MRZ",
            paceKeyReference: .mrz,
            pendingPACEKey: "SYNTHETIC-CAN",
            pendingPACEKeyReference: .can
        )

        XCTAssertThrowsError(try reader.validatePACEPolicyBeforeAttempt()) { error in
            guard case NFCPassportReaderError.PACEError = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
        }
    }

    func testDataGroupReadReportsAreSafeAndCanTrackSkippedStates() throws {
        let model = NFCPassportModel()
        model.recordDataGroupReadStatus(.requested, for: .DG1)
        model.recordDataGroupReadStatus(.advertised, for: .DG2)
        model.recordDataGroupReadStatus(.blockedByPolicy, for: .DG2)

        let reports = model.identityResult.dataGroupReadReports
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG1, status: .requested)))
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG2, status: .blockedByPolicy)))
        XCTAssertFalse(String(describing: reports).localizedCaseInsensitiveContains("APDU"))
    }

    func testDataGroupReadReportsReplaceTransientFailureWithUnsupportedFinalState() {
        let model = NFCPassportModel()
        model.recordDataGroupReadStatus(.requested, for: .DG15)
        model.recordDataGroupReadStatus(.advertised, for: .DG15)
        model.recordDataGroupReadStatus(.failed, for: .DG15)
        model.recordDataGroupReadStatus(.unsupported, for: .DG15)

        let reports = model.identityResult.dataGroupReadReports
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG15, status: .requested)))
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG15, status: .advertised)))
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG15, status: .unsupported)))
        XCTAssertFalse(reports.contains(PassportDataGroupReadReport(dataGroup: .DG15, status: .failed)))
    }

    func testDataGroupReadReportsReplaceTransientFailureWithReadFinalState() {
        let model = NFCPassportModel()
        model.recordDataGroupReadStatus(.requested, for: .DG14)
        model.recordDataGroupReadStatus(.advertised, for: .DG14)
        model.recordDataGroupReadStatus(.failed, for: .DG14)
        model.recordDataGroupReadStatus(.read, for: .DG14)

        let reports = model.identityResult.dataGroupReadReports
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG14, status: .requested)))
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG14, status: .advertised)))
        XCTAssertTrue(reports.contains(PassportDataGroupReadReport(dataGroup: .DG14, status: .read)))
        XCTAssertFalse(reports.contains(PassportDataGroupReadReport(dataGroup: .DG14, status: .failed)))
    }

    func testInteroperabilityRecordRejectsIdentifyingLookingNotes() {
        let safe = PassportInteroperabilityRecord(
            issuingRegionCode: "USA",
            chipFeatureClass: "PACE+DG2",
            scanOptions: .notaryStrict,
            verificationResult: nil,
            trustLevel: nil,
            notes: "Older chip, synthetic note only"
        )
        XCTAssertTrue(safe.containsOnlyNonIdentifyingFields)

        let unsafe = PassportInteroperabilityRecord(
            issuingRegionCode: "USA",
            chipFeatureClass: "PACE+DG2",
            scanOptions: .notaryStrict,
            verificationResult: nil,
            trustLevel: nil,
            notes: "L898902C36UTO7408122F1204159ZE184226B"
        )
        XCTAssertFalse(unsafe.containsOnlyNonIdentifyingFields)
    }

    func testInteroperabilityRecordRejectsSensitiveLabelsAndSeparatedHex() {
        let sensitiveNotes = [
            "Passport number L898902C3",
            "DOB 740812, expiry 120415",
            "APDU A0 00 00 02 47 10 01",
            "KSenc 8F:DC:FE:75:9E:40:A4:DF",
            "Certificate fingerprint 11-22-33-44-55-66-77-88",
            "Face image was retained"
        ]

        for note in sensitiveNotes {
            let record = PassportInteroperabilityRecord(
                issuingRegionCode: "USA",
                chipFeatureClass: "PACE+DG2",
                scanOptions: .notaryStrict,
                verificationResult: nil,
                trustLevel: nil,
                notes: note
            )

            XCTAssertFalse(record.containsOnlyNonIdentifyingFields, note)
        }
    }

    func testIdentityResultRequiresActualDG7ImagePayloadForSignaturePresence() throws {
        let model = NFCPassportModel()
        let dg7WithoutImages = try XCTUnwrap(try DataGroupParser().parseDG(data: [0x67, 0x03, 0x02, 0x01, 0x00]) as? DataGroup7)
        model.addDataGroup(.DG7, dataGroup: dg7WithoutImages)

        XCTAssertFalse(model.identityResult.hasSignatureImage)
    }

    func testIdentityResultReportsNoFaceImageWhenDG2WasNotRead() {
        let modelWithoutDG2 = NFCPassportModel()
        XCTAssertFalse(modelWithoutDG2.identityResult.hasFaceImage)
    }

    func testChipReadResultDiagnosticsUsesEffectivePhotoPolicy() throws {
        let model = NFCPassportModel()
        let dg2Data = try diagnosticDataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2Data) as? DataGroup2)
        model.addDataGroup(.DG2, dataGroup: dg2)

        let skipped = PassportChipReadResult(
            passport: model,
            photoPolicy: .skip,
            securityPolicy: .identityOnly
        )
        XCTAssertNil(skipped.faceImageData)
        XCTAssertFalse(skipped.identity.hasFaceImage)
        XCTAssertEqual(skipped.diagnosticsSummary.photoPolicy, .skip)
        XCTAssertEqual(skipped.diagnosticsSummary.securityPolicy, .identityOnly)

        let read = PassportChipReadResult(passport: model, photoPolicy: .read)
        XCTAssertNotNil(read.faceImageData)
        XCTAssertTrue(read.identity.hasFaceImage)
        XCTAssertEqual(read.diagnosticsSummary.photoPolicy, .read)
        XCTAssertEqual(read.diagnosticsSummary.securityPolicy, .default)
    }

    func testDiagnosticsSummaryContainsOnlySafeScanMetadata() {
        let failureSummary = PassportReaderDiagnosticsSummary(
            scanProfile: .identityOnly,
            photoPolicy: .skip,
            securityPolicy: .identityOnly,
            failure: NFCPassportReaderError.ConnectionError.privacySafeFailure
        )

        XCTAssertEqual(failureSummary.failure?.reason, .connectionLost)
        XCTAssertNil(failureSummary.verificationResult)
        XCTAssertTrue(failureSummary.dataGroupsRead.isEmpty)

        let successSummary = PassportReaderDiagnosticsSummary(
            scanProfile: .identityWithPhoto,
            photoPolicy: .read,
            passport: NFCPassportModel()
        )

        XCTAssertEqual(successSummary.trustLevel, .inconclusive)
        XCTAssertEqual(successSummary.verificationResult?.overallStatus, .notChecked)
        XCTAssertEqual(successSummary.dataGroupReadReports, [])
        XCTAssertNil(successSummary.failure)
    }

    func testSuggestedPrivacyCopyDoesNotIncludeSensitiveExamples() {
        let copy = [
            PassportReaderPrivacyCopy.nfcConsent,
            PassportReaderPrivacyCopy.noRawDiagnostics,
            PassportReaderPrivacyCopy.verificationInconclusive
        ].joined(separator: "\n")

        for fragment in ["Kseed", "KSenc", "KSmac", "APDU", "RAPDU", "12345678", "FFD8FFE0"] {
            XCTAssertFalse(copy.localizedCaseInsensitiveContains(fragment))
        }
    }

    func testSecurityPolicyDoesNotExposeRawExportOptIn() {
        let labels = Mirror(reflecting: PassportReaderSecurityPolicy()).children.compactMap(\.label)

        XCTAssertFalse(labels.contains("allowsUnsafeRawDataExport"))
    }

    @available(iOS 15, *)
    func testFixtureReaderCanReturnSafeResultAndProgressWithoutNFC() async throws {
        let result = PassportChipReadResult(passport: NFCPassportModel())
        let fixture = PassportReaderFixture(result: .success(result))
        let progressRecorder = ProgressRecorder()

        let scannedResult = try await fixture.readPassportIdentity(
            mrzKey: "SYNTHETIC",
            scanProfile: .identityOnly,
            progressHandler: { progressRecorder.record($0) }
        )

        XCTAssertEqual(scannedResult, result)
        XCTAssertFalse(Mirror(reflecting: scannedResult).children.contains { $0.label == "dataGroupsRead" })
        XCTAssertEqual(progressRecorder.events, [.waitingForPassport, .complete])
    }

    @available(iOS 15, *)
    func testFixtureReaderCanReturnPrivacySafeFailureWithoutNFC() async {
        let fixture = PassportReaderFixture(result: .failure(.ConnectionError))

        do {
            _ = try await fixture.readPassportIdentity(mrzKey: "SYNTHETIC", scanProfile: .identityOnly)
            XCTFail("Expected fixture to throw")
        } catch let error as NFCPassportReaderError {
            XCTAssertEqual(error.privacySafeFailure.reason, .connectionLost)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    @available(iOS 15, *)
    func testFixtureReaderUsesSafeOptionsShape() async throws {
        let result = PassportChipReadResult(passport: NFCPassportModel())
        let fixture = PassportReaderFixture(result: .success(result))

        let scannedResult = try await fixture.readPassportIdentity(
            mrzKey: "SYNTHETIC",
            options: PassportScanOptions(
                scanProfile: .identityOnly,
                securityPolicy: PassportReaderSecurityPolicy(verificationRequirement: .passiveAuthentication),
                pacePolicy: .requirePACEWhenAdvertised
            )
        )

        XCTAssertEqual(scannedResult, result)
    }
}

private func diagnosticTLV(tag: [UInt8], value: [UInt8]) throws -> [UInt8] {
    try tag + toAsn1Length(value.count) + value
}

private func diagnosticDataGroup1Fixture(mrz: String) throws -> [UInt8] {
    let mrzBytes = [UInt8](mrz.utf8)
    let mrzDataObject = try diagnosticTLV(tag: [0x5F, 0x1F], value: mrzBytes)
    return try [0x61] + toAsn1Length(mrzDataObject.count) + mrzDataObject
}

private func diagnosticDataGroup2Fixture(imageBytes: [UInt8]) throws -> [UInt8] {
    let biometricHeader = try diagnosticTLV(tag: [0xA1], value: [0x80, 0x01, 0x01])
    let biometricData = try diagnosticTLV(
        tag: [0x5F, 0x2E],
        value: diagnosticISO19794FaceRecord(imageBytes: imageBytes)
    )
    let template = try diagnosticTLV(tag: [0x7F, 0x60], value: biometricHeader + biometricData)
    let body = try diagnosticTLV(tag: [0x7F, 0x61], value: diagnosticTLV(tag: [0x02], value: [0x01]) + template)
    return try [0x75] + toAsn1Length(body.count) + body
}

private func diagnosticISO19794FaceRecord(imageBytes: [UInt8]) -> [UInt8] {
    var record: [UInt8] = []
    record.reserveCapacity(46 + imageBytes.count)
    record += [0x46, 0x41, 0x43, 0x00]
    record += [0x30, 0x31, 0x30, 0x00]
    record += diagnosticFixedWidthBytes(46 + imageBytes.count, count: 4)
    record += diagnosticFixedWidthBytes(1, count: 2)
    record += diagnosticFixedWidthBytes(46 + imageBytes.count - 14, count: 4)
    record += diagnosticFixedWidthBytes(0, count: 2)
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00]
    record += diagnosticFixedWidthBytes(1, count: 2)
    record += diagnosticFixedWidthBytes(1, count: 2)
    record += [0x00, 0x00]
    record += [0x00, 0x00]
    record += [0x00, 0x00]
    record += imageBytes
    return record
}

private func diagnosticFixedWidthBytes(_ value: Int, count: Int) -> [UInt8] {
    (0..<count).map { shift in
        UInt8((value >> (8 * (count - shift - 1))) & 0xFF)
    }
}

private func diagnosticMRZPadded(_ value: String, length: Int) -> String {
    if value.count >= length {
        return String(value.prefix(length))
    }
    return value + String(repeating: "<", count: length - value.count)
}

private func diagnosticSyntheticTD3MRZ() -> String {
    let documentNumber = "ABC123456"
    let dateOfBirth = "700101"
    let expiryDate = "300101"
    let optionalData = String(repeating: "<", count: 14)
    let line1 = "P<UTO" + diagnosticMRZPadded("DOE<<JANE", length: 39)
    let documentNumberCheckDigit = diagnosticMRZCheckDigit(documentNumber)
    let dateOfBirthCheckDigit = diagnosticMRZCheckDigit(dateOfBirth)
    let expiryDateCheckDigit = diagnosticMRZCheckDigit(expiryDate)
    let optionalDataCheckDigit = diagnosticMRZCheckDigit(optionalData)
    let compositeCheckDigit = diagnosticMRZCheckDigit(
        documentNumber + documentNumberCheckDigit +
        dateOfBirth + dateOfBirthCheckDigit +
        expiryDate + expiryDateCheckDigit +
        optionalData + optionalDataCheckDigit
    )
    let line2 = documentNumber + documentNumberCheckDigit +
        "UTO" +
        dateOfBirth + dateOfBirthCheckDigit +
        "F" +
        expiryDate + expiryDateCheckDigit +
        optionalData + optionalDataCheckDigit +
        compositeCheckDigit
    return line1 + line2
}

private func diagnosticMRZCheckDigit(_ value: String) -> String {
    let weights = [7, 3, 1]
    let sum = value.utf8.enumerated().reduce(0) { partial, item in
        let (offset, byte) = item
        return partial + diagnosticMRZCharacterValue(byte) * weights[offset % weights.count]
    }
    return String(sum % 10)
}

private func diagnosticMRZCharacterValue(_ byte: UInt8) -> Int {
    switch byte {
    case 0x30...0x39:
        return Int(byte - 0x30)
    case 0x41...0x5A:
        return Int(byte - 0x41) + 10
    case 0x3C:
        return 0
    default:
        return 0
    }
}

private func diagnosticSequence(_ value: [UInt8]) throws -> [UInt8] {
    try diagnosticTLV(tag: [0x30], value: value)
}

private func diagnosticASN1Set(_ value: [UInt8]) throws -> [UInt8] {
    try diagnosticTLV(tag: [0x31], value: value)
}

private func diagnosticASN1Integer(_ value: [UInt8]) throws -> [UInt8] {
    try diagnosticTLV(tag: [0x02], value: value)
}

private func diagnosticASN1ObjectIdentifier(_ oid: String) -> [UInt8] {
    OpenSSLUtils.asn1EncodeOID(oid: oid)
}

private func securityInfo(
    oid: String,
    requiredData: [UInt8],
    optionalData: [UInt8]? = nil
) throws -> [UInt8] {
    try diagnosticSequence(
        diagnosticASN1ObjectIdentifier(oid) +
        requiredData +
        (optionalData ?? [])
    )
}
