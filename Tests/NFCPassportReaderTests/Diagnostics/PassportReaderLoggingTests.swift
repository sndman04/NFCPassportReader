import XCTest

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

    func testASN1DebugDescriptionRedactsParsedValues() {
        let item = ASN1Item(line: "0:d=1  hl=2 l=  16 prim: OCTET STRING      :00112233445566778899AABBCCDDEEFF")
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

    func testPACEInfoSelectionPrefersImplementedGMOverEarlierUnsupportedMapping() {
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

        XCTAssertFalse(im.isImplementedForReading)
        XCTAssertTrue(gm.isImplementedForReading)

        let infos = [im, gm]
        let ordered = infos.filter { $0.isImplementedForReading } + infos.filter { !$0.isImplementedForReading }

        XCTAssertTrue(ordered.first === gm)
    }

    func testUnknownSecurityInfoIsPreservedAsRedactedObject() throws {
        let sequenceItem = ASN1Item(line: "0:d=1  hl=2 l=  10 cons: SEQUENCE")
        sequenceItem.addChild(ASN1Item(line: "0:d=2  hl=2 l=   4 prim: OBJECT            :1.2.3.4"))
        sequenceItem.addChild(ASN1Item(line: "0:d=2  hl=2 l=   1 prim: INTEGER           :02"))

        let info = try XCTUnwrap(SecurityInfo.getInstance(object: sequenceItem, body: []))

        XCTAssertFalse(info.isRecognized)
        XCTAssertTrue(info is UnknownSecurityInfo)
        XCTAssertEqual(info.getProtocolOIDString(), "Unknown security info")
    }

    func testSecurityInfoRejectsInvalidPublicKeyOffsetsWithoutTrapping() {
        let sequenceItem = ASN1Item(line: "0:d=1  hl=2 l=  10 cons: SEQUENCE")
        sequenceItem.addChild(ASN1Item(line: "0:d=2  hl=2 l=   4 prim: OBJECT            :0.4.0.127.0.7.2.2.1.2"))
        sequenceItem.addChild(ASN1Item(line: "0:d=2  hl=-1 l=   1 prim: SEQUENCE"))

        XCTAssertNil(SecurityInfo.getInstance(object: sequenceItem, body: [0x30, 0x00]))
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
        XCTAssertEqual(result.activeAuthenticationDetail.reason, .notSupported)
        XCTAssertEqual(result.chipAuthenticationDetail.reason, .notSupported)
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
        XCTAssertEqual(result.verificationResult.overallStatus, .notChecked)
        XCTAssertFalse(Mirror(reflecting: result).children.contains { $0.label == "passportMRZ" })
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
        model.verifyActiveAuthentication(challenge: [0x01, 0x02], signature: [0x03, 0x04])

        XCTAssertNotNil(model.getDataGroup(.DG1))
        XCTAssertFalse(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertFalse(model.activeAuthenticationSignature.isEmpty)

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG1))
        XCTAssertTrue(model.dataGroupsAvailable.isEmpty)
        XCTAssertTrue(model.dataGroupHashes.isEmpty)
        XCTAssertTrue(model.activeAuthenticationChallenge.isEmpty)
        XCTAssertTrue(model.activeAuthenticationSignature.isEmpty)
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
    func testPACEPolicyRequiresExplicitCredentialWithoutLoggingDetails() throws {
        let reader = PassportReader()

        XCTAssertNoThrow(try reader.validatePACEPolicyBeforeAttempt())

        let strictOptions = PassportScanOptions(
            scanProfile: .identityOnly,
            pacePolicy: .requireExplicitCredential(.can)
        )
        XCTAssertEqual(strictOptions.pacePolicy, .requireExplicitCredential(.can))
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

    func testIdentityResultRequiresActualDG7ImagePayloadForSignaturePresence() throws {
        let model = NFCPassportModel()
        let dg7WithoutImages = try XCTUnwrap(try DataGroupParser().parseDG(data: [0x67, 0x03, 0x02, 0x01, 0x00]) as? DataGroup7)
        model.addDataGroup(.DG7, dataGroup: dg7WithoutImages)

        XCTAssertFalse(model.identityResult.hasSignatureImage)
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
