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
        XCTAssertEqual(NFCPassportReaderError.ScanAlreadyInProgress.privacySafeFailureReason.description, "unexpected read failure")
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

    func testScanProfilesMapToExpectedDataGroups() {
        XCTAssertEqual(PassportScanProfile.identityOnly.dataGroups, [.COM, .SOD, .DG1])
        XCTAssertEqual(PassportScanProfile.identityWithPhoto.dataGroups, [.COM, .SOD, .DG1, .DG2])
        XCTAssertEqual(PassportScanProfile.fullVerification.dataGroups, [.COM, .SOD, .DG1, .DG2, .DG12, .DG14, .DG15])
    }

    func testCustomScanProfileDeduplicatesWithoutReordering() {
        let profile = PassportScanProfile.custom([.DG1, .DG2, .DG1, .SOD, .DG2])

        XCTAssertEqual(profile.dataGroups, [.DG1, .DG2, .SOD])
    }

    func testFailureMetadataProvidesRetryGuidanceWithoutSensitiveDetails() {
        let connectionFailure = NFCPassportReaderError.ConnectionError.privacySafeFailure
        XCTAssertEqual(connectionFailure.reason, .connectionLost)
        XCTAssertTrue(connectionFailure.isRetryLikelyToHelp)
        XCTAssertFalse(connectionFailure.recoverySuggestion.localizedCaseInsensitiveContains("APDU"))

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
    }

    func testCountrySigningCertificateStatusIsNotCheckedWithoutMasterList() {
        let model = NFCPassportModel()

        model.verifyPassport(masterListURL: nil)

        XCTAssertTrue(model.passportVerificationAttempted)
        XCTAssertFalse(model.masterListWasProvided)
        XCTAssertEqual(model.verificationResult.countrySigningCertificateStatus, .notChecked)
    }

    func testPhotoPolicyCanRemoveDG2FromRequestedGroups() {
        let requested: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG12]

        XCTAssertEqual(PassportPhotoPolicy.read.apply(to: requested), requested)
        XCTAssertEqual(PassportPhotoPolicy.skip.apply(to: requested), [.COM, .SOD, .DG1, .DG12])
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

    func testUnsafeRawExporterRequiresExplicitPolicyOptIn() throws {
        let model = NFCPassportModel()
        let dataGroup = try DataGroup([0x61, 0x00])
        model.addDataGroup(.DG1, dataGroup: dataGroup)

        let blockedExporter = UnsafePassportRawDataExporter(securityPolicy: .default)
        XCTAssertThrowsError(
            try blockedExporter.unsafeExportRawPassportData(from: model, selectedDataGroups: [.DG1])
        ) { error in
            guard case .RawDataExportNotAllowed = error as? NFCPassportReaderError else {
                return XCTFail("Expected RawDataExportNotAllowed")
            }
        }

        let explicitPolicy = PassportReaderSecurityPolicy(allowsUnsafeRawDataExport: true)
        let allowedExporter = UnsafePassportRawDataExporter(securityPolicy: explicitPolicy)
        let exported = try allowedExporter.unsafeExportRawPassportData(from: model, selectedDataGroups: [.DG1])

        XCTAssertEqual(exported["DG1"], Data([0x61, 0x00]).base64EncodedString())
    }

    @available(iOS 15, *)
    func testFixtureReaderCanReturnModelAndProgressWithoutNFC() async throws {
        let fixture = PassportReaderFixture(result: .success(NFCPassportModel()))
        let progressRecorder = ProgressRecorder()

        let model = try await fixture.readPassport(
            mrzKey: "SYNTHETIC",
            scanProfile: .identityOnly,
            progressHandler: { progressRecorder.record($0) }
        )

        XCTAssertNotNil(model)
        XCTAssertEqual(progressRecorder.events, [.waitingForPassport, .complete])
    }

    @available(iOS 15, *)
    func testFixtureReaderCanReturnPrivacySafeFailureWithoutNFC() async {
        let fixture = PassportReaderFixture(result: .failure(.ConnectionError))

        do {
            _ = try await fixture.readPassport(mrzKey: "SYNTHETIC", scanProfile: .identityOnly)
            XCTFail("Expected fixture to throw")
        } catch let error as NFCPassportReaderError {
            XCTAssertEqual(error.privacySafeFailure.reason, .connectionLost)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    @available(iOS 15, *)
    func testFixtureReaderAppliesSecurityPolicy() async {
        let fixture = PassportReaderFixture(result: .success(NFCPassportModel()))

        do {
            _ = try await fixture.readPassport(
                mrzKey: "SYNTHETIC",
                scanProfile: .identityOnly,
                securityPolicy: PassportReaderSecurityPolicy(verificationRequirement: .passiveAuthentication)
            )
            XCTFail("Expected policy failure")
        } catch let error as NFCPassportReaderError {
            guard case .SecurityPolicyViolation = error else {
                return XCTFail("Expected SecurityPolicyViolation")
            }
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}
