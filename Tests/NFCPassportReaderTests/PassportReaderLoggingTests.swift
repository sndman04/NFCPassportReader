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

        XCTAssertFalse(error.localizedDescription.contains("["))
        XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("expected"))
        XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("received"))
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

    func testPhotoPolicyCanRemoveDG2FromRequestedGroups() {
        let requested: [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG12]

        XCTAssertEqual(PassportPhotoPolicy.read.apply(to: requested), requested)
        XCTAssertEqual(PassportPhotoPolicy.skip.apply(to: requested), [.COM, .SOD, .DG1, .DG12])
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
}
