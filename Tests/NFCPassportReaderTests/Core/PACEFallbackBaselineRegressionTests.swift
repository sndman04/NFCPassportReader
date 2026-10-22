import XCTest
@testable import NFCPassportReader

/// These tests also run unchanged on d31fefb with only transport/configuration
/// injection backported (no recovery or authentication changes). Both fail there.
@MainActor
final class PACEFallbackBaselineRegressionTests: XCTestCase {
    func testFailedGAChainIsDiscardedBeforeApplicationSelection() async throws {
        let reader = PassportReader()
        reader.configureAccessForTesting(mrzKey: "synthetic-access-credential")
        let scan = try XCTUnwrap(reader.beginScanIfPossible())
        let transport = ScriptedPassportTransport(.pace)
        do { _ = try await reader.startReading(tagReader: TagReader(transport: transport), scanID: scan) }
        catch { /* Stop at the recovery boundary; no physical NFC session in tests. */ }
        XCTAssertEqual(transport.commands.last, "GA mapping rejected")
        XCTAssertFalse(transport.commands.contains("select application"), "Do not select on an incomplete GA connection")
        XCTAssertFalse(transport.commands.contains("BAC challenge"))
    }

    func testFailedPACEStateIsClearedBeforeFallbackSelect() async throws {
        let reader = PassportReader()
        reader.configureAccessForTesting(mrzKey: "synthetic-access-credential")
        let scan = try XCTUnwrap(reader.beginScanIfPossible())
        let transport = ScriptedPassportTransport(.missingCardAccess, rejectSelection: true)
        let tag = TagReader(transport: transport)
        tag.secureMessaging = SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
        do { _ = try await reader.startReading(tagReader: tag, scanID: scan) }
        catch { /* Stop at rejected selection/recovery; inspect only safe state. */ }
        XCTAssertTrue(transport.selectedWithoutSecureMessaging)
        XCTAssertNil(tag.secureMessaging)
        XCTAssertFalse(transport.commands.contains("BAC challenge"))
    }
}
