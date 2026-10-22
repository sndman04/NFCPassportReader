import XCTest
@preconcurrency import CoreNFC
@testable import NFCPassportReader

/// Serialized by the scan task. Only non-identifying command names are retained.
final class ScriptedPassportTransport: PassportTagTransport, @unchecked Sendable {
    enum Mode { case missingCardAccess, noPACE, pace, fresh }
    let mode: Mode
    let rejectSelection: Bool
    let rejectBAC: Bool
    var selectionError: Error?
    var accessError: Error?
    var cardSecurityError: Error?
    var commands: [String] = []
    var selectedWithoutSecureMessaging = false
    private var gaCount = 0
    private let key = "synthetic-access-credential"
    private let challenge = Array(UInt8(1)...UInt8(8))
    private var cardAccess: [UInt8] {
        if mode == .noPACE { return [0x31, 0] }
        let info = oidToBytes(oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, replaceTag: false)
            + [0x02, 0x01, 0x02, 0x02, 0x01, UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)]
        return wrapDO(b: 0x31, arr: wrapDO(b: 0x30, arr: info))
    }

    init(_ mode: Mode, rejectSelection: Bool = false, rejectBAC: Bool = false) {
        self.mode = mode
        self.rejectSelection = rejectSelection
        self.rejectBAC = rejectBAC
    }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        switch apdu.instructionCode {
        case 0xA4:
            if apdu.p1Parameter == 4 {
                commands.append("select application")
                selectedWithoutSecureMessaging = apdu.instructionClass == 0
                XCTAssertTrue(selectedWithoutSecureMessaging)
                XCTAssertEqual(apdu.p2Parameter, 0x0C)
                XCTAssertTrue(apdu.data == Data([0xA0, 0, 0, 2, 0x47, 0x10, 1]))
                if let selectionError { throw selectionError }
                return (Data(), rejectSelection ? 0x69 : 0x90, rejectSelection ? 0x85 : 0)
            }
            if apdu.data == Data([1, 0x1D]) {
                if let cardSecurityError { throw cardSecurityError }
                return (Data(), 0x6A, 0x82)
            }
            commands.append("select access file")
            if let accessError { throw accessError }
            if mode == .missingCardAccess { return (Data(), 0x6A, 0x82) }
            return (Data(), 0x90, 0)
        case 0xB0:
            commands.append("read CardAccess")
            let offset = Int(apdu.p1Parameter) * 256 + Int(apdu.p2Parameter)
            return (Data(cardAccess.dropFirst(offset).prefix(apdu.expectedResponseLength)), 0x90, 0)
        case 0x22:
            commands.append("MSE")
            return (Data(), 0x90, 0)
        case 0x86:
            gaCount += 1
            XCTAssertEqual(apdu.instructionClass, 0x10)
            if gaCount == 1 {
                commands.append("GA nonce")
                XCTAssertTrue(apdu.data == Data([0x7C, 0]))
                return (Data(wrapDO(b: 0x7C, arr: wrapDO(b: 0x80, arr: Array(repeating: 1, count: 16)))), 0x90, 0)
            }
            commands.append("GA mapping rejected")
            return (Data(), 0x6A, 0x80)
        case 0x84:
            commands.append("BAC challenge")
            return (Data(challenge), 0x90, 0)
        case 0x82:
            commands.append("BAC mutual authentication")
            if rejectBAC { return (Data(), 0x63, 0) }
            // Synthetic chip performs the BAC response using the request's
            // fresh terminal nonce. No real document values or retained keys.
            let seed = Array(calcSHA1Hash(Array(key.utf8)).prefix(16))
            let generator = SecureMessagingSessionKeyGenerator()
            let enc = try generator.deriveKey(keySeed: seed, mode: .ENC_MODE)
            let macKey = try generator.deriveKey(keySeed: seed, mode: .MAC_MODE)
            let request = tripleDESDecrypt(key: enc, message: Array((apdu.data ?? Data()).prefix(32)), iv: Array(repeating: 0, count: 8))
            guard request.count == 32 else { throw NFCPassportReaderError.InvalidMRZKey }
            let response = challenge + request.prefix(8) + Array(repeating: UInt8(3), count: 16)
            let encrypted = tripleDESEncrypt(key: enc, message: Array(response), iv: Array(repeating: 0, count: 8))
            let checksum = mac(algoName: .DES, key: macKey, msg: pad(encrypted, blockSize: 8))
            return (Data(encrypted + checksum.prefix(8)), 0x90, 0)
        default:
            XCTFail("Unexpected command in synthetic transport")
            throw NFCPassportReaderError.UnexpectedError
        }
    }
}
