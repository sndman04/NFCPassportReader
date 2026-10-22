import XCTest
import OpenSSL
import OpenSSLCompat
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class PACEConversationTests: XCTestCase {
    func testRealECDHGenericMappingCompletesAllPACECommands() async throws {
        try await runPACE(isDH: false)
    }

    func testRealDHGenericMappingCompletesAllPACECommands() async throws {
        try await runPACE(isDH: true)
    }

    func testPACERejectsReflectedEphemeralKeyBeforeTokenExchange() async throws {
        try await runPACE(isDH: false, reflectKey: true)
    }

    private func runPACE(isDH: Bool, reflectKey: Bool = false) async throws {
        let credential = "synthetic-access-credential"
        let oid = isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128
        let info = PACEInfo(oid: oid, version: 2, parameterId: isDH ? PACEInfo.PARAM_ID_GFP_1024_160 : PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
        let mappingKey = try isDH ? OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1) : OpenSSLUtils.generateECKeyPair(curveNID: NID_X9_62_prime256v1)
        defer { EVP_PKEY_free(mappingKey) }
        let nonce = Array(repeating: UInt8(3), count: 16)
        let passwordKey = try PACEHandler.createPaceKey(from: credential, cipherAlg: "AES", keyLength: 128)
        var ephemeral: OpaquePointer?
        var terminal: OpaquePointer?
        var macKey: [UInt8] = []
        defer { EVP_PKEY_free(ephemeral); EVP_PKEY_free(terminal); macKey.removeAll() }
        weak var handler: PACEHandler?
        var step = 0
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0x22 { return (Data(), 0x90, 0) }
            XCTAssertEqual(command.instructionCode, 0x86)
            step += 1
            XCTAssertEqual(command.instructionClass, step == 4 ? 0 : 0x10)
            let input = try unwrapDO(tag: 0x7C, wrappedData: Array(command.data ?? Data()))
            let response: [UInt8]
            switch step {
            case 1:
                XCTAssertTrue(input.isEmpty)
                response = wrapDO(b: 0x80, arr: AESEncrypt(key: passwordKey, message: nonce, iv: Array(repeating: 0, count: 16)))
            case 2:
                let terminalMapping = try unwrapDO(tag: 0x81, wrappedData: input)
                let nonceBN = try XCTUnwrap(nonce.withUnsafeBufferPointer { BN_bin2bn($0.baseAddress, Int32($0.count), nil) })
                defer { BN_clear_free(nonceBN) }
                let parameters = try XCTUnwrap(terminalMapping.withUnsafeBufferPointer {
                    isDH ? NFCPRCreateDHMappedParameters(mappingKey, $0.baseAddress, $0.count, nonceBN)
                        : NFCPRCreateECDHMappedParameters(mappingKey, $0.baseAddress, $0.count, nonceBN)
                })
                defer { EVP_PKEY_free(parameters) }
                ephemeral = try OpenSSLUtils.generateKeyPair(fromParameters: parameters)
                response = wrapDO(b: 0x82, arr: try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: mappingKey)))
            case 3:
                if reflectKey {
                    response = wrapDO(b: 0x84, arr: try unwrapDO(tag: 0x83, wrappedData: input))
                    break
                }
                let chipKey = try XCTUnwrap(ephemeral)
                terminal = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: try unwrapDO(tag: 0x83, wrappedData: input), params: chipKey)
                let secret = try OpenSSLUtils.computeSharedSecret(privateKeyPair: chipKey, publicKey: XCTUnwrap(terminal))
                macKey = try SecureMessagingSessionKeyGenerator().deriveKey(keySeed: secret, cipherAlgName: "AES", keyLength: 128, mode: .MAC_MODE)
                response = wrapDO(b: 0x84, arr: try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: chipKey)))
            case 4:
                let token = try unwrapDO(tag: 0x85, wrappedData: input)
                let pace = try XCTUnwrap(handler)
                let expected = try pace.generateAuthenticationToken(publicKey: XCTUnwrap(ephemeral), macKey: macKey)
                XCTAssertTrue(token == expected, "Synthetic chip must verify the terminal token")
                response = wrapDO(b: 0x86, arr: try pace.generateAuthenticationToken(publicKey: XCTUnwrap(terminal), macKey: macKey))
            default:
                XCTFail("Unexpected authentication step")
                throw NFCPassportReaderError.UnexpectedError
            }
            return (Data(wrapDO(b: 0x7C, arr: response)), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let pace = PACEHandler(paceInfo: info, tagReader: tag)
        handler = pace
        if reflectKey {
            do { try await pace.doPACE(mrzKey: credential); XCTFail("Expected reflected key rejection") }
            catch NFCPassportReaderError.PACEError { } catch { XCTFail("Wrong reflected-key failure") }
            XCTAssertEqual(step, 3)
            XCTAssertNil(tag.secureMessaging)
        } else {
            try await pace.doPACE(mrzKey: credential)
            XCTAssertEqual(step, 4)
            XCTAssertNotNil(tag.secureMessaging)
            XCTAssertFalse(tag.generalAuthenticationChainOpen)
        }
        XCTAssertFalse(transport.commands.contains(0x84))
        tag.disconnect()
    }
}
