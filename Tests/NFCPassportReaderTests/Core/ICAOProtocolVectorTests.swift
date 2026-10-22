import XCTest
import OpenSSL
import OpenSSLCompat
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class ICAOProtocolVectorTests: XCTestCase {
    func testECDHGenericMappingPublishedConversation() async throws { try await pace("ecdh") }
    func testDHGenericMappingPublishedConversationWithAuthorityReference() async throws { try await pace("dh") }
    func testChipAuthenticationMappingPublishedConversation() async throws { try await pace("cam") }
    func testPublishedPACERejectsAlteredAuthenticationToken() async throws { try await pace("ecdh", corruptToken: true) }
    func testPublishedGMRejectsUnexpectedCAMData() async throws { try await pace("ecdh", unexpectedCAM: true) }
    func testPublishedCAMRejectsUnrelatedStaticKey() async throws { try await pace("cam", wrongStaticKey: true) }

    private func pace(_ name: String, corruptToken: Bool = false, wrongStaticKey: Bool = false, unexpectedCAM: Bool = false) async throws {
        let vector = try ICAOVector(name)
        var step = 0
        let transport = LifecycleTransport { command, _ in
            guard step < 5 else { throw VectorError.invalidFixture }
            let expected = try XCTUnwrap(NFCISO7816APDU(data: Data(vector.bytes("command\(step)"))))
            XCTAssertEqual(command.instructionClass, expected.instructionClass)
            XCTAssertEqual(command.instructionCode, expected.instructionCode)
            XCTAssertEqual(command.p1Parameter, expected.p1Parameter)
            XCTAssertEqual(command.p2Parameter, expected.p2Parameter)
            // CoreNFC parses encoded Le=00 as zero on some SDK versions.
            XCTAssertEqual(command.expectedResponseLength, step == 0 ? -1 : 256)
            XCTAssertTrue(command.data == expected.data, "ICAO command mismatch at step \(step); lengths \(command.data?.count ?? 0)/\(expected.data?.count ?? 0); bytes suppressed")
            var response = try vector.bytes("response\(step)")
            if corruptToken && step == 4 { response[4] ^= 1 }
            if unexpectedCAM && step == 4 {
                let body = try unwrapDO(tag: 0x7C, wrappedData: Array(response.dropLast(2)))
                response = wrapDO(b: 0x7C, arr: body + wrapDO(b: 0x8A, arr: Array(repeating: 1, count: 16))) + [0x90, 0]
            }
            step += 1
            return (Data(response.dropLast(2)), response[response.count - 2], response.last!)
        }
        let info = VectorPACEInfo(vector: vector, cam: name == "cam")
        let tag = TagReader(transport: transport)
        defer { tag.disconnect() }
        let handler = VectorPACEHandler(paceInfo: info, tagReader: tag)
        if corruptToken || unexpectedCAM {
            do { try await handler.doPACE(mrzKey: XCTUnwrap(vector.fields["credential"])); XCTFail("Expected token rejection") }
            catch NFCPassportReaderError.PACEError { } catch { XCTFail("Wrong token failure category") }
            XCTAssertNil(tag.secureMessaging)
            XCTAssertNil(handler.chipAuthenticationMappingResult)
        } else {
            try await handler.doPACE(mrzKey: XCTUnwrap(vector.fields["credential"]))
            XCTAssertNotNil(tag.secureMessaging)
            XCTAssertFalse(tag.generalAuthenticationChainOpen)
            if name == "cam" {
                let parameters = try vector.parameters()
                defer { EVP_PKEY_free(parameters) }
                let key = try wrongStaticKey ? OpenSSLUtils.generateECKeyPair(curveNID: NID_brainpoolP256r1)
                    : XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: vector.bytes("staticPublic"), params: parameters))
                let publicInfo = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: key)
                XCTAssertEqual(try XCTUnwrap(handler.chipAuthenticationMappingResult).verifies(using: [publicInfo]), !wrongStaticKey)
            }
        }
        XCTAssertEqual(step, 5)
        XCTAssertFalse(transport.commands.contains(0x84))
    }

    func testECDHIntegratedMappingPublishedVector() throws { try integrated("im_ecdh") }
    func testDHIntegratedMappingPublishedVector() throws { try integrated("im_dh") }

    private func integrated(_ name: String) throws {
        let v = try ICAOVector(name)
        let clear = AESDecrypt(key: try v.bytes("passwordKey"), message: try v.bytes("encryptedNonce"), iv: Array(repeating: 0, count: 16))
        XCTAssertTrue(clear == (try v.bytes("nonce")), "ICAO nonce mismatch")
        let field = try PACEHandler.integratedMappingField(passportNonce: v.bytes("nonce"), terminalNonce: v.bytes("terminalNonce"), cipherAlg: "AES", keyLength: 128, primeBitLength: v.isDH ? 1024 : 256)
        XCTAssertTrue(field == (try v.bytes("field")), "ICAO integrated mapping PRF mismatch")
        let domain = try v.parameters()
        defer { EVP_PKEY_free(domain) }
        let parameters = try XCTUnwrap(field.withUnsafeBufferPointer {
            v.isDH ? NFCPRCreateDHIntegratedMappedParameters(domain, $0.baseAddress, $0.count)
                : NFCPRCreateECDHIntegratedMappedParameters(domain, $0.baseAddress, $0.count)
        })
        defer { EVP_PKEY_free(parameters) }
        try assertGenerator(parameters, vector: v)
        let terminal = try importVectorKey(parameters: parameters, privateBytes: v.bytes("ephemeralPrivate"), publicBytes: v.bytes("ephemeralPublic"), isDH: v.isDH)
        defer { EVP_PKEY_free(terminal) }
        let chip = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: v.bytes("chipEphemeralPublic"), params: terminal))
        defer { EVP_PKEY_free(chip) }
        let secret = try OpenSSLUtils.computeSharedSecret(privateKeyPair: terminal, publicKey: chip)
        XCTAssertTrue(secret == (try v.bytes("secret")), "ICAO IM shared-secret mismatch")
        for (name, mode) in [("enc", SecureMessagingSessionKeyGenerator.SMSMode.ENC_MODE), ("mac", .MAC_MODE)] {
            XCTAssertTrue(try SecureMessagingSessionKeyGenerator().deriveKey(keySeed: secret, cipherAlgName: "AES", keyLength: 128, mode: mode) == v.bytes(name), "ICAO IM session-key mismatch")
        }
        let oid = v.isDH ? SecurityInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128
        let tag = TagReader(transport: LifecycleTransport { _, _ in throw VectorError.invalidFixture })
        let handler = PACEHandler(paceInfo: PACEInfo(oid: oid, version: 2, parameterId: v.isDH ? 0 : 13), tagReader: tag)
        for (key, name) in [(chip, "terminalToken"), (terminal, "chipToken")] {
            let input = try handler.encodePublicKey(oid: oid, key: key)
            let token = Array(OpenSSLUtils.generateAESCMAC(key: try v.bytes("mac"), message: input).prefix(8))
            XCTAssertTrue(token == (try v.bytes(name)), "ICAO IM token mismatch")
        }
    }

    func testBACPublishedKeysAgreeIncludingDESParityConvention() throws {
        let v = try ICAOVector("bac")
        let handler = BACHandler()
        let credential = try XCTUnwrap(v.fields["credential"])
        XCTAssertTrue(handler.generateInitialKseed(kmrz: credential) == (try v.bytes("seed")))
        let (enc, mac) = try handler.deriveDocumentBasicAccessKeys(mrz: credential)
        // DES parity bits do not affect encryption; implementation expands K1/K2/K1.
        for (actual, name) in [(enc, "enc"), (mac, "mac")] {
            let expected = try v.bytes(name)
            XCTAssertTrue(actual.prefix(16).map { $0 & 0xFE } == expected.map { $0 & 0xFE })
            XCTAssertTrue(actual.suffix(8) == actual.prefix(8))
        }
        handler.removeSensitiveData()
    }

    func testEveryPublishedBACResponseByteIsAuthenticated() throws {
        let v = try ICAOVector("bac")
        let handler = VectorBACHandler()
        handler.vector = v
        _ = try handler.deriveDocumentBasicAccessKeys(mrz: XCTUnwrap(v.fields["credential"]))
        _ = try handler.authentication(rnd_icc: v.bytes("chipRandom"))
        let response = try v.bytes("response")
        for offset in response.indices {
            var altered = response
            altered[offset] ^= 1
            XCTAssertThrowsError(try handler.sessionKeys(data: altered)) { error in
                guard case NFCPassportReaderError.InvalidResponseChecksum = error else { return XCTFail("Wrong integrity failure") }
            }
        }
        handler.removeSensitiveData()
    }

    func testPublishedSecureResponseRejectsReplayAndEveryByteMutation() throws {
        let v = try ICAOVector("bac")
        let wire = try v.bytes("responseSM0")
        func messaging() throws -> SecureMessaging {
            let sm = SecureMessaging(ksenc: try v.bytes("sessionEnc"), ksmac: try v.bytes("sessionMac"), ssc: try v.bytes("counter"))
            _ = try sm.protect(apdu: NFCISO7816APDU(instructionClass: 0, instructionCode: 0xA4, p1Parameter: 2, p2Parameter: 0x0C, data: Data([1, 0x1E]), expectedResponseLength: -1))
            return sm
        }
        let response = ResponseAPDU(data: Array(wire.dropLast(2)), sw1: 0x90, sw2: 0)
        let sm = try messaging()
        _ = try sm.unprotect(rapdu: response)
        XCTAssertThrowsError(try sm.unprotect(rapdu: response))
        for offset in 0..<wire.count - 2 {
            var altered = Array(wire.dropLast(2))
            altered[offset] ^= 1
            XCTAssertThrowsError(try messaging().unprotect(rapdu: ResponseAPDU(data: altered, sw1: 0x90, sw2: 0)))
        }
    }

    func testBACPublishedAuthenticationAndSecureMessagingSequence() async throws {
        let v = try ICAOVector("bac")
        let transport = LifecycleTransport { command, index in
            if index == 1 {
                XCTAssertEqual(command.instructionCode, 0x84)
                return (Data(try v.bytes("chipRandom")), 0x90, 0)
            }
            XCTAssertEqual(command.instructionCode, 0x82)
            XCTAssertTrue(command.data == Data(try v.bytes("command")), "ICAO BAC command mismatch")
            return (Data(try v.bytes("response")), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let bac = VectorBACHandler(tagReader: tag)
        bac.vector = v
        try await bac.performBACAndGetSessionKeys(mrzKey: XCTUnwrap(v.fields["credential"]))
        let sm = try XCTUnwrap(tag.secureMessaging)
        XCTAssertTrue(sm.sequenceCounter == (try v.bytes("counter")))
        let plainCommands: [[UInt8]] = [[0, 0xA4, 2, 0x0C, 2, 1, 0x1E], [0, 0xB0, 0, 0, 4], [0, 0xB0, 0, 4, 0x12]]
        var file: [UInt8] = []
        for (index, plain) in plainCommands.enumerated() {
            let command = try XCTUnwrap(NFCISO7816APDU(data: Data(plain)))
            let protected = try sm.protect(apdu: command)
            let expected = try XCTUnwrap(NFCISO7816APDU(data: Data(v.bytes("protected\(index)"))))
            XCTAssertTrue(protected.data == expected.data, "ICAO protected command mismatch")
            let wire = try v.bytes("responseSM\(index)")
            let decoded = try sm.unprotect(rapdu: ResponseAPDU(data: Array(wire.dropLast(2)), sw1: wire[wire.count - 2], sw2: wire.last!))
            XCTAssertEqual(decoded.sw1, 0x90)
            XCTAssertEqual(decoded.sw2, 0)
            file += decoded.data
        }
        XCTAssertTrue(file == (try v.bytes("com")), "ICAO COM read mismatch")
        XCTAssertTrue(bac.rnd_icc.isEmpty && bac.rnd_ifd.isEmpty)
        tag.disconnect()
    }
}

@MainActor
private final class VectorPACEHandler: PACEHandler {
    override func createEphemeralKey(from parameters: OpaquePointer) throws -> OpaquePointer {
        let vector = try XCTUnwrap(paceInfo as? VectorPACEInfo).vector
        try assertGenerator(parameters, vector: vector)
        return try importVectorKey(parameters: parameters, privateBytes: vector.bytes("ephemeralPrivate"), publicBytes: vector.bytes("ephemeralPublic"), isDH: vector.isDH)
    }
    override func paceCompleted(ksEnc: [UInt8], ksMac: [UInt8]) throws {
        let v = try XCTUnwrap(paceInfo as? VectorPACEInfo).vector
        XCTAssertTrue(ksEnc == (try v.bytes("enc")), "ICAO PACE encryption-key mismatch")
        XCTAssertTrue(ksMac == (try v.bytes("mac")), "ICAO PACE MAC-key mismatch")
        try super.paceCompleted(ksEnc: ksEnc, ksMac: ksMac)
    }
}

private final class VectorPACEInfo: PACEInfo {
    let vector: ICAOVector
    init(vector: ICAOVector, cam: Bool) {
        self.vector = vector
        super.init(oid: cam ? SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 : (vector.isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128), version: 2, parameterId: vector.isDH ? 0 : 13)
    }
    override func createMappingKey() throws -> OpaquePointer {
        let parameters = try vector.parameters()
        defer { EVP_PKEY_free(parameters) }
        return try importVectorKey(parameters: parameters, privateBytes: vector.bytes("mappingPrivate"), publicBytes: vector.bytes("mappingPublic"), isDH: vector.isDH)
    }
}

private func assertGenerator(_ parameters: OpaquePointer, vector: ICAOVector) throws {
    let generator = try vector.bytes("generator")
    let matches = generator.withUnsafeBufferPointer {
        vector.isDH ? NFCPRVerifyDHGenerator(parameters, $0.baseAddress, $0.count) : NFCPRVerifyECGenerator(parameters, $0.baseAddress, $0.count)
    }
    XCTAssertEqual(matches, 1, "ICAO mapped-generator mismatch")
}

@MainActor
private final class VectorBACHandler: BACHandler {
    var vector: ICAOVector?
    override func randomBytes(count: Int) -> [UInt8] {
        (try? vector?.bytes(count == 8 ? "terminalRandom" : "terminalMaterial")) ?? []
    }
}
