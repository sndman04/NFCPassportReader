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

    func testAllAdvertisedCipherAndMappingCombinations() async throws {
        for oid in PACEInfo.allowedIdentifiers.sorted() {
            let isDH = try PACEInfo.toKeyAgreementAlgorithm(oid: oid) == "DH"
            try await runPACE(isDH: isDH, protocolOID: oid)
        }
    }

    func testICAOAlgorithmInventoryAndAllPermittedParameterCombinations() async throws {
        // Independently enumerated from ICAO Part 11 §9.2.3 and Table 12, not the implementation allowlist.
        var expected = Set<String>()
        for family in [1, 2, 3, 4, 6] {
            for cipher in (family == 6 ? [2, 3, 4] : [1, 2, 3, 4]) {
                let oid = "0.4.0.127.0.7.2.2.4.\(family).\(cipher)"
                expected.insert(oid)
                let dh = family == 1 || family == 3
                for parameter in (dh ? [0, 1, 2] : Array(8...18)) {
                    if family == 4 && parameter == 10 { continue } // Table 12 excludes P-224 with IM.
                    try await runPACE(isDH: dh, protocolOID: oid, parameterID: parameter)
                }
            }
        }
        XCTAssertEqual(PACEInfo.allowedIdentifiers, expected)
    }

    func testExplicitKnownParametersCompleteConversationsWithLocalIdentifiers() async throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "pace-explicit-parameters", withExtension: "json", subdirectory: "Fixtures"))
        let parameters = try JSONDecoder().decode([String: String].self, from: Data(contentsOf: url))
        for parameter in [0, 1, 2, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18] {
            let dh = parameter < 3
            for family in (dh ? [1, 3] : [2, 4, 6]) {
                if family == 4 && parameter == 10 { continue }
                let protocolOID = "0.4.0.127.0.7.2.2.4.\(family)"
                let oid = protocolOID + ".2"
                let domainAlgorithm = dh ? "1.2.840.10046.2.1" : "1.2.840.10045.2.1"
                let domain = wrapDO(b: 0x30, arr: oidToBytes(oid: domainAlgorithm, replaceTag: false)
                    + hexRepToBin(try XCTUnwrap(parameters[String(parameter)])))
                let domainInfo = wrapDO(b: 0x30, arr: oidToBytes(oid: protocolOID, replaceTag: false) + domain + [2, 1, 32])
                let info = wrapDO(b: 0x30, arr: oidToBytes(oid: oid, replaceTag: false) + [2, 1, 2, 2, 1, 32])
                let access = try CardAccess(wrapDO(b: 0x31, arr: info + domainInfo))
                XCTAssertEqual(access.preferredPACEInfo?.effectiveStandardParameterId, parameter)
                try await runPACE(isDH: dh, protocolOID: oid, parameterID: parameter, cardAccess: access)
            }
        }
    }

    func testAllStandardDomainParametersWithGenericMapping() async throws {
        for parameter in [0, 1, 2, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18] {
            try await runPACE(isDH: parameter < 3, parameterID: parameter)
        }
    }

    func testEveryGeneralAuthenticateBoundaryFailsWithoutInstallingMessaging() async throws {
        for failedStep in 1...4 {
            try await runPACE(isDH: false, failedStep: failedStep)
        }
    }

    private func runPACE(isDH: Bool, reflectKey: Bool = false, protocolOID: String? = nil,
                         parameterID: Int? = nil, failedStep: Int? = nil, cardAccess: CardAccess? = nil) async throws {
        let credential = "synthetic-access-credential"
        let oid = protocolOID ?? (isDH ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128)
        let info = PACEInfo(oid: oid, version: 2, parameterId: parameterID ?? (isDH ? 0 : 13))
        let mapping = try info.getMappingType()
        let cipher = try info.getCipherAlgorithm()
        let bits = try info.getKeyLength()
        let algorithm: SecureMessagingSupportedAlgorithms = cipher == "AES" ? .AES : .DES
        let mappingKey = try info.createMappingKey()
        defer { EVP_PKEY_free(mappingKey) }
        let nonce = Array(repeating: UInt8(3), count: try PACEHandler.expectedNonceLength(cipherAlg: cipher, keyLength: bits))
        let passwordKey = try PACEHandler.createPaceKey(from: credential, cipherAlg: cipher, keyLength: bits)
        var ephemeral: OpaquePointer?
        var terminal: OpaquePointer?
        var macKey: [UInt8] = []
        var encKey: [UInt8] = []
        defer { EVP_PKEY_free(ephemeral); EVP_PKEY_free(terminal); macKey.removeAll(); encKey.removeAll() }
        weak var handler: PACEHandler?
        var step = 0
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0x22 { return (Data(), 0x90, 0) }
            XCTAssertEqual(command.instructionCode, 0x86)
            step += 1
            XCTAssertEqual(command.instructionClass, step == 4 ? 0 : 0x10)
            if failedStep == step { return (Data(), 0x69, 0x85) }
            let input = try unwrapDO(tag: 0x7C, wrappedData: Array(command.data ?? Data()))
            let response: [UInt8]
            switch step {
            case 1:
                XCTAssertTrue(input.isEmpty)
                let encrypted = cipher == "AES" ? AESEncrypt(key: passwordKey, message: nonce, iv: Array(repeating: 0, count: 16))
                    : tripleDESEncrypt(key: passwordKey, message: nonce, iv: Array(repeating: 0, count: 8))
                response = wrapDO(b: 0x80, arr: encrypted)
            case 2:
                let terminalMapping = try unwrapDO(tag: 0x81, wrappedData: input)
                let parameters: OpaquePointer
                if mapping == .IM {
                    let field = try PACEHandler.integratedMappingField(passportNonce: nonce, terminalNonce: terminalMapping,
                        cipherAlg: cipher, keyLength: bits, primeBitLength: Int(EVP_PKEY_get_bits(mappingKey)))
                    parameters = try XCTUnwrap(field.withUnsafeBufferPointer {
                        isDH ? NFCPRCreateDHIntegratedMappedParameters(mappingKey, $0.baseAddress, $0.count)
                            : NFCPRCreateECDHIntegratedMappedParameters(mappingKey, $0.baseAddress, $0.count)
                    })
                    response = wrapDO(b: 0x82, arr: [])
                } else {
                    let nonceBN = try XCTUnwrap(nonce.withUnsafeBufferPointer { BN_bin2bn($0.baseAddress, Int32($0.count), nil) })
                    defer { BN_clear_free(nonceBN) }
                    parameters = try XCTUnwrap(terminalMapping.withUnsafeBufferPointer {
                        isDH ? NFCPRCreateDHMappedParameters(mappingKey, $0.baseAddress, $0.count, nonceBN)
                            : NFCPRCreateECDHMappedParameters(mappingKey, $0.baseAddress, $0.count, nonceBN)
                    })
                    response = wrapDO(b: 0x82, arr: try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: mappingKey)))
                }
                defer { EVP_PKEY_free(parameters) }
                ephemeral = try OpenSSLUtils.generateKeyPair(fromParameters: parameters)
            case 3:
                if reflectKey {
                    response = wrapDO(b: 0x84, arr: try unwrapDO(tag: 0x83, wrappedData: input))
                    break
                }
                let chipKey = try XCTUnwrap(ephemeral)
                terminal = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: try unwrapDO(tag: 0x83, wrappedData: input), params: chipKey)
                let secret = try OpenSSLUtils.computeSharedSecret(privateKeyPair: chipKey, publicKey: XCTUnwrap(terminal))
                let generator = SecureMessagingSessionKeyGenerator()
                macKey = try generator.deriveKey(keySeed: secret, cipherAlgName: cipher, keyLength: bits, mode: .MAC_MODE)
                encKey = try generator.deriveKey(keySeed: secret, cipherAlgName: cipher, keyLength: bits, mode: .ENC_MODE)
                response = wrapDO(b: 0x84, arr: try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: chipKey)))
            case 4:
                let token = try unwrapDO(tag: 0x85, wrappedData: input)
                let pace = try XCTUnwrap(handler)
                let expected = try pace.generateAuthenticationToken(publicKey: XCTUnwrap(ephemeral), macKey: macKey)
                XCTAssertTrue(token == expected, "Synthetic chip must verify the terminal token")
                var data = wrapDO(b: 0x86, arr: try pace.generateAuthenticationToken(publicKey: XCTUnwrap(terminal), macKey: macKey))
                if mapping == .CAM {
                    let iv = AESECBEncrypt(key: encKey, message: Array(repeating: 0xFF, count: 16))
                    data += wrapDO(b: 0x8A, arr: AESEncrypt(key: encKey, message: pad([1], blockSize: 16), iv: iv))
                }
                response = data
            default:
                XCTFail("Unexpected authentication step")
                throw NFCPassportReaderError.UnexpectedError
            }
            return (Data(wrapDO(b: 0x7C, arr: response)), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        defer { tag.disconnect() }
        let pace = try cardAccess.map { try PACEHandler(cardAccess: $0, tagReader: tag) } ?? PACEHandler(paceInfo: info, tagReader: tag)
        handler = pace
        if reflectKey || failedStep != nil {
            do { try await pace.doPACE(mrzKey: credential); XCTFail("Expected PACE rejection") }
            catch { XCTAssertTrue(error is NFCPassportReaderError) }
            XCTAssertEqual(step, failedStep ?? 3)
            XCTAssertNil(tag.secureMessaging)
            XCTAssertNil(pace.chipAuthenticationMappingResult)
        } else {
            try await pace.doPACE(mrzKey: credential)
            XCTAssertEqual(step, 4)
            let sm = try XCTUnwrap(tag.secureMessaging)
            XCTAssertFalse(tag.generalAuthenticationChainOpen)
            // Check the installed keys by authenticating a protected command.
            let control = SecureMessaging(encryptionAlgorithm: algorithm, ksenc: encKey, ksmac: macKey, ssc: Array(repeating: 0, count: 8))
            let command = NFCISO7816APDU(instructionClass: 0, instructionCode: 0xB0, p1Parameter: 0, p2Parameter: 0, data: Data(), expectedResponseLength: 4)
            XCTAssertTrue(try sm.protect(apdu: command).data == control.protect(apdu: command).data)
        }
        XCTAssertFalse(transport.commands.contains(0x84))
    }
}
