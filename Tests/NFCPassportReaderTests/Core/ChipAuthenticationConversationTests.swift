import XCTest
import OpenSSL
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class ChipAuthenticationConversationTests: XCTestCase {
    func testICAOCAInventoryAndAllStandardDomainParametersConfirmNewKeys() async throws {
        // ICAO Part 11 Tables 5/6: independent inventory, including key identifier zero.
        for family in [1, 2] {
            for cipher in 1...4 {
                let oid = "0.4.0.127.0.7.2.2.3.\(family).\(cipher)"
                XCTAssertTrue(ChipAuthenticationInfo.checkRequiredIdentifier(oid))
                for parameter in (family == 1 ? [0, 1, 2] : Array(8...18)) {
                    try await runCA(oid: oid, parameter: parameter)
                }
            }
        }
        for oid in ["0.4.0.127.0.7.2.2.3.1.5", "0.4.0.127.0.7.2.2.3.3.1"] {
            XCTAssertFalse(ChipAuthenticationInfo.checkRequiredIdentifier(oid))
        }
    }

    func testCASelectsStrongestAdvertisedCipherForTheSameKey() async throws {
        try await runCA(oid: "0.4.0.127.0.7.2.2.3.2.4", parameter: 13, alternatives: true)
    }

    func testCARejectsCorruptedNewSessionConfirmationForEveryCipherAndFamily() async throws {
        for family in [1, 2] {
            for cipher in 1...4 {
                try await runCA(oid: "0.4.0.127.0.7.2.2.3.\(family).\(cipher)", parameter: family == 1 ? 0 : 13, corruptMAC: true)
            }
        }
    }

    func testCARejectsAlgorithmAndKeyFamilyMismatchBeforeSendingCommands() async throws {
        let key = try PACEInfo(oid: SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128, version: 2, parameterId: 13).createMappingKey()
        defer { EVP_PKEY_free(key) }
        let transport = LifecycleTransport { _, _ in XCTFail("Invalid metadata must not reach chip"); return (Data(), 0x90, 0) }
        let tag = TagReader(transport: transport)
        let handler = ChipAuthenticationHandler()
        handler.tagReader = tag
        handler.isChipAuthenticationSupported = true
        handler.chipAuthInfos = [0: ChipAuthenticationInfo(oid: SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID, version: 1, keyId: 0)]
        handler.chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: key, keyId: 0, ownsPublicKey: false)]
        do { try await handler.doChipAuthentication(); XCTFail("Expected key family rejection") }
        catch NFCPassportReaderError.InvalidASN1Structure { }
        XCTAssertTrue(transport.commands.isEmpty)
        let first = ChipAuthenticationPublicKeyInfo(oid: SecurityInfo.ID_PK_ECDH_OID, pubKey: key, keyId: 0, ownsPublicKey: false)
        let duplicate = ChipAuthenticationPublicKeyInfo(oid: first.oid, pubKey: key, keyId: 0, ownsPublicKey: false)
        XCTAssertEqual(try ChipAuthenticationHandler.metadata(from: [first, duplicate]).publicKeyInfos.count, 1)
        let ambiguous = ChipAuthenticationPublicKeyInfo(oid: first.oid, pubKey: key, ownsPublicKey: false)
        XCTAssertThrowsError(try ChipAuthenticationHandler.metadata(from: [first, ambiguous]))
    }

    private func runCA(oid: String, parameter: Int, corruptMAC: Bool = false, alternatives: Bool = false) async throws {
        let dh = parameter < 3
        let chip = try PACEInfo(oid: dh ? SecurityInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128 : SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
                                version: 2, parameterId: parameter).createMappingKey()
        defer { EVP_PKEY_free(chip) }
        let size = i2d_PUBKEY(chip, nil)
        XCTAssertGreaterThan(size, 0)
        var spki = [UInt8](repeating: 0, count: Int(size))
        _ = spki.withUnsafeMutableBufferPointer { buffer in
            var cursor = buffer.baseAddress
            return i2d_PUBKEY(chip, &cursor)
        }
        let keyOID = dh ? SecurityInfo.ID_PK_DH_OID : SecurityInfo.ID_PK_ECDH_OID
        let keyInfo = wrapDO(b: 0x30, arr: oidToBytes(oid: keyOID, replaceTag: false) + spki + [2, 1, 0])
        let algorithmInfo = wrapDO(b: 0x30, arr: oidToBytes(oid: oid, replaceTag: false) + [2, 1, 1, 2, 1, 0])
        let alternativeInfo = alternatives ? wrapDO(b: 0x30, arr: oidToBytes(oid: "0.4.0.127.0.7.2.2.3.2.1", replaceTag: false) + [2, 1, 1, 2, 1, 0]) : []
        let dg14 = try DataGroup14(wrapDO(b: 0x6E, arr: wrapDO(b: 0x31, arr: keyInfo + alternativeInfo + algorithmInfo)))
        let des = oid.hasSuffix(".1")
        let bits = des ? 128 : (oid.hasSuffix(".2") ? 128 : (oid.hasSuffix(".3") ? 192 : 256))
        let blockSize = des ? 8 : 16
        var macKey: [UInt8] = []
        defer { macKey.removeAll(keepingCapacity: false) }
        let transport = LifecycleTransport { command, _ in
            var terminalBytes: [UInt8]?
            if command.instructionCode == 0x22 {
                XCTAssertEqual(command.p1Parameter, 0x41)
                XCTAssertEqual(command.p2Parameter, des ? 0xA6 : 0xA4)
                let fields = try SimpleASN1Node.parse(wrapDO(b: 0x30, arr: Array(command.data ?? Data()))).children
                XCTAssertEqual(fields.last?.tag, 0x84)
                XCTAssertEqual(fields.last?.value, [0])
                XCTAssertEqual(fields.first?.tag, des ? 0x91 : 0x80)
                if des { terminalBytes = fields.first?.value }
                else { XCTAssertEqual(fields.first?.value, Array(oidToBytes(oid: oid, replaceTag: false).dropFirst(2))) }
            } else if command.instructionCode == 0x86 {
                terminalBytes = try unwrapDO(tag: 0x80, wrappedData: unwrapDO(tag: 0x7C, wrappedData: Array(command.data ?? Data())))
            } else {
                XCTAssertEqual(command.instructionCode, 0xA4)
                XCTAssertEqual(command.instructionClass, 0x0C)
                XCTAssertFalse(macKey.isEmpty)
                let counter = Array(repeating: UInt8(0), count: blockSize - 1) + [2]
                let status: [UInt8] = [0x99, 2, 0x90, 0]
                var checksum = Array(mac(algoName: des ? .DES : .AES, key: macKey, msg: pad(counter + status, blockSize: blockSize)).prefix(8))
                if corruptMAC { checksum[0] ^= 1 }
                return (Data(status + wrapDO(b: 0x8E, arr: checksum)), 0x90, 0)
            }
            if let terminalBytes {
                let terminal = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: terminalBytes, params: chip))
                defer { EVP_PKEY_free(terminal) }
                let secret = try OpenSSLUtils.computeSharedSecret(privateKeyPair: chip, publicKey: terminal)
                macKey = try SecureMessagingSessionKeyGenerator().deriveKey(keySeed: secret, cipherAlgName: des ? "DESede" : "AES", keyLength: bits, mode: .MAC_MODE)
            }
            return (Data(), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let handler = try ChipAuthenticationHandler(dg14: dg14, tagReader: tag)
        let reader = PassportReader()
        reader.configureAccessForTesting(mrzKey: "synthetic-access-credential", progress: nil)
        reader.configureLifecycleForTesting(tagReader: tag)
        let scanID = try XCTUnwrap(reader.beginScanIfPossible())
        do {
            try await reader.authenticateChip(tagReader: tag, scanID: scanID) { try await handler.doChipAuthentication() }
            XCTAssertFalse(corruptMAC, "Unauthenticated response must fail")
        } catch {
            guard corruptMAC else { throw error }
        }
        XCTAssertEqual(transport.commands, des ? [0x22, 0xA4] : [0x22, 0x86, 0xA4])
        reader.failActiveScan(error: .UserCanceled, scanID: scanID)
        let snapshot = try XCTUnwrap(reader.lastDiagnosticSnapshot)
        XCTAssertEqual(snapshot.verification.chipAuthentication.status, corruptMAC ? .failed : .succeeded)
        XCTAssertNil(tag.secureMessaging)
        dg14.removeSensitiveDataForPrivacy()
        XCTAssertTrue(dg14.securityInfos.isEmpty)
    }
}
