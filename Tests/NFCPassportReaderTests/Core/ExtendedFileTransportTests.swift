import XCTest
import OpenSSL
@preconcurrency import CoreNFC
@testable import NFCPassportReader

@MainActor
final class ExtendedFileTransportTests: XCTestCase {
    func testLargeFileCrossesBothOffsetBoundariesWithoutWrapping() async throws {
        // Synthetic, non-biometric file contents. Deliberately exceeds 16-bit addressing.
        let body = (0..<70_000).map { UInt8($0 % 251) }
        let file = wrapDO(b: 0x75, arr: body)
        var offsets: [Int] = []
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
            let offset: Int
            let response: [UInt8]
            if command.instructionCode == 0xB0 {
                XCTAssertLessThan(command.p1Parameter, 0x80)
                offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
                XCTAssertLessThanOrEqual(offset + command.expectedResponseLength, 0x8000)
                response = Array(file.dropFirst(offset).prefix(command.expectedResponseLength))
            } else {
                XCTAssertEqual(command.instructionCode, 0xB1)
                XCTAssertEqual(command.p1Parameter, 0)
                XCTAssertEqual(command.p2Parameter, 0)
                let encoded = try unwrapDO(tag: 0x54, wrappedData: Array(command.data ?? Data()))
                XCTAssertNotEqual(encoded.first, 0)
                offset = encoded.reduce(0) { ($0 << 8) | Int($1) }
                XCTAssertGreaterThanOrEqual(offset, 0x8000)
                XCTAssertLessThanOrEqual(command.expectedResponseLength, 256)
                let count = command.expectedResponseLength - (command.expectedResponseLength <= 129 ? 2 : 3)
                response = wrapDO(b: 0x53, arr: Array(file.dropFirst(offset).prefix(count)))
            }
            offsets.append(offset)
            return (Data(response), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        tag.preferExtendedReadAmount()
        let actual = try await tag.readDataGroup(dataGroup: .DG2)
        XCTAssertTrue(actual == file, "File must be reconstructed without exposing content")
        XCTAssertTrue(offsets.contains(0x8000))
        XCTAssertTrue(offsets.contains { $0 > 0xFFFF })
        XCTAssertEqual(offsets, offsets.sorted())
    }

    func testOddReadRejectsMalformedDiscretionaryDataObject() async throws {
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0xA4 { return (Data(), 0x90, 0) }
            if command.instructionCode == 0xB1 { return (Data([0x54, 1, 0]), 0x90, 0) }
            let offset = Int(command.p1Parameter) * 256 + Int(command.p2Parameter)
            if offset == 0 { return (Data([0x75, 0x82, 0x90, 0, 0, 0]), 0x90, 0) }
            return (Data(repeating: 0, count: command.expectedResponseLength), 0x90, 0)
        }
        do { _ = try await TagReader(transport: transport).readDataGroup(dataGroup: .DG2); XCTFail("Expected malformed B1 response") }
        catch { XCTAssertTrue(error is NFCPassportReaderError) }
        XCTAssertEqual(transport.commands.last, 0xB1)
    }

    func testLargeDHChipAuthenticationUsesOneCompleteGeneralAuthenticateCommand() async throws {
        let key = try OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 2)
        defer { EVP_PKEY_free(key) }
        let wire = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: key))
        let transport = LifecycleTransport { command, _ in
            if command.instructionCode == 0x86 {
                XCTAssertEqual(command.instructionClass, 0)
                let dynamic = try unwrapDO(tag: 0x7C, wrappedData: Array(command.data ?? Data()))
                XCTAssertTrue(try unwrapDO(tag: 0x80, wrappedData: dynamic) == wire)
                XCTAssertGreaterThan((command.data ?? Data()).count, 255)
            }
            // CA v1 has no protocol response data; PACE still requires its objects.
            return (Data(), 0x90, 0)
        }
        let tag = TagReader(transport: transport)
        let handler = ChipAuthenticationHandler()
        handler.tagReader = tag
        try await handler.sendPublicKey(oid: SecurityInfo.ID_CA_DH_AES_CBC_CMAC_128_OID, keyId: nil, pcdPublicKey: key)
        XCTAssertEqual(transport.commands, [0x22, 0x86])
        XCTAssertFalse(tag.generalAuthenticationChainOpen)
    }

    func testGeneralAuthenticateDoesNotRetryIdenticalWrongLengthCommand() async throws {
        let transport = LifecycleTransport { _, _ in (Data(), 0x67, 0) }
        let tag = TagReader(transport: transport)
        do { _ = try await tag.sendGeneralAuthenticate(data: [], isLast: false); XCTFail("Expected length rejection") }
        catch { XCTAssertTrue(error is NFCPassportReaderError) }
        XCTAssertEqual(transport.commands.count, 1)
        XCTAssertTrue(tag.generalAuthenticationChainOpen)
    }

    func testGetResponseStopsBeforeSendingBeyondSegmentBudget() async throws {
        let transport = LifecycleTransport { _, _ in (Data([1]), 0x61, 1) }
        do { _ = try await TagReader(transport: transport).getChallenge(); XCTFail("Expected bounded response failure") }
        catch NFCPassportReaderError.InvalidASN1Structure { } catch { XCTFail("Wrong budget failure") }
        XCTAssertEqual(transport.commands.count, 513) // original + 512 GET RESPONSE
    }

    func testInitialResponseAlsoHasByteBudget() async throws {
        let transport = LifecycleTransport { _, _ in (Data(repeating: 0, count: 2 * 1024 * 1024 + 1), 0x61, 1) }
        do { _ = try await TagReader(transport: transport).getChallenge(); XCTFail("Expected oversized response failure") }
        catch NFCPassportReaderError.InvalidASN1Structure { } catch { XCTFail("Wrong budget failure") }
        XCTAssertEqual(transport.commands.count, 1)
    }

    func testSecureMessagingKeepsGeneralAuthenticationChainingFlag() throws {
        let command = NFCISO7816APDU(instructionClass: 0x10, instructionCode: 0x86, p1Parameter: 0, p2Parameter: 0, data: Data([0x7C, 0]), expectedResponseLength: 256)
        let protected = try syntheticMessaging().protect(apdu: command)
        XCTAssertEqual(protected.instructionClass, 0x1C)
        XCTAssertEqual(protected.data?.first, 0x87)
    }

    func testOddReadUsesDO85AndIncludesOffsetInAuthenticatedCommand() throws {
        let command = try TagReader.readBinaryCommand(offset: 0x10000, amount: 160)
        let sm = syntheticMessaging()
        let protected = try sm.protect(apdu: command)
        let data = Array(protected.data ?? Data())
        XCTAssertEqual(data.first, 0x85)
        let (length, size) = try asn1Length(data[1...])
        XCTAssertEqual(length, 8) // No DO87 padding indicator in the encrypted object.
        let cipher = Array(data[(1 + size)..<(1 + size + length)])
        let plain = strictUnpad(tripleDESDecrypt(key: Array(repeating: 1, count: 16), message: cipher, iv: Array(repeating: 0, count: 8)))
        XCTAssertTrue(plain == Array(command.data ?? Data()), "Encrypted offset must round-trip")
        XCTAssertEqual(data[1 + size + length], 0x97)
    }

    func testOddSecureResponseVerifiesDecryptsAndRejectsTampering() throws {
        for algorithm in [SecureMessagingSupportedAlgorithms.DES, .AES] {
            let enc = Array(repeating: UInt8(1), count: 16)
            let macKey = Array(repeating: UInt8(2), count: 16)
            let initial = Array(repeating: UInt8(0), count: 8)
            let sm = SecureMessaging(encryptionAlgorithm: algorithm, ksenc: enc, ksmac: macKey, ssc: initial)
            let counter = sm.incSSC()
            let block = algorithm == .DES ? 8 : 16
            let payload = wrapDO(b: 0x53, arr: [1, 2, 3])
            let cipher: [UInt8]
            if algorithm == .DES {
                cipher = tripleDESEncrypt(key: enc, message: pad(payload, blockSize: block), iv: Array(repeating: 0, count: 8))
            } else {
                let iv = AESECBEncrypt(key: enc, message: Array(repeating: 0, count: 8) + counter)
                cipher = AESEncrypt(key: enc, message: pad(payload, blockSize: block), iv: iv)
            }
            let object = wrapDO(b: 0x85, arr: cipher)
            let status: [UInt8] = [0x99, 2, 0x90, 0]
            let paddedCounter = algorithm == .DES ? counter : Array(repeating: 0, count: 8) + counter
            let checksum = Array(mac(algoName: algorithm, key: macKey, msg: pad(paddedCounter + object + status, blockSize: block)).prefix(8))
            guard checksum.count == 8 else {
                XCTFail(algorithm == .DES ? "Synthetic DES MAC failed" : "Synthetic AES MAC failed")
                continue
            }
            let wire = object + status + wrapDO(b: 0x8E, arr: checksum)
            let decoded = try sm.unprotect(rapdu: ResponseAPDU(data: wire, sw1: 0x90, sw2: 0), useDO85: true)
            XCTAssertTrue(decoded.data == payload)
            var corrupt = wire
            corrupt[2] ^= 1
            let verifier = SecureMessaging(encryptionAlgorithm: algorithm, ksenc: enc, ksmac: macKey, ssc: initial)
            XCTAssertThrowsError(try verifier.unprotect(rapdu: ResponseAPDU(data: corrupt, sw1: 0x90, sw2: 0), useDO85: true))
        }
    }

    private func syntheticMessaging() -> SecureMessaging {
        SecureMessaging(ksenc: Array(repeating: 1, count: 16), ksmac: Array(repeating: 2, count: 16), ssc: Array(repeating: 0, count: 8))
    }
}
