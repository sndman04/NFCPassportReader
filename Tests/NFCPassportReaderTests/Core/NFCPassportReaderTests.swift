import XCTest
import CoreNFC
import OpenSSL

@testable import NFCPassportReader

public func XCTAssertNoThrow<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line, also validateResult: (T) -> Void) {
    func executeAndAssignResult(_ expression: @autoclosure () throws -> T, to: inout T?) rethrows {
        to = try expression()
    }
    var result: T?
    XCTAssertNoThrow(try executeAndAssignResult(expression(), to: &result), message, file: file, line: line)
    if let r = result {
        validateResult(r)
    }
}


final class NFCPassportReaderTests: XCTestCase {
    func testBinToHexRep() {
        let val : [UInt8] = [0x12, 0x24, 0x55, 0x77]
        XCTAssertEqual( binToHexRep(val), "12245577" )
    }
    
    func testHexRepToBin() {
        let val : [UInt8] = [0x12, 0x24, 0x55, 0x77]
        XCTAssertEqual( hexRepToBin("12245577"), val  )
    }
    
    func testAsn1Length() {
        // Test < 127
        XCTAssertNoThrow(try asn1Length([0x32])) { (len, offset) in
            XCTAssertEqual(len, 0x32)
            XCTAssertEqual(offset, 1)
        }
        
        // Test 127
        XCTAssertNoThrow(try asn1Length([0x7f])) { (len, offset) in
            XCTAssertEqual(len, 0x7f)
            XCTAssertEqual(offset, 1)
        }
        
        // Test 128
        XCTAssertNoThrow(try asn1Length([0x81, 0x80])) { (len, offset) in
            XCTAssertEqual(len, 128)
            XCTAssertEqual(offset, 2)
        }
        
        // Test 255
        XCTAssertNoThrow(try asn1Length([0x81, 0xFF])) { (len, offset) in
            XCTAssertEqual(len, 255)
            XCTAssertEqual(offset, 2)
        }
        
        // Test 256
        XCTAssertNoThrow(try asn1Length([0x82, 0x01,0x00])) { (len, offset) in
            XCTAssertEqual(len, 256)
            XCTAssertEqual(offset, 3)
        }
        
        // Test 1000
        XCTAssertNoThrow(try asn1Length([0x82, 0x03, 0xE8])) { (len, offset) in
            XCTAssertEqual(len, 1000)
            XCTAssertEqual(offset, 3)
        }
        
        // Test Max value - 65535
        XCTAssertNoThrow(try asn1Length([0x82, 0xff, 0xff])) { (len, offset) in
            XCTAssertEqual(len, 65535)
            XCTAssertEqual(offset, 3)
        }

        // Test 65536, used by valid large data groups such as DG2 photos
        XCTAssertNoThrow(try asn1Length([0x83, 0x01, 0x00, 0x00])) { (len, offset) in
            XCTAssertEqual(len, 65536)
            XCTAssertEqual(offset, 4)
        }

        // Test 16777216, longest supported definite length form
        XCTAssertNoThrow(try asn1Length([0x84, 0x01, 0x00, 0x00, 0x00])) { (len, offset) in
            XCTAssertEqual(len, 16777216)
            XCTAssertEqual(offset, 5)
        }
        
        XCTAssertThrowsError(try asn1Length([]))
        XCTAssertThrowsError(try asn1Length([0x81]))
        XCTAssertThrowsError(try asn1Length([0x82, 0x01]))
        XCTAssertThrowsError(try asn1Length([0x80]))
        XCTAssertThrowsError(try asn1Length([0x85, 0x01, 0x00, 0x00, 0x00, 0x00]))
        XCTAssertThrowsError(try asn1Length([0x84, 0x80, 0x00, 0x00, 0x00]))
    }
    
    func testToASNLength() {
        // Test < 127
        XCTAssertNoThrow(try toAsn1Length(50)) { data in
            XCTAssertEqual(data.count, 1)
            XCTAssertEqual(data[0], 0x32)
        }
        
        // Test 127
        XCTAssertNoThrow(try toAsn1Length(127)) { data in
            XCTAssertEqual(data.count, 1)
            XCTAssertEqual(data[0], 0x7f)
        }
        
        // Test 128
        XCTAssertNoThrow(try toAsn1Length(128)) { data in
            XCTAssertEqual(data.count, 2)
            XCTAssertEqual(data[0], 0x81)
            XCTAssertEqual(data[1], 0x80)
        }
        
        // Test 255
        XCTAssertNoThrow(try toAsn1Length(255)) { data in
            XCTAssertEqual(data.count, 2)
            XCTAssertEqual(data[0], 0x81)
            XCTAssertEqual(data[1], 0xff)
        }
        
        // Test 256
        XCTAssertNoThrow(try toAsn1Length(256)) { data in
            XCTAssertEqual(data.count, 3)
            XCTAssertEqual(data[0], 0x82)
            XCTAssertEqual(data[1], 0x01)
            XCTAssertEqual(data[2], 0x00)
        }
        
        // Test 1000
        XCTAssertNoThrow(try toAsn1Length(1000)) { data in
            XCTAssertEqual(data.count, 3)
            XCTAssertEqual(data[0], 0x82)
            XCTAssertEqual(data[1], 0x03)
            XCTAssertEqual(data[2], 0xE8)
        }
        
        // Test Max value - 65535
        XCTAssertNoThrow(try toAsn1Length(65535)) { data in
            XCTAssertEqual(data.count, 3)
            XCTAssertEqual(data[0], 0x82)
            XCTAssertEqual(data[1], 0xff)
            XCTAssertEqual(data[2], 0xff)
        }

        // Test 65536
        XCTAssertNoThrow(try toAsn1Length(65536)) { data in
            XCTAssertEqual(data, [0x83, 0x01, 0x00, 0x00])
        }

        // Test 16777216
        XCTAssertNoThrow(try toAsn1Length(16777216)) { data in
            XCTAssertEqual(data, [0x84, 0x01, 0x00, 0x00, 0x00])
        }
        
        // Test Too Big
        XCTAssertThrowsError(try toAsn1Length(-1))
        XCTAssertThrowsError(try toAsn1Length(Int(Int32.max) + 1))
    }

    func testDataObjectHelpersPreserveEmptyValues() throws {
        let wrapped = wrapDO(b: 0x82, arr: [])

        XCTAssertEqual(wrapped, [0x82, 0x00])
        XCTAssertEqual(try unwrapDO(tag: 0x82, wrappedData: wrapped), [])
    }

    func testHexRepToBinRejectsInvalidInputWithoutTrapping() {
        XCTAssertEqual(hexRepToBin("not hex"), [])
        XCTAssertEqual(hexRepToBin("AAZ1"), [])
        XCTAssertEqual(hexRepToBin("F"), [0x0f])
    }

    #if !os(macOS)
    func testExtendedReadAmountIsCappedToRemainingFileLength() {
        XCTAssertEqual(TagReader.readAmount(maximum: 256, remaining: 12), 12)
        XCTAssertEqual(TagReader.readAmount(maximum: 256, remaining: 256), 256)
        XCTAssertEqual(TagReader.readAmount(maximum: 160, remaining: 12), 12)
        XCTAssertEqual(TagReader.readAmount(maximum: 160, remaining: 300), 160)
    }

    func testReadChunkRejectsMoreDataThanAdvertisedFileLength() {
        var data: [UInt8] = [0x61, 0x03]
        var remaining = 2

        XCTAssertThrowsError(try TagReader.appendReadChunk([0x01, 0x02, 0x03], to: &data, remaining: &remaining)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }

        XCTAssertEqual(data, [0x61, 0x03])
        XCTAssertEqual(remaining, 2)
    }

    func testReadChunkTracksRemainingAdvertisedFileLength() throws {
        var data: [UInt8] = [0x61, 0x03]
        var remaining = 3

        try TagReader.appendReadChunk([0x01, 0x02], to: &data, remaining: &remaining)
        XCTAssertEqual(data, [0x61, 0x03, 0x01, 0x02])
        XCTAssertEqual(remaining, 1)
    }

    func testInitialFileReadRetainsBodyBytesAlreadyReturnedWithHeader() throws {
        let parsed = try TagReader.parseInitialFileRead([0x61, 0x03, 0x01, 0x02, 0x03])

        XCTAssertEqual(parsed.data, [0x61, 0x03, 0x01, 0x02, 0x03])
        XCTAssertEqual(parsed.remaining, 0)
    }

    func testInitialFileReadAcceptsThreeByteLongFormLength() throws {
        let header = try [UInt8]([0x75]) + toAsn1Length(65_536) + [0xAA]
        let parsed = try TagReader.parseInitialFileRead(header)

        XCTAssertEqual(parsed.data, header)
        XCTAssertEqual(parsed.remaining, 65_535)
    }

    func testInitialFileReadRejectsOversizedAdvertisedLengthBeforeReserve() throws {
        let header = try [UInt8]([0x75]) + toAsn1Length((24 * 1024 * 1024) + 1)

        XCTAssertThrowsError(try TagReader.parseInitialFileRead(header)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testGetResponseBudgetRejectsUnboundedChaining() {
        XCTAssertNoThrow(try TagReader.validateChainedResponseBudget(
            currentByteCount: (2 * 1024 * 1024) - 1,
            incomingByteCount: 1,
            segmentCount: 512
        ))

        XCTAssertThrowsError(try TagReader.validateChainedResponseBudget(
            currentByteCount: 2 * 1024 * 1024,
            incomingByteCount: 1,
            segmentCount: 512
        )) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }

        XCTAssertThrowsError(try TagReader.validateChainedResponseBudget(
            currentByteCount: 0,
            incomingByteCount: 1,
            segmentCount: 513
        )) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testGetResponseLengthTreatsZeroAsMaximumShortResponseLength() {
        XCTAssertEqual(TagReader.getResponseLength(sw2: 0x00), 256)
        XCTAssertEqual(TagReader.getResponseLength(sw2: 0x01), 1)
        XCTAssertEqual(TagReader.getResponseLength(sw2: 0xA0), 160)
        XCTAssertEqual(TagReader.getResponseLength(sw2: 0xFF), 255)
    }

    func testMSEAlgorithmIdentifierRejectsInvalidOIDBeforeAPDUConstruction() throws {
        XCTAssertThrowsError(try TagReader.mseAlgorithmIdentifierData(oid: "not an oid")) { error in
            guard case NFCPassportReaderError.InvalidDataPassed = error else {
                XCTFail("Expected InvalidDataPassed, got \(error)")
                return
            }
        }
    }

    func testMSEAlgorithmIdentifierUsesPrivateAlgorithmTagForValidOID() throws {
        let paceOIDString = "0.4.0.127.0.7.2.2.4.2.2"
        let chipAuthenticationOIDString = SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID
        let paceOID = try TagReader.mseAlgorithmIdentifierData(oid: paceOIDString)
        let chipAuthenticationOID = try TagReader.mseAlgorithmIdentifierData(oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID)

        XCTAssertEqual(paceOID.first, 0x80)
        XCTAssertEqual(chipAuthenticationOID.first, 0x80)
        XCTAssertEqual(paceOID.dropFirst(), oidToBytes(oid: paceOIDString, replaceTag: false).dropFirst())
        XCTAssertEqual(chipAuthenticationOID.dropFirst(), oidToBytes(oid: chipAuthenticationOIDString, replaceTag: false).dropFirst())
    }

    func testMSEKeyIdentifierRejectsNegativeValuesBeforeAPDUConstruction() throws {
        XCTAssertThrowsError(try TagReader.mseKeyIdentifierData(keyId: -1)) { error in
            guard case NFCPassportReaderError.InvalidDataPassed = error else {
                XCTFail("Expected InvalidDataPassed, got \(error)")
                return
            }
        }
    }

    func testMSEKeyIdentifierOmitsAbsentAndZeroValues() throws {
        XCTAssertNil(try TagReader.mseKeyIdentifierData(keyId: nil))
        XCTAssertNil(try TagReader.mseKeyIdentifierData(keyId: 0))
    }

    func testMSEKeyIdentifierWrapsPositiveValues() throws {
        XCTAssertEqual(try TagReader.mseKeyIdentifierData(keyId: 1), [0x84, 0x01, 0x01])
        XCTAssertEqual(try TagReader.mseKeyIdentifierData(keyId: 0x012C), [0x84, 0x02, 0x01, 0x2C])
    }

    func testPACEAuthenticationTokenParsingAcceptsCAMBeforeToken() throws {
        let response = wrapDO(b: 0x8A, arr: [0xAA, 0xBB, 0xCC]) +
            wrapDO(b: 0x86, arr: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

        let parsed = try PACEHandler.authenticationTokenAndCAMData(from: response)

        XCTAssertEqual(parsed.authenticationToken, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        XCTAssertEqual(parsed.encryptedCAMData, [0xAA, 0xBB, 0xCC])
    }

    func testPACEAuthenticationTokenParsingRejectsMissingToken() {
        let response = wrapDO(b: 0x8A, arr: [0xAA, 0xBB, 0xCC])

        XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: response)) { error in
            guard case NFCPassportReaderError.PACEError = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
        }
    }

    func testPACEAuthenticationTokenParsingRejectsDuplicateToken() {
        let token = [UInt8](repeating: 0x01, count: 8)
        let response = wrapDO(b: 0x86, arr: token) + wrapDO(b: 0x86, arr: token)

        XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: response)) { error in
            guard case NFCPassportReaderError.PACEError(let step, let reason) = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
            XCTAssertEqual(step, "Step3 KeyAgreement")
            XCTAssertEqual(reason, "Malformed passport authentication response")
        }
    }

    func testPACEAuthenticationTokenParsingRejectsDuplicateCAMData() {
        let token = [UInt8](repeating: 0x01, count: 8)
        let response = wrapDO(b: 0x86, arr: token) +
            wrapDO(b: 0x8A, arr: [0xAA]) +
            wrapDO(b: 0x8A, arr: [0xBB])

        XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: response)) { error in
            guard case NFCPassportReaderError.PACEError(let step, let reason) = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
            XCTAssertEqual(step, "Step3 KeyAgreement")
            XCTAssertEqual(reason, "Malformed passport authentication response")
        }
    }

    func testPACEAuthenticationTokenParsingRejectsUnknownObjects() {
        let token = [UInt8](repeating: 0x01, count: 8)
        let response = wrapDO(b: 0x86, arr: token) + wrapDO(b: 0x87, arr: [0xAA])

        XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: response)) { error in
            guard case NFCPassportReaderError.PACEError(let step, let reason) = error else {
                XCTFail("Expected PACEError, got \(error)")
                return
            }
            XCTAssertEqual(step, "Step3 KeyAgreement")
            XCTAssertEqual(reason, "Malformed passport authentication response")
        }
    }

    func testPACEAuthenticationTokenParsingRejectsWrongLengthToken() {
        for token in [[0x01], [UInt8](repeating: 0x02, count: 7), [UInt8](repeating: 0x03, count: 9)] {
            let response = wrapDO(b: 0x86, arr: token)

            XCTAssertThrowsError(try PACEHandler.authenticationTokenAndCAMData(from: response)) { error in
                guard case NFCPassportReaderError.PACEError(let step, let reason) = error else {
                    XCTFail("Expected PACEError, got \(error)")
                    return
                }
                XCTAssertEqual(step, "Step3 KeyAgreement")
                XCTAssertEqual(reason, "Invalid passport authentication token length")
            }
        }
    }

    func testPACEAuthenticationTokenComparisonUsesExactBytes() {
        XCTAssertTrue(PACEHandler.constantTimeEqual([0x01, 0x02, 0x03], [0x01, 0x02, 0x03]))
        XCTAssertFalse(PACEHandler.constantTimeEqual([0x01, 0x02, 0x03], [0x01, 0x02, 0x04]))
        XCTAssertFalse(PACEHandler.constantTimeEqual([0x01, 0x02, 0x03], [0x01, 0x02]))
    }

    @available(iOS 15, *)
    func testPACEExpectedNonceLengthMatchesCipherAndKeyLength() throws {
        XCTAssertEqual(try PACEHandler.expectedNonceLength(cipherAlg: "DESede", keyLength: 128), 16)
        XCTAssertEqual(try PACEHandler.expectedNonceLength(cipherAlg: "AES", keyLength: 128), 16)
        XCTAssertEqual(try PACEHandler.expectedNonceLength(cipherAlg: "AES", keyLength: 192), 32)
        XCTAssertEqual(try PACEHandler.expectedNonceLength(cipherAlg: "AES", keyLength: 256), 32)

        XCTAssertThrowsError(try PACEHandler.expectedNonceLength(cipherAlg: "AES", keyLength: 512)) { error in
            guard case NFCPassportReaderError.UnsupportedCipherAlgorithm = error else {
                XCTFail("Expected UnsupportedCipherAlgorithm, got \(error)")
                return
            }
        }
        XCTAssertThrowsError(try PACEHandler.expectedNonceLength(cipherAlg: "Blowfish", keyLength: 128)) { error in
            guard case NFCPassportReaderError.UnsupportedCipherAlgorithm = error else {
                XCTFail("Expected UnsupportedCipherAlgorithm, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    func testPACEIntegratedMappingRejectsUnsupportedCipherMetadataBeforeEncryption() {
        XCTAssertThrowsError(try PACEHandler.integratedMappingField(
            passportNonce: [UInt8](repeating: 0x01, count: 16),
            terminalNonce: [UInt8](repeating: 0x02, count: 64),
            cipherAlg: "AES",
            keyLength: 512,
            primeBitLength: 256
        )) { error in
            guard case NFCPassportReaderError.UnsupportedCipherAlgorithm = error else {
                XCTFail("Expected UnsupportedCipherAlgorithm, got \(error)")
                return
            }
        }
    }

    private func placeholderPublicKey() -> OpaquePointer {
        OpaquePointer(bitPattern: 0x01)!
    }

    func testChipAuthenticationChunkingRejectsInvalidSegmentSizesWithoutTrapping() {
        XCTAssertEqual(ChipAuthenticationHandler.chunk(data: [0x01, 0x02], segmentSize: 0), [])
        XCTAssertEqual(ChipAuthenticationHandler.chunk(data: [0x01, 0x02], segmentSize: -1), [])
        XCTAssertEqual(ChipAuthenticationHandler.chunk(data: [], segmentSize: 224), [])
    }

    func testChipAuthenticationChunkingPreservesSegmentOrderAndRemainder() {
        XCTAssertEqual(
            ChipAuthenticationHandler.chunk(data: [0x01, 0x02, 0x03, 0x04, 0x05], segmentSize: 2),
            [[0x01, 0x02], [0x03, 0x04], [0x05]]
        )
    }

    func testChipAuthenticationPublicKeyInfoCleanupClearsRetainedNativeKey() throws {
        let key = try OpenSSLUtils.generateECKeyPair(
            curveNID: PACEInfo.getParameterSpec(stdDomainParam: PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
        )
        let publicKeyInfo = ChipAuthenticationPublicKeyInfo(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            pubKey: key
        )

        XCTAssertNotNil(publicKeyInfo.pubKey)

        publicKeyInfo.removeSensitiveDataForPrivacy()

        XCTAssertNil(publicKeyInfo.pubKey)
    }

    @MainActor
    func testChipAuthenticationCleanupClearsRetryMetadata() {
        let handler = ChipAuthenticationHandler()
        let publicKeyInfo = ChipAuthenticationPublicKeyInfo(
            oid: SecurityInfo.ID_PK_ECDH_OID,
            pubKey: placeholderPublicKey(),
            keyId: 7,
            ownsPublicKey: false
        )
        handler.gaSegments = [[0x01], [0x02]]
        handler.chipAuthInfos = [
            7: ChipAuthenticationInfo(
                oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
                version: 2,
                keyId: 7
            )
        ]
        handler.chipAuthPublicKeyInfos = [publicKeyInfo]
        handler.isChipAuthenticationSupported = true

        handler.removeSensitiveData()

        XCTAssertTrue(handler.gaSegments.isEmpty)
        XCTAssertTrue(handler.chipAuthInfos.isEmpty)
        XCTAssertTrue(handler.chipAuthPublicKeyInfos.isEmpty)
        XCTAssertNil(publicKeyInfo.pubKey)
        XCTAssertFalse(handler.isChipAuthenticationSupported)
    }

    func testChipAuthenticationMetadataAllowsExactDuplicateInfoForSameKeyId() throws {
        let first = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
            version: 2,
            keyId: 7
        )
        let duplicate = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
            version: 2,
            keyId: 7
        )

        let metadata = try ChipAuthenticationHandler.metadata(from: [first, duplicate])

        XCTAssertEqual(metadata.infosByKeyId.count, 1)
        XCTAssertTrue(metadata.infosByKeyId[7] === first)
    }

    func testChipAuthenticationMetadataRejectsConflictingDuplicateInfoForSameKeyId() {
        let first = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
            version: 2,
            keyId: 7
        )
        let conflicting = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID,
            version: 2,
            keyId: 7
        )

        XCTAssertThrowsError(try ChipAuthenticationHandler.metadata(from: [first, conflicting])) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testChipAuthenticationMetadataTreatsMissingAndZeroKeyIdsAsSameSlot() {
        let defaultKeyInfo = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_128_OID,
            version: 2
        )
        let zeroKeyInfo = ChipAuthenticationInfo(
            oid: SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID,
            version: 2,
            keyId: 0
        )

        XCTAssertThrowsError(try ChipAuthenticationHandler.metadata(from: [defaultKeyInfo, zeroKeyInfo])) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    @MainActor
    func testChipAuthenticationContinuesAfterUnsupportedPublicKeyWithoutAttemptFailure() async throws {
        let handler = ChipAuthenticationHandler()
        handler.isChipAuthenticationSupported = true
        handler.chipAuthPublicKeyInfos = [
            ChipAuthenticationPublicKeyInfo(
                oid: SecurityInfo.ID_PK_ECDH_OID,
                pubKey: placeholderPublicKey(),
                keyId: 1,
                ownsPublicKey: false
            ),
            ChipAuthenticationPublicKeyInfo(
                oid: SecurityInfo.ID_PK_ECDH_OID,
                pubKey: placeholderPublicKey(),
                keyId: 2,
                ownsPublicKey: false
            )
        ]
        var attemptedKeyIds = [Int?]()

        try await handler.doChipAuthentication { publicKeyInfo in
            attemptedKeyIds.append(publicKeyInfo.keyId)
            return publicKeyInfo.keyId == 2
        }

        XCTAssertEqual(attemptedKeyIds, [1, 2])
    }

    @MainActor
    func testChipAuthenticationStopsAfterThrownAttemptFailure() async {
        let handler = ChipAuthenticationHandler()
        handler.isChipAuthenticationSupported = true
        handler.chipAuthPublicKeyInfos = [
            ChipAuthenticationPublicKeyInfo(
                oid: SecurityInfo.ID_PK_ECDH_OID,
                pubKey: placeholderPublicKey(),
                keyId: 1,
                ownsPublicKey: false
            ),
            ChipAuthenticationPublicKeyInfo(
                oid: SecurityInfo.ID_PK_ECDH_OID,
                pubKey: placeholderPublicKey(),
                keyId: 2,
                ownsPublicKey: false
            )
        ]
        var attemptedKeyIds = [Int?]()

        do {
            try await handler.doChipAuthentication { publicKeyInfo in
                attemptedKeyIds.append(publicKeyInfo.keyId)
                throw NFCPassportReaderError.ChipAuthenticationFailed
            }
            XCTFail("Expected ChipAuthenticationFailed")
        } catch {
            guard case NFCPassportReaderError.ChipAuthenticationFailed = error else {
                XCTFail("Expected ChipAuthenticationFailed, got \(error)")
                return
            }
        }

        XCTAssertEqual(attemptedKeyIds, [1])
    }

    @MainActor
    func testChipAuthenticationClearsPendingGeneralAuthenticationSegmentsAfterSuccessfulAttempt() async throws {
        let handler = ChipAuthenticationHandler()

        let result = try await handler.withPendingGeneralAuthenticationSegments([[0x01], [0x02]]) {
            XCTAssertEqual(handler.gaSegments, [[0x01], [0x02]])
            return "completed"
        }

        XCTAssertEqual(result, "completed")
        XCTAssertTrue(handler.gaSegments.isEmpty)
    }

    @MainActor
    func testChipAuthenticationClearsPendingGeneralAuthenticationSegmentsAfterFailedAttempt() async {
        let handler = ChipAuthenticationHandler()

        do {
            try await handler.withPendingGeneralAuthenticationSegments([[0xAA], [0xBB]]) {
                XCTAssertEqual(handler.gaSegments, [[0xAA], [0xBB]])
                throw NFCPassportReaderError.ChipAuthenticationFailed
            }
            XCTFail("Expected ChipAuthenticationFailed")
        } catch {
            guard case NFCPassportReaderError.ChipAuthenticationFailed = error else {
                XCTFail("Expected ChipAuthenticationFailed, got \(error)")
                return
            }
        }

        XCTAssertTrue(handler.gaSegments.isEmpty)
    }
    #endif

    func testByteIntegerHelpersUseBigEndianArithmetic() {
        XCTAssertEqual(binToHex([0x01, 0x02, 0x03]), 0x010203)
        XCTAssertEqual(binToHex([UInt8](repeating: 0xFF, count: 9)), 0)
        XCTAssertEqual(binToInt([0x01, 0x2C]), 300)
        XCTAssertEqual(intToBin(0x2C), [0x2C])
        XCTAssertEqual(intToBin(0x012C), [0x01, 0x2C])
        XCTAssertEqual(intToBin(0x012C, pad: 4), [0x01, 0x2C])
        XCTAssertEqual(intToBin(-1), [])
        XCTAssertEqual(intToBin(-1, pad: 4), [])
        XCTAssertEqual(intToBytes(val: -1, removePadding: true), [])
        XCTAssertEqual(intToBytes(val: -1, removePadding: false), [])
    }

    func testSecureMessagingSequenceCounterIncrementDoesNotUseTruncatingIntegerConversion() {
        let sm = SecureMessaging(ksenc: [], ksmac: [], ssc: [0x00, 0x00, 0xFF])

        XCTAssertEqual(sm.incSSC(), [0x00, 0x01, 0x00])
        XCTAssertEqual(sm.incSSC(), [0x00, 0x01, 0x00])
    }

    func testSecureMessagingProtectDoesNotAdvanceSequenceCounterWhenLocalProtectionFails() throws {
        let sm = SecureMessaging(ksenc: [], ksmac: [], ssc: [0x00, 0x00, 0x00, 0x00])
        let apduData: [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01, 0x00]
        let apdu = try XCTUnwrap(NFCISO7816APDU(data: Data(apduData)))

        XCTAssertThrowsError(try sm.protect(apdu: apdu)) { error in
            guard case NFCPassportReaderError.UnableToProtectAPDU = error else {
                XCTFail("Expected UnableToProtectAPDU, got \(error)")
                return
            }
        }

        XCTAssertEqual(sm.sequenceCounter, [0x00, 0x00, 0x00, 0x00])
    }

    func testSecureMessagingCleanupClearsSessionKeysAndCounter() throws {
        let sm = SecureMessaging(
            ksenc: [UInt8](repeating: 0x11, count: 16),
            ksmac: [UInt8](repeating: 0x22, count: 16),
            ssc: [UInt8](repeating: 0x33, count: 8)
        )

        XCTAssertFalse(mirroredByteArray(from: sm, named: "ksenc").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: sm, named: "ksmac").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: sm, named: "ssc").isEmpty)

        sm.removeSensitiveData()

        XCTAssertTrue(mirroredByteArray(from: sm, named: "ksenc").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: sm, named: "ksmac").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: sm, named: "ssc").isEmpty)

        let apduData: [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01, 0x00]
        let apdu = try XCTUnwrap(NFCISO7816APDU(data: Data(apduData)))
        XCTAssertThrowsError(try sm.protect(apdu: apdu)) { error in
            guard case NFCPassportReaderError.UnableToProtectAPDU = error else {
                XCTFail("Expected UnableToProtectAPDU, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testBACHandlerCleanupClearsDerivedKeysAndRandoms() throws {
        let bac = BACHandler()
        _ = try bac.deriveDocumentBasicAccessKeys(mrz: "ABC1234567001012300101")
        _ = try bac.authentication(rnd_icc: [UInt8](repeating: 0x44, count: 8))

        XCTAssertFalse(mirroredByteArray(from: bac, named: "ksenc").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: bac, named: "ksmac").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: bac, named: "rnd_icc").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: bac, named: "rnd_ifd").isEmpty)
        XCTAssertFalse(mirroredByteArray(from: bac, named: "kifd").isEmpty)

        bac.removeSensitiveData()

        XCTAssertTrue(mirroredByteArray(from: bac, named: "ksenc").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: bac, named: "ksmac").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: bac, named: "rnd_icc").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: bac, named: "rnd_ifd").isEmpty)
        XCTAssertTrue(mirroredByteArray(from: bac, named: "kifd").isEmpty)
    }

    func testUnpadHandlesEmptyAndZeroOnlyInputWithoutTrapping() {
        XCTAssertEqual(unpad([]), [])
        XCTAssertEqual(unpad([0x00, 0x00]), [0x00, 0x00])
        XCTAssertEqual(unpad([0x01, 0x80, 0x00]), [0x01])
    }

    func testStrictUnpadRejectsMissingPaddingMarker() {
        XCTAssertNil(strictUnpad([]))
        XCTAssertNil(strictUnpad([0x00, 0x00]))
        XCTAssertNil(strictUnpad([0x01, 0x02, 0x00]))
        XCTAssertEqual(strictUnpad([0x01, 0x80, 0x00]), [0x01])
    }

    func testDESMACRejectsShortKeyWithoutTrapping() {
        XCTAssertEqual(desMAC(key: [], msg: []), [])
        XCTAssertEqual(desMAC(key: [0x00], msg: [0x00]), [])
    }

    func testCryptoWrappersRejectInvalidKeyAndIVLengths() {
        XCTAssertEqual(AESEncrypt(key: [], message: [0x00], iv: [UInt8](repeating: 0, count: 16)), [])
        XCTAssertEqual(AESDecrypt(key: [UInt8](repeating: 0, count: 16), message: [0x00], iv: []), [])
        XCTAssertEqual(AESECBEncrypt(key: [0x00], message: [0x00]), [])
        XCTAssertEqual(tripleDESEncrypt(key: [0x00], message: [0x00], iv: [UInt8](repeating: 0, count: 8)), [])
        XCTAssertEqual(tripleDESDecrypt(key: [UInt8](repeating: 0, count: 16), message: [0x00], iv: []), [])
        XCTAssertEqual(DESEncrypt(key: [0x00], message: [0x00], iv: [UInt8](repeating: 0, count: 8)), [])
        XCTAssertEqual(DESDecrypt(key: [UInt8](repeating: 0, count: 8), message: [0x00], iv: []), [])
    }

    func testSessionKeyGeneratorUsesTypedUnsupportedCipherErrors() {
        let generator = SecureMessagingSessionKeyGenerator()
        let lowLevelFragments = ["Blowfish-448", "AES-512", "DESede", "key length"]

        let attempts: [() throws -> [UInt8]] = [
            {
                try generator.deriveKey(
                    keySeed: [UInt8](repeating: 0x01, count: 32),
                    cipherAlgName: "Blowfish-448",
                    keyLength: 448,
                    mode: .ENC_MODE
                )
            },
            {
                try generator.deriveKey(
                    keySeed: [UInt8](repeating: 0x02, count: 32),
                    cipherAlgName: "AES",
                    keyLength: 512,
                    mode: .MAC_MODE
                )
            },
            {
                try generator.deriveKey(
                    keySeed: [UInt8](repeating: 0x03, count: 32),
                    cipherAlgName: "DESede",
                    keyLength: 64,
                    mode: .ENC_MODE
                )
            }
        ]

        for attempt in attempts {
            XCTAssertThrowsError(try attempt()) { error in
                guard let readerError = error as? NFCPassportReaderError else {
                    return XCTFail("Expected NFCPassportReaderError")
                }
                guard case .UnsupportedCipherAlgorithm = readerError else {
                    return XCTFail("Expected UnsupportedCipherAlgorithm, got \(readerError)")
                }

                for fragment in lowLevelFragments {
                    XCTAssertFalse(readerError.value.localizedCaseInsensitiveContains(fragment))
                    XCTAssertFalse(readerError.localizedDescription.localizedCaseInsensitiveContains(fragment))
                    XCTAssertFalse(String(describing: readerError).localizedCaseInsensitiveContains(fragment))
                }
            }
        }
    }

    func testSessionKeyGeneratorRejectsEmptyKeySeed() {
        let generator = SecureMessagingSessionKeyGenerator()
        let sensitiveFragments = ["Kseed", "KSenc", "KSmac", "0011223344556677"]

        XCTAssertThrowsError(
            try generator.deriveKey(
                keySeed: [],
                cipherAlgName: "AES",
                keyLength: 128,
                mode: .ENC_MODE
            )
        ) { error in
            guard let readerError = error as? NFCPassportReaderError else {
                return XCTFail("Expected NFCPassportReaderError")
            }
            guard case .InvalidDataPassed = readerError else {
                return XCTFail("Expected InvalidDataPassed, got \(readerError)")
            }

            for fragment in sensitiveFragments {
                XCTAssertFalse(readerError.value.localizedCaseInsensitiveContains(fragment))
                XCTAssertFalse(readerError.localizedDescription.localizedCaseInsensitiveContains(fragment))
                XCTAssertFalse(String(describing: readerError).localizedCaseInsensitiveContains(fragment))
            }
        }
    }

    func testSessionKeyGeneratorPreservesExpectedKeyLengths() throws {
        let generator = SecureMessagingSessionKeyGenerator()
        let seed = [UInt8](repeating: 0x42, count: 32)

        XCTAssertEqual(try generator.deriveKey(keySeed: seed, mode: .ENC_MODE).count, 24)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "AES", keyLength: 128, mode: .ENC_MODE).count, 16)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "AES", keyLength: 192, mode: .MAC_MODE).count, 24)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "AES", keyLength: 256, mode: .PACE_MODE).count, 32)
    }

    func testSessionKeyGeneratorNormalizesSupportedCipherNames() throws {
        let generator = SecureMessagingSessionKeyGenerator()
        let seed = [UInt8](repeating: 0x24, count: 32)

        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "desede", keyLength: 128, mode: .ENC_MODE).count, 24)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "3des", keyLength: 112, mode: .MAC_MODE).count, 24)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "aes-128", keyLength: 128, mode: .ENC_MODE).count, 16)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "aes-192", keyLength: 192, mode: .MAC_MODE).count, 24)
        XCTAssertEqual(try generator.deriveKey(keySeed: seed, cipherAlgName: "aes-256", keyLength: 256, mode: .PACE_MODE).count, 32)
    }

    @available(iOS 15, *)
    func testPACEKeyCreationRejectsMissingCredentialBeforeHashing() {
        for credential in ["", " ", "\n\t"] {
            XCTAssertThrowsError(try PACEHandler.createPaceKey(
                from: credential,
                keyReference: .can,
                cipherAlg: "AES",
                keyLength: 128
            )) { error in
                guard case NFCPassportReaderError.PACEError(let step, let reason) = error else {
                    XCTFail("Expected PACEError, got \(error)")
                    return
                }
                XCTAssertEqual(step, "Key derivation")
                XCTAssertEqual(reason, "Missing PACE credential")
            }
        }
    }

    @available(iOS 15, *)
    func testPACEKeyCreationPreservesValidCredentialDerivation() throws {
        XCTAssertEqual(try PACEHandler.createPaceKey(
            from: "123456",
            keyReference: .can,
            cipherAlg: "AES",
            keyLength: 128
        ).count, 16)
        XCTAssertEqual(try PACEHandler.createPaceKey(
            from: "L898902C<369080619406236",
            keyReference: .mrz,
            cipherAlg: "DESede",
            keyLength: 128
        ).count, 24)
    }

    func testDESDecryptUsesCBCInitializationVector() {
        let key: [UInt8] = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1]
        let iv: [UInt8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]
        let message: [UInt8] = [0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x20]

        let encrypted = DESEncrypt(key: key, message: message, iv: iv)
        XCTAssertFalse(encrypted.isEmpty)
        XCTAssertEqual(DESDecrypt(key: key, message: encrypted, iv: iv), message)
        XCTAssertNotEqual(DESDecrypt(key: key, message: encrypted, iv: [UInt8](repeating: 0, count: 8)), message)
    }

    func testInvalidOIDEncodingDoesNotTrap() {
        XCTAssertEqual(OpenSSLUtils.asn1EncodeOID(oid: "not an oid"), [])
        XCTAssertEqual(oidToBytes(oid: "not an oid", replaceTag: true), [])
    }
    

    func testDES3Encryption() {
        let msg = [UInt8]("maryhadalittlelambaaaaaa".utf8)
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let key : [UInt8] = [191, 73, 56, 112, 158, 148, 146, 127, 157, 76, 117, 8, 239, 128, 87, 42]
        let enc = tripleDESEncrypt(key: key, message: msg, iv: iv)
        
        XCTAssertEqual( binToHexRep(enc), "4DAF068AB358BC9E8F5E916D3DEDE750D92315370E44D9B3" )
    }
    
    func testDES3Decryption() {
        let enc = hexRepToBin("4DAF068AB358BC9E8F5E916D3DEDE750D92315370E44D9B3")
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let key : [UInt8] = [191, 73, 56, 112, 158, 148, 146, 127, 157, 76, 117, 8, 239, 128, 87, 42]
        let dec = tripleDESDecrypt(key: key, message: enc, iv: iv)
        
        let val = String(data:Data(dec), encoding:.utf8)
        XCTAssertEqual( val, "maryhadalittlelambaaaaaa" )
    }
    
    func testSecureMessagingProtect() throws {
        
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA7")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01, 0x00]
        guard let apdu = NFCISO7816APDU(data: Data(data)) else {
            XCTFail("Unable to create test APDU")
            return
        }
        let protApdu = try sm.protect(apdu: apdu)
        
        XCTAssertNotNil(protApdu.data )
        XCTAssertEqual( protApdu.instructionClass, 0x0c )
        XCTAssertEqual( protApdu.instructionCode, 0xA4 )
        XCTAssertEqual( protApdu.p1Parameter, 0x02 )
        XCTAssertEqual( protApdu.p2Parameter, 0x0c )
        
        let hexDataRep = binToHexRep([UInt8](protApdu.data ?? Data()))
        XCTAssertEqual( hexDataRep, "870901CC69089F8F1AB4698E08B6334B3ABD5A9E09" )
        XCTAssertEqual( protApdu.expectedResponseLength, 0 )
    }

    func testSecureMessagingUnprotectNoData() {
        
        // Note - same keys as above but SSC incremented by 1 as per spec
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = hexRepToBin("990290008E08C61E440E5DD41546")
        let protRespApdu = ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00)
        
        XCTAssertNoThrow(try sm.unprotect( rapdu: protRespApdu )) { rapdu in
            XCTAssertEqual(binToHexRep(rapdu.data), "")
            XCTAssertEqual( rapdu.sw1, 0x90 )
            XCTAssertEqual( rapdu.sw2, 0x00 )
        }
    }

    func testSecureMessagingUnprotectDoesNotAdvanceSequenceCounterForPlainStatusError() throws {
        let sm = SecureMessaging(
            ksenc: [UInt8](repeating: 0x11, count: 16),
            ksmac: [UInt8](repeating: 0x22, count: 16),
            ssc: [0x00, 0x00, 0x00, 0x10]
        )
        let statusError = ResponseAPDU(data: [], sw1: 0x6A, sw2: 0x82)

        let response = try sm.unprotect(rapdu: statusError)

        XCTAssertEqual(response.sw1, 0x6A)
        XCTAssertEqual(response.sw2, 0x82)
        XCTAssertEqual(sm.sequenceCounter, [0x00, 0x00, 0x00, 0x10])
    }

    func testSecureMessagingUnprotectWithData() {
        
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = hexRepToBin("87090156D0EFCC887F8973990290008E08D6B9C0DA21DC965F")
        let protRespApdu = ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00)
        
        XCTAssertNoThrow(try sm.unprotect( rapdu: protRespApdu )) { rapdu in
            XCTAssertEqual(binToHexRep(rapdu.data), "615B5F1F")
            XCTAssertEqual( rapdu.sw1, 0x90 )
            XCTAssertEqual( rapdu.sw2, 0x00 )

        }
    }

    func testSecureMessagingRejectsAuthenticatedResponseWithMalformedDecryptedPadding() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")

        let malformedPaddedPlaintext = [UInt8](repeating: 0xA5, count: 8)
        let encryptedData = tripleDESEncrypt(
            key: KSenc,
            message: malformedPaddedPlaintext,
            iv: [0, 0, 0, 0, 0, 0, 0, 0]
        )
        XCTAssertFalse(encryptedData.isEmpty)

        let do87 = [0x87, 0x09, 0x01] + encryptedData
        let do99 = hexRepToBin("99029000")
        let responseSSC = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc).incSSC()
        var checksum = mac(algoName: .DES, key: KSmac, msg: pad(responseSSC + do87 + do99, blockSize: 8))
        checksum = [UInt8](checksum.prefix(8))
        XCTAssertEqual(checksum.count, 8)

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let response = ResponseAPDU(data: do87 + do99 + [0x8E, 0x08] + checksum, sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: response)) { error in
            guard case NFCPassportReaderError.UnableToUnprotectAPDU = error else {
                XCTFail("Expected UnableToUnprotectAPDU, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsMalformedChecksumObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("990290008E08C61E44"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                XCTFail("Expected MissingMandatoryFields, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsMalformedEncryptedDataObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("87300156D0990290008E08D6B9C0DA21DC965F"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.D087Malformed = error else {
                XCTFail("Expected D087Malformed, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsEmptyEncryptedDataObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("870101990290008E08D6B9C0DA21DC965F"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.D087Malformed = error else {
                XCTFail("Expected D087Malformed, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsUnalignedEncryptedDataObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("870301AABB990290008E08D6B9C0DA21DC965F"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.D087Malformed = error else {
                XCTFail("Expected D087Malformed, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsTrailingBytesAfterChecksumObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("990290008E08C61E440E5DD4154600"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                XCTFail("Expected MissingMandatoryFields, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsEmptySuccessfulResponse() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: [], sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                XCTFail("Expected MissingMandatoryFields, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsTruncatedStatusObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("990290"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                XCTFail("Expected MissingMandatoryFields, got \(error)")
                return
            }
        }
    }

    func testSecureMessagingRejectsMalformedStatusObject() {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("9901908E08D6B9C0DA21DC965F"), sw1: 0x90, sw2: 0x00)

        XCTAssertThrowsError(try sm.unprotect(rapdu: malformed)) { error in
            guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                XCTFail("Expected MissingMandatoryFields, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testBACAuthenticationRejectsInvalidChallengeLengthBeforeRetainingIt() throws {
        let bac = BACHandler()
        _ = try bac.deriveDocumentBasicAccessKeys(mrz: "L898902C<369080619406236")

        for challenge in [[UInt8](), [UInt8](repeating: 0xA5, count: 7), [UInt8](repeating: 0xA5, count: 9)] {
            XCTAssertThrowsError(try bac.authentication(rnd_icc: challenge)) { error in
                guard case NFCPassportReaderError.MissingMandatoryFields = error else {
                    XCTFail("Expected MissingMandatoryFields, got \(error)")
                    return
                }
            }
            XCTAssertTrue(bac.rnd_icc.isEmpty)
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testBACSessionKeysRejectShortMutualAuthenticationResponse() {
        let bac = BACHandler()

        XCTAssertThrowsError(try bac.sessionKeys(data: [0x00, 0x01])) { error in
            guard case NFCPassportReaderError.InvalidMRZKey = error else {
                XCTFail("Expected InvalidMRZKey, got \(error)")
                return
            }
        }
    }

    @available(iOS 15, *)
    @MainActor
    func testBACSessionKeysVerifyMutualAuthenticationResponseMACAndNonceEchoes() throws {
        let bac = BACHandler()
        _ = try bac.deriveDocumentBasicAccessKeys(mrz: "L898902C<369080619406236")
        let rndICC = [UInt8](0x10...0x17)
        _ = try bac.authentication(rnd_icc: rndICC)

        let response = try syntheticBACMutualAuthenticationResponse(for: bac, chipKIFD: [UInt8](0x21...0x30))
        let (ksenc, ksmac, ssc) = try bac.sessionKeys(data: response)

        XCTAssertEqual(ksenc.count, 24)
        XCTAssertEqual(ksmac.count, 24)
        XCTAssertEqual(ssc, [UInt8](rndICC.suffix(4) + bac.rnd_ifd.suffix(4)))

        var tamperedMAC = response
        tamperedMAC[39] ^= 0x01
        XCTAssertThrowsError(try bac.sessionKeys(data: tamperedMAC)) { error in
            guard case NFCPassportReaderError.InvalidMRZKey = error else {
                XCTFail("Expected InvalidMRZKey, got \(error)")
                return
            }
        }

        var trailingBytes = response
        trailingBytes.append(0x00)
        XCTAssertThrowsError(try bac.sessionKeys(data: trailingBytes)) { error in
            guard case NFCPassportReaderError.InvalidMRZKey = error else {
                XCTFail("Expected InvalidMRZKey, got \(error)")
                return
            }
        }

        let mismatchedNonceResponse = try syntheticBACMutualAuthenticationResponse(
            for: bac,
            chipKIFD: [UInt8](0x31...0x40),
            rndICCOverride: [UInt8](repeating: 0xA5, count: 8)
        )
        XCTAssertThrowsError(try bac.sessionKeys(data: mismatchedNonceResponse)) { error in
            guard case NFCPassportReaderError.InvalidMRZKey = error else {
                XCTFail("Expected InvalidMRZKey, got \(error)")
                return
            }
        }
    }
    
    
    func testConvertECDSAPlainTODer() {
        let sigText = "67e147aac644325792dfa0b1615956dc4ed54e8cd859341571db98003431936e0651e9a3cdbcea3c8accd75a6f6bf07eb6bcf9ad1728e21aa854049e634e6fbf"
        let sig = hexRepToBin(sigText)
        
        guard let ecsig = ECDSA_SIG_new() else {
            XCTFail("Unable to allocate ECDSA signature")
            return
        }
        defer { ECDSA_SIG_free(ecsig) }
        sig.withUnsafeBufferPointer { (unsafeBufPtr) in
            guard let unsafePointer = unsafeBufPtr.baseAddress else { return }
            let r = BN_bin2bn(unsafePointer, 32, nil)
            let s = BN_bin2bn(unsafePointer + 32, 32, nil)
            ECDSA_SIG_set0(ecsig, r, s)
        }
        
        let derLength = i2d_ECDSA_SIG(ecsig, nil)
        guard derLength > 0 else {
            XCTFail("Unable to DER-encode ECDSA signature")
            return
        }
        var derBytes = [UInt8](repeating: 0, count: Int(derLength))
        derBytes.withUnsafeMutableBufferPointer { buffer in
            var pointer = buffer.baseAddress
            _ = i2d_ECDSA_SIG(ecsig, &pointer)
        }

        XCTAssertNoThrow(try SimpleASN1Node.parse(derBytes), "Successfully parsed")
    }

    func testVerifyECDSASignatureRejectsMalformedSignature() {
        guard let key = EVP_PKEY_new() else {
            XCTFail("Unable to allocate EVP_PKEY")
            return
        }
        defer { EVP_PKEY_free(key) }

        XCTAssertFalse(OpenSSLUtils.verifyECDSASignature(publicKey: key, signature: [], data: []))
        XCTAssertFalse(OpenSSLUtils.verifyECDSASignature(publicKey: key, signature: [0x01], data: []))
    }

    func testOpenSSLSignatureHelpersRejectOversizedInputsBeforeNativeWork() {
        guard let key = EVP_PKEY_new() else {
            XCTFail("Unable to allocate EVP_PKEY")
            return
        }
        defer { EVP_PKEY_free(key) }

        let oversizedSignature = [UInt8](repeating: 0x30, count: 64 * 1024 + 2)

        XCTAssertFalse(OpenSSLUtils.verifyECDSASignature(publicKey: key, signature: oversizedSignature, data: []))
        XCTAssertFalse(OpenSSLUtils.verifySignature(data: [], signature: oversizedSignature, pubKey: key, digestType: "sha256"))
        XCTAssertThrowsError(try OpenSSLUtils.decryptRSASignature(signature: Data(oversizedSignature), pubKey: key)) { error in
            guard case OpenSSLError.UnableToDecryptRSASignature = error else {
                XCTFail("Expected UnableToDecryptRSASignature, got \(error)")
                return
            }
        }
    }

    func testOpenSSLX509StackHelpersHandleNilPointers() {
        XCTAssertEqual(OpenSSLUtils.sk_X509_num(nil), 0)
        XCTAssertNil(OpenSSLUtils.sk_X509_value(nil, 0))
        XCTAssertNil(OpenSSLUtils.sk_X509_value(nil, -1))
        XCTAssertNil(OpenSSLUtils.sk_X509_value(nil, 1))
    }

    func testOpenSSLBIOToStringRejectsOversizedContent() {
        guard let bio = BIO_new(BIO_s_mem()) else {
            XCTFail("Unable to allocate BIO")
            return
        }
        defer { BIO_free(bio) }

        let oversizedText = [CChar](repeating: 0x41, count: 64 * 1024 + 1)
        let bytesWritten = oversizedText.withUnsafeBufferPointer { buffer in
            BIO_write(bio, buffer.baseAddress, Int32(oversizedText.count))
        }

        XCTAssertEqual(Int(bytesWritten), oversizedText.count)
        XCTAssertEqual(OpenSSLUtils.bioToString(bio: bio), "")
    }

    func testX509WrapperPreservesLargeSerialNumbersWithoutLongTruncation() {
        guard let serial = ASN1_INTEGER_new() else {
            XCTFail("Unable to allocate ASN1 serial number")
            return
        }
        defer { ASN1_INTEGER_free(serial) }

        let serialBytes = hexRepToBin("0102030405060708090A0B0C0D0E0F10")
        let serialBN = serialBytes.withUnsafeBufferPointer { buffer in
            BN_bin2bn(buffer.baseAddress, Int32(serialBytes.count), nil)
        }
        guard let serialBN else {
            XCTFail("Unable to allocate serial BIGNUM")
            return
        }
        defer { BN_free(serialBN) }

        guard BN_to_ASN1_INTEGER(serialBN, serial) != nil else {
            XCTFail("Unable to encode ASN1 serial number")
            return
        }

        XCTAssertEqual(X509Wrapper.serialNumberString(from: serial), "0102030405060708090A0B0C0D0E0F10")
    }

    func testOpenSSLTrustVerificationFailsClosedWhenMasterListCannotBeLoaded() throws {
        let certificate = try XCTUnwrap(makeSyntheticX509Wrapper())
        let missingMasterListURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("pem")

        let result = OpenSSLUtils.verifyTrustAndGetIssuerCertificate(
            x509: certificate,
            CAFile: missingMasterListURL
        )

        guard case let .failure(error) = result,
              case let OpenSSLError.UnableToVerifyX509CertificateForSOD(message) = error else {
            XCTFail("Expected UnableToVerifyX509CertificateForSOD, got \(result)")
            return
        }
        XCTAssertEqual(message, "Unable to load trusted certificates")
    }

    func testOpenSSLPublicKeyHelpersRejectUnsupportedKeyTypes() {
        guard let key = EVP_PKEY_new() else {
            XCTFail("Unable to allocate EVP_PKEY")
            return
        }
        defer { EVP_PKEY_free(key) }

        XCTAssertNil(OpenSSLUtils.getPublicKeyData(from: key))
        XCTAssertNil(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: [0x04, 0x01, 0x02, 0x03], params: key))
    }

    func testOpenSSLRejectsOversizedNativeParserInputsBeforeParsing() {
        let oversizedCMS = Data(repeating: 0x30, count: 2 * 1024 * 1024 + 1)
        let oversizedPublicKey = [UInt8](repeating: 0x30, count: 64 * 1024 + 1)

        XCTAssertThrowsError(try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der: oversizedCMS))
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(oversizedCMS, trustedCertificatesURL: nil))
        XCTAssertThrowsError(try OpenSSLUtils.readPublicKey(data: oversizedPublicKey))
    }

    func testOpenSSLRejectsEmptyNativeParserInputsBeforeParsing() {
        XCTAssertThrowsError(try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der: Data()))
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(Data(), trustedCertificatesURL: nil))
        XCTAssertThrowsError(try OpenSSLUtils.readPublicKey(data: []))
    }

    func testSignatureDigestNameSelectionCoversActiveAuthenticationAlgorithms() {
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-SHA1"), "sha1")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-SHA224"), "sha224")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-SHA256"), "sha256")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-SHA384"), "sha384")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-SHA512"), "sha512")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "ecdsa-plain-RIPEMD160"), "ripemd160")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: "RSASSA-PSS"), "sha256")
        XCTAssertEqual(OpenSSLUtils.digestName(forSignatureType: ""), "sha256")
    }

}

private func mirroredByteArray(from object: Any, named label: String) -> [UInt8] {
    Mirror(reflecting: object).children.first { $0.label == label }?.value as? [UInt8] ?? []
}

@available(iOS 15, *)
@MainActor
private func syntheticBACMutualAuthenticationResponse(
    for bac: BACHandler,
    chipKIFD: [UInt8],
    rndICCOverride: [UInt8]? = nil
) throws -> [UInt8] {
    let ksenc = mirroredByteArray(from: bac, named: "ksenc")
    let ksmac = mirroredByteArray(from: bac, named: "ksmac")
    guard !ksenc.isEmpty, !ksmac.isEmpty, chipKIFD.count == 16 else {
        throw NFCPassportReaderError.InvalidMRZKey
    }

    let rndICC = rndICCOverride ?? bac.rnd_icc
    let plaintext = rndICC + bac.rnd_ifd + chipKIFD
    let encryptedResponse = tripleDESEncrypt(
        key: ksenc,
        message: plaintext,
        iv: [0, 0, 0, 0, 0, 0, 0, 0]
    )
    var responseMAC = mac(algoName: .DES, key: ksmac, msg: pad(encryptedResponse, blockSize: 8))
    guard !encryptedResponse.isEmpty, !responseMAC.isEmpty else {
        throw NFCPassportReaderError.InvalidMRZKey
    }
    if responseMAC.count > 8 {
        responseMAC = [UInt8](responseMAC[0..<8])
    }
    return encryptedResponse + responseMAC
}

private func makeSyntheticX509Wrapper() -> X509Wrapper? {
    guard let cert = X509_new(),
          let key = try? OpenSSLUtils.generateECKeyPair(
            curveNID: PACEInfo.getParameterSpec(stdDomainParam: PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
          ) else {
        return nil
    }
    defer {
        X509_free(cert)
        EVP_PKEY_free(key)
    }

    guard X509_set_version(cert, 2) == 1,
          let serial = X509_get_serialNumber(cert),
          ASN1_INTEGER_set(serial, 1) == 1,
          let notBefore = X509_getm_notBefore(cert),
          let notAfter = X509_getm_notAfter(cert),
          X509_gmtime_adj(notBefore, 0) != nil,
          X509_gmtime_adj(notAfter, 86400) != nil,
          X509_set_pubkey(cert, key) == 1,
          let name = X509_get_subject_name(cert) else {
        return nil
    }

    let commonName = [UInt8]("Synthetic Test Certificate".utf8)
    let didAddName = "CN".withCString { field in
        commonName.withUnsafeBufferPointer { value in
            X509_NAME_add_entry_by_txt(
                name,
                field,
                MBSTRING_ASC,
                value.baseAddress,
                Int32(commonName.count),
                -1,
                0
            )
        }
    }

    guard didAddName == 1,
          X509_set_issuer_name(cert, name) == 1,
          X509_sign(cert, key, EVP_sha256()) > 0 else {
        return nil
    }

    return X509Wrapper(with: cert)
}
