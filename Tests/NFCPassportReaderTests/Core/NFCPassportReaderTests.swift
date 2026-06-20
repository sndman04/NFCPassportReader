import XCTest
import CoreNFC
import OpenSSL

@testable import NFCPassportReader

public func XCTAssertNoThrow<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #file, line: UInt = #line, also validateResult: (T) -> Void) {
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
    #endif

    func testByteIntegerHelpersUseBigEndianArithmetic() {
        XCTAssertEqual(binToHex([0x01, 0x02, 0x03]), 0x010203)
        XCTAssertEqual(binToHex([UInt8](repeating: 0xFF, count: 9)), 0)
        XCTAssertEqual(binToInt([0x01, 0x2C]), 300)
        XCTAssertEqual(intToBin(0x2C), [0x2C])
        XCTAssertEqual(intToBin(0x012C), [0x01, 0x2C])
        XCTAssertEqual(intToBin(0x012C, pad: 4), [0x01, 0x2C])
    }

    func testSecureMessagingSequenceCounterIncrementDoesNotUseTruncatingIntegerConversion() {
        let sm = SecureMessaging(ksenc: [], ksmac: [], ssc: [0x00, 0x00, 0xFF])

        XCTAssertEqual(sm.incSSC(), [0x00, 0x01, 0x00])
        XCTAssertEqual(sm.incSSC(), [0x00, 0x01, 0x00])
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

    func testSecureMessagingTreatsMalformedStatusObjectAsStatusResponse() throws {
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")

        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let malformed = ResponseAPDU(data: hexRepToBin("9901908E08D6B9C0DA21DC965F"), sw1: 0x90, sw2: 0x00)
        let response = try sm.unprotect(rapdu: malformed)

        XCTAssertEqual(response.data, [])
        XCTAssertEqual(response.sw1, 0x90)
        XCTAssertEqual(response.sw2, 0x8E)
    }

    @available(iOS 15, *)
    func testBACSessionKeysRejectShortMutualAuthenticationResponse() {
        let bac = BACHandler()

        XCTAssertThrowsError(try bac.sessionKeys(data: [0x00, 0x01])) { error in
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

    
    static var allTests = [
        ("testBinToHexRep", testBinToHexRep),
        ("testHexRepToBin", testHexRepToBin),
        ("testAsn1Length", testAsn1Length),
        ("testToASNLength", testToASNLength),
        ("testDES3Encryption", testDES3Encryption),
        ("testDES3Decryption", testDES3Decryption),
        ("testSecureMessagingProtect", testSecureMessagingProtect),
        ("testSecureMessagingUnprotectNoData", testSecureMessagingUnprotectNoData),
        ("testSecureMessagingUnprotectWithData", testSecureMessagingUnprotectWithData),
    ]
}

private func mirroredByteArray(from object: Any, named label: String) -> [UInt8] {
    Mirror(reflecting: object).children.first { $0.label == label }?.value as? [UInt8] ?? []
}
