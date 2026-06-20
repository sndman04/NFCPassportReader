//
//  DataGroupParsingTests.swift
//  
//
//  Created by Andy Qua on 15/06/2019.
//

import Foundation
import XCTest
import OpenSSL

@testable import NFCPassportReader


final class DataGroupParsingTests: XCTestCase {
    func testDatagroup1Parsing() throws {
        
        // Random generated test MRZ
        let mrz = "P<GBRTHATCHER<<BOB<<<<<<<<<<<<<<<<<<<<<<<<<<7125143269GBR3906022M1601013<<<<<<<<<<<<<<08"
        let mrzBin = [UInt8](mrz.utf8)
        let tag = try [0x5F,0x1F] +  toAsn1Length(mrzBin.count) + mrzBin
        let dg1 = try [0x61] + toAsn1Length(tag.count) + tag
        
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg1)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup1 )
        }
    }

    func testDatagroup1RejectsNonStandardMRZLength() throws {
        let invalidMRZ = [UInt8](repeating: 0x50, count: 89)
        let tag = try [0x5F, 0x1F] + toAsn1Length(invalidMRZ.count) + invalidMRZ
        let dg1 = try [0x61] + toAsn1Length(tag.count) + tag

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dg1)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }
    
    func testDatagroup2ParsingJPEG2000() {
        
        // This is a cut down version of the DG2 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = hexRepToBin("755A7F61570201017F6082203FA1128002010081010282010087020101880200085F2E38464143003031300000002026000100002018000000000000000000010000000000000001000000000000000000000000000C6A5020200D0A")
        
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg2)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup2 )
        }
        
    }
    
    func testDatagroup2ParsingJPEG() {
        
        // This is a cut down version of the DG2 record. It contains everything up to the begininnig of what would be the image data - no actual image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = hexRepToBin("755C7F618220470201017F6082203FA1128002010081010282010087020101880200085F2E3846414300303130000000202600010000201800000000000000000001000000000000000100000000000000000000FFD8FFE000104A464946")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg2)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup2 )
        }
    }

    func testDataGroup2RejectsMissingImagePayloadWithoutTrapping() throws {
        let validDG2 = hexRepToBin("755C7F618220470201017F6082203FA1128002010081010282010087020101880200085F2E3846414300303130000000202600010000201800000000000000000001000000000000000100000000000000000000FFD8FFE000104A464946")
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)

        let isoHeaderWithoutImage = hexRepToBin(
            "46414300" + // FAC marker
            "30313000" + // version
            "00000020" + // record length
            "0001" +     // one facial image
            "00000020" + // facial record length
            "0000" +     // feature points
            "00" +       // gender
            "00" +       // eye color
            "00" +       // hair color
            "000000" +   // feature mask
            "0000" +     // expression
            "000000" +   // pose angle
            "000000" +   // pose uncertainty
            "00" +       // image type
            "00" +       // image data type
            "0000" +     // width
            "0000" +     // height
            "00" +       // color space
            "00" +       // source type
            "0000" +     // device type
            "0000"       // quality
        )

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: isoHeaderWithoutImage)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
    }

    func testDatagroup2RejectsEmptyImageCountWithoutTrapping() throws {
        let body = try [0x7F, 0x61] + toAsn1Length(2) + [0x02, 0x00]
        let data = try [UInt8]([0x75]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup2RejectsExcessiveFeaturePointSkipWithoutTrapping() throws {
        let validDG2 = hexRepToBin("755C7F618220470201017F6082203FA1128002010081010282010087020101880200085F2E3846414300303130000000202600010000201800000000000000000001000000000000000100000000000000000000FFD8FFE000104A464946")
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(featurePoints: 10_001)

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup2RejectsExcessiveImageDimensionsBeforeRetainingImage() throws {
        let validDG2 = hexRepToBin("755C7F618220470201017F6082203FA1128002010081010282010087020101880200085F2E3846414300303130000000202600010000201800000000000000000001000000000000000100000000000000000000FFD8FFE000104A464946")
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(width: 20_001, height: 1)

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
    }
    
    func testDatagroup7ParsingJPEG() {
        
        // This is a cut down version of the DG7 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg7 = hexRepToBin("67060201015F4300")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg7)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup7 )
        }
    }

    func testDatagroup7PreservesMultipleImageItems() throws {
        let body = try [0x02] + toAsn1Length(1) + [0x02] +
            tlv(tag: [0x5F, 0x43], value: [0x01, 0x02]) +
            tlv(tag: [0x5F, 0x43], value: [0x03, 0x04, 0x05])
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body

        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup7)

        XCTAssertEqual(dg7.imageData, [0x01, 0x02])
        XCTAssertEqual(dg7.imageDataItems, [[0x01, 0x02], [0x03, 0x04, 0x05]])
    }

    func testAllLDSDataGroupTagsParseToTypedGroups() throws {
        let cases: [(UInt8, DataGroupId, DataGroup.Type)] = [
            (0x63, .DG3, DataGroup3.self),
            (0x76, .DG4, DataGroup4.self),
            (0x65, .DG5, DataGroup5.self),
            (0x66, .DG6, DataGroup6.self),
            (0x68, .DG8, DataGroup8.self),
            (0x69, .DG9, DataGroup9.self),
            (0x6A, .DG10, DataGroup10.self),
            (0x6D, .DG13, DataGroup13.self),
            (0x70, .DG16, DataGroup16.self)
        ]

        for (tag, id, expectedType) in cases {
            let dg = try DataGroupParser().parseDG(data: [tag, 0x00])

            XCTAssertTrue(type(of: dg) == expectedType, "Expected \(expectedType) for \(id.getName())")
            XCTAssertEqual(dg.datagroupType, id)
            XCTAssertEqual(dg.body, [])
        }
    }

    func testDatagroup11Parsing() {
        
        // This is a cut down version of the DG7 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg11Val = hexRepToBin("6B305C065F0E5F2B5F115F0E0C546573743C3C5465737465725F2B0831393730313230315F110B4E6F727468616D70746F6E")
        let dgp = DataGroupParser()
        
        XCTAssertNoThrow(try dgp.parseDG(data: dg11Val)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup11 )

            guard let dg11 = dg as? DataGroup11 else {
                XCTFail("Expected DataGroup11")
                return
            }
            XCTAssertEqual(dg11.fullName, "Test<<Tester")
            XCTAssertEqual(dg11.dateOfBirth, "19701201")
            XCTAssertEqual(dg11.placeOfBirth, "Northampton")
        }
    }

    func testDataGroup11ParsesMultilingualUTF8Text() throws {
        let name = "MULLER<<山田"
        let birthplace = "Zürich القاهرة"
        let tagList: [UInt8] = [0x5F, 0x0E, 0x5F, 0x11]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x0E], value: Array(name.utf8)) +
            tlv(tag: [0x5F, 0x11], value: Array(birthplace.utf8))
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        let dg11 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup11)

        XCTAssertEqual(dg11.fullName, name)
        XCTAssertEqual(dg11.placeOfBirth, birthplace)
    }

    func testDatagroup12Parsing() {
        
        // This is a cut down version of the DG7 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg12Val = hexRepToBin("6C1A5C045F265F195F260832303138303332365F1906544553544552")
        let dgp = DataGroupParser()
        
        XCTAssertNoThrow(try dgp.parseDG(data: dg12Val)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup12 )

            guard let dg12 = dg as? DataGroup12 else {
                XCTFail("Expected DataGroup12")
                return
            }
            XCTAssertEqual(dg12.issuingAuthority, "TESTER")
            XCTAssertEqual(dg12.dateOfIssue, "20180326")
        }
    }

    func testDataGroup12ParsesMultilingualUTF8Text() throws {
        let issuingAuthority = "Préfecture 東京"
        let observations = "Validación القاهرة"
        let tagList: [UInt8] = [0x5F, 0x19, 0x5F, 0x1B]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x19], value: Array(issuingAuthority.utf8)) +
            tlv(tag: [0x5F, 0x1B], value: Array(observations.utf8))
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.issuingAuthority, issuingAuthority)
        XCTAssertEqual(dg12.endorsementsOrObservations, observations)
    }

    func testOptionalDG11FieldsCanBeAbsentAfterTagList() {
        let dg11Val: [UInt8] = [0x6B, 0x03, 0x5C, 0x01, 0x5F]

        XCTAssertNoThrow(try DataGroupParser().parseDG(data: dg11Val)) { dg in
            XCTAssertTrue(dg is DataGroup11)
        }
    }

    func testOptionalDG12FieldsCanBeAbsentAfterTagList() {
        let dg12Val: [UInt8] = [0x6C, 0x03, 0x5C, 0x01, 0x5F]

        XCTAssertNoThrow(try DataGroupParser().parseDG(data: dg12Val)) { dg in
            XCTAssertTrue(dg is DataGroup12)
        }
    }

    func testDatagroup15Parsing() {
        
        // This is a cut down version of the DG7 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg15Val = hexRepToBin("6F820137308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7020101034200049BD24313046EB43CC4652B6FC1AA00E76B5405F4E7016521E95BE53B9C5BAE5A1410F12CF3AE23F886EFCEDE89F7C63AD9CA9E5C6C05DE902DB70F2EB2341F9D")
        let dgp = DataGroupParser()
        
        XCTAssertNoThrow(try dgp.parseDG(data: dg15Val)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup15 )

            let dg15 = dg as? DataGroup15
            XCTAssertTrue( dg15?.ecdsaPublicKey != nil || dg15?.rsaPublicKey != nil )
        }
    }


    func testCOMDatagroupParsing() {
        let com = hexRepToBin("601A5F0104303130375F36063034303030305C08617563676B6C6E6F")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: com)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is COM )
            guard let com = dg as? COM else { XCTFail(); return }
            
            // Version should be 0x30313037 or [0x30, 0x31, 0x30, 0x37]
            XCTAssertEqual( com.version, "1.7")
            
            // Unicode version should be 0x303430303030 or [0x30, 0x34, 0x30, 0x30, 0x30, 0x30]
            XCTAssertEqual( com.unicodeVersion, "4.0.0")
            
            // Datagroups present are COM, DG1, DG2, DG3, DG7, DG11, DG12, DG14, DG15
            XCTAssertEqual( com.dataGroupsPresent,["DG1", "DG2", "DG3", "DG7", "DG11", "DG12", "DG14", "DG15"])

        }
    }

    func testSODSignatureContentRejectsOutOfRangeDataGroupIdWithoutTrapping() {
        let content = """
        0:d=2  hl=2 l=   9 prim: OBJECT            :sha256
        0:d=3  hl=2 l=   1 prim: INTEGER           :20
        0:d=3  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
        """

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(content)) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                return XCTFail("Expected UnableToParseSODHashes, got \(error)")
            }
        }
    }

    func testSODSignatureContentRejectsZeroDataGroupId() {
        let content = """
        0:d=2  hl=2 l=   9 prim: OBJECT            :sha256
        0:d=3  hl=2 l=   1 prim: INTEGER           :00
        0:d=3  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
        """

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(content)) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                return XCTFail("Expected UnableToParseSODHashes, got \(error)")
            }
        }
    }

    func testSODSignatureContentParsesWhitespacePaddedDataGroupId() throws {
        let content = """
        0:d=2  hl=2 l=   9 prim: OBJECT            :sha256
        0:d=3  hl=2 l=   1 prim: INTEGER           : 01
        0:d=3  hl=2 l=  32 prim: OCTET STRING      [HEX DUMP]:00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
        """

        let (algorithm, hashes) = try NFCPassportModel().parseSODSignatureContent(content)

        XCTAssertEqual(algorithm, "SHA256")
        XCTAssertEqual(hashes[.DG1], "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
    }

    func testStructuredSODSignatureContentParsesDataGroupHashes() throws {
        let hash = [UInt8](repeating: 0xA5, count: 32)
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: hash)
        )
        let content = try sequence(
            asn1Integer([0x00]) +
            digestAlgorithm +
            sequence(dataGroupHash)
        )

        let (algorithm, hashes) = try NFCPassportModel().parseSODSignatureContent(data: Data(content))

        XCTAssertEqual(algorithm, "SHA256")
        XCTAssertEqual(hashes[.DG1], binToHexRep(hash))
    }

    func testStructuredSODSignatureContentRejectsInvalidDataGroupNumber() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x20]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let content = try sequence(
            asn1Integer([0x00]) +
            digestAlgorithm +
            sequence(dataGroupHash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content)))
    }

    func testSimpleASN1NodeRejectsNegativeIntegerAndParsesLargeOIDSecondArc() throws {
        let negativeInteger = try SimpleASN1Node.parse(asn1Integer([0x80]))
        XCTAssertNil(negativeInteger.integerValue)

        let oid = try SimpleASN1Node.parse(asn1OID([0x88, 0x37, 0x03]))
        XCTAssertEqual(oid.objectIdentifier, "2.999.3")
    }

    func testSimpleASN1NodeRejectsOverflowingIntegerAndOIDArc() throws {
        let overflowingInteger = try SimpleASN1Node.parse(asn1Integer([0x00] + [UInt8](repeating: 0xFF, count: 8)))
        XCTAssertNil(overflowingInteger.integerValue)

        let overflowingOID = try SimpleASN1Node.parse(asn1OID([UInt8](repeating: 0xFF, count: 10) + [0x7F]))
        XCTAssertNil(overflowingOID.objectIdentifier)
    }

    func testItShouldThrowAnErrorWhenActualTagDoesNotMatchExpectedTag() throws {
        let sut = try DataGroup([1, 0])
        let expected = 1
        let actual = 2

        XCTAssertThrowsError(try sut.verifyTag(actual, equals: expected)) { error in
            XCTAssertEqual("Invalid response in Unknown", error.localizedDescription)
        }
    }

    func testBaseDataGroupRejectsMissingAndOverlongBodyWithoutTrapping() {
        XCTAssertThrowsError(try DataGroup([]))
        XCTAssertThrowsError(try DataGroup([0x61]))
        XCTAssertThrowsError(try DataGroup([0x61, 0x02, 0x5F]))
    }

    func testBaseDataGroupUsesDeclaredBodyLength() throws {
        let sut = try DataGroup([0x61, 0x01, 0x5F, 0x00])

        XCTAssertEqual(sut.body, [0x5F])
    }

    func testBaseDataGroupTrimsRetainedDataToDeclaredLength() throws {
        let sut = try DataGroup([0x61, 0x01, 0x5F, 0x00, 0xFF])

        XCTAssertEqual(sut.body, [0x5F])
        XCTAssertEqual(sut.data, [0x61, 0x01, 0x5F])
        XCTAssertEqual(sut.hash("SHA1"), calcSHA1Hash([0x61, 0x01, 0x5F]))
    }

    func testBaseDataGroupAcceptsThreeByteLongFormLength() throws {
        let payload = [UInt8](repeating: 0x5F, count: 65_536)
        let sut = try DataGroup([0x61, 0x83, 0x01, 0x00, 0x00] + payload)

        XCTAssertEqual(sut.body.count, payload.count)
        XCTAssertEqual(sut.body.first, 0x5F)
        XCTAssertEqual(sut.body.last, 0x5F)
    }

    func testItShouldNotThrowAnErrorWhenActualTagMatchesExpectedTag() throws {
        let sut = try DataGroup([1, 0])
        let expected = 1
        let actual = 1

        XCTAssertNoThrow(try sut.verifyTag(actual, equals: expected))
    }

    func testItShouldThrowAnErrorWhenActualTagIsNotAnExpectedTag() throws {
        let sut = try DataGroup([1, 0])
        let expected = [1, 3]
        let actual = 2

        XCTAssertThrowsError(try sut.verifyTag(actual, oneOf: expected)) { error in
            XCTAssertEqual("Invalid response in Unknown", error.localizedDescription)
        }
    }

    func testItShouldNotThrowAnErrorWhenActualTagIsAnExpectedTag() throws {
        let sut = try DataGroup([1, 0])
        let expected = [1, 3]
        let actual = 3

        XCTAssertNoThrow(try sut.verifyTag(actual, oneOf: expected))
    }

    static var allTests = [
        ("testDatagroup1Parsing", testDatagroup1Parsing),
        ("testDatagroup2Parsing", testDatagroup2ParsingJPEG2000),
        ("testDatagroup2ParsingJPEG", testDatagroup2ParsingJPEG),
        ("testCOMDatagroupParsing", testCOMDatagroupParsing),
    ]
    
}

private func tlv(tag: [UInt8], value: [UInt8]) throws -> [UInt8] {
    try tag + toAsn1Length(value.count) + value
}

private func sequence(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x30], value: value)
}

private func asn1Integer(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x02], value: value)
}

private func asn1OID(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x06], value: value)
}

private func iso19794FaceRecord(
    featurePoints: Int = 0,
    width: Int = 1,
    height: Int = 1,
    imageBytes: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
) -> [UInt8] {
    [0x46, 0x41, 0x43, 0x00] +
    [0x30, 0x31, 0x30, 0x00] +
    fixedWidthBytes(46 + imageBytes.count, count: 4) +
    fixedWidthBytes(1, count: 2) +
    fixedWidthBytes(46 + imageBytes.count - 14, count: 4) +
    fixedWidthBytes(featurePoints, count: 2) +
    [0x00, 0x00, 0x00] +
    [0x00, 0x00, 0x00] +
    [0x00, 0x00] +
    [0x00, 0x00, 0x00] +
    [0x00, 0x00, 0x00] +
    Array(repeating: 0x00, count: max(featurePoints, 0) * 8) +
    [0x00, 0x00] +
    fixedWidthBytes(width, count: 2) +
    fixedWidthBytes(height, count: 2) +
    [0x00, 0x00] +
    [0x00, 0x00] +
    [0x00, 0x00] +
    imageBytes
}

private func fixedWidthBytes(_ value: Int, count: Int) -> [UInt8] {
    guard count > 0 else { return [] }
    return (0..<count).map { shift in
        UInt8((value >> ((count - shift - 1) * 8)) & 0xFF)
    }
}
