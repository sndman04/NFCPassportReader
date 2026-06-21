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

    func testDatagroup1ParsesTD1MRZ() throws {
        let line1 = "I<" + "UTO" + "ABC123456" + "7" + String(repeating: "<", count: 15)
        let line2 = "700101" + "1" + "F" + "300101" + "2" + "UTO" + "OPTIONAL<<<" + "3"
        let line3 = mrzPadded("DOE<<JANE", length: 30)
        let dg1 = try dataGroup1Fixture(mrz: line1 + line2 + line3)

        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1) as? DataGroup1)

        XCTAssertEqual(parsed.elements["5F03"], "I<")
        XCTAssertEqual(parsed.elements["5F28"], "UTO")
        XCTAssertEqual(parsed.elements["5A"], "ABC123456")
        XCTAssertEqual(parsed.elements["5F57"], "700101")
        XCTAssertEqual(parsed.elements["5F35"], "F")
        XCTAssertEqual(parsed.elements["59"], "300101")
        XCTAssertEqual(parsed.elements["5F2C"], "UTO")
        XCTAssertEqual(parsed.elements["53"], String(repeating: "<", count: 15) + "OPTIONAL<<<")
        XCTAssertEqual(parsed.elements["5B"], line3)
    }

    func testDatagroup1ParsesTD2MRZ() throws {
        let line1 = "I<" + "UTO" + mrzPadded("DOE<<JOHN", length: 31)
        let line2 = "ABC123456" + "7" + "UTO" + "700101" + "1" + "M" + "300101" + "2" + "OPT<<<<" + "3"
        let dg1 = try dataGroup1Fixture(mrz: line1 + line2)

        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1) as? DataGroup1)

        XCTAssertEqual(parsed.elements["5F03"], "I<")
        XCTAssertEqual(parsed.elements["5F28"], "UTO")
        XCTAssertEqual(parsed.elements["5B"], line1.dropFirst(5).description)
        XCTAssertEqual(parsed.elements["5A"], "ABC123456")
        XCTAssertEqual(parsed.elements["5F57"], "700101")
        XCTAssertEqual(parsed.elements["5F35"], "M")
        XCTAssertEqual(parsed.elements["59"], "300101")
        XCTAssertEqual(parsed.elements["5F2C"], "UTO")
        XCTAssertEqual(parsed.elements["53"], "OPT<<<<")
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

    func testDatagroup2ParsingJPEGWithExifMarker() throws {
        let dg2 = try dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)

        XCTAssertEqual(parsed.imageData, [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        XCTAssertEqual(parsed.imageDataItems, [[0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10]])
    }

    func testIdentityResultReportsFaceImageOnlyWhenDG2ContainsImagePayload() throws {
        let imageBytes = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let dg2 = try dataGroup2Fixture(imageBytes: imageBytes)
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)
        let model = NFCPassportModel()
        model.addDataGroup(.DG2, dataGroup: parsed)

        XCTAssertTrue(model.identityResult.hasFaceImage)

        let readResult = PassportChipReadResult(passport: model, photoPolicy: .read)
        XCTAssertEqual(readResult.faceImageData?.data, Data(imageBytes))
        XCTAssertEqual(readResult.faceImageData?.format, .jpeg)
        XCTAssertEqual(readResult.faceImageData?.mimeType, "image/jpeg")

        let skippedResult = PassportChipReadResult(passport: model, photoPolicy: .skip)
        XCTAssertNil(skippedResult.faceImageData)
    }

    func testModelPrivacyCleanupScrubsRetainedDataGroupPayloadsBeforeReleasingReferences() throws {
        let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: dataGroup1Fixture(mrz: mrzPadded("P<UTODOE<<JANE", length: 88))
        ) as? DataGroup1)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        ) as? DataGroup2)
        let dg7Body = try [0x02] + toAsn1Length(1) + [0x01] +
            tlv(tag: [0x5F, 0x43], value: [0xAA, 0xBB, 0xCC])
        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: [UInt8]([0x67]) + toAsn1Length(dg7Body.count) + dg7Body
        ) as? DataGroup7)
        let dg11 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: try dataGroup11Fixture(fullName: "DOE<<JANE", placeOfBirth: "Zürich")
        ) as? DataGroup11)
        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: try dataGroup12Fixture(frontImage: [0x01, 0x02], rearImage: [0x03, 0x04])
        ) as? DataGroup12)
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: dg1)
        model.addDataGroup(.DG2, dataGroup: dg2)
        model.addDataGroup(.DG7, dataGroup: dg7)
        model.addDataGroup(.DG11, dataGroup: dg11)
        model.addDataGroup(.DG12, dataGroup: dg12)

        XCTAssertFalse(dg1.elements.isEmpty)
        XCTAssertFalse(dg2.imageData.isEmpty)
        XCTAssertFalse(dg7.imageDataItems.isEmpty)
        XCTAssertEqual(dg11.fullName, "DOE<<JANE")
        XCTAssertEqual(dg12.frontImage, [0x01, 0x02])

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG2))
        XCTAssertTrue(model.dataGroupsAvailable.isEmpty)
        XCTAssertTrue(dg1.elements.isEmpty)
        XCTAssertTrue(dg1.data.isEmpty)
        XCTAssertTrue(dg1.body.isEmpty)
        XCTAssertTrue(dg2.imageData.isEmpty)
        XCTAssertTrue(dg2.imageDataItems.isEmpty)
        XCTAssertTrue(dg2.data.isEmpty)
        XCTAssertTrue(dg2.body.isEmpty)
        XCTAssertTrue(dg7.imageData.isEmpty)
        XCTAssertTrue(dg7.imageDataItems.isEmpty)
        XCTAssertTrue(dg7.data.isEmpty)
        XCTAssertTrue(dg7.body.isEmpty)
        XCTAssertNil(dg11.fullName)
        XCTAssertNil(dg11.placeOfBirth)
        XCTAssertTrue(dg11.data.isEmpty)
        XCTAssertTrue(dg11.body.isEmpty)
        XCTAssertNil(dg12.frontImage)
        XCTAssertNil(dg12.rearImage)
        XCTAssertTrue(dg12.data.isEmpty)
        XCTAssertTrue(dg12.body.isEmpty)
    }

    func testDatagroup2PreservesMultipleBiometricTemplates() throws {
        let first = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let second = [UInt8]([0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43])
        let dg2 = try dataGroup2Fixture(imageBytesItems: [first, second])
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)

        XCTAssertEqual(parsed.nrImages, 2)
        XCTAssertEqual(parsed.imageData, first)
        XCTAssertEqual(parsed.imageDataItems, [first, second])
    }

    func testDatagroup2PreservesMultipleFacialRecordsInOneTemplate() throws {
        let first = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let second = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x12])
        let dg2 = try dataGroup2Fixture(singleTemplateFacialRecordImageBytesItems: [first, second])
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)

        XCTAssertEqual(parsed.nrImages, 1)
        XCTAssertEqual(parsed.numberOfFacialImages, 2)
        XCTAssertEqual(parsed.imageData, first)
        XCTAssertEqual(parsed.imageDataItems, [first, second])
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

    func testDatagroup7RejectsOversizedImageItem() throws {
        let oversizedImage = [UInt8](repeating: 0xA5, count: 10 * 1024 * 1024 + 1)
        let body = try [0x02] + toAsn1Length(1) + [0x01] +
            tlv(tag: [0x5F, 0x43], value: oversizedImage)
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
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

    func testDataGroup11ParsesUTF16BigEndianText() throws {
        let name = "TEST<<東京"
        let encodedName = try XCTUnwrap(name.data(using: .utf16BigEndian)).map { $0 }
        let tagList: [UInt8] = [0x5F, 0x0E]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x0E], value: [0xFE, 0xFF] + encodedName)
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        let dg11 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup11)

        XCTAssertEqual(dg11.fullName, name)
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

            let model = NFCPassportModel()
            model.addDataGroup(.DG12, dataGroup: dg12)
            XCTAssertEqual(model.identityResult.dateOfIssue, "20180326")
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

    func testDataGroup12ParsesLatin1Text() throws {
        let latin1Authority = [UInt8]([0x50, 0x72, 0xE9, 0x66, 0x65, 0x63, 0x74, 0x75, 0x72, 0x65])
        let tagList: [UInt8] = [0x5F, 0x19]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x19], value: latin1Authority)
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.issuingAuthority, "Préfecture")
    }

    func testDataGroup12ParsesOtherPersonsDetailsAsPlainText() throws {
        let details = "CHILD<<山田"
        let tagList: [UInt8] = [0xA0]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0xA0], value: Array(details.utf8))
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.otherPersonsDetails, details)
    }

    func testDataGroup12ParsesOtherPersonsDetailsNestedText() throws {
        let firstPerson = "PARENT<<MULLER"
        let secondPerson = "وصي القاهرة"
        let nested = try tlv(tag: [0x5F, 0x0E], value: Array(firstPerson.utf8)) +
            tlv(tag: [0x5F, 0x11], value: Array(secondPerson.utf8))
        let tagList: [UInt8] = [0xA0]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0xA0], value: nested)
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.otherPersonsDetails, [firstPerson, secondPerson].joined(separator: "\n"))
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

    func testStructuredSODSignatureContentRejectsZeroDataGroupNumber() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x00]) +
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

    func testSimpleASN1NodePreservesOriginalEncodedBytes() throws {
        let integerWithLongFormLength: [UInt8] = [0x02, 0x81, 0x01, 0x01]
        let sequenceWithLongFormLength: [UInt8] = [0x30, 0x81, UInt8(integerWithLongFormLength.count)] + integerWithLongFormLength

        let sequence = try SimpleASN1Node.parse(sequenceWithLongFormLength)

        XCTAssertEqual(sequence.encodedBytes, sequenceWithLongFormLength)
        XCTAssertEqual(sequence.headerLength, 3)
        XCTAssertEqual(sequence.children.first?.encodedBytes, integerWithLongFormLength)
        XCTAssertEqual(sequence.children.first?.headerLength, 3)
        XCTAssertEqual(sequence.children.first?.integerValue, 1)
    }

    func testSODParsesCMSFieldsWithoutASN1DumpText() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let signature: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD]
        let signedAttributesValue = try syntheticSODSignedAttributesValue(messageDigest: messageDigest)
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: signature,
            includeOptionalCertificateAndCRLFields: true
        ))

        XCTAssertEqual(try sod.getEncapsulatedContent(), Data(encapsulatedContent))
        XCTAssertEqual(try sod.getEncapsulatedContentDigestAlgorithm(), "SHA256")
        XCTAssertEqual(try sod.getMessageDigestFromSignedAttributes(), Data(messageDigest))
        XCTAssertEqual(try sod.getSignature(), Data(signature))
        XCTAssertEqual(try sod.getSignatureAlgorithm(), "sha256WithRSAEncryption")
        XCTAssertEqual(try sod.getSignedAttributes(), Data(try asn1Set(signedAttributesValue)))
    }

    func testCardSecurityParsesSignedSecurityInfosEncapsulatedContent() throws {
        let cardSecurity = try CardSecurity(syntheticCardSecurityData())
        let parsedPACEInfo = try XCTUnwrap(cardSecurity.securityInfos.first as? PACEInfo)

        XCTAssertEqual(parsedPACEInfo.getObjectIdentifier(), SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128)
        XCTAssertEqual(parsedPACEInfo.version, 2)
        XCTAssertEqual(parsedPACEInfo.parameterId, PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
    }

    func testSecurityInfosParserParsesMixedDERInfosWithoutASN1DumpText() throws {
        let paceInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Integer([0x02]) +
            asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
        )
        let chipAuthenticationInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID) +
            asn1Integer([0x01]) +
            asn1Integer([0x01, 0x00])
        )
        let activeAuthenticationInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_AA_OID) +
            asn1Integer([0x01]) +
            asn1ObjectIdentifier(SecurityInfo.ECDSA_PLAIN_SHA256_OID)
        )
        let unknownInfo = try sequence(
            asn1ObjectIdentifier("1.2.3.4.5") +
            asn1Integer([0x01])
        )

        let securityInfos = try SecurityInfosParser.parse(asn1Set(
            paceInfo +
            chipAuthenticationInfo +
            activeAuthenticationInfo +
            unknownInfo
        ))

        XCTAssertEqual(securityInfos.count, 4)

        let parsedPACEInfo = try XCTUnwrap(securityInfos.compactMap { $0 as? PACEInfo }.first)
        XCTAssertEqual(parsedPACEInfo.getObjectIdentifier(), SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128)
        XCTAssertEqual(parsedPACEInfo.getVersion(), 2)
        XCTAssertEqual(parsedPACEInfo.getParameterId(), PACEInfo.PARAM_ID_ECP_NIST_P256_R1)

        let parsedChipAuthenticationInfo = try XCTUnwrap(securityInfos.compactMap { $0 as? ChipAuthenticationInfo }.first)
        XCTAssertEqual(parsedChipAuthenticationInfo.getObjectIdentifier(), SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID)
        XCTAssertEqual(parsedChipAuthenticationInfo.getKeyId(), 256)

        let parsedActiveAuthenticationInfo = try XCTUnwrap(securityInfos.compactMap { $0 as? ActiveAuthenticationInfo }.first)
        XCTAssertEqual(parsedActiveAuthenticationInfo.getProtocolOIDString(), "id-AA")
        XCTAssertEqual(parsedActiveAuthenticationInfo.getSignatureAlgorithmOIDString(), "ecdsa-plain-SHA256")

        let parsedUnknownInfo = try XCTUnwrap(securityInfos.first { !$0.isRecognized })
        XCTAssertEqual(parsedUnknownInfo.getProtocolOIDString(), "Unknown security info")
    }

    func testActiveAuthenticationSignatureOIDMetadataCoversSupportedECDSAPlainAlgorithms() {
        let expectedNames = [
            SecurityInfo.ECDSA_PLAIN_SHA1_OID: "ecdsa-plain-SHA1",
            SecurityInfo.ECDSA_PLAIN_SHA224_OID: "ecdsa-plain-SHA224",
            SecurityInfo.ECDSA_PLAIN_SHA256_OID: "ecdsa-plain-SHA256",
            SecurityInfo.ECDSA_PLAIN_SHA384_OID: "ecdsa-plain-SHA384",
            SecurityInfo.ECDSA_PLAIN_SHA512_OID: "ecdsa-plain-SHA512",
            SecurityInfo.ECDSA_PLAIN_RIPEMD160_OID: "ecdsa-plain-RIPEMD160"
        ]

        for (oid, expectedName) in expectedNames {
            let info = ActiveAuthenticationInfo(
                oid: SecurityInfo.ID_AA_OID,
                version: 1,
                signatureAlgorithmOID: oid
            )

            XCTAssertEqual(info.getProtocolOIDString(), "id-AA")
            XCTAssertEqual(info.getSignatureAlgorithmOIDString(), expectedName)
        }

        let unsupportedInfo = ActiveAuthenticationInfo(
            oid: SecurityInfo.ID_AA_OID,
            version: 1,
            signatureAlgorithmOID: "1.2.3.4"
        )
        XCTAssertNil(unsupportedInfo.getSignatureAlgorithmOIDString())

        let missingSignatureAlgorithmInfo = ActiveAuthenticationInfo(
            oid: SecurityInfo.ID_AA_OID,
            version: 1
        )
        XCTAssertNil(missingSignatureAlgorithmInfo.getSignatureAlgorithmOIDString())
    }

    func testCardSecurityVerificationFailureDoesNotTrustUnsignedContent() throws {
        let cardSecurity = try CardSecurity(syntheticCardSecurityData())

        XCTAssertThrowsError(try cardSecurity.verifySignature(trustedCertificatesURL: nil))
        XCTAssertFalse(cardSecurity.signatureVerified)
        XCTAssertFalse(cardSecurity.signerTrusted)
    }

    func testSyntheticParserFuzzCorpusRejectsMalformedInputsWithoutTrapping() {
        var generator = DeterministicByteGenerator(seed: 0xD00DCAFE)
        for _ in 0..<200 {
            let length = Int(generator.next() % 96)
            let bytes = (0..<length).map { _ in generator.next() }

            do {
                _ = try DataGroupParser().parseDG(data: bytes)
            } catch {
                XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("APDU"))
                XCTAssertNil(error.localizedDescription.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
            }

            do {
                _ = try SimpleASN1Node.parse(bytes)
            } catch {
                XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("APDU"))
                XCTAssertNil(error.localizedDescription.range(of: #"[0-9A-Fa-f]{32,}"#, options: .regularExpression))
            }
        }
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

}

private func tlv(tag: [UInt8], value: [UInt8]) throws -> [UInt8] {
    try tag + toAsn1Length(value.count) + value
}

private func sequence(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x30], value: value)
}

private func asn1Set(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x31], value: value)
}

private func context0(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0xA0], value: value)
}

private func context1(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0xA1], value: value)
}

private func asn1Null() -> [UInt8] {
    [0x05, 0x00]
}

private func algorithmIdentifier(_ oid: String) throws -> [UInt8] {
    try sequence(asn1ObjectIdentifier(oid) + asn1Null())
}

private func syntheticSODSignedAttributesValue(messageDigest: [UInt8]) throws -> [UInt8] {
    let contentTypeAttribute = try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.9.3") +
        asn1Set(asn1ObjectIdentifier("2.23.136.1.1.1"))
    )
    let messageDigestAttribute = try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.9.4") +
        asn1Set(try tlv(tag: [0x04], value: messageDigest))
    )
    return contentTypeAttribute + messageDigestAttribute
}

private func syntheticSODData(
    encapsulatedContent: [UInt8],
    messageDigest: [UInt8],
    signature: [UInt8],
    includeOptionalCertificateAndCRLFields: Bool
) throws -> [UInt8] {
    let digestAlgorithm = try algorithmIdentifier("2.16.840.1.101.3.4.2.1")
    let digestAlgorithms = try asn1Set(digestAlgorithm)
    let encapContentInfo = try sequence(
        asn1ObjectIdentifier("2.23.136.1.1.1") +
        context0(try tlv(tag: [0x04], value: encapsulatedContent))
    )
    let signedAttributes = try context0(syntheticSODSignedAttributesValue(messageDigest: messageDigest))
    let signatureAlgorithm = try algorithmIdentifier("1.2.840.113549.1.1.11")
    let signerInfo = try sequence(
        asn1Integer([0x01]) +
        sequence([]) +
        digestAlgorithm +
        signedAttributes +
        signatureAlgorithm +
        tlv(tag: [0x04], value: signature)
    )
    var signedDataBody = try asn1Integer([0x03]) + digestAlgorithms + encapContentInfo
    if includeOptionalCertificateAndCRLFields {
        signedDataBody += try context0([])
        signedDataBody += try context1([])
    }
    signedDataBody += try asn1Set(signerInfo)

    let cmsContent = try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.7.2") +
        context0(try sequence(signedDataBody))
    )
    return try [0x77] + toAsn1Length(cmsContent.count) + cmsContent
}

private func syntheticCardSecurityData() throws -> [UInt8] {
    let paceInfo = try sequence(
        asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) +
        asn1Integer([0x02]) +
        asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
    )
    let securityInfos = try asn1Set(paceInfo)
    let encapContentInfo = try sequence(
        asn1ObjectIdentifier("2.23.136.1.1.1") +
        context0(try tlv(tag: [0x04], value: securityInfos))
    )
    let signedData = try sequence(
        asn1Integer([0x03]) +
        asn1Set([]) +
        encapContentInfo +
        asn1Set([])
    )
    return try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.7.2") +
        context0(signedData)
    )
}

private func dataGroup1Fixture(mrz: String) throws -> [UInt8] {
    let mrzBytes = [UInt8](mrz.utf8)
    let tag = try [0x5F, 0x1F] + toAsn1Length(mrzBytes.count) + mrzBytes
    return try [UInt8]([0x61]) + toAsn1Length(tag.count) + tag
}

private func dataGroup11Fixture(fullName: String, placeOfBirth: String) throws -> [UInt8] {
    let body = try tlv(tag: [0x5C], value: [0x5F, 0x0E, 0x5F, 0x11]) +
        tlv(tag: [0x5F, 0x0E], value: Array(fullName.utf8)) +
        tlv(tag: [0x5F, 0x11], value: Array(placeOfBirth.utf8))
    return try [UInt8]([0x6B]) + toAsn1Length(body.count) + body
}

private func dataGroup12Fixture(frontImage: [UInt8], rearImage: [UInt8]) throws -> [UInt8] {
    let body = try tlv(tag: [0x5C], value: [0x5F, 0x1D, 0x5F, 0x1E]) +
        tlv(tag: [0x5F, 0x1D], value: frontImage) +
        tlv(tag: [0x5F, 0x1E], value: rearImage)
    return try [UInt8]([0x6C]) + toAsn1Length(body.count) + body
}

private func mrzPadded(_ value: String, length: Int) -> String {
    String((value + String(repeating: "<", count: length)).prefix(length))
}

private func asn1Integer(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x02], value: value)
}

private func asn1OID(_ value: [UInt8]) throws -> [UInt8] {
    try tlv(tag: [0x06], value: value)
}

private func asn1ObjectIdentifier(_ oid: String) -> [UInt8] {
    OpenSSLUtils.asn1EncodeOID(oid: oid)
}

private func dataGroup2Fixture(imageBytes: [UInt8]) throws -> [UInt8] {
    try dataGroup2Fixture(imageBytesItems: [imageBytes])
}

private func dataGroup2Fixture(imageBytesItems: [[UInt8]]) throws -> [UInt8] {
    let count = imageBytesItems.count
    let templates = try imageBytesItems.map { imageBytes in
        let biometricHeader = try tlv(tag: [0xA1], value: [0x80, 0x01, 0x01])
        let biometricData = try tlv(tag: [0x5F, 0x2E], value: iso19794FaceRecord(imageBytes: imageBytes))
        return try tlv(tag: [0x7F, 0x60], value: biometricHeader + biometricData)
    }.flatMap { $0 }
    let body = try tlv(tag: [0x7F, 0x61], value: tlv(tag: [0x02], value: [UInt8(count)]) + templates)
    return try [UInt8]([0x75]) + toAsn1Length(body.count) + body
}

private func dataGroup2Fixture(singleTemplateFacialRecordImageBytesItems imageBytesItems: [[UInt8]]) throws -> [UInt8] {
    let biometricHeader = try tlv(tag: [0xA1], value: [0x80, 0x01, 0x01])
    let biometricData = try tlv(tag: [0x5F, 0x2E], value: iso19794FaceRecordPayload(imageBytesItems: imageBytesItems))
    let template = try tlv(tag: [0x7F, 0x60], value: biometricHeader + biometricData)
    let body = try tlv(tag: [0x7F, 0x61], value: tlv(tag: [0x02], value: [0x01]) + template)
    return try [UInt8]([0x75]) + toAsn1Length(body.count) + body
}

private func iso19794FaceRecord(
    featurePoints: Int = 0,
    width: Int = 1,
    height: Int = 1,
    imageBytes: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
) -> [UInt8] {
    var record: [UInt8] = []
    record.reserveCapacity(46 + imageBytes.count + max(featurePoints, 0) * 8)
    record += [0x46, 0x41, 0x43, 0x00]
    record += [0x30, 0x31, 0x30, 0x00]
    record += fixedWidthBytes(46 + imageBytes.count, count: 4)
    record += fixedWidthBytes(1, count: 2)
    record += fixedWidthBytes(46 + imageBytes.count - 14, count: 4)
    record += fixedWidthBytes(featurePoints, count: 2)
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += Array(repeating: 0x00, count: max(featurePoints, 0) * 8)
    record += [0x00, 0x00]
    record += fixedWidthBytes(width, count: 2)
    record += fixedWidthBytes(height, count: 2)
    record += [0x00, 0x00]
    record += [0x00, 0x00]
    record += [0x00, 0x00]
    record += imageBytes
    return record
}

private func iso19794FaceRecordPayload(imageBytesItems: [[UInt8]]) -> [UInt8] {
    let records = imageBytesItems.flatMap { iso19794FacialRecord(imageBytes: $0) }
    return [0x46, 0x41, 0x43, 0x00] +
        [0x30, 0x31, 0x30, 0x00] +
        fixedWidthBytes(14 + records.count, count: 4) +
        fixedWidthBytes(imageBytesItems.count, count: 2) +
        records
}

private func iso19794FacialRecord(imageBytes: [UInt8]) -> [UInt8] {
    var recordTail = fixedWidthBytes(0, count: 2)
    recordTail.reserveCapacity(32 + imageBytes.count)
    recordTail += [0x00, 0x00, 0x00]
    recordTail += [0x00, 0x00, 0x00]
    recordTail += [0x00, 0x00]
    recordTail += [0x00, 0x00, 0x00]
    recordTail += [0x00, 0x00, 0x00]
    recordTail += [0x00, 0x00]
    recordTail += fixedWidthBytes(1, count: 2)
    recordTail += fixedWidthBytes(1, count: 2)
    recordTail += [0x00, 0x00]
    recordTail += [0x00, 0x00]
    recordTail += [0x00, 0x00]
    recordTail += imageBytes
    return fixedWidthBytes(4 + recordTail.count, count: 4) + recordTail
}

private func fixedWidthBytes(_ value: Int, count: Int) -> [UInt8] {
    guard count > 0 else { return [] }
    return (0..<count).map { shift in
        UInt8((value >> ((count - shift - 1) * 8)) & 0xFF)
    }
}

private struct DeterministicByteGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt8 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return UInt8((state >> 32) & 0xFF)
    }
}
