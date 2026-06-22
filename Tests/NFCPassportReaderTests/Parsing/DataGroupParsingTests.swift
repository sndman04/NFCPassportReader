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
        let documentNumber = "ABC123456"
        let optional1 = String(repeating: "<", count: 15)
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let optional2 = "OPTIONAL<<<"
        let line1Prefix = "I<" + "UTO" + documentNumber + mrzCheckDigit(documentNumber) + optional1
        let line2Prefix = dateOfBirth + mrzCheckDigit(dateOfBirth) + "F" +
            expiryDate + mrzCheckDigit(expiryDate) + "UTO" + optional2
        let line1 = line1Prefix
        let line2 = line2Prefix + mrzCheckDigit(
            documentNumber + mrzCheckDigit(documentNumber) + optional1 +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + optional2
        )
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

    func testDatagroup1ParsesTD1LongDocumentNumber() throws {
        let documentNumber = "ABC123456789"
        let principalDocumentNumber = String(documentNumber.prefix(9))
        let documentNumberContinuation = String(documentNumber.dropFirst(9))
        let documentNumberCheckDigit = mrzCheckDigit(principalDocumentNumber + documentNumberContinuation)
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let optional2 = "OPTIONAL<<<"
        let line1 = "I<" + "UTO" + principalDocumentNumber + "<" +
            documentNumberContinuation + documentNumberCheckDigit +
            String(repeating: "<", count: 30 - 5 - 9 - 1 - documentNumberContinuation.count - 1)
        let line2Prefix = dateOfBirth + mrzCheckDigit(dateOfBirth) + "F" +
            expiryDate + mrzCheckDigit(expiryDate) + "UTO" + optional2
        let line2 = line2Prefix + mrzCheckDigit(
            String(line1.dropFirst(5)) +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + optional2
        )
        let line3 = mrzPadded("DOE<<JANE", length: 30)
        let dg1 = try dataGroup1Fixture(mrz: line1 + line2 + line3)

        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1) as? DataGroup1)

        XCTAssertEqual(parsed.elements["5A"], documentNumber)
        XCTAssertEqual(parsed.elements["5F04"], documentNumberCheckDigit)
        XCTAssertEqual(parsed.elements["53"], optional2)
    }

    func testDatagroup1ParsesTD1LongDocumentNumberWithUpperOptionalDataAfterMarker() throws {
        let documentNumber = "ABC123456789"
        let principalDocumentNumber = String(documentNumber.prefix(9))
        let documentNumberContinuation = String(documentNumber.dropFirst(9))
        let documentNumberCheckDigit = mrzCheckDigit(principalDocumentNumber + documentNumberContinuation)
        let upperOptionalData = "PERMIT42<<"
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let optional2 = "OPTIONAL<<<"
        let line1 = "I<" + "UTO" + principalDocumentNumber + "<" +
            documentNumberContinuation + documentNumberCheckDigit + "<" + upperOptionalData
        let line2Prefix = dateOfBirth + mrzCheckDigit(dateOfBirth) + "F" +
            expiryDate + mrzCheckDigit(expiryDate) + "UTO" + optional2
        let line2 = line2Prefix + mrzCheckDigit(
            String(line1.dropFirst(5)) +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + optional2
        )
        let line3 = mrzPadded("DOE<<JANE", length: 30)
        let dg1 = try dataGroup1Fixture(mrz: line1 + line2 + line3)

        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1) as? DataGroup1)

        XCTAssertEqual(parsed.elements["5A"], documentNumber)
        XCTAssertEqual(parsed.elements["5F04"], documentNumberCheckDigit)
        XCTAssertEqual(parsed.elements["53"], upperOptionalData + optional2)
    }

    func testDatagroup1RejectsTD1LongDocumentNumberWithInvalidCheckDigit() throws {
        let documentNumber = "ABC123456789"
        let principalDocumentNumber = String(documentNumber.prefix(9))
        let documentNumberContinuation = String(documentNumber.dropFirst(9))
        let correctDocumentNumberCheckDigit = try XCTUnwrap(Int(mrzCheckDigit(documentNumber)))
        let wrongDocumentNumberCheckDigit = String((correctDocumentNumberCheckDigit + 1) % 10)
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let optional2 = "OPTIONAL<<<"
        let line1 = "I<" + "UTO" + principalDocumentNumber + "<" +
            documentNumberContinuation + wrongDocumentNumberCheckDigit +
            String(repeating: "<", count: 30 - 5 - 9 - 1 - documentNumberContinuation.count - 1)
        let line2Prefix = dateOfBirth + mrzCheckDigit(dateOfBirth) + "F" +
            expiryDate + mrzCheckDigit(expiryDate) + "UTO" + optional2
        let line2 = line2Prefix + mrzCheckDigit(
            String(line1.dropFirst(5)) +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + optional2
        )
        let line3 = mrzPadded("DOE<<JANE", length: 30)

        XCTAssertThrowsError(
            try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: line1 + line2 + line3))
        ) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1RejectsTD1CompositeCheckDigitIncludingNationality() throws {
        let documentNumber = "ABC123456"
        let optional1 = String(repeating: "<", count: 15)
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let nationality = "ZZZ"
        let optional2 = "OPTIONAL<<<"
        let line1Prefix = "I<" + "UTO" + documentNumber + mrzCheckDigit(documentNumber) + optional1
        let line2Prefix = dateOfBirth + mrzCheckDigit(dateOfBirth) + "F" +
            expiryDate + mrzCheckDigit(expiryDate) + nationality + optional2
        let incorrectCompositeCheckDigit = mrzCheckDigit(
            documentNumber + mrzCheckDigit(documentNumber) + optional1 +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + nationality + optional2
        )
        let line3 = mrzPadded("DOE<<JANE", length: 30)

        XCTAssertThrowsError(
            try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: line1Prefix + line2Prefix + incorrectCompositeCheckDigit + line3))
        ) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1ParsesTD2MRZ() throws {
        let line1 = "I<" + "UTO" + mrzPadded("DOE<<JOHN", length: 31)
        let documentNumber = "ABC123456"
        let dateOfBirth = "700101"
        let expiryDate = "300101"
        let optionalData = "OPT<<<<"
        let line2Prefix = documentNumber + mrzCheckDigit(documentNumber) + "UTO" +
            dateOfBirth + mrzCheckDigit(dateOfBirth) + "M" +
            expiryDate + mrzCheckDigit(expiryDate) + optionalData
        let line2 = line2Prefix + mrzCheckDigit(
            documentNumber + mrzCheckDigit(documentNumber) +
            dateOfBirth + mrzCheckDigit(dateOfBirth) +
            expiryDate + mrzCheckDigit(expiryDate) + optionalData
        )
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

    func testDatagroup1RejectsInvalidMRZCharactersBeforeProjection() throws {
        let invalidLowercaseMRZ = mrzPadded("P<UTODOE<<Jane", length: 88)

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: invalidLowercaseMRZ))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }

        var invalidEncodedMRZ = [UInt8](mrzPadded("P<UTODOE<<JANE", length: 88).utf8)
        invalidEncodedMRZ[10] = 0xFF
        let tag = try [0x5F, 0x1F] + toAsn1Length(invalidEncodedMRZ.count) + invalidEncodedMRZ
        let dg1 = try [UInt8]([0x61]) + toAsn1Length(tag.count) + tag

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dg1)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1RejectsInvalidCheckDigitsBeforeProjection() throws {
        var mrz = syntheticTD3MRZ()
        let checkDigitIndex = mrz.index(mrz.startIndex, offsetBy: 53)
        let originalCheckDigit = mrz[checkDigitIndex]
        mrz.replaceSubrange(checkDigitIndex...checkDigitIndex, with: "0")
        if originalCheckDigit == "0" {
            mrz.replaceSubrange(checkDigitIndex...checkDigitIndex, with: "1")
        }

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: mrz))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1RejectsNonDigitDateFieldsEvenWithMatchingCheckDigit() throws {
        let mrz = syntheticTD3MRZ(dateOfBirth: "70A101")

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: mrz))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1RejectsInvalidCalendarBirthDateEvenWithMatchingCheckDigit() throws {
        let mrz = syntheticTD3MRZ(dateOfBirth: "701340")

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: mrz))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup1RejectsInvalidCalendarExpiryDateEvenWithMatchingCheckDigit() throws {
        let mrz = syntheticTD3MRZ(expiryDate: "300230")

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: dataGroup1Fixture(mrz: mrz))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }
    
    func testDatagroup2ParsingJPEG2000() throws {
        
        // This is a cut down version of the DG2 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = try dataGroup2Fixture(imageBytes: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A])
        
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg2)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup2 )
        }
        
    }
    
    func testDatagroup2ParsingJPEG() throws {
        
        // This is a cut down version of the DG2 record. It contains everything up to the begininnig of what would be the image data - no actual image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = try dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
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

    func testFaceImageResultFormatFollowsValidatedBytesWhenMetadataDisagrees() throws {
        let jpeg2000Bytes = [UInt8]([0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A])
        let dg2 = try dataGroup2Fixture(imageDataType: 0x00, imageBytes: jpeg2000Bytes)
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)
        let model = NFCPassportModel()
        model.addDataGroup(.DG2, dataGroup: parsed)

        let readResult = PassportChipReadResult(passport: model, photoPolicy: .read)

        XCTAssertEqual(parsed.imageDataType, 0x00)
        XCTAssertEqual(readResult.faceImageData?.format, .jpeg2000)
        XCTAssertEqual(readResult.faceImageData?.mimeType, "image/jp2")
    }

    func testFaceImageResultReportsJPEGWhenBytesAreJPEGAndMetadataDisagrees() throws {
        let jpegBytes = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let dg2 = try dataGroup2Fixture(imageDataType: 0x01, imageBytes: jpegBytes)
        let parsed = try XCTUnwrap(try DataGroupParser().parseDG(data: dg2) as? DataGroup2)
        let model = NFCPassportModel()
        model.addDataGroup(.DG2, dataGroup: parsed)

        let readResult = PassportChipReadResult(passport: model, photoPolicy: .read)

        XCTAssertEqual(parsed.imageDataType, 0x01)
        XCTAssertEqual(readResult.faceImageData?.format, .jpeg)
        XCTAssertEqual(readResult.faceImageData?.mimeType, "image/jpeg")
    }

    func testModelPrivacyCleanupScrubsRetainedDataGroupPayloadsBeforeReleasingReferences() throws {
        let com = try XCTUnwrap(try DataGroupParser().parseDG(
            data: try comFixture(dataGroupTags: [0x61, 0x75, 0x6B])
        ) as? COM)
        let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: dataGroup1Fixture(mrz: syntheticTD3MRZ())
        ) as? DataGroup1)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        ) as? DataGroup2)
        let dg7Body = try [0x02] + toAsn1Length(1) + [0x01] +
            tlv(tag: [0x5F, 0x43], value: [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: [UInt8]([0x67]) + toAsn1Length(dg7Body.count) + dg7Body
        ) as? DataGroup7)
        let dg11 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: try dataGroup11Fixture(fullName: "DOE<<JANE", placeOfBirth: "Zürich")
        ) as? DataGroup11)
        let frontImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let rearImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43])
        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: try dataGroup12Fixture(frontImage: frontImage, rearImage: rearImage)
        ) as? DataGroup12)
        let dg15 = try XCTUnwrap(try DataGroupParser().parseDG(data: dataGroup15Fixture()) as? DataGroup15)
        let model = NFCPassportModel()
        model.addDataGroup(.COM, dataGroup: com)
        model.addDataGroup(.DG1, dataGroup: dg1)
        model.addDataGroup(.DG2, dataGroup: dg2)
        model.addDataGroup(.DG7, dataGroup: dg7)
        model.addDataGroup(.DG11, dataGroup: dg11)
        model.addDataGroup(.DG12, dataGroup: dg12)
        model.addDataGroup(.DG15, dataGroup: dg15)

        XCTAssertEqual(com.version, "1.7")
        XCTAssertEqual(com.unicodeVersion, "4.0.0")
        XCTAssertEqual(com.dataGroupsPresent, ["DG1", "DG2", "DG11"])
        XCTAssertFalse(dg1.elements.isEmpty)
        XCTAssertFalse(dg2.imageData.isEmpty)
        XCTAssertGreaterThan(dg2.nrImages, 0)
        XCTAssertGreaterThan(dg2.versionNumber, 0)
        XCTAssertGreaterThan(dg2.lengthOfRecord, 0)
        XCTAssertGreaterThan(dg2.numberOfFacialImages, 0)
        XCTAssertGreaterThan(dg2.facialRecordDataLength, 0)
        XCTAssertEqual(dg2.imageWidth, 1)
        XCTAssertEqual(dg2.imageHeight, 1)
        XCTAssertFalse(dg7.imageDataItems.isEmpty)
        XCTAssertEqual(dg11.fullName, "DOE<<JANE")
        XCTAssertEqual(dg12.frontImage, frontImage)
        XCTAssertTrue(dg15.ecdsaPublicKey != nil || dg15.rsaPublicKey != nil)

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG2))
        XCTAssertTrue(model.dataGroupsAvailable.isEmpty)
        XCTAssertEqual(com.version, "Unknown")
        XCTAssertEqual(com.unicodeVersion, "Unknown")
        XCTAssertTrue(com.dataGroupsPresent.isEmpty)
        XCTAssertTrue(com.data.isEmpty)
        XCTAssertTrue(com.body.isEmpty)
        XCTAssertTrue(dg1.elements.isEmpty)
        XCTAssertTrue(dg1.data.isEmpty)
        XCTAssertTrue(dg1.body.isEmpty)
        XCTAssertTrue(dg2.imageData.isEmpty)
        XCTAssertTrue(dg2.imageDataItems.isEmpty)
        XCTAssertTrue(dg2.data.isEmpty)
        XCTAssertTrue(dg2.body.isEmpty)
        XCTAssertEqual(dg2.nrImages, 0)
        XCTAssertEqual(dg2.versionNumber, 0)
        XCTAssertEqual(dg2.lengthOfRecord, 0)
        XCTAssertEqual(dg2.numberOfFacialImages, 0)
        XCTAssertEqual(dg2.facialRecordDataLength, 0)
        XCTAssertEqual(dg2.nrFeaturePoints, 0)
        XCTAssertEqual(dg2.gender, 0)
        XCTAssertEqual(dg2.eyeColor, 0)
        XCTAssertEqual(dg2.hairColor, 0)
        XCTAssertEqual(dg2.featureMask, 0)
        XCTAssertEqual(dg2.expression, 0)
        XCTAssertEqual(dg2.poseAngle, 0)
        XCTAssertEqual(dg2.poseAngleUncertainty, 0)
        XCTAssertEqual(dg2.faceImageType, 0)
        XCTAssertEqual(dg2.imageDataType, 0)
        XCTAssertEqual(dg2.imageWidth, 0)
        XCTAssertEqual(dg2.imageHeight, 0)
        XCTAssertEqual(dg2.imageColorSpace, 0)
        XCTAssertEqual(dg2.sourceType, 0)
        XCTAssertEqual(dg2.deviceType, 0)
        XCTAssertEqual(dg2.quality, 0)
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
        XCTAssertNil(dg15.ecdsaPublicKey)
        XCTAssertNil(dg15.rsaPublicKey)
        XCTAssertTrue(dg15.data.isEmpty)
        XCTAssertTrue(dg15.body.isEmpty)
    }

    func testIdentityProjectionFallsBackToDG1WhenDG11NameIsEmpty() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: ""
        )

        XCTAssertEqual(model.lastName, "DOE")
        XCTAssertEqual(model.firstName, "JANE")
        XCTAssertEqual(model.identityResult.lastName, "DOE")
        XCTAssertEqual(model.identityResult.firstName, "JANE")
    }

    func testIdentityProjectionFallsBackToDG1WhenDG11NameIsUnstructured() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: "JANE DOE"
        )

        XCTAssertEqual(model.lastName, "DOE")
        XCTAssertEqual(model.firstName, "JANE")
        XCTAssertEqual(model.identityResult.lastName, "DOE")
        XCTAssertEqual(model.identityResult.firstName, "JANE")
    }

    func testIdentityProjectionCanUseStructuredDG11Name() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: "PUBLIC<<JOHN"
        )

        XCTAssertEqual(model.lastName, "PUBLIC")
        XCTAssertEqual(model.firstName, "JOHN")
        XCTAssertEqual(model.identityResult.lastName, "PUBLIC")
        XCTAssertEqual(model.identityResult.firstName, "JOHN")
    }

    func testIdentityProjectionFallsBackToDG1PersonalNumberWhenDG11ValueIsBlank() throws {
        let model = try modelWithDG1AndDG11(
            optionalData: "PERSONAL12345",
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE",
            dg11PersonalNumber: "   "
        )

        XCTAssertEqual(model.personalNumber, "PERSONAL12345")
        XCTAssertEqual(model.identityResult.personalNumber, "PERSONAL12345")
    }

    func testIdentityProjectionReturnsNilForFillerOnlyDG1PersonalNumber() throws {
        let model = try modelWithDG1AndDG11(
            optionalData: String(repeating: "<", count: 14),
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE"
        )

        XCTAssertNil(model.personalNumber)
        XCTAssertNil(model.identityResult.personalNumber)
    }

    func testIdentityProjectionFallsBackToDG1PersonalNumberWhenDG11ValueIsFillerOnly() throws {
        let model = try modelWithDG1AndDG11(
            optionalData: "PERSONAL12345",
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE",
            dg11PersonalNumber: "<<<<<<"
        )

        XCTAssertEqual(model.personalNumber, "PERSONAL12345")
        XCTAssertEqual(model.identityResult.personalNumber, "PERSONAL12345")
    }

    func testIdentityProjectionReturnsNilForBlankOptionalDG11TextFields() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE",
            dg11PlaceOfBirth: "   ",
            dg11Address: "",
            dg11Telephone: "\n\t"
        )

        XCTAssertNil(model.placeOfBirth)
        XCTAssertNil(model.residenceAddress)
        XCTAssertNil(model.phoneNumber)
        XCTAssertNil(model.identityResult.placeOfBirth)
        XCTAssertNil(model.identityResult.residenceAddress)
        XCTAssertNil(model.identityResult.phoneNumber)
    }

    func testIdentityProjectionReturnsNilForFillerOnlyOptionalDG11TextFields() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE",
            dg11PlaceOfBirth: "<<<<",
            dg11Address: "<<",
            dg11Telephone: "<<<"
        )

        XCTAssertNil(model.placeOfBirth)
        XCTAssertNil(model.residenceAddress)
        XCTAssertNil(model.phoneNumber)
        XCTAssertNil(model.identityResult.placeOfBirth)
        XCTAssertNil(model.identityResult.residenceAddress)
        XCTAssertNil(model.identityResult.phoneNumber)
    }

    func testIdentityProjectionTrimsOptionalDG11TextFields() throws {
        let model = try modelWithDG1AndDG11(
            dg1Name: "DOE<<JANE",
            dg11FullName: "DOE<<JANE",
            dg11PlaceOfBirth: "  Zürich  ",
            dg11Address: "\nMain Street\t",
            dg11Telephone: " +41 44 000 00 00 "
        )

        XCTAssertEqual(model.placeOfBirth, "Zürich")
        XCTAssertEqual(model.residenceAddress, "Main Street")
        XCTAssertEqual(model.phoneNumber, "+41 44 000 00 00")
        XCTAssertEqual(model.identityResult.placeOfBirth, "Zürich")
        XCTAssertEqual(model.identityResult.residenceAddress, "Main Street")
        XCTAssertEqual(model.identityResult.phoneNumber, "+41 44 000 00 00")
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
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)

        let isoHeaderWithoutImage = hexRepToBin(
            "46414300" + // FAC marker
            "30313000" + // version
            "0000002E" + // record length
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

    func testDataGroup2RejectsUndeclaredTrailingBytesBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(imageBytes: [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10]) + [0xAA, 0xBB]

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsShortDeclaredFacialRecordLengthBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let correctRecordLength = 32 + validImage.count
        let malformed = iso19794FaceRecord(
            declaredFacialRecordDataLength: correctRecordLength - 1,
            imageBytes: validImage
        )

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsLongDeclaredFacialRecordLengthBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let correctRecordLength = 32 + validImage.count
        let malformed = iso19794FaceRecord(
            declaredFacialRecordDataLength: correctRecordLength + 1,
            imageBytes: validImage
        )

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsShortDeclaredTopLevelRecordLengthBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let correctRecordLength = 46 + validImage.count
        let malformed = iso19794FaceRecord(
            declaredLengthOfRecord: correctRecordLength - 1,
            imageBytes: validImage
        )

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsLongDeclaredTopLevelRecordLengthBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10])
        let correctRecordLength = 46 + validImage.count
        let malformed = iso19794FaceRecord(
            declaredLengthOfRecord: correctRecordLength + 1,
            imageBytes: validImage
        )

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsZeroDeclaredFacialImagesBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(numberOfFacialImages: 0)

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
    }

    func testDataGroup2RejectsOversizedDeclaredFacialImagesBeforeRetainingImage() throws {
        let baselineImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46])
        let validDG2 = try dataGroup2Fixture(imageBytes: baselineImage)
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(numberOfFacialImages: 33)

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
        XCTAssertEqual(dg2.imageData, baselineImage)
        XCTAssertEqual(dg2.imageDataItems, [baselineImage])
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
        let validDG2 = try dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let dg2 = try XCTUnwrap(try DataGroupParser().parseDG(data: validDG2) as? DataGroup2)
        let malformed = iso19794FaceRecord(featurePoints: 10_001)

        XCTAssertThrowsError(try dg2.parseISO19794_5(data: malformed)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup2RejectsExcessiveImageDimensionsBeforeRetainingImage() throws {
        let validDG2 = try dataGroup2Fixture(imageBytes: [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
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
            tlv(tag: [0x5F, 0x43], value: [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]) +
            tlv(tag: [0x5F, 0x43], value: [0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43])
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body

        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup7)

        XCTAssertEqual(dg7.imageData, [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        XCTAssertEqual(dg7.imageDataItems, [
            [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10],
            [0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43]
        ])
    }

    func testDatagroup7UsesFirstNonEmptyImageForCompatibility() throws {
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let body = try [0x02] + toAsn1Length(1) + [0x02] +
            tlv(tag: [0x5F, 0x43], value: []) +
            tlv(tag: [0x5F, 0x43], value: validImage)
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body

        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup7)

        XCTAssertEqual(dg7.imageData, validImage)
        XCTAssertEqual(dg7.imageDataItems, [[], validImage])
    }

    func testIdentityResultIgnoresEmptyDG7ImageItemsForSignaturePresence() throws {
        let body = try [0x02] + toAsn1Length(1) + [0x01] +
            tlv(tag: [0x5F, 0x43], value: [])
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body
        let dg7 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup7)
        let model = NFCPassportModel()
        model.addDataGroup(.DG7, dataGroup: dg7)

        XCTAssertEqual(dg7.imageDataItems, [[]])
        XCTAssertTrue(dg7.imageData.isEmpty)
        XCTAssertFalse(model.identityResult.hasSignatureImage)
    }

    func testDatagroup7RejectsImageCountMismatchWithoutRetainingPayload() throws {
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let missingItemBody = try [0x02] + toAsn1Length(1) + [0x02] +
            tlv(tag: [0x5F, 0x43], value: validImage)
        let missingItemData = try [UInt8]([0x67]) + toAsn1Length(missingItemBody.count) + missingItemBody

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: missingItemData)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }

        let extraItemBody = try [0x02] + toAsn1Length(1) + [0x00] +
            tlv(tag: [0x5F, 0x43], value: validImage)
        let extraItemData = try [UInt8]([0x67]) + toAsn1Length(extraItemBody.count) + extraItemBody

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: extraItemData)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDatagroup7RejectsArbitrarySignatureBytesBeforeRetainingThem() throws {
        let body = try [0x02] + toAsn1Length(1) + [0x01] +
            tlv(tag: [0x5F, 0x43], value: [0x01, 0x02])
        let data = try [UInt8]([0x67]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
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

    func testDataGroup11RejectsInvalidCalendarDateOfBirth() throws {
        let tagList: [UInt8] = [0x5F, 0x2B]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x2B], value: Array("19701340".utf8))
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
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

    func testDataGroup11RejectsOversizedTextBeforeRetainingIt() throws {
        let oversizedName = [UInt8](repeating: 0x41, count: 64 * 1024 + 1)
        let tagList: [UInt8] = [0x5F, 0x0E]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x0E], value: oversizedName)
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup11RejectsFieldsMissingFromTagListBeforeRetainingThem() throws {
        let tagList: [UInt8] = [0x5F, 0x0E]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x0E], value: Array("DOE<<JANE".utf8)) +
            tlv(tag: [0x5F, 0x11], value: Array("DECLARED-NOWHERE".utf8))
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup11RejectsMalformedDateOfBirth() throws {
        let tagList: [UInt8] = [0x5F, 0x2B]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x2B], value: Array("1970AB01".utf8))
        let data = try [UInt8]([0x6B]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
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

    func testDataGroup12RejectsMalformedASCIIDateOfIssue() throws {
        let tagList: [UInt8] = [0x5F, 0x26]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x26], value: Array("2018-326".utf8))
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup12RejectsInvalidCalendarASCIIDateOfIssue() throws {
        let tagList: [UInt8] = [0x5F, 0x26]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x26], value: Array("20181340".utf8))
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup12ParsesCompactBCDDateOfIssue() throws {
        let tagList: [UInt8] = [0x5F, 0x26]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x26], value: [0x20, 0x18, 0x03, 0x26])
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.dateOfIssue, "20180326")
    }

    func testDataGroup12RejectsMalformedBCDDateOfIssue() throws {
        let tagList: [UInt8] = [0x5F, 0x26]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x26], value: [0x20, 0x1A, 0x03, 0x26])
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup12RejectsInvalidCalendarBCDDateOfIssue() throws {
        let tagList: [UInt8] = [0x5F, 0x26]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x26], value: [0x20, 0x18, 0x13, 0x40])
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
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

    func testDataGroup12RejectsOversizedTextBeforeRetainingIt() throws {
        let oversizedObservation = [UInt8](repeating: 0x41, count: 64 * 1024 + 1)
        let tagList: [UInt8] = [0x5F, 0x1B]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x1B], value: oversizedObservation)
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
    }

    func testDataGroup12FallsBackToBoundedPlainTextForMalformedNestedDetails() throws {
        let details = Array("BOUNDARY-NOTE".utf8)
        let malformedHighTagPrefix = [UInt8]([0xBF, 0x80, 0x80, 0x80, 0x80])
        let tagList: [UInt8] = [0xA0]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0xA0], value: malformedHighTagPrefix + details)
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        let dg12 = try XCTUnwrap(try DataGroupParser().parseDG(data: data) as? DataGroup12)

        XCTAssertEqual(dg12.otherPersonsDetails, LDSStringDecoder.decode(malformedHighTagPrefix + details))
    }

    func testDataGroup12RejectsMalformedImageBytesBeforeRetainingThem() throws {
        let malformedFrontImage = try dataGroup12Fixture(frontImage: [0x01, 0x02], rearImage: [])

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: malformedFrontImage)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }

        let oversizedRearImage = try dataGroup12Fixture(
            frontImage: [],
            rearImage: [UInt8](repeating: 0xFF, count: 10 * 1024 * 1024 + 1)
        )

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: oversizedRearImage)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
    }

    func testDataGroup12RejectsFieldsMissingFromTagListBeforeRetainingThem() throws {
        let validImage = [UInt8]([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        let tagList: [UInt8] = [0x5F, 0x19]
        let body = try tlv(tag: [0x5C], value: tagList) +
            tlv(tag: [0x5F, 0x19], value: Array("ISSUER".utf8)) +
            tlv(tag: [0x5F, 0x1D], value: validImage)
        let data = try [UInt8]([0x6C]) + toAsn1Length(body.count) + body

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: data)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
        }
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
        let dg15Val = dataGroup15Fixture()
        let dgp = DataGroupParser()
        
        XCTAssertNoThrow(try dgp.parseDG(data: dg15Val)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup15 )

            let dg15 = dg as? DataGroup15
            XCTAssertTrue( dg15?.ecdsaPublicKey != nil || dg15?.rsaPublicKey != nil )
        }
    }

    func testDatagroup15RejectsUnsupportedPublicKeyAlgorithm() throws {
        XCTAssertThrowsError(try DataGroupParser().parseDG(data: try unsupportedDataGroup15Fixture())) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                return XCTFail("Expected InvalidASN1Structure, got \(error)")
            }
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

    func testCOMRejectsUnknownDataGroupTags() throws {
        let com = try comFixture(dataGroupTags: [0x61, 0x62])

        XCTAssertThrowsError(try DataGroupParser().parseDG(data: com)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testCOMRejectsMalformedLDSVersionFields() throws {
        let malformedValues = [
            Array("010".utf8),
            Array("01A7".utf8)
        ]

        for malformedValue in malformedValues {
            let com = try comFixture(ldsVersion: malformedValue, dataGroupTags: [0x61, 0x75])

            XCTAssertThrowsError(try DataGroupParser().parseDG(data: com)) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    return XCTFail("Expected InvalidASN1Structure, got \(error)")
                }
            }
        }
    }

    func testCOMRejectsMalformedUnicodeVersionFields() throws {
        let malformedValues = [
            Array("04000".utf8),
            Array("040A00".utf8)
        ]

        for malformedValue in malformedValues {
            let com = try comFixture(unicodeVersion: malformedValue, dataGroupTags: [0x61, 0x75])

            XCTAssertThrowsError(try DataGroupParser().parseDG(data: com)) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    return XCTFail("Expected InvalidASN1Structure, got \(error)")
                }
            }
        }
    }

    func testCOMDeduplicatesAdvertisedDataGroupsWithoutReordering() throws {
        let com = try comFixture(dataGroupTags: [0x61, 0x75, 0x61, 0x6B, 0x75])

        let dataGroup = try DataGroupParser().parseDG(data: com)
        let parsedCOM = try XCTUnwrap(dataGroup as? COM)

        XCTAssertEqual(parsedCOM.dataGroupsPresent, ["DG1", "DG2", "DG11"])
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

    func testStructuredSODSignatureContentRejectsMalformedVersionField() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let content = try sequence(
            asn1Null() +
            digestAlgorithm +
            sequence(dataGroupHash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content))) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                XCTFail("Expected UnableToParseSODHashes, got \(error)")
                return
            }
        }
    }

    func testStructuredSODSignatureContentRejectsUnsupportedVersion() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let content = try sequence(
            asn1Integer([0x01]) +
            digestAlgorithm +
            sequence(dataGroupHash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content))) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                XCTFail("Expected UnableToParseSODHashes, got \(error)")
                return
            }
        }
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

    func testStructuredSODSignatureContentRejectsDuplicateDataGroupHashes() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let firstDG1Hash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let secondDG1Hash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0x5A, count: 32))
        )
        let content = try sequence(
            asn1Integer([0x00]) +
            digestAlgorithm +
            sequence(firstDG1Hash + secondDG1Hash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content))) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                XCTFail("Expected UnableToParseSODHashes, got \(error)")
                return
            }
        }
    }

    func testStructuredSODSignatureContentRejectsExtraDataGroupHashFields() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32)) +
            asn1Null()
        )
        let content = try sequence(
            asn1Integer([0x00]) +
            digestAlgorithm +
            sequence(dataGroupHash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content))) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                XCTFail("Expected UnableToParseSODHashes, got \(error)")
                return
            }
        }
    }

    func testStructuredSODSignatureContentRejectsHashLengthMismatch() throws {
        let digestAlgorithm = try sequence(
            asn1OID([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) +
            [0x05, 0x00]
        )
        let shortSHA256Hash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 31))
        )
        let content = try sequence(
            asn1Integer([0x00]) +
            digestAlgorithm +
            sequence(shortSHA256Hash)
        )

        XCTAssertThrowsError(try NFCPassportModel().parseSODSignatureContent(data: Data(content))) { error in
            guard case PassiveAuthenticationError.UnableToParseSODHashes = error else {
                XCTFail("Expected UnableToParseSODHashes, got \(error)")
                return
            }
        }
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

    func testSimpleASN1NodeRejectsExcessiveNestingWithoutTrapping() throws {
        var nested = try asn1Integer([0x01])
        for _ in 0..<66 {
            nested = try sequence(nested)
        }

        XCTAssertThrowsError(try SimpleASN1Node.parse(nested)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testSimpleASN1NodeRejectsOverflowingHighTagNumberWithoutTrapping() {
        let overflowingHighTag = [0x3F] + [UInt8](repeating: 0xFF, count: MemoryLayout<Int>.size + 1) + [0x00, 0x00]

        XCTAssertThrowsError(try SimpleASN1Node.parse(overflowingHighTag)) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
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

    func testSODAccessorsFailClosedAfterPrivacyCleanup() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true
        ))

        sod.removeSensitiveDataForPrivacy()

        XCTAssertThrowsError(try sod.getEncapsulatedContent()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
            XCTAssertFalse(error.localizedDescription.localizedCaseInsensitiveContains("APDU"))
        }
    }

    func testVerifyPassportPreservesSODSignatureFailureWhenHashFallbackSucceeds() throws {
        let dg1Bytes = try dataGroup1Fixture(
            mrz: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        )
        let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1Bytes) as? DataGroup1)
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: calcSHA256Hash(dg1.data))
        )
        let ldsSecurityObject = try sequence(
            asn1Integer([0x00]) +
            algorithmIdentifier("2.16.840.1.101.3.4.2.1") +
            sequence(dataGroupHash)
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: ldsSecurityObject,
            messageDigest: calcSHA256Hash(ldsSecurityObject),
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true
        ))
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: dg1)
        model.addDataGroup(.SOD, dataGroup: sod)

        model.verifyPassport(masterListURL: nil)

        XCTAssertFalse(model.documentSigningCertificateVerified)
        XCTAssertTrue(model.passportDataNotTampered)
        XCTAssertTrue(model.verificationErrors.contains { $0 is OpenSSLError })
        XCTAssertEqual(model.verificationResult.sodSignatureDetail.status, .failed)
        XCTAssertEqual(model.verificationResult.sodSignatureDetail.reason, .signatureInvalid)
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.status, .passed)
    }

    func testAddingDataGroupAfterVerificationInvalidatesDerivedPassiveState() throws {
        let dg1Bytes = try dataGroup1Fixture(
            mrz: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        )
        let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1Bytes) as? DataGroup1)
        let dataGroupHash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: calcSHA256Hash(dg1.data))
        )
        let ldsSecurityObject = try sequence(
            asn1Integer([0x00]) +
            algorithmIdentifier("2.16.840.1.101.3.4.2.1") +
            sequence(dataGroupHash)
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: ldsSecurityObject,
            messageDigest: calcSHA256Hash(ldsSecurityObject),
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true
        ))
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: dg1)
        model.addDataGroup(.SOD, dataGroup: sod)
        model.verifyPassport(masterListURL: nil)

        XCTAssertTrue(model.passportVerificationAttempted)
        XCTAssertTrue(model.passportDataNotTampered)
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.status, .passed)

        let replacementDG1 = try XCTUnwrap(try DataGroupParser().parseDG(
            data: dataGroup1Fixture(mrz: syntheticTD3MRZ())
        ) as? DataGroup1)
        model.addDataGroup(.DG1, dataGroup: replacementDG1)

        XCTAssertTrue(dg1.elements.isEmpty)
        XCTAssertTrue(dg1.data.isEmpty)
        XCTAssertTrue(dg1.body.isEmpty)
        XCTAssertFalse(replacementDG1.elements.isEmpty)
        XCTAssertFalse(replacementDG1.data.isEmpty)
        XCTAssertFalse(replacementDG1.body.isEmpty)
        XCTAssertFalse(model.passportVerificationAttempted)
        XCTAssertFalse(model.documentSigningCertificateVerified)
        XCTAssertFalse(model.passportDataNotTampered)
        XCTAssertTrue(model.verificationErrors.isEmpty)
        XCTAssertTrue(model.dataGroupHashes.isEmpty)
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.status, .notChecked)
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.reason, .notRequested)
    }

    func testVerifyPassportReportsSODCoverageInDataGroupNumberOrder() throws {
        let dg1Bytes = try dataGroup1Fixture(
            mrz: "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36UTO7408122F1204159ZE184226B<<<<<10"
        )
        let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(data: dg1Bytes) as? DataGroup1)
        let dg1Hash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: calcSHA256Hash(dg1.data))
        )
        let unreadDG2Hash = try sequence(
            asn1Integer([0x02]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let unreadDG11Hash = try sequence(
            asn1Integer([0x0B]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0x5A, count: 32))
        )
        let ldsSecurityObject = try sequence(
            asn1Integer([0x00]) +
            algorithmIdentifier("2.16.840.1.101.3.4.2.1") +
            sequence(dg1Hash + unreadDG11Hash + unreadDG2Hash)
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: ldsSecurityObject,
            messageDigest: calcSHA256Hash(ldsSecurityObject),
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true
        ))
        let model = NFCPassportModel()
        model.addDataGroup(.DG1, dataGroup: dg1)
        model.addDataGroup(.SOD, dataGroup: sod)

        model.verifyPassport(masterListURL: nil)

        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.status, .passed)
        XCTAssertEqual(model.verificationResult.dataGroupCoverage, [
            PassportDataGroupVerificationCoverage(dataGroup: .DG1, status: .coveredAndMatched),
            PassportDataGroupVerificationCoverage(dataGroup: .DG2, status: .coveredButNotRead),
            PassportDataGroupVerificationCoverage(dataGroup: .DG11, status: .coveredButNotRead)
        ])
    }

    func testVerifyPassportDoesNotPassDataGroupHashesWhenNoReadGroupsWereCompared() throws {
        let unreadDG1Hash = try sequence(
            asn1Integer([0x01]) +
            tlv(tag: [0x04], value: [UInt8](repeating: 0xA5, count: 32))
        )
        let ldsSecurityObject = try sequence(
            asn1Integer([0x00]) +
            algorithmIdentifier("2.16.840.1.101.3.4.2.1") +
            sequence(unreadDG1Hash)
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: ldsSecurityObject,
            messageDigest: calcSHA256Hash(ldsSecurityObject),
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true
        ))
        let model = NFCPassportModel()
        model.addDataGroup(.SOD, dataGroup: sod)

        model.verifyPassport(masterListURL: nil)

        XCTAssertFalse(model.passportDataNotTampered)
        XCTAssertTrue(model.dataGroupHashes.isEmpty)
        XCTAssertTrue(model.verificationErrors.contains { error in
            if case PassiveAuthenticationError.NoDataGroupHashesCompared = error { return true }
            return false
        })
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.status, .failed)
        XCTAssertEqual(model.verificationResult.dataGroupHashDetail.reason, .attemptedFailed)
        XCTAssertEqual(model.verificationResult.dataGroupCoverage, [
            PassportDataGroupVerificationCoverage(dataGroup: .DG1, status: .coveredButNotRead)
        ])
    }

    func testCardSecurityParsesSignedSecurityInfosEncapsulatedContent() throws {
        let cardSecurity = try CardSecurity(syntheticCardSecurityData())
        let parsedPACEInfo = try XCTUnwrap(cardSecurity.securityInfos.first as? PACEInfo)

        XCTAssertEqual(parsedPACEInfo.getObjectIdentifier(), SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128)
        XCTAssertEqual(parsedPACEInfo.version, 2)
        XCTAssertEqual(parsedPACEInfo.parameterId, PACEInfo.PARAM_ID_ECP_NIST_P256_R1)
    }

    func testCardSecurityRejectsUnsignedEncapsulatedContentOID() throws {
        let malformedCMS = try syntheticCardSecurityData(contentOID: "1.2.840.113549.1.7.1")

        XCTAssertThrowsError(try CardSecurity(malformedCMS)) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testSODRejectsSignedDataWrapperWithExtraSequenceChild() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true,
            explicitSignedDataPrefix: try sequence(asn1Integer([0x00]))
        ))

        XCTAssertThrowsError(try sod.getEncapsulatedContent()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testSODRejectsUnexpectedEncapsulatedContentType() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true,
            encapsulatedContentOID: "1.2.840.113549.1.7.1"
        ))

        XCTAssertThrowsError(try sod.getEncapsulatedContent()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testSODRejectsUnexpectedEncapsulatedContentChild() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true,
            encapsulatedContentPrefix: try tlv(tag: [0x04], value: [0x00])
        ))

        XCTAssertThrowsError(try sod.getEncapsulatedContent()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testSODRejectsMessageDigestAttributeWithExtraValues() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let malformedMessageDigestAttribute = try sequence(
            asn1ObjectIdentifier("1.2.840.113549.1.9.4") +
            asn1Set(
                (try tlv(tag: [0x04], value: [0x00])) +
                (try tlv(tag: [0x04], value: messageDigest))
            )
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true,
            signedAttributesValue: try syntheticSODContentTypeAttribute() + malformedMessageDigestAttribute
        ))

        XCTAssertThrowsError(try sod.getMessageDigestFromSignedAttributes()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testSODRejectsMessageDigestAttributeWithUnexpectedFirstValue() throws {
        let encapsulatedContent: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x01]
        let messageDigest = calcSHA256Hash(encapsulatedContent)
        let malformedMessageDigestAttribute = try sequence(
            asn1ObjectIdentifier("1.2.840.113549.1.9.4") +
            asn1Set(
                asn1Null() +
                (try tlv(tag: [0x04], value: messageDigest))
            )
        )
        let sod = try SOD(syntheticSODData(
            encapsulatedContent: encapsulatedContent,
            messageDigest: messageDigest,
            signature: [0xAA, 0xBB, 0xCC, 0xDD],
            includeOptionalCertificateAndCRLFields: true,
            signedAttributesValue: try syntheticSODContentTypeAttribute() + malformedMessageDigestAttribute
        ))

        XCTAssertThrowsError(try sod.getMessageDigestFromSignedAttributes()) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testCardSecurityRejectsSignedDataWithoutExplicitContentWrapper() throws {
        let malformedCMS = try syntheticCardSecurityData(wrapSignedData: false)

        XCTAssertThrowsError(try CardSecurity(malformedCMS)) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testCardSecurityRejectsSignedDataWrapperWithExtraSequenceChild() throws {
        let malformedCMS = try syntheticCardSecurityData(
            explicitSignedDataPrefix: try sequence(asn1Integer([0x00]))
        )

        XCTAssertThrowsError(try CardSecurity(malformedCMS)) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
    }

    func testCardSecurityRejectsUnexpectedEncapsulatedContentChild() throws {
        let malformedCMS = try syntheticCardSecurityData(
            encapsulatedContentPrefix: try tlv(tag: [0x04], value: [0x00])
        )

        XCTAssertThrowsError(try CardSecurity(malformedCMS)) { error in
            guard case OpenSSLError.UnableToExtractSignedDataFromPKCS7 = error else {
                XCTFail("Expected UnableToExtractSignedDataFromPKCS7, got \(error)")
                return
            }
        }
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

    func testSecurityInfosParserRejectsMalformedRecognizedRequiredFields() throws {
        let malformedPACEInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Null() +
            asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
        )
        let malformedChipAuthenticationInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID) +
            asn1Null()
        )
        let malformedActiveAuthenticationInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_AA_OID) +
            asn1Null()
        )
        let malformedChipAuthenticationPublicKeyInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PK_ECDH_OID) +
            asn1Null()
        )

        for malformedInfo in [
            malformedPACEInfo,
            malformedChipAuthenticationInfo,
            malformedActiveAuthenticationInfo,
            malformedChipAuthenticationPublicKeyInfo
        ] {
            XCTAssertThrowsError(try SecurityInfosParser.parse(asn1Set(malformedInfo))) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    XCTFail("Expected InvalidASN1Structure, got \(error)")
                    return
                }
            }
        }
    }

    func testSecurityInfosParserRejectsMalformedTopLevelEntriesInsteadOfSkippingThem() throws {
        let nonSequenceEntry = try asn1Integer([0x01])
        let missingOIDEntry = try sequence(asn1Integer([0x01]))
        let missingRequiredDataEntry = try sequence(asn1ObjectIdentifier("1.2.3.4.5"))

        for malformedInfos in [
            try asn1Set(nonSequenceEntry),
            try asn1Set(missingOIDEntry),
            try asn1Set(missingRequiredDataEntry)
        ] {
            XCTAssertThrowsError(try SecurityInfosParser.parse(malformedInfos)) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    XCTFail("Expected InvalidASN1Structure, got \(error)")
                    return
                }
            }
        }
    }

    func testSecurityInfosParserRejectsSequenceRoot() throws {
        let paceInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Integer([0x02]) +
            asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
        )

        XCTAssertThrowsError(try SecurityInfosParser.parse(sequence(paceInfo))) { error in
            guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                XCTFail("Expected InvalidASN1Structure, got \(error)")
                return
            }
        }
    }

    func testSecurityInfosParserRejectsExtraSecurityInfoFields() throws {
        let overlongPACEInfo = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Integer([0x02]) +
            asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)]) +
            asn1Null()
        )
        let overlongUnknownInfo = try sequence(
            asn1ObjectIdentifier("1.2.3.4.5") +
            asn1Integer([0x01]) +
            asn1Null() +
            asn1Null()
        )

        for malformedInfo in [overlongPACEInfo, overlongUnknownInfo] {
            XCTAssertThrowsError(try SecurityInfosParser.parse(asn1Set(malformedInfo))) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    XCTFail("Expected InvalidASN1Structure, got \(error)")
                    return
                }
            }
        }
    }

    func testSecurityInfosParserRejectsMalformedRecognizedOptionalFields() throws {
        let malformedPACEParameter = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Integer([0x02]) +
            asn1Null()
        )
        let malformedChipAuthenticationKeyId = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID) +
            asn1Integer([0x01]) +
            asn1Null()
        )
        let malformedActiveAuthenticationSignatureOID = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_AA_OID) +
            asn1Integer([0x01]) +
            asn1Null()
        )

        for malformedInfo in [
            malformedPACEParameter,
            malformedChipAuthenticationKeyId,
            malformedActiveAuthenticationSignatureOID
        ] {
            XCTAssertThrowsError(try SecurityInfosParser.parse(asn1Set(malformedInfo))) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    XCTFail("Expected InvalidASN1Structure, got \(error)")
                    return
                }
            }
        }
    }

    func testSecurityInfosParserRejectsUnsupportedRecognizedVersions() throws {
        let unsupportedPACEVersion = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128) +
            asn1Integer([0x01]) +
            asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
        )
        let unsupportedChipAuthenticationVersion = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_CA_ECDH_AES_CBC_CMAC_256_OID) +
            asn1Integer([0x02]) +
            asn1Integer([0x01])
        )
        let unsupportedActiveAuthenticationVersion = try sequence(
            asn1ObjectIdentifier(SecurityInfo.ID_AA_OID) +
            asn1Integer([0x02]) +
            asn1ObjectIdentifier(SecurityInfo.ECDSA_PLAIN_SHA256_OID)
        )

        for malformedInfo in [
            unsupportedPACEVersion,
            unsupportedChipAuthenticationVersion,
            unsupportedActiveAuthenticationVersion
        ] {
            XCTAssertThrowsError(try SecurityInfosParser.parse(asn1Set(malformedInfo))) { error in
                guard case NFCPassportReaderError.InvalidASN1Structure = error else {
                    XCTFail("Expected InvalidASN1Structure, got \(error)")
                    return
                }
            }
        }
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

    @MainActor
    func testReaderRejectsMalformedPresentCardSecurityData() throws {
        let reader = PassportReader()
        let malformedCMS = try syntheticCardSecurityData(wrapSignedData: false)

        XCTAssertThrowsError(try reader.storeCardSecurity(from: malformedCMS))
    }

    func testModelPrivacyCleanupScrubsRetainedCardAccessAndCardSecurityReferences() throws {
        let cardAccess = try CardAccess(syntheticPACEInfoSet())
        let cardSecurity = try CardSecurity(syntheticCardSecurityData())
        let model = NFCPassportModel()
        model.cardAccess = cardAccess
        model.cardSecurity = cardSecurity

        XCTAssertNotNil(cardAccess.paceInfo)
        XCTAssertFalse(cardAccess.securityInfos.isEmpty)
        XCTAssertFalse(cardSecurity.securityInfos.isEmpty)

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.cardAccess)
        XCTAssertNil(model.cardSecurity)
        XCTAssertNil(cardAccess.paceInfo)
        XCTAssertTrue(cardAccess.securityInfos.isEmpty)
        XCTAssertTrue(cardSecurity.securityInfos.isEmpty)
        XCTAssertFalse(cardSecurity.signatureVerified)
        XCTAssertFalse(cardSecurity.signerTrusted)
    }

    func testModelPrivacyCleanupScrubsRetainedDG14SecurityInfoPublicKeys() throws {
        let dg14 = try XCTUnwrap(DataGroupParser().parseDG(data: dataGroup14ChipAuthenticationFixture()) as? DataGroup14)
        let retainedPublicKeyInfo = try XCTUnwrap(dg14.securityInfos.first as? ChipAuthenticationPublicKeyInfo)
        let model = NFCPassportModel()
        model.addDataGroup(.DG14, dataGroup: dg14)

        XCTAssertNotNil(retainedPublicKeyInfo.pubKey)

        model.removeSensitiveDataForPrivacy()

        XCTAssertNil(model.getDataGroup(.DG14))
        XCTAssertTrue(dg14.securityInfos.isEmpty)
        XCTAssertNil(retainedPublicKeyInfo.pubKey)
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

    func testModelDataGroupHashHelperUsesFullEncodedDataGroup() throws {
        let dataGroup = try DataGroup([0x61, 0x01, 0x5F, 0x00, 0xFF])
        let model = NFCPassportModel()

        model.addDataGroup(.DG1, dataGroup: dataGroup)

        XCTAssertEqual(model.getHashesForDatagroups(hashAlgorythm: "SHA1")[.DG1], calcSHA1Hash([0x61, 0x01, 0x5F]))
        XCTAssertNotEqual(model.getHashesForDatagroups(hashAlgorythm: "SHA1")[.DG1], calcSHA1Hash([0x5F]))
        XCTAssertTrue(model.getHashesForDatagroups(hashAlgorythm: "MD5").isEmpty)
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

private func comFixture(
    ldsVersion: [UInt8] = Array("0107".utf8),
    unicodeVersion: [UInt8] = Array("040000".utf8),
    dataGroupTags: [UInt8]
) throws -> [UInt8] {
    let body = try tlv(tag: [0x5F, 0x01], value: ldsVersion) +
        tlv(tag: [0x5F, 0x36], value: unicodeVersion) +
        tlv(tag: [0x5C], value: dataGroupTags)
    return try tlv(tag: [0x60], value: body)
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

private func syntheticSODContentTypeAttribute() throws -> [UInt8] {
    try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.9.3") +
        asn1Set(asn1ObjectIdentifier("2.23.136.1.1.1"))
    )
}

private func syntheticSODSignedAttributesValue(messageDigest: [UInt8]) throws -> [UInt8] {
    let messageDigestAttribute = try sequence(
        asn1ObjectIdentifier("1.2.840.113549.1.9.4") +
        asn1Set(try tlv(tag: [0x04], value: messageDigest))
    )
    return try syntheticSODContentTypeAttribute() + messageDigestAttribute
}

private func syntheticSODData(
    encapsulatedContent: [UInt8],
    messageDigest: [UInt8],
    signature: [UInt8],
    includeOptionalCertificateAndCRLFields: Bool,
    encapsulatedContentOID: String = "2.23.136.1.1.1",
    encapsulatedContentPrefix: [UInt8] = [],
    explicitSignedDataPrefix: [UInt8] = [],
    signedAttributesValue: [UInt8]? = nil
) throws -> [UInt8] {
    let digestAlgorithm = try algorithmIdentifier("2.16.840.1.101.3.4.2.1")
    let digestAlgorithms = try asn1Set(digestAlgorithm)
    let encapContentInfo = try sequence(
        asn1ObjectIdentifier(encapsulatedContentOID) +
        encapsulatedContentPrefix +
        context0(try tlv(tag: [0x04], value: encapsulatedContent))
    )
    let signedAttributes = try context0(signedAttributesValue ?? syntheticSODSignedAttributesValue(messageDigest: messageDigest))
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
        context0(explicitSignedDataPrefix + (try sequence(signedDataBody)))
    )
    return try [0x77] + toAsn1Length(cmsContent.count) + cmsContent
}

private func syntheticCardSecurityData(
    contentOID: String = "1.2.840.113549.1.7.2",
    wrapSignedData: Bool = true,
    explicitSignedDataPrefix: [UInt8] = [],
    encapsulatedContentPrefix: [UInt8] = []
) throws -> [UInt8] {
    let securityInfos = try syntheticPACEInfoSet()
    let encapContentInfo = try sequence(
        asn1ObjectIdentifier("2.23.136.1.1.1") +
        encapsulatedContentPrefix +
        context0(try tlv(tag: [0x04], value: securityInfos))
    )
    let signedData = try sequence(
        asn1Integer([0x03]) +
        asn1Set([]) +
        encapContentInfo +
        asn1Set([])
    )
    let signedDataContent = wrapSignedData ? try context0(explicitSignedDataPrefix + signedData) : signedData
    return try sequence(
        asn1ObjectIdentifier(contentOID) +
        signedDataContent
    )
}

private func syntheticPACEInfoSet() throws -> [UInt8] {
    let paceInfo = try sequence(
        asn1ObjectIdentifier(SecurityInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128) +
        asn1Integer([0x02]) +
        asn1Integer([UInt8(PACEInfo.PARAM_ID_ECP_NIST_P256_R1)])
    )
    return try asn1Set(paceInfo)
}

private func dataGroup1Fixture(mrz: String) throws -> [UInt8] {
    let mrzBytes = [UInt8](mrz.utf8)
    let tag = try [0x5F, 0x1F] + toAsn1Length(mrzBytes.count) + mrzBytes
    return try [UInt8]([0x61]) + toAsn1Length(tag.count) + tag
}

private func dataGroup11Fixture(
    fullName: String,
    placeOfBirth: String,
    personalNumber: String? = nil,
    address: String? = nil,
    telephone: String? = nil
) throws -> [UInt8] {
    var tagList: [UInt8] = [0x5F, 0x0E]
    var fields = try tlv(tag: [0x5F, 0x0E], value: Array(fullName.utf8))
    if let personalNumber = personalNumber {
        tagList += [0x5F, 0x10]
        fields += try tlv(tag: [0x5F, 0x10], value: Array(personalNumber.utf8))
    }
    tagList += [0x5F, 0x11]
    fields += try tlv(tag: [0x5F, 0x11], value: Array(placeOfBirth.utf8))
    if let address = address {
        tagList += [0x5F, 0x42]
        fields += try tlv(tag: [0x5F, 0x42], value: Array(address.utf8))
    }
    if let telephone = telephone {
        tagList += [0x5F, 0x12]
        fields += try tlv(tag: [0x5F, 0x12], value: Array(telephone.utf8))
    }

    let body = try tlv(tag: [0x5C], value: tagList) + fields
    return try [UInt8]([0x6B]) + toAsn1Length(body.count) + body
}

private func modelWithDG1AndDG11(
    optionalData: String = String(repeating: "<", count: 14),
    dg1Name: String,
    dg11FullName: String,
    dg11PersonalNumber: String? = nil,
    dg11PlaceOfBirth: String = "Zürich",
    dg11Address: String? = nil,
    dg11Telephone: String? = nil
) throws -> NFCPassportModel {
    let dg1 = try XCTUnwrap(try DataGroupParser().parseDG(
        data: dataGroup1Fixture(mrz: syntheticTD3MRZ(optionalData: optionalData, name: dg1Name))
    ) as? DataGroup1)
    let dg11 = try XCTUnwrap(try DataGroupParser().parseDG(
        data: try dataGroup11Fixture(
            fullName: dg11FullName,
            placeOfBirth: dg11PlaceOfBirth,
            personalNumber: dg11PersonalNumber,
            address: dg11Address,
            telephone: dg11Telephone
        )
    ) as? DataGroup11)
    let model = NFCPassportModel()
    model.addDataGroup(.DG1, dataGroup: dg1)
    model.addDataGroup(.DG11, dataGroup: dg11)
    return model
}

private func dataGroup12Fixture(frontImage: [UInt8], rearImage: [UInt8]) throws -> [UInt8] {
    let body = try tlv(tag: [0x5C], value: [0x5F, 0x1D, 0x5F, 0x1E]) +
        tlv(tag: [0x5F, 0x1D], value: frontImage) +
        tlv(tag: [0x5F, 0x1E], value: rearImage)
    return try [UInt8]([0x6C]) + toAsn1Length(body.count) + body
}

private func dataGroup15Fixture() -> [UInt8] {
    hexRepToBin(
        "6F820137308201333081EC06072A8648CE3D02013081E0020101302C06072A8648CE3D0101022100" +
        "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377304404207D5A0975" +
        "FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9042026DC5C6CE94A4B44F330" +
        "B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B60441048BD2AEB9CB7E57CB2C4B482FFC81B7" +
        "AFB9DE27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C27745132DED8" +
        "E545C1D54C72F046997022100A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E" +
        "82974856A7020101034200049BD24313046EB43CC4652B6FC1AA00E76B5405F4E7016521E95BE53" +
        "B9C5BAE5A1410F12CF3AE23F886EFCEDE89F7C63AD9CA9E5C6C05DE902DB70F2EB2341F9D"
    )
}

private func dataGroup14ChipAuthenticationFixture() throws -> [UInt8] {
    let dataGroup15 = try DataGroup15(dataGroup15Fixture())
    let chipAuthenticationPublicKeyInfo = try sequence(
        asn1ObjectIdentifier(SecurityInfo.ID_PK_ECDH_OID) +
        dataGroup15.body
    )
    let securityInfos = try asn1Set(chipAuthenticationPublicKeyInfo)
    return try [UInt8]([0x6E]) + toAsn1Length(securityInfos.count) + securityInfos
}

private func unsupportedDataGroup15Fixture() throws -> [UInt8] {
    let dsaPublicKey = hexRepToBin(
        "308201B73082012B06072A8648CE3804013082011E02818100DE30137B556E2ECCAA44015633B7" +
        "E7FAB90C65C34FA291135C7C7A5C99257309379CA12E293A05651900E0D8625DCBA28F3A45C40" +
        "CFD3E534B2914D5FFC03FE51EBE0589ADB5F4B94D5C5DCBCAFC1CA07A35C415FD35748AF538E" +
        "28EC406CC6948E817789B177AB7FA097E3AA3CEAD04D1FE57147BFBDB279E835F3ACDBD1DC" +
        "3021500C95EAEFAFC0B4C1A6A555F46E333A422B9EF71650281802F15E6EBECCC446EB94537" +
        "F38FA183DE73544329D5912051B9EFFA15B4529C54910248664BDA7C9D48A828BA81417D1C78" +
        "6FF17974D944FED3FFBF7EE39F077FAE17CF93E7D27E80CE26AFA847A63179C53893BA913B43" +
        "B31FEC05A0AF72AF92921F7C308F67040EE59F710EC2CC37A2AE8AE3B65A285EF76024B0452" +
        "DDA82B60381850002818100B7C34E99705FCEA38EB9C5D421658A1CF93F6EF581FD9D6E15B3" +
        "081BC70F720270D65E26037A2A34AC6E0A1F58EF3E2C982AFE22E9D41798032556C18DE39B16" +
        "2DC8C149278C06D708F8199325CF65E5314588992E0FE97976E613EAD43C6B11BC46DE3CA97" +
        "22BA4D7782FF083B07A0D58C96E522C11728352C7AAA579401256"
    )
    return try [UInt8]([0x6F]) + toAsn1Length(dsaPublicKey.count) + dsaPublicKey
}

private func mrzPadded(_ value: String, length: Int) -> String {
    String((value + String(repeating: "<", count: length)).prefix(length))
}

private func syntheticTD3MRZ(
    documentNumber: String = "ABC123456",
    issuingAuthority: String = "UTO",
    nationality: String = "UTO",
    dateOfBirth: String = "700101",
    gender: String = "F",
    expiryDate: String = "300101",
    optionalData: String = String(repeating: "<", count: 14),
    name: String = "DOE<<JANE"
) -> String {
    let normalizedDocumentNumber = mrzPadded(documentNumber, length: 9)
    let normalizedOptionalData = mrzPadded(optionalData, length: 14)
    let line1 = "P<" + issuingAuthority + mrzPadded(name, length: 39)
    let documentNumberCheckDigit = mrzCheckDigit(normalizedDocumentNumber)
    let dateOfBirthCheckDigit = mrzCheckDigit(dateOfBirth)
    let expiryDateCheckDigit = mrzCheckDigit(expiryDate)
    let optionalDataCheckDigit = mrzCheckDigit(normalizedOptionalData)
    let compositeCheckDigit = mrzCheckDigit(
        normalizedDocumentNumber + documentNumberCheckDigit +
        dateOfBirth + dateOfBirthCheckDigit +
        expiryDate + expiryDateCheckDigit +
        normalizedOptionalData + optionalDataCheckDigit
    )
    let line2 = normalizedDocumentNumber + documentNumberCheckDigit +
        nationality +
        dateOfBirth + dateOfBirthCheckDigit +
        gender +
        expiryDate + expiryDateCheckDigit +
        normalizedOptionalData + optionalDataCheckDigit +
        compositeCheckDigit
    return line1 + line2
}

private func mrzCheckDigit(_ value: String) -> String {
    let weights = [7, 3, 1]
    let sum = value.utf8.enumerated().reduce(0) { partial, item in
        let (offset, byte) = item
        return partial + mrzCharacterValue(byte) * weights[offset % weights.count]
    }
    return String(sum % 10)
}

private func mrzCharacterValue(_ byte: UInt8) -> Int {
    switch byte {
    case 0x30...0x39:
        return Int(byte - 0x30)
    case 0x41...0x5A:
        return Int(byte - 0x41) + 10
    case 0x3C:
        return 0
    default:
        return 0
    }
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

private func dataGroup2Fixture(imageDataType: UInt8, imageBytes: [UInt8]) throws -> [UInt8] {
    let biometricHeader = try tlv(tag: [0xA1], value: [0x80, 0x01, 0x01])
    let biometricData = try tlv(tag: [0x5F, 0x2E], value: iso19794FaceRecord(imageDataType: imageDataType, imageBytes: imageBytes))
    let template = try tlv(tag: [0x7F, 0x60], value: biometricHeader + biometricData)
    let body = try tlv(tag: [0x7F, 0x61], value: tlv(tag: [0x02], value: [0x01]) + template)
    return try [UInt8]([0x75]) + toAsn1Length(body.count) + body
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
    imageDataType: UInt8 = 0x00,
    numberOfFacialImages: Int = 1,
    declaredLengthOfRecord: Int? = nil,
    declaredFacialRecordDataLength: Int? = nil,
    imageBytes: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
) -> [UInt8] {
    var record: [UInt8] = []
    record.reserveCapacity(46 + imageBytes.count + max(featurePoints, 0) * 8)
    record += [0x46, 0x41, 0x43, 0x00]
    record += [0x30, 0x31, 0x30, 0x00]
    record += fixedWidthBytes(declaredLengthOfRecord ?? 46 + imageBytes.count, count: 4)
    record += fixedWidthBytes(numberOfFacialImages, count: 2)
    record += fixedWidthBytes(declaredFacialRecordDataLength ?? 46 + imageBytes.count - 14, count: 4)
    record += fixedWidthBytes(featurePoints, count: 2)
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += [0x00, 0x00, 0x00]
    record += Array(repeating: 0x00, count: max(featurePoints, 0) * 8)
    record += [0x00, imageDataType]
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
