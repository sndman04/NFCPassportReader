//
//  DataGroup2.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
class DataGroup2 : DataGroup {
    private static let maxImageDataLength = 10 * 1024 * 1024
    private static let maxImageDimension = 20_000
    private static let maxFeaturePoints = 10_000
    private static let jpegHeader: [UInt8] = [0xff, 0xd8, 0xff]
    private static let jpeg2000BitmapHeader: [UInt8] = [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a]
    private static let jpeg2000CodestreamBitmapHeader: [UInt8] = [0xff, 0x4f, 0xff, 0x51]

    public private(set) var nrImages : Int = 0
    public private(set) var versionNumber : Int = 0
    public private(set) var lengthOfRecord : Int = 0
    public private(set) var numberOfFacialImages : Int = 0
    public private(set) var facialRecordDataLength : Int = 0
    public private(set) var nrFeaturePoints : Int = 0
    public private(set) var gender : Int = 0
    public private(set) var eyeColor : Int = 0
    public private(set) var hairColor : Int = 0
    public private(set) var featureMask : Int = 0
    public private(set) var expression : Int = 0
    public private(set) var poseAngle : Int = 0
    public private(set) var poseAngleUncertainty : Int = 0
    public private(set) var faceImageType : Int = 0
    public private(set) var imageDataType : Int = 0
    public private(set) var imageWidth : Int = 0
    public private(set) var imageHeight : Int = 0
    public private(set) var imageColorSpace : Int = 0
    public private(set) var sourceType : Int = 0
    public private(set) var deviceType : Int = 0
    public private(set) var quality : Int = 0
    public private(set) var imageData : [UInt8] = []
    public private(set) var imageDataItems : [[UInt8]] = []

    public override var datagroupType: DataGroupId { .DG2 }

#if !os(macOS)
    func getImage() -> UIImage? {
        guard Self.canDecodeImageData(imageData) else {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }

    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F61)
        _ = try getNextLength()
        
        // Tag should be 0x02
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        let imageCount = try getNextValue()
        guard let firstImageCountByte = imageCount.first else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        nrImages = Int(firstImageCountByte)
        
        guard nrImages > 0 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        var parsedTemplateCount = 0
        while hasUnreadBody {
            try parseBiometricInformationTemplate()
            parsedTemplateCount += 1
        }

        guard parsedTemplateCount == nrImages else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
    }

    override func removeSensitiveDataForPrivacy() {
        nrImages = 0
        versionNumber = 0
        lengthOfRecord = 0
        numberOfFacialImages = 0
        facialRecordDataLength = 0
        nrFeaturePoints = 0
        gender = 0
        eyeColor = 0
        hairColor = 0
        featureMask = 0
        expression = 0
        poseAngle = 0
        poseAngleUncertainty = 0
        faceImageType = 0
        imageDataType = 0
        imageWidth = 0
        imageHeight = 0
        imageColorSpace = 0
        sourceType = 0
        deviceType = 0
        quality = 0
        imageData.removeAll(keepingCapacity: false)
        imageDataItems.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }

    private func parseBiometricInformationTemplate() throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F60)
        _ = try getNextLength()

        // Next tag is 0xA1 (Biometric Header Template) - don't care about this
        tag = try getNextTag()
        try verifyTag(tag, equals: 0xA1)
        _ = try getNextValue()

        // Now we get to the good stuff - next tag is either 5F2E or 7F2E
        tag = try getNextTag()
        try verifyTag(tag, oneOf: [0x5F2E, 0x7F2E])
        let value = try getNextValue()

        try parseISO19794_5(data: value)
    }
    
    func parseISO19794_5( data : [UInt8] ) throws {
        // Validate header - 'F', 'A' 'C' 0x00 - 0x46414300
        guard data.count >= 46 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        if data[0] != 0x46 || data[1] != 0x41 || data[2] != 0x43 || data[3] != 0x00 {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: 0x46,
                actualTag: Int(data[0])
            )
        }
        
        var offset = 4
        let parsedVersionNumber = try readInteger(from: data, offset: &offset, byteCount: 4)
        let parsedLengthOfRecord = try readInteger(from: data, offset: &offset, byteCount: 4)
        let parsedNumberOfFacialImages = try readInteger(from: data, offset: &offset, byteCount: 2)

        guard parsedLengthOfRecord == data.count else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        guard parsedNumberOfFacialImages > 0,
              parsedNumberOfFacialImages <= 32 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        if parsedNumberOfFacialImages > 1,
           try parseMultipleFacialRecordsIfPossible(
            data: data,
            offset: offset,
            versionNumber: parsedVersionNumber,
            lengthOfRecord: parsedLengthOfRecord,
            numberOfFacialImages: parsedNumberOfFacialImages
           ) {
            return
        }

        let recordStart = offset
        var lengthOffset = offset
        let facialRecordDataLength = try readInteger(from: data, offset: &lengthOffset, byteCount: 4)
        let remainingDataLength = data.count - recordStart
        guard facialRecordDataLength >= 32,
              facialRecordDataLength <= remainingDataLength,
              facialRecordDataLength == remainingDataLength else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        let recordEnd = recordStart + facialRecordDataLength

        let record = try parseFacialRecord(
            data: data,
            offset: &offset,
            recordEnd: recordEnd,
            versionNumber: parsedVersionNumber,
            lengthOfRecord: parsedLengthOfRecord,
            numberOfFacialImages: parsedNumberOfFacialImages
        )
        append(record)
    }

    private func parseMultipleFacialRecordsIfPossible(
        data: [UInt8],
        offset startingOffset: Int,
        versionNumber: Int,
        lengthOfRecord: Int,
        numberOfFacialImages: Int
    ) throws -> Bool {
        var parsedRecords: [ParsedFacialRecord] = []
        parsedRecords.reserveCapacity(numberOfFacialImages)
        var offset = startingOffset

        for _ in 0..<numberOfFacialImages {
            let recordStart = offset
            var lengthOffset = offset
            let facialRecordDataLength = try readInteger(from: data, offset: &lengthOffset, byteCount: 4)
            guard facialRecordDataLength >= 32,
                  recordStart + facialRecordDataLength <= data.count else {
                return false
            }

            let record = try parseFacialRecord(
                data: data,
                offset: &offset,
                recordEnd: recordStart + facialRecordDataLength,
                versionNumber: versionNumber,
                lengthOfRecord: lengthOfRecord,
                numberOfFacialImages: numberOfFacialImages
            )
            parsedRecords.append(record)
        }

        guard offset == data.count else {
            return false
        }

        parsedRecords.forEach { append($0) }
        return true
    }

    private func parseFacialRecord(
        data: [UInt8],
        offset: inout Int,
        recordEnd: Int,
        versionNumber: Int,
        lengthOfRecord: Int,
        numberOfFacialImages: Int
    ) throws -> ParsedFacialRecord {
        let parsedFacialRecordDataLength = try readInteger(from: data, offset: &offset, byteCount: 4)
        let parsedFeaturePoints = try readInteger(from: data, offset: &offset, byteCount: 2)
        let parsedGender = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedEyeColor = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedHairColor = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedFeatureMask = try readInteger(from: data, offset: &offset, byteCount: 3)
        let parsedExpression = try readInteger(from: data, offset: &offset, byteCount: 2)
        let parsedPoseAngle = try readInteger(from: data, offset: &offset, byteCount: 3)
        let parsedPoseAngleUncertainty = try readInteger(from: data, offset: &offset, byteCount: 3)
        
        // Features (not handled). There shouldn't be any but if for some reason there were,
        // then we are going to skip over them
        // The Feature block is 8 bytes
        guard parsedFeaturePoints <= Self.maxFeaturePoints,
              parsedFeaturePoints <= (recordEnd - offset) / 8 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        offset += parsedFeaturePoints * 8

        guard recordEnd >= offset + 12 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        
        let parsedFaceImageType = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedImageDataType = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedImageWidth = try readInteger(from: data, offset: &offset, byteCount: 2)
        let parsedImageHeight = try readInteger(from: data, offset: &offset, byteCount: 2)
        let parsedImageColorSpace = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedSourceType = try readInteger(from: data, offset: &offset, byteCount: 1)
        let parsedDeviceType = try readInteger(from: data, offset: &offset, byteCount: 2)
        let parsedQuality = try readInteger(from: data, offset: &offset, byteCount: 2)

        guard parsedImageWidth <= Self.maxImageDimension,
              parsedImageHeight <= Self.maxImageDimension else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        
        guard recordEnd > offset else {
            throw NFCPassportReaderError.UnknownImageFormat
        }

        let imageBytes = data[offset..<recordEnd]
        guard Self.canDecodeImageData(imageBytes) else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        
        offset = recordEnd
        return ParsedFacialRecord(
            versionNumber: versionNumber,
            lengthOfRecord: lengthOfRecord,
            numberOfFacialImages: numberOfFacialImages,
            facialRecordDataLength: parsedFacialRecordDataLength,
            nrFeaturePoints: parsedFeaturePoints,
            gender: parsedGender,
            eyeColor: parsedEyeColor,
            hairColor: parsedHairColor,
            featureMask: parsedFeatureMask,
            expression: parsedExpression,
            poseAngle: parsedPoseAngle,
            poseAngleUncertainty: parsedPoseAngleUncertainty,
            faceImageType: parsedFaceImageType,
            imageDataType: parsedImageDataType,
            imageWidth: parsedImageWidth,
            imageHeight: parsedImageHeight,
            imageColorSpace: parsedImageColorSpace,
            sourceType: parsedSourceType,
            deviceType: parsedDeviceType,
            quality: parsedQuality,
            imageData: Array(imageBytes)
        )
    }

    private func append(_ record: ParsedFacialRecord) {
        if imageDataItems.isEmpty {
            versionNumber = record.versionNumber
            lengthOfRecord = record.lengthOfRecord
            numberOfFacialImages = record.numberOfFacialImages
            facialRecordDataLength = record.facialRecordDataLength
            nrFeaturePoints = record.nrFeaturePoints
            gender = record.gender
            eyeColor = record.eyeColor
            hairColor = record.hairColor
            featureMask = record.featureMask
            expression = record.expression
            poseAngle = record.poseAngle
            poseAngleUncertainty = record.poseAngleUncertainty
            faceImageType = record.faceImageType
            imageDataType = record.imageDataType
            imageWidth = record.imageWidth
            imageHeight = record.imageHeight
            imageColorSpace = record.imageColorSpace
            sourceType = record.sourceType
            deviceType = record.deviceType
            quality = record.quality
            imageData = record.imageData
        }
        imageDataItems.append(record.imageData)
    }

    private func readInteger(from data: [UInt8], offset: inout Int, byteCount: Int) throws -> Int {
        guard byteCount > 0,
              offset + byteCount <= data.count else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        var value = 0
        for byte in data[offset ..< offset + byteCount] {
            value = (value << 8) | Int(byte)
        }
        offset += byteCount
        return value
    }

    private static func canDecodeImageData<T: Collection>(_ data: T) -> Bool where T.Element == UInt8 {
        data.count > 0 &&
            data.count <= maxImageDataLength &&
            (
                data.starts(with: jpegHeader) ||
                data.starts(with: jpeg2000BitmapHeader) ||
                data.starts(with: jpeg2000CodestreamBitmapHeader)
            )
    }

    private struct ParsedFacialRecord {
        let versionNumber: Int
        let lengthOfRecord: Int
        let numberOfFacialImages: Int
        let facialRecordDataLength: Int
        let nrFeaturePoints: Int
        let gender: Int
        let eyeColor: Int
        let hairColor: Int
        let featureMask: Int
        let expression: Int
        let poseAngle: Int
        let poseAngleUncertainty: Int
        let faceImageType: Int
        let imageDataType: Int
        let imageWidth: Int
        let imageHeight: Int
        let imageColorSpace: Int
        let sourceType: Int
        let deviceType: Int
        let quality: Int
        let imageData: [UInt8]
    }
}
