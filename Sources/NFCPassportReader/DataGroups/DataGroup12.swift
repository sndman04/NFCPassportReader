//
//  DataGroup12.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class DataGroup12 : DataGroup {
    private static let maxTextValueLength = 64 * 1024
    private static let maxNestedTagLength = 4
    private static let maxImageDataLength = 10 * 1024 * 1024
    private static let jpegHeader: [UInt8] = [0xff, 0xd8, 0xff]
    private static let jpeg2000BitmapHeader: [UInt8] = [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a]
    private static let jpeg2000CodestreamBitmapHeader: [UInt8] = [0xff, 0x4f, 0xff, 0x51]

    public private(set) var issuingAuthority : String?
    public private(set) var dateOfIssue : String?
    public private(set) var otherPersonsDetails : String?
    public private(set) var endorsementsOrObservations : String?
    public private(set) var taxOrExitRequirements : String?
    public private(set) var frontImage : [UInt8]?
    public private(set) var rearImage : [UInt8]?
    public private(set) var personalizationTime : String?
    public private(set) var personalizationDeviceSerialNr : String?

    public override var datagroupType: DataGroupId { .DG12 }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }

    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x5C)

        let tagList = try getNextValue()
        let declaredTags = try parseTagList(tagList, allowTrailingIncompleteTag: !hasUnreadBody)
        
        while hasUnreadBody {
            tag = try getNextTag()
            guard declaredTags.contains(tag) else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }

            let val = try getNextValue()
            
            switch tag {
            case 0x5F19:
                issuingAuthority = try decodeTextValue(val)
            case 0x5F26:
                dateOfIssue = try parseDateOfIssue(value: val)
            case 0xA0:
                otherPersonsDetails = try parseOtherPersonsDetails(value: val)
            case 0x5F1B:
                endorsementsOrObservations = try decodeTextValue(val)
            case 0x5F1C:
                taxOrExitRequirements = try decodeTextValue(val)
            case 0x5F1D:
                frontImage = try validatedImageData(val)
            case 0x5F1E:
                rearImage = try validatedImageData(val)
            case 0x5F55:
                personalizationTime = try decodeTextValue(val)
            case 0x5F56:
                personalizationDeviceSerialNr = try decodeTextValue(val)
            default:
                break
            }
        }
    }

    override func removeSensitiveDataForPrivacy() {
        issuingAuthority = nil
        dateOfIssue = nil
        otherPersonsDetails = nil
        endorsementsOrObservations = nil
        taxOrExitRequirements = nil
        frontImage?.removeAll(keepingCapacity: false)
        rearImage?.removeAll(keepingCapacity: false)
        frontImage = nil
        rearImage = nil
        personalizationTime = nil
        personalizationDeviceSerialNr = nil
        super.removeSensitiveDataForPrivacy()
    }
    
    private func parseDateOfIssue(value: [UInt8]) throws -> String? {
        if value.count == 4 {
            return try decodeBCD(value: value)
        } else {
            return try decodeASCII(value: value)
        }
    }
    
    private func decodeASCII(value: [UInt8]) throws -> String? {
        return try LDSDateDecoder.decodeEightDigitDate(value)
    }
    
    private func decodeBCD(value: [UInt8]) throws -> String? {
        var digits = ""
        digits.reserveCapacity(value.count * 2)
        for byte in value {
            let high = byte >> 4
            let low = byte & 0x0F
            guard high <= 9, low <= 9 else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            digits.append(String(high))
            digits.append(String(low))
        }
        return try LDSDateDecoder.decodeEightDigitDate(Array(digits.utf8))
    }

    private func parseOtherPersonsDetails(value: [UInt8]) throws -> String? {
        try validateTextLength(value)

        if let nestedValues = decodeNestedTextValues(value), !nestedValues.isEmpty {
            return nestedValues.joined(separator: "\n")
        }

        let decoded = try decodeTextValue(value).trimmingCharacters(in: .whitespacesAndNewlines)
        return decoded.isEmpty ? nil : decoded
    }

    private func decodeTextValue(_ value: [UInt8]) throws -> String {
        try validateTextLength(value)
        return LDSStringDecoder.decode(value)
    }

    private func validateTextLength(_ value: [UInt8]) throws {
        guard value.count <= Self.maxTextValueLength else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
    }

    private func validatedImageData(_ data: [UInt8]) throws -> [UInt8] {
        guard data.isEmpty || Self.canDecodeImageData(data) else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        return data
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

    private func decodeNestedTextValues(_ value: [UInt8], depth: Int = 0) -> [String]? {
        guard !value.isEmpty, depth < 4 else {
            return nil
        }

        var pos = 0
        var decodedValues: [String] = []

        while pos < value.count {
            guard let tag = readTLVTag(value, position: &pos),
                  let length = readTLVLength(value, position: &pos),
                  length >= 0,
                  length <= value.count - pos else {
                return nil
            }

            let itemValue = [UInt8](value[pos ..< pos + length])
            pos += length

            if tag.isConstructed {
                if let nested = decodeNestedTextValues(itemValue, depth: depth + 1) {
                    decodedValues.append(contentsOf: nested)
                }
            } else {
                let decoded = LDSStringDecoder.decode(itemValue).trimmingCharacters(in: .whitespacesAndNewlines)
                if !decoded.isEmpty {
                    decodedValues.append(decoded)
                }
            }
        }

        return pos == value.count ? decodedValues : nil
    }

    private func readTLVTag(_ value: [UInt8], position: inout Int) -> [UInt8]? {
        guard position < value.count else {
            return nil
        }

        var tag = [value[position]]
        position += 1

        if tag[0] & 0x1F == 0x1F {
            repeat {
                guard position < value.count else {
                    return nil
                }
                let next = value[position]
                tag.append(next)
                position += 1
                guard tag.count <= Self.maxNestedTagLength else {
                    return nil
                }
                if next & 0x80 == 0 {
                    break
                }
            } while true
        }

        return tag
    }

    private func readTLVLength(_ value: [UInt8], position: inout Int) -> Int? {
        guard position < value.count else {
            return nil
        }

        let end = min(position + 5, value.count)
        do {
            let (length, offset) = try asn1Length(value[position ..< end])
            position += offset
            return length
        } catch {
            return nil
        }
    }
}

private extension Array where Element == UInt8 {
    var isConstructed: Bool {
        first.map { $0 & 0x20 == 0x20 } ?? false
    }
}
