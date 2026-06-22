//
//  DataGroup1.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum DocTypeEnum: String {
    case TD1
    case TD2
    case OTHER
    
    var desc: String {
        get {
            return self.rawValue
        }
    }
}

@available(iOS 13, macOS 10.15, *)
class DataGroup1 : DataGroup {
    public private(set) var elements : [String:String] = [:]

    public override var datagroupType: DataGroupId { .DG1 }

    private struct TD1DocumentNumberLayout {
        let valueRanges: [Range<Int>]
        let checkDigitIndex: Int
        let optionalDataRange: Range<Int>?
    }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        let tag = try getNextTag()
        try verifyTag(tag, equals: 0x5F1F)
        let body = try getNextValue()
        try validateMRZBytes(body)
        let docType = getMRZType(length:body.count)
        
        switch docType {
            case .TD1:
                try self.parseTd1(body)
            case .TD2:
                try self.parseTd2(body)
            default:
                try self.parseOther(body)
        }
        
        guard let mrz = String(bytes: body, encoding: .utf8) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        // Store MRZ data internally for legacy model projection.
        elements["5F1F"] = mrz
    }

    override func removeSensitiveDataForPrivacy() {
        elements.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }
    
    func parseTd1(_ data : [UInt8]) throws {
        guard data.count == 90 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        let documentNumberLayout = try td1DocumentNumberLayout(data)
        try validateCheckDigit(data, field: 30..<36, checkDigitAt: 36)
        try validateCheckDigit(data, field: 38..<44, checkDigitAt: 44)
        try validateCheckDigit(
            data,
            fieldRanges: [5..<30, 30..<37, 38..<45, 48..<59],
            checkDigitAt: 59
        )
        try validateDateField(data, in: 30..<36)
        try validateDateField(data, in: 38..<44)

        setElement("5F03", from: data, in: 0..<2)
        setElement("5F28", from: data, in: 2..<5)
        elements["5A"] = documentNumberLayout.valueRanges
            .map { string(from: data, in: $0) }
            .joined()
        setElement("5F04", from: data, in: documentNumberLayout.checkDigitIndex ..< documentNumberLayout.checkDigitIndex + 1)
        elements["53"] = string(from: data, in: documentNumberLayout.optionalDataRange) + string(from: data, in: 48..<59)
        setElement("5F57", from: data, in: 30..<36)
        setElement("5F05", from: data, in: 36..<37)
        setElement("5F35", from: data, in: 37..<38)
        setElement("59", from: data, in: 38..<44)
        setElement("5F06", from: data, in: 44..<45)
        setElement("5F2C", from: data, in: 45..<48)
        setElement("5F07", from: data, in: 59..<60)
        setElement("5B", from: data, in: 60..<data.count)
    }
    
    func parseTd2(_ data : [UInt8]) throws {
        guard data.count == 72 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        try validateCheckDigit(data, field: 36..<45, checkDigitAt: 45)
        try validateCheckDigit(data, field: 49..<55, checkDigitAt: 55)
        try validateCheckDigit(data, field: 57..<63, checkDigitAt: 63)
        try validateCheckDigit(
            data,
            fieldRanges: [36..<46, 49..<56, 57..<71],
            checkDigitAt: 71
        )
        try validateDateField(data, in: 49..<55)
        try validateDateField(data, in: 57..<63)

        setElement("5F03", from: data, in: 0..<2)
        setElement("5F28", from: data, in: 2..<5)
        setElement("5B", from: data, in: 5..<36)
        setElement("5A", from: data, in: 36..<45)
        setElement("5F04", from: data, in: 45..<46)
        setElement("5F2C", from: data, in: 46..<49)
        setElement("5F57", from: data, in: 49..<55)
        setElement("5F05", from: data, in: 55..<56)
        setElement("5F35", from: data, in: 56..<57)
        setElement("59", from: data, in: 57..<63)
        setElement("5F06", from: data, in: 63..<64)
        setElement("53", from: data, in: 64..<71)
        setElement("5F07", from: data, in: 71..<72)
    }
    
    func parseOther(_ data : [UInt8]) throws {
        guard data.count == 88 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        try validateCheckDigit(data, field: 44..<53, checkDigitAt: 53)
        try validateCheckDigit(data, field: 57..<63, checkDigitAt: 63)
        try validateCheckDigit(data, field: 65..<71, checkDigitAt: 71)
        try validateCheckDigit(data, field: 72..<86, checkDigitAt: 86)
        try validateCheckDigit(
            data,
            fieldRanges: [44..<54, 57..<64, 65..<87],
            checkDigitAt: 87
        )
        try validateDateField(data, in: 57..<63)
        try validateDateField(data, in: 65..<71)

        setElement("5F03", from: data, in: 0..<2)
        setElement("5F28", from: data, in: 2..<5)
        setElement("5B", from: data, in: 5..<44)
        setElement("5A", from: data, in: 44..<53)
        setElement("5F04", from: data, in: 53..<54)
        setElement("5F2C", from: data, in: 54..<57)
        setElement("5F57", from: data, in: 57..<63)
        setElement("5F05", from: data, in: 63..<64)
        setElement("5F35", from: data, in: 64..<65)
        setElement("59", from: data, in: 65..<71)
        setElement("5F06", from: data, in: 71..<72)
        setElement("53", from: data, in: 72..<86)
        setElement("5F02", from: data, in: 86..<87)
        setElement("5F07", from: data, in: 87..<88)
    }

    private func setElement(_ key: String, from data: [UInt8], in range: Range<Int>) {
        elements[key] = string(from: data, in: range)
    }

    private func string(from data: [UInt8], in range: Range<Int>) -> String {
        String(bytes: data[range], encoding: .utf8) ?? ""
    }

    private func string(from data: [UInt8], in range: Range<Int>?) -> String {
        guard let range = range else {
            return ""
        }

        return string(from: data, in: range)
    }

    private func validateMRZBytes(_ data: [UInt8]) throws {
        guard data.allSatisfy(Self.isValidMRZByte) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
    }

    private static func isValidMRZByte(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x30...0x39, 0x41...0x5A, 0x3C:
            return true
        default:
            return false
        }
    }

    private func validateDateField(_ data: [UInt8], in range: Range<Int>) throws {
        guard data[range].allSatisfy({ byte in byte >= 0x30 && byte <= 0x39 }),
              Self.isValidMRZDate(Array(data[range])) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
    }

    private func td1DocumentNumberLayout(_ data: [UInt8]) throws -> TD1DocumentNumberLayout {
        guard data.count == 90 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        if data[14] != 0x3C {
            try validateCheckDigit(data, field: 5..<14, checkDigitAt: 14)
            return TD1DocumentNumberLayout(
                valueRanges: [5..<14],
                checkDigitIndex: 14,
                optionalDataRange: 15..<30
            )
        }

        for checkDigitIndex in 16...28 {
            guard data[checkDigitIndex + 1] == 0x3C,
                  let expected = Self.checkDigit(for: Array(data[5..<14]) + Array(data[15..<checkDigitIndex])),
                  let actual = Self.mrzDigitValue(data[checkDigitIndex]),
                  expected == actual else {
                continue
            }

            let optionalDataRange = td1UpperLineOptionalDataRange(afterLongDocumentNumberMarkerAt: checkDigitIndex + 1, data)
            return TD1DocumentNumberLayout(
                valueRanges: [5..<14, 15..<checkDigitIndex],
                checkDigitIndex: checkDigitIndex,
                optionalDataRange: optionalDataRange
            )
        }

        throw NFCPassportReaderError.InvalidASN1Structure
    }

    private func td1UpperLineOptionalDataRange(afterLongDocumentNumberMarkerAt markerIndex: Int, _ data: [UInt8]) -> Range<Int>? {
        let startIndex = markerIndex + 1
        guard startIndex < 30 else {
            return nil
        }

        let range = startIndex..<30
        guard data[range].contains(where: { $0 != 0x3C }) else {
            return nil
        }

        return range
    }

    private static func isValidMRZDate(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == 6,
              let year = Int(String(decoding: bytes[0 ..< 2], as: UTF8.self)),
              let month = Int(String(decoding: bytes[2 ..< 4], as: UTF8.self)),
              let day = Int(String(decoding: bytes[4 ..< 6], as: UTF8.self)),
              (1...12).contains(month) else {
            return false
        }

        let daysInMonth: Int
        switch month {
        case 2:
            daysInMonth = year.isMultiple(of: 4) ? 29 : 28
        case 4, 6, 9, 11:
            daysInMonth = 30
        default:
            daysInMonth = 31
        }

        return (1...daysInMonth).contains(day)
    }

    private func validateCheckDigit(_ data: [UInt8], field: Range<Int>, checkDigitAt index: Int) throws {
        try validateCheckDigit(data, fieldRanges: [field], checkDigitAt: index)
    }

    private func validateCheckDigit(_ data: [UInt8], fieldRanges: [Range<Int>], checkDigitAt index: Int) throws {
        guard index < data.count,
              let expected = Self.checkDigit(for: fieldRanges.flatMap({ data[$0] })),
              let actual = Self.mrzDigitValue(data[index]),
              expected == actual else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
    }

    private static func checkDigit<T: Collection>(for bytes: T) -> Int? where T.Element == UInt8 {
        let weights = [7, 3, 1]
        var sum = 0
        for (offset, byte) in bytes.enumerated() {
            guard let value = mrzCharacterValue(byte) else {
                return nil
            }
            sum += value * weights[offset % weights.count]
        }
        return sum % 10
    }

    private static func mrzCharacterValue(_ byte: UInt8) -> Int? {
        switch byte {
        case 0x30...0x39:
            return Int(byte - 0x30)
        case 0x41...0x5A:
            return Int(byte - 0x41) + 10
        case 0x3C:
            return 0
        default:
            return nil
        }
    }

    private static func mrzDigitValue(_ byte: UInt8) -> Int? {
        guard byte >= 0x30 && byte <= 0x39 else {
            return nil
        }
        return Int(byte - 0x30)
    }
    
    private func getMRZType(length: Int) -> DocTypeEnum {
        if length == 0x5A {
            return .TD1
        }
        if length == 0x48 {
            return .TD2
        }
        return .OTHER
    }
    
}
