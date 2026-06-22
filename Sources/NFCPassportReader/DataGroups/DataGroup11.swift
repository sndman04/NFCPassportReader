//
//  DataGroup11.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class DataGroup11 : DataGroup {
    private static let maxTextValueLength = 64 * 1024

    
    public private(set) var fullName : String?
    public private(set) var personalNumber : String?
    public private(set) var dateOfBirth : String?
    public private(set) var placeOfBirth : String?
    public private(set) var address : String?
    public private(set) var telephone : String?
    public private(set) var profession : String?
    public private(set) var title : String?
    public private(set) var personalSummary : String?
    public private(set) var proofOfCitizenship : String?
    public private(set) var tdNumbers : String?
    public private(set) var custodyInfo : String?

    public override var datagroupType: DataGroupId { .DG11 }

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

            let value = try getNextValue()
            switch tag {
            case 0x5F0E:
                fullName = try decodeTextValue(value)
            case 0x5F10:
                personalNumber = try decodeTextValue(value)
            case 0x5F11:
                placeOfBirth = try decodeTextValue(value)
            case 0x5F2B:
                dateOfBirth = try LDSDateDecoder.decodeEightDigitDate(value)
            case 0x5F42:
                address = try decodeTextValue(value)
            case 0x5F12:
                telephone = try decodeTextValue(value)
            case 0x5F13:
                profession = try decodeTextValue(value)
            case 0x5F14:
                title = try decodeTextValue(value)
            case 0x5F15:
                personalSummary = try decodeTextValue(value)
            case 0x5F16:
                proofOfCitizenship = try decodeTextValue(value)
            case 0x5F17:
                tdNumbers = try decodeTextValue(value)
            case 0x5F18:
                custodyInfo = try decodeTextValue(value)
            default:
                break
            }
        }
    }

    override func removeSensitiveDataForPrivacy() {
        fullName = nil
        personalNumber = nil
        dateOfBirth = nil
        placeOfBirth = nil
        address = nil
        telephone = nil
        profession = nil
        title = nil
        personalSummary = nil
        proofOfCitizenship = nil
        tdNumbers = nil
        custodyInfo = nil
        super.removeSensitiveDataForPrivacy()
    }

    private func decodeTextValue(_ value: [UInt8]) throws -> String {
        guard value.count <= Self.maxTextValueLength else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        return LDSStringDecoder.decode(value)
    }
}
