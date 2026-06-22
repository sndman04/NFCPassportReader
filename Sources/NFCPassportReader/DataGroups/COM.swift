//
//  COM.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class COM : DataGroup {
    public private(set) var version : String = "Unknown"
    public private(set) var unicodeVersion : String = "Unknown"
    public private(set) var dataGroupsPresent : [String] = []

    public override var datagroupType: DataGroupId { .COM }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x5F01)

        // Version is 4 bytes (ascii) - AABB
        // AA is major number, BB is minor number
        // e.g.  48 49 48 55 -> 01 07 -> 1.7
        var versionBytes = try getNextValue()
        guard let parsedVersion = Self.versionString(from: versionBytes, componentWidths: [2, 2]) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        version = parsedVersion

        tag = try getNextTag()
        try verifyTag(tag, equals: 0x5F36)
        
        versionBytes = try getNextValue()
        guard let parsedUnicodeVersion = Self.versionString(from: versionBytes, componentWidths: [2, 2, 2]) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        unicodeVersion = parsedUnicodeVersion
        
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x5C)
        
        let vals = try getNextValue()
        var seenDataGroups = Set<UInt8>()
        for v in vals {
            guard let name = DataGroupParser.tagNameLookup[v] else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            if seenDataGroups.insert(v).inserted {
                dataGroupsPresent.append(name)
            }
        }
    }

    override func removeSensitiveDataForPrivacy() {
        version = "Unknown"
        unicodeVersion = "Unknown"
        dataGroupsPresent.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }

    private static func versionString(from bytes: [UInt8], componentWidths: [Int]) -> String? {
        guard bytes.count == componentWidths.reduce(0, +) else {
            return nil
        }

        var offset = 0
        var components: [String] = []
        components.reserveCapacity(componentWidths.count)
        for width in componentWidths {
            guard let value = decimalValue(bytes[offset ..< offset + width]) else {
                return nil
            }
            components.append(String(value))
            offset += width
        }
        return components.joined(separator: ".")
    }

    private static func decimalValue(_ bytes: ArraySlice<UInt8>) -> Int? {
        var value = 0
        for byte in bytes {
            guard byte >= 0x30, byte <= 0x39 else {
                return nil
            }
            value = (value * 10) + Int(byte - 0x30)
        }
        return value
    }
}
