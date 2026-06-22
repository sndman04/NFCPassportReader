//
//  DataGroup.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class DataGroup {
    var datagroupType : DataGroupId { .Unknown }
    
    /// Body contains the actual data
    public private(set) var body : [UInt8] = []
    
    /// Data contains the whole DataGroup data (as that is what the hash is calculated from
    public private(set) var data : [UInt8] = []
    
    var pos = 0
    private var bodyEnd = 0
    
    required init( _ data : [UInt8] ) throws {
        self.data = data
        
        // Skip the first byte which is the header byte
        pos = 1
        let bodyLength = try getNextLength()
        guard bodyLength >= 0,
              pos + bodyLength <= data.count else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        bodyEnd = pos + bodyLength
        self.body = [UInt8](data[pos..<bodyEnd])
        self.data = [UInt8](data[..<bodyEnd])
        
        try parse(self.data)
    }

    var hasUnreadBody: Bool {
        pos < bodyEnd
    }
    
    func parse( _ data:[UInt8] ) throws {
    }

    func removeSensitiveDataForPrivacy() {
        body.removeAll(keepingCapacity: false)
        data.removeAll(keepingCapacity: false)
        pos = 0
        bodyEnd = 0
    }
    
    func getNextTag() throws -> Int {
        var tag = 0
        
        // Fix for some passports that may have invalid data - ensure that we do have data!
        guard bodyEnd > pos else {
            throw NFCPassportReaderError.TagNotValid
        }

        if data[pos] & 0x1F == 0x1F {
            guard pos + 1 < bodyEnd else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }

            tag = (Int(data[pos]) << 8) | Int(data[pos + 1])
            pos += 2
        } else {
            tag = Int(data[pos])
            pos += 1
        }
        return tag
    }
    
    func getNextLength() throws -> Int  {
        guard pos < data.count else {
            throw NFCPassportReaderError.CannotDecodeASN1Length
        }

        let limit = bodyEnd == 0 ? data.count : bodyEnd
        let end = pos+5 < limit ? pos+5 : limit
        let (len, lenOffset) = try asn1Length(data[pos..<end])
        pos += lenOffset
        return len
    }
    
    func getNextValue() throws -> [UInt8] {
        let length = try getNextLength()
        guard length >= 0,
              pos + length <= bodyEnd else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        let value = [UInt8](data[pos ..< pos+length])
        pos += length
        return value
    }
    
    func hash( _ hashAlgorythm: String ) -> [UInt8]  {
        switch hashAlgorythm {
        case "SHA1":
            return calcSHA1Hash(self.data)
        case "SHA224":
            return calcSHA224Hash(self.data)
        case "SHA256":
            return calcSHA256Hash(self.data)
        case "SHA384":
            return calcSHA384Hash(self.data)
        case "SHA512":
            return calcSHA512Hash(self.data)
        default:
            return []
        }
    }

    func verifyTag(_ tag: Int, equals expectedTag: Int) throws {
        if tag != expectedTag  {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: expectedTag,
                actualTag: tag
            )
        }
    }

    func verifyTag(_ tag: Int, oneOf expectedTags: [Int]) throws {
        guard let firstExpectedTag = expectedTags.first else {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: 0,
                actualTag: tag
            )
        }

        if !expectedTags.contains(tag) {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: firstExpectedTag,
                actualTag: tag
            )
        }
    }

    func parseTagList(_ value: [UInt8], allowTrailingIncompleteTag: Bool = false) throws -> Set<Int> {
        var offset = 0
        var tags = Set<Int>()

        while offset < value.count {
            let first = value[offset]
            offset += 1

            if first & 0x1F == 0x1F {
                guard offset < value.count else {
                    if allowTrailingIncompleteTag {
                        return tags
                    }
                    throw NFCPassportReaderError.InvalidASN1Structure
                }

                let second = value[offset]
                offset += 1
                tags.insert((Int(first) << 8) | Int(second))
            } else {
                tags.insert(Int(first))
            }
        }

        return tags
    }
}
