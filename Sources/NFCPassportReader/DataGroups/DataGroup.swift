//
//  DataGroup.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup {
    public var datagroupType : DataGroupId { .Unknown }
    
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
    
    public func hash( _ hashAlgorythm: String ) -> [UInt8]  {
        var ret : [UInt8] = []
        if hashAlgorythm == "SHA1" {
            ret = calcSHA1Hash(self.data)
        } else if hashAlgorythm == "SHA224" {
            ret = calcSHA224Hash(self.data)
        } else if hashAlgorythm == "SHA256" {
            ret = calcSHA256Hash(self.data)
        } else if hashAlgorythm == "SHA384" {
            ret = calcSHA384Hash(self.data)
        } else if hashAlgorythm == "SHA512" {
            ret = calcSHA512Hash(self.data)
        }
        
        return ret
    }

    public func verifyTag(_ tag: Int, equals expectedTag: Int) throws {
        if tag != expectedTag  {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: expectedTag,
                actualTag: tag
            )
        }
    }

    public func verifyTag(_ tag: Int, oneOf expectedTags: [Int]) throws {
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
}
