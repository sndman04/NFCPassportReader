//
//  DataGroup12.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class DataGroup12 : DataGroup {
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

        // Skip the taglist - ideally we would check this but...
        let _ = try getNextValue()
        
        while hasUnreadBody {
            tag = try getNextTag()
            let val = try getNextValue()
            
            if tag == 0x5F19 {
                issuingAuthority = LDSStringDecoder.decode(val)
            } else if tag == 0x5F26 {
                dateOfIssue = parseDateOfIssue(value: val)
            } else if tag == 0xA0 {
                otherPersonsDetails = parseOtherPersonsDetails(value: val)
            } else if tag == 0x5F1B {
                endorsementsOrObservations = LDSStringDecoder.decode(val)
            } else if tag == 0x5F1C {
                taxOrExitRequirements = LDSStringDecoder.decode(val)
            } else if tag == 0x5F1D {
                frontImage = val
            } else if tag == 0x5F1E {
                rearImage = val
            } else if tag == 0x5F55 {
                personalizationTime = LDSStringDecoder.decode(val)
            } else if tag == 0x5F56 {
                personalizationDeviceSerialNr = LDSStringDecoder.decode(val)
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
    
    private func parseDateOfIssue(value: [UInt8]) -> String? {
        if value.count == 4 {
            return decodeBCD(value: value)
        } else {
            return decodeASCII(value: value)
        }
    }
    
    private func decodeASCII(value: [UInt8]) -> String? {
        return LDSStringDecoder.decode(value)
    }
    
    private func decodeBCD(value: [UInt8]) -> String? {
        binToHexRep(value)
    }

    private func parseOtherPersonsDetails(value: [UInt8]) -> String? {
        if let nestedValues = decodeNestedTextValues(value), !nestedValues.isEmpty {
            return nestedValues.joined(separator: "\n")
        }

        let decoded = LDSStringDecoder.decode(value).trimmingCharacters(in: .whitespacesAndNewlines)
        return decoded.isEmpty ? nil : decoded
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
                  pos + length <= value.count else {
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
