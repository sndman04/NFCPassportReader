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
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        let tag = try getNextTag()
        try verifyTag(tag, equals: 0x5F1F)
        let body = try getNextValue()
        let docType = getMRZType(length:body.count)
        
        switch docType {
            case .TD1:
                try self.parseTd1(body)
            case .TD2:
                try self.parseTd2(body)
            default:
                try self.parseOther(body)
        }
        
        // Store MRZ data
        elements["5F1F"] = String(bytes: body, encoding:.utf8)
    }

    override func removeSensitiveDataForPrivacy() {
        elements.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }
    
    func parseTd1(_ data : [UInt8]) throws {
        guard data.count == 90 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        setElement("5F03", from: data, in: 0..<2)
        setElement("5F28", from: data, in: 2..<5)
        setElement("5A", from: data, in: 5..<14)
        setElement("5F04", from: data, in: 14..<15)
        elements["53"] = string(from: data, in: 15..<30) + string(from: data, in: 48..<59)
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
