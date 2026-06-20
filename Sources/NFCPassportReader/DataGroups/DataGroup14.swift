//
//  DataGroup14.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

// SecurityInfos ::= SET of SecurityInfo
// SecurityInfo ::= SEQUENCE {
//    protocol OBJECT IDENTIFIER,
//    requiredData ANY DEFINED BY protocol,
//    optionalData ANY DEFINED BY protocol OPTIONAL
@available(iOS 13, macOS 10.15, *)
class DataGroup14 : DataGroup {
    public private(set) var securityInfos : [SecurityInfo] = [SecurityInfo]()

    public override var datagroupType: DataGroupId { .DG14 }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        securityInfos = try SecurityInfosParser.parse(body)
    }

    override func removeSensitiveDataForPrivacy() {
        securityInfos.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }
}
