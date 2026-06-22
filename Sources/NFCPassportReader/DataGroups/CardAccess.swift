//
//  CardAccess.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation

// SecurityInfos ::= SET of SecurityInfo
// SecurityInfo ::= SEQUENCE {
//    protocol OBJECT IDENTIFIER,
//    requiredData ANY DEFINED BY protocol,
//    optionalData ANY DEFINED BY protocol OPTIONAL
@available(iOS 13, macOS 10.15, *)
class CardAccess {
    public private(set) var securityInfos : [SecurityInfo] = [SecurityInfo]()
    
    var paceInfos: [PACEInfo] {
        securityInfos.compactMap { $0 as? PACEInfo }
    }

    var paceInfo : PACEInfo? {
        get {
            return paceInfos.first
        }
    }
    
    required init( _ data : [UInt8] ) throws {
        securityInfos = try SecurityInfosParser.parse(data)
    }

    func removeSensitiveDataForPrivacy() {
        securityInfos.forEach { $0.removeSensitiveDataForPrivacy() }
        securityInfos.removeAll(keepingCapacity: false)
    }
}
