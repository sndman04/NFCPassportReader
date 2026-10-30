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
        let parameters = securityInfos.compactMap { $0 as? PACEDomainParameterInfo }
        guard parameters.count <= 1 || parameters.allSatisfy({ $0.parameterId != nil }) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        for (index, value) in parameters.enumerated() {
            if parameters.contains(where: { $0 !== value && $0.parameterId == nil && $0.oid == value.oid }) {
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            for previous in parameters.prefix(index) where previous.parameterId == value.parameterId {
                guard previous.encodedParameters == value.encodedParameters else {
                    throw NFCPassportReaderError.InvalidASN1Structure
                }
            }
        }
        for info in paceInfos where info.parameterId == nil || (info.parameterId ?? 0) >= 32 {
            let protocolOID = info.oid.split(separator: ".").dropLast().joined(separator: ".")
            let matches = parameters.filter { $0.oid == protocolOID && $0.parameterId == info.parameterId }
            if let match = matches.first { info.resolvedStandardParameterId = match.standardParameterId }
        }
    }

    func removeSensitiveDataForPrivacy() {
        securityInfos.forEach { $0.removeSensitiveDataForPrivacy() }
        securityInfos.removeAll(keepingCapacity: false)
    }
}
