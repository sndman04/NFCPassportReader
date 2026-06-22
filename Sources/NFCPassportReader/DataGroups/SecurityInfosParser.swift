//
//  SecurityInfosParser.swift
//  NFCPassportReader
//
//  Created for shared SecurityInfos parsing.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum SecurityInfosParser {
    private static let idSignedData = "1.2.840.113549.1.7.2"

    static func parse(_ data: [UInt8]) throws -> [SecurityInfo] {
        let root = try SimpleASN1Node.parse(data)
        guard root.tag == 0x31 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        var securityInfos: [SecurityInfo] = []

        for child in root.children {
            guard child.tag == 0x30 else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }

            guard child.children.count == 2 || child.children.count == 3,
                  let oidNode = child.children.first,
                  let requiredData = child.children.dropFirst().first,
                  let oid = oidNode.objectIdentifier else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }

            let optionalData = child.children.dropFirst(2).first
            if let secInfo = try SecurityInfo.getInstance(
                oid: oid,
                requiredData: requiredData,
                requiredDataDER: requiredData.encodedBytes,
                optionalData: optionalData
            ) {
                securityInfos.append(secInfo)
            }
        }
        return securityInfos
    }

    static func signedEncapsulatedContent(from data: [UInt8]) throws -> [UInt8] {
        let root = try SimpleASN1Node.parse(data)
        let contentType = root.children.first
        let explicitContent = root.children.dropFirst().first
        guard root.tag == 0x30,
              root.children.count == 2,
              contentType?.objectIdentifier == Self.idSignedData,
              explicitContent?.tag == 0xA0,
              explicitContent?.children.count == 1,
              let signedData = explicitContent?.children.first,
              signedData.tag == 0x30,
              signedData.children.count >= 4,
              signedData.children.first?.tag == 0x02,
              signedData.children.dropFirst().first?.tag == 0x31,
              let encapContentInfo = signedData.children.dropFirst(2).first,
              encapContentInfo.tag == 0x30,
              encapContentInfo.children.count == 2,
              encapContentInfo.children.first?.objectIdentifier != nil,
              let eContent = encapContentInfo.children.dropFirst().first,
              eContent.tag == 0xA0,
              eContent.children.count == 1,
              let content = eContent.children.first,
              content.tag == 0x04,
              signedData.children.last?.tag == 0x31 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        return content.value
    }
}
