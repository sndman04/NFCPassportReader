//
//  SecurityInfosParser.swift
//  NFCPassportReader
//
//  Created for shared SecurityInfos parsing.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum SecurityInfosParser {
    static func parse(_ data: [UInt8]) throws -> [SecurityInfo] {
        let root = try SimpleASN1Node.parse(data)
        guard root.tag == 0x31 || root.tag == 0x30 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        var securityInfos: [SecurityInfo] = []

        for child in root.children where child.tag == 0x30 {
            guard child.children.count >= 2,
                  let oid = child.children[0].objectIdentifier else {
                continue
            }

            let requiredData = child.children[1]
            let optionalData = child.children.count > 2 ? child.children[2] : nil
            if let secInfo = SecurityInfo.getInstance(
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
        guard root.tag == 0x30,
              root.children.count >= 2,
              let signedData = root.children[1].children.first(where: { $0.tag == 0x30 }),
              signedData.children.count >= 3,
              let eContent = signedData.children[2].children.first(where: { $0.tag == 0xA0 }),
              let content = eContent.children.first(where: { $0.tag == 0x04 }) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        return content.value
    }
}
