//
//  CardSecurity.swift
//  NFCPassportReader
//
//  Created for EF.CardSecurity parsing.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
class CardSecurity {
    private(set) var securityInfos: [SecurityInfo] = []
    private(set) var signatureVerified = false
    private(set) var signerTrusted = false
    private var signedData: [UInt8]

    required init(_ data: [UInt8]) throws {
        signedData = data
        let encapsulatedSecurityInfos = try SecurityInfosParser.signedEncapsulatedContent(from: data)
        securityInfos = try SecurityInfosParser.parse(encapsulatedSecurityInfos)
    }

    func verifySignature(trustedCertificatesURL: URL?) throws {
        signatureVerified = false
        signerTrusted = false

        defer {
            signedData.removeAll(keepingCapacity: false)
        }

        let content = try OpenSSLUtils.verifyAndReturnCMSEncapsulatedData(
            Data(signedData),
            trustedCertificatesURL: trustedCertificatesURL
        )
        securityInfos = try SecurityInfosParser.parse([UInt8](content))
        signatureVerified = true
        signerTrusted = trustedCertificatesURL != nil
    }

    func removeSensitiveDataForPrivacy() {
        securityInfos.forEach { $0.removeSensitiveDataForPrivacy() }
        securityInfos.removeAll(keepingCapacity: false)
        signatureVerified = false
        signerTrusted = false
        signedData.removeAll(keepingCapacity: false)
    }
}
