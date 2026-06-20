//
//  PACEChipAuthenticationMappingResult.swift
//  NFCPassportReader
//
//  Created for PACE-CAM verification hardening.
//

import Foundation
import OpenSSL
import OpenSSLCompat

@available(iOS 15, *)
struct PACEChipAuthenticationMappingResult {
    private let mappingPublicKey: [UInt8]
    private let chipAuthenticationData: [UInt8]

    init(mappingPublicKey: [UInt8], encryptedChipAuthenticationData: [UInt8], encryptionKey: [UInt8]) throws {
        let ivInput = [UInt8](repeating: 0xFF, count: 16)
        let iv = AESEncrypt(key: encryptionKey, message: ivInput, iv: [UInt8](repeating: 0x00, count: 16))
        guard iv.count == 16 else {
            throw NFCPassportReaderError.PACEError("CAM verification", "Unable to derive CAM IV")
        }

        let decryptedData = AESDecrypt(key: encryptionKey, message: encryptedChipAuthenticationData, iv: iv)
        let unpaddedData = unpad(decryptedData)
        guard !unpaddedData.isEmpty else {
            throw NFCPassportReaderError.PACEError("CAM verification", "Unable to decrypt CAM data")
        }

        self.mappingPublicKey = mappingPublicKey
        self.chipAuthenticationData = unpaddedData
    }

    func verifies(using publicKeyInfos: [ChipAuthenticationPublicKeyInfo]) -> Bool {
        publicKeyInfos.contains { publicKeyInfo in
            var mappingPublicKey = mappingPublicKey
            var chipAuthenticationData = chipAuthenticationData
            return NFCPRVerifyECDHCAMPublicKey(
                publicKeyInfo.pubKey,
                &mappingPublicKey,
                mappingPublicKey.count,
                &chipAuthenticationData,
                chipAuthenticationData.count
            ) == 1
        }
    }
}
