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
    private let keyIdentifier: Int

    init(mappingPublicKey: [UInt8], encryptedChipAuthenticationData: [UInt8], encryptionKey: [UInt8], keyIdentifier: Int) throws {
        guard keyIdentifier >= 0 else {
            throw NFCPassportReaderError.PACEError("CAM verification", "Invalid chip authentication key identifier")
        }
        let ivInput = [UInt8](repeating: 0xFF, count: 16)
        let iv = AESEncrypt(key: encryptionKey, message: ivInput, iv: [UInt8](repeating: 0x00, count: 16))
        guard iv.count == 16 else {
            throw NFCPassportReaderError.PACEError("CAM verification", "Unable to derive CAM IV")
        }

        let decryptedData = AESDecrypt(key: encryptionKey, message: encryptedChipAuthenticationData, iv: iv)
        guard let unpaddedData = strictUnpad(decryptedData), !unpaddedData.isEmpty else {
            throw NFCPassportReaderError.PACEError("CAM verification", "Unable to decrypt CAM data")
        }

        self.mappingPublicKey = mappingPublicKey
        self.chipAuthenticationData = unpaddedData
        self.keyIdentifier = keyIdentifier
    }

    func verifies(using publicKeyInfos: [ChipAuthenticationPublicKeyInfo]) -> Bool {
        // Part 11 §9.2.1 binds CAM to the PACEInfo parameter ID. A proof from
        // another advertised key, or conflicting keys sharing this ID, is not enough.
        let matches = publicKeyInfos.filter { $0.keyId == keyIdentifier }
        guard let first = matches.first, first.oid == SecurityInfo.ID_PK_ECDH_OID,
              let pubKey = first.pubKey, OpenSSLUtils.publicKeyType(pubKey) == EVP_PKEY_EC,
              matches.allSatisfy({ candidate in
                  guard candidate.oid == first.oid, let key = candidate.pubKey else { return false }
                  return EVP_PKEY_eq(pubKey, key) == 1
              }) else { return false }
        var mappingPublicKey = mappingPublicKey
        var chipAuthenticationData = chipAuthenticationData
        return NFCPRVerifyECDHCAMPublicKey(
            pubKey,
            &mappingPublicKey,
            mappingPublicKey.count,
            &chipAuthenticationData,
            chipAuthenticationData.count
        ) == 1
    }
}
