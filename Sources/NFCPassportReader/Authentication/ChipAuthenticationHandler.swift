//
//  ChipAuthenticationHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OpenSSL

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 15, *)
@MainActor
class ChipAuthenticationHandler {
    
    private static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    private static let ENC_MODE : UInt8 = 0x1
    private static let MAC_MODE : UInt8 = 0x2
    private static let PACE_MODE : UInt8 = 0x3

    private static let COMMAND_CHAINING_CHUNK_SIZE = 224

    struct ChipAuthenticationMetadata {
        let infosByKeyId: [Int: ChipAuthenticationInfo]
        let publicKeyInfos: [ChipAuthenticationPublicKeyInfo]
    }

    var tagReader : TagReader?
    var gaSegments = [[UInt8]]()
    
    var chipAuthInfos = [Int:ChipAuthenticationInfo]()
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    var isChipAuthenticationSupported : Bool = false

    init() {
        self.tagReader = nil
    }
    
    init(dg14 : DataGroup14, tagReader: TagReader) throws {
        self.tagReader = tagReader

        let metadata = try Self.metadata(from: dg14.securityInfos)
        chipAuthInfos = metadata.infosByKeyId
        chipAuthPublicKeyInfos = metadata.publicKeyInfos

        if chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    nonisolated static func metadata(from securityInfos: [SecurityInfo]) throws -> ChipAuthenticationMetadata {
        var infosByKeyId = [Int: ChipAuthenticationInfo]()
        var publicKeyInfos = [ChipAuthenticationPublicKeyInfo]()

        for secInfo in securityInfos {
            if let chipAuthInfo = secInfo as? ChipAuthenticationInfo {
                let keyId = chipAuthInfo.getKeyId()
                if let existing = infosByKeyId[keyId] {
                    guard existing.oid == chipAuthInfo.oid,
                          existing.version == chipAuthInfo.version,
                          existing.keyId == chipAuthInfo.keyId else {
                        throw NFCPassportReaderError.InvalidASN1Structure
                    }
                    continue
                }
                infosByKeyId[keyId] = chipAuthInfo
            } else if let publicKeyInfo = secInfo as? ChipAuthenticationPublicKeyInfo {
                publicKeyInfos.append(publicKeyInfo)
            }
        }

        return ChipAuthenticationMetadata(
            infosByKeyId: infosByKeyId,
            publicKeyInfos: publicKeyInfos
        )
    }

    isolated deinit {
        removeSensitiveData()
    }

    func removeSensitiveData() {
        gaSegments.removeAll(keepingCapacity: false)
        chipAuthInfos.removeAll(keepingCapacity: false)
        chipAuthPublicKeyInfos.forEach { $0.removeSensitiveDataForPrivacy() }
        chipAuthPublicKeyInfos.removeAll(keepingCapacity: false)
        tagReader?.secureMessaging?.removeSensitiveData()
        tagReader?.secureMessaging = nil
        tagReader = nil
        isChipAuthenticationSupported = false
    }

    func doChipAuthentication() async throws  {
        try await doChipAuthentication { publicKeyInfo in
            try await self.doChipAuthentication(with: publicKeyInfo)
        }
    }

    func doChipAuthentication(
        using attempt: @MainActor (ChipAuthenticationPublicKeyInfo) async throws -> Bool
    ) async throws {
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported( "ChipAuthentication not supported" )
        }
        
        var success = false
        for pubKey in chipAuthPublicKeyInfos {
            success = try await attempt(pubKey)
            if success {
                break
            }
        }
        
        if !success {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
    }
    
    private func doChipAuthentication( with chipAuthPublicKeyInfo : ChipAuthenticationPublicKeyInfo ) async throws -> Bool {
        
        // So it turns out that some passports don't have ChipAuthInfo items.
        // So if we do have a ChipAuthInfo the we take the keyId (if present) and OID from there,
        // BUT if we don't then we will try to infer the OID from the public key
        let keyId = chipAuthPublicKeyInfo.keyId
        let chipAuthInfoOID : String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthInfoOID = chipAuthInfo.oid
        } else {
            if let oid = inferOID( fromPublicKeyOID:chipAuthPublicKeyInfo.oid) {
                chipAuthInfoOID = oid
            } else {
                return false
            }
        }
        
        guard let publicKey = chipAuthPublicKeyInfo.pubKey else {
            return false
        }

        try await self.doCA( keyId: keyId, encryptionDetailsOID: chipAuthInfoOID, publicKey: publicKey )
        return true
    }
    
    /// Infer OID from public key type - Best guess seems to be to use 3DES_CBC_CBC for both ECDH and DH keys
    /// Apparently works for French passports
    private func inferOID(fromPublicKeyOID: String ) -> String? {
        if fromPublicKeyOID == SecurityInfo.ID_PK_ECDH_OID {
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        } else if fromPublicKeyOID == SecurityInfo.ID_PK_DH_OID {
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        }
        return nil;
    }
    
    private func doCA( keyId: Int?, encryptionDetailsOID oid: String, publicKey: OpaquePointer) async throws {
        
        // Generate Ephemeral Keypair from parameters from DG14 Public key
        // This should work for both EC and DH keys
        var ephemeralKeyPair : OpaquePointer? = nil
        guard let pctx = EVP_PKEY_CTX_new(publicKey, nil) else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
        defer { EVP_PKEY_CTX_free(pctx) }

        guard EVP_PKEY_keygen_init(pctx) == 1,
              EVP_PKEY_keygen(pctx, &ephemeralKeyPair) == 1 else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }

        guard let ephemeralKeyPair else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
        defer { EVP_PKEY_free(ephemeralKeyPair) }
        
        // Send the public key to the passport
        try await sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeralKeyPair)
        
        // Use our ephemeral private key and the passports public key to generate a shared secret
        // (the passport with do the same thing with their private key and our public key)
        let sharedSecret = try OpenSSLUtils.computeSharedSecret(privateKeyPair:ephemeralKeyPair, publicKey:publicKey)
        guard !sharedSecret.isEmpty else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
        
        // Now try to restart Secure Messaging using the new shared secret and
        try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
    }
    
    private func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : OpaquePointer) async throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        guard let keyData = OpenSSLUtils.getPublicKeyData(from: pcdPublicKey) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data from public key" )
        }
        
        if cipherAlg.hasPrefix("DESede") {
        
            let idData = try TagReader.mseKeyIdentifierData(keyId: keyId)
            let wrappedKeyData = wrapDO( b:0x91, arr:keyData)
            _ = try await self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: idData.map { Data($0) })
        } else if cipherAlg.hasPrefix("AES") {
            _ = try await self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
            let data = wrapDO(b: 0x80, arr:keyData)
            try await withPendingGeneralAuthenticationSegments(Self.chunk(data: data, segmentSize: ChipAuthenticationHandler.COMMAND_CHAINING_CHUNK_SIZE)) {
                try await self.handleGeneralAuthentication()
            }
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }
    }

    func withPendingGeneralAuthenticationSegments<T>(
        _ segments: [[UInt8]],
        operation: () async throws -> T
    ) async throws -> T {
        gaSegments = segments
        defer {
            gaSegments.removeAll(keepingCapacity: false)
        }
        return try await operation()
    }
    
    private func handleGeneralAuthentication() async throws {
        guard !gaSegments.isEmpty else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }

        repeat {
            // Pull next segment from list
            let segment = gaSegments.removeFirst()
            let isLast = gaSegments.isEmpty
        
            // send it
            _ = try await self.tagReader?.sendGeneralAuthenticate(data: segment, isLast: isLast)
        } while ( !gaSegments.isEmpty )
    }
        
    private func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        
        // Start secure messaging.
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }
    }
    
    
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1"
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1"
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256"
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256"
        }
        
        throw NFCPassportReaderError.UnsupportedCipherAlgorithm
    }
    
    /// Chunks up a byte array into a number of segments of the given size,
    /// and a final segment if there is a remainder.
    /// - Parameter segmentSize the number of bytes per segment
    /// - Parameter data the data to be partitioned
    /// - Parameter a list with the segments
    nonisolated static func chunk( data : [UInt8], segmentSize: Int ) -> [[UInt8]] {
        guard segmentSize > 0, !data.isEmpty else {
            return []
        }

        return stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< Swift.min($0 + segmentSize, data.count)])
        }
    }
}

#endif
