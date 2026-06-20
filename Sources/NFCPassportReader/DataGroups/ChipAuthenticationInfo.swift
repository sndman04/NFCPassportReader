//
//  ChipAuthenticationInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationInfo : SecurityInfo {
    
    var oid : String
    var version : Int
    var keyId : Int?

    private static let supportedIdentifiers: Set<String> = [
        ID_CA_DH_3DES_CBC_CBC_OID,
        ID_CA_ECDH_3DES_CBC_CBC_OID,
        ID_CA_DH_AES_CBC_CMAC_128_OID,
        ID_CA_DH_AES_CBC_CMAC_192_OID,
        ID_CA_DH_AES_CBC_CMAC_256_OID,
        ID_CA_ECDH_AES_CBC_CMAC_128_OID,
        ID_CA_ECDH_AES_CBC_CMAC_192_OID,
        ID_CA_ECDH_AES_CBC_CMAC_256_OID
    ]

    private static let keyAgreementAlgorithms: [String: String] = [
        ID_CA_DH_3DES_CBC_CBC_OID: "DH",
        ID_CA_DH_AES_CBC_CMAC_128_OID: "DH",
        ID_CA_DH_AES_CBC_CMAC_192_OID: "DH",
        ID_CA_DH_AES_CBC_CMAC_256_OID: "DH",
        ID_CA_ECDH_3DES_CBC_CBC_OID: "ECDH",
        ID_CA_ECDH_AES_CBC_CMAC_128_OID: "ECDH",
        ID_CA_ECDH_AES_CBC_CMAC_192_OID: "ECDH",
        ID_CA_ECDH_AES_CBC_CMAC_256_OID: "ECDH"
    ]

    private static let cipherAlgorithms: [String: String] = [
        ID_CA_DH_3DES_CBC_CBC_OID: "DESede",
        ID_CA_ECDH_3DES_CBC_CBC_OID: "DESede",
        ID_CA_DH_AES_CBC_CMAC_128_OID: "AES",
        ID_CA_DH_AES_CBC_CMAC_192_OID: "AES",
        ID_CA_DH_AES_CBC_CMAC_256_OID: "AES",
        ID_CA_ECDH_AES_CBC_CMAC_128_OID: "AES",
        ID_CA_ECDH_AES_CBC_CMAC_192_OID: "AES",
        ID_CA_ECDH_AES_CBC_CMAC_256_OID: "AES"
    ]

    private static let keyLengths: [String: Int] = [
        ID_CA_DH_3DES_CBC_CBC_OID: 128,
        ID_CA_ECDH_3DES_CBC_CBC_OID: 128,
        ID_CA_DH_AES_CBC_CMAC_128_OID: 128,
        ID_CA_ECDH_AES_CBC_CMAC_128_OID: 128,
        ID_CA_DH_AES_CBC_CMAC_192_OID: 192,
        ID_CA_ECDH_AES_CBC_CMAC_192_OID: 192,
        ID_CA_DH_AES_CBC_CMAC_256_OID: 256,
        ID_CA_ECDH_AES_CBC_CMAC_256_OID: 256
    ]

    private static let protocolOIDStrings: [String: String] = [
        ID_CA_DH_3DES_CBC_CBC_OID: "id-CA-DH-3DES-CBC-CBC",
        ID_CA_DH_AES_CBC_CMAC_128_OID: "id-CA-DH-AES-CBC-CMAC-128",
        ID_CA_DH_AES_CBC_CMAC_192_OID: "id-CA-DH-AES-CBC-CMAC-192",
        ID_CA_DH_AES_CBC_CMAC_256_OID: "id-CA-DH-AES-CBC-CMAC-256",
        ID_CA_ECDH_3DES_CBC_CBC_OID: "id-CA-ECDH-3DES-CBC-CBC",
        ID_CA_ECDH_AES_CBC_CMAC_128_OID: "id-CA-ECDH-AES-CBC-CMAC-128",
        ID_CA_ECDH_AES_CBC_CMAC_192_OID: "id-CA-ECDH-AES-CBC-CMAC-192",
        ID_CA_ECDH_AES_CBC_CMAC_256_OID: "id-CA-ECDH-AES-CBC-CMAC-256"
    ]
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        supportedIdentifiers.contains(oid)
    }
    
    init(oid: String, version: Int, keyId: Int? = nil) {
        self.oid = oid
        self.version = version
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationInfo.toProtocolOIDString(oid:oid)
    }
    
    // The keyid refers to a specific key if there are multiple otherwise if not set, only one key is present so set to 0
    public func getKeyId() -> Int {
        return keyId ?? 0
    }
    
    /// Returns the key agreement algorithm - DH or ECDH for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: key agreement algorithm
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyAgreementAlgorithm( oid : String ) throws -> String {
        if let algorithm = keyAgreementAlgorithms[oid] {
            return algorithm
        }

        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup key agreement algorithm - invalid oid" )
    }
    
    /// Returns the cipher algorithm - DESede or AES for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the cipher algorithm type
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toCipherAlgorithm( oid : String ) throws -> String {
        if let algorithm = cipherAlgorithms[oid] {
            return algorithm
        }
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup cipher algorithm - invalid oid" )
    }
    
    /// Returns the key length in bits (128, 192, or 256) for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the key length in bits
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyLength( oid : String ) throws -> Int {
        if let keyLength = keyLengths[oid] {
            return keyLength
        }

        throw NFCPassportReaderError.InvalidDataPassed( "Unable to get key length - invalid oid" )
    }
    
    private static func toProtocolOIDString(oid : String) -> String {
        protocolOIDStrings[oid] ?? oid
    }
}
