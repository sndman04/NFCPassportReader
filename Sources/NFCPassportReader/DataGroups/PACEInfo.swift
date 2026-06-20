//
//  PaceInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OpenSSL

enum PACEMappingType {
    case GM  // Generic Mapping
    case IM  // Integrated Mapping
    case CAM // Chip Authentication Mapping
    
    func description () -> String {
        switch self {
            case .GM:
                return "Generic Mapping"
            case .IM:
                return "Integrated Mapping"
            case .CAM:
                return "Chip Authentication Mapping"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
class PACEInfo : SecurityInfo {
    
    // Standardized domain parameters. Based on Table 6.
    public static let PARAM_ID_GFP_1024_160 = 0
    public static let PARAM_ID_GFP_2048_224 = 1
    public static let PARAM_ID_GFP_2048_256 = 2
    public static let PARAM_ID_ECP_NIST_P192_R1 = 8
    public static let PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9
    public static let PARAM_ID_ECP_NIST_P224_R1 = 10
    public static let PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11
    public static let PARAM_ID_ECP_NIST_P256_R1 = 12
    public static let PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13
    public static let PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14
    public static let PARAM_ID_ECP_NIST_P384_R1 = 15
    public static let PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16
    public static let PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17
    public static let PARAM_ID_ECP_NIST_P521_R1 = 18

    static let allowedIdentifiers: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC,
        ID_PACE_DH_GM_AES_CBC_CMAC_128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192,
        ID_PACE_DH_GM_AES_CBC_CMAC_256,
        ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_DH_IM_AES_CBC_CMAC_192,
        ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_GM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256]

    private static let mappingTypes: [String: PACEMappingType] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: .GM,
        ID_PACE_DH_GM_AES_CBC_CMAC_128: .GM,
        ID_PACE_DH_GM_AES_CBC_CMAC_192: .GM,
        ID_PACE_DH_GM_AES_CBC_CMAC_256: .GM,
        ID_PACE_ECDH_GM_3DES_CBC_CBC: .GM,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: .GM,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: .GM,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: .GM,
        ID_PACE_DH_IM_3DES_CBC_CBC: .IM,
        ID_PACE_DH_IM_AES_CBC_CMAC_128: .IM,
        ID_PACE_DH_IM_AES_CBC_CMAC_192: .IM,
        ID_PACE_DH_IM_AES_CBC_CMAC_256: .IM,
        ID_PACE_ECDH_IM_3DES_CBC_CBC: .IM,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: .IM,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: .IM,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: .IM,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: .CAM,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: .CAM,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: .CAM
    ]

    private static let keyAgreementAlgorithms: [String: String] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: "DH",
        ID_PACE_DH_GM_AES_CBC_CMAC_128: "DH",
        ID_PACE_DH_GM_AES_CBC_CMAC_192: "DH",
        ID_PACE_DH_GM_AES_CBC_CMAC_256: "DH",
        ID_PACE_DH_IM_3DES_CBC_CBC: "DH",
        ID_PACE_DH_IM_AES_CBC_CMAC_128: "DH",
        ID_PACE_DH_IM_AES_CBC_CMAC_192: "DH",
        ID_PACE_DH_IM_AES_CBC_CMAC_256: "DH",
        ID_PACE_ECDH_GM_3DES_CBC_CBC: "ECDH",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "ECDH",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "ECDH",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "ECDH",
        ID_PACE_ECDH_IM_3DES_CBC_CBC: "ECDH",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "ECDH",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "ECDH",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "ECDH",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "ECDH",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "ECDH",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "ECDH"
    ]

    private static let cipherAlgorithms: [String: String] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: "DESede",
        ID_PACE_DH_IM_3DES_CBC_CBC: "DESede",
        ID_PACE_ECDH_GM_3DES_CBC_CBC: "DESede",
        ID_PACE_ECDH_IM_3DES_CBC_CBC: "DESede",
        ID_PACE_DH_GM_AES_CBC_CMAC_128: "AES",
        ID_PACE_DH_GM_AES_CBC_CMAC_192: "AES",
        ID_PACE_DH_GM_AES_CBC_CMAC_256: "AES",
        ID_PACE_DH_IM_AES_CBC_CMAC_128: "AES",
        ID_PACE_DH_IM_AES_CBC_CMAC_192: "AES",
        ID_PACE_DH_IM_AES_CBC_CMAC_256: "AES",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "AES",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "AES",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "AES",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "AES",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "AES",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "AES",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "AES",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "AES",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "AES"
    ]

    private static let digestAlgorithms: [String: String] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: "SHA-1",
        ID_PACE_DH_IM_3DES_CBC_CBC: "SHA-1",
        ID_PACE_ECDH_GM_3DES_CBC_CBC: "SHA-1",
        ID_PACE_ECDH_IM_3DES_CBC_CBC: "SHA-1",
        ID_PACE_DH_GM_AES_CBC_CMAC_128: "SHA-1",
        ID_PACE_DH_IM_AES_CBC_CMAC_128: "SHA-1",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "SHA-1",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "SHA-1",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "SHA-1",
        ID_PACE_DH_GM_AES_CBC_CMAC_192: "SHA-256",
        ID_PACE_DH_IM_AES_CBC_CMAC_192: "SHA-256",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "SHA-256",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "SHA-256",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "SHA-256",
        ID_PACE_DH_GM_AES_CBC_CMAC_256: "SHA-256",
        ID_PACE_DH_IM_AES_CBC_CMAC_256: "SHA-256",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "SHA-256",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "SHA-256",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "SHA-256"
    ]

    private static let keyLengths: [String: Int] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: 128,
        ID_PACE_DH_IM_3DES_CBC_CBC: 128,
        ID_PACE_ECDH_GM_3DES_CBC_CBC: 128,
        ID_PACE_ECDH_IM_3DES_CBC_CBC: 128,
        ID_PACE_DH_GM_AES_CBC_CMAC_128: 128,
        ID_PACE_DH_IM_AES_CBC_CMAC_128: 128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: 128,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: 128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: 128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192: 192,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: 192,
        ID_PACE_DH_IM_AES_CBC_CMAC_192: 192,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: 192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: 192,
        ID_PACE_DH_GM_AES_CBC_CMAC_256: 256,
        ID_PACE_DH_IM_AES_CBC_CMAC_256: 256,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: 256,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: 256,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: 256
    ]

    private static let protocolOIDStrings: [String: String] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: "id-PACE-DH-GM-3DES-CBC-CBC",
        ID_PACE_DH_GM_AES_CBC_CMAC_128: "id-PACE-DH-GM-AES-CBC-CMAC-128",
        ID_PACE_DH_GM_AES_CBC_CMAC_192: "id-PACE-DH-GM-AES-CBC-CMAC-192",
        ID_PACE_DH_GM_AES_CBC_CMAC_256: "id-PACE-DH-GM-AES-CBC-CMAC-256",
        ID_PACE_DH_IM_3DES_CBC_CBC: "id-PACE-DH-IM-3DES-CBC-CBC",
        ID_PACE_DH_IM_AES_CBC_CMAC_128: "id-PACE-DH-IM-AES-CBC-CMAC-128",
        ID_PACE_DH_IM_AES_CBC_CMAC_192: "id-PACE-DH-IM-AES-CBC-CMAC-192",
        ID_PACE_DH_IM_AES_CBC_CMAC_256: "id-PACE-DH-IM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_GM_3DES_CBC_CBC: "id-PACE-ECDH-GM-3DES-CBC-CBC",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_IM_3DES_CBC_CBC: "id-PACE-ECDH-IM-3DES-CBC-CBC",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "id-PACE-ECDH-CAM-AES-CBC-CMAC-256"
    ]

    var oid : String
    var version : Int
    var parameterId : Int?
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return allowedIdentifiers.contains( oid )
    }
    
    init(oid: String, version: Int, parameterId: Int?) {
        self.oid = oid
        self.version = version
        self.parameterId = parameterId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return PACEInfo.toProtocolOIDString(oid:oid)
    }
    
    func getVersion() -> Int {
        return version
    }
    
    func getParameterId() -> Int? {
        return parameterId
    }
    
    func getParameterSpec() throws -> Int32 {
        return try PACEInfo.getParameterSpec(stdDomainParam: self.parameterId ?? -1 )
    }
    
    func getMappingType() throws -> PACEMappingType {
        return try PACEInfo.toMappingType(oid: oid); // Either GM, CAM, or IM.
    }
    
    func getKeyAgreementAlgorithm() throws -> String {
        return try PACEInfo.toKeyAgreementAlgorithm(oid: oid); // Either DH or ECDH.
    }
    
    func getCipherAlgorithm() throws -> String {
        return try PACEInfo.toCipherAlgorithm(oid: oid); // Either DESede or AES.
    }
    
    func getDigestAlgorithm() throws -> String {
        return try PACEInfo.toDigestAlgorithm(oid: oid); // Either SHA-1 or SHA-256.
    }
    
    func getKeyLength() throws -> Int {
        return try PACEInfo.toKeyLength(oid: oid); // Of the enc cipher. Either 128, 192, or 256.
    }

    var isImplementedForReading: Bool {
        guard let mappingType = try? getMappingType() else {
            return false
        }

        guard mappingType != .CAM || (try? getKeyAgreementAlgorithm()) == "ECDH" else {
            return false
        }

        return (try? getParameterSpec()) != nil
    }

    /// Caller is required to free the returned EVP_PKEY value
    func createMappingKey( ) throws -> OpaquePointer {
        switch try getKeyAgreementAlgorithm() {
            case "DH":
                switch try getParameterSpec() {
                    case 0:
                        return try OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1)
                    case 1:
                        return try OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 2)
                    case 2:
                        return try OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 3)
                    default:
                        throw NFCPassportReaderError.InvalidDataPassed("Unable to create DH mapping key")
                }
            
            case "ECDH":
                return try OpenSSLUtils.generateECKeyPair(curveNID: try getParameterSpec())
            default:
                throw NFCPassportReaderError.InvalidDataPassed("Unsupported agreement algorithm")
        }
    }

    public static func getParameterSpec(stdDomainParam : Int) throws -> Int32 {
        switch (stdDomainParam) {
            case PARAM_ID_GFP_1024_160:
                return 0 // "rfc5114_1024_160";
            case PARAM_ID_GFP_2048_224:
                return 1 // "rfc5114_2048_224";
            case PARAM_ID_GFP_2048_256:
                return 2 // "rfc5114_2048_256";
            case PARAM_ID_ECP_NIST_P192_R1:
                return NID_X9_62_prime192v1 // "secp192r1";
            case PARAM_ID_ECP_NIST_P224_R1:
                return NID_secp224r1 // "secp224r1";
            case PARAM_ID_ECP_NIST_P256_R1:
                return NID_X9_62_prime256v1 //"secp256r1";
            case PARAM_ID_ECP_NIST_P384_R1:
                return NID_secp384r1 // "secp384r1";
            case PARAM_ID_ECP_BRAINPOOL_P192_R1:
                return NID_brainpoolP192r1 //"brainpoolp192r1";
            case PARAM_ID_ECP_BRAINPOOL_P224_R1:
                return NID_brainpoolP224r1 // "brainpoolp224r1";
            case PARAM_ID_ECP_BRAINPOOL_P256_R1:
                return NID_brainpoolP256r1 // "brainpoolp256r1";
            case PARAM_ID_ECP_BRAINPOOL_P320_R1:
                return NID_brainpoolP320r1 //"brainpoolp320r1";
            case PARAM_ID_ECP_BRAINPOOL_P384_R1:
                return NID_brainpoolP384r1 //"brainpoolp384r1";
            case PARAM_ID_ECP_BRAINPOOL_P512_R1:
                return NID_brainpoolP512r1 //"";
            case PARAM_ID_ECP_NIST_P521_R1:
                return NID_secp521r1 //"secp224r1";
            default:
                throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup parameterSpec - invalid oid" )
        }
    }
    
    public static func toMappingType( oid : String ) throws -> PACEMappingType {
        if let mappingType = mappingTypes[oid] {
            return mappingType
        }

        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup mapping type - invalid oid" )
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
    
    public static func toDigestAlgorithm( oid : String ) throws -> String {
        if let algorithm = digestAlgorithms[oid] {
            return algorithm
        }

        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup digest algorithm - invalid oid" )

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
