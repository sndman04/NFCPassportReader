//
//  ChipAuthenticationPublicKeyInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
class ChipAuthenticationPublicKeyInfo : SecurityInfo {
    var oid : String
    var pubKey : OpaquePointer
    var keyId : Int?
    private let ownsPublicKey: Bool
    
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_PK_DH_OID == oid
            || ID_PK_ECDH_OID == oid
    }
    
    init(oid:String, pubKey:OpaquePointer, keyId: Int? = nil, ownsPublicKey: Bool = true) {
        self.oid = oid
        self.pubKey = pubKey
        self.keyId = keyId
        self.ownsPublicKey = ownsPublicKey
    }

    deinit {
        if ownsPublicKey {
            EVP_PKEY_free(pubKey)
        }
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public override func getProtocolOIDString() -> String {
        return ChipAuthenticationPublicKeyInfo.toProtocolOIDString(oid:oid)
    }

    // The keyid refers to a specific key if there are multiple otherwise if not set, only one key is present so set to 0
    func getKeyId() -> Int {
        return keyId ?? 0
    }
    

    private static func toProtocolOIDString(oid : String) -> String {
        if ID_PK_DH_OID == oid {
            return "id-PK-DH"
        }
        if ID_PK_ECDH_OID == oid {
            return "id-PK-ECDH"
        }
        
        return oid
    }

}
