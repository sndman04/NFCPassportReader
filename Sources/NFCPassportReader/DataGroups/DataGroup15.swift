//
//  DataGroup15.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
class DataGroup15 : DataGroup {
    
    public private(set) var rsaPublicKey : OpaquePointer?
    public private(set) var ecdsaPublicKey : OpaquePointer?

    public override var datagroupType: DataGroupId { .DG15 }

    deinit {
        removeSensitiveDataForPrivacy()
    }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    
    override func parse(_ data: [UInt8]) throws {
        
        guard let key = try OpenSSLUtils.readPublicKey(data: body) else {
            return
        }

        switch OpenSSLUtils.publicKeyType(key) {
        case EVP_PKEY_EC:
            ecdsaPublicKey = key
        case EVP_PKEY_RSA:
            rsaPublicKey = key
        default:
            EVP_PKEY_free(key)
        }
    }

    override func removeSensitiveDataForPrivacy() {
        if let key = ecdsaPublicKey {
            EVP_PKEY_free(key)
            ecdsaPublicKey = nil
        }
        if let key = rsaPublicKey {
            EVP_PKEY_free(key)
            rsaPublicKey = nil
        }
        super.removeSensitiveDataForPrivacy()
    }
}
