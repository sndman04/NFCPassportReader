//
//  DataGroup15.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import OpenSSL
import OpenSSLCompat

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
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        switch OpenSSLUtils.publicKeyType(key) {
        case EVP_PKEY_EC:
            // ICAO Part 11 §6.1.2.3: prime curves and uncompressed points only.
            guard let spki = try? SimpleASN1Node.parse(body), spki.children.count == 2,
                  spki.children[1].tag == 0x03, spki.children[1].value.starts(with: [0, 4]),
                  NFCPRIsPrimeCurveKey(key) == 1 else {
                EVP_PKEY_free(key)
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            ecdsaPublicKey = key
        case EVP_PKEY_RSA:
            rsaPublicKey = key
        default:
            EVP_PKEY_free(key)
            throw NFCPassportReaderError.InvalidASN1Structure
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
