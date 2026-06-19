//
//  OpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import Foundation
import OpenSSL
import CryptoTokenKit

@available(iOS 13, macOS 10.15, *)
public class OpenSSLUtils {
    /// Returns any OpenSSL Error as a String
    public static func getOpenSSLError() -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { return "Unknown" }
        defer { BIO_free(out) }
        
        ERR_print_errors( out )
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    /// Extracts the contents of a BIO object and returns it as a String
    /// - Parameter bio: a Pointer to a BIO buffer
    /// - Returns: A string containing the contents of the BIO buffer
    static func bioToString( bio : OpaquePointer ) -> String {
        
        let len = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        var buffer = [CChar](repeating: 0, count: len+1)
        BIO_read(bio, &buffer, Int32(len))
        
        // Ensure last value is 0 (null terminated) otherwise we get buffer overflow!
        buffer[len] = 0
        let ret = String(cString:buffer)
        return ret
    }
    

    static func sk_X509_num(_ sk : OpaquePointer!) -> Int32 {
        return OPENSSL_sk_num(ossl_check_const_X509_sk_type(sk))
    }
    
    static func sk_X509_value(_ sk : OpaquePointer!, _ idx : Int32 ) -> OpaquePointer! {
        let p = OPENSSL_sk_value(ossl_check_const_X509_sk_type(sk), (idx))
        let op = OpaquePointer(p)
        return op
    }

    
    static func X509ToPEM( x509: OpaquePointer ) -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { return "" }
        defer { BIO_free( out) }
        
        PEM_write_bio_X509(out, x509);
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    /// Extracts a X509 certificate in PEM format from a PKCS7 container
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The PEM formatted X509 certificate
    /// - Throws: A OpenSSLError.UnableToGetX509CertificateFromPKCS7 are thrown for any error
    static func getX509CertificatesFromPKCS7( pkcs7Der : Data ) throws -> [X509Wrapper] {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
        guard let p7 = d2i_PKCS7_bio(inf, nil) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to read PKCS7 DER data") }
        defer { PKCS7_free(p7) }
        
        var certs : OpaquePointer? = nil
        let i = OBJ_obj2nid(p7.pointee.type);
        switch (i) {
            case NID_pkcs7_signed:
                if let sign = p7.pointee.d.sign {
                    certs = sign.pointee.cert
                }
                break;
            case NID_pkcs7_signedAndEnveloped:
                if let signed_and_enveloped = p7.pointee.d.signed_and_enveloped {
                    certs = signed_and_enveloped.pointee.cert
                }
                break;
            default:
                break;
        }
        
        var ret = [X509Wrapper]()
        if let certs = certs  {
            let certCount = sk_X509_num(certs)
            for i in 0 ..< certCount {
                let x = sk_X509_value(certs, i);
                if let x509 = X509Wrapper(with:x) {
                    ret.append( x509 )
                }
            }
        }
        
        return ret
    }
    
    /// Checks whether a trust chain can be built up to verify a X509 certificate. A CAFile containing a list of trusted certificates (each in PEM format)
    /// is used to build the trust chain.
    /// The trusted certificates in this use case are typically from a Countries master list (see the scripts for  more informaton on how to prepare this)
    /// - Parameter x509Cert: The X509 certificate (in PEM format) to verify
    /// - Parameter CAFile: The URL path of a file containing the list of certificates used to try to discover and build a trust chain
    /// - Returns: either the X509 issue signing certificate that was used to sign the passed in X509 certificate or an error
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL ) -> Result<X509Wrapper, OpenSSLError> {
                
        guard let cert_ctx = X509_STORE_new() else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store")) }
        defer { X509_STORE_free(cert_ctx) }
        
        X509_STORE_set_verify_cb(cert_ctx) { (ok, ctx) -> Int32 in
            let cert_error = X509_STORE_CTX_get_error(ctx)
            
            var ret : Int32 = ok
            if ok == 0 {
                // OpenSSL V3 made a change to fail verification for certificates using explicit parameters
                // However the ICAO spec requires no implicit parameters
                // So if we have the explict params error - we ignore it and return 1 (no error) for this error
                if cert_error == X509_V_ERR_EC_KEY_EXPLICIT_PARAMS {
                    // Ignoring this
                    ret = 1
                } else {
                }
            }
            
            return ret;
        }
        
        guard let lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file()) else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store")) }
        
        // Load masterList.pem file
        var rc = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)
        
        guard let store = X509_STORE_CTX_new() else {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create new X509_STORE_CTX"))
        }
        defer { X509_STORE_CTX_free(store) }
        
        X509_STORE_set_flags(cert_ctx, 0)
        rc = X509_STORE_CTX_init(store, cert_ctx, x509.cert, nil)
        if rc == 0 {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX"))
        }

        // discover and verify X509 certificte chain
        let i = X509_verify_cert(store);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(store)
            
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)"))
        }
        
        // Get chain and issue certificate is the last cert in the chain
        let chain = X509_STORE_CTX_get1_chain(store);
        let nrCertsInChain = sk_X509_num(chain)
        if nrCertsInChain > 1 {
            let cert = sk_X509_value(chain, nrCertsInChain-1)
            if let certWrapper = X509Wrapper(with: cert) {
                return .success( certWrapper )
            }
        }
        
        return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to get issuer certificate - not found"))
    }
    
    
    /// Verifies the signed data section against the stored certificate and extracts the signed data section from a PKCS7 container (if present and valid)
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The signed data from a PKCS7 container if we could read it
    ///
    /// - Note: To test from the command line using openssl (NOTE NOT THE default mac version as it doesn't currently support CMS):
    ///      extract the SOD Base64 from an exported passport (you will need to unescape slashes!) - save this to ppt.b64
    ///      convert to binary (cat ppt.b64 | base64 -D > ppt.bin
    ///      extract the der file from the SOD (which includes header) - tail -c+5 ppt.bin > aq.der (blindy discards header)
    ///      convert der to PEM - openssl pkcs7 -in ppt.der --inform der -out ppt.pem -outform pem
    ///      verify signature data against included document signing cert - openssl cms -verify -in ppt.pem -inform pem -noverify
    ///           the -noverify is don't verify against the signers certifcate (as we don' thave that!)
    ///
    ///      This should return Verification Successful and the signed data
    static func verifyAndReturnSODEncapsulatedDataUsingCMS( sod : SOD ) throws -> Data {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        
        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate output buffer") }
        defer { BIO_free(out) }
        
        let _ = sod.body.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(sod.body.count))
        }
        
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to create CMS")
        }
        defer { CMS_ContentInfo_free(cms) }
        
        let flags : UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY)
        
        if CMS_verify(cms, nil, nil, nil, out, flags) == 0 {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to verify signature")
        }
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(len))
        let sigData = Data(buffer)
        
        return sigData
    }
    
    
    static func verifyAndReturnSODEncapsulatedData( sod : SOD ) throws -> Data {
        
        let encapsulatedContent = try sod.getEncapsulatedContent()
        let signedAttribsHashAlgo = try sod.getEncapsulatedContentDigestAlgorithm()
        let signedAttributes = try sod.getSignedAttributes()
        let messageDigest = try sod.getMessageDigestFromSignedAttributes()
        let signature = try sod.getSignature()
        let sigType = try sod.getSignatureAlgorithm()
        
        let pubKey = try sod.getPublicKey()
        
        let mdHash : Data = try Data(calcHash(data: [UInt8](encapsulatedContent), hashAlgorithm: signedAttribsHashAlgo))
        
        // Make sure that hash equals the messageDigest
        if messageDigest != mdHash {
            // Invalid - signed data hash doesn't match message digest hash
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("messageDigest Hash doesn't hatch that of the signed attributes")
        }
        
        // Verify signed attributes
        if  !verifySignature( data : [UInt8](signedAttributes), signature : [UInt8](signature), pubKey : pubKey, digestType: sigType ) {
            
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("Unable to verify signature for signed attributes")
        }
        
        return encapsulatedContent
    }
    
    /// Parses a signed data structures encoded in ASN1 format and returns the structure in text format
    /// - Parameter data: The data to be parsed in ASN1 format
    /// - Returns: The parsed data as A String
    static func ASN1Parse( data: Data ) throws -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToParseASN1("Unable to allocate output buffer") }
        defer { BIO_free(out) }
        
        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 0, 0)
            if rc == 0 {
                let str = OpenSSLUtils.getOpenSSLError()
                throw OpenSSLError.UnableToParseASN1("Failed to parse ASN1 Data - \(str)")
            }
            
            parsed = bioToString(bio: out)
        }
        
        return parsed
    }
    
    
    
    /// Reads a public key in DER SubjectPublicKeyInfo format and converts it to an OpenSSL EVP_PKEY value.
    /// - Parameter data: The public key in DER format
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readRSAPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let key = d2i_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        return key
    }
    
    /// This code is taken pretty much from rsautl.c - to decrypt a signature with a public key
    /// NOTE: Current no padding is used! - This seems to be the default for Active Authentication RSA signatures (guess)
    /// - Parameter signature: The RSA encrypted signature to decrypt
    /// - Parameter pubKey: The RSA Public Key
    /// - Returns: The decrypted signature data
    static func decryptRSASignature( signature : Data, pubKey : OpaquePointer ) throws -> [UInt8] {
        
        guard let ctx = EVP_PKEY_CTX_new(pubKey, nil) else {
            throw OpenSSLError.UnableToDecryptRSASignature("Unable to create verification context")
        }
        defer { EVP_PKEY_CTX_free(ctx) }

        guard EVP_PKEY_verify_recover_init(ctx) == 1,
              EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) == 1 else {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature("Unable to initialise RSA signature recovery - \(error)")
        }

        var outputLength = 0
        let sizeResult = signature.withUnsafeBytes { sigPtr in
            EVP_PKEY_verify_recover(
                ctx,
                nil,
                &outputLength,
                sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                signature.count
            )
        }

        guard sizeResult == 1 else {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature( "RSA signature recovery failed - \(error)" )
        }

        var outputBuf = [UInt8](repeating: 0, count: outputLength)
        let recoverResult = signature.withUnsafeBytes { sigPtr in
            outputBuf.withUnsafeMutableBytes { outPtr in
                EVP_PKEY_verify_recover(
                    ctx,
                    outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    &outputLength,
                    sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signature.count
                )
            }
        }

        if recoverResult != 1 {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature( "RSA signature recovery failed - \(error)" )
        }
        
        return [UInt8](outputBuf.prefix(outputLength))
    }
    
    /// Reads an ECDSA Public Key  in DER  format and converts it to an OpenSSL EVP_PKEY value for use whilst verifying a ECDSA signature
    /// - Parameter data: The ECDSA key in DER forma
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readECPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let key = d2i_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        return key
    }
    
    
    /// Verifies Active Authentication data valid against an ECDSA signature and ECDSA Public Key - used in Active Authentication
    /// - Parameter publicKey: The OpenSSL EVP_PKEY ECDSA key
    /// - Parameter signature: The ECDSA signature to verify
    /// - Parameter data: The data used to generate the signature
    /// - Returns: True if the signature was verified
    static func verifyECDSASignature( publicKey:OpaquePointer, signature: [UInt8], data: [UInt8], digestType: String = "" ) -> Bool {
        guard !signature.isEmpty,
              signature.count.isMultiple(of: 2),
              let ecsig = ECDSA_SIG_new() else {
            return false
        }
                
        // We first need to convert the signature from PLAIN ECDSA to ASN1 DER encoded
        defer { ECDSA_SIG_free(ecsig) }
        let sigData = signature
        let l = sigData.count / 2
        sigData.withUnsafeBufferPointer { (unsafeBufPtr) in
            guard let unsafePointer = unsafeBufPtr.baseAddress else { return }
            let r = BN_bin2bn(unsafePointer, Int32(l), nil)
            let s = BN_bin2bn((unsafePointer + l), Int32(l), nil)
            ECDSA_SIG_set0(ecsig, r, s)
        }
        let sigSize = i2d_ECDSA_SIG(ecsig, nil)
        guard sigSize > 0 else {
            return false
        }

        var derBytes = [UInt8](repeating: 0, count: Int(sigSize))
        derBytes.withUnsafeMutableBufferPointer { (unsafeBufPtr) in
            var unsafePointer = unsafeBufPtr.baseAddress
            let _ = i2d_ECDSA_SIG(ecsig, &unsafePointer)
        }
        
        let rc = verifySignature(data: data, signature: derBytes, pubKey: publicKey, digestType: digestType)
        return rc
    }
    
    /// Verifies that a signature is valid for some data and a Public Key
    /// - Parameter data: The data used to generate the signature
    /// - Parameter signature: The signature to verify
    /// - Parameter publicKey: The OpenSSL EVP_PKEY  key
    /// - Parameter digestType: the type of hash to use (empty string to use no digest type)
    /// - Returns: True if the signature was verified
    static func verifySignature( data : [UInt8], signature : [UInt8], pubKey : OpaquePointer, digestType: String ) -> Bool {
        
        var digest = "sha256"
        let digestType = digestType.lowercased()
        if digestType.contains( "sha1" ) {
            digest = "sha1"
        } else if digestType.contains( "sha224" ) {
            digest = "sha224"
        } else if digestType.contains( "sha256" ) || digestType.contains( "rsassapss" ) {
            digest = "sha256"
        } else if digestType.contains( "sha384" ) {
            digest = "sha384"
        } else if digestType.contains( "sha512" ) {
            digest = "sha512"
        }
        
        // Fix for some invalid ECDSA based signatures
        // An ECDSA signature comprises of a Sequence of 2 big integers (R & S) and the verification
        // is a linear equation of these two integers, the data hash and the public key
        // However, in some passports the encoding of the integers is incorrect and has a leading 00
        // causing the verification to fail.
        // So in this case, we check to see if it is actually a valid BigInteger, and if not, we remove the
        // leading prefix, check again and if a valid big integer this time then we use this otherwise
        // we keep the original value
        // If we change any values then we re-generate the signature and use this
        var fixedSignature = signature
        if digestType.contains( "ecdsa" ) {
            // Decode signature
            if let sequence = TKBERTLVRecord(from:Data(signature)),
               sequence.tag == 0x30,
               var intRecords = TKBERTLVRecord.sequenceOfRecords(from: sequence.value),
               intRecords.count == 2 {
                
                var didFix = false
                for (idx, rec) in intRecords.enumerated() {
                    // Only process if the first byte is a 0
                    guard let firstByte = rec.value.first else {
                        continue
                    }

                    if firstByte != 0 {
                        continue
                    }

                    // There is a feature in TKBERTLVRecord.sequenceOfRecords where the 2nd record.data call
                    // contains the data for the whole data not the actual record
                    // (reported as FB9077037)
                    // So for the moment, work aroud this and create a new record
                    let fixedRec = TKBERTLVRecord( tag: rec.tag, value: rec.value)
                    let data = [UInt8](fixedRec.data)
                    
                    // Check to see if a valid Big Integer (we need the whole record including tag and length for the d2i_ASN1_INTEGER call)
                    data.withUnsafeBufferPointer { (ptr) in
                        var address = ptr.baseAddress
                        let v = d2i_ASN1_INTEGER(nil, &address, data.count)
                        defer { ASN1_INTEGER_free(v) }
                        if v == nil && rec.value.count > 1 {
                            // Not a valid BigInteger, so remove the first value and try again
                            let newRec = TKBERTLVRecord( tag: rec.tag, value: rec.value[1...])

                            let data2 = [UInt8](newRec.data)
                            data2.withUnsafeBufferPointer { (ptr) in
                                var address = ptr.baseAddress
                                let v2 = d2i_ASN1_INTEGER(nil, &address, data2.count)
                                defer { ASN1_INTEGER_free(v2) }
                                if v2 != nil {
                                    // OK, we have a valid BigInteger this time so replace the original
                                    // record with the new one
                                    intRecords[idx] = newRec
                                    didFix = true
                                }
                            }
                        }
                    }
                }

                // We only reencode if we changed any of the integers, otherwise assume they were actually
                // correctly encoded
                if didFix {
                    // re-encode
                    let newSequence = TKBERTLVRecord( tag: sequence.tag, records: intRecords)
                    fixedSignature = [UInt8](newSequence.data)
                }
            }
        }
        
        let md = EVP_get_digestbyname(digest)
        
        let ctx = EVP_MD_CTX_new()
        var pkey_ctx : OpaquePointer?

        defer{ EVP_MD_CTX_free( ctx) }
        
        var nRes = EVP_DigestVerifyInit(ctx, &pkey_ctx, md, nil, pubKey)
        if ( nRes != 1 ) {
            return false;
        }
        
        if digestType.contains( "rsassapss" ) {
            EVP_PKEY_CTX_ctrl_str(pkey_ctx, "rsa_padding_mode", "pss" )
            EVP_PKEY_CTX_ctrl_str(pkey_ctx, "rsa_pss_saltlen", "auto" )
        }
        
        nRes = EVP_DigestUpdate(ctx, data, data.count);
        if ( nRes != 1 ) {
            return false;
        }
        
        nRes = EVP_DigestVerifyFinal(ctx, fixedSignature, fixedSignature.count);
        if (nRes != 1) {
            return false;
        }
        
        return true
    }

    @available(iOS 13, macOS 10.15, *)
    static func generateAESCMAC( key: [UInt8], message : [UInt8] ) -> [UInt8] {
        guard let mac = EVP_MAC_fetch(nil, "CMAC", nil) else {
            return []
        }
        defer { EVP_MAC_free(mac) }

        guard let ctx = EVP_MAC_CTX_new(mac) else {
            return []
        }
        defer { EVP_MAC_CTX_free(ctx) }

        let cipherName: String
        switch key.count {
        case 16:
            cipherName = "AES-128-CBC"
        case 24:
            cipherName = "AES-192-CBC"
        case 32:
            cipherName = "AES-256-CBC"
        default:
            return []
        }

        var params = [
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, strdup(cipherName), 0),
            OSSL_PARAM_construct_end()
        ]
        defer {
            free(params[0].data)
        }

        var mutableKey = key
        var mutableMessage = message
        var output = [UInt8](repeating: 0, count: 32)
        var outputLength = 0

        guard EVP_MAC_init(ctx, &mutableKey, mutableKey.count, &params) == 1,
              EVP_MAC_update(ctx, &mutableMessage, mutableMessage.count) == 1,
              EVP_MAC_final(ctx, &output, &outputLength, output.count) == 1 else {
            return []
        }

        return [UInt8](output.prefix(outputLength))
    }
    
    @available(iOS 13, macOS 10.15, *)
    static func asn1EncodeOID (oid : String) -> [UInt8] {
        guard let obj = OBJ_txt2obj(oid.cString(using: .utf8), 1) else {
            return []
        }
        defer { ASN1_OBJECT_free(obj) }

        let payloadLen = i2d_ASN1_OBJECT(obj, nil)
        guard payloadLen > 0 else {
            return []
        }
        
        var data  = [UInt8](repeating: 0, count: Int(payloadLen))
        
        let _ = data.withUnsafeMutableBytes { (ptr) in
            var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            _ = i2d_ASN1_OBJECT(obj, &newPtr)
        }
        
        return data
    }

    @available(iOS 13, macOS 10.15, *)
    public static func getPublicKeyData(from key:OpaquePointer) -> [UInt8]? {
        var data : [UInt8] = []
        // Get Key type
        let v = EVP_PKEY_get_base_id( key )
        if v == EVP_PKEY_DH || v == EVP_PKEY_DHX {
            var dhPubKey: OpaquePointer?
            guard EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PUB_KEY, &dhPubKey) == 1,
                  let dhPubKey else {
                return nil
            }
            defer { BN_free(dhPubKey) }

            let nrBytes = (BN_num_bits(dhPubKey)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            _ = BN_bn2bin(dhPubKey, &data)
        } else if v == EVP_PKEY_EC {

            var length = 0
            guard EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, nil, 0, &length) == 1,
                  length > 0 else {
                return nil
            }

            data = [UInt8](repeating: 0, count: length)
            guard EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, &data, data.count, &length) == 1 else {
                return nil
            }
            data = [UInt8](data.prefix(length))
        }
        
        return data
    }

    static func generateDHXKeyPair(rfc5114Group: Int32) throws -> OpaquePointer {
        guard let paramContext = EVP_PKEY_CTX_new_id(EVP_PKEY_DHX, nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create DH parameter context")
        }
        defer { EVP_PKEY_CTX_free(paramContext) }

        var parameters: OpaquePointer?
        guard EVP_PKEY_paramgen_init(paramContext) == 1,
              EVP_PKEY_CTX_set_dhx_rfc5114(paramContext, rfc5114Group) == 1,
              EVP_PKEY_paramgen(paramContext, &parameters) == 1,
              let parameters else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create DH parameters")
        }
        defer { EVP_PKEY_free(parameters) }

        return try generateKeyPair(fromParameters: parameters)
    }

    static func generateECKeyPair(curveNID: Int32) throws -> OpaquePointer {
        guard let paramContext = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create EC parameter context")
        }
        defer { EVP_PKEY_CTX_free(paramContext) }

        var parameters: OpaquePointer?
        guard EVP_PKEY_paramgen_init(paramContext) == 1,
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramContext, curveNID) == 1,
              EVP_PKEY_paramgen(paramContext, &parameters) == 1,
              let parameters else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create EC parameters")
        }
        defer { EVP_PKEY_free(parameters) }

        return try generateKeyPair(fromParameters: parameters)
    }

    static func generateKeyPair(fromParameters parameters: OpaquePointer) throws -> OpaquePointer {
        guard let keyContext = EVP_PKEY_CTX_new(parameters, nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create key context")
        }
        defer { EVP_PKEY_CTX_free(keyContext) }

        var keyPair: OpaquePointer?
        guard EVP_PKEY_keygen_init(keyContext) == 1,
              EVP_PKEY_keygen(keyContext, &keyPair) == 1,
              let keyPair else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create key pair")
        }

        return keyPair
    }
    
    // Caller is responsible for freeing the key
    @available(iOS 13, macOS 10.15, *)
    public static func decodePublicKeyFromBytes(pubKeyData: [UInt8], params: OpaquePointer) -> OpaquePointer? {
        let keyType = EVP_PKEY_get_base_id( params )
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            var p: OpaquePointer?
            var q: OpaquePointer?
            var g: OpaquePointer?
            guard EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_P, &p) == 1,
                  EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_Q, &q) == 1,
                  EVP_PKEY_get_bn_param(params, OSSL_PKEY_PARAM_FFC_G, &g) == 1,
                  let p,
                  let q,
                  let g else {
                return nil
            }
            defer {
                BN_free(p)
                BN_free(q)
                BN_free(g)
            }

            var pBytes = bnBytes(p)
            var qBytes = bnBytes(q)
            var gBytes = bnBytes(g)
            var publicBytes = pubKeyData
            var fromDataParams = [
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_P, &pBytes, pBytes.count),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_Q, &qBytes, qBytes.count),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_FFC_G, &gBytes, gBytes.count),
                OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PUB_KEY, &publicBytes, publicBytes.count),
                OSSL_PARAM_construct_end()
            ]

            return createPublicKey(algorithm: "DHX", params: &fromDataParams)
        } else {
            var groupNameLength = 0
            guard EVP_PKEY_get_utf8_string_param(params, OSSL_PKEY_PARAM_GROUP_NAME, nil, 0, &groupNameLength) == 1,
                  groupNameLength > 0 else {
                return nil
            }

            var groupName = [CChar](repeating: 0, count: groupNameLength + 1)
            guard EVP_PKEY_get_utf8_string_param(params, OSSL_PKEY_PARAM_GROUP_NAME, &groupName, groupName.count, &groupNameLength) == 1 else {
                return nil
            }

            var publicBytes = pubKeyData
            var fromDataParams = [
                OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, &groupName, groupName.count),
                OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, &publicBytes, publicBytes.count),
                OSSL_PARAM_construct_end()
            ]

            return createPublicKey(algorithm: "EC", params: &fromDataParams)
        }
    }
    

    public static func computeSharedSecret( privateKeyPair: OpaquePointer, publicKey: OpaquePointer ) throws -> [UInt8] {
        guard let ctx = EVP_PKEY_CTX_new(privateKeyPair, nil) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to create shared-secret context")
        }
        defer{ EVP_PKEY_CTX_free(ctx) }

        guard EVP_PKEY_derive_init(ctx) == 1,
              EVP_PKEY_derive_set_peer(ctx, publicKey) == 1 else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to initialise shared-secret derivation")
        }

        var keyLen = 0
        guard EVP_PKEY_derive(ctx, nil, &keyLen) == 1,
              keyLen > 0 else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to determine shared-secret length")
        }

        var secret = [UInt8](repeating: 0, count: keyLen)
        guard EVP_PKEY_derive(ctx, &secret, &keyLen) == 1,
              keyLen > 0 else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to derive shared secret")
        }
        secret = [UInt8](secret.prefix(keyLen))
        return secret
    }

    private static func bnBytes(_ bn: OpaquePointer) -> [UInt8] {
        let count = Int((BN_num_bits(bn) + 7) / 8)
        var bytes = [UInt8](repeating: 0, count: count)
        BN_bn2bin(bn, &bytes)
        return bytes
    }

    private static func createPublicKey(algorithm: String, params: inout [OSSL_PARAM]) -> OpaquePointer? {
        guard let context = EVP_PKEY_CTX_new_from_name(nil, algorithm, nil) else {
            return nil
        }
        defer { EVP_PKEY_CTX_free(context) }

        var publicKey: OpaquePointer?
        // EVP_PKEY_PUBLIC_KEY is a compound C macro that Swift cannot import.
        let publicKeySelection = 0x04 | 0x02
        guard EVP_PKEY_fromdata_init(context) == 1,
              EVP_PKEY_fromdata(context, &publicKey, Int32(publicKeySelection), &params) == 1 else {
            return nil
        }

        return publicKey
    }
    
}
