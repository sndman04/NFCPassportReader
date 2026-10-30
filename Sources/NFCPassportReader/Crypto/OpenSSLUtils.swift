//
//  OpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import Foundation
import OpenSSL
import OpenSSLCompat
import CryptoTokenKit

@available(iOS 13, macOS 10.15, *)
class OpenSSLUtils {
    private static let maxBIOStringLength = 64 * 1024
    private static let maxNativeParserInputLength = 2 * 1024 * 1024
    private static let maxPublicKeyDERLength = 64 * 1024
    private static let maxSignatureInputLength = 64 * 1024
    private static let maxSignatureOutputLength = 64 * 1024
    private static let maxSharedSecretLength = 8192

    /// Returns any OpenSSL error as a string.
    ///
    /// This is an internal low-level helper, not an app-facing diagnostic surface. Do not include
    /// returned OpenSSL text in user-visible errors, logs, support tickets, or telemetry without a
    /// separate privacy review.
    static func getOpenSSLError() -> String {
        
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
        guard len > 0,
              len <= maxBIOStringLength else {
            return ""
        }

        var buffer = [CChar](repeating: 0, count: len+1)
        guard BIO_read(bio, &buffer, Int32(len)) == len else {
            return ""
        }
        
        return buffer.withUnsafeBufferPointer { pointer in
            String(decoding: UnsafeRawBufferPointer(start: pointer.baseAddress, count: len), as: UTF8.self)
        }
    }
    

    static func sk_X509_num(_ sk : OpaquePointer?) -> Int32 {
        guard let sk else { return 0 }
        return OPENSSL_sk_num(ossl_check_const_X509_sk_type(sk))
    }
    
    static func sk_X509_value(_ sk : OpaquePointer?, _ idx : Int32 ) -> OpaquePointer? {
        guard let sk,
              idx >= 0,
              idx < sk_X509_num(sk) else { return nil }
        let p = OPENSSL_sk_value(ossl_check_const_X509_sk_type(sk), (idx))
        let op = OpaquePointer(p)
        return op
    }

    
    static func X509ToPEM( x509: OpaquePointer ) -> String {
        
        guard let out = BIO_new(BIO_s_mem()) else { return "" }
        defer { BIO_free( out) }
        
        guard PEM_write_bio_X509(out, x509) == 1 else {
            return ""
        }
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }
    
    /// Extracts a X509 certificate in PEM format from a PKCS7 container
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The PEM formatted X509 certificate
    /// - Throws: A OpenSSLError.UnableToGetX509CertificateFromPKCS7 are thrown for any error
    static func getX509CertificatesFromPKCS7( pkcs7Der : Data ) throws -> [X509Wrapper] {
        guard isNativeParserInputSizeValid(pkcs7Der.count) else {
            throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Invalid PKCS7 DER size")
        }
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let bytesWritten = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
        guard bytesWritten == pkcs7Der.count else {
            throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to write PKCS7 DER data")
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
            guard certCount > 0 else {
                return ret
            }
            for i in 0 ..< certCount {
                let x = sk_X509_value(certs, i);
                if let x509 = X509Wrapper(with:x) {
                    ret.append( x509 )
                }
            }
        }
        
        return ret
    }
    
    /// Resolve each RFC 5652 SignerIdentifier; certificate-set position has no meaning.
    static func getCMSSignerCertificates(_ data: Data) throws -> [X509Wrapper] {
        let stack = data.withUnsafeBytes { bytes in
            NFCPRCopyCMSSignerCertificates(bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count)
        }
        guard let stack else {
            throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Missing or ambiguous signing certificate")
        }
        defer { OSSL_STACK_OF_X509_free(stack) }
        return try (0..<sk_X509_num(stack)).map { index in
            guard let cert = X509Wrapper(with: sk_X509_value(stack, index)) else {
                throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to copy signing certificate")
            }
            return cert
        }
    }

    private static func validatedSODAlgorithms(_ sod: SOD, operation: PassportDiagnosticOperation,
                                              diagnostic: ((PassportDiagnosticFailure) -> Void)?) throws -> [SODSignatureAlgorithm] {
        do { return try sod.validatedSignatureAlgorithms() }
        catch {
            let reason: PassportDiagnosticReason = (error as? SODSignatureAlgorithm.Failure) == .unsupported
                ? .unsupportedAlgorithm : .malformedStructure
            diagnostic?(.init(subsystem: .parser, operation: operation, stage: .passiveAuthentication, reason: reason))
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Invalid SOD signer structure or algorithm")
        }
    }

    /// Checks whether a trust chain can be built up to verify a X509 certificate. A CAFile containing a list of trusted certificates (each in PEM format)
    /// is used to build the trust chain.
    /// The trusted certificates in this use case are typically from a Countries master list (see the scripts for  more informaton on how to prepare this)
    /// - Parameter x509Cert: The X509 certificate (in PEM format) to verify
    /// - Parameter CAFile: The URL path of a file containing the list of certificates used to try to discover and build a trust chain
    /// - Returns: either the X509 issue signing certificate that was used to sign the passed in X509 certificate or an error
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL, diagnostic: ((PassportDiagnosticFailure) -> Void)? = nil ) -> Result<X509Wrapper, OpenSSLError> {
        var failureReason: PassportDiagnosticReason = .trustStoreUnavailable
        var validationCode: Int?
        var succeeded = false
        defer {
            if !succeeded {
                diagnostic?(.init(subsystem: .trust, operation: .validateChain, stage: .passiveAuthentication,
                                  reason: failureReason, certificateValidationCode: validationCode))
            }
        }
        let cert_ctx: OpaquePointer
        do {
            cert_ctx = try makeX509Store(CAFile: CAFile)
        } catch let error as OpenSSLError {
            return .failure(error)
        } catch {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store"))
        }
        defer { X509_STORE_free(cert_ctx) }
        
        failureReason = .resourceFailure
        guard let store = X509_STORE_CTX_new() else {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create new X509_STORE_CTX"))
        }
        defer { X509_STORE_CTX_free(store) }
        
        X509_STORE_set_flags(cert_ctx, 0)
        let rc = X509_STORE_CTX_init(store, cert_ctx, x509.cert, nil)
        if rc == 0 {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX"))
        }

        // discover and verify X509 certificte chain
        let i = X509_verify_cert(store);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(store)
            validationCode = Int(err)
            switch err {
            case X509_V_ERR_CERT_HAS_EXPIRED: failureReason = .certificateExpired
            case X509_V_ERR_CERT_NOT_YET_VALID: failureReason = .certificateNotYetValid
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                 X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                failureReason = .issuerNotFound
            case X509_V_ERR_CERT_SIGNATURE_FAILURE: failureReason = .certificateSignatureInvalid
            case X509_V_ERR_CERT_REVOKED: failureReason = .certificateRevoked
            case X509_V_ERR_INVALID_PURPOSE: failureReason = .invalidCertificatePurpose
            default: failureReason = .chainInvalid
            }
            
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)"))
        }
        
        // The direct issuer is chain[1]. A CSCA link chain may have a different
        // trust anchor at its end; that key cannot authenticate the signer's CRL.
        failureReason = .issuerNotFound
        let chain = X509_STORE_CTX_get1_chain(store);
        defer {
            if let chain {
                OSSL_STACK_OF_X509_free(chain)
            }
        }
        let nrCertsInChain = sk_X509_num(chain)
        if nrCertsInChain > 1 {
            let cert = sk_X509_value(chain, 1)
            if let certWrapper = X509Wrapper(with: cert) {
                succeeded = true
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
    static func verifyAndReturnSODEncapsulatedDataUsingCMS( sod : SOD, diagnostic: ((PassportDiagnosticFailure) -> Void)? = nil ) throws -> Data {
        _ = try validatedSODAlgorithms(sod, operation: .cmsVerification, diagnostic: diagnostic)
        _ = try sod.signingCertificates()
        _ = try sod.getEncapsulatedContent()
        return try verifyAndReturnCMSEncapsulatedData(Data(sod.body), trustedCertificatesURL: nil, diagnostic: diagnostic)
    }

    static func verifyAndReturnCMSEncapsulatedData(_ cmsDer: Data, trustedCertificatesURL: URL?, diagnostic: ((PassportDiagnosticFailure) -> Void)? = nil) throws -> Data {
        var reason: PassportDiagnosticReason = .resourceFailure
        var succeeded = false
        defer {
            if !succeeded {
                diagnostic?(.init(subsystem: .cryptography, operation: .cmsVerification,
                                  stage: .passiveAuthentication, reason: reason))
            }
        }
        guard isNativeParserInputSizeValid(cmsDer.count) else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Invalid DER size")
        }

        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate input buffer") }
        defer { BIO_free(inf) }

        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to allocate output buffer") }
        defer { BIO_free(out) }

        let bytesWritten = cmsDer.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(cmsDer.count))
        }
        guard bytesWritten == cmsDer.count else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to write DER data")
        }

        reason = .malformedStructure
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to create CMS")
        }
        defer { CMS_ContentInfo_free(cms) }

        var store: OpaquePointer?
        if let trustedCertificatesURL {
            store = try makeX509Store(CAFile: trustedCertificatesURL)
        }
        defer {
            if let store {
                X509_STORE_free(store)
            }
        }

        let flags: UInt32 = trustedCertificatesURL == nil ? UInt32(CMS_NO_SIGNER_CERT_VERIFY) : 0

        reason = .signatureInvalid
        if CMS_verify(cms, nil, store, nil, out, flags) == 0 {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification of P7 failed - unable to verify signature")
        }
        reason = .malformedStructure
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        guard len > 0,
              len <= maxNativeParserInputLength else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Verification returned no content")
        }

        var buffer = [UInt8](repeating: 0, count: len)
        guard BIO_read(out, &buffer, Int32(len)) == len else {
            throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("CMS - Unable to read verified content")
        }
        let sigData = Data(buffer)
        
        succeeded = true
        return sigData
    }

    private static func makeX509Store(CAFile: URL) throws -> OpaquePointer {
        guard let store = X509_STORE_new() else {
            throw OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store")
        }

        X509_STORE_set_verify_cb(store) { (ok, ctx) -> Int32 in
            let certError = X509_STORE_CTX_get_error(ctx)
            if ok == 0 && certError == X509_V_ERR_EC_KEY_EXPLICIT_PARAMS {
                return 1
            }
            return ok
        }

        guard let lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file()) else {
            X509_STORE_free(store)
            throw OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store")
        }

        let rc = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)
        guard rc == 1 else {
            X509_STORE_free(store)
            throw OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to load trusted certificates")
        }

        return store
    }
    
    
    static func verifyAndReturnSODEncapsulatedData( sod : SOD, diagnostic: ((PassportDiagnosticFailure) -> Void)? = nil ) throws -> Data {
        var reason: PassportDiagnosticReason = .malformedStructure
        var succeeded = false
        defer {
            if !succeeded {
                diagnostic?(.init(subsystem: reason == .malformedStructure ? .parser : .cryptography,
                                  operation: .manualVerification, stage: .passiveAuthentication, reason: reason))
            }
        }
        
        let algorithms: [SODSignatureAlgorithm]
        do { algorithms = try sod.validatedSignatureAlgorithms() }
        catch {
            reason = (error as? SODSignatureAlgorithm.Failure) == .unsupported ? .unsupportedAlgorithm : .malformedStructure
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Invalid SOD signer structure or algorithm")
        }
        let encapsulatedContent = try sod.getEncapsulatedContent()
        for (index, algorithm) in algorithms.enumerated() {
            let contentDigest = try sod.getEncapsulatedContentDigestAlgorithm(signerIndex: index) { reason = $0 }
            let signedAttributes = try sod.getSignedAttributes(signerIndex: index)
            let messageDigest = try sod.getMessageDigestFromSignedAttributes(signerIndex: index)
            let signature = try sod.getSignature(signerIndex: index)
            reason = .certificateUnavailable
            let pubKey = try sod.getPublicKey(signerIndex: index)
            let mdHash = try Data(calcHash(data: [UInt8](encapsulatedContent), hashAlgorithm: contentDigest))
            reason = .signedContentDigestMismatch
            guard messageDigest == mdHash else {
                throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("Signed content digest does not match")
            }
            reason = .signatureInvalid
            guard verifySODSignature(data: signedAttributes, signature: signature, publicKey: pubKey, algorithm: algorithm) else {
                throw OpenSSLError.VerifyAndReturnSODEncapsulatedData("Unable to verify signed attributes")
            }
        }
        succeeded = true
        return encapsulatedContent
    }
    /// Reads a public key in DER SubjectPublicKeyInfo format and converts it to an OpenSSL EVP_PKEY value.
    /// - Parameter data: The public key in DER format
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readRSAPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        guard let key = try readPublicKey(data: data) else {
            return nil
        }
        guard publicKeyType(key) == EVP_PKEY_RSA else {
            EVP_PKEY_free(key)
            return nil
        }
        return key
    }

    static func readPublicKey(data : [UInt8]) throws -> OpaquePointer? {
        guard isPublicKeyDERSizeValid(data.count) else {
            throw OpenSSLError.UnableToReadECPublicKey("Invalid public key size")
        }
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let bytesWritten = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        guard bytesWritten == data.count else {
            throw OpenSSLError.UnableToReadECPublicKey("Unable to write public key data")
        }
        
        guard let key = d2i_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        guard BIO_ctrl_pending(inf) == 0 else {
            EVP_PKEY_free(key)
            throw OpenSSLError.UnableToReadECPublicKey("Unexpected trailing public key data")
        }
        return key
    }
    
    /// This code is taken pretty much from rsautl.c - to decrypt a signature with a public key
    /// NOTE: Current no padding is used! - This seems to be the default for Active Authentication RSA signatures (guess)
    /// - Parameter signature: The RSA encrypted signature to decrypt
    /// - Parameter pubKey: The RSA Public Key
    /// - Returns: The decrypted signature data
    static func decryptRSASignature( signature : Data, pubKey : OpaquePointer ) throws -> [UInt8] {
        guard !signature.isEmpty,
              signature.count <= maxSignatureInputLength else {
            throw OpenSSLError.UnableToDecryptRSASignature("Invalid RSA signature size")
        }
        
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

        guard sizeResult == 1,
              outputLength > 0,
              outputLength <= maxSignatureOutputLength else {
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

        guard recoverResult == 1,
              outputLength > 0,
              outputLength <= outputBuf.count else {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature( "RSA signature recovery failed - \(error)" )
        }
        
        return [UInt8](outputBuf.prefix(outputLength))
    }
    
    static func normalizedActiveAuthenticationBlock(_ block: [UInt8], key: OpaquePointer) -> [UInt8]? {
        var normalized = block
        let valid = normalized.withUnsafeMutableBufferPointer {
            NFCPRNormalizeAARecovery(key, $0.baseAddress, $0.count)
        }
        return valid == 1 ? normalized : nil
    }

    /// Reads an ECDSA Public Key  in DER  format and converts it to an OpenSSL EVP_PKEY value for use whilst verifying a ECDSA signature
    /// - Parameter data: The ECDSA key in DER forma
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readECPublicKey( data : [UInt8] ) throws -> OpaquePointer? {
        guard let key = try readPublicKey(data: data) else {
            return nil
        }
        guard publicKeyType(key) == EVP_PKEY_EC else {
            EVP_PKEY_free(key)
            return nil
        }
        return key
    }

    static func publicKeyType(_ key: OpaquePointer) -> Int32 {
        EVP_PKEY_get_base_id(key)
    }
    
    
    /// Verifies Active Authentication data valid against an ECDSA signature and ECDSA Public Key - used in Active Authentication
    /// - Parameter publicKey: The OpenSSL EVP_PKEY ECDSA key
    /// - Parameter signature: The ECDSA signature to verify
    /// - Parameter data: The data used to generate the signature
    /// - Returns: True if the signature was verified
    static func verifyECDSASignature( publicKey:OpaquePointer, signature: [UInt8], data: [UInt8], digestType: String = "" ) -> Bool {
        guard !signature.isEmpty,
              signature.count <= maxSignatureInputLength,
              signature.count.isMultiple(of: 2),
              let ecsig = ECDSA_SIG_new() else {
            return false
        }
                
        // We first need to convert the signature from PLAIN ECDSA to ASN1 DER encoded
        defer { ECDSA_SIG_free(ecsig) }
        let sigData = signature
        let l = sigData.count / 2
        let didSetSignature = sigData.withUnsafeBufferPointer { (unsafeBufPtr) -> Bool in
            guard let unsafePointer = unsafeBufPtr.baseAddress else { return false }
            let r = BN_bin2bn(unsafePointer, Int32(l), nil)
            let s = BN_bin2bn((unsafePointer + l), Int32(l), nil)
            guard let r,
                  let s,
                  ECDSA_SIG_set0(ecsig, r, s) == 1 else {
                BN_free(r)
                BN_free(s)
                return false
            }
            return true
        }
        guard didSetSignature else {
            return false
        }

        let sigSize = i2d_ECDSA_SIG(ecsig, nil)
        guard sigSize > 0,
              sigSize <= maxSignatureOutputLength else {
            return false
        }

        var derBytes = [UInt8](repeating: 0, count: Int(sigSize))
        let encodedSize = derBytes.withUnsafeMutableBufferPointer { (unsafeBufPtr) in
            var unsafePointer = unsafeBufPtr.baseAddress
            return i2d_ECDSA_SIG(ecsig, &unsafePointer)
        }
        guard encodedSize == sigSize else {
            return false
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
        guard !signature.isEmpty,
              signature.count <= maxSignatureInputLength else {
            return false
        }
        
        let digestType = digestType.lowercased()
        guard !digestType.contains("rsassapss"), let digest = digestName(forSignatureType: digestType) else { return false }
        
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
        
        guard let md = EVP_get_digestbyname(digest),
              let ctx = EVP_MD_CTX_new() else {
            return false
        }
        var pkey_ctx : OpaquePointer?

        defer{ EVP_MD_CTX_free( ctx) }
        
        var nRes = EVP_DigestVerifyInit(ctx, &pkey_ctx, md, nil, pubKey)
        if ( nRes != 1 ) {
            return false;
        }
        
        nRes = data.withUnsafeBytes { dataPtr in
            EVP_DigestUpdate(ctx, dataPtr.baseAddress, data.count)
        }
        if ( nRes != 1 ) {
            return false;
        }
        
        nRes = fixedSignature.withUnsafeBytes { signaturePtr in
            EVP_DigestVerifyFinal(
                ctx,
                signaturePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                fixedSignature.count
            )
        }
        if (nRes != 1) {
            return false;
        }
        
        return true
    }

    /// Apply every declared PSS parameter, including exact salt length. EVP also enforces
    /// restrictions carried by an RSA-PSS SubjectPublicKeyInfo (RFC 4056 §3).
    private static func verifySODSignature(data: Data, signature: Data, publicKey: OpaquePointer,
                                           algorithm: SODSignatureAlgorithm) -> Bool {
        guard !signature.isEmpty, signature.count <= maxSignatureInputLength,
              let md = EVP_get_digestbyname(algorithm.digest), let ctx = EVP_MD_CTX_new() else { return false }
        defer { EVP_MD_CTX_free(ctx) }
        let keyType = EVP_PKEY_get_base_id(publicKey)
        switch algorithm.padding {
        case .rsaPKCS1: guard keyType == EVP_PKEY_RSA else { return false }
        case .rsaPSS: guard keyType == EVP_PKEY_RSA || keyType == EVP_PKEY_RSA_PSS else { return false }
        case .ecdsa: guard keyType == EVP_PKEY_EC else { return false }
        case .dsa: guard keyType == EVP_PKEY_DSA else { return false }
        }
        var keyContext: OpaquePointer?
        guard EVP_DigestVerifyInit(ctx, &keyContext, md, nil, publicKey) == 1, let keyContext else { return false }
        switch algorithm.padding {
        case .rsaPSS:
            guard let mgf = algorithm.maskDigest, let salt = algorithm.saltLength,
                  EVP_PKEY_CTX_ctrl_str(keyContext, "rsa_padding_mode", "pss") == 1,
                  EVP_PKEY_CTX_ctrl_str(keyContext, "rsa_mgf1_md", mgf) == 1,
                  EVP_PKEY_CTX_ctrl_str(keyContext, "rsa_pss_saltlen", String(salt)) == 1 else { return false }
        case .rsaPKCS1:
            guard EVP_PKEY_CTX_ctrl_str(keyContext, "rsa_padding_mode", "pkcs1") == 1 else { return false }
        case .ecdsa, .dsa: break
        }
        return data.withUnsafeBytes { bytes in
            EVP_DigestVerifyUpdate(ctx, bytes.baseAddress, data.count)
        } == 1 && signature.withUnsafeBytes { bytes in
            EVP_DigestVerifyFinal(ctx, bytes.baseAddress?.assumingMemoryBound(to: UInt8.self), signature.count)
        } == 1
    }

    static func digestName(forSignatureType digestType: String) -> String? {
        let normalized = digestType.lowercased()
        for digest in ["sha1", "sha224", "sha256", "sha384", "sha512", "ripemd160"] {
            if normalized == digest || normalized == "ecdsa-plain-" + digest
                || normalized == "ecdsa-with-" + digest || normalized == digest + "withrsaencryption" {
                return digest
            }
        }
        return nil
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

        guard let cipherNamePointer = strdup(cipherName) else {
            return []
        }
        defer {
            free(cipherNamePointer)
        }

        var output = [UInt8](repeating: 0, count: 32)
        var outputLength = 0
        let outputCapacity = output.count

        // OSSL_PARAM retains pointers; a bridged Swift String is valid only
        // inside withCString, including the eventual EVP_MAC_init call.
        let success = OSSL_MAC_PARAM_CIPHER.withCString { parameterName in
            var params = [
                OSSL_PARAM_construct_utf8_string(parameterName, cipherNamePointer, 0),
                OSSL_PARAM_construct_end()
            ]
            return key.withUnsafeBytes { keyPtr in
                message.withUnsafeBytes { messagePtr in
                    output.withUnsafeMutableBytes { outputPtr in
                        EVP_MAC_init(
                            ctx,
                            keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            key.count,
                            &params
                        ) == 1
                        && EVP_MAC_update(
                            ctx,
                            messagePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            message.count
                        ) == 1
                        && EVP_MAC_final(
                            ctx,
                            outputPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            &outputLength,
                            outputCapacity
                        ) == 1
                    }
                }
            }
        }

        guard success else {
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

    /// Returns an encoded public key from an OpenSSL key.
    ///
    /// This internal low-level helper may expose cryptographic material used during PACE or Chip
    /// Authentication. Do not log, persist, or transmit returned bytes.
    @available(iOS 13, macOS 10.15, *)
    static func getPublicKeyData(from key:OpaquePointer) -> [UInt8]? {
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
            guard nrBytes > 0,
                  nrBytes <= maxPublicKeyDERLength else {
                return nil
            }
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            guard BN_bn2bin(dhPubKey, &data) == nrBytes else {
                return nil
            }
        } else if v == EVP_PKEY_EC {

            var length = 0
            guard EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, nil, 0, &length) == 1,
                  length > 0,
                  length <= maxPublicKeyDERLength else {
                return nil
            }

            data = [UInt8](repeating: 0, count: length)
            guard EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, &data, data.count, &length) == 1,
                  length > 0,
                  length <= data.count else {
                return nil
            }
            data = [UInt8](data.prefix(length))
        } else {
            return nil
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
    
    /// Decodes an encoded public key using the domain parameters from another OpenSSL key.
    ///
    /// Caller is responsible for freeing the returned key. This is an internal low-level helper for
    /// passport protocol internals; do not surface inputs or outputs in diagnostics.
    @available(iOS 13, macOS 10.15, *)
    static func decodePublicKeyFromBytes(pubKeyData: [UInt8], params: OpaquePointer) -> OpaquePointer? {
        guard isPublicKeyDERSizeValid(pubKeyData.count) else {
            return nil
        }

        let keyType = EVP_PKEY_get_base_id(params)
        guard keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX || keyType == EVP_PKEY_EC,
              let publicKey = EVP_PKEY_new() else { return nil }
        // Preserve all domain parameters, including PACE's mapped generator.
        // OpenSSL consumes the wire encoding directly, avoiding native-endian
        // OSSL_PARAM BNs and Swift temporary-buffer lifetime pitfalls.
        let imported = EVP_PKEY_copy_parameters(publicKey, params) == 1
            && pubKeyData.withUnsafeBufferPointer {
                EVP_PKEY_set1_encoded_public_key(publicKey, $0.baseAddress, $0.count) == 1
            }
        guard imported, let context = EVP_PKEY_CTX_new(publicKey, nil) else {
            EVP_PKEY_free(publicKey)
            return nil
        }
        defer { EVP_PKEY_CTX_free(context) }
        guard EVP_PKEY_public_check(context) == 1 else {
            EVP_PKEY_free(publicKey)
            return nil
        }
        return publicKey
    }
    

    /// Computes a Diffie-Hellman/ECDH shared secret from an OpenSSL private key and peer public key.
    ///
    /// The returned bytes are sensitive session-key material. Never log, persist, or transmit the
    /// result.
    static func computeSharedSecret( privateKeyPair: OpaquePointer, publicKey: OpaquePointer ) throws -> [UInt8] {
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
              keyLen > 0,
              keyLen <= maxSharedSecretLength else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to determine shared-secret length")
        }

        var secret = [UInt8](repeating: 0, count: keyLen)
        guard EVP_PKEY_derive(ctx, &secret, &keyLen) == 1,
              keyLen > 0,
              keyLen <= maxSharedSecretLength,
              keyLen <= secret.count else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to derive shared secret")
        }
        secret = [UInt8](secret.prefix(keyLen))
        return secret
    }

    private static func isNativeParserInputSizeValid(_ count: Int) -> Bool {
        count > 0 && count <= maxNativeParserInputLength
    }

    private static func isPublicKeyDERSizeValid(_ count: Int) -> Bool {
        count > 0 && count <= maxPublicKeyDERLength
    }

}
