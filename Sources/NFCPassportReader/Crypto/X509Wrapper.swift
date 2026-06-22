//
//  X509Wrapper.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import OpenSSL

@available(iOS 13, macOS 10.15, *)
enum CertificateType {
    case documentSigningCertificate
    case issuerSigningCertificate
}

@available(iOS 13, macOS 10.15, *)
enum CertificateItem : String {
    case fingerprint = "Certificate fingerprint"
    case issuerName = "Issuer"
    case subjectName = "Subject"
    case serialNumber = "Serial number"
    case signatureAlgorithm = "Signature algorithm"
    case publicKeyAlgorithm = "Public key algorithm"
    case notBefore = "Valid from"
    case notAfter = "Valid to"
}

@available(iOS 13, macOS 10.15, *)
class X509Wrapper {
    private static let maxCertificateDigestLength = Int(EVP_MAX_MD_SIZE)
    private static let maxCertificateSerialLength = 64

    let cert : OpaquePointer
    
    public init?( with cert: OpaquePointer? ) {
        guard let cert = cert,
              let duplicatedCert = X509_dup(cert) else { return nil }
        
        self.cert = duplicatedCert
    }

    deinit {
        X509_free(cert)
    }
    
    func getItemsAsDict() -> [CertificateItem:String] {
        var item = [CertificateItem:String]()
        if let fingerprint = self.getFingerprint() {
            item[.fingerprint] = fingerprint
        }
        if let issuerName = self.getIssuerName() {
            item[.issuerName] = issuerName
            
        }
        if let subjectName = self.getSubjectName() {
            item[.subjectName] = subjectName
        }
        if let serialNr = self.getSerialNumber() {
            item[.serialNumber] = serialNr
        }
        if let signatureAlgorithm = self.getSignatureAlgorithm() {
            item[.signatureAlgorithm] = signatureAlgorithm
        }
        if let publicKeyAlgorithm = self.getPublicKeyAlgorithm() {
            item[.publicKeyAlgorithm] = publicKeyAlgorithm
        }
        if let notBefore = self.getNotBeforeDate() {
            item[.notBefore] = notBefore
        }
        if let notAfter = self.getNotAfterDate() {
            item[.notAfter] = notAfter
        }
        
        return item
    }
    func certToPEM() -> String {
        return OpenSSLUtils.X509ToPEM( x509:cert )
    }
    
    func getFingerprint( ) -> String? {
        let fdig = EVP_sha1();
        
        var n : UInt32 = 0
        let md = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_MAX_MD_SIZE))
        defer { md.deallocate() }
        
        guard X509_digest(cert, fdig, md, &n) == 1,
              n > 0,
              n <= EVP_MAX_MD_SIZE else {
            return nil
        }
        let arr = UnsafeMutableBufferPointer(start: md, count: Int(n)).map({ binToHexRep($0) }).joined(separator: ":")
        return arr
    }
    
    func getNotBeforeDate() -> String? {
        var notBefore : String?
        if let val = X509_get0_notBefore(cert) {
            notBefore = ASN1TimeToString( val )
        }
        return notBefore
        
    }
    
    func getNotAfterDate() -> String? {
        var notAfter : String?
        if let val = X509_get0_notAfter(cert) {
            notAfter = ASN1TimeToString( val )
        }
        return notAfter
    }
    
    func getSerialNumber() -> String? {
        return X509Wrapper.serialNumberString(from: X509_get_serialNumber(cert))
    }

    static func serialNumberString(from serial: UnsafePointer<ASN1_INTEGER>?) -> String? {
        guard let serial,
              let serialBN = ASN1_INTEGER_to_BN(serial, nil) else {
            return nil
        }
        defer { BN_free(serialBN) }

        guard BN_is_negative(serialBN) == 0 else {
            return nil
        }

        let byteCount = (BN_num_bits(serialBN) + 7) / 8
        guard byteCount > 0,
              byteCount <= X509Wrapper.maxCertificateSerialLength else {
            return nil
        }

        var serialBytes = [UInt8](repeating: 0, count: Int(byteCount))
        guard BN_bn2bin(serialBN, &serialBytes) == byteCount else {
            return nil
        }

        return serialBytes.map { binToHexRep($0) }.joined()
    }
    
    func getSignatureAlgorithm() -> String? {
        let algor = X509_get0_tbs_sigalg(cert);
        let algo = getAlgorithm( algor?.pointee.algorithm )
        return algo
    }
    
    func getPublicKeyAlgorithm() -> String? {
        guard let pubKey = X509_get_X509_PUBKEY(cert) else { return nil }
        var ptr : OpaquePointer?
        X509_PUBKEY_get0_param(&ptr, nil, nil, nil, pubKey)
        let algo = getAlgorithm(ptr)
        return algo
    }
    
    func getIssuerName() -> String? {
        return getName(for: X509_get_issuer_name(cert))
    }
    
    func getSubjectName() -> String? {
        return getName(for: X509_get_subject_name(cert))
    }
    
    private func getName( for name: OpaquePointer? ) -> String? {
        guard let name = name else { return nil }
        
        var issuer: String = ""
        
        guard let out = BIO_new( BIO_s_mem()) else { return nil }
        defer { BIO_free(out) }
        
        guard X509_NAME_print_ex(out, name, 0, UInt(ASN1_STRFLGS_ESC_2253 |
                                                    ASN1_STRFLGS_ESC_CTRL |
                                                    ASN1_STRFLGS_ESC_MSB |
                                                    ASN1_STRFLGS_UTF8_CONVERT |
                                                    ASN1_STRFLGS_DUMP_UNKNOWN |
                                                    ASN1_STRFLGS_DUMP_DER | XN_FLAG_SEP_COMMA_PLUS |
                                                    XN_FLAG_DN_REV |
                                                    XN_FLAG_FN_SN |
                                                    XN_FLAG_DUMP_UNKNOWN_FIELDS)) >= 0 else {
            return nil
        }
        issuer = OpenSSLUtils.bioToString(bio: out)
        
        return issuer
    }
    
    private func getAlgorithm( _ algo:  OpaquePointer? ) -> String? {
        guard let algo = algo else { return nil }
        let len = OBJ_obj2nid(algo)
        var algoString : String? = nil
        if let sa = OBJ_nid2ln(len) {
            algoString = String(cString: sa )
        }
        return algoString
    }
    
    private func ASN1TimeToString( _ date: UnsafePointer<ASN1_TIME> ) -> String? {
        guard let b = BIO_new(BIO_s_mem()) else { return nil }
        defer { BIO_free(b) }
        
        guard ASN1_TIME_print(b, date) == 1 else {
            return nil
        }
        return OpenSSLUtils.bioToString(bio: b)
    }
    
}
