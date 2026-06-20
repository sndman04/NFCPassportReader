//
//  SOD.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import OpenSSL


// Format of SOD: ASN1 - Signed Data  (taken from rfc5652 - https://tools.ietf.org/html/rfc5652):
// The SOD is a CMS container of type Signed-data
//
// Note - ideally I'd be using a proper ASN1 parser, however currently there isn't a reliable one for Swift
// and I haven't written on (yet?).  So for the moment, I'm relying on the output from ASN1Dump and a
// simple parser for that
//
// Sequence
//   Object ID: signedData
//   Content: SignedData
//       SignedData ::= SEQUENCE {
//           INTEGER version CMSVersion,
//           SET digestAlgorithms DigestAlgorithmIdentifiers,
//           SEQUENCE encapContentInfo EncapsulatedContentInfo,
//           certificates [0] IMPLICIT CertificateSet OPTIONAL,
//           crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//           SET signerInfos SignerInfos }
//
// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm       OBJECT IDENTIFIER,
//     parameters      ANY OPTIONAL
// }
//
// EncapsulatedContentInfo ::= SEQUENCE {
//    eContentType ContentType,
//    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
//
// SignerInfos ::= SET OF SignerInfo
//
// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// SignerIdentifier ::= CHOICE {
//     issuerAndSerialNumber IssuerAndSerialNumber,
//     subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// Attribute ::= SEQUENCE {
//     attrType OBJECT IDENTIFIER,
//     attrValues SET OF AttributeValue }
// AttributeValue ::= ANY
// SignatureValue ::= OCTET STRING
@available(iOS 13, macOS 10.15, *)
class SOD : DataGroup {
    
    public private(set) var pkcs7CertificateData : [UInt8] = []
    private var asn1 : ASN1Item!
    private var pubKey : OpaquePointer?

    override var datagroupType: DataGroupId { .SOD }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
    }
    
    deinit {
        if ( pubKey != nil ) {
            EVP_PKEY_free(pubKey);
        }
    }

    override func parse(_ data: [UInt8]) throws {
        let p = SimpleASN1DumpParser()
        asn1 = try p.parse(data: Data(body))
    }

    private func itemBytes(_ item: ASN1Item) throws -> [UInt8] {
        let end = item.pos + item.headerLen + item.length
        guard item.pos >= 0,
              item.headerLen >= 0,
              item.length >= 0,
              end <= pkcs7CertificateData.count else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        return [UInt8](pkcs7CertificateData[item.pos ..< end])
    }

    private func octetStringData(_ item: ASN1Item) throws -> Data {
        guard item.type.hasPrefix("OCTET STRING"),
              item.value.count.isMultiple(of: 2) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        var bytes: [UInt8] = []
        var index = item.value.startIndex
        while index < item.value.endIndex {
            let nextIndex = item.value.index(index, offsetBy: 2)
            guard let byte = UInt8(item.value[index..<nextIndex], radix: 16) else {
                throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
            }
            bytes.append(byte)
            index = nextIndex
        }

        return Data(bytes)
    }

    private func signedDataItem() throws -> ASN1Item {
        guard let signedData = asn1.getChild(1)?.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signedData
    }

    private func signerInfoItem() throws -> ASN1Item {
        let signedData = try signedDataItem()
        guard let signerInfos = signedData.getChild(signedData.getNumberOfChildren() - 1),
              signerInfos.type == "SET",
              let signerInfo = signerInfos.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signerInfo
    }

    private func signedAttributesItem(in signerInfo: ASN1Item) throws -> ASN1Item {
        for index in 0 ..< signerInfo.getNumberOfChildren() {
            if let child = signerInfo.getChild(index),
               child.type.hasPrefix("cont [ 0 ]") {
                return child
            }
        }
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
    }

    private func signatureAlgorithmItem(in signerInfo: ASN1Item) throws -> ASN1Item {
        for index in 0 ..< signerInfo.getNumberOfChildren() {
            guard let child = signerInfo.getChild(index),
                  child.type.hasPrefix("cont [ 0 ]") else {
                continue
            }

            guard let signatureAlgorithm = signerInfo.getChild(index + 1) else {
                break
            }
            return signatureAlgorithm
        }

        guard let signatureAlgorithm = signerInfo.getChild(3) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signatureAlgorithm
    }

    private func signatureItem(in signerInfo: ASN1Item) throws -> ASN1Item {
        for index in 0 ..< signerInfo.getNumberOfChildren() {
            guard let child = signerInfo.getChild(index),
                  child.type.hasPrefix("cont [ 0 ]") else {
                continue
            }

            guard let signature = signerInfo.getChild(index + 2) else {
                break
            }
            return signature
        }

        guard let signature = signerInfo.getChild(4) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signature
    }
    
    /// Returns the public key from the embedded X509 certificate
    /// - Returns pointer to the public key
    func getPublicKey( ) throws -> OpaquePointer {
        
        if let key = pubKey {
            return key
        }
        
        let certs = try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der:Data(pkcs7CertificateData))
        guard let cert = certs.first else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No signing certificate found")
        }

        if let key = X509_get_pubkey(cert.cert) {
            pubKey = key
            return key
        }
        
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Unable to get public key")
    }
    
    
    /// Extracts the encapsulated content section from a SignedData PKCS7 container (if present)
    /// - Returns: The encapsulated content from a PKCS7 container if we could read it
    /// - Throws: Error if we can't find or read the encapsulated content
    func getEncapsulatedContent() throws -> Data {
        let signedData = try signedDataItem()
        guard let encContent = signedData.getChild(2)?.getChild(1),
              let content = encContent.getChild(0) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return try octetStringData(content)
    }
    
    /// Gets the digest algorithm used to hash the encapsulated content in the signed data section (if present)
    /// - Returns: The digest algorithm used to hash the encapsulated content in the signed data section
    /// - Throws: Error if we can't find or read the digest algorithm
    func getEncapsulatedContentDigestAlgorithm() throws -> String {
        let signedData = try signedDataItem()
        guard let digestAlgo = signedData.getChild(1)?.getChild(0)?.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return String(digestAlgo.value)
    }
    
    /// Gets the signed attributes section (if present)
    /// - Returns: the signed attributes section
    /// - Throws: Error if we can't find or read the signed attributes
    func getSignedAttributes( ) throws -> Data {
        let signerInfo = try signerInfoItem()
        let signedAttrs = try signedAttributesItem(in: signerInfo)
        
        var bytes = try itemBytes(signedAttrs)
        guard !bytes.isEmpty else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // The first byte will be 0xA0 -> as its a explicit tag for a contextual item which we need to convert
        // for the hash to calculate correctly
        // We know that the actual tag is a SET (0x31) - See section 5.4 of https://tools.ietf.org/html/rfc5652
        // So we need to change this from 0xA0 to 0x31
        if bytes[0] == 0xA0 {
            bytes[0] = 0x31
        }
        let signedAttribs = Data(bytes)
        
        return signedAttribs
    }
    
/// Gets the message digest from the signed attributes section (if present)
/// - Returns: the message digest
/// - Throws: Error if we can't find or read the message digest
    func getMessageDigestFromSignedAttributes( ) throws -> Data {
        
        // For the SOD, the SignedAttributes consists of:
        // A Content type Object (which has the value of the attributes content type)
        // A messageDigest Object which has the message digest as it value
        // We want the messageDigest value
        
        let signerInfo = try signerInfoItem()
        let signedAttrs = try signedAttributesItem(in: signerInfo)
        
        // Find the messageDigest in the signedAttributes section
        var sigData : Data?
        for i in 0 ..< signedAttrs.getNumberOfChildren() {
            let attrObj = signedAttrs.getChild(i)
            if attrObj?.getChild(0)?.value == "messageDigest" {
                if let set = attrObj?.getChild(1),
                   let digestVal = set.getChild(0) {
                    
                    sigData = try octetStringData(digestVal)
                }
            }
        }
        
        guard let messageDigest = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No messageDigest Returned") }
        
        return messageDigest
    }
    
    /// Gets the signature data (if present)
    /// - Returns: the signature
    /// - Throws: Error if we can't find or read the signature
    func getSignature( ) throws -> Data {
        let signerInfo = try signerInfoItem()
        let signature = try signatureItem(in: signerInfo)
        
        return try octetStringData(signature)
    }
    
    /// Gets the signature algorithm used (if present)
    /// - Returns: the signature algorithm used
    /// - Throws: Error if we can't find or read the signature algorithm
    func getSignatureAlgorithm( ) throws -> String {
        let signerInfo = try signerInfoItem()
        let signatureAlgorithm = try signatureAlgorithmItem(in: signerInfo)
        guard let signatureAlgo = signatureAlgorithm.getChild(0) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Vals I've seen are:
        // sha1WithRSAEncryption => default pkcs1
        // sha256WithRSAEncryption => default pkcs1
        // rsassaPss => pss        
        return signatureAlgo.value
    }
}
