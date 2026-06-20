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
    private var asn1Root : SimpleASN1Node!
    private var pubKey : OpaquePointer?

    private static let idSignedData = "1.2.840.113549.1.7.2"
    private static let idMessageDigest = "1.2.840.113549.1.9.4"

    private static let digestAlgorithmNamesByOID: [String: String] = [
        "1.3.14.3.2.26": "SHA1",
        "2.16.840.1.101.3.4.2.4": "SHA224",
        "2.16.840.1.101.3.4.2.1": "SHA256",
        "2.16.840.1.101.3.4.2.2": "SHA384",
        "2.16.840.1.101.3.4.2.3": "SHA512"
    ]

    private static let signatureAlgorithmNamesByOID: [String: String] = [
        "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10": "rsassaPss",
        "1.2.840.10045.4.1": "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4": "ecdsa-with-SHA512"
    ]

    override var datagroupType: DataGroupId { .SOD }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
    }
    
    deinit {
        clearPublicKey()
    }

    override func removeSensitiveDataForPrivacy() {
        pkcs7CertificateData.removeAll(keepingCapacity: false)
        asn1Root = nil
        clearPublicKey()
        super.removeSensitiveDataForPrivacy()
    }

    override func parse(_ data: [UInt8]) throws {
        asn1Root = try SimpleASN1Node.parse(body)
    }

    private func signedDataItem() throws -> SimpleASN1Node {
        guard asn1Root.tag == 0x30,
              asn1Root.children.count >= 2,
              asn1Root.children[0].objectIdentifier == Self.idSignedData,
              asn1Root.children[1].tag == 0xA0,
              let signedData = asn1Root.children[1].children.first(where: { $0.tag == 0x30 }) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signedData
    }

    private func signerInfoItem() throws -> SimpleASN1Node {
        let signedData = try signedDataItem()
        guard let signerInfos = signedData.children.last,
              signerInfos.tag == 0x31,
              let signerInfo = signerInfos.children.first(where: { $0.tag == 0x30 }) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signerInfo
    }

    private func signedAttributesItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        guard let signedAttributes = signerInfo.children.first(where: { $0.tag == 0xA0 }) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signedAttributes
    }

    private func signatureAlgorithmItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        if let signedAttributeIndex = signerInfo.children.firstIndex(where: { $0.tag == 0xA0 }),
           signedAttributeIndex + 1 < signerInfo.children.count {
            return signerInfo.children[signedAttributeIndex + 1]
        }

        guard signerInfo.children.count > 3 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signerInfo.children[3]
    }

    private func signatureItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        if let signedAttributeIndex = signerInfo.children.firstIndex(where: { $0.tag == 0xA0 }),
           signedAttributeIndex + 2 < signerInfo.children.count {
            return signerInfo.children[signedAttributeIndex + 2]
        }

        guard signerInfo.children.count > 4 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signerInfo.children[4]
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

    private func clearPublicKey() {
        if let key = pubKey {
            EVP_PKEY_free(key)
            pubKey = nil
        }
    }
    
    
    /// Extracts the encapsulated content section from a SignedData PKCS7 container (if present)
    /// - Returns: The encapsulated content from a PKCS7 container if we could read it
    /// - Throws: Error if we can't find or read the encapsulated content
    func getEncapsulatedContent() throws -> Data {
        let signedData = try signedDataItem()
        guard signedData.children.count >= 3,
              let eContent = signedData.children[2].children.first(where: { $0.tag == 0xA0 }),
              let content = eContent.children.first(where: { $0.tag == 0x04 }) else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return Data(content.value)
    }
    
    /// Gets the digest algorithm used to hash the encapsulated content in the signed data section (if present)
    /// - Returns: The digest algorithm used to hash the encapsulated content in the signed data section
    /// - Throws: Error if we can't find or read the digest algorithm
    func getEncapsulatedContentDigestAlgorithm() throws -> String {
        let signedData = try signedDataItem()
        guard signedData.children.count >= 2,
              let digestAlgorithmOID = signedData.children[1].children.first?.children.first?.objectIdentifier,
              let digestAlgorithm = Self.digestAlgorithmNamesByOID[digestAlgorithmOID] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return digestAlgorithm
    }
    
    /// Gets the signed attributes section (if present)
    /// - Returns: the signed attributes section
    /// - Throws: Error if we can't find or read the signed attributes
    func getSignedAttributes( ) throws -> Data {
        let signerInfo = try signerInfoItem()
        let signedAttrs = try signedAttributesItem(in: signerInfo)
        
        var bytes = signedAttrs.encodedBytes
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
        for attrObj in signedAttrs.children where attrObj.tag == 0x30 {
            if attrObj.children.first?.objectIdentifier == Self.idMessageDigest {
                if attrObj.children.count >= 2,
                   let digestVal = attrObj.children[1].children.first(where: { $0.tag == 0x04 }) {
                    sigData = Data(digestVal.value)
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
        
        guard signature.tag == 0x04 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        return Data(signature.value)
    }
    
    /// Gets the signature algorithm used (if present)
    /// - Returns: the signature algorithm used
    /// - Throws: Error if we can't find or read the signature algorithm
    func getSignatureAlgorithm( ) throws -> String {
        let signerInfo = try signerInfoItem()
        let signatureAlgorithm = try signatureAlgorithmItem(in: signerInfo)
        guard let signatureAlgorithmOID = signatureAlgorithm.children.first?.objectIdentifier,
              let signatureAlgorithmName = Self.signatureAlgorithmNamesByOID[signatureAlgorithmOID] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Vals I've seen are:
        // sha1WithRSAEncryption => default pkcs1
        // sha256WithRSAEncryption => default pkcs1
        // rsassaPss => pss        
        return signatureAlgorithmName
    }
}
